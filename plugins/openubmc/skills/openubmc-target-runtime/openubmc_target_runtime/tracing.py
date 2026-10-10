"""Optional, bounded and behavior-neutral Runtime tracing.

No OpenTelemetry package is imported on the disabled path. Only fixed span
names and opaque references cross the export boundary. This module never
records application exceptions, arguments, results, or ambient baggage.
"""

from __future__ import annotations

from collections import deque
from contextvars import ContextVar
from dataclasses import dataclass
import hashlib
import hmac
import os
from queue import Empty, Full, Queue
import threading
import time
from urllib.parse import urlsplit


_SPAN_NAMES = frozenset({
    "mcp.observe", "mcp.execute", "agent.observe", "agent.execute",
    "runtime.observe", "runtime.execute", "runtime.gate", "runtime.effect",
    "host.capture",
})


@dataclass(frozen=True)
class TraceSettings:
    enabled: bool = False
    endpoint: str | None = None
    queue_size: int = 128
    max_spans_per_run: int = 64
    max_tracked_runs: int = 256
    max_attribute_bytes: int = 64
    export_timeout_seconds: float = 1.0

    def __post_init__(self) -> None:
        if not 1 <= self.queue_size <= 1024:
            raise ValueError("trace queue size is out of range")
        if not 1 <= self.max_spans_per_run <= 128:
            raise ValueError("trace span budget is out of range")
        if not 1 <= self.max_tracked_runs <= 1024:
            raise ValueError("trace Run budget is out of range")
        if not 16 <= self.max_attribute_bytes <= 64:
            raise ValueError("trace attribute limit is out of range")
        if not 0.05 <= self.export_timeout_seconds <= 5.0:
            raise ValueError("trace export timeout is out of range")
        if self.endpoint is not None:
            parsed = urlsplit(self.endpoint)
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                    or parsed.username or parsed.password or parsed.query
                    or parsed.fragment):
                raise ValueError("trace endpoint must be an HTTP(S) URL without credentials")

    @classmethod
    def from_environment(cls) -> TraceSettings:
        """Invalid trace configuration is a disabled observation, not a preflight."""
        try:
            if os.environ.get("OPENUBMC_TRACE_ENABLED") != "1":
                return cls()
            return cls(
                enabled=True,
                endpoint=os.environ.get("OPENUBMC_TRACE_OTLP_ENDPOINT") or None,
                queue_size=int(os.environ.get("OPENUBMC_TRACE_QUEUE_SIZE", "128")),
                max_spans_per_run=int(os.environ.get("OPENUBMC_TRACE_MAX_SPANS_PER_RUN", "64")),
                export_timeout_seconds=float(
                    os.environ.get("OPENUBMC_TRACE_EXPORT_TIMEOUT_SECONDS", "1")
                ),
            )
        except (ValueError, OverflowError):
            return cls()


class LocalSpanCollector:
    """Bounded offline collector used when no endpoint was explicitly set."""

    def __init__(self, capacity: int, success: object) -> None:
        self._spans: deque[object] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._success = success
        self.evicted = 0

    def export(self, spans: object) -> object:
        with self._lock:
            for span in spans:
                if len(self._spans) == self._spans.maxlen:
                    self.evicted += 1
                self._spans.append(span)
        return self._success

    def snapshot(self) -> tuple[object, ...]:
        with self._lock:
            return tuple(self._spans)

    def shutdown(self) -> None:
        pass


class _BoundedSpanProcessor:
    """Nonblocking, single worker SpanProcessor with observable drops."""

    def __init__(
        self, exporter: object, *, capacity: int, timeout: float, success: object,
        max_spans_per_run: int, max_tracked_runs: int,
    ) -> None:
        self.exporter = exporter
        self.timeout = timeout
        self.success = success
        self.queue: Queue[object] = Queue(maxsize=capacity)
        self._lock = threading.Lock()
        self.dropped_queue = 0
        self.dropped_export = 0
        self.dropped_budget = 0
        self._run_counts: dict[str, int] = {}
        self._max_spans_per_run = max_spans_per_run
        self._max_tracked_runs = max_tracked_runs
        self._closed = False
        self._worker = threading.Thread(target=self._drain, name="openubmc-trace", daemon=True)
        self._worker.start()

    def on_start(self, span: object, parent_context: object | None = None) -> None:
        pass

    def _on_ending(self, span: object) -> None:
        # SDK 1.45 calls this hook before on_end; no application data is read.
        pass

    def on_end(self, span: object) -> None:
        with self._lock:
            if self._closed:
                self.dropped_queue += 1
                return
            run_ref = span.attributes.get("run.ref")
            if run_ref is not None:
                count = self._run_counts.get(run_ref)
                if (count is None and len(self._run_counts) >= self._max_tracked_runs
                        or count is not None and count >= self._max_spans_per_run):
                    self.dropped_budget += 1
                    return
                self._run_counts[run_ref] = (count or 0) + 1
            try:
                self.queue.put_nowait(span)
            except Full:
                self.dropped_queue += 1

    def _drain(self) -> None:
        while True:
            try:
                span = self.queue.get(timeout=0.02)
            except Empty:
                with self._lock:
                    if self._closed and self.queue.empty():
                        return
                continue
            try:
                # The OTLP exporter receives its own bounded request timeout.
                # No Runtime or device operation is retried from this thread.
                if self.exporter.export((span,)) != self.success:
                    with self._lock:
                        self.dropped_export += 1
            except Exception:
                with self._lock:
                    self.dropped_export += 1
            finally:
                self.queue.task_done()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        deadline = time.monotonic() + min(self.timeout, max(0, timeout_millis) / 1000)
        while self.queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.005)
        return self.queue.unfinished_tasks == 0

    def shutdown(self) -> None:
        with self._lock:
            self._closed = True
        self._worker.join(timeout=self.timeout)
        if not self._worker.is_alive():
            try:
                self.exporter.shutdown()
            except Exception:
                pass


class _TraceSpan:
    def __init__(
        self, owner: RunTracer, name: str, task_id: str, run_id: str,
        effect_id: str,
    ) -> None:
        self.owner = owner
        self.name = name
        self.task_id = task_id
        self.run_id = run_id
        self.effect_id = effect_id
        self.span = None
        self.token = None

    def __enter__(self) -> _TraceSpan:
        self.owner._start(self)
        return self

    def bind_run(self, run_id: str) -> None:
        self.run_id = run_id
        if self.span is not None:
            try:
                self.span.set_attribute("run.ref", self.owner._ref(run_id))
            except Exception:
                self.owner._drop_internal()

    def __exit__(self, _type: object, _value: object, _traceback: object) -> bool:
        self.owner._end(self)
        return False


class RunTracer:
    """One local trace session; none of its state participates in Run decisions."""

    def __init__(
        self, settings: TraceSettings | None = None, *, exporter: object | None = None,
    ) -> None:
        self.settings = settings or TraceSettings.from_environment()
        self._lock = threading.Lock()
        self._key = b""
        self._counts: dict[str, int] = {}
        self._parents: dict[str, object] = {}
        self._active: ContextVar[object | None] = ContextVar(
            f"openubmc_trace_{id(self)}", default=None,
        )
        self._internal_drops = 0
        self._budget_drops = 0
        self._provider = None
        self._tracer = None
        self._processor = None
        self._collector = None
        if not self.settings.enabled:
            return
        processor = None
        try:
            self._key = os.urandom(32)
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import SpanLimits, TracerProvider
            from opentelemetry.sdk.trace.export import SpanExportResult

            if exporter is None and self.settings.endpoint is not None:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
                exporter = OTLPSpanExporter(
                    endpoint=self.settings.endpoint,
                    timeout=self.settings.export_timeout_seconds,
                )
            if exporter is None:
                exporter = LocalSpanCollector(self.settings.queue_size, SpanExportResult.SUCCESS)
                self._collector = exporter
            processor = _BoundedSpanProcessor(
                exporter, capacity=self.settings.queue_size,
                timeout=self.settings.export_timeout_seconds,
                success=SpanExportResult.SUCCESS,
                max_spans_per_run=self.settings.max_spans_per_run,
                max_tracked_runs=self.settings.max_tracked_runs,
            )
            provider = TracerProvider(
                resource=Resource({"service.name": "openubmc-target-runtime"}),
                shutdown_on_exit=False,
                span_limits=SpanLimits(
                    max_span_attributes=4,
                    max_events=0,
                    max_links=0,
                    max_span_attribute_length=self.settings.max_attribute_bytes,
                ),
            )
            provider.add_span_processor(processor)
            self._provider = provider
            self._processor = processor
            self._tracer = provider.get_tracer("openubmc_target_runtime.tracing")
        except Exception:
            # Missing optional SDK or invalid exporter configuration never stops Runtime.
            if processor is not None:
                try:
                    processor.shutdown()
                except Exception:
                    pass
            self._collector = None

    @property
    def enabled(self) -> bool:
        return self._tracer is not None

    def _ref(self, value: str) -> str:
        return hmac.new(
            self._key, value.encode("utf-8", "replace"), hashlib.sha256,
        ).hexdigest()[:32]

    def _drop_internal(self) -> None:
        with self._lock:
            self._internal_drops += 1

    def _start(self, scope: _TraceSpan) -> None:
        if not self.enabled:
            return
        try:
            if scope.name not in _SPAN_NAMES:
                self._drop_internal()
                return
            identity = ("run:" + self._ref(scope.run_id) if scope.run_id
                        else "task:" + self._ref(scope.task_id))
            with self._lock:
                count = self._counts.get(identity)
                if count is None and len(self._counts) >= self.settings.max_tracked_runs:
                    self._budget_drops += 1
                    return
                if count is not None and count >= self.settings.max_spans_per_run:
                    self._budget_drops += 1
                    return
                self._counts[identity] = (count or 0) + 1
                dropped = self._internal_drops + self._budget_drops
            if self._processor is not None:
                with self._processor._lock:
                    dropped += (self._processor.dropped_queue
                                + self._processor.dropped_export
                                + self._processor.dropped_budget)
            if self._collector is not None:
                dropped += self._collector.evicted
            from opentelemetry import context as otel_context, trace as otel_trace
            parent = self._active.get()
            if parent is None:
                with self._lock:
                    parent = self._parents.get(identity)
                    if parent is None and scope.task_id:
                        parent = self._parents.get("task:" + self._ref(scope.task_id))
            context = otel_context.Context()
            if parent is not None:
                context = otel_trace.set_span_in_context(
                    otel_trace.NonRecordingSpan(parent), context,
                )
            attributes: dict[str, str | int] = {
                "trace.dropped_before": min(dropped, 2**63 - 1),
            }
            if scope.task_id:
                attributes["task.ref"] = self._ref(scope.task_id)
            if scope.run_id:
                attributes["run.ref"] = self._ref(scope.run_id)
            if scope.effect_id:
                attributes["effect.ref"] = self._ref(scope.effect_id)
            scope.span = self._tracer.start_span(
                scope.name, context=context, attributes=attributes,
                record_exception=False, set_status_on_exception=False,
            )
            scope.token = self._active.set(scope.span.get_span_context())
        except Exception:
            self._drop_internal()

    def _end(self, scope: _TraceSpan) -> None:
        if scope.span is None:
            return
        try:
            context = scope.span.get_span_context()
            if scope.token is not None:
                self._active.reset(scope.token)
            scope.span.end()
            with self._lock:
                if scope.task_id:
                    self._parents["task:" + self._ref(scope.task_id)] = context
                if scope.run_id:
                    self._parents["run:" + self._ref(scope.run_id)] = context
                while len(self._parents) > self.settings.max_tracked_runs * 2:
                    self._parents.pop(next(iter(self._parents)))
        except Exception:
            self._drop_internal()

    def span(
        self, name: str, *, task_id: str = "", run_id: str = "",
        effect_id: str = "",
    ) -> _TraceSpan:
        return _TraceSpan(self, name, task_id, run_id, effect_id)

    def stats(self) -> dict[str, int | bool]:
        with self._lock:
            internal = self._internal_drops
            budget = self._budget_drops
            tracked = len(self._counts)
        queue_drops = export_drops = processor_budget_drops = 0
        if self._processor is not None:
            with self._processor._lock:
                queue_drops = self._processor.dropped_queue
                export_drops = self._processor.dropped_export
                processor_budget_drops = self._processor.dropped_budget
        evicted = self._collector.evicted if self._collector is not None else 0
        return {
            "enabled": self.enabled,
            "dropped_spans": (
                internal + budget + processor_budget_drops + queue_drops
                + export_drops + evicted
            ),
            "dropped_budget": budget + processor_budget_drops,
            "dropped_internal": internal,
            "dropped_queue": queue_drops,
            "dropped_export": export_drops,
            "dropped_local_eviction": evicted,
            "tracked_scopes": tracked,
        }

    def local_spans(self) -> tuple[object, ...]:
        return self._collector.snapshot() if self._collector is not None else ()

    def flush(self) -> bool:
        if self._processor is None:
            return True
        return self._processor.force_flush(
            int(self.settings.export_timeout_seconds * 1000)
        )

    def close(self) -> None:
        if self._processor is not None:
            try:
                self._processor.shutdown()
            except Exception:
                self._drop_internal()
