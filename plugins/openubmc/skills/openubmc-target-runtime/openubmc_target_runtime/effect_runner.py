"""Single-process execution for durable Runtime Effect intents."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from enum import Enum
import os
import re
import threading
import time

from .capability import EffectClass
from .contracts import RUNTIME_API_VERSION


EFFECT_INTENT_SCHEMA = f"{RUNTIME_API_VERSION}/effect-intent-v1"
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class EffectIntent:
    """The durable identity and inputs needed to execute or recover one Effect."""

    run_id: str
    effect_id: str
    operation: str
    effect_class: EffectClass
    request_fingerprint: str
    arguments: Mapping[str, object]

    def __post_init__(self) -> None:
        for name, value in (
            ("run_id", self.run_id),
            ("effect_id", self.effect_id),
            ("operation", self.operation),
        ):
            if _SAFE_ID.fullmatch(value) is None:
                raise ValueError(f"Effect intent {name} must be a safe identifier")
        if _SHA256.fullmatch(self.request_fingerprint) is None:
            raise ValueError("Effect intent request_fingerprint must be SHA-256")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "EffectIntent":
        if value.get("schema") != EFFECT_INTENT_SCHEMA:
            raise ValueError("unsupported Effect intent schema")
        if value.get("version") != 1:
            raise ValueError("unsupported Effect intent version")
        raw_arguments = value.get("arguments")
        if not isinstance(raw_arguments, Mapping):
            raise ValueError("Effect intent arguments must be an object")
        return cls(
            run_id=str(value.get("run_id", "")),
            effect_id=str(value.get("effect_id", "")),
            operation=str(value.get("operation", "")),
            effect_class=EffectClass(str(value.get("effect_class", ""))),
            request_fingerprint=str(value.get("request_fingerprint", "")),
            arguments=dict(raw_arguments),
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": EFFECT_INTENT_SCHEMA,
            "version": 1,
            "run_id": self.run_id,
            "effect_id": self.effect_id,
            "operation": self.operation,
            "effect_class": self.effect_class.value,
            "request_fingerprint": self.request_fingerprint,
            "arguments": dict(self.arguments),
        }


@dataclass(frozen=True)
class PreparedEffect:
    intent: EffectIntent
    accepted_payload: Mapping[str, object]


class EffectRunMode(str, Enum):
    DISPATCH = "dispatch"
    REATTACH = "reattach"
    RECOVER = "recover"


class EffectSettlementMode(str, Enum):
    DISPATCH = "dispatch"
    RECONCILE = "reconcile"


@dataclass(frozen=True)
class EffectExecution:
    """One in-process execution bound to its original durable settlement lane."""

    future: Future[Mapping[str, object]]
    mode: EffectRunMode
    settlement_generation: int
    admitted_at: float = field(default_factory=time.time)


class LocalEffectRunner:
    """Run durable Effects locally while preserving one identity across reattach."""

    def __init__(
        self,
        execute: Callable[[EffectIntent], Mapping[str, object]],
        recover: Callable[[EffectIntent], Mapping[str, object]],
        *,
        max_workers: int = 4,
    ) -> None:
        if max_workers <= 0:
            raise ValueError("EffectRunner max_workers must be positive")
        self._execute = execute
        self._recover = recover
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="openubmc-effect",
        )
        self._executions: dict[tuple[str, str], EffectExecution] = {}
        self._history: dict[
            tuple[str, str], tuple[EffectIntent, EffectRunMode]
        ] = {}
        self._lock = threading.Lock()
        self._closed = False

    def ensure(
        self,
        intent: EffectIntent,
        *,
        mode: EffectRunMode,
        settlement_generation: int = 0,
        claim: Callable[[], bool] | None = None,
    ) -> EffectExecution | None:
        if not isinstance(mode, EffectRunMode):
            raise TypeError("EffectRunner mode must be an EffectRunMode")
        if settlement_generation < 0:
            raise ValueError("EffectRunner settlement generation must be non-negative")
        identity = (intent.run_id, intent.effect_id)
        with self._lock:
            if self._closed:
                raise RuntimeError("EffectRunner is closed")
            history = self._history.get(identity)
            if history is not None and history[0] != intent:
                raise ValueError("Effect identity has a conflicting intent")
            current = self._executions.get(identity)
            if current is not None:
                return current
            if claim is not None and not claim():
                return None
            effective_mode = mode
            if mode is EffectRunMode.REATTACH and history is not None:
                effective_mode = history[1]
            callback = (
                self._recover
                if effective_mode is EffectRunMode.RECOVER
                else self._execute
            )
            future = self._executor.submit(callback, intent)
            execution = EffectExecution(
                future=future,
                mode=effective_mode,
                settlement_generation=settlement_generation,
            )
            self._executions[identity] = execution
            self._history[identity] = (intent, effective_mode)
            return execution

    def has_seen(self, intent: EffectIntent) -> bool:
        with self._lock:
            return (intent.run_id, intent.effect_id) in self._history

    def has_execution(self, intent: EffectIntent) -> bool:
        """Whether this process still owns a queued, running, or settled future."""
        with self._lock:
            return (intent.run_id, intent.effect_id) in self._executions

    def activity(self, intent: EffectIntent) -> dict[str, object]:
        """Observe local ownership without claiming remote/domain progress.

        This heartbeat is emitted by the supervisor when it is queried. It
        does not update the durable last-progress timestamp, and disappears
        on process restart so recovery cannot mistake a stale PID for a live
        worker.
        """
        with self._lock:
            execution = self._executions.get((intent.run_id, intent.effect_id))
            if execution is None:
                return {}
            future = execution.future
            return {
                "scope": "local-supervisor",
                "observed_at": time.time(),
                "owner_pid": os.getpid(),
                "admitted_at": execution.admitted_at,
                "worker_state": (
                    "settled" if future.done()
                    else "running" if future.running()
                    else "queued"
                ),
                "mode": execution.mode.value,
                "settlement_generation": execution.settlement_generation,
            }

    def has_settled(self, intent: EffectIntent) -> bool:
        with self._lock:
            execution = self._executions.get((intent.run_id, intent.effect_id))
            return execution is not None and execution.future.done()

    def acknowledge(
        self,
        intent: EffectIntent,
        execution: EffectExecution,
        *,
        retain_for_reattach: bool,
    ) -> None:
        """Release a committed result and retain only a genuine reattach lane."""
        identity = (intent.run_id, intent.effect_id)
        with self._lock:
            if self._executions.get(identity) is execution:
                del self._executions[identity]
                if not retain_for_reattach:
                    self._history.pop(identity, None)

    @staticmethod
    def wait(
        execution: EffectExecution,
        timeout: float,
    ) -> bool:
        try:
            execution.future.result(timeout=max(0.0, timeout))
        except FutureTimeout:
            return False
        except BaseException:
            # RunEngine converts the settled error into the authoritative
            # RunDecision after this wait boundary.
            return True
        return True

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._executor.shutdown(wait=True, cancel_futures=False)
