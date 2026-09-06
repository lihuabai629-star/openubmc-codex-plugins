"""Fair bounded scheduling for independent openUBMC target work."""
from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
import os
import statistics
import threading
import time
from typing import Callable, Generic, TypeVar


TargetT = TypeVar("TargetT")
ValueT = TypeVar("ValueT")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ScheduledTargetResult(Generic[ValueT]):
    index: int
    submitted_at_monotonic: float
    started_at_monotonic: float
    completed_at_monotonic: float
    started_at: str
    completed_at: str
    value: ValueT | None = None
    error_code: str = ""
    error: str = ""

    @property
    def queue_delay_ms(self) -> float:
        return max(
            0.0,
            (self.started_at_monotonic - self.submitted_at_monotonic) * 1000,
        )

    @property
    def duration_ms(self) -> float:
        return max(
            0.0,
            (self.completed_at_monotonic - self.started_at_monotonic) * 1000,
        )

    @property
    def ok(self) -> bool:
        return not self.error_code


@dataclass(frozen=True)
class SchedulerRunResult(Generic[ValueT]):
    results: list[ScheduledTargetResult[ValueT]]
    completion_order: list[int]
    metrics: dict[str, object]


class FairTargetScheduler:
    """Queue all targets, bound active work, and preserve target-local outcomes."""

    def __init__(
        self,
        *,
        concurrency: str | int = "auto",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if isinstance(concurrency, bool):
            raise ValueError("concurrency must be auto, unbounded, or a positive integer")
        if isinstance(concurrency, int):
            if concurrency < 1:
                raise ValueError("concurrency must be positive")
            self.policy = str(concurrency)
        elif isinstance(concurrency, str):
            selected = concurrency.strip().lower()
            if selected.isdecimal() and int(selected) > 0:
                self.policy = str(int(selected))
            elif selected in {"auto", "unbounded"}:
                self.policy = selected
            else:
                raise ValueError(
                    "concurrency must be auto, unbounded, or a positive integer"
                )
        else:
            raise TypeError("concurrency must be a string or integer")
        self._clock = clock

    def budget_for(self, target_count: int) -> int:
        if target_count < 1:
            raise ValueError("target_count must be positive")
        if self.policy == "unbounded":
            return target_count
        if self.policy == "auto":
            cpu_budget = max(2, min(8, os.cpu_count() or 2))
            return min(target_count, cpu_budget)
        return min(target_count, int(self.policy))

    def run(
        self,
        targets: list[TargetT],
        worker: Callable[[TargetT, object], ValueT],
        *,
        context: object,
    ) -> SchedulerRunResult[ValueT]:
        if not targets:
            raise ValueError("at least one target is required")
        budget = self.budget_for(len(targets))
        submitted_at = self._clock()
        submitted_wall = _utc_now()
        completion_order: list[int] = []
        completion_lock = threading.Lock()

        def run_one(index: int, target: TargetT) -> ScheduledTargetResult[ValueT]:
            started_monotonic = self._clock()
            started_at = _utc_now()
            try:
                if context is not None:
                    context.raise_if_stopped()
                value = worker(target, context)
                if context is not None:
                    context.raise_if_stopped()
                result = ScheduledTargetResult(
                    index=index,
                    submitted_at_monotonic=submitted_at,
                    started_at_monotonic=started_monotonic,
                    completed_at_monotonic=self._clock(),
                    started_at=started_at,
                    completed_at=_utc_now(),
                    value=value,
                )
            except Exception as exc:
                result = ScheduledTargetResult(
                    index=index,
                    submitted_at_monotonic=submitted_at,
                    started_at_monotonic=started_monotonic,
                    completed_at_monotonic=self._clock(),
                    started_at=started_at,
                    completed_at=_utc_now(),
                    error_code=type(exc).__name__,
                    error=str(exc),
                )
            with completion_lock:
                completion_order.append(index)
            return result

        ordered: list[ScheduledTargetResult[ValueT] | None] = [None] * len(targets)
        peak_inflight = 0
        with ThreadPoolExecutor(max_workers=budget) as executor:
            futures = {}
            next_index = 0

            def fill_window() -> None:
                nonlocal next_index, peak_inflight
                while next_index < len(targets) and len(futures) < budget:
                    future = executor.submit(
                        run_one,
                        next_index,
                        targets[next_index],
                    )
                    futures[future] = next_index
                    next_index += 1
                peak_inflight = max(peak_inflight, len(futures))

            fill_window()
            while futures:
                completed, _pending = wait(
                    tuple(futures),
                    return_when=FIRST_COMPLETED,
                )
                for future in completed:
                    futures.pop(future, None)
                    result = future.result()
                    ordered[result.index] = result
                fill_window()
        results = [item for item in ordered if item is not None]
        completed_at = self._clock()
        durations = [item.duration_ms for item in results]
        if len(durations) >= 2:
            duration_p75 = statistics.quantiles(
                durations,
                n=4,
                method="inclusive",
            )[2]
        else:
            duration_p75 = durations[0]
        queue_delays = [item.queue_delay_ms for item in results]
        first_completed = min(
            (item.completed_at_monotonic for item in results),
            default=completed_at,
        )
        metrics: dict[str, object] = {
            "requested_policy": self.policy,
            "actual_concurrency_budget": budget,
            "peak_inflight_submissions": peak_inflight,
            "target_count": len(targets),
            "completed_count": sum(item.ok for item in results),
            "failed_count": sum(not item.ok for item in results),
            "max_queue_delay_ms": max(queue_delays, default=0.0),
            "target_duration_p75_ms": duration_p75,
            "first_result_ms": max(0.0, (first_completed - submitted_at) * 1000),
            "total_duration_ms": max(0.0, (completed_at - submitted_at) * 1000),
            "observation_window_start": submitted_wall,
            "observation_window_end": _utc_now(),
            "completion_order": list(completion_order),
        }
        return SchedulerRunResult(
            results=results,
            completion_order=completion_order,
            metrics=metrics,
        )
