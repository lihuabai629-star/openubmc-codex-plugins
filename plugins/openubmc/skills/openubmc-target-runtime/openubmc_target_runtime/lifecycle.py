"""Task-scoped resource lifecycle, cancellation, deadlines, and engine choice."""
from __future__ import annotations

from dataclasses import dataclass, field
import threading
import time
from typing import Callable, Generic, TypeVar


ResourceT = TypeVar("ResourceT")
ResultT = TypeVar("ResultT")


class OperationCancelled(RuntimeError):
    """Raised when queued or cooperative bounded work is cancelled."""


class OperationDeadlineExceeded(TimeoutError):
    """Raised when an operation exhausts its queue or execution budget."""


class RuntimeCapacityExceeded(RuntimeError):
    """Raised when every task is busy and no idle LRU entry can be reclaimed."""


class EngineUnavailable(RuntimeError):
    """Raised before remote work when neither requested engine is ready."""


class EngineSwitchProhibited(RuntimeError):
    """Raised when code attempts to execute through a non-selected engine."""


class CancellationToken:
    def __init__(self) -> None:
        self._event = threading.Event()
        self._reason = "operation cancelled"
        self._lock = threading.Lock()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str:
        with self._lock:
            return self._reason

    def cancel(self, reason: str = "operation cancelled") -> None:
        with self._lock:
            self._reason = str(reason) or "operation cancelled"
            self._event.set()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise OperationCancelled(self.reason)

    def wait(self, timeout: float) -> None:
        if self._event.wait(max(0.0, timeout)):
            self.raise_if_cancelled()


@dataclass(frozen=True)
class OperationContext:
    task_id: str
    operation_id: str
    deadline_at: float
    cancellation: CancellationToken
    _clock: Callable[[], float] = field(repr=False, compare=False)

    def remaining(self) -> float:
        return max(0.0, self.deadline_at - self._clock())

    def raise_if_stopped(self) -> None:
        self.cancellation.raise_if_cancelled()
        if self.remaining() <= 0:
            raise OperationDeadlineExceeded(
                f"operation {self.operation_id} exceeded its deadline"
            )

    def wait(self, seconds: float) -> None:
        self.raise_if_stopped()
        wait_for = min(max(0.0, seconds), self.remaining())
        self.cancellation.wait(wait_for)
        self.raise_if_stopped()

    def derive(self, operation_id: str) -> "OperationContext":
        child_id = str(operation_id).strip()
        if not child_id:
            raise ValueError("operation_id must not be empty")
        return OperationContext(
            task_id=self.task_id,
            operation_id=child_id,
            deadline_at=self.deadline_at,
            cancellation=self.cancellation,
            _clock=self._clock,
        )


@dataclass
class _ManagedTask(Generic[ResourceT]):
    task_id: str
    resource: ResourceT
    created_at: float
    last_used_at: float
    state: str = "active"
    active_operations: int = 0
    queued_operations: int = 0
    operation_tokens: dict[str, CancellationToken] = field(default_factory=dict)
    operation_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


class TaskRunRegistry(Generic[ResourceT]):
    """Reuse one resource per task while bounding idle and pressure retention."""

    def __init__(
        self,
        *,
        factory: Callable[[str], ResourceT],
        closer: Callable[[ResourceT], None],
        status_reader: Callable[[ResourceT], dict[str, object]],
        maintenance: Callable[[ResourceT], object] | None = None,
        completion_preparer: Callable[[ResourceT], object] | None = None,
        max_tasks: int = 32,
        idle_timeout_seconds: float = 1800,
        max_lifetime_seconds: float = 28800,
        max_concurrent_operations: int = 8,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_tasks < 1:
            raise ValueError("max_tasks must be positive")
        if idle_timeout_seconds <= 0:
            raise ValueError("idle_timeout_seconds must be positive")
        if max_lifetime_seconds <= 0:
            raise ValueError("max_lifetime_seconds must be positive")
        if max_concurrent_operations < 1:
            raise ValueError("max_concurrent_operations must be positive")
        self._factory = factory
        self._closer = closer
        self._status_reader = status_reader
        self._maintenance = maintenance
        self._completion_preparer = completion_preparer
        self.max_tasks = max_tasks
        self.idle_timeout_seconds = float(idle_timeout_seconds)
        self.max_lifetime_seconds = float(max_lifetime_seconds)
        self.max_concurrent_operations = max_concurrent_operations
        self._clock = clock
        self._tasks: dict[str, _ManagedTask[ResourceT]] = {}
        self._pending_cancellations: dict[tuple[str, str], str] = {}
        self._condition = threading.Condition(threading.RLock())
        self._operation_slots = threading.BoundedSemaphore(max_concurrent_operations)
        self._closed = False

    def _close_resource(self, resource: ResourceT) -> None:
        try:
            self._closer(resource)
        except Exception:
            pass

    def _prepare_completion(self, resource: ResourceT) -> None:
        if self._completion_preparer is None:
            return
        try:
            self._completion_preparer(resource)
        except Exception:
            pass

    def _get_or_create(self, task_id: str) -> _ManagedTask[ResourceT]:
        while True:
            victim: ResourceT | None = None
            with self._condition:
                if self._closed:
                    raise RuntimeError("TaskRunRegistry is closed")
                existing = self._tasks.get(task_id)
                if existing is not None:
                    if existing.state != "active":
                        raise OperationCancelled(
                            f"task {task_id} is completing and cannot accept new work"
                        )
                    return existing
                if len(self._tasks) < self.max_tasks:
                    now = self._clock()
                    managed = _ManagedTask(
                        task_id=task_id,
                        resource=self._factory(task_id),
                        created_at=now,
                        last_used_at=now,
                    )
                    self._tasks[task_id] = managed
                    return managed
                idle = [
                    task
                    for task in self._tasks.values()
                    if task.active_operations == 0
                    and task.queued_operations == 0
                    and task.state == "active"
                ]
                if not idle:
                    raise RuntimeCapacityExceeded(
                        "all retained TaskRuns are busy; retry within the request deadline"
                    )
                lru = min(idle, key=lambda task: (task.last_used_at, task.created_at))
                self._tasks.pop(lru.task_id, None)
                lru.state = "reclaimed"
                victim = lru.resource
            if victim is not None:
                self._close_resource(victim)

    @staticmethod
    def _acquire_interruptibly(
        lock,
        context: OperationContext,
    ) -> None:
        while True:
            context.raise_if_stopped()
            wait_for = min(0.05, context.remaining())
            if lock.acquire(timeout=wait_for):
                return

    def execute(
        self,
        *,
        task_id: str,
        operation_id: str,
        timeout_seconds: float,
        callback: Callable[[ResourceT, OperationContext], ResultT],
    ) -> ResultT:
        if not task_id.strip():
            raise ValueError("task_id must not be empty")
        if not operation_id.strip():
            raise ValueError("operation_id must not be empty")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.reap()
        managed = self._get_or_create(task_id)
        token = CancellationToken()
        context = OperationContext(
            task_id=task_id,
            operation_id=operation_id,
            deadline_at=self._clock() + float(timeout_seconds),
            cancellation=token,
            _clock=self._clock,
        )
        with self._condition:
            if (
                self._tasks.get(task_id) is not managed
                or managed.state != "active"
            ):
                raise OperationCancelled(
                    f"task {task_id} is completing and cannot accept new work"
                )
            if operation_id in managed.operation_tokens:
                raise ValueError(
                    f"operation_id is already active in task {task_id}: {operation_id}"
                )
            managed.operation_tokens[operation_id] = token
            managed.queued_operations += 1
            managed.last_used_at = self._clock()
            pending_reason = self._pending_cancellations.pop(
                (task_id, operation_id), None
            )
            if pending_reason is not None:
                token.cancel(pending_reason)

        task_lock_acquired = False
        slot_acquired = False
        operation_started = False
        close_after: ResourceT | None = None
        try:
            self._acquire_interruptibly(managed.operation_lock, context)
            task_lock_acquired = True
            self._acquire_interruptibly(self._operation_slots, context)
            slot_acquired = True
            with self._condition:
                managed.queued_operations -= 1
                managed.active_operations += 1
                operation_started = True
            context.raise_if_stopped()
            if self._maintenance is not None:
                self._maintenance(managed.resource)
            context.raise_if_stopped()
            result = callback(managed.resource, context)
            context.raise_if_stopped()
            return result
        finally:
            with self._condition:
                if operation_started:
                    managed.active_operations -= 1
                else:
                    managed.queued_operations = max(0, managed.queued_operations - 1)
                managed.operation_tokens.pop(operation_id, None)
                managed.last_used_at = self._clock()
                if (
                    managed.state == "completing"
                    and managed.active_operations == 0
                    and managed.queued_operations == 0
                    and self._tasks.get(task_id) is managed
                ):
                    self._tasks.pop(task_id, None)
                    managed.state = "completed"
                    close_after = managed.resource
                self._condition.notify_all()
            if slot_acquired:
                self._operation_slots.release()
            if task_lock_acquired:
                managed.operation_lock.release()
            if close_after is not None:
                self._prepare_completion(close_after)
                self._close_resource(close_after)

    def cancel_operation(
        self,
        task_id: str,
        operation_id: str,
        *,
        reason: str = "operation cancelled by client",
    ) -> bool:
        with self._condition:
            managed = self._tasks.get(task_id)
            token = (
                managed.operation_tokens.get(operation_id)
                if managed is not None
                else None
            )
            if token is None:
                self._pending_cancellations[(task_id, operation_id)] = reason
                return True
            token.cancel(reason)
            self._condition.notify_all()
            return True

    def complete(self, task_id: str) -> bool:
        close_after: ResourceT | None = None
        with self._condition:
            managed = self._tasks.get(task_id)
            if managed is None:
                return False
            managed.state = "completing"
            for key in tuple(self._pending_cancellations):
                if key[0] == task_id:
                    self._pending_cancellations.pop(key, None)
            if managed.active_operations == 0 and managed.queued_operations == 0:
                self._tasks.pop(task_id, None)
                managed.state = "completed"
                close_after = managed.resource
            self._condition.notify_all()
        if close_after is not None:
            self._prepare_completion(close_after)
            self._close_resource(close_after)
        return True

    def reap(self) -> int:
        now = self._clock()
        resources: list[ResourceT] = []
        with self._condition:
            for task_id, managed in tuple(self._tasks.items()):
                if managed.active_operations or managed.queued_operations:
                    continue
                idle_expired = now - managed.last_used_at >= self.idle_timeout_seconds
                lifetime_expired = now - managed.created_at >= self.max_lifetime_seconds
                if managed.state != "active" or idle_expired or lifetime_expired:
                    self._tasks.pop(task_id, None)
                    managed.state = "reclaimed"
                    resources.append(managed.resource)
            self._condition.notify_all()
        for resource in resources:
            self._close_resource(resource)
        return len(resources)

    def status(self) -> dict[str, object]:
        self.reap()
        with self._condition:
            tasks = list(self._tasks.values())
        rendered: list[dict[str, object]] = []
        for managed in sorted(tasks, key=lambda task: task.task_id):
            try:
                resource_status = self._status_reader(managed.resource)
            except Exception as exc:
                resource_status = {
                    "status": "unavailable",
                    "error": type(exc).__name__,
                }
            rendered.append(
                {
                    "task_id": managed.task_id,
                    "state": managed.state,
                    "active_operations": managed.active_operations,
                    "queued_operations": managed.queued_operations,
                    "age_seconds": max(0.0, self._clock() - managed.created_at),
                    "idle_seconds": max(0.0, self._clock() - managed.last_used_at),
                    "resource": resource_status,
                }
            )
        return {
            "task_count": len(rendered),
            "max_tasks": self.max_tasks,
            "idle_timeout_seconds": self.idle_timeout_seconds,
            "max_lifetime_seconds": self.max_lifetime_seconds,
            "max_concurrent_operations": self.max_concurrent_operations,
            "tasks": rendered,
        }

    def close(self) -> None:
        resources: list[ResourceT] = []
        with self._condition:
            if self._closed:
                return
            self._closed = True
            self._pending_cancellations.clear()
            for managed in self._tasks.values():
                managed.state = "completing"
                for token in managed.operation_tokens.values():
                    token.cancel("runtime registry closed")
                if managed.active_operations == 0 and managed.queued_operations == 0:
                    resources.append(managed.resource)
            self._tasks = {
                task_id: managed
                for task_id, managed in self._tasks.items()
                if managed.active_operations or managed.queued_operations
            }
            self._condition.notify_all()
        for resource in resources:
            self._close_resource(resource)


@dataclass
class RequestEngineDecision:
    preference: str
    engine: str
    fallback_used: bool = False
    remote_started: bool = False

    def mark_remote_started(self) -> None:
        self.remote_started = True

    def require_engine(self, engine: str) -> None:
        if engine != self.engine:
            phase = "after remote execution started" if self.remote_started else "for this request"
            raise EngineSwitchProhibited(
                f"request engine is fixed to {self.engine}; cannot switch to {engine} {phase}"
            )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "preference": self.preference,
            "engine": self.engine,
            "fallback_used": self.fallback_used,
            "remote_started": self.remote_started,
        }


def select_request_engine(
    *,
    preference: str,
    mcp_available: bool,
    one_shot_available: bool,
) -> RequestEngineDecision:
    selected_preference = preference.strip().lower()
    if selected_preference not in {"auto", "mcp", "one-shot"}:
        raise ValueError("preference must be auto, mcp, or one-shot")
    if selected_preference in {"auto", "mcp"} and mcp_available:
        return RequestEngineDecision(selected_preference, "mcp")
    if one_shot_available:
        return RequestEngineDecision(
            selected_preference,
            "one-shot",
            fallback_used=selected_preference in {"auto", "mcp"},
        )
    raise EngineUnavailable(
        "neither MCP nor a matching one-shot Target Runtime is ready before remote execution"
    )
