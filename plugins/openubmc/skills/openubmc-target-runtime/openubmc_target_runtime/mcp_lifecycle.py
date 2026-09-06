"""Task-scoped MCP process ownership and lifecycle evidence."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
import json
import math
import os
from pathlib import Path
import select
import signal
import threading
import time


MCP_PROCESS_LIFECYCLE_SCHEMA = "openubmc.mcp-process-lifecycle.v1"


def _default_process_alive(process_id: int) -> bool:
    if process_id <= 1:
        return False
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        stat = Path(f"/proc/{process_id}/stat").read_text(encoding="utf-8")
        command_end = stat.rfind(")")
        fields = stat[command_end + 2 :].split() if command_end >= 0 else []
        if fields and fields[0] == "Z":
            return False
    except (OSError, UnicodeError):
        pass
    return True


def _default_process_identity(process_id: int) -> str:
    try:
        stat = Path(f"/proc/{process_id}/stat").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return "unknown"
    command_end = stat.rfind(")")
    fields = stat[command_end + 2 :].split() if command_end >= 0 else []
    return fields[19] if len(fields) > 19 else "unknown"


def _atomic_json(path: Path, value: Mapping[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(dict(value), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


class McpProcessLifecycle:
    """Persist attributable lifecycle state for one MCP stdio process."""

    def __init__(
        self,
        *,
        component: str,
        version: str,
        client: str,
        task_id: str,
        session_id: str,
        source_commit: str = "unknown-source-commit",
        model_identity: Mapping[str, object] | None = None,
        codex_identity: Mapping[str, object] | None = None,
        formal_run: bool = False,
        parent_pid: int,
        state_path: Path,
        lifecycle_root: Path,
        idle_timeout_seconds: float,
        process_id: int | None = None,
        monotonic_clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        process_alive: Callable[[int], bool] | None = None,
        process_identity: Callable[[int], str] | None = None,
    ) -> None:
        self.component = self._required(component, "component")
        self.version = self._required(version, "version")
        self.client = self._required(client, "client")
        self.task_id = self._required(task_id, "task_id")
        self.session_id = self._required(session_id, "session_id")
        self.source_commit = self._required(source_commit, "source_commit")
        self.model_identity = self._identity(model_identity, "model_identity")
        self.codex_identity = self._identity(codex_identity, "codex_identity")
        if not isinstance(formal_run, bool):
            raise ValueError("formal_run must be a boolean")
        self.formal_run = formal_run
        if isinstance(parent_pid, bool) or not isinstance(parent_pid, int) or parent_pid < 0:
            raise ValueError("parent_pid must be a non-negative integer")
        resolved_process_id = os.getpid() if process_id is None else process_id
        if (
            isinstance(resolved_process_id, bool)
            or not isinstance(resolved_process_id, int)
            or resolved_process_id <= 0
        ):
            raise ValueError("process_id must be a positive integer")
        self.parent_pid = parent_pid
        self.process_id = resolved_process_id
        self.state_path = Path(state_path).expanduser().absolute()
        self.lifecycle_root = Path(lifecycle_root).expanduser().absolute()
        if not math.isfinite(idle_timeout_seconds) or idle_timeout_seconds <= 0:
            raise ValueError("idle_timeout_seconds must be finite and positive")
        self.idle_timeout_seconds = float(idle_timeout_seconds)
        self._monotonic_clock = monotonic_clock
        self._wall_clock = wall_clock
        self._process_alive = process_alive or _default_process_alive
        self._process_identity = process_identity or _default_process_identity
        self.process_identity = self._process_identity(self.process_id)
        self.parent_identity = (
            self._process_identity(self.parent_pid)
            if self.parent_pid > 1 and self._process_alive(self.parent_pid)
            else "unknown"
        )
        self._parent_identity_verified_ever = (
            self.parent_identity != "unknown"
            and self._parent_identity_currently_verified()
        )
        self._started_monotonic = self._monotonic_clock()
        self._last_activity = self._started_monotonic
        self._started_at = self._timestamp()
        self._active_requests = 0
        self._exit_reason: str | None = None
        self._requested_exit_reason: str | None = None
        self._lock = threading.RLock()
        self._last_persisted_state = ""
        self.lifecycle_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        safe_component = "".join(
            character if character.isalnum() or character in "-." else "-"
            for character in self.component
        )
        identity_key = self.process_identity
        if identity_key == "unknown":
            identity_key = self._started_at
        safe_identity = "".join(
            character if character.isalnum() or character in "-." else "-"
            for character in identity_key
        )
        self.record_path = self.lifecycle_root / (
            f"{safe_component}-{self.process_id}-{safe_identity}.json"
        )
        self._write_record(self.status())

    @staticmethod
    def _required(value: str, name: str) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{name} must be a string")
        normalized = value.strip()
        if not normalized:
            raise ValueError(f"{name} must not be empty")
        return normalized

    @staticmethod
    def _identity(
        value: Mapping[str, object] | None,
        name: str,
    ) -> dict[str, object]:
        if value is None:
            return {}
        if not isinstance(value, Mapping):
            raise ValueError(f"{name} must be an object")
        try:
            normalized = json.loads(
                json.dumps(dict(value), ensure_ascii=True, sort_keys=True)
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be JSON serializable") from exc
        if not isinstance(normalized, dict):
            raise ValueError(f"{name} must be an object")
        return normalized

    def _timestamp(self) -> str:
        return datetime.fromtimestamp(self._wall_clock(), UTC).isoformat().replace(
            "+00:00", "Z"
        )

    def _ownership_state(self) -> str:
        if self._exit_reason is not None:
            return "stopped"
        if self.parent_pid <= 1:
            return "unknown-owner"
        try:
            parent_alive = self._process_alive(self.parent_pid)
        except OSError:
            return "unknown-owner"
        if not parent_alive:
            return "orphaned"
        current_parent_identity = self._process_identity(self.parent_pid)
        if self.parent_identity == "unknown":
            if current_parent_identity == "unknown":
                return "unknown-owner"
            self.parent_identity = current_parent_identity
        if (
            self.parent_identity != "unknown"
            and current_parent_identity == "unknown"
        ):
            return "unknown-owner"
        if (
            self.parent_identity != "unknown"
            and current_parent_identity != self.parent_identity
        ):
            return "orphaned"
        self._parent_identity_verified_ever = True
        if self.client == "unknown-client" or self.task_id == "unknown-task":
            return "unknown-owner"
        return "active" if self._active_requests else "idle"

    def _parent_identity_currently_verified(self) -> bool:
        if self.parent_pid <= 1 or self.parent_identity == "unknown":
            return False
        try:
            return self._process_alive(self.parent_pid) and (
                self._process_identity(self.parent_pid) == self.parent_identity
            )
        except OSError:
            return False

    def status(self) -> dict[str, object]:
        with self._lock:
            now = self._monotonic_clock()
            lifecycle_state = self._ownership_state()
            parent_identity_currently_verified = (
                self._parent_identity_currently_verified()
            )
            if parent_identity_currently_verified:
                self._parent_identity_verified_ever = True
            return {
                "schema": MCP_PROCESS_LIFECYCLE_SCHEMA,
                "component": self.component,
                "version": self.version,
                "client": self.client,
                "task_id": self.task_id,
                "session_id": self.session_id,
                "source_commit": self.source_commit,
                "model_identity": dict(self.model_identity),
                "codex_identity": dict(self.codex_identity),
                "formal_run": self.formal_run,
                "parent_pid": self.parent_pid,
                "parent_identity": self.parent_identity,
                "parent_identity_verified": self._parent_identity_verified_ever,
                "parent_identity_currently_verified": (
                    parent_identity_currently_verified
                ),
                "process_id": self.process_id,
                "process_identity": self.process_identity,
                "start_time": self._started_at,
                "updated_at": self._timestamp(),
                "state_path": str(self.state_path),
                "runtime_state_root": str(self.state_path),
                "lifecycle_state": lifecycle_state,
                "active_requests": self._active_requests,
                "idle_seconds": max(0.0, now - self._last_activity),
                "idle_timeout_seconds": self.idle_timeout_seconds,
                "shutdown_requested": self._requested_exit_reason,
                "exit_reason": self._exit_reason,
            }

    def attribute(
        self,
        *,
        client: str | None = None,
        task_id: str | None = None,
        session_id: str | None = None,
    ) -> None:
        """Fill unknown ownership fields from the first attributable request."""

        with self._lock:
            changed = False
            if self.client == "unknown-client" and client is not None:
                self.client = self._required(client, "client")
                changed = True
            if self.task_id == "unknown-task" and task_id is not None:
                self.task_id = self._required(task_id, "task_id")
                changed = True
            if self.session_id == "unknown-session" and session_id is not None:
                self.session_id = self._required(session_id, "session_id")
                changed = True
            if changed:
                self._write_record(self.status())

    @contextmanager
    def request(self):
        """Mark one public MCP request active until its response is complete."""

        self.begin_request()
        try:
            yield
        finally:
            self.end_request()

    def begin_request(self) -> None:
        """Keep one accepted request active until its response is flushed."""

        with self._lock:
            reason = self._exit_reason or self._requested_exit_reason
            if reason is not None:
                raise RuntimeError(f"MCP process is shutting down: {reason}")
            self._active_requests += 1
            self._last_activity = self._monotonic_clock()
            self._write_record(self.status())

    def end_request(self) -> None:
        """Finish one request after its response no longer depends on the process."""

        with self._lock:
            if self._active_requests <= 0:
                raise RuntimeError("cannot finish an inactive MCP request")
            self._active_requests -= 1
            self._last_activity = self._monotonic_clock()
            self._write_record(self.status())

    def exit_reason_if_due(self) -> str | None:
        """Return and persist a safe process-exit reason when ownership expires."""

        with self._lock:
            if self._exit_reason is not None:
                return self._exit_reason
            status = self.status()
            if self._active_requests:
                if (
                    status["lifecycle_state"] == "orphaned"
                    and self._requested_exit_reason is None
                ):
                    self._requested_exit_reason = "parent-exited"
                    status = self.status()
                if status["lifecycle_state"] != self._last_persisted_state:
                    self._write_record(status)
                elif self._requested_exit_reason is not None:
                    self._write_record(status)
                return None
            lifecycle_state = status["lifecycle_state"]
            if self._requested_exit_reason is not None:
                reason = self._requested_exit_reason
            elif lifecycle_state == "orphaned":
                reason = "parent-exited"
            elif (
                lifecycle_state == "idle"
                and float(status["idle_seconds"]) >= self.idle_timeout_seconds
            ):
                reason = "idle-timeout"
            else:
                if status["lifecycle_state"] != self._last_persisted_state:
                    self._write_record(status)
                return None
            self._exit_reason = reason
            self._requested_exit_reason = None
            self._write_record(self.status())
            return reason

    def request_exit(self, reason: str) -> None:
        """Request shutdown without interrupting an active MCP request."""

        normalized = self._required(reason, "exit_reason")
        with self._lock:
            if self._exit_reason is None and self._requested_exit_reason is None:
                self._requested_exit_reason = normalized
                self._write_record(self.status())

    def request_task_closeout(self) -> None:
        """Request deterministic task closeout without interrupting responses."""

        self.request_exit("task-closeout")

    @property
    def shutdown_requested(self) -> bool:
        with self._lock:
            return self._requested_exit_reason is not None

    def record_exit(self, reason: str) -> None:
        """Persist a terminal reason after all active requests have drained."""

        normalized = self._required(reason, "exit_reason")
        with self._lock:
            if self._active_requests:
                raise RuntimeError("cannot stop an MCP process with active requests")
            if self._exit_reason is None:
                self._exit_reason = normalized
            self._write_record(self.status())

    def _write_record(self, status: dict[str, object]) -> None:
        _atomic_json(self.record_path, status)
        self._last_persisted_state = str(status["lifecycle_state"])


def _read_lifecycle_records(lifecycle_root: Path) -> list[tuple[Path, dict[str, object]]]:
    root = Path(lifecycle_root).expanduser().absolute()
    records: list[tuple[Path, dict[str, object]]] = []
    if not root.is_dir():
        return records
    for path in sorted(root.glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict) or value.get("schema") != MCP_PROCESS_LIFECYCLE_SCHEMA:
            continue
        records.append((path, value))
    return records


def inspect_mcp_process_records(
    lifecycle_root: Path,
    *,
    process_alive: Callable[[int], bool] = _default_process_alive,
    process_identity: Callable[[int], str] = _default_process_identity,
) -> list[dict[str, object]]:
    """Return current ownership status without trusting stale recorded state."""

    statuses: list[dict[str, object]] = []
    for path, record in _read_lifecycle_records(lifecycle_root):
        try:
            process_id = int(record["process_id"])
            parent_pid = int(record["parent_pid"])
            active_requests = int(record.get("active_requests", 0))
        except (KeyError, TypeError, ValueError):
            continue
        running = process_alive(process_id)
        recorded_identity = str(record.get("process_identity", "unknown"))
        current_identity = process_identity(process_id) if running else "unknown"
        identity_verified = (
            running
            and recorded_identity != "unknown"
            and current_identity == recorded_identity
        )
        parent_identity = str(record.get("parent_identity", "unknown"))
        owner_known = all(
            isinstance(record.get(field), str)
            and str(record[field]).strip()
            and not str(record[field]).startswith("unknown-")
            for field in ("client", "task_id", "session_id")
        )
        parent_identity_currently_verified = False
        if parent_pid > 1 and parent_identity != "unknown" and process_alive(parent_pid):
            parent_identity_currently_verified = (
                process_identity(parent_pid) == parent_identity
            )
        parent_identity_verified = (
            record.get("parent_identity_verified") is True
            or parent_identity_currently_verified
        )
        ownership_identity_bound = (
            identity_verified
            and owner_known
            and parent_pid > 1
            and parent_identity != "unknown"
            and parent_identity_verified
        )
        if not running:
            lifecycle_state = "stopped"
        elif parent_pid <= 1 or not identity_verified:
            lifecycle_state = "unknown-owner"
        elif not process_alive(parent_pid):
            lifecycle_state = "orphaned"
        elif parent_identity != "unknown":
            current_parent_identity = process_identity(parent_pid)
            if current_parent_identity == "unknown":
                lifecycle_state = "unknown-owner"
            elif current_parent_identity != parent_identity:
                lifecycle_state = "orphaned"
            elif not owner_known:
                lifecycle_state = "unknown-owner"
            else:
                lifecycle_state = "active" if active_requests else "idle"
        elif parent_identity == "unknown" or not owner_known:
            lifecycle_state = "unknown-owner"
        else:
            lifecycle_state = "active" if active_requests else "idle"
        shutdown_requested = record.get("shutdown_requested")
        exit_reason = record.get("exit_reason")
        if running and exit_reason is not None:
            shutdown_requested = shutdown_requested or exit_reason
            exit_reason = None
        statuses.append(
            {
                **record,
                "record_path": str(path),
                "process_running": running,
                "identity_verified": identity_verified,
                "parent_identity_verified": parent_identity_verified,
                "parent_identity_currently_verified": (
                    parent_identity_currently_verified
                ),
                "ownership_identity_bound": ownership_identity_bound,
                "lifecycle_state": lifecycle_state,
                "shutdown_requested": shutdown_requested,
                "exit_reason": exit_reason,
            }
        )
    return statuses


def cleanup_confirmed_orphaned_mcp_processes(
    lifecycle_root: Path,
    *,
    task_id: str,
    session_id: str,
    process_alive: Callable[[int], bool] = _default_process_alive,
    process_identity: Callable[[int], str] = _default_process_identity,
) -> list[int]:
    """Terminate only idle live processes whose owner death is confirmed."""

    cleaned: list[int] = []
    for status in inspect_mcp_process_records(
        lifecycle_root,
        process_alive=process_alive,
        process_identity=process_identity,
    ):
        process_id = int(status["process_id"])
        if (
            status.get("task_id") != task_id
            or status.get("session_id") != session_id
            or process_id == os.getpid()
            or status["lifecycle_state"] != "orphaned"
            or status["identity_verified"] is not True
            or status["ownership_identity_bound"] is not True
            or int(status.get("active_requests", 0)) != 0
        ):
            continue
        if (
            not process_alive(process_id)
            or process_identity(process_id) != status["process_identity"]
        ):
            continue
        try:
            process_handle = os.pidfd_open(process_id, 0)
        except (AttributeError, OSError):
            continue
        try:
            if process_identity(process_id) != status["process_identity"]:
                continue
            latest_status = next(
                (
                    item
                    for item in inspect_mcp_process_records(
                        lifecycle_root,
                        process_alive=process_alive,
                        process_identity=process_identity,
                    )
                    if item.get("record_path") == status["record_path"]
                ),
                None,
            )
            if latest_status is None:
                continue
            if (
                latest_status.get("lifecycle_state") != "orphaned"
                or latest_status.get("ownership_identity_bound") is not True
                or int(latest_status.get("process_id", -1)) != process_id
                or str(latest_status.get("process_identity", "unknown"))
                != status["process_identity"]
                or int(latest_status.get("active_requests", 0)) != 0
            ):
                continue
            signal.pidfd_send_signal(process_handle, signal.SIGTERM)
            poller = select.poll()
            poller.register(process_handle, select.POLLIN)
            exited = bool(poller.poll(1000))
        except (AttributeError, OSError, TypeError, ValueError):
            continue
        finally:
            os.close(process_handle)
        if exited:
            cleaned.append(process_id)
    return cleaned
