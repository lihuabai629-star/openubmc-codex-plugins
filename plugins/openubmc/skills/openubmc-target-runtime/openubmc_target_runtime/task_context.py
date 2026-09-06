"""Bounded durable task context for MCP process restart recovery."""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import threading
import time
import uuid


TASK_CONTEXT_SCHEMA = "openubmc-target-runtime.task-context"
TASK_CONTEXT_VERSION = 1


class TaskContextTooLarge(ValueError):
    """Raised when one task context exceeds its configured durable bound."""


class TaskContextStore:
    """Persist secret-free task context with atomic writes, TTL, and LRU bounds."""

    def __init__(
        self,
        root: Path,
        *,
        ttl_seconds: float = 7 * 24 * 60 * 60,
        max_entries: int = 128,
        max_state_bytes: int = 256 * 1024,
        touch_interval_seconds: float = 300,
        clock=time.time,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        if max_state_bytes < 1024:
            raise ValueError("max_state_bytes must be at least 1024")
        if touch_interval_seconds < 0:
            raise ValueError("touch_interval_seconds must be non-negative")
        self.root = Path(root)
        self.ttl_seconds = float(ttl_seconds)
        self.max_entries = int(max_entries)
        self.max_state_bytes = int(max_state_bytes)
        self.touch_interval_seconds = float(touch_interval_seconds)
        self._clock = clock
        self._lock = threading.RLock()
        self._recent_access: dict[Path, float] = {}

    @staticmethod
    def _task_digest(task_id: str) -> str:
        return hashlib.sha256(task_id.encode("utf-8")).hexdigest()

    def _path_for(self, task_id: str) -> Path:
        return self.root / f"{self._task_digest(task_id)}.json"

    @staticmethod
    def _number(value: object, default: float) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return default
        return float(value)

    def _normalize(
        self,
        raw: object,
        *,
        expected_task_id: str | None = None,
    ) -> dict[str, object] | None:
        if not isinstance(raw, Mapping):
            return None
        if raw.get("schema") != TASK_CONTEXT_SCHEMA:
            return None
        version = raw.get("version")
        if isinstance(version, bool) or version not in {0, TASK_CONTEXT_VERSION}:
            return None
        task_id = raw.get("task_id")
        context = raw.get("context")
        if not isinstance(task_id, str) or not task_id:
            return None
        if expected_task_id is not None and task_id != expected_task_id:
            return None
        if not isinstance(context, Mapping):
            return None
        now = self._clock()
        created_at = self._number(raw.get("created_at"), now)
        accessed_at = self._number(
            raw.get("accessed_at"),
            self._number(raw.get("updated_at"), created_at),
        )
        return {
            "schema": TASK_CONTEXT_SCHEMA,
            "version": TASK_CONTEXT_VERSION,
            "task_id": task_id,
            "created_at": created_at,
            "accessed_at": accessed_at,
            "context": dict(context),
            "_needs_rewrite": (
                version != TASK_CONTEXT_VERSION or "accessed_at" not in raw
            ),
        }

    def _read_path(
        self,
        path: Path,
        *,
        expected_task_id: str | None = None,
    ) -> dict[str, object] | None:
        try:
            if path.stat().st_size > self.max_state_bytes:
                return None
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        return self._normalize(raw, expected_task_id=expected_task_id)

    def _encoded_document(
        self,
        task_id: str,
        context: Mapping[str, object],
        *,
        created_at: float,
        accessed_at: float,
    ) -> bytes:
        document = {
            "schema": TASK_CONTEXT_SCHEMA,
            "version": TASK_CONTEXT_VERSION,
            "task_id": task_id,
            "created_at": created_at,
            "accessed_at": accessed_at,
            "context": dict(context),
        }
        encoded = json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > self.max_state_bytes:
            raise TaskContextTooLarge(
                f"task context requires {len(encoded)} bytes; "
                f"limit is {self.max_state_bytes}"
            )
        return encoded

    def _write_atomic(self, path: Path, encoded: bytes) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        temporary = self.root / f".{path.name}.{uuid.uuid4().hex}.tmp"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            try:
                directory_descriptor = os.open(self.root, os.O_RDONLY)
            except OSError:
                directory_descriptor = None
            if directory_descriptor is not None:
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
        finally:
            try:
                temporary.unlink()
            except OSError:
                pass

    @staticmethod
    def _discard(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass

    def _reap_locked(self, *, keep: Path | None = None) -> int:
        if not self.root.is_dir():
            return 0
        now = self._clock()
        retained: list[tuple[float, Path]] = []
        removed = 0
        for path in self.root.glob("*.json"):
            document = self._read_path(path)
            if document is None:
                self._discard(path)
                self._recent_access.pop(path, None)
                removed += 1
                continue
            accessed_at = max(
                float(document["accessed_at"]),
                self._recent_access.get(path, float("-inf")),
            )
            if path != keep and now - accessed_at >= self.ttl_seconds:
                self._discard(path)
                self._recent_access.pop(path, None)
                removed += 1
                continue
            retained.append((accessed_at, path))
        excess = max(0, len(retained) - self.max_entries)
        for _accessed_at, path in sorted(retained, key=lambda item: item[0]):
            if excess <= 0:
                break
            if path == keep:
                continue
            self._discard(path)
            self._recent_access.pop(path, None)
            removed += 1
            excess -= 1
        return removed

    def save(self, task_id: str, context: Mapping[str, object]) -> None:
        if not isinstance(task_id, str) or not task_id.strip():
            raise ValueError("task_id must not be empty")
        if not isinstance(context, Mapping):
            raise TypeError("task context must be an object")
        task_id = task_id.strip()
        with self._lock:
            path = self._path_for(task_id)
            try:
                current = self._read_path(path, expected_task_id=task_id)
                now = self._clock()
                created_at = (
                    float(current["created_at"])
                    if current is not None
                    else now
                )
                encoded = self._encoded_document(
                    task_id,
                    context,
                    created_at=created_at,
                    accessed_at=now,
                )
                self._write_atomic(path, encoded)
            except Exception:
                self._discard(path)
                self._recent_access.pop(path, None)
                raise
            self._recent_access[path] = now
            self._reap_locked(keep=path)

    def load(self, task_id: str) -> dict[str, object] | None:
        if not isinstance(task_id, str) or not task_id.strip():
            raise ValueError("task_id must not be empty")
        task_id = task_id.strip()
        with self._lock:
            self._reap_locked()
            path = self._path_for(task_id)
            document = self._read_path(path, expected_task_id=task_id)
            if document is None:
                self._discard(path)
                self._recent_access.pop(path, None)
                return None
            now = self._clock()
            accessed_at = max(
                float(document["accessed_at"]),
                self._recent_access.get(path, float("-inf")),
            )
            if now - accessed_at >= self.ttl_seconds:
                self._discard(path)
                self._recent_access.pop(path, None)
                return None
            self._recent_access[path] = now
            if (
                bool(document.get("_needs_rewrite"))
                or now - float(document["accessed_at"])
                >= self.touch_interval_seconds
            ):
                encoded = self._encoded_document(
                    task_id,
                    document["context"],
                    created_at=float(document["created_at"]),
                    accessed_at=now,
                )
                self._write_atomic(path, encoded)
            return dict(document["context"])

    def delete(self, task_id: str) -> bool:
        if not isinstance(task_id, str) or not task_id.strip():
            raise ValueError("task_id must not be empty")
        path = self._path_for(task_id.strip())
        with self._lock:
            existed = path.exists()
            self._discard(path)
            self._recent_access.pop(path, None)
            return existed

    def reap(self) -> int:
        with self._lock:
            return self._reap_locked()

    def status(self) -> dict[str, object]:
        with self._lock:
            self._reap_locked()
            entry_count = (
                sum(1 for _path in self.root.glob("*.json"))
                if self.root.is_dir()
                else 0
            )
        return {
            "enabled": True,
            "schema": TASK_CONTEXT_SCHEMA,
            "version": TASK_CONTEXT_VERSION,
            "entry_count": entry_count,
            "ttl_seconds": self.ttl_seconds,
            "max_entries": self.max_entries,
            "max_state_bytes": self.max_state_bytes,
            "touch_interval_seconds": self.touch_interval_seconds,
        }
