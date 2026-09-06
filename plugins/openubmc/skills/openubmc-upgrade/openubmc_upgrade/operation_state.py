"""Durable, secret-free evidence for one Upgrade operation."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import threading
from typing import Mapping


_SCHEMA = "openubmc.upgrade.v1/operation-state"


class UpgradeOperationStateStore:
    """Persist protocol and WebUI task correlation beside mutation journals."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).expanduser().resolve() / "upgrade-operation-state"
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            self.root.chmod(0o700)
        except OSError:
            pass
        self._lock = threading.RLock()

    @staticmethod
    def _key(task_id: str, operation_id: str) -> str:
        return hashlib.sha256(
            f"{task_id}\0{operation_id}".encode("utf-8")
        ).hexdigest()

    def _path(self, task_id: str, operation_id: str) -> Path:
        return self.root / f"{self._key(task_id, operation_id)}.json"

    def load(self, task_id: str, operation_id: str) -> dict[str, object] | None:
        path = self._path(task_id, operation_id)
        with self._lock:
            try:
                raw = path.read_text(encoding="utf-8")
            except FileNotFoundError:
                return None
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Upgrade operation state is corrupt") from exc
        if not isinstance(value, Mapping) or value.get("schema") != _SCHEMA:
            raise RuntimeError("Upgrade operation state has an unsupported schema")
        if value.get("task_id") != task_id or value.get("operation_id") != operation_id:
            raise RuntimeError("Upgrade operation state identity does not match")
        return dict(value)

    def initialize(
        self,
        *,
        task_id: str,
        operation_id: str,
        protocol: str,
        verification_mode: str,
        artifact_file_name: str,
        mutation_fingerprint: str,
    ) -> dict[str, object]:
        if protocol not in {"redfish", "webui"}:
            raise ValueError("Upgrade operation state requires a resolved protocol")
        if verification_mode not in {"manager-version", "task-completion"}:
            raise ValueError(
                "Upgrade operation state requires a resolved verification mode"
            )
        value: dict[str, object] = {
            "schema": _SCHEMA,
            "task_id": task_id,
            "operation_id": operation_id,
            "protocol": protocol,
            "verification_mode": verification_mode,
            "artifact_file_name": artifact_file_name,
            "mutation_fingerprint": mutation_fingerprint,
            "baseline_task_identities": None,
            "upload_accepted": False,
            "task_id_remote": "",
            "task_uri": "",
            "cleanup": None,
        }
        self._save(value)
        return value

    def update(
        self,
        *,
        task_id: str,
        operation_id: str,
        values: Mapping[str, object],
    ) -> dict[str, object]:
        with self._lock:
            current = self.load(task_id, operation_id)
            if current is None:
                raise RuntimeError("Upgrade operation state was not initialized")
            for name in (
                "schema",
                "task_id",
                "operation_id",
                "protocol",
                "verification_mode",
                "artifact_file_name",
                "mutation_fingerprint",
            ):
                if name in values and values[name] != current.get(name):
                    raise RuntimeError(
                        f"Upgrade operation state cannot change immutable field {name}"
                    )
            current.update(values)
            self._save(current)
            return current

    def _save(self, value: Mapping[str, object]) -> None:
        task_id = str(value.get("task_id", ""))
        operation_id = str(value.get("operation_id", ""))
        if not task_id or not operation_id:
            raise ValueError("Upgrade operation state requires task and operation IDs")
        payload = json.dumps(
            dict(value),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
        destination = self._path(task_id, operation_id)
        temporary = destination.with_name(
            f".{destination.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        with self._lock:
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    stat.S_IRUSR | stat.S_IWUSR,
                )
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, destination)
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass


__all__ = ["UpgradeOperationStateStore"]
