#!/usr/bin/env python3
"""Run direct Live Patch CLI mutations through the production Target Runtime."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


from collections.abc import Callable, Mapping
import hashlib
import json
import os
from pathlib import Path
import sys


SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_ROOT = SCRIPT_DIR.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from openubmc_live_patch.runtime_backend import LivePatchMcpBackend  # noqa: E402
from openubmc_target_runtime import (  # noqa: E402
    MutationJournalStore,
    RuntimeMcpService,
)


BackendFactory = Callable[[MutationJournalStore], object]


class RuntimeMutationFailed(RuntimeError):
    """Direct CLI failure with the durable, secret-free journal attached."""

    def __init__(
        self,
        message: str,
        *,
        operation_id: str,
        journal: Mapping[str, object] | None,
    ) -> None:
        super().__init__(message)
        self.operation_id = operation_id
        self.journal = dict(journal or {})


def _state_dir(value: Path | None) -> Path:
    if value is not None:
        return value.expanduser().resolve()
    configured = os.environ.get("OPENUBMC_TARGET_RUNTIME_STATE_DIR", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path.home() / ".local" / "state" / "openubmc-target-runtime").resolve()


def _text(arguments: Mapping[str, object], name: str) -> str:
    value = arguments.get(name, "")
    if isinstance(value, Path):
        return str(value)
    return str(value).strip() if isinstance(value, (str, int)) else ""


def _boolean(
    arguments: Mapping[str, object],
    name: str,
    *,
    default: bool = False,
) -> bool:
    value = arguments.get(name, default)
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a boolean")
    return value


def _action(arguments: Mapping[str, object]) -> str:
    action = _text(arguments, "action").lower().replace("-", "_")
    if action in {"", "apply"}:
        return "apply"
    if action == "rollback":
        return action
    raise ValueError("Live Patch action must be apply or rollback")


def _local_sha256(arguments: Mapping[str, object], action: str) -> str:
    if action != "apply":
        return ""
    local = Path(_text(arguments, "local_path")).expanduser().resolve()
    if not local.is_file():
        raise ValueError(f"Live Patch local_path is unavailable: {local}")
    digest = hashlib.sha256()
    with local.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _digest(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _identities(
    arguments: Mapping[str, object],
    *,
    action: str,
    local_sha256: str,
) -> tuple[str, str]:
    selector_source = _text(arguments, "ssh_identity_file")
    selector_digest = (
        hashlib.sha256(selector_source.encode("utf-8")).hexdigest()
        if selector_source
        else ""
    )
    target = {
        "ip": _text(arguments, "ip").lower(),
        "ssh_port": int(arguments.get("ssh_port", 22)),
        "telnet_port": int(arguments.get("telnet_port", 23)),
        "ssh_user": _text(arguments, "ssh_user"),
        "ssh_user_env": _text(arguments, "ssh_user_env"),
        "ssh_password_env": _text(arguments, "ssh_password_env"),
        "ssh_identity_digest": selector_digest,
        "telnet_user": _text(arguments, "telnet_user"),
        "telnet_user_env": _text(arguments, "telnet_user_env"),
        "telnet_password_env": _text(arguments, "telnet_password_env"),
        "ssh_host_key_policy": _text(arguments, "ssh_host_key_policy")
        or "insecure",
    }
    operation = {
        "target": target,
        "action": action,
        "remote_path": _text(arguments, "remote_path"),
        "backup_path": _text(arguments, "backup_path"),
        "remove_created": _boolean(arguments, "remove_created"),
        "expected_current_sha256": _text(
            arguments,
            "expected_current_sha256",
        ).lower(),
        "backup_dir": _text(arguments, "backup_dir") or "/tmp",
        "staging_path": _text(arguments, "staging_path"),
        "local_sha256": local_sha256,
        "mode": _text(arguments, "mode") or "644",
        "restart_scope": _text(arguments, "restart_scope") or "none",
        "no_backup": _boolean(arguments, "no_backup"),
        "no_remount": _boolean(arguments, "no_remount"),
        "force_path": _boolean(arguments, "force_path"),
    }
    task_id = f"live-patch-cli-{_digest(target)[:24]}"
    label = "rollback" if action == "rollback" else "apply"
    operation_id = f"live-patch-{label}-{_digest(operation)[:24]}"
    return task_id, operation_id


def run_runtime_mutation(
    arguments: Mapping[str, object],
    *,
    state_dir: Path | None = None,
    backend_factory: BackendFactory | None = None,
) -> dict[str, object]:
    """Execute one direct CLI mutation with durable idempotency and fresh verify."""

    bounded = dict(arguments)
    action = _action(bounded)
    bounded["action"] = action
    bounded["intent"] = (
        "rollback"
        if action == "rollback"
        else (
            _text(bounded, "intent").lower().replace("_", "-")
            or "live-patch"
        )
    )
    local_sha256 = _local_sha256(bounded, action)
    task_id, operation_id = _identities(
        bounded,
        action=action,
        local_sha256=local_sha256,
    )
    root = _state_dir(state_dir)
    store = MutationJournalStore(root / "mutations")
    factory = backend_factory or (
        lambda journal_store: LivePatchMcpBackend(journal_store=journal_store)
    )
    service = RuntimeMcpService(
        factory(store),
        max_tasks=1,
        max_concurrent_operations=1,
    )
    try:
        try:
            return service.call_tool(
                "live_patch_run",
                bounded,
                task_id=task_id,
                operation_id=operation_id,
            )
        except Exception as exc:
            journal = store.load(task_id, operation_id)
            raise RuntimeMutationFailed(
                str(exc),
                operation_id=operation_id,
                journal=(journal.to_public_dict() if journal is not None else None),
            ) from exc
    finally:
        service.close()


__all__ = ["RuntimeMutationFailed", "run_runtime_mutation"]
