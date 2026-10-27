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
import argparse
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
        **({"local_path": str(Path(_text(arguments, "local_path")).expanduser().resolve())}
           if action == "apply" else {}),
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
    return _call_runtime_mutation(
        bounded, store=store, task_id=task_id, operation_id=operation_id,
        backend_factory=backend_factory,
    )


def reconcile_runtime_mutation(
    arguments: Mapping[str, object],
    *,
    task_id: str,
    operation_id: str,
    state_dir: Path | None = None,
    backend_factory: BackendFactory | None = None,
) -> dict[str, object]:
    """Inspect and verify one existing CLI journal without starting a mutation.

    Supply the original mutation arguments and journal identities. The journal's
    checksum pins the original artifact even if the local file changed or vanished.
    These CLI identities do not identify a public Runtime Run.
    """
    store = MutationJournalStore(_state_dir(state_dir) / "mutations")
    journal = store.load(task_id, operation_id)
    if journal is None:
        raise ValueError("CLI reconciliation found no durable mutation journal; no Apply was started")
    bounded = dict(arguments)
    action = _action(bounded)
    if journal.action != ("rollback" if action == "rollback" else "live_patch"):
        raise ValueError("CLI reconciliation action differs from the original journal")
    checksum = (journal.expected_checksum or _local_sha256(bounded, action)) if action == "apply" else ""
    if _identities(bounded, action=action, local_sha256=checksum) != (task_id, operation_id):
        raise ValueError("CLI reconciliation arguments differ from the original journal identity")
    bounded["action"] = action
    bounded["intent"] = (
        "rollback" if action == "rollback" else
        (_text(bounded, "intent").lower().replace("_", "-") or "live-patch")
    )
    if action == "apply":
        bounded["artifact_sha256"] = checksum
    bounded["_runtime_effect_recovery"] = "reconcile"
    return _call_runtime_mutation(
        bounded, store=store, task_id=task_id, operation_id=operation_id,
        backend_factory=backend_factory,
    )


def _call_runtime_mutation(
    arguments: Mapping[str, object],
    *,
    store: MutationJournalStore,
    task_id: str,
    operation_id: str,
    backend_factory: BackendFactory | None,
) -> dict[str, object]:
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
                arguments,
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Reconcile an existing direct CLI mutation journal only.")
    parser.add_argument("command", choices=("reconcile",))
    parser.add_argument("--task-id", required=True, help="Original CLI journal task_id, not a public run_id")
    parser.add_argument("--operation-id", required=True, help="Original journal operation_id")
    parser.add_argument("--arguments-file", type=Path, required=True, help="Private JSON object with the original mutation arguments")
    parser.add_argument("--state-dir", type=Path, help="Original Runtime state directory")
    args = parser.parse_args()
    try:
        arguments = json.loads(args.arguments_file.read_text(encoding="utf-8"))
        if not isinstance(arguments, dict):
            raise ValueError("arguments-file must contain a JSON object")
        result = reconcile_runtime_mutation(
            arguments, task_id=args.task_id, operation_id=args.operation_id,
            state_dir=args.state_dir,
        )
    except (ValueError, TypeError, OSError, RuntimeError) as error:
        print(json.dumps({"ok": False, "error": str(error),
                          "task_id": args.task_id, "operation_id": args.operation_id,
                          "identity_kind": "cli-mutation-journal",
                          **({"journal": error.journal} if isinstance(error, RuntimeMutationFailed) else {})}))
        return 1
    journal = result.get("journal", {})
    verified = isinstance(journal, dict) and journal.get("stage") in {"verified", "rollback_verified"}
    print(json.dumps({"ok": verified, "identity_kind": "cli-mutation-journal", "result": result}))
    return 0 if verified else 1


__all__ = ["RuntimeMutationFailed", "run_runtime_mutation", "reconcile_runtime_mutation"]


if __name__ == "__main__":
    raise SystemExit(main())
