"""Private same-host equality proof for explicitly reusable local build evidence.

This is an optimization of a completed Attempt, never a source of fresh target
verification. Callers hold the existing Plan, checkout, and output locks.
"""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import hashlib
import hmac
import json
import os
from pathlib import Path
import stat

from create_build_plan import atomic_write_json
from write_artifact_metadata import artifact_identity


def enabled(plan: dict[str, object]) -> bool:
    declaration = plan.get("evidence_reuse", {})
    return (plan.get("mode") in {"validate", "component-package"}
            and declaration.get("scope") == "local-only"
            and declaration.get("kind") in {"compile", "official-ut"}
            and "toolchain" in plan.get("locks", {})
            and bool(plan.get("expectations", {}).get("outputs")))


def _key(plan_root: Path, *, create: bool) -> bytes:
    path = plan_root / ".evidence-reuse-key"
    flags = os.O_CLOEXEC | os.O_NOFOLLOW
    if create and not path.exists():
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | flags, 0o600)
        try:
            os.write(descriptor, os.urandom(32))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    descriptor = os.open(path, os.O_RDONLY | flags)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise ValueError("unsafe_evidence_reuse_key")
        value = os.read(descriptor, 33)
        if len(value) != 32:
            raise ValueError("invalid_evidence_reuse_key")
        return value
    finally:
        os.close(descriptor)


def _mac(key: bytes, value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hmac.new(key, encoded, hashlib.sha256).hexdigest()


def begin(state_path: Path, plan: dict[str, object]) -> None:
    """Invalidate the previous cache hint before an Attempt can execute.

    The hint cannot prove success; it only prevents falling back to an older
    Attempt when a later record is missing, interrupted, failed, or backdated.
    """
    if not enabled(plan):
        return
    plan_root = state_path.parent.parent.parent
    hint_path = plan_root / "latest-evidence-attempt.json"
    hint_path.unlink(missing_ok=True)
    try:
        key = _key(plan_root, create=True)
        hint = {"attempt_id": state_path.parent.name, "plan_id": plan["plan_id"]}
        atomic_write_json(hint_path, {"hint": hint, "mac": _mac(key, hint)})
    except (OSError, ValueError):
        return


def _proof(state_path: Path, state: dict[str, object], plan: dict[str, object],
           environment: dict[str, str], key: bytes) -> dict[str, object]:
    root = state_path.parent
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not boot_id:
        raise ValueError("unobservable_local_environment")
    outputs = {}
    for role, path in plan["expectations"]["outputs"].items():
        identity = artifact_identity(Path(path))
        expected = state.get("outputs_after", {}).get(role, {})
        if any(identity[field] != expected.get(field) for field in ("path", "sha256", "size")):
            raise ValueError("completed_evidence_output_drift")
        outputs[role] = {**identity, "mode": stat.S_IMODE(os.lstat(path).st_mode)}
    return {
        "schema": "openubmc-build/completed-evidence-v1",
        "environment": _mac(key, {"environment": environment, "boot_id": boot_id,
                                  "system": tuple(os.uname()), "uid": os.geteuid()}),
        "state": artifact_identity(state_path),
        "command": artifact_identity(root / "command.json"),
        "log": artifact_identity(root / "build.log"),
        "outputs": outputs,
    }


def seal(state_path: Path, state: dict[str, object], plan: dict[str, object],
         environment: dict[str, str]) -> None:
    if not enabled(plan) or state.get("status") != "succeeded":
        return
    try:
        key = _key(state_path.parent.parent.parent, create=True)
        proof = _proof(state_path, state, plan, environment, key)
        atomic_write_json(state_path.parent / "completed-evidence.json", {"proof": proof, "mac": _mac(key, proof)})
    except (OSError, ValueError, KeyError, TypeError):
        # Missing output/private proof never invalidates a real command result,
        # but it can never authorize reuse.
        return


def find_completed(attempts_root: Path, plan: dict[str, object], plan_sha256: str,
                   environment: dict[str, str]) -> tuple[Path, dict[str, object]] | None:
    if not enabled(plan):
        return None
    try:
        key = _key(attempts_root.parent, create=False)
        latest = json.loads((attempts_root.parent / "latest-evidence-attempt.json").read_text())
        hint = latest["hint"]
        attempt_id = hint["attempt_id"]
        if (not isinstance(attempt_id, str) or len(attempt_id) != 32
                or any(character not in "0123456789abcdef" for character in attempt_id)
                or hint.get("plan_id") != plan["plan_id"]
                or not hmac.compare_digest(str(latest.get("mac", "")), _mac(key, hint))):
            return None
        state_path = attempts_root / attempt_id / "state.json"
        state = json.loads(state_path.read_text())
        if (state.get("status") != "succeeded" or state.get("rc") != 0
                or state.get("process_rc") != 0 or not state.get("finished_at")
                or state.get("plan_id") != plan["plan_id"]
                or state.get("plan_sha256") != plan_sha256
                or state.get("attempt_id") != state_path.parent.name):
            return None
        saved = json.loads((state_path.parent / "completed-evidence.json").read_text())
        proof = _proof(state_path, state, plan, environment, key)
        if saved.get("proof") != proof or not hmac.compare_digest(str(saved.get("mac", "")), _mac(key, proof)):
            return None
        return state_path, state
    except (OSError, ValueError, KeyError, TypeError):
        return None
