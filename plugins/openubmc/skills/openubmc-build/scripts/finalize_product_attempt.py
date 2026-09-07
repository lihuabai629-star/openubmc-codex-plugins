#!/usr/bin/env python3
"""Finalize one product Attempt under its Plan, checkout, and output locks."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Callable, TextIO
import uuid

from create_build_plan import (
    EXECUTION_CONTRACT_FILES,
    LOCAL_LOCK_ROOT,
    atomic_write_json,
    file_identity,
    output_resource_lock,
    semantic_plan_id,
    skill_digest,
    workspace_identity,
)
from verify_product_artifact import verify
from write_artifact_metadata import artifact_identity, write_metadata


FINALIZATION_SCHEMA = "openubmc-build/finalization-v1"
_WORKSPACE_FIELDS = (
    "root",
    "git_dir",
    "git_common_dir",
    "git_head",
    "scoped_diff_sha256",
)
_SNAPSHOT_FIELDS = (
    "path",
    "status",
    "sha256",
    "size",
    "device",
    "inode",
    "mtime_ns",
    "ctime_ns",
)


def load_json(path: Path) -> tuple[Path, bytes, dict[str, object]]:
    resolved = path.resolve(strict=True)
    raw = resolved.read_bytes()
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{resolved}: expected a JSON object")
    return resolved, raw, document


def snapshot_file(path: Path) -> dict[str, object]:
    absolute = path.absolute()
    identity = artifact_identity(absolute)
    metadata = os.lstat(absolute)
    return {
        **identity,
        "status": "present",
        "device": int(metadata.st_dev),
        "inode": int(metadata.st_ino),
        "mtime_ns": int(metadata.st_mtime_ns),
        "ctime_ns": int(metadata.st_ctime_ns),
    }


def output_changed(
    before: dict[str, object],
    after: dict[str, object],
) -> bool:
    if after.get("status") != "present":
        return False
    if before.get("status") != "present":
        return True
    return before.get("sha256") != after.get("sha256")


def validate_fresh_outputs(
    plan: dict[str, object],
    state: dict[str, object],
) -> dict[str, dict[str, object]]:
    outputs = plan.get("expectations", {}).get("outputs", {})
    if set(outputs) != {"artifact", "dependency_lock", "rootfs_image"}:
        raise ValueError(f"plan_product_outputs_invalid: {sorted(outputs)}")
    current: dict[str, dict[str, object]] = {}
    for role, raw_path in outputs.items():
        observed = snapshot_file(Path(str(raw_path)))
        after = state.get("outputs_after", {}).get(role, {})
        for field in _SNAPSHOT_FIELDS:
            if observed.get(field) != after.get(field):
                raise ValueError(
                    f"output_identity_mismatch: {role}.{field}: "
                    f"attempt={after.get(field)} current={observed.get(field)}"
                )
        before = state.get("outputs_before", {}).get(role, {})
        if not output_changed(before, after):
            raise ValueError(f"stale_product_output: {role}")
        current[str(role)] = observed
    return current


def expected_output_resources(plan: dict[str, object]) -> list[dict[str, str]]:
    expectations = plan.get("expectations", {})
    resources = (
        ("artifact", expectations.get("artifact", {}).get("path", "")),
        (
            "dependency_lock",
            expectations.get("dependency_delta", {}).get("actual_path", ""),
        ),
        (
            "metadata",
            expectations.get("metadata", {}).get("path", ""),
        ),
        (
            "product_version",
            expectations.get("versions", {})
            .get("product", {})
            .get("evidence_path", ""),
        ),
        ("rootfs", expectations.get("rootfs_access", {}).get("root", "")),
    )
    if any(not path for _role, path in resources):
        raise ValueError("plan_missing_output_resource")
    return sorted(
        (
            output_resource_lock(role, Path(str(path)))
            for role, path in resources
        ),
        key=lambda item: (item["role"], item["path"]),
    )


def prepare_local_lock_root() -> None:
    LOCAL_LOCK_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = os.lstat(LOCAL_LOCK_ROOT)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ValueError(f"unsafe_local_lock_root: {LOCAL_LOCK_ROOT}")
    os.chmod(LOCAL_LOCK_ROOT, 0o700)
    output_root = LOCAL_LOCK_ROOT / "output-locks"
    output_root.mkdir(mode=0o700, exist_ok=True)
    metadata = os.lstat(output_root)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ValueError(f"unsafe_output_lock_root: {output_root}")
    os.chmod(output_root, 0o700)


def acquire_locks(specs: list[tuple[Path, str]]) -> list[TextIO]:
    handles: list[TextIO] = []
    unique: dict[Path, str] = {}
    for raw_path, contention in specs:
        unique.setdefault(raw_path.resolve(), contention)
    try:
        for path, contention in sorted(unique.items(), key=lambda item: str(item[0])):
            path.parent.mkdir(parents=True, exist_ok=True)
            handle = path.open("a+", encoding="utf-8")
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                handle.close()
                raise ValueError(f"{contention}: {path}") from exc
            handles.append(handle)
        return handles
    except Exception:
        release_locks(handles)
        raise


def release_locks(handles: list[TextIO]) -> None:
    for handle in reversed(handles):
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except (OSError, ValueError):
            pass
        try:
            handle.close()
        except (OSError, ValueError):
            pass


def verify_workspaces(plan: dict[str, object]) -> None:
    for name, planned in plan.get("workspaces", {}).items():
        mutable_paths = tuple(str(item) for item in planned.get("mutable_paths", []))
        current = workspace_identity(Path(str(planned["root"])), mutable_paths)
        for field in _WORKSPACE_FIELDS:
            if current.get(field) != planned.get(field):
                raise ValueError(f"workspace_drift: {name}.{field}")


def verify_input_locks(plan: dict[str, object]) -> None:
    for name, planned in plan.get("locks", {}).items():
        current = file_identity(Path(str(planned.get("path", ""))))
        for field in ("path", "sha256", "size", "mode"):
            if current.get(field) != planned.get(field):
                raise ValueError(f"input_lock_drift: {name}.{field}")


def run_gate(
    script: Path,
    *,
    plan_path: Path,
    state_path: Path,
    output_path: Path,
    finalization_id: str,
) -> int:
    completed = subprocess.run(
        [
            sys.executable, "-B",
            str(script),
            "--plan",
            str(plan_path),
            "--attempt-state",
            str(state_path),
            "--output",
            str(output_path),
            "--finalization-id",
            finalization_id,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode not in {0, 1}:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ValueError(f"gate_execution_failed: {script.name}: {detail}")
    return completed.returncode


def safe_evidence_path(path: Path, attempt_root: Path) -> Path:
    absolute = path.absolute()
    if absolute.parent.resolve() != attempt_root.resolve():
        raise ValueError(f"evidence_path_outside_attempt: {absolute}")
    if absolute.is_symlink():
        raise ValueError(f"refusing evidence symlink: {absolute}")
    return absolute


def safe_report_path(path: Path, reports_root: Path) -> Path:
    absolute = path.absolute()
    if absolute.parent.resolve() != reports_root.resolve():
        raise ValueError(f"report_path_outside_attempt: {absolute}")
    if absolute.is_symlink():
        raise ValueError(f"refusing report symlink: {absolute}")
    return absolute


def verify_bound_file(
    path: Path,
    expected: bytes,
    label: str,
) -> None:
    if path.is_symlink():
        raise ValueError(f"{label}_changed_during_finalization: symlink")
    try:
        current = path.read_bytes()
    except OSError as exc:
        raise ValueError(
            f"{label}_changed_during_finalization: unreadable"
        ) from exc
    if current != expected:
        raise ValueError(f"{label}_changed_during_finalization: sha256")


def commit_evidence_transaction(
    replacements: list[tuple[Path, Path]],
    *,
    postcommit_check: Callable[[], None],
    finalization_path: Path,
    finalization_document: dict[str, object],
) -> None:
    installed: list[tuple[Path, Path | None]] = []
    try:
        for staged, target in replacements:
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_symlink():
                raise ValueError(f"refusing evidence symlink: {target}")
            if target.exists() and not target.is_file():
                raise ValueError(f"evidence target is not a regular file: {target}")
            backup: Path | None = None
            if target.exists():
                backup = target.with_name(
                    f".{target.name}.openubmc-build-backup-{uuid.uuid4().hex}"
                )
                os.replace(target, backup)
            installed.append((target, backup))
            os.replace(staged, target)

        postcommit_check()
        atomic_write_json(finalization_path, finalization_document)
    except Exception as exc:
        rollback_errors: list[str] = []
        for target, backup in reversed(installed):
            try:
                target.unlink(missing_ok=True)
                if backup is not None:
                    os.replace(backup, target)
            except OSError as rollback_exc:
                rollback_errors.append(f"{target}: {rollback_exc}")
        if rollback_errors:
            raise ValueError(
                "evidence_commit_rollback_failed: " + "; ".join(rollback_errors)
            ) from exc
        raise
    else:
        for _target, backup in installed:
            if backup is not None:
                try:
                    backup.unlink(missing_ok=True)
                except OSError:
                    pass
    finally:
        for staged, _target in replacements:
            try:
                staged.unlink(missing_ok=True)
            except OSError:
                pass


def finalization(
    plan_path: Path,
    state_path: Path,
) -> dict[str, object]:
    plan_resolved, plan_bytes, plan = load_json(plan_path)
    state_resolved, state_bytes, state = load_json(state_path)
    plan_id = str(plan.get("plan_id", ""))
    plan_sha256 = hashlib.sha256(plan_bytes).hexdigest()
    if (
        plan.get("schema") != "openubmc-build/plan-v1"
        or plan.get("mode") != "product-artifact"
        or not plan_id
        or semantic_plan_id(plan) != plan_id
    ):
        raise ValueError("invalid_product_plan")
    execution = plan.get("execution", {})
    if Path(str(execution.get("plan_path", ""))).resolve() != plan_resolved:
        raise ValueError("plan_path_mismatch")
    current_contract = skill_digest(
        Path(__file__).resolve().parents[1],
        EXECUTION_CONTRACT_FILES,
    )
    if current_contract != plan.get("runner", {}).get("execution_contract_sha256"):
        raise ValueError("execution_contract_digest_mismatch")
    attempt_id = str(state.get("attempt_id", ""))
    if (
        state.get("schema") != "openubmc-build/attempt-v1"
        or state.get("plan_id") != plan_id
        or state.get("plan_sha256") != plan_sha256
        or state.get("status") != "succeeded"
        or state.get("rc") != 0
        or not attempt_id
        or state.get("workspace_contamination")
        or state.get("input_lock_drift")
        or state.get("signal_escalated")
    ):
        raise ValueError("attempt_not_eligible_for_finalization")
    run_root = Path(str(execution.get("run_root", ""))).resolve()
    expected_state = (
        run_root
        / "plans"
        / plan_id
        / "attempts"
        / attempt_id
        / "state.json"
    ).resolve()
    if state_resolved != expected_state:
        raise ValueError("attempt_state_path_mismatch")
    attempt_root = state_resolved.parent
    finalization_path = safe_evidence_path(
        attempt_root / "finalization.json",
        attempt_root,
    )
    reports_root = attempt_root / "reports"
    if reports_root.exists() and reports_root.is_symlink():
        raise ValueError(f"refusing reports symlink: {reports_root}")
    reports_root.mkdir(mode=0o700, exist_ok=True)

    planned_checkout_locks = list(execution.get("checkout_locks", []))
    expected_checkout_locks = sorted(
        {
            str(Path(str(item["git_dir"])) / "openubmc-build.lock")
            for item in plan.get("workspaces", {}).values()
        }
    )
    if planned_checkout_locks != expected_checkout_locks:
        raise ValueError("checkout_lock_mismatch")
    planned_resources = execution.get("output_resources", [])
    expected_resources = expected_output_resources(plan)
    if planned_resources != expected_resources:
        raise ValueError("output_resource_lock_mismatch")
    lock_specs = [
        (Path(path), "workspace_or_plan_already_running")
        for path in expected_checkout_locks
    ]
    lock_specs.append(
        (
            run_root / "locks" / f"plan-{plan_id}.lock",
            "workspace_or_plan_already_running",
        )
    )
    for resource in expected_resources:
        lock_specs.append(
            (
                Path(resource["lock_path"]),
                "output_resource_already_running: "
                f"{resource['role']}={resource['path']}",
            )
        )

    prepare_local_lock_root()
    handles = acquire_locks(lock_specs)
    pending_paths: list[Path] = []
    try:
        if finalization_path.exists():
            raise ValueError(
                f"finalization_already_recorded: {finalization_path}"
            )
        verify_bound_file(plan_resolved, plan_bytes, "plan")
        verify_bound_file(state_resolved, state_bytes, "attempt_state")
        verify_workspaces(plan)
        verify_input_locks(plan)
        validate_fresh_outputs(plan, state)
        finalization_id = uuid.uuid4().hex
        skill_root = Path(__file__).resolve().parents[1]
        dependency_report = safe_report_path(
            reports_root / "dependency-delta.json",
            reports_root,
        )
        rootfs_report = safe_report_path(
            reports_root / "rootfs-access.json",
            reports_root,
        )
        run_gate(
            skill_root / "scripts/check_dependency_delta.py",
            plan_path=plan_resolved,
            state_path=state_resolved,
            output_path=dependency_report,
            finalization_id=finalization_id,
        )
        run_gate(
            skill_root / "scripts/check_rootfs_access.py",
            plan_path=plan_resolved,
            state_path=state_resolved,
            output_path=rootfs_report,
            finalization_id=finalization_id,
        )
        verification_path = safe_evidence_path(
            attempt_root / "verification.json",
            attempt_root,
        )
        verification_staged = safe_evidence_path(
            attempt_root / f".verification-{finalization_id}.pending.json",
            attempt_root,
        )
        pending_paths.append(verification_staged)
        verification = verify(
            plan_path=plan_resolved,
            attempt_state_path=state_resolved,
            artifact_path=Path(
                str(plan.get("expectations", {}).get("artifact", {}).get("path", ""))
            ),
            gate_report_paths=[dependency_report, rootfs_report],
            finalization_id=finalization_id,
        )
        atomic_write_json(verification_staged, verification)

        metadata_path: Path | None = None
        metadata_staged: Path | None = None
        if verification["status"] == "accepted":
            artifact_path = Path(
                str(plan["expectations"]["artifact"]["path"])
            )
            metadata_path = Path(f"{artifact_path.resolve()}.metadata.json")
            planned_metadata_path = Path(
                str(
                    plan.get("expectations", {})
                    .get("metadata", {})
                    .get("path", metadata_path)
                )
            ).resolve()
            if planned_metadata_path != metadata_path.resolve():
                raise ValueError("metadata_path_mismatch")
            metadata_path = planned_metadata_path
            metadata_staged = safe_evidence_path(
                attempt_root / f".metadata-{finalization_id}.pending.json",
                attempt_root,
            )
            pending_paths.append(metadata_staged)
            write_metadata(
                artifact_path,
                verification_path=verification_staged,
                output_path=metadata_staged,
            )

        verify_bound_file(plan_resolved, plan_bytes, "plan")
        verify_bound_file(state_resolved, state_bytes, "attempt_state")
        verify_workspaces(plan)
        verify_input_locks(plan)
        validate_fresh_outputs(plan, state)
        verification_status = str(verification["status"])
        status = (
            ("accepted" if verification.get("upgrade_eligible") is True else "accepted_local_only")
            if verification_status == "accepted"
            else "rejected"
        )
        document: dict[str, object] = {
            "schema": FINALIZATION_SCHEMA,
            "status": status,
            "verification_status": verification_status,
            "plan_id": plan_id,
            "attempt_id": attempt_id,
            "finalization_id": finalization_id,
            "verification_path": str(verification_path),
            "verification_sha256": hashlib.sha256(
                verification_staged.read_bytes()
            ).hexdigest(),
            "gate_reports": [str(dependency_report), str(rootfs_report)],
            "package_binding": verification.get("package_binding", "package_binding_unverified"),
            "upgrade_eligible": verification.get("upgrade_eligible", False),
            "package_binding_proof": verification.get("package_binding_proof", {}),
        }
        if verification_status == "accepted":
            document.update({
                "artifact_path": verification["artifact"]["path"],
                "artifact_sha256": verification["artifact"]["sha256"],
                "product_version": verification["artifact"]["observed_version"],
                "evidence_ids": [
                    f"build-plan:{plan_sha256}",
                    f"build-attempt:{hashlib.sha256(state_bytes).hexdigest()}",
                    f"build-verification:{document['verification_sha256']}",
                ],
            })
        replacements = [(verification_staged, verification_path)]
        if metadata_path is not None and metadata_staged is not None:
            document["metadata_path"] = str(metadata_path)
            replacements.append((metadata_staged, metadata_path))

        def postcommit_check() -> None:
            verify_bound_file(plan_resolved, plan_bytes, "plan")
            verify_bound_file(state_resolved, state_bytes, "attempt_state")
            verify_workspaces(plan)
            verify_input_locks(plan)
            validate_fresh_outputs(plan, state)

        commit_evidence_transaction(
            replacements,
            postcommit_check=postcommit_check,
            finalization_path=finalization_path,
            finalization_document=document,
        )
        return {**document, "finalization_path": str(finalization_path)}
    finally:
        for pending_path in pending_paths:
            try:
                pending_path.unlink(missing_ok=True)
            except OSError:
                pass
        release_locks(handles)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--attempt-state", required=True)
    args = parser.parse_args(argv)
    try:
        result = finalization(Path(args.plan), Path(args.attempt_state))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] in {"accepted", "accepted_local_only"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
