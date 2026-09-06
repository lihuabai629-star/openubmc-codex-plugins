#!/usr/bin/env python3
"""Write a digest-bound openUBMC HPM metadata sidecar atomically."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

from create_build_plan import semantic_plan_id


SCHEMA = "openubmc-agent-workflow/artifact-metadata-v1"
VERIFICATION_SCHEMA = "openubmc-build/verification-v1"
_STABLE_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")


def _signature(value: os.stat_result) -> tuple[int, ...]:
    return tuple(int(getattr(value, field)) for field in _STABLE_FIELDS)


def artifact_identity(path: Path) -> dict[str, object]:
    path = path.absolute()
    before_path = os.lstat(path)
    if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
        raise ValueError(f"artifact must be a regular file: {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (before_path.st_dev, before_path.st_ino):
            raise ValueError(f"artifact changed while opening: {path}")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = os.lstat(path)
    if _signature(before) != _signature(after):
        raise ValueError(f"artifact changed while hashing: {path}")
    if _signature(after) != _signature(after_path):
        raise ValueError(f"artifact path changed while hashing: {path}")
    return {
        "path": str(path),
        "sha256": digest.hexdigest(),
        "size": int(after.st_size),
    }


def evidence_bytes(entry: dict[str, object], role: str) -> tuple[Path, bytes]:
    path = Path(str(entry.get("path", ""))).resolve(strict=True)
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != entry.get("sha256"):
        raise ValueError(f"verification_evidence_changed: {role}")
    return path, raw


def write_metadata(
    artifact_path: Path,
    *,
    verification_path: Path,
    output_path: Path | None = None,
) -> dict[str, object]:
    verification_resolved = verification_path.resolve(strict=True)
    verification_bytes = verification_resolved.read_bytes()
    verification = json.loads(verification_bytes.decode("utf-8"))
    if verification.get("schema") != VERIFICATION_SCHEMA:
        raise ValueError("verification_schema_mismatch")
    if verification.get("status") != "accepted" or verification.get("failed_checks"):
        raise ValueError("verification_not_accepted")
    evidence = verification.get("evidence")
    if not isinstance(evidence, dict):
        raise ValueError("verification_missing_evidence")
    plan_path, plan_bytes = evidence_bytes(evidence.get("plan", {}), "plan")
    state_path, state_bytes = evidence_bytes(evidence.get("attempt", {}), "attempt")
    plan = json.loads(plan_bytes.decode("utf-8"))
    state = json.loads(state_bytes.decode("utf-8"))
    plan_id = str(verification.get("plan_id", "")).strip()
    attempt_id = str(verification.get("attempt_id", "")).strip()
    finalization_id = str(verification.get("finalization_id", "")).strip()
    plan_sha256 = str(verification.get("plan_sha256", "")).strip()
    if (
        plan.get("schema") != "openubmc-build/plan-v1"
        or plan.get("mode") != "product-artifact"
        or plan.get("plan_id") != plan_id
        or semantic_plan_id(plan) != plan_id
        or hashlib.sha256(plan_bytes).hexdigest() != plan_sha256
    ):
        raise ValueError("verification_plan_identity_invalid")
    if (
        state.get("schema") != "openubmc-build/attempt-v1"
        or state.get("plan_id") != plan_id
        or state.get("plan_sha256") != plan_sha256
        or state.get("attempt_id") != attempt_id
        or state.get("status") != "succeeded"
        or state.get("rc") != 0
        or not finalization_id
    ):
        raise ValueError("verification_attempt_identity_invalid")
    binding = str(verification.get("package_binding", ""))
    eligible = verification.get("upgrade_eligible")
    planned_binding = plan.get("expectations", {}).get("package_binding")
    valid_unverified = (
        binding == "package_binding_unverified"
        and eligible is False
        and planned_binding == {"status": "package_binding_unverified", "upgrade_eligible": False}
    )
    valid_verified = (
        binding == "package_binding_verified"
        and eligible is True
        and isinstance(planned_binding, dict)
        and planned_binding.get("method") == "openubmc-picmg-ext4-aes128cbc-gzip-tar"
        and planned_binding.get("required") is True
        and isinstance(verification.get("package_binding_proof"), dict)
        and verification["package_binding_proof"].get("status") == "verified"
    )
    if not (valid_unverified or valid_verified):
        raise ValueError("verification_package_binding_invalid")
    required_checks = [
        "plan",
        "attempt",
        "artifact",
        "product-version",
        "package-binding-policy",
        *plan.get("expectations", {}).get("required_gates", []),
    ]
    if verification.get("required_checks") != required_checks:
        raise ValueError("verification_required_checks_mismatch")
    checks = verification.get("checks")
    if not isinstance(checks, list):
        raise ValueError("verification_checks_invalid")
    check_ids = [item.get("id") for item in checks if isinstance(item, dict)]
    if (
        len(check_ids) != len(checks)
        or len(set(check_ids)) != len(check_ids)
        or set(check_ids) != set(required_checks)
        or any(item.get("status") != "pass" for item in checks)
    ):
        raise ValueError("verification_checks_invalid")
    gate_evidence = evidence.get("gates")
    if not isinstance(gate_evidence, list):
        raise ValueError("verification_gate_evidence_invalid")
    gate_ids: list[str] = []
    for item in gate_evidence:
        if not isinstance(item, dict):
            raise ValueError("verification_gate_evidence_invalid")
        gate_ids.append(str(item.get("id", "")))
        _, raw = evidence_bytes(item, f"gate:{item.get('id')}")
        report = json.loads(raw.decode("utf-8"))
        if (
            report.get("gate") != item.get("id")
            or report.get("plan_id") != plan_id
            or report.get("attempt_id") != attempt_id
            or report.get("finalization_id") != finalization_id
            or report.get("status") != "pass"
        ):
            raise ValueError("verification_gate_evidence_invalid")
    if gate_ids != plan.get("expectations", {}).get("required_gates", []):
        raise ValueError("verification_gate_evidence_invalid")
    verified_artifact = verification.get("artifact")
    if not isinstance(verified_artifact, dict):
        raise ValueError("verification_missing_artifact")
    verified_path = Path(str(verified_artifact.get("path", ""))).resolve()
    supplied_path = artifact_path.resolve(strict=True)
    if verified_path != supplied_path:
        raise ValueError("artifact_verification_mismatch: path")
    version = str(verified_artifact.get("observed_version", "")).strip()
    expected_version = str(verified_artifact.get("expected_version", "")).strip()
    if not version or version != expected_version:
        raise ValueError("artifact_verification_mismatch: product version")
    identity = artifact_identity(artifact_path)
    expected = str(verified_artifact.get("sha256", "")).strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise ValueError("artifact_verification_mismatch: SHA-256")
    if identity["sha256"] != expected:
        raise ValueError("artifact_verification_mismatch: SHA-256")
    if identity["size"] != verified_artifact.get("size"):
        raise ValueError("artifact_verification_mismatch: size")
    if (
        re.fullmatch(r"[0-9a-f]{64}", plan_id) is None
        or re.fullmatch(r"[0-9a-f]{64}", plan_sha256) is None
        or not attempt_id
    ):
        raise ValueError("verification_identity_invalid")
    version_evidence = verification.get("version_evidence")
    if not isinstance(version_evidence, dict):
        raise ValueError("verification_missing_version_evidence")
    current_version_evidence = artifact_identity(
        Path(str(version_evidence.get("path", "")))
    )
    if any(
        current_version_evidence.get(field) != version_evidence.get(field)
        for field in ("path", "sha256", "size")
    ):
        raise ValueError("verification_version_evidence_changed")
    if valid_verified:
        proof = verification["package_binding_proof"]
        if (
            proof.get("schema") != "openubmc-build/hpm-containment-v1"
            or proof.get("method") != planned_binding["method"]
            or any(proof.get("artifact", {}).get(field) != identity.get(field)
                   for field in ("sha256", "size"))
            or any(proof.get("rootfs", {}).get(field) != current_version_evidence.get(field)
                   for field in ("sha256", "size"))
        ):
            raise ValueError("verification_containment_identity_mismatch")
    sidecar = (
        output_path.absolute()
        if output_path is not None
        else Path(f"{identity['path']}.metadata.json")
    )
    if sidecar.is_symlink():
        raise ValueError(f"refusing to replace metadata sidecar symlink: {sidecar}")
    document = {
        "artifact": {
            "kind": "openubmc-hpm",
            "sha256": identity["sha256"],
            "size": identity["size"],
        },
        "product_version": version,
        "package_binding": binding,
        "upgrade_eligible": eligible,
        "package_binding_proof": verification.get("package_binding_proof", {}),
        "provenance": "openubmc-build",
        "schema": SCHEMA,
        "build": {
            "plan_id": plan_id,
            "plan_sha256": plan_sha256,
            "attempt_id": attempt_id,
            "finalization_id": finalization_id,
            "verification_sha256": hashlib.sha256(verification_bytes).hexdigest(),
        },
    }
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{sidecar.name}.",
        dir=sidecar.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, sidecar)
        final_identity = artifact_identity(artifact_path)
        if final_identity != identity:
            sidecar.unlink(missing_ok=True)
            raise ValueError("artifact changed before metadata commit")
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return {
        **identity,
        "metadata_path": str(sidecar),
        "product_version": version,
        "package_binding": binding,
        "upgrade_eligible": eligible,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-path", required=True)
    parser.add_argument("--verification", required=True)
    parser.parse_args(argv)
    print(
        "error: standalone product metadata creation is retired; use "
        "scripts/finalize_product_attempt.py",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
