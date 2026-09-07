#!/usr/bin/env python3
"""Verify a product HPM against its immutable Plan, Attempt, and gate evidence."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import hashlib
import json
from pathlib import Path
import sys

from check_rootfs_access import debugfs_tool, image_file_bytes
from create_build_plan import atomic_write_json, file_identity, semantic_plan_id
from write_artifact_metadata import artifact_identity
from verify_hpm_containment import verify_hpm_containment


SCHEMA = "openubmc-build/verification-v1"
GATE_SCHEMA = "openubmc-build/gate-report-v1"
REQUIRED_PRODUCT_GATES = ("dependency-delta", "rootfs-access")


def load_json(path: Path) -> tuple[Path, bytes, dict[str, object]]:
    resolved = path.resolve(strict=True)
    raw = resolved.read_bytes()
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{resolved}: expected a JSON object")
    return resolved, raw, document


def digest_object(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def check(identifier: str, passed: bool, detail: str) -> dict[str, object]:
    return {
        "id": identifier,
        "status": "pass" if passed else "fail",
        "detail": detail,
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


def state_output_matches(
    state: dict[str, object],
    role: str,
    identity: dict[str, object],
) -> tuple[bool, str]:
    before = state.get("outputs_before", {}).get(role, {})
    after = state.get("outputs_after", {}).get(role, {})
    matches = all(
        identity.get(field) == after.get(field)
        for field in ("path", "sha256", "size")
    )
    changed = output_changed(before, after)
    return matches and changed, f"matches_attempt={matches} changed={changed}"


def read_product_version(
    rootfs_requirement: dict[str, object],
    version_spec: dict[str, object],
) -> tuple[str, dict[str, object]]:
    image = Path(str(rootfs_requirement.get("image_path", "")))
    identity = artifact_identity(image)
    inside_path = str(version_spec.get("inside_image_path", ""))
    if inside_path != "/etc/version.json":
        raise ValueError("unexpected_product_version_image_path")
    raw = image_file_bytes(
        debugfs_tool(rootfs_requirement),
        image,
        inside_path,
    )
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid_product_version_json") from exc
    version = ""
    if isinstance(document, dict):
        value = document.get("Version", document.get("version", ""))
        if isinstance(value, str):
            version = value.strip()
    if not version:
        raise ValueError(
            f"product version not found in {identity['path']}:{inside_path}"
        )
    if artifact_identity(image) != identity:
        raise ValueError("rootfs_image_changed_while_reading_version")
    return version, {
        **identity,
        "inside_image_path": inside_path,
        "content_sha256": hashlib.sha256(raw).hexdigest(),
    }


def verify(
    *,
    plan_path: Path,
    attempt_state_path: Path,
    artifact_path: Path,
    gate_report_paths: list[Path],
    finalization_id: str,
) -> dict[str, object]:
    plan_resolved, plan_bytes, plan = load_json(plan_path)
    state_resolved, state_bytes, state = load_json(attempt_state_path)
    checks: list[dict[str, object]] = []
    if not finalization_id:
        raise ValueError("missing_finalization_id")

    recorded_plan_id = str(plan.get("plan_id", ""))
    actual_plan_id = semantic_plan_id(plan)
    plan_sha256 = hashlib.sha256(plan_bytes).hexdigest()
    plan_ok = (
        plan.get("schema") == "openubmc-build/plan-v1"
        and plan.get("mode") == "product-artifact"
        and bool(recorded_plan_id)
        and recorded_plan_id == actual_plan_id
    )
    checks.append(
        check(
            "plan",
            plan_ok,
            f"recorded={recorded_plan_id} calculated={actual_plan_id}",
        )
    )

    attempt_id = str(state.get("attempt_id", ""))
    attempt_ok = (
        state.get("schema") == "openubmc-build/attempt-v1"
        and state.get("plan_id") == recorded_plan_id
        and state.get("plan_sha256") == plan_sha256
        and state.get("status") == "succeeded"
        and state.get("rc") == 0
        and bool(attempt_id)
        and not state.get("workspace_contamination")
        and not state.get("signal_escalated")
    )
    checks.append(
        check(
            "attempt",
            attempt_ok,
            f"status={state.get('status')} rc={state.get('rc')}",
        )
    )

    expectation = plan.get("expectations", {})
    artifact_expectation = expectation.get("artifact", {})
    expected_path = str(artifact_expectation.get("path", ""))
    expected_version = str(artifact_expectation.get("expected_version", ""))

    artifact: dict[str, object] = {}
    artifact_ok = False
    artifact_detail = ""
    try:
        artifact = artifact_identity(artifact_path.resolve(strict=True))
        state_match, state_detail = state_output_matches(state, "artifact", artifact)
        artifact_ok = artifact["path"] == expected_path and state_match
        artifact_detail = (
            f"path={artifact['path']} expected={expected_path} {state_detail}"
        )
    except Exception as exc:
        artifact_detail = str(exc)
    checks.append(check("artifact", artifact_ok, artifact_detail))

    version = ""
    version_identity: dict[str, object] = {}
    version_ok = False
    version_detail = ""
    try:
        version_spec = expectation.get("versions", {}).get("product", {})
        if not isinstance(version_spec, dict):
            raise ValueError("Plan product version evidence is not structured")
        rootfs_requirement = expectation.get("rootfs_access", {})
        if not isinstance(rootfs_requirement, dict):
            raise ValueError("Plan rootfs requirement is not structured")
        version, version_identity = read_product_version(
            rootfs_requirement,
            version_spec,
        )
        state_match, state_detail = state_output_matches(
            state,
            "rootfs_image",
            version_identity,
        )
        version_ok = (
            bool(expected_version)
            and version == expected_version
            and version_spec.get("expected") == expected_version
            and state_match
        )
        version_detail = (
            f"observed={version} expected={expected_version} {state_detail}"
        )
    except Exception as exc:
        version_detail = str(exc)
    checks.append(check("product-version", version_ok, version_detail))

    package_binding_policy = expectation.get("package_binding")
    local_only_policy = package_binding_policy == {
        "status": "package_binding_unverified",
        "upgrade_eligible": False,
    }
    containment_required = package_binding_policy == {
        "method": "openubmc-picmg-ext4-aes128cbc-gzip-tar",
        "required": True,
    }
    containment: dict[str, object] = {}
    if containment_required and artifact_ok and version_ok:
        key = plan.get("locks", {}).get("hpm_key", {})
        key_path = Path(str(key.get("path", "")))
        if key and file_identity(key_path) == key:
            containment = verify_hpm_containment(
                artifact_path,
                Path(str(version_identity["path"])),
                key_path=key_path,
                expected_artifact_sha256=str(artifact["sha256"]),
                expected_rootfs_sha256=str(version_identity["sha256"]),
            )
    containment_verified = containment.get("status") == "verified"
    package_binding_ok = local_only_policy or (containment_required and containment_verified)
    checks.append(
        check(
            "package-binding-policy",
            package_binding_ok,
            f"containment_required={containment_required} verified={containment_verified}",
        )
    )

    gate_reports: dict[str, tuple[Path, bytes, dict[str, object]]] = {}
    for raw_path in gate_report_paths:
        resolved, raw, report = load_json(raw_path)
        gate = str(report.get("gate", ""))
        if not gate:
            raise ValueError(f"{resolved}: gate report is missing gate")
        if gate in gate_reports:
            raise ValueError(f"duplicate gate report: {gate}")
        gate_reports[gate] = (resolved, raw, report)

    required_gates = tuple(expectation.get("required_gates", []))
    if required_gates != REQUIRED_PRODUCT_GATES:
        checks.append(
            check(
                "required-gates",
                False,
                f"planned={required_gates} required={REQUIRED_PRODUCT_GATES}",
            )
        )

    evidence_gates: list[dict[str, object]] = []
    for gate in REQUIRED_PRODUCT_GATES:
        record = gate_reports.get(gate)
        passed = False
        detail = "missing"
        if record:
            resolved, raw, report = record
            requirement_key = (
                "dependency_delta" if gate == "dependency-delta" else "rootfs_access"
            )
            expected_requirement_digest = digest_object(
                expectation.get(requirement_key, {})
            )
            passed = (
                report.get("schema") == GATE_SCHEMA
                and report.get("plan_id") == recorded_plan_id
                and report.get("attempt_id") == attempt_id
                and report.get("finalization_id") == finalization_id
                and report.get("status") == "pass"
                and report.get("requirements_sha256")
                == expected_requirement_digest
            )
            detail = (
                f"status={report.get('status')} "
                f"requirements={report.get('requirements_sha256')}"
            )
            if gate == "dependency-delta":
                allowed = set(expectation.get("allowed_dependency_changes", []))
                changed = set(report.get("details", {}).get("changed", []))
                unexpected = sorted(changed - allowed)
                if unexpected:
                    passed = False
                    detail += f" unexpected={unexpected}"
            else:
                requirement = expectation.get("rootfs_access", {})
                if (
                    report.get("details", {}).get("services")
                    != requirement.get("services")
                    or report.get("inputs", [{}])[0].get("path")
                    != requirement.get("image_path")
                ):
                    passed = False
                    detail += " rootfs_requirement_mismatch"
            evidence_gates.append(
                {
                    "id": gate,
                    "path": str(resolved),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        checks.append(check(gate, passed, detail))

    failed_checks = [
        str(item["id"]) for item in checks if item["status"] != "pass"
    ]
    status = "accepted" if not failed_checks else "rejected"
    return {
        "schema": SCHEMA,
        "status": status,
        "plan_id": recorded_plan_id,
        "plan_sha256": plan_sha256,
        "attempt_id": attempt_id,
        "finalization_id": finalization_id,
        "artifact": {
            **artifact,
            "expected_version": expected_version,
            "observed_version": version,
        },
        "version_evidence": version_identity,
        "package_binding": (
            "package_binding_verified" if containment_verified else "package_binding_unverified"
        ),
        "upgrade_eligible": status == "accepted" and containment_verified,
        "package_binding_proof": containment,
        "checks": checks,
        "required_checks": [
            "plan",
            "attempt",
            "artifact",
            "product-version",
            "package-binding-policy",
            *REQUIRED_PRODUCT_GATES,
        ],
        "failed_checks": failed_checks,
        "evidence": {
            "plan": {
                "path": str(plan_resolved),
                "sha256": plan_sha256,
            },
            "attempt": {
                "path": str(state_resolved),
                "sha256": hashlib.sha256(state_bytes).hexdigest(),
            },
            "gates": evidence_gates,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--attempt-state", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--gate-report", action="append", default=[])
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    print(
        "error: standalone product acceptance is retired; use "
        "scripts/finalize_product_attempt.py so gates, verification, and "
        "metadata are recomputed under the Plan locks",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
