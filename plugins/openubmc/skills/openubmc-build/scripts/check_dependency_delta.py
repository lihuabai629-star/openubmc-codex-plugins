#!/usr/bin/env python3
"""Compare two Conan lock files against a build plan dependency allowlist."""

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

from create_build_plan import atomic_write_json


SCHEMA = "openubmc-build/gate-report-v1"
REQUIREMENT_ROLES = (
    "requires",
    "build_requires",
    "python_requires",
    "config_requires",
)


def load_object(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    document = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{resolved}: expected a JSON object")
    return document


def lock_components(
    document: dict[str, object],
) -> dict[str, dict[str, set[str]]]:
    missing = [role for role in REQUIREMENT_ROLES if role not in document]
    invalid = [
        role
        for role in REQUIREMENT_ROLES
        if role in document
        and (
            not isinstance(document[role], list)
            or any(not isinstance(item, str) for item in document[role])
        )
    ]
    if missing or invalid:
        detail = ", ".join((*missing, *invalid))
        raise ValueError(f"incomplete_resolved_lock: {detail}")
    result: dict[str, dict[str, set[str]]] = {}
    for field in REQUIREMENT_ROLES:
        values = document[field]
        role_result: dict[str, set[str]] = {}
        for raw in values:
            if "/" not in raw:
                raise ValueError(
                    f"invalid_resolved_lock_reference: {field}: {raw}"
                )
            normalized = raw.split("%", 1)[0]
            name = normalized.split("/", 1)[0].lower()
            role_result.setdefault(name, set()).add(normalized)
        result[field] = role_result
    return result


def file_input(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    return {
        "path": str(resolved),
        "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
        "size": resolved.stat().st_size,
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--attempt-state", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--finalization-id")
    args = parser.parse_args(argv)
    try:
        plan_path = Path(args.plan)
        state_path = Path(args.attempt_state)
        plan = load_object(plan_path)
        state = load_object(state_path)
        plan_id = str(plan.get("plan_id", ""))
        attempt_id = str(state.get("attempt_id", ""))
        if not plan_id or state.get("plan_id") != plan_id or not attempt_id:
            raise ValueError("plan_attempt_identity_mismatch")
        if state.get("status") != "succeeded" or state.get("rc") != 0:
            raise ValueError("attempt_not_succeeded")
        requirement = plan.get("expectations", {}).get("dependency_delta", {})
        baseline_expected = requirement.get("baseline", {})
        baseline_path = Path(str(baseline_expected.get("path", "")))
        actual_path = Path(str(requirement.get("actual_path", "")))
        baseline_input = file_input(baseline_path)
        for field in ("path", "sha256", "size"):
            if baseline_input[field] != baseline_expected.get(field):
                raise ValueError(f"dependency_baseline_drift: {field}")
        before = state.get("outputs_before", {}).get("dependency_lock", {})
        after = state.get("outputs_after", {}).get("dependency_lock", {})
        actual_input = file_input(actual_path)
        for field in ("path", "sha256", "size"):
            if actual_input[field] != after.get(field):
                raise ValueError(f"dependency_output_identity_mismatch: {field}")
        if not output_changed(before, after):
            raise ValueError("stale_dependency_output")
        allowed = {
            str(name).lower()
            for name in plan.get("expectations", {}).get(
                "allowed_dependency_changes",
                [],
            )
        }
        planned_roles = tuple(requirement.get("roles", []))
        if planned_roles != REQUIREMENT_ROLES:
            raise ValueError(
                "dependency_role_contract_mismatch: "
                f"planned={planned_roles} required={REQUIREMENT_ROLES}"
            )
        baseline = lock_components(load_object(baseline_path))
        actual = lock_components(load_object(actual_path))
        changes_by_role: dict[str, dict[str, dict[str, list[str]]]] = {}
        changed_names: set[str] = set()
        for role in REQUIREMENT_ROLES:
            role_changes: dict[str, dict[str, list[str]]] = {}
            names = sorted(set(baseline[role]) | set(actual[role]))
            for name in names:
                before_refs = baseline[role].get(name, set())
                after_refs = actual[role].get(name, set())
                if before_refs == after_refs:
                    continue
                changed_names.add(name)
                role_changes[name] = {
                    "before": sorted(before_refs),
                    "after": sorted(after_refs),
                }
            changes_by_role[role] = role_changes
        changed = sorted(changed_names)
        unexpected = sorted(set(changed) - allowed)
        changes = {
            name: {
                "roles": [
                    role
                    for role in REQUIREMENT_ROLES
                    if name in changes_by_role[role]
                ],
            }
            for name in changed
        }
        status = "pass" if not unexpected else "fail"
        report = {
            "schema": SCHEMA,
            "gate": "dependency-delta",
            "plan_id": plan_id,
            "attempt_id": attempt_id,
            "status": status,
            "inputs": [
                {"role": "baseline", **baseline_input},
                {"role": "actual", **actual_input},
            ],
            "requirements_sha256": hashlib.sha256(
                json.dumps(
                    requirement,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
            "summary": (
                "dependency changes match the plan allowlist"
                if status == "pass"
                else "unexpected dependency changes detected"
            ),
            "details": {
                "allowed": sorted(allowed),
                "changed": changed,
                "unexpected": unexpected,
                "changes": changes,
                "changes_by_role": changes_by_role,
            },
        }
        if args.finalization_id:
            report["finalization_id"] = args.finalization_id
        atomic_write_json(Path(args.output), report)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": report["status"],
                "report_path": str(Path(args.output).resolve()),
                "unexpected": report["details"]["unexpected"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
