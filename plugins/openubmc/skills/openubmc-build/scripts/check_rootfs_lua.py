#!/usr/bin/env python3
"""Check Lua source syntax from the Plan-bound final ext4 rootfs image."""

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
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile

from check_rootfs_access import (
    debugfs_tool,
    image_file_bytes,
    rootfs_image_identity,
    run_debugfs,
    validate_image_path,
)
from create_build_plan import atomic_write_json, file_identity
from write_artifact_metadata import artifact_identity


SCHEMA = "openubmc-build/gate-report-v1"
GATE = "rootfs-lua-syntax"
_ENTRY = re.compile(
    r"^/(?P<inode>\d+)/(?P<mode>[0-7]{6})/(?P<uid>\d+)/(?P<gid>\d+)/"
    r"(?P<name>[^/]*)/(?P<size>\d*)/$"
)
_SAFE_NAME = re.compile(r"[A-Za-z0-9._+@-]+")
_TYPE_MASK = 0o170000
_DIRECTORY = 0o040000
_REGULAR = 0o100000
_SYMLINK = 0o120000


def load_object(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    document = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{resolved}: expected a JSON object")
    return document


def stable_tool(requirement: dict[str, object]) -> Path:
    planned = requirement.get("checker")
    if not isinstance(planned, dict):
        raise ValueError("plan_missing_lua_checker_identity")
    path = Path(str(planned.get("path", "")))
    if path.is_symlink() or not os.access(path, os.X_OK):
        raise ValueError("lua_checker_not_executable")
    current = file_identity(path)
    for field in ("path", "sha256", "size", "mode"):
        if current.get(field) != planned.get(field):
            raise ValueError(f"lua_checker_identity_drift: {field}")
    return Path(str(current["path"]))


def directory_entries(
    debugfs: Path,
    image: Path,
    directory: PurePosixPath,
) -> list[tuple[str, int, int]]:
    output = run_debugfs(debugfs, image, f"ls -p {directory}")
    entries: list[tuple[str, int, int]] = []
    for line in output.splitlines():
        if not line:
            continue
        match = _ENTRY.fullmatch(line)
        if not match:
            raise ValueError(f"debugfs_listing_unparseable: {directory}")
        name = match.group("name")
        if name in {".", ".."}:
            continue
        if not _SAFE_NAME.fullmatch(name):
            raise ValueError(f"unsafe_rootfs_entry_name: {directory}")
        entries.append(
            (
                name,
                int(match.group("mode"), 8) & _TYPE_MASK,
                int(match.group("size") or "0"),
            )
        )
    return entries


def discover_lua_files(
    debugfs: Path,
    image: Path,
    roots: list[PurePosixPath],
    *,
    max_files: int,
) -> tuple[list[tuple[PurePosixPath, int]], list[dict[str, str]]]:
    pending = list(reversed(roots))
    visited: set[PurePosixPath] = set()
    files: list[tuple[PurePosixPath, int]] = []
    unsupported: list[dict[str, str]] = []
    while pending:
        directory = pending.pop()
        if directory in visited:
            continue
        visited.add(directory)
        for name, kind, size in directory_entries(debugfs, image, directory):
            child = directory / name
            if kind == _DIRECTORY:
                pending.append(child)
            elif kind == _REGULAR and name.endswith(".lua"):
                files.append((child, size))
                if len(files) > max_files:
                    raise ValueError(f"rootfs_lua_file_limit_exceeded: {max_files}")
            elif kind == _SYMLINK and name.endswith(".lua"):
                unsupported.append(
                    {"path": str(child), "reason": "lua_symlink_not_inspected"}
                )
    return sorted(files, key=lambda item: str(item[0])), unsupported


def diagnostic_evidence(value: bytes, temporary: Path) -> dict[str, object]:
    prefix = value[:4096].decode("utf-8", errors="replace")
    line_match = re.search(rf"{re.escape(str(temporary))}:(\d+):", prefix)
    evidence: dict[str, object] = {
        "checker_output_sha256": hashlib.sha256(value).hexdigest(),
        "checker_output_size": len(value),
    }
    if line_match:
        evidence["line"] = int(line_match.group(1))
    return evidence


def evaluate(
    plan: dict[str, object],
    state: dict[str, object],
    *,
    finalization_id: str | None = None,
) -> dict[str, object]:
    plan_id = str(plan.get("plan_id", ""))
    attempt_id = str(state.get("attempt_id", ""))
    if not plan_id or state.get("plan_id") != plan_id or not attempt_id:
        raise ValueError("plan_attempt_identity_mismatch")
    if state.get("status") != "succeeded" or state.get("rc") != 0:
        raise ValueError("attempt_not_succeeded")

    expectations = plan.get("expectations", {})
    requirement = expectations.get("rootfs_lua", {})
    access_requirement = expectations.get("rootfs_access", {})
    if not isinstance(requirement, dict) or not isinstance(access_requirement, dict):
        raise ValueError("plan_missing_rootfs_lua_requirements")
    if requirement.get("image_format") != "ext4":
        raise ValueError("unsupported_rootfs_image_format")
    if requirement.get("image_path") != access_requirement.get("image_path"):
        raise ValueError("rootfs_lua_image_mismatch")
    if requirement.get("debugfs") != access_requirement.get("debugfs"):
        raise ValueError("rootfs_lua_debugfs_mismatch")
    if requirement.get("checker_argv") != ["-p", "{source}"]:
        raise ValueError("unsupported_lua_checker_contract")

    raw_roots = requirement.get("roots")
    if not isinstance(raw_roots, list) or not raw_roots:
        raise ValueError("plan_missing_rootfs_lua_roots")
    roots = [validate_image_path(str(item)) for item in raw_roots]
    if [str(item) for item in roots] != sorted({str(item) for item in roots}):
        raise ValueError("rootfs_lua_roots_not_canonical")

    limits = requirement.get("limits")
    if not isinstance(limits, dict):
        raise ValueError("plan_missing_rootfs_lua_limits")
    expected_limits = {
        "max_files": 20000,
        "max_file_bytes": 16777216,
        "max_total_bytes": 536870912,
        "checker_timeout_seconds": 20,
    }
    if limits != expected_limits:
        raise ValueError("rootfs_lua_limits_mismatch")

    image_identity = rootfs_image_identity(access_requirement, state)
    image = Path(str(image_identity["path"]))
    debugfs = debugfs_tool(requirement)
    checker = stable_tool(requirement)
    discovered, unsupported = discover_lua_files(
        debugfs,
        image,
        roots,
        max_files=expected_limits["max_files"],
    )
    failures: list[dict[str, object]] = list(unsupported)
    checked: list[dict[str, object]] = []
    total_bytes = 0
    if not discovered:
        failures.append({"reason": "no_lua_files_in_planned_roots"})

    with tempfile.TemporaryDirectory(prefix="openubmc-lua-gate-") as raw_temp:
        temporary_root = Path(raw_temp)
        for index, (inside, listed_size) in enumerate(discovered):
            raw = image_file_bytes(debugfs, image, str(inside))
            size = len(raw)
            total_bytes += size
            record: dict[str, object] = {
                "path": str(inside),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": size,
                "listed_size": listed_size,
            }
            if size != listed_size:
                record["status"] = "fail"
                failures.append(
                    {
                        "path": str(inside),
                        "reason": "rootfs_lua_size_mismatch",
                        "listed_size": listed_size,
                        "read_size": size,
                    }
                )
                checked.append(record)
                continue
            if size > expected_limits["max_file_bytes"]:
                record["status"] = "fail"
                failures.append(
                    {
                        "path": str(inside),
                        "reason": "rootfs_lua_file_too_large",
                        "size": size,
                    }
                )
                checked.append(record)
                continue
            if size == 0:
                record["status"] = "fail"
                failures.append(
                    {"path": str(inside), "reason": "empty_lua_source"}
                )
                checked.append(record)
                continue
            if total_bytes > expected_limits["max_total_bytes"]:
                raise ValueError(
                    "rootfs_lua_total_size_limit_exceeded: "
                    f"{expected_limits['max_total_bytes']}"
                )
            temporary = temporary_root / f"source-{index:06d}.lua"
            temporary.write_bytes(raw)
            try:
                completed = subprocess.run(
                    [str(checker), "-p", str(temporary)],
                    cwd=temporary_root,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=expected_limits["checker_timeout_seconds"],
                    check=False,
                )
            except subprocess.TimeoutExpired:
                record["status"] = "fail"
                failures.append(
                    {"path": str(inside), "reason": "lua_checker_timeout"}
                )
            else:
                record["status"] = "pass" if completed.returncode == 0 else "fail"
                if completed.returncode != 0:
                    diagnostic = diagnostic_evidence(
                        completed.stderr or completed.stdout,
                        temporary,
                    )
                    failures.append(
                        {
                            "path": str(inside),
                            "reason": "lua_syntax_error",
                            "checker_rc": completed.returncode,
                            **diagnostic,
                        }
                    )
            checked.append(record)

    if artifact_identity(image) != image_identity:
        raise ValueError("rootfs_image_changed_during_lua_inspection")
    if file_identity(checker) != requirement["checker"]:
        raise ValueError("lua_checker_changed_during_inspection")

    canonical_requirement = json.dumps(
        requirement,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    status = "pass" if not failures else "fail"
    report: dict[str, object] = {
        "schema": SCHEMA,
        "gate": GATE,
        "plan_id": plan_id,
        "attempt_id": attempt_id,
        "status": status,
        "inputs": [
            {"role": "rootfs_image", **image_identity},
            {"role": "lua_checker", **requirement["checker"]},
        ],
        "requirements_sha256": hashlib.sha256(canonical_requirement).hexdigest(),
        "summary": (
            "all Lua source in the planned image roots passed syntax validation"
            if status == "pass"
            else "Lua source validation failed for the final rootfs image"
        ),
        "details": {
            "roots": [str(item) for item in roots],
            "checked_count": len(checked),
            "checked_bytes": total_bytes,
            "checked": checked,
            "failures": failures,
        },
    }
    if finalization_id:
        report["finalization_id"] = finalization_id
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--attempt-state", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--finalization-id")
    args = parser.parse_args(argv)
    try:
        report = evaluate(
            load_object(Path(args.plan)),
            load_object(Path(args.attempt_state)),
            finalization_id=args.finalization_id,
        )
        atomic_write_json(Path(args.output), report)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": report["status"],
                "report_path": str(Path(args.output).resolve()),
                "checked_count": report["details"]["checked_count"],
                "failure_count": len(report["details"]["failures"]),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
