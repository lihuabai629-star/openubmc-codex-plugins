#!/usr/bin/env python3
"""Check planned service traversal against the final ext4 rootfs image."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys

from create_build_plan import atomic_write_json, file_identity
from write_artifact_metadata import artifact_identity


SCHEMA = "openubmc-build/gate-report-v1"
_SAFE_IMAGE_PATH = re.compile(r"/[A-Za-z0-9._+@/-]*")


def load_object(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    document = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{resolved}: expected a JSON object")
    return document


def output_changed(
    before: dict[str, object],
    after: dict[str, object],
) -> bool:
    if after.get("status") != "present":
        return False
    if before.get("status") != "present":
        return True
    return before.get("sha256") != after.get("sha256")


def stable_output_identity(identity: dict[str, object]) -> dict[str, object]:
    return {
        "path": identity.get("path"),
        "sha256": identity.get("sha256"),
        "size": identity.get("size"),
    }


def rootfs_image_identity(
    requirement: dict[str, object],
    state: dict[str, object],
) -> dict[str, object]:
    image = Path(str(requirement.get("image_path", "")))
    identity = artifact_identity(image)
    before = state.get("outputs_before", {}).get("rootfs_image", {})
    after = state.get("outputs_after", {}).get("rootfs_image", {})
    if stable_output_identity(identity) != stable_output_identity(after):
        raise ValueError("rootfs_image_output_identity_mismatch")
    if not output_changed(before, after):
        raise ValueError("stale_rootfs_image_output")
    return identity


def validate_image_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or not _SAFE_IMAGE_PATH.fullmatch(value)
        or str(path) != value
    ):
        raise ValueError(f"unsafe rootfs image path: {value}")
    return path


def debugfs_tool(requirement: dict[str, object]) -> Path:
    planned = requirement.get("debugfs")
    if not isinstance(planned, dict):
        raise ValueError("plan_missing_debugfs_identity")
    current = file_identity(Path(str(planned.get("path", ""))))
    for field in ("path", "sha256", "size", "mode"):
        if current.get(field) != planned.get(field):
            raise ValueError(f"debugfs_identity_drift: {field}")
    return Path(str(current["path"]))


def run_debugfs(tool: Path, image: Path, command: str) -> str:
    completed = subprocess.run(
        [str(tool), "-R", command, str(image)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    errors = [
        line.strip()
        for line in completed.stderr.splitlines()
        if line.strip() and not line.startswith("debugfs ")
    ]
    if completed.returncode != 0 or errors:
        detail = "; ".join(errors) or f"rc={completed.returncode}"
        raise ValueError(f"debugfs_read_failed: {command}: {detail}")
    return completed.stdout


def image_file_bytes(
    tool: Path,
    image: Path,
    inside_path: str,
) -> bytes:
    path = validate_image_path(inside_path)
    completed = subprocess.run(
        [str(tool), "-R", f"cat {path}", str(image)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    errors = [
        line.strip()
        for line in completed.stderr.decode("utf-8", errors="replace").splitlines()
        if line.strip() and not line.startswith("debugfs ")
    ]
    if completed.returncode != 0 or errors:
        detail = "; ".join(errors) or f"rc={completed.returncode}"
        raise ValueError(f"debugfs_read_failed: cat {path}: {detail}")
    return completed.stdout


def image_inode(tool: Path, image: Path, path: PurePosixPath) -> dict[str, object]:
    output = run_debugfs(tool, image, f"stat {path}")
    type_match = re.search(r"\bType:\s+(\S+)\s+Mode:\s+0*([0-7]+)", output)
    owner_match = re.search(r"\bUser:\s+(\d+)\s+Group:\s+(\d+)", output)
    if not type_match or not owner_match:
        raise ValueError(f"debugfs_stat_unparseable: {path}")
    return {
        "path": str(path),
        "type": type_match.group(1),
        "mode": int(type_match.group(2), 8),
        "uid": int(owner_match.group(1)),
        "gid": int(owner_match.group(2)),
    }


def can_traverse(
    mode: int,
    owner_uid: int,
    owner_gid: int,
    service: dict[str, object],
) -> bool:
    uid = int(service["uid"])
    gid = int(service["gid"])
    supplementary = {
        int(item) for item in service.get("supplementary_gids", [])
    }
    if uid == owner_uid:
        return bool(mode & stat.S_IXUSR)
    if owner_gid == gid or owner_gid in supplementary:
        return bool(mode & stat.S_IXGRP)
    return bool(mode & stat.S_IXOTH)


def ancestor_paths(requested: PurePosixPath) -> list[PurePosixPath]:
    result = [PurePosixPath("/")]
    current = PurePosixPath("/")
    for part in requested.parts[1:]:
        current /= part
        result.append(current)
    return result


def blocked_ancestor(
    tool: Path,
    image: Path,
    requested: PurePosixPath,
    service: dict[str, object],
) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    observed: list[dict[str, object]] = []
    for ancestor in ancestor_paths(requested):
        try:
            inode = image_inode(tool, image, ancestor)
        except ValueError as exc:
            return (
                {
                    "service": service["name"],
                    "path": str(requested),
                    "blocked_at": str(ancestor),
                    "reason": "missing_or_unreadable",
                    "detail": str(exc),
                },
                observed,
            )
        observed.append(inode)
        if inode["type"] != "directory":
            return (
                {
                    "service": service["name"],
                    "path": str(requested),
                    "blocked_at": str(ancestor),
                    "reason": "not_a_directory",
                    "inode_type": inode["type"],
                },
                observed,
            )
        if not can_traverse(
            int(inode["mode"]),
            int(inode["uid"]),
            int(inode["gid"]),
            service,
        ):
            return (
                {
                    "service": service["name"],
                    "path": str(requested),
                    "blocked_at": str(ancestor),
                    "reason": "execute_bit_denied",
                    "mode": f"{int(inode['mode']):04o}",
                    "owner_uid": inode["uid"],
                    "owner_gid": inode["gid"],
                },
                observed,
            )
    return None, observed


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
    requirement = plan.get("expectations", {}).get("rootfs_access", {})
    if not isinstance(requirement, dict):
        raise ValueError("plan_missing_rootfs_requirements")
    if requirement.get("image_format") != "ext4":
        raise ValueError("unsupported_rootfs_image_format")
    services = requirement.get("services")
    if not isinstance(services, list) or not services:
        raise ValueError("plan_missing_rootfs_services")
    image_identity = rootfs_image_identity(requirement, state)
    image = Path(str(image_identity["path"]))
    tool = debugfs_tool(requirement)
    canonical_requirement = json.dumps(
        requirement,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    blocked: list[dict[str, object]] = []
    checked: list[dict[str, object]] = []
    for service in services:
        if not isinstance(service, dict) or not service.get("name"):
            raise ValueError("invalid_rootfs_service")
        paths = service.get("paths")
        if not isinstance(paths, list) or not paths:
            raise ValueError(f"rootfs_service_missing_paths: {service.get('name')}")
        for raw_path in paths:
            requested = validate_image_path(str(raw_path))
            failure, ancestors = blocked_ancestor(
                tool,
                image,
                requested,
                service,
            )
            checked.append(
                {
                    "service": service["name"],
                    "path": str(requested),
                    "ancestors": ancestors,
                }
            )
            if failure:
                blocked.append(failure)
    if artifact_identity(image) != image_identity:
        raise ValueError("rootfs_image_changed_during_inspection")
    status = "pass" if not blocked else "fail"
    report: dict[str, object] = {
        "schema": SCHEMA,
        "gate": "rootfs-access",
        "plan_id": plan_id,
        "attempt_id": attempt_id,
        "status": status,
        "inputs": [{"role": "rootfs_image", **image_identity}],
        "requirements_sha256": hashlib.sha256(canonical_requirement).hexdigest(),
        "summary": (
            "all planned services can traverse their mapped image paths"
            if status == "pass"
            else "one or more mapped image paths are not traversable"
        ),
        "details": {
            "services": services,
            "checked": checked,
            "blocked": blocked,
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
                "blocked_count": len(report["details"]["blocked"]),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
