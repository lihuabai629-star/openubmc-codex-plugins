"""Fail-closed firmware release gates used before packaging and deployment."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import zipfile


SCHEMA = "openubmc-build/release-gates/v1"


class ReleaseGateError(ValueError):
    pass


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def lua_source_gate(
    sources: Mapping[str, Path],
    *,
    checker: Sequence[str],
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, object]:
    """Check every expected Lua source before a package is produced."""
    checked: list[dict[str, object]] = []
    failures: list[dict[str, object]] = []
    if not sources:
        failures.append({"code": "lua_sources_missing"})
    for name, raw_path in sorted(sources.items()):
        path = Path(raw_path)
        entry = {"name": name, "path": str(path), "status": "pass"}
        try:
            raw = path.read_bytes()
            if not raw or raw.endswith(b"\0") or raw.endswith(b"-- TRUNCATED\n"):
                raise ValueError("source_empty_or_truncated")
            completed = runner(
                [*checker, "-p", str(path)],
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode != 0:
                raise ValueError("lua_syntax_error")
            entry["sha256"] = _digest(path)
        except (OSError, ValueError) as exc:
            entry["status"] = "fail"
            entry["reason"] = str(exc)
            failures.append({"name": name, "reason": str(exc)})
        checked.append(entry)
    return {
        "gate": "lua-source-syntax",
        "status": "pass" if not failures else "fail",
        "checked": checked,
        "failures": failures,
    }


def _package_members(path: Path) -> dict[str, bytes]:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            return {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}
    if tarfile.is_tarfile(path):
        with tarfile.open(path, "r:*") as archive:
            return {
                member.name: archive.extractfile(member).read()
                for member in archive.getmembers()
                if member.isfile() and archive.extractfile(member) is not None
            }
    raise ReleaseGateError("unsupported_package_container")


def inspect_final_package(
    package: Path,
    *,
    expected_files: Mapping[str, str] | Iterable[str] = (),
) -> dict[str, object]:
    """Unpack a synthetic/CI package and verify expected bytes and completeness."""
    path = Path(package).resolve(strict=True)
    members = _package_members(path)
    if isinstance(expected_files, Mapping):
        expected = dict(expected_files)
    else:
        expected = {str(name): "" for name in expected_files}
    missing = sorted(set(expected) - set(members))
    truncated = sorted(
        name for name, value in members.items()
        if not value or value.endswith(b"\0") or value.endswith(b"-- TRUNCATED\n")
    )
    mismatched = sorted(
        name for name, digest in expected.items()
        if digest and hashlib.sha256(members.get(name, b"")).hexdigest() != digest.removeprefix("sha256:")
    )
    failures = {
        "missing": missing,
        "truncated": truncated,
        "mismatched": mismatched,
    }
    return {
        "gate": "package-completeness",
        "status": "pass" if not any(failures.values()) else "fail",
        "package": {"path": str(path), "sha256": _digest(path)},
        "members": sorted(members),
        "failures": failures,
    }


def service_start_smoke(
    adapter: Callable[[str], bool | Mapping[str, object]],
    *,
    required_services: Sequence[str],
    target: str,
    address: str,
    version: str,
    command: Sequence[str],
    observed_at: str | None = None,
) -> dict[str, object]:
    """Run a controlled post-activation smoke and bind every result identity."""
    checks: list[dict[str, object]] = []
    failures: list[str] = []
    if not required_services:
        failures.append("required_services_missing")
    if not all(str(value).strip() for value in (target, address, version)):
        failures.append("service_smoke_identity_incomplete")
    if not command or any(not str(item).strip() for item in command):
        failures.append("service_smoke_command_missing")
    for service in required_services:
        try:
            raw = adapter(service)
            ok = raw is True or isinstance(raw, Mapping) and raw.get("active") is True
        except Exception as exc:
            raw = None
            ok = False
            failures.append(f"{service}:{type(exc).__name__}")
        checks.append({"service": service, "active": ok})
    if any(not item["active"] for item in checks):
        failures.append("required_service_inactive")
    passed = not failures
    return {
        "gate": "service-start-smoke",
        "status": "pass" if passed else "fail",
        "target": target,
        "address": address,
        "version": version,
        "observed_at": observed_at or datetime.now(timezone.utc).isoformat(),
        "command": list(command),
        "checks": checks,
        "failures": failures,
    }


def rollback_gate(
    *,
    recovery_artifact: Mapping[str, object] | None,
    rollback: Callable[[], Mapping[str, object]],
) -> dict[str, object]:
    """Require a pre-mutation recovery identity and independent verification."""
    if (
        not isinstance(recovery_artifact, Mapping)
        or not recovery_artifact.get("sha256")
        or not recovery_artifact.get("version")
        or recovery_artifact.get("established_before_mutation") is not True
    ):
        return {"gate": "rollback", "status": "fail", "reason": "recovery_artifact_missing"}
    try:
        result = rollback()
    except Exception as exc:
        return {
            "gate": "rollback",
            "status": "fail",
            "reason": f"rollback_error:{type(exc).__name__}",
            "recovery_artifact": dict(recovery_artifact),
        }
    evidence_ids = result.get("evidence_ids", []) if isinstance(result, Mapping) else []
    verified = (
        isinstance(result, Mapping)
        and result.get("verified") is True
        and str(result.get("artifact_sha256", "")).removeprefix("sha256:")
        == str(recovery_artifact.get("sha256", "")).removeprefix("sha256:")
        and result.get("version") == recovery_artifact.get("version")
        and isinstance(evidence_ids, list)
        and bool(evidence_ids)
    )
    return {
        "gate": "rollback",
        "status": "pass" if verified else "fail",
        "recovery_artifact": dict(recovery_artifact),
        "verification": dict(result) if isinstance(result, Mapping) else {},
    }


def release_result(
    *gates: Mapping[str, object],
    required_gates: Sequence[str] = (),
) -> dict[str, object]:
    names = [str(gate.get("gate", "unknown")) for gate in gates]
    failures = [
        name for name, gate in zip(names, gates) if gate.get("status") != "pass"
    ]
    failures.extend(name for name in required_gates if name not in names)
    failures.extend(name for name in set(names) if names.count(name) > 1)
    if not gates:
        failures.append("release_gates_missing")
    failures = list(dict.fromkeys(failures))
    return {
        "schema": SCHEMA,
        "status": "accepted" if not failures else "rejected",
        "gates": [dict(gate) for gate in gates],
        "failed_gates": failures,
        "required_gates": list(required_gates),
    }
