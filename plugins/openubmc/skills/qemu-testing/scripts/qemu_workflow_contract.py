#!/usr/bin/env python3
"""Validate an openUBMC QEMU workflow plan and its layered result receipt."""

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
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
import re
import sys


PLAN_SCHEMA = "openubmc-qemu-workflow-plan/v1"
RESULT_SCHEMA = "openubmc-qemu-workflow-result/v1"
SCENARIOS = {"daily-development", "model-simulation", "alarm-testing"}
ACTIONS = {
    "discover",
    "launch",
    "observe",
    "smoke",
    "stop",
    "diagnose-existing-instance",
}
LAYER_ORDER = (
    "launcher",
    "process",
    "serial",
    "ports",
    "readiness",
    "services",
    "stability",
    "cleanup",
)
LAYER_STATUSES = {"passed", "failed", "blocked", "skipped"}
RESULT_STATUSES = {"completed", "failed", "partial", "blocked"}
TLS_MODES = {"ca_bundle", "exact_fingerprint"}
CHECK_MODES = {
    "ssh": {"host_key_pinned"},
    "web": TLS_MODES,
    "redfish": TLS_MODES,
    "ipmi": {"protocol_native"},
    "process": {"local_process_identity"},
    **{name: {"host_key_pinned", "protocol_native"} for name in (
        "identity", "mdb", "systemd", "selinux", "logs", "bus-permissions",
        "resource-tree", "alarms")},
}
FULL_X86_SMOKE = {
    "identity", "ssh", "web", "redfish", "ipmi", "mdb", "systemd",
    "selinux", "logs", "bus-permissions", "resource-tree", "alarms",
}
SENSITIVE_FIELD_FRAGMENTS = {
    "password",
    "passwd",
    "token",
    "private_key",
    "secret",
    "credential_value",
}


class ContractError(ValueError):
    """The supplied plan or result does not satisfy the QEMU contract."""


def _load(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"invalid JSON document: {path}") from error
    if not isinstance(value, dict):
        raise ContractError(f"document must be an object: {path}")
    return value


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{field} must be an object")
    return value


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{field} must be a non-empty string")
    return value.strip()


def _timestamp(value: object, field: str) -> datetime:
    text = _text(value, field)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", text):
        raise ContractError(f"{field} must be an RFC3339 timestamp with timezone")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as error:
        raise ContractError(f"{field} is an invalid timestamp") from error


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{field} must be a boolean")
    return value


def _string_list(value: object, field: str, *, required: bool = False) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ContractError(f"{field} must be an array of non-empty strings")
    normalized = [item.strip() for item in value]
    if required and not normalized:
        raise ContractError(f"{field} must not be empty")
    if len(normalized) != len(set(normalized)):
        raise ContractError(f"{field} must not contain duplicates")
    return normalized


def _sha256(value: object, field: str) -> str:
    digest = _text(value, field)
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ContractError(f"{field} must be a lowercase SHA-256 digest")
    return digest


def canonical_digest(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _reject_sensitive_fields(value: object, field: str = "document") -> None:
    if isinstance(value, Mapping):
        for raw_name, nested in value.items():
            name = str(raw_name).strip().lower()
            if any(fragment in name for fragment in SENSITIVE_FIELD_FRAGMENTS):
                raise ContractError(f"{field}.{raw_name} is a forbidden secret-bearing field")
            _reject_sensitive_fields(nested, f"{field}.{raw_name}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_sensitive_fields(nested, f"{field}[{index}]")


def _validate_absolute_path(value: object, field: str) -> Path:
    path = Path(_text(value, field))
    if not path.is_absolute():
        raise ContractError(f"{field} must be an absolute path")
    return path


def _directory_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    files = sorted(item for item in path.rglob("*") if item.is_file())
    if len(files) > 50_000:
        raise ContractError(f"directory identity exceeds 50000 files: {path}")
    for item in files:
        relative = item.relative_to(path).as_posix().encode("utf-8")
        file_digest, file_size = _file_digest(item)
        total += file_size
        digest.update(relative)
        digest.update(b"\0")
        digest.update(str(file_size).encode("ascii"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(file_digest))
        digest.update(b"\0")
    return digest.hexdigest(), total


def _file_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            size += len(block)
            digest.update(block)
    return digest.hexdigest(), size


def _validate_identity(
    value: object,
    field: str,
    *,
    verify_files: bool,
) -> None:
    identity = _mapping(value, field)
    path = _validate_absolute_path(identity.get("path"), f"{field}.path")
    digest = _sha256(identity.get("sha256"), f"{field}.sha256")
    size = identity.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ContractError(f"{field}.size must be a non-negative integer")
    kind = str(identity.get("kind", "file")).strip().lower()
    if kind not in {"file", "directory"}:
        raise ContractError(f"{field}.kind must be file or directory")
    if not verify_files:
        return
    if kind == "file":
        if not path.is_file():
            raise ContractError(f"{field}.path is not a regular file")
        actual_digest, actual_size = _file_digest(path)
    else:
        if not path.is_dir():
            raise ContractError(f"{field}.path is not a directory")
        actual_digest, actual_size = _directory_digest(path)
    if actual_size != size or actual_digest != digest:
        raise ContractError(f"{field} does not match the current filesystem identity")


def required_layers(actions: set[str]) -> tuple[str, ...]:
    required = ["launcher"]
    if actions & {"launch", "observe", "smoke", "stop", "diagnose-existing-instance"}:
        required.append("process")
    if actions & {"observe", "smoke", "diagnose-existing-instance"}:
        required.extend(("serial", "ports"))
    if "smoke" in actions:
        required.extend(("readiness", "services", "stability"))
    if "stop" in actions:
        required.append("cleanup")
    return tuple(dict.fromkeys(required))


def validate_plan(
    plan: Mapping[str, object],
    *,
    verify_files: bool = False,
    now: datetime | None = None,
) -> dict[str, object]:
    now = now or datetime.now(timezone.utc)
    _reject_sensitive_fields(plan, "plan")
    if plan.get("schema") != PLAN_SCHEMA:
        raise ContractError(f"schema must be {PLAN_SCHEMA}")
    scenario = _text(plan.get("scenario"), "scenario")
    if scenario not in SCENARIOS:
        raise ContractError("unsupported scenario")
    actions = set(_string_list(plan.get("actions"), "actions", required=True))
    unsupported = actions - ACTIONS
    if unsupported:
        raise ContractError("unsupported actions: " + ", ".join(sorted(unsupported)))

    repository = _mapping(plan.get("repository"), "repository")
    _validate_absolute_path(repository.get("root"), "repository.root")
    _text(repository.get("revision"), "repository.revision")

    launcher = _mapping(plan.get("launcher"), "launcher")
    _validate_identity(launcher, "launcher", verify_files=verify_files)
    enforcement = _mapping(
        launcher.get("authorization_enforcement"),
        "launcher.authorization_enforcement",
    )
    mode = _text(enforcement.get("mode"), "launcher.authorization_enforcement.mode")
    if mode not in {"repository_launcher", "reviewed_wrapper", "task_command", "read_only_blocked"}:
        raise ContractError("unsupported launcher authorization enforcement mode")
    if mode != "read_only_blocked":
        _text(enforcement.get("seam"), "launcher.authorization_enforcement.seam")
        _string_list(
            enforcement.get("evidence_ids"),
            "launcher.authorization_enforcement.evidence_ids",
            required=True,
        )

    runtime = _mapping(plan.get("runtime"), "runtime")
    _validate_absolute_path(runtime.get("root"), "runtime.root")
    reuse = _text(runtime.get("mode"), "runtime.mode")
    if reuse not in {"fresh", "existing"}:
        raise ContractError("runtime.mode must be fresh or existing")
    _boolean(runtime.get("preserve_data"), "runtime.preserve_data")
    if reuse == "existing":
        _text(runtime.get("stateful_reason"), "runtime.stateful_reason")
        _validate_identity(
            runtime.get("initial_artifact"),
            "runtime.initial_artifact",
            verify_files=verify_files,
        )

    artifact = _mapping(plan.get("artifact"), "artifact")
    _validate_identity(
        artifact.get("index"),
        "artifact.index",
        verify_files=verify_files,
    )
    _text(artifact.get("source_revision"), "artifact.source_revision")
    _text(artifact.get("product_version"), "artifact.product_version")
    image_inputs = artifact.get("image_inputs")
    if not isinstance(image_inputs, list) or not image_inputs:
        raise ContractError("artifact.image_inputs must contain at least one identity")
    roles: set[str] = set()
    for index, item in enumerate(image_inputs):
        field = f"artifact.image_inputs[{index}]"
        identity = _mapping(item, field)
        role = _text(identity.get("role"), f"{field}.role")
        if role in roles:
            raise ContractError("artifact.image_inputs roles must be unique")
        roles.add(role)
        _validate_identity(identity, field, verify_files=verify_files)

    intent = _mapping(plan.get("intent"), "intent")
    authorization = _mapping(plan.get("authorization"), "authorization")
    local_control = _boolean(
        authorization.get("local_process_control"),
        "authorization.local_process_control",
    )
    expose_intent = _boolean(
        intent.get("expose_non_loopback_ports"),
        "intent.expose_non_loopback_ports",
    )
    expose_authorized = _boolean(
        authorization.get("expose_non_loopback_ports"),
        "authorization.expose_non_loopback_ports",
    )
    weaken_intent = _boolean(
        intent.get("weaken_verification"),
        "intent.weaken_verification",
    )
    weaken_authorized = _boolean(
        authorization.get("weaken_verification"),
        "authorization.weaken_verification",
    )
    if actions & {"launch", "stop"}:
        if mode == "read_only_blocked" or not local_control:
            raise ContractError(
                "launch/stop requires an enforceable seam and local process control authorization"
            )
    if weaken_intent != weaken_authorized:
        raise ContractError("verification weakening requires matching intent and authorization")

    ports = plan.get("ports")
    if not isinstance(ports, list):
        raise ContractError("ports must be an array")
    host_keys: set[tuple[str, str, int]] = set()
    non_loopback = False
    for index, item in enumerate(ports):
        field = f"ports[{index}]"
        port = _mapping(item, field)
        protocol = _text(port.get("protocol"), f"{field}.protocol").lower()
        if protocol not in {"tcp", "udp"}:
            raise ContractError(f"{field}.protocol must be tcp or udp")
        bind = _text(port.get("bind"), f"{field}.bind")
        host_port = port.get("host_port")
        guest_port = port.get("guest_port")
        for name, number in (("host_port", host_port), ("guest_port", guest_port)):
            if isinstance(number, bool) or not isinstance(number, int) or not 1 <= number <= 65535:
                raise ContractError(f"{field}.{name} must be an integer between 1 and 65535")
        key = (protocol, bind, host_port)
        if key in host_keys:
            raise ContractError("ports must not contain duplicate host bindings")
        host_keys.add(key)
        if bind not in {"127.0.0.1", "::1", "localhost"}:
            non_loopback = True
    if non_loopback and not (expose_intent and expose_authorized):
        raise ContractError("non-loopback ports require matching intent and authorization")
    if not non_loopback and (expose_intent or expose_authorized):
        raise ContractError("non-loopback exposure flags require a non-loopback port plan")

    verification = _mapping(plan.get("verification"), "verification")
    profile = _text(verification.get("profile"), "verification.profile")
    if profile not in {"targeted", "full-x86"}:
        raise ContractError("verification.profile must be targeted or full-x86")
    required_smoke = _string_list(
        verification.get("required_smoke"),
        "verification.required_smoke",
        required="smoke" in actions,
    )
    if profile == "full-x86":
        if "smoke" not in actions:
            raise ContractError("full-x86 verification requires the smoke action")
        missing = sorted(FULL_X86_SMOKE - set(required_smoke))
        if missing:
            raise ContractError("full-x86 verification omits checks: " + ", ".join(missing))
    tls_mode = _text(verification.get("tls_mode"), "verification.tls_mode")
    tls_required = bool(set(required_smoke) & {"web", "redfish"})
    if (tls_mode not in TLS_MODES
            and not (not tls_required and tls_mode == "not_applicable")
            and not (weaken_intent and weaken_authorized and tls_mode == "weakened_authorized")):
        raise ContractError("verification.tls_mode is not a trusted verification mode")
    not_before = _timestamp(verification.get("not_before"), "verification.not_before")
    if not_before > now:
        raise ContractError("verification.not_before is in the future")
    max_age = verification.get("max_evidence_age_seconds")
    if isinstance(max_age, bool) or not isinstance(max_age, int) or not 1 <= max_age <= 3600:
        raise ContractError("verification.max_evidence_age_seconds must be between 1 and 3600")
    check_modes = _mapping(verification.get("check_modes"), "verification.check_modes")
    if set(check_modes) != set(required_smoke):
        raise ContractError("verification.check_modes must match required_smoke")
    weakened_checks = _string_list(verification.get("weakened_checks", []), "verification.weakened_checks")
    if weakened_checks and not (weaken_intent and weaken_authorized):
        raise ContractError("weakened checks require authorization")
    for name in required_smoke:
        check_mode = _text(check_modes[name], f"verification.check_modes.{name}")
        allowed = CHECK_MODES.get(name, set())
        if not (check_mode in allowed or (check_mode == "weakened_authorized" and name in weakened_checks)):
            raise ContractError(f"verification.check_modes.{name} is not trusted for this protocol")
        if name in {"web", "redfish"} and check_mode != tls_mode:
            raise ContractError(f"verification.check_modes.{name} must match tls_mode")
    if set(weakened_checks) != {name for name, mode in check_modes.items() if mode == "weakened_authorized"}:
        raise ContractError("weakened_checks must match the weakened verification modes")
    if weaken_intent and weaken_authorized:
        _text(verification.get("weakened_scope"), "verification.weakened_scope")
        if _timestamp(verification.get("expires_at"), "verification.expires_at") <= now:
            raise ContractError("verification weakening has expired")
        _string_list(
            verification.get("recovery_steps"),
            "verification.recovery_steps",
            required=True,
        )
    stability = verification.get("stability_seconds")
    if (
        isinstance(stability, bool)
        or not isinstance(stability, int)
        or not 1 <= stability <= 3600
    ):
        raise ContractError("verification.stability_seconds must be between 1 and 3600")
    if profile == "full-x86" and stability < 120:
        raise ContractError("full QEMU smoke requires at least 120 seconds of stability observation")
    if scenario == "daily-development":
        baseline = _mapping(plan.get("baseline"), "baseline")
        if baseline.get("fault_injection") not in {"disabled", "after-baseline"}:
            raise ContractError(
                "daily-development fault injection must be disabled or after-baseline"
            )
        baseline_required = profile == "full-x86" or baseline.get("fault_injection") == "after-baseline"
        allowed_baselines = {"healthy"} if baseline_required else {"healthy", "not_requested"}
        if baseline.get("expected_state") not in allowed_baselines:
            raise ContractError("requested full acceptance or fault injection requires a healthy baseline")

    return {
        "schema": PLAN_SCHEMA,
        "plan_digest": canonical_digest(plan),
        "scenario": scenario,
        "actions": sorted(actions),
        "required_layers": list(required_layers(actions)),
        "required_smoke": required_smoke,
    }


def validate_result(
    plan: Mapping[str, object],
    result: Mapping[str, object],
    *,
    verify_files: bool = False,
    now: datetime | None = None,
    historical: bool = False,
) -> dict[str, object]:
    _reject_sensitive_fields(result, "result")
    now = now or datetime.now(timezone.utc)
    started = _timestamp(result.get("started_at"), "result.started_at")
    finished = _timestamp(result.get("finished_at"), "result.finished_at")
    if not started <= finished <= now:
        raise ContractError("result observation window is reversed or in the future")
    plan_summary = validate_plan(plan, verify_files=verify_files, now=started)
    verification = _mapping(plan["verification"], "verification")
    max_age = verification["max_evidence_age_seconds"]
    if not historical and (now - finished).total_seconds() > max_age:
        raise ContractError("result evidence is stale")

    def check_observed(value: object, field: str) -> datetime:
        observed = _timestamp(value, field)
        if not started <= observed <= finished:
            raise ContractError(f"{field} is outside the result observation window")
        if ((finished if historical else now) - observed).total_seconds() > max_age:
            raise ContractError(f"{field} evidence is stale")
        return observed
    if result.get("schema") != RESULT_SCHEMA:
        raise ContractError(f"result.schema must be {RESULT_SCHEMA}")
    if result.get("plan_digest") != plan_summary["plan_digest"]:
        raise ContractError("result.plan_digest does not match the plan")
    status = _text(result.get("status"), "result.status")
    if status not in RESULT_STATUSES:
        raise ContractError("unsupported result.status")

    layers = _mapping(result.get("layers"), "result.layers")
    required = list(plan_summary["required_layers"])
    first_nonpassing = ""
    for name in required:
        layer = _mapping(layers.get(name), f"result.layers.{name}")
        layer_status = _text(layer.get("status"), f"result.layers.{name}.status")
        if layer_status not in LAYER_STATUSES:
            raise ContractError(f"unsupported result.layers.{name}.status")
        _text(layer.get("summary"), f"result.layers.{name}.summary")
        check_observed(layer.get("observed_at"), f"result.layers.{name}.observed_at")
        evidence = _string_list(
            layer.get("evidence_ids"),
            f"result.layers.{name}.evidence_ids",
            required=layer_status in {"passed", "failed"},
        )
        if layer_status == "passed" and not evidence:
            raise ContractError(f"passed layer {name} requires evidence")
        if not first_nonpassing and layer_status != "passed":
            first_nonpassing = name

    plan_intent = _mapping(plan.get("intent"), "intent")
    plan_authorization = _mapping(plan.get("authorization"), "authorization")
    weakened = (
        plan_intent.get("weaken_verification") is True
        and plan_authorization.get("weaken_verification") is True
    )
    smoke_rows = result.get("smoke")
    if not isinstance(smoke_rows, list):
        raise ContractError("result.smoke must be an array")
    smoke_by_name: dict[str, Mapping[str, object]] = {}
    for index, raw in enumerate(smoke_rows):
        field = f"result.smoke[{index}]"
        row = _mapping(raw, field)
        name = _text(row.get("name"), f"{field}.name")
        if name in smoke_by_name:
            raise ContractError("result.smoke names must be unique")
        smoke_by_name[name] = row
        smoke_status = _text(row.get("status"), f"{field}.status")
        if smoke_status not in LAYER_STATUSES:
            raise ContractError(f"unsupported {field}.status")
        endpoint = _text(row.get("endpoint"), f"{field}.endpoint")
        observed = check_observed(row.get("observed_at"), f"{field}.observed_at")
        mode = _text(row.get("verification_mode"), f"{field}.verification_mode")
        if mode == "not_run" and smoke_status in {"blocked", "skipped"}:
            pass
        elif mode != verification["check_modes"].get(name):
            raise ContractError(f"{field}.verification_mode is not trusted by the plan")
        else:
            if endpoint.startswith("http://") and mode != "weakened_authorized":
                raise ContractError(f"{field}.endpoint requires explicitly weakened verification for plain HTTP")
            endpoint_modes = TLS_MODES if endpoint.startswith("https://") else (
                {"host_key_pinned"} if endpoint.startswith("ssh://") else None)
            if endpoint_modes and mode not in endpoint_modes and mode != "weakened_authorized":
                raise ContractError(f"{field}.verification_mode does not match the endpoint protocol")
            if mode == "weakened_authorized" and (
                not weakened or observed >= _timestamp(verification.get("expires_at"), "verification.expires_at")
            ):
                raise ContractError(f"{field} verification weakening has expired")
        _string_list(
            row.get("evidence_ids"),
            f"{field}.evidence_ids",
            required=smoke_status in {"passed", "failed"},
        )
    missing_smoke = sorted(set(plan_summary["required_smoke"]) - set(smoke_by_name))
    if missing_smoke:
        raise ContractError("result.smoke omits required checks: " + ", ".join(missing_smoke))
    nonpassing_smoke = sorted(
        name
        for name in plan_summary["required_smoke"]
        if smoke_by_name[name].get("status") != "passed"
    )

    instance = _mapping(result.get("instance"), "result.instance")
    runtime_root = _validate_absolute_path(
        instance.get("runtime_root"),
        "result.instance.runtime_root",
    )
    planned_runtime = Path(str(_mapping(plan["runtime"], "runtime")["root"]))
    if runtime_root != planned_runtime:
        raise ContractError("result.instance.runtime_root does not match the plan")
    artifact_digest = _sha256(
        instance.get("artifact_index_sha256"),
        "result.instance.artifact_index_sha256",
    )
    planned_artifact = _mapping(
        _mapping(plan["artifact"], "artifact")["index"],
        "artifact.index",
    )
    if artifact_digest != planned_artifact.get("sha256"):
        raise ContractError("result.instance artifact index does not match the plan")
    process_passed = _mapping(layers.get("process", {}), "result.layers.process").get("status") == "passed"
    guest_passed = any(
        _mapping(layers.get(name, {}), f"result.layers.{name}").get("status") == "passed"
        for name in ("readiness", "services", "stability")
    )
    if process_passed:
        _text(instance.get("identity"), "result.instance.identity")
        pid = instance.get("pid")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ContractError("result.instance.pid must be a positive integer")
        _text(instance.get("process_start"), "result.instance.process_start")
        _validate_absolute_path(instance.get("executable"), "result.instance.executable")
    if guest_passed:
        _text(instance.get("boot_id"), "result.instance.boot_id")
        if instance.get("product_version") != _mapping(plan["artifact"], "artifact").get("product_version"):
            raise ContractError("result.instance.product_version does not match the plan")
    stability_layer = _mapping(layers.get("stability", {}), "result.layers.stability")
    if stability_layer.get("status") == "passed":
        observed = stability_layer.get("observed_seconds")
        expected = _mapping(plan["verification"], "verification")["stability_seconds"]
        if (isinstance(observed, bool) or not isinstance(observed, (int, float))
                or not expected <= observed < float("inf")):
            raise ContractError("stability observation is shorter than the planned window")
        if (finished - started).total_seconds() < observed:
            raise ContractError("stability duration exceeds the result observation window")
        boot = _text(instance.get("boot_id"), "result.instance.boot_id")
        if stability_layer.get("boot_id_start") != boot or stability_layer.get("boot_id_end") != boot:
            raise ContractError("guest boot identity changed during stability observation")
        if stability_layer.get("service_identities_unchanged") is not True:
            raise ContractError("service identities changed during stability observation")
    if (guest_passed and plan.get("scenario") == "daily-development"
            and plan.get("baseline", {}).get("expected_state") == "healthy"):
        baseline = _mapping(result.get("baseline"), "result.baseline")
        _text(baseline.get("status"), "result.baseline.status")
        if status == "completed" and baseline.get("status") != "healthy":
            raise ContractError("daily-development result requires a healthy baseline")
        _string_list(baseline.get("evidence_ids"), "result.baseline.evidence_ids", required=True)

    classification = _text(
        result.get("failure_classification"),
        "result.failure_classification",
    )
    if status == "completed":
        if first_nonpassing or nonpassing_smoke:
            raise ContractError("completed result requires every requested layer and smoke check to pass")
        if classification != "none":
            raise ContractError("completed result failure_classification must be none")
    elif classification == "none":
        raise ContractError("non-completed result requires a failure classification")
    if first_nonpassing and classification == "none":
        raise ContractError("a non-passing layer requires a failure classification")

    evidence = _string_list(
        result.get("evidence_ids"),
        "result.evidence_ids",
        required=True,
    )
    return {
        "schema": RESULT_SCHEMA,
        "plan_digest": plan_summary["plan_digest"],
        "status": status,
        "first_nonpassing_layer": first_nonpassing or None,
        "nonpassing_smoke": nonpassing_smoke,
        "evidence_ids": evidence,
        "validation_mode": "historical" if historical else "current",
        "freshness_verified": not historical,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_plan_parser = subparsers.add_parser("validate-plan")
    validate_plan_parser.add_argument("plan", type=Path)
    validate_result_parser = subparsers.add_parser("validate-result")
    validate_result_parser.add_argument("plan", type=Path)
    validate_result_parser.add_argument("result", type=Path)
    validate_result_parser.add_argument("--historical", action="store_true",
                                        help="audit past observations; does not establish current readiness or authorization")
    digest_parser = subparsers.add_parser("digest")
    digest_parser.add_argument("plan", type=Path)
    evidence_parser = subparsers.add_parser("prepare-evidence")
    evidence_parser.add_argument("plan", type=Path)
    evidence_parser.add_argument("result", type=Path)
    evidence_parser.add_argument("--run-id", required=True)
    evidence_parser.add_argument("--target", required=True)
    evidence_parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        plan = _load(arguments.plan)
        if arguments.command == "validate-plan":
            output = validate_plan(plan, verify_files=True)
        elif arguments.command == "validate-result":
            output = validate_result(
                plan,
                _load(arguments.result),
                verify_files=True,
                historical=arguments.historical,
            )
        elif arguments.command == "prepare-evidence":
            result = _load(arguments.result)
            validate_result(plan, result, verify_files=True)
            packet = {"schema": "openubmc-qemu-evidence/v1",
                      "run_id": _text(arguments.run_id, "run_id"),
                      "target": _text(arguments.target, "target"), "plan": plan, "result": result}
            body = (json.dumps(packet, sort_keys=True, indent=2) + "\n").encode()
            if len(body) > 1024 * 1024:
                raise ContractError("QEMU evidence exceeds 1 MiB")
            output_path = _validate_absolute_path(str(arguments.output), "output")
            with output_path.open("xb") as stream:
                stream.write(body)
            output = {"kind": "attach_qemu_evidence", "run_id": arguments.run_id,
                      "target": arguments.target, "path": str(output_path),
                      "sha256": hashlib.sha256(body).hexdigest()}
        else:
            validate_plan(plan, verify_files=True)
            output = {"plan_digest": canonical_digest(plan)}
    except (ContractError, OSError) as error:
        print(json.dumps({"status": "rejected", "reason": str(error)}))
        return 2
    print(json.dumps(output, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
