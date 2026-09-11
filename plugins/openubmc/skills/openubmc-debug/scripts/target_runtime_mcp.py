#!/usr/bin/env python3
"""Run the local domain-specific Target Runtime MCP for openUBMC Debug."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


from collections import OrderedDict
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import re
import sys
import threading
import time
import uuid
import systemd_observation

from _comparison import (
    compact_comparison_values,
    run_dual_target_comparison,
    run_multi_target_comparison,
)
from _cli_common import resolve_debug_credentials
from _source_root import resolve_source_root
from _target_runtime_adapter import _load_runtime_module, open_debug_runtime_lease
import workflow_remote
from _remote_common import (
    SSH_HOST_KEY_POLICY_ENV,
    SSH_KNOWN_HOSTS_FILE_ENV,
)


def select_default_credentials_file() -> str:
    if "OPENUBMC_CREDENTIALS_CONFIG" in os.environ:
        return os.environ["OPENUBMC_CREDENTIALS_CONFIG"]
    selectors = (
        "OPENUBMC_CREDENTIALS_FILE",
        "OPENUBMC_DEBUG_CREDENTIALS_FILE",
    )
    for selector in selectors:
        if selector in os.environ:
            return str(os.environ[selector])
    config_root = Path(
        os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    )
    structured = config_root / "openubmc" / "credentials.json"
    if structured.exists() or structured.is_symlink():
        return str(structured)
    credentials = config_root / "openubmc" / "credentials.env"
    if credentials.is_file():
        return str(credentials)
    return ""


_STRING_OPTIONS = {
    "ip": "--ip",
    "keyword": "--keyword",
    "logs": "--logs",
    "tree_service": "--tree-service",
    "alarm_service": "--alarm-service",
    "alarm_path": "--alarm-path",
    "alarm_call_signature": "--alarm-call-signature",
    "source_root": "--source-root",
    "ssh_user": "--ssh-user",
    "ssh_user_env": "--ssh-user-env",
    "telnet_user": "--telnet-user",
    "telnet_user_env": "--telnet-user-env",
}
_MCP_DIRECT_CREDENTIAL_OPTIONS = (
    ("ssh_password", "--ssh-password"),
    ("telnet_password", "--telnet-password"),
)
_POLICY_OPTIONS = {
    "mdb_concurrency": "--mdb-concurrency",
}
for _transport, _field in (
    ("ssh", "password_env"),
    ("ssh", "identity_file"),
    ("telnet", "password_env"),
):
    _STRING_OPTIONS[f"{_transport}_{_field}"] = (
        f"--{_transport}-{_field.replace('_', '-')}"
    )
_INTEGER_OPTIONS = {
    "lines": "--lines",
    "rotated_limit": "--rotated-limit",
    "log_max_bytes": "--log-max-bytes",
    "tree_head": "--tree-head",
    "alarm_discovery_service_limit": "--alarm-discovery-service-limit",
    "alarm_discovery_path_limit": "--alarm-discovery-path-limit",
    "alarm_limit": "--alarm-limit",
    "timeout": "--timeout",
    "deadline": "--deadline",
    "source_max_matches": "--source-max-matches",
    "correlate_alarm_limit": "--correlate-alarm-limit",
    "correlation_time_window": "--correlation-time-window",
    "ssh_port": "--ssh-port",
    "telnet_port": "--telnet-port",
}
_BOOLEAN_OPTIONS = {
    "include_rotated": "--include-rotated",
    "mdb_only": "--mdb-only",
    "no_freshness": "--no-freshness",
    "no_source_correlation": "--no-source-correlation",
    "skip_telnet": "--skip-telnet",
    "compact_json": "--compact-json",
}
_LIST_OPTIONS = {
    "files": "--file",
    "alarm_call_args": "--alarm-call-arg",
    "mdb_queries": "--mdb-query",
    "mdb_expand_classes": "--mdb-expand-class",
}
_ORCHESTRATION_OPTIONS = {"profile", "reference_role"}
_TRANSPORT_STRING_OPTIONS = {
    "ssh_host_key_policy",
    "ssh_known_hosts_file",
}
_TRANSPORT_BOOLEAN_OPTIONS = {"allow_insecure_host_key"}
_HARDWARE_ACCEPTANCE_OPTIONS = {"hardware_acceptance"}
_DRIVE_PROTOCOL_CODES = {"SATA": 3, "SAS": 4, "NVMe": 6}


def _boolean_argument(
    arguments: Mapping[str, object],
    name: str,
    *,
    default: bool = False,
) -> bool:
    value = arguments.get(name, default)
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a boolean")
    return value


def _workflow_argv(arguments: Mapping[str, object]) -> list[str]:
    unknown = set(arguments) - (
        set(_STRING_OPTIONS)
        | {name for name, _option in _MCP_DIRECT_CREDENTIAL_OPTIONS}
        | set(_POLICY_OPTIONS)
        | set(_INTEGER_OPTIONS)
        | set(_BOOLEAN_OPTIONS)
        | set(_LIST_OPTIONS)
        | _ORCHESTRATION_OPTIONS
        | _TRANSPORT_STRING_OPTIONS
        | _TRANSPORT_BOOLEAN_OPTIONS
        | _HARDWARE_ACCEPTANCE_OPTIONS
    )
    if unknown:
        raise ValueError(
            "unsupported Debug MCP arguments: " + ", ".join(sorted(unknown))
        )
    argv: list[str] = []
    for name, option in _STRING_OPTIONS.items():
        if name not in arguments:
            continue
        value = arguments[name]
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string")
        argv.extend([option, value])
    for name, option in _MCP_DIRECT_CREDENTIAL_OPTIONS:
        if name not in arguments:
            continue
        value = arguments[name]
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string")
        argv.extend([option, value])
    for name, option in _POLICY_OPTIONS.items():
        if name not in arguments:
            continue
        value = arguments[name]
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise TypeError(f"{name} must be a string or integer")
        argv.extend([option, str(value)])
    for name, option in _INTEGER_OPTIONS.items():
        if name not in arguments:
            continue
        value = arguments[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError(f"{name} must be a number")
        if int(value) != value:
            raise ValueError(f"{name} must be an integer")
        argv.extend([option, str(int(value))])
    for name, option in _BOOLEAN_OPTIONS.items():
        if name not in arguments:
            continue
        value = arguments[name]
        if not isinstance(value, bool):
            raise TypeError(f"{name} must be a boolean")
        if value:
            argv.append(option)
    for name, option in _LIST_OPTIONS.items():
        if name not in arguments:
            continue
        value = arguments[name]
        if not isinstance(value, list) or not all(
            isinstance(item, str) for item in value
        ):
            raise TypeError(f"{name} must be an array of strings")
        for item in value:
            argv.extend([option, item])
    for name in _TRANSPORT_STRING_OPTIONS:
        if name in arguments and not isinstance(arguments[name], str):
            raise TypeError(f"{name} must be a string")
    for name in _TRANSPORT_BOOLEAN_OPTIONS:
        if name in arguments and not isinstance(arguments[name], bool):
            raise TypeError(f"{name} must be a boolean")
    argv.append("--json")
    return argv


def _normalize_hardware_acceptance(value: object) -> tuple[dict[str, str], ...]:
    if value is None:
        return ()
    if not isinstance(value, Mapping) or set(value) != {"devices"}:
        raise TypeError("hardware_acceptance must contain only a devices array")
    devices = value.get("devices")
    if (
        not isinstance(devices, Sequence)
        or isinstance(devices, (str, bytes, bytearray))
        or not devices
        or len(devices) > 64
    ):
        raise TypeError("hardware_acceptance.devices must contain 1 through 64 devices")
    normalized: list[dict[str, str]] = []
    identities: set[int] = set()
    for index, raw_device in enumerate(devices):
        if not isinstance(raw_device, Mapping) or set(raw_device) != {
            "device_id",
            "protocol",
            "resource_id",
        }:
            raise TypeError(
                f"hardware_acceptance.devices[{index}] must contain device_id, "
                "protocol, and resource_id"
            )
        device_id = str(raw_device.get("device_id", "")).strip()
        match = re.fullmatch(r"(?:Drive|Disk)(\d+)", device_id)
        if match is None:
            raise ValueError(
                f"hardware_acceptance.devices[{index}].device_id must be Drive<N>"
            )
        numeric_id = int(match.group(1))
        if numeric_id in identities:
            raise ValueError("hardware_acceptance device identities must be unique")
        identities.add(numeric_id)
        protocol = str(raw_device.get("protocol", "")).strip()
        if protocol not in _DRIVE_PROTOCOL_CODES:
            raise ValueError(
                f"hardware_acceptance.devices[{index}].protocol must be NVMe, SATA, or SAS"
            )
        resource_id = str(raw_device.get("resource_id", "")).strip()
        if resource_id not in {"positive", "zero"}:
            raise ValueError(
                f"hardware_acceptance.devices[{index}].resource_id must be positive or zero"
            )
        normalized.append(
            {
                "device_id": f"Drive{numeric_id}",
                "protocol": protocol,
                "resource_id": resource_id,
            }
        )
    return tuple(normalized)


def _debug_property(value: object) -> object:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value.strip()


def _mdb_properties(lane: Mapping[str, object]) -> dict[str, dict[str, object]]:
    result = lane.get("result")
    result = dict(result) if isinstance(result, Mapping) else {}
    properties = result.get("properties")
    if isinstance(properties, Mapping) and properties:
        return {
            str(interface): dict(values)
            for interface, values in properties.items()
            if isinstance(values, Mapping)
        }
    payload = lane.get("payload")
    payload = dict(payload) if isinstance(payload, Mapping) else {}
    native = payload.get("result")
    native = dict(native) if isinstance(native, Mapping) else {}
    properties = native.get("properties")
    if isinstance(properties, Mapping) and properties:
        return {
            str(interface): dict(values)
            for interface, values in properties.items()
            if isinstance(values, Mapping)
        }
    lines = native.get("stdout_lines")
    if not isinstance(lines, Sequence) or isinstance(lines, (str, bytes, bytearray)):
        return {}
    parsed: dict[str, dict[str, object]] = {}
    current_interface = ""
    for raw_line in lines:
        line = str(raw_line)
        stripped = line.strip()
        if not stripped:
            continue
        if not line[:1].isspace():
            current_interface = stripped
            parsed.setdefault(current_interface, {})
            continue
        if current_interface and "=" in stripped:
            name, raw_value = stripped.split("=", 1)
            if name:
                parsed[current_interface][name] = raw_value
    return {interface: values for interface, values in parsed.items() if values}


def _apply_hardware_acceptance(
    result: dict[str, object],
    requirements: Sequence[Mapping[str, str]],
) -> dict[str, object]:
    if not requirements:
        return result
    raw_result = result.get("result")
    raw_result = dict(raw_result) if isinstance(raw_result, Mapping) else {}
    raw_lanes = raw_result.get("lanes")
    raw_lanes = dict(raw_lanes) if isinstance(raw_lanes, Mapping) else {}
    raw_ssh = raw_lanes.get("ssh")
    raw_ssh = dict(raw_ssh) if isinstance(raw_ssh, Mapping) else {}
    observed: dict[int, dict[str, object]] = {}
    for name, raw_lane in raw_ssh.items():
        if not str(name).startswith("mdbctl_expand_") or not isinstance(
            raw_lane, Mapping
        ):
            continue
        lane = dict(raw_lane)
        if lane.get("ok") is not True:
            continue
        properties = _mdb_properties(lane)
        drive = properties.get("bmc.kepler.Systems.Storage.Drive", {})
        status = properties.get(
            "bmc.kepler.Systems.Storage.Drive.DriveStatus", {}
        )
        inventory = properties.get("bmc.kepler.Inventory.Hardware", {})
        device_id = _debug_property(drive.get("Id"))
        if isinstance(device_id, bool) or not isinstance(device_id, int):
            continue
        observed[device_id] = {
            "protocol": _debug_property(drive.get("Protocol")),
            "presence": _debug_property(drive.get("Presence")),
            "controller": _debug_property(drive.get("RefControllerId")),
            "resource_id": _debug_property(drive.get("ResourceId")),
            "health": _debug_property(status.get("Health")),
            "serial": str(_debug_property(inventory.get("SerialNumber")) or "").strip(),
        }
    gaps: list[str] = []
    accepted_devices: list[dict[str, object]] = []
    for requirement in requirements:
        device_id = int(str(requirement["device_id"]).removeprefix("Drive"))
        label = f"Drive{device_id}"
        actual = observed.get(device_id)
        if actual is None:
            gaps.append(f"{label} is missing from complete Drive evidence")
            continue
        protocol = str(requirement["protocol"])
        if actual["protocol"] != _DRIVE_PROTOCOL_CODES[protocol]:
            gaps.append(f"{label} protocol must be {protocol}")
        if actual["presence"] != 1:
            gaps.append(f"{label} Presence must be 1")
        if actual["health"] != 0:
            gaps.append(f"{label} Health must be 0")
        if not actual["serial"]:
            gaps.append(f"{label} SerialNumber must be non-empty")
        if protocol == "NVMe" and actual["controller"] != 255:
            gaps.append(f"{label} RefControllerId must identify a direct NVMe drive")
        resource_id = actual["resource_id"]
        if requirement["resource_id"] == "positive" and (
            isinstance(resource_id, bool)
            or not isinstance(resource_id, int)
            or resource_id <= 0
        ):
            gaps.append(f"{label} ResourceId must be positive")
        if requirement["resource_id"] == "zero" and resource_id != 0:
            gaps.append(f"{label} ResourceId must be zero")
        accepted_devices.append(
            {
                "device_id": label,
                "protocol": protocol,
                "resource_id": resource_id,
            }
        )
    acceptance = {
        "status": "pending" if gaps else "passed",
        "devices": accepted_devices,
        "gaps": gaps,
    }
    result["hardware_acceptance"] = acceptance
    if gaps:
        result["ok"] = False
        result["status"] = "partial"
        result["partial"] = True
        result["code"] = "hardware_acceptance_pending"
        result["normalized_code"] = "hardware_acceptance_pending"
        result["error"] = "; ".join(gaps)
    return result


def workflow_arguments_from_namespace(args) -> dict[str, object]:
    """Project legacy workflow argparse values into the Catalog input shape."""

    result: dict[str, object] = {}
    for name in (
        set(_STRING_OPTIONS)
        | set(_POLICY_OPTIONS)
        | set(_INTEGER_OPTIONS)
        | set(_BOOLEAN_OPTIONS)
        | set(_LIST_OPTIONS)
    ):
        attribute = "alarm_call_arg" if name == "alarm_call_args" else name
        if hasattr(args, attribute):
            result[name] = getattr(args, attribute)
    return result


def _credential_binding_fingerprint(
    args,
    credential_values: Mapping[str, str] | None,
) -> str:
    bindings = {
        f"value:{key}": str(value)
        for key, value in (credential_values or {}).items()
    }
    for field, fallback in (
        ("ssh_user_env", "OPENUBMC_SSH_USER"),
        ("ssh_password_env", "OPENUBMC_SSH_PASSWORD"),
        ("telnet_user_env", "OPENUBMC_TELNET_USER"),
        ("telnet_password_env", "OPENUBMC_TELNET_PASSWORD"),
    ):
        selector = str(getattr(args, field, "") or fallback).strip()
        bindings[f"env:{selector}"] = os.environ.get(selector, "")
    for field in ("ssh_password", "telnet_password"):
        bindings[f"inline:{field}"] = str(getattr(args, field, ""))
    identity_file = str(getattr(args, "ssh_identity_file", "")).strip()
    if identity_file:
        try:
            bindings[f"identity:{identity_file}"] = hashlib.sha256(
                Path(identity_file).read_bytes()
            ).hexdigest()
        except OSError:
            bindings[f"identity:{identity_file}"] = "unavailable"
    for selector in (
        "OPENUBMC_CREDENTIALS_FILE",
        "OPENUBMC_DEBUG_CREDENTIALS_FILE",
    ):
        path = os.environ.get(selector, "").strip()
        if not path:
            continue
        try:
            bindings[f"file:{selector}:{path}"] = hashlib.sha256(
                Path(path).read_bytes()
            ).hexdigest()
        except OSError:
            bindings[f"file:{selector}:{path}"] = "unavailable"
    body = "\n".join(
        f"{key}={bindings[key]}" for key in sorted(bindings)
    ).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _lease_key(
    args,
    credential_values: Mapping[str, str] | None = None,
) -> tuple[object, ...]:
    host_key_policy = str(
        getattr(args, "ssh_host_key_policy", "")
        or os.environ.get(SSH_HOST_KEY_POLICY_ENV, "")
        or "insecure"
    ).strip().lower()
    known_hosts_file = str(
        getattr(args, "ssh_known_hosts_file", "")
        or os.environ.get(SSH_KNOWN_HOSTS_FILE_ENV, "")
    ).strip()
    return (
        str(args.ip).strip().lower(),
        int(args.ssh_port),
        int(args.telnet_port),
        str(args.ssh_user),
        str(args.ssh_user_env),
        str(args.ssh_password_env),
        str(args.ssh_identity_file),
        str(args.telnet_user),
        str(args.telnet_user_env),
        str(args.telnet_password_env),
        host_key_policy,
        known_hosts_file,
        bool(getattr(args, "allow_insecure_host_key", False)),
        os.environ.get("OPENUBMC_CREDENTIALS_FILE", ""),
        os.environ.get("OPENUBMC_DEBUG_CREDENTIALS_FILE", ""),
        _credential_binding_fingerprint(args, credential_values),
    )


def _observation_instant(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _result_window(value: object) -> tuple[str, str]:
    result = value if isinstance(value, Mapping) else {}
    payload = result.get("payload")
    payload = payload if isinstance(payload, Mapping) else {}
    anchor = str(payload.get("observed_at", "")).strip()
    started = str(result.get("started_at") or anchor).strip()
    completed = str(result.get("completed_at") or anchor or started).strip()
    return started, completed


def _attempt_window(
    selector_facts: list[dict[str, object]],
) -> tuple[str, str]:
    starts = [
        (instant, str(fact.get("started_at", "")))
        for fact in selector_facts
        if (instant := _observation_instant(fact.get("started_at"))) is not None
    ]
    completions = [
        (instant, str(fact.get("completed_at", "")))
        for fact in selector_facts
        if (instant := _observation_instant(fact.get("completed_at"))) is not None
    ]
    return (
        min(starts, key=lambda item: item[0])[1] if starts else "",
        max(completions, key=lambda item: item[0])[1] if completions else "",
    )


class DebugMcpTask:
    """Own all Debug leases created inside one Codex task."""

    def __init__(
        self,
        task_id: str,
        *,
        mutation_journal_store=None,
        max_cached_leases: int = 32,
    ) -> None:
        if max_cached_leases < 1:
            raise ValueError("max_cached_leases must be positive")
        self.task_id = task_id
        self.mutation_journal_store = mutation_journal_store
        self.max_cached_leases = int(max_cached_leases)
        self._leases: OrderedDict[tuple[object, ...], object] = OrderedDict()
        self._active_lease_keys: dict[tuple[object, ...], int] = {}
        self._lease_evictions = 0
        self._peak_leases = 0
        self._lock = threading.RLock()

    def _lease_for(
        self,
        args,
        *,
        credential_values: Mapping[str, str] | None = None,
        pin: bool = False,
    ):
        key = _lease_key(args, credential_values)
        victim = None
        with self._lock:
            existing = self._leases.get(key)
            if existing is not None:
                if bool(
                    getattr(existing, "closed", False)
                    or getattr(existing, "_closed", False)
                ):
                    self._leases.pop(key, None)
                    self._active_lease_keys.pop(key, None)
                    existing = None
            if existing is not None:
                self._leases.move_to_end(key)
                if (
                    not bool(args.skip_telnet)
                    and getattr(existing, "telnet_lease", None) is None
                ):
                    if credential_values is None:
                        credentials = resolve_debug_credentials(
                            args,
                            include_telnet=True,
                        )
                    else:
                        credentials = resolve_debug_credentials(
                            args,
                            include_telnet=True,
                            credentials=credential_values,
                        )
                    existing.ensure_telnet(args, credentials["telnet"])
                if pin:
                    self._active_lease_keys[key] = (
                        self._active_lease_keys.get(key, 0) + 1
                    )
                return existing
            if credential_values is None:
                credentials = resolve_debug_credentials(
                    args,
                    include_telnet=not args.skip_telnet,
                )
            else:
                credentials = resolve_debug_credentials(
                    args,
                    include_telnet=not args.skip_telnet,
                    credentials=credential_values,
                )
            lease_options = {
                "args": args,
                "credential_bundle": credentials,
                "task_id": self.task_id,
            }
            if self.mutation_journal_store is not None:
                lease_options["mutation_journal_store"] = (
                    self.mutation_journal_store
                )
            lease = open_debug_runtime_lease(
                **lease_options,
            )
            if len(self._leases) >= self.max_cached_leases:
                victim_key = next(
                    (
                        candidate
                        for candidate in self._leases
                        if self._active_lease_keys.get(candidate, 0) == 0
                    ),
                    None,
                )
                if victim_key is not None:
                    victim = self._leases.pop(victim_key)
                    self._active_lease_keys.pop(victim_key, None)
            if victim is not None:
                self._lease_evictions += 1
            self._leases[key] = lease
            if pin:
                self._active_lease_keys[key] = (
                    self._active_lease_keys.get(key, 0) + 1
                )
            self._peak_leases = max(self._peak_leases, len(self._leases))
        if victim is not None:
            victim.close()
        return lease

    def lease_for(
        self,
        args,
        *,
        credential_values: Mapping[str, str] | None = None,
    ):
        return self._lease_for(
            args,
            credential_values=credential_values,
        )

    @contextmanager
    def lease_scope(
        self,
        args,
        *,
        credential_values: Mapping[str, str] | None = None,
    ):
        key = _lease_key(args, credential_values)
        lease = self._lease_for(
            args,
            credential_values=credential_values,
            pin=True,
        )
        try:
            yield lease
        finally:
            victims: list[object] = []
            with self._lock:
                active = self._active_lease_keys.get(key, 0)
                if active <= 1:
                    self._active_lease_keys.pop(key, None)
                else:
                    self._active_lease_keys[key] = active - 1
                while len(self._leases) > self.max_cached_leases:
                    victim_key = next(
                        (
                            candidate
                            for candidate in self._leases
                            if self._active_lease_keys.get(candidate, 0) == 0
                        ),
                        None,
                    )
                    if victim_key is None:
                        break
                    victims.append(self._leases.pop(victim_key))
                    self._active_lease_keys.pop(victim_key, None)
                    self._lease_evictions += 1
            for victim in victims:
                victim.close()

    def maintain(self) -> int:
        with self._lock:
            leases = list(self._leases.values())
        return sum(
            int(lease.task_run.prune_dead_connections())
            for lease in leases
            if hasattr(lease, "task_run")
        )

    def status(self) -> dict[str, object]:
        with self._lock:
            leases = list(self._leases.values())
            active_leases = sum(self._active_lease_keys.values())
        return {
            "task_id": self.task_id,
            "debug_run_count": len(leases),
            "debug_lease_cache_limit": self.max_cached_leases,
            "debug_lease_evictions": self._lease_evictions,
            "active_debug_leases": active_leases,
            "peak_debug_leases": self._peak_leases,
            "debug_runs": [lease.runtime_status() for lease in leases],
        }

    def close(self) -> None:
        with self._lock:
            leases = list(self._leases.values())
            self._leases.clear()
            self._active_lease_keys.clear()
        for lease in leases:
            lease.close()


class DebugMcpBackend:
    def __init__(
        self,
        *,
        engine_name: str = "mcp",
        mutation_journal_store=None,
        max_cached_leases: int = 32,
    ) -> None:
        self.engine_name = engine_name
        self.mutation_journal_store = mutation_journal_store
        self.max_cached_leases = int(max_cached_leases)

    def open_task(self, task_id: str) -> DebugMcpTask:
        return DebugMcpTask(
            task_id,
            mutation_journal_store=self.mutation_journal_store,
            max_cached_leases=self.max_cached_leases,
        )

    @staticmethod
    def close_task(task: DebugMcpTask) -> None:
        task.close()

    @staticmethod
    def maintain_task(task: DebugMcpTask) -> int:
        return task.maintain()

    @staticmethod
    def task_status(task: DebugMcpTask) -> dict[str, object]:
        return task.status()

    @staticmethod
    def _workflow_args(
        bounded: dict[str, object],
        context,
        *,
        default_deadline: int,
        fast_snapshot: bool,
    ):
        bounded["deadline"] = max(
            1,
            min(
                int(bounded.get("deadline", default_deadline)),
                int(math.ceil(context.remaining())),
            ),
        )
        try:
            args = workflow_remote.parse_args(_workflow_argv(bounded))
            for name in _TRANSPORT_STRING_OPTIONS:
                setattr(args, name, str(bounded.get(name, "")))
            for name in _TRANSPORT_BOOLEAN_OPTIONS:
                setattr(args, name, _boolean_argument(bounded, name))
            args.fast_snapshot = fast_snapshot
            workflow_remote._validate_numeric_args(args)
            workflow_remote.validate_workflow_inputs(args)
        except SystemExit as exc:
            message = (
                str(exc.code).strip()
                if isinstance(exc.code, str) and str(exc.code).strip()
                else "Debug arguments failed validation"
            )
            raise ValueError(message) from None
        return args

    def observe_query(
        self,
        task: DebugMcpTask,
        arguments: Mapping[str, object],
        context,
    ) -> dict[str, object]:
        """Collect full capability truth plus exact MDB values without a Case."""

        context.raise_if_stopped()
        bounded = dict(arguments)
        bounded.pop("_context_authoritative", None)
        selectors = bounded.pop("selectors", [])
        if not isinstance(selectors, list) or not all(
            isinstance(item, Mapping) for item in selectors
        ):
            raise TypeError("selectors must be an array of objects")
        normalized_selectors = [dict(item) for item in selectors]
        capability_names = bounded.pop("capability_names", [])
        if not isinstance(capability_names, list) or not all(
            isinstance(item, str) for item in capability_names
        ):
            raise TypeError("capability_names must be an array of strings")
        assured = bounded.pop("assured", False)
        if not isinstance(assured, bool):
            raise TypeError("assured must be a boolean")
        prior_observation = bounded.pop("prior_observation", None)
        if prior_observation is not None and not isinstance(prior_observation, Mapping):
            raise TypeError("prior_observation must be an object")
        if prior_observation is not None and not assured:
            raise ValueError("prior_observation is only valid for assured upgrade")
        declared_capability_names = [
            str(name)
            for selector in normalized_selectors
            if selector.get("kind") == "capability"
            for name in selector.get("names", [])
        ]
        declared_mdb_queries = [
            str(query)
            for selector in normalized_selectors
            if selector.get("kind") == "mdb"
            for query in selector.get("queries", [])
        ]
        if declared_capability_names != capability_names:
            raise ValueError(
                "capability selector scope does not match Runtime arguments"
            )
        if declared_mdb_queries != list(bounded.get("mdb_queries", [])):
            raise ValueError("MDB selector scope does not match Runtime arguments")
        systemd_selectors = [item for item in normalized_selectors if item.get("kind") == "systemd"]
        if len(systemd_selectors) > 1:
            raise ValueError("one systemd selector is allowed per observation")
        for selector in systemd_selectors:
            systemd_observation.validate_names(selector.get("names"))
        credential_values = bounded.pop("_credential_values", None)
        minimum_target_epoch = bounded.pop("_minimum_target_epoch", 0)
        preflight_checks: set[str] = set()
        for name in capability_names:
            if name == "ssh":
                preflight_checks.add("SSH")
            elif name == "telnet":
                preflight_checks.add("TELNET")
            elif name == "mdbctl":
                preflight_checks.update({"SSH", "MDBCTL"})
            elif name == "dbus":
                preflight_checks.update({"SSH", "DBUS_ENV"})
            elif name in {"busctl", "alarms"}:
                preflight_checks.update({"SSH", "DBUS_ENV", "BUSCTL"})
        if systemd_selectors:
            preflight_checks.add("SSH")
        if bounded.get("mdb_queries"):
            preflight_checks.update({"SSH", "MDBCTL"})
        bounded["mdb_only"] = preflight_checks <= {"SSH", "MDBCTL"}
        bounded["mdb_concurrency"] = "auto"
        bounded["skip_telnet"] = "TELNET" not in preflight_checks
        bounded["no_freshness"] = True
        bounded["no_source_correlation"] = True
        args = self._workflow_args(
            bounded,
            context,
            default_deadline=180,
            fast_snapshot=True,
        )
        args.preflight_checks = sorted(preflight_checks)
        deadline = workflow_remote.WorkflowDeadline(args.deadline)
        environment = os.environ.copy()
        with task.lease_scope(
            args,
            credential_values=(
                dict(credential_values)
                if isinstance(credential_values, Mapping)
                else None
            ),
        ) as lease:
            if minimum_target_epoch:
                lease.task_run.ensure_target_epoch(
                    lease.target,
                    int(minimum_target_epoch),
                    reason="agent-observation",
                )
            runner = workflow_remote.build_typed_debug_tool_runner(lease)
            if isinstance(prior_observation, Mapping):
                prior_result = prior_observation.get("result", {})
                if not isinstance(prior_result, Mapping):
                    raise ValueError("prior observation result is invalid")
                preflight = prior_result.get("preflight_start", {})
                prior_lanes = prior_result.get("lanes", {})
                ssh_lane = (
                    prior_lanes.get("ssh", {})
                    if isinstance(prior_lanes, Mapping)
                    else {}
                )
                if not isinstance(preflight, Mapping) or not isinstance(ssh_lane, Mapping):
                    raise ValueError("prior observation cannot be reused")
                preflight = dict(preflight)
                mdb_results = dict(ssh_lane)
                capabilities = workflow_remote.preflight_capabilities(preflight)
                if not runner.prepare_assurance_refresh(args):
                    raise _load_runtime_module().AssuranceUnavailable(
                        "prior capability scope is no longer epoch-valid"
                    )
            else:
                preflight = runner(
                    "preflight_start",
                    workflow_remote._preflight_command(args),
                    environment,
                    args.timeout,
                    deadline=deadline,
                )
                capabilities = workflow_remote.preflight_capabilities(preflight)
                requested_queries = list(getattr(args, "mdb_queries", []))
                if requested_queries and capabilities.get("mdbctl") is True:
                    mdb_results = workflow_remote._run_mdb_plan(
                        args,
                        environment,
                        deadline,
                        tool_runner=runner,
                    )
                else:
                    reason = "mdbctl capability was unavailable"
                    mdb_results = {
                        ("mdbctl" if index == 0 else f"mdbctl_{index + 1}"): (
                            workflow_remote.skipped_result(
                                "mdbctl" if index == 0 else f"mdbctl_{index + 1}",
                                reason,
                            )
                        )
                        for index, _query in enumerate(requested_queries)
                    }
            systemd_results = {}
            ssh_credentials = lease.ssh_credentials_mapping() if systemd_selectors else {}
            def run_systemd_ssh(command, **limits):
                return lease.ssh_runner(ip=args.ip, remote_cmd=command,
                                        **ssh_credentials, **limits)
            for selector in systemd_selectors:
                systemd_results[selector["id"]] = lease.run_ssh_read(
                    request_id=f"systemd-{uuid.uuid4().hex}", collector_name="systemd",
                    operation={"names": selector["names"]},
                    collect=lambda selector=selector: systemd_observation.collect_systemd(
                        selector["names"], run_systemd_ssh,
                        deadline=time.monotonic() + deadline.remaining(),
                        secret_values=(str(ssh_credentials.get("password", "")),)),
                )
            preflight_end = None
            if assured:
                preflight_end = runner(
                    "preflight_end",
                    workflow_remote._preflight_command(args),
                    environment,
                    args.timeout,
                    deadline=deadline,
                )
                capabilities = workflow_remote.preflight_capabilities(preflight_end)
            runtime_status = lease.runtime_status()
        context.raise_if_stopped()
        freshness_anchor = preflight_end or preflight
        preflight_payload = freshness_anchor.get("payload", {})
        observed_at = (
            str(preflight_payload.get("observed_at", ""))
            if isinstance(preflight_payload, Mapping)
            else ""
        )
        selector_facts: list[dict[str, object]] = []
        mdb_index = 0
        runtime = _load_runtime_module()
        capability_started, capability_completed = _result_window(
            preflight_end or preflight
        )
        for selector in normalized_selectors:
            selector_id = str(selector.get("id", ""))
            kind = str(selector.get("kind", ""))
            if not selector_id or kind not in {"capability", "mdb", "systemd"}:
                raise ValueError("selector identity and kind must be explicit")
            if kind == "systemd":
                child = systemd_results[selector_id]
                selector_facts.append({"selector_id": selector_id, "kind": kind,
                    "started_at": child["started_at"], "completed_at": child["completed_at"],
                    "status": "observed" if child["complete"] else "missing"})
                continue
            if kind == "capability":
                names = selector.get("names", [])
                observed = isinstance(names, list) and runtime.capability_selector_complete(
                    capabilities,
                    [str(name) for name in names],
                )
                selector_facts.append(
                    {
                        "selector_id": selector_id,
                        "kind": kind,
                        "started_at": capability_started,
                        "completed_at": capability_completed,
                        "status": "observed" if observed else "missing",
                    }
                )
                continue
            queries = selector.get("queries", [])
            children: list[Mapping[str, object]] = []
            for _query in queries if isinstance(queries, list) else []:
                name = "mdbctl" if mdb_index == 0 else f"mdbctl_{mdb_index + 1}"
                mdb_index += 1
                child = mdb_results.get(name)
                if isinstance(child, Mapping):
                    children.append(child)
            windows = [_result_window(child) for child in children]
            starts = [
                (instant, value)
                for value, _completed in windows
                if (instant := _observation_instant(value)) is not None
            ]
            completions = [
                (instant, value)
                for _started, value in windows
                if (instant := _observation_instant(value)) is not None
            ]
            expected_queries = len(queries) if isinstance(queries, list) else 0
            selector_facts.append(
                {
                    "selector_id": selector_id,
                    "kind": kind,
                    "started_at": (
                        min(starts, key=lambda item: item[0])[1]
                        if starts
                        else observed_at
                        if len(children) == expected_queries and expected_queries > 0
                        else ""
                    ),
                    "completed_at": (
                        max(completions, key=lambda item: item[0])[1]
                        if completions
                        else observed_at
                        if len(children) == expected_queries and expected_queries > 0
                        else ""
                    ),
                    "status": (
                        "observed"
                        if len(children) == expected_queries
                        and expected_queries > 0
                        and all(child.get("ok") is True for child in children)
                        else "missing"
                    ),
                }
            )
        attempt_started, attempt_completed = _attempt_window(selector_facts)
        return {
            "schema_version": "openubmc-debug.v1",
            "tool": "agent_observe",
            "ip": str(args.ip),
            "observed_at": observed_at,
            "ok": bool(preflight.get("ok")) and (
                preflight_end is None or bool(preflight_end.get("ok"))
            ),
            "code": str(freshness_anchor.get("code", "ok")),
            "returncode": int(freshness_anchor.get("returncode", 0)),
            "observation_timing": {
                "started_at": attempt_started,
                "completed_at": attempt_completed,
                "selectors": selector_facts,
            },
            "result": {
                "capabilities": capabilities,
                "preflight_start": preflight,
                **(
                    {"preflight_end": preflight_end}
                    if preflight_end is not None
                    else {}
                ),
                **({"systemd": systemd_results} if systemd_results else {}),
                "lanes": {"ssh": mdb_results},
                "runtime": {"engine": self.engine_name, "status": runtime_status},
            },
        }

    def _run_single(
        self,
        task: DebugMcpTask,
        arguments: Mapping[str, object],
        context,
        *,
        collect_only: bool,
    ) -> dict[str, object]:
        context.raise_if_stopped()
        bounded = dict(arguments)
        hardware_acceptance = _normalize_hardware_acceptance(
            bounded.pop("hardware_acceptance", None)
        )
        credential_values = bounded.pop("_credential_values", None)
        if credential_values is not None and not isinstance(
            credential_values, Mapping
        ):
            raise TypeError("_credential_values must be an internal mapping")
        minimum_target_epoch = bounded.pop("_minimum_target_epoch", 0)
        if (
            isinstance(minimum_target_epoch, bool)
            or not isinstance(minimum_target_epoch, int)
            or minimum_target_epoch < 0
        ):
            raise TypeError("_minimum_target_epoch must be a non-negative integer")
        profile = str(bounded.get("profile", "standard"))
        if profile not in {"standard", "mdb", "object-alarm"}:
            raise ValueError(
                "profile must describe evidence scope: standard, mdb, or object-alarm"
            )
        fast_object_alarm = collect_only and profile == "object-alarm"
        fast_mdb = collect_only and (
            profile == "mdb"
            or (profile == "standard" and bounded.get("mdb_only") is True)
        )
        if fast_object_alarm:
            bounded["skip_telnet"] = True
            bounded["no_freshness"] = True
            bounded["no_source_correlation"] = True
        if fast_mdb:
            bounded["mdb_only"] = True
            bounded["skip_telnet"] = True
            bounded["no_freshness"] = True
            bounded["no_source_correlation"] = True
        args = self._workflow_args(
            bounded,
            context,
            default_deadline=600,
            fast_snapshot=fast_object_alarm or fast_mdb,
        )
        source_root, source_root_source = resolve_source_root(args.source_root)
        args.source_root = str(source_root) if source_root else ""
        with task.lease_scope(
            args,
            credential_values=(
                dict(credential_values)
                if isinstance(credential_values, Mapping)
                else None
            ),
        ) as lease:
            if minimum_target_epoch:
                lease.task_run.ensure_target_epoch(
                    lease.target,
                    minimum_target_epoch,
                    reason="orchestrated-fresh-verification",
                )
            captured: list[dict[str, object]] = []
            returncode = workflow_remote._execute_workflow(
                args,
                source_root_source=source_root_source,
                engine=self.engine_name,
                env=os.environ.copy(),
                tool_runner=workflow_remote.build_typed_debug_tool_runner(lease),
                runtime_status=lease.runtime_status,
                parallel_lanes=True,
                emit_output=False,
                output_handler=captured.append,
            )
        context.raise_if_stopped()
        if len(captured) != 1:
            raise RuntimeError("Debug workflow did not produce exactly one result")
        result = captured[0]
        if int(result.get("returncode", returncode)) != returncode:
            raise RuntimeError("Debug workflow return code disagrees with its result")
        return (
            _apply_hardware_acceptance(result, hardware_acceptance)
            if collect_only
            else result
        )

    def debug_run(self, task, arguments, context) -> dict[str, object]:
        targets = arguments.get("targets")
        if targets is None:
            return self._run_single(task, arguments, context, collect_only=False)
        if not isinstance(targets, list) or len(targets) < 2 or not all(
            isinstance(target, Mapping) for target in targets
        ):
            raise ValueError("targets must contain at least two target objects")
        concurrency = arguments.get("concurrency", "auto")
        common = {
            key: value
            for key, value in arguments.items()
            if key not in {"targets", "reference_role", "concurrency", "_credential_values_by_target"}
        }
        merged_targets = [
            {**common, **dict(target)}
            for target in targets
        ]
        credentials_by_target = arguments.get("_credential_values_by_target", {})
        def runner(request, child_context):
            scoped = dict(request)
            selected = credentials_by_target.get(str(request.get("ip", "")))
            if selected is not None:
                scoped["_credential_values"] = selected
            return self._run_single(task, scoped, child_context, collect_only=False)
        if len(merged_targets) == 2:
            payload = run_dual_target_comparison(
                targets=merged_targets,
                run_target=runner,
                context=context,
                concurrency=concurrency,
            )
        else:
            payload = run_multi_target_comparison(
                targets=merged_targets,
                run_target=runner,
                context=context,
                concurrency=concurrency,
            )
        return (
            compact_comparison_values(payload)
            if arguments.get("compact_json") is True
            else payload
        )

    def debug_collect(self, task, arguments, context) -> dict[str, object]:
        return self._run_single(task, arguments, context, collect_only=True)


def _positive_env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    value = int(raw)
    if value < 1:
        raise SystemExit(f"{name} must be positive")
    return value


def _positive_env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be finite and positive") from exc
    if not math.isfinite(value) or value <= 0:
        raise SystemExit(f"{name} must be finite and positive")
    return value


def _parent_pid_environment() -> tuple[int, str | None]:
    raw = os.environ.get("OPENUBMC_MCP_PARENT_PID", "").strip()
    if not raw:
        return os.getppid(), None
    try:
        value = int(raw)
    except ValueError:
        return 0, "OPENUBMC_MCP_PARENT_PID must be a non-negative integer"
    if value < 0:
        return 0, "OPENUBMC_MCP_PARENT_PID must be a non-negative integer"
    return value, None


def _runtime_state_dir() -> Path:
    configured = os.environ.get("OPENUBMC_TARGET_RUNTIME_STATE_DIR", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path.home() / ".local" / "state" / "openubmc-target-runtime").resolve()


_LOG_ANALYZER_MODULE = None
_LIVE_PATCH_MODULE = None
_UPGRADE_MODULE = None


def _load_log_analyzer_backend(*, artifact_store=None):
    """Load the sibling domain through its public Python integration surface."""

    global _LOG_ANALYZER_MODULE
    if _LOG_ANALYZER_MODULE is not None:
        return _LOG_ANALYZER_MODULE.LogBundleMcpBackend(
            artifact_store=artifact_store
        )
    skill_root = (
        Path(__file__).resolve().parents[2]
        / "openubmc-log-analyzer"
    )
    package = skill_root / "openubmc_log_analyzer" / "__init__.py"
    if not package.is_file():
        return None
    added = str(skill_root) not in sys.path
    if added:
        sys.path.insert(0, str(skill_root))
    try:
        module = importlib.import_module(
            "openubmc_log_analyzer.runtime_backend"
        )
    finally:
        if added:
            try:
                sys.path.remove(str(skill_root))
            except ValueError:
                pass
    _LOG_ANALYZER_MODULE = module
    return module.LogBundleMcpBackend(artifact_store=artifact_store)


def _load_public_domain_module(skill_name: str, package_name: str, module_name: str):
    skill_root = Path(__file__).resolve().parents[2] / skill_name
    package = skill_root / package_name / "__init__.py"
    if not package.is_file():
        return None
    added = str(skill_root) not in sys.path
    if added:
        sys.path.insert(0, str(skill_root))
    try:
        return importlib.import_module(f"{package_name}.{module_name}")
    finally:
        if added:
            try:
                sys.path.remove(str(skill_root))
            except ValueError:
                pass


def _load_live_patch_backend(journal_store):
    global _LIVE_PATCH_MODULE
    if _LIVE_PATCH_MODULE is None:
        _LIVE_PATCH_MODULE = _load_public_domain_module(
            "openubmc-live-patch",
            "openubmc_live_patch",
            "runtime_backend",
        )
    if _LIVE_PATCH_MODULE is None:
        return None
    return _LIVE_PATCH_MODULE.LivePatchMcpBackend(journal_store=journal_store)


def _load_upgrade_backend(journal_store):
    global _UPGRADE_MODULE
    if _UPGRADE_MODULE is None:
        _UPGRADE_MODULE = _load_public_domain_module(
            "openubmc-upgrade",
            "openubmc_upgrade",
            "runtime_backend",
        )
    if _UPGRADE_MODULE is None:
        return None
    return _UPGRADE_MODULE.UpgradeMcpBackend(journal_store=journal_store)


def create_service():
    select_default_credentials_file()
    runtime = _load_runtime_module()
    state_dir = _runtime_state_dir()
    artifact_dir = state_dir / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_store = runtime.LocalArtifactStore(
        content_root=artifact_dir / "content",
        repository=runtime.SQLiteArtifactRepository(
            state_dir / "artifact-lifecycle.sqlite3"
        ),
    )
    journal_store = runtime.MutationJournalStore(
        state_dir / "mutations",
        artifact_roots=(artifact_dir,),
    )
    debug_backend = DebugMcpBackend(
        mutation_journal_store=journal_store,
        max_cached_leases=_positive_env_int(
            "OPENUBMC_TARGET_RUNTIME_DEBUG_LEASE_CACHE", 32
        ),
    )
    tool_backends = {
        "debug_run": debug_backend,
        "debug_collect": debug_backend,
    }
    log_backend = _load_log_analyzer_backend(artifact_store=artifact_store)
    if log_backend is not None:
        for operation in (
            "log_bundle_collect",
            "log_bundle_index",
            "log_bundle_query",
            "log_bundle_export",
        ):
            tool_backends[operation] = log_backend
    live_patch_backend = _load_live_patch_backend(journal_store)
    if live_patch_backend is not None:
        tool_backends["live_patch_run"] = live_patch_backend
    upgrade_backend = _load_upgrade_backend(journal_store)
    if upgrade_backend is not None:
        tool_backends["upgrade_run"] = upgrade_backend
        tool_backends["upgrade_batch"] = upgrade_backend
    task_context_store = runtime.TaskContextStore(
        state_dir / "task-contexts",
        ttl_seconds=_positive_env_int(
            "OPENUBMC_TARGET_RUNTIME_CONTEXT_TTL",
            7 * 24 * 60 * 60,
        ),
        max_entries=_positive_env_int(
            "OPENUBMC_TARGET_RUNTIME_CONTEXT_MAX_ENTRIES",
            128,
        ),
        max_state_bytes=_positive_env_int(
            "OPENUBMC_TARGET_RUNTIME_CONTEXT_MAX_BYTES",
            256 * 1024,
        ),
    )
    orchestrated_backend = runtime.OrchestratedMcpBackend(
        tool_backends,
        state_store=task_context_store,
    )
    return runtime.RuntimeMcpService(
        orchestrated_backend,
        interface_profile=os.environ.get(
            "OPENUBMC_TARGET_RUNTIME_INTERFACE_PROFILE", "agent"
        ),
        context_repository=runtime.SQLiteRuntimeRepository(
            state_dir / "context-runtime.sqlite3"
        ),
        session_outcome_repository=runtime.SQLiteSessionOutcomeRepository(
            state_dir / "session-outcomes.sqlite3"
        ),
        blob_repository=runtime.FilesystemBlobRepository(
            state_dir / "evidence-blobs"
        ),
        artifact_store=artifact_store,
        envelope_max_bytes=_positive_env_int(
            "OPENUBMC_TARGET_RUNTIME_ENVELOPE_MAX_BYTES", 24 * 1024
        ),
        context_max_cached_projections=_positive_env_int(
            "OPENUBMC_TARGET_RUNTIME_CASE_CACHE", 64
        ),
        context_retention_seconds=_positive_env_int(
            "OPENUBMC_TARGET_RUNTIME_CASE_TTL", 7 * 24 * 60 * 60
        ),
        context_storage_soft_limit_bytes=_positive_env_int(
            "OPENUBMC_TARGET_RUNTIME_STORAGE_SOFT_BYTES", 1024 * 1024 * 1024
        ),
        context_mode=os.environ.get(
            "OPENUBMC_TARGET_RUNTIME_CONTEXT_MODE", "authoritative"
        ),
        max_tasks=_positive_env_int("OPENUBMC_TARGET_RUNTIME_MAX_TASKS", 32),
        idle_timeout_seconds=_positive_env_int(
            "OPENUBMC_TARGET_RUNTIME_IDLE_TIMEOUT", 1800
        ),
        max_lifetime_seconds=_positive_env_int(
            "OPENUBMC_TARGET_RUNTIME_MAX_LIFETIME", 28800
        ),
        max_concurrent_operations=_positive_env_int(
            "OPENUBMC_TARGET_RUNTIME_MAX_OPERATIONS", 8
        ),
    )


def main() -> int:
    runtime = _load_runtime_module()
    configured_task = (
        os.environ.get("OPENUBMC_MCP_TASK_ID", "").strip()
        or os.environ.get("CODEX_TASK_ID", "").strip()
        or os.environ.get("OPENUBMC_EVALUATION_TASK_ID", "").strip()
    )
    configured_session = os.environ.get(
        "OPENUBMC_MCP_SESSION_ID", ""
    ).strip()
    session_id = configured_session or configured_task or "unknown-session"
    task_id = configured_task or "unknown-task"
    client = os.environ.get("OPENUBMC_MCP_CLIENT", "").strip()
    if not client and os.environ.get("CODEX_TASK_ID", "").strip():
        client = "codex"
    elif not client and os.environ.get("OPENUBMC_EVALUATION_TASK_ID", "").strip():
        client = "dsh"
    client = client or "unknown-client"
    source_commit = os.environ.get(
        "OPENUBMC_MCP_SOURCE_COMMIT", "unknown-source-commit"
    ).strip() or "unknown-source-commit"
    identity_errors: list[str] = []

    def identity_environment(name: str) -> dict[str, object]:
        raw = os.environ.get(name, "").strip()
        if not raw:
            return {}
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            identity_errors.append(f"{name} must be a JSON object")
            return {}
        if not isinstance(value, dict):
            identity_errors.append(f"{name} must be a JSON object")
            return {}
        return value

    model_identity = identity_environment("OPENUBMC_MCP_MODEL_IDENTITY")
    codex_identity = identity_environment("OPENUBMC_MCP_CODEX_IDENTITY")
    formal_run_raw = os.environ.get("OPENUBMC_MCP_FORMAL_RUN", "").strip().lower()
    if formal_run_raw in {"", "0", "false", "no"}:
        formal_run = False
    elif formal_run_raw in {"1", "true", "yes"}:
        formal_run = True
    else:
        formal_run = False
        identity_errors.append("OPENUBMC_MCP_FORMAL_RUN must be boolean")
    if formal_run and (not model_identity or not codex_identity):
        identity_errors.append("formal MCP run requires model and Codex identity")
    parent_pid, parent_pid_error = _parent_pid_environment()
    if formal_run and parent_pid != os.getppid():
        identity_errors.append("formal MCP run requires direct parent identity")
    state_dir = _runtime_state_dir()
    configured_lifecycle_root = os.environ.get(
        "OPENUBMC_MCP_LIFECYCLE_DIR", ""
    ).strip()
    if configured_lifecycle_root:
        lifecycle_root = Path(configured_lifecycle_root)
    elif os.environ.get("OPENUBMC_TARGET_RUNTIME_STATE_DIR", "").strip():
        lifecycle_root = state_dir / "mcp-processes"
    else:
        lifecycle_root = (
            Path.home()
            / ".local"
            / "state"
            / "openubmc-agent-workflow"
            / "mcp-processes"
        )
    if formal_run:
        if client != "codex":
            identity_errors.append("formal MCP run requires Codex client identity")
        if not configured_task:
            identity_errors.append("formal MCP run requires task ID")
        if not configured_session:
            identity_errors.append("formal MCP run requires session ID")
        if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", source_commit) is None:
            identity_errors.append("formal MCP run requires full source commit")
        if not os.environ.get("OPENUBMC_TARGET_RUNTIME_STATE_DIR", "").strip():
            identity_errors.append("formal MCP run requires Runtime state root")
        if not configured_lifecycle_root:
            identity_errors.append("formal MCP run requires lifecycle root")
    idle_timeout_error: SystemExit | None = None
    try:
        mcp_idle_timeout_seconds = _positive_env_float(
            "OPENUBMC_MCP_IDLE_TIMEOUT_SECONDS", 1800.0
        )
    except SystemExit as exc:
        mcp_idle_timeout_seconds = 1800.0
        idle_timeout_error = exc
    process_lifecycle = runtime.McpProcessLifecycle(
        component="target-runtime",
        version=runtime.RUNTIME_API_VERSION,
        client=client,
        task_id=task_id,
        session_id=session_id,
        source_commit=source_commit,
        model_identity=model_identity,
        codex_identity=codex_identity,
        formal_run=formal_run,
        parent_pid=parent_pid,
        state_path=state_dir,
        lifecycle_root=lifecycle_root,
        idle_timeout_seconds=mcp_idle_timeout_seconds,
    )
    if parent_pid_error is not None:
        process_lifecycle.record_exit("startup-error")
        raise SystemExit(parent_pid_error)
    if identity_errors:
        process_lifecycle.record_exit("startup-error")
        raise SystemExit("; ".join(identity_errors))
    if formal_run and not process_lifecycle.status()["parent_identity_verified"]:
        process_lifecycle.record_exit("startup-error")
        raise SystemExit("formal MCP run requires verified parent identity")
    if idle_timeout_error is not None:
        process_lifecycle.record_exit("startup-error")
        raise idle_timeout_error
    try:
        lifecycle_poll_seconds = _positive_env_float(
            "OPENUBMC_MCP_LIFECYCLE_POLL_SECONDS", 0.25
        )
    except SystemExit:
        process_lifecycle.record_exit("startup-error")
        raise
    try:
        service = create_service()
    except BaseException:
        process_lifecycle.record_exit("startup-error")
        raise
    endpoint = runtime.JsonRpcMcpEndpoint(
        service,
        session_task_id=configured_task or None,
    )
    server = runtime.StdioMcpServer(
        endpoint,
        process_lifecycle=process_lifecycle,
        lifecycle_poll_seconds=lifecycle_poll_seconds,
    )
    server.serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
