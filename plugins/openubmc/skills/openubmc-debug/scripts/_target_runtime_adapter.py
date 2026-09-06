#!/usr/bin/env python3
"""Compatibility adapter from public helpers to Target Runtime v1."""
from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
from typing import TypeVar
import uuid

from _remote_common import OpenSshControlMasterTransport
from _runtime_distribution import (
    read_runtime_api_version,
    runtime_content_digest,
)
from _telnet_common import (
    TelnetCommandResult,
    close_telnet,
    run_cmd_result,
    telnet_connect,
)


TARGET_RUNTIME_API_VERSION = "openubmc.target-runtime.v1"
PACKAGE_MARKER = ".openubmc-debug-package.json"
_RUNTIME_MODULE_CACHE: dict[str, object] = {}
T = TypeVar("T")


def _runtime_failure(reason: str) -> SystemExit:
    return SystemExit(
        "Target Runtime v1 validation failed before remote execution: "
        f"{reason}; repair or reinstall the Runtime/MCP environment"
    )


def _read_json_object(path: Path, *, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _runtime_failure(f"{label} is unavailable or invalid") from exc
    if not isinstance(value, dict):
        raise _runtime_failure(f"{label} must contain a JSON object")
    return value


def _validated_contract(value: object, *, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise _runtime_failure(f"{label} is missing Target Runtime metadata")
    required = ("apiVersion", "contentDigest", "vendorPath", "source")
    contract: dict[str, str] = {}
    for key in required:
        item = value.get(key)
        if not isinstance(item, str) or not item.strip():
            raise _runtime_failure(f"{label} has an invalid {key}")
        contract[key] = item
    return contract


def _package_runtime_contract() -> tuple[Path, dict[str, str]] | None:
    skill_root = Path(__file__).resolve().parents[1]
    marker_path = skill_root / PACKAGE_MARKER
    if not marker_path.exists():
        return None
    marker = _read_json_object(marker_path, label="package marker")
    manifest = _read_json_object(skill_root / "skill.json", label="package manifest")
    marker_contract = _validated_contract(
        marker.get("target_runtime"), label="package marker"
    )
    manifest_contract = _validated_contract(
        manifest.get("targetRuntime"), label="package manifest"
    )
    if marker_contract["apiVersion"] != manifest_contract["apiVersion"]:
        raise _runtime_failure("Runtime API mismatch between package marker and manifest")
    if marker_contract["contentDigest"] != manifest_contract["contentDigest"]:
        raise _runtime_failure(
            "Runtime content digest mismatch between package marker and manifest"
        )
    if marker_contract != manifest_contract:
        raise _runtime_failure(
            "Target Runtime package metadata mismatch between marker and manifest"
        )
    vendor_relative = Path(marker_contract["vendorPath"])
    if (
        vendor_relative.is_absolute()
        or vendor_relative.as_posix() != marker_contract["vendorPath"]
        or any(part in {"", ".", ".."} for part in vendor_relative.parts)
    ):
        raise _runtime_failure("package vendorPath must stay inside the Skill root")
    vendor_root = (skill_root / vendor_relative).resolve()
    if skill_root.resolve() not in vendor_root.parents:
        raise _runtime_failure("package vendorPath escapes the Skill root")
    return vendor_root, marker_contract


def _import_runtime_package(package_root: Path, digest: str):
    cache_key = f"{package_root.resolve()}|{digest}"
    cached = _RUNTIME_MODULE_CACHE.get(cache_key)
    if cached is not None:
        return cached
    module_name = "_openubmc_target_runtime_" + digest.rsplit(":", 1)[-1][:16]
    existing = sys.modules.get(module_name)
    if existing is not None:
        _RUNTIME_MODULE_CACHE[cache_key] = existing
        return existing
    init_path = package_root / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        module_name,
        init_path,
        submodule_search_locations=[str(package_root)],
    )
    if spec is None or spec.loader is None:
        raise _runtime_failure(f"cannot import Runtime package from {package_root}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        for loaded_name in tuple(sys.modules):
            if loaded_name == module_name or loaded_name.startswith(module_name + "."):
                sys.modules.pop(loaded_name, None)
        raise
    _RUNTIME_MODULE_CACHE[cache_key] = module
    return module


def _load_validated_runtime(
    package_root: Path,
    *,
    expected_api: str,
    expected_digest: str | None,
):
    if not (package_root / "__init__.py").is_file():
        raise _runtime_failure(f"Runtime package is missing at {package_root}")
    actual_api = read_runtime_api_version(package_root)
    if actual_api != expected_api:
        raise _runtime_failure(
            f"Runtime API mismatch: expected {expected_api}, found {actual_api}"
        )
    actual_digest = runtime_content_digest(package_root)
    if expected_digest is not None and actual_digest != expected_digest:
        raise _runtime_failure(
            "Runtime content digest mismatch: "
            f"expected {expected_digest}, found {actual_digest}"
        )
    module = _import_runtime_package(package_root, actual_digest)
    if getattr(module, "RUNTIME_API_VERSION", None) != expected_api:
        raise _runtime_failure(
            "Runtime API mismatch after import; package metadata is inconsistent"
        )
    return module


def _load_runtime_module():
    packaged = _package_runtime_contract()
    if packaged is not None:
        vendor_root, contract = packaged
        return _load_validated_runtime(
            vendor_root,
            expected_api=contract["apiVersion"],
            expected_digest=contract["contentDigest"],
        )

    spec = importlib.util.find_spec("openubmc_target_runtime")
    if spec is not None and spec.origin:
        return _load_validated_runtime(
            Path(spec.origin).resolve().parent,
            expected_api=TARGET_RUNTIME_API_VERSION,
            expected_digest=None,
        )

    canonical_package = (
        Path(__file__).resolve().parents[2]
        / "openubmc-target-runtime"
        / "openubmc_target_runtime"
    )
    if (canonical_package / "__init__.py").is_file():
        return _load_validated_runtime(
            canonical_package,
            expected_api=TARGET_RUNTIME_API_VERSION,
            expected_digest=None,
        )
    raise _runtime_failure(
        "no installed, canonical, or package-vendored Runtime is available"
    )


class ObjectAlarmRuntimeLease:
    """Production adapter that binds typed object/alarm collectors to one SSH lane."""

    def __init__(
        self,
        *,
        args,
        credential_loader: Callable[[], Mapping[str, str | int]],
        task_id: str,
        transport_factory=None,
    ) -> None:
        runtime = _load_runtime_module()
        self._runtime = runtime
        self._closed = False
        selector = runtime.CredentialSelector.for_ssh(
            user=str(getattr(args, "ssh_user", "")),
            user_env=str(getattr(args, "ssh_user_env", "")),
            password_env=str(getattr(args, "ssh_password_env", "")),
            identity_file=str(getattr(args, "ssh_identity_file", "")),
            environ=os.environ,
        )
        host_key_policy = str(
            getattr(args, "ssh_host_key_policy", "")
            or os.environ.get("OPENUBMC_SSH_HOST_KEY_POLICY", "")
            or "insecure"
        )
        self.target = runtime.TargetSpec(
            host=str(args.ip),
            ssh_port=int(args.ssh_port),
            telnet_port=int(getattr(args, "telnet_port", 23)),
            redfish_port=int(getattr(args, "redfish_port", 443)),
            credential_selector_fingerprint=selector.fingerprint,
            policy=runtime.TargetPolicy(ssh_host_key_policy=host_key_policy),
        )
        self.selector = selector
        resolver = runtime.CredentialResolver(
            lambda _selector: runtime.ResolvedSshCredentials.from_mapping(
                credential_loader()
            )
        )
        self.task_run = runtime.OpenUBMCTaskRun(
            task_id=task_id,
            credential_resolver=resolver,
        )
        selected_transport_factory = (
            transport_factory or OpenSshControlMasterTransport
        )
        self.transport = selected_transport_factory(
            host_key_policy=str(getattr(args, "ssh_host_key_policy", "")),
            known_hosts_file=str(getattr(args, "ssh_known_hosts_file", "")),
            allow_insecure_host_key=bool(
                getattr(args, "allow_insecure_host_key", False)
            ),
        )
        self.lane = self.task_run.ssh_lane(
            target=self.target,
            credential_selector=self.selector,
            lease_name="debug-object-alarm",
            transport=self.transport,
        )

    @property
    def ssh_runner(self):
        return self._run_read_only_ssh

    def _run_read_only_ssh(self, *args, **kwargs):
        kwargs["replay_safe"] = True
        return self.lane.run_ssh(*args, **kwargs)

    def get_dbus_environment(self, loader: Callable[[], T]) -> T:
        return self.lane.get_dbus_environment(loader)

    def get_alarm_endpoint(self, loader: Callable[[], T]) -> T:
        return self.lane.get_alarm_endpoint(loader)

    def invalidate_alarm_endpoint(self) -> bool:
        return bool(self.lane.invalidate_alarm_endpoint())

    def cache_capability(self, name: str, value: T) -> T:
        return self.lane.cache_capability(name, value)

    def run_read(
        self,
        *,
        request_id: str,
        collector_name: str,
        operation: Mapping[str, object],
        collect: Callable[[Mapping[str, str | int], "ObjectAlarmRuntimeLease"], T],
    ) -> T:
        request = self._runtime.RemoteReadRequest.create(
            request_id=request_id,
            target=self.target,
            credential_selector=self.selector,
            collector_name=collector_name,
            operation=operation,
        )
        result = self.task_run.run_read(
            request,
            lambda context: collect(
                context.credentials.to_ssh_mapping(),
                self,
            ),
        )
        return result.value

    def runtime_status(self) -> dict[str, object]:
        return self.task_run.runtime_status()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.lane.close()

    def __enter__(self) -> "ObjectAlarmRuntimeLease":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def open_object_alarm_lease(
    *,
    args,
    credential_loader: Callable[[], Mapping[str, str | int]],
    task_id: str | None = None,
    transport_factory=None,
) -> ObjectAlarmRuntimeLease:
    return ObjectAlarmRuntimeLease(
        args=args,
        credential_loader=credential_loader,
        task_id=task_id or f"one-shot-{uuid.uuid4().hex}",
        transport_factory=transport_factory,
    )


def run_typed_object_alarm_one_shot(
    *,
    args,
    collector_name: str,
    operation: Mapping[str, object],
    credential_loader: Callable[[], Mapping[str, str | int]],
    collect: Callable[[Mapping[str, str | int], ObjectAlarmRuntimeLease], T],
) -> T:
    with open_object_alarm_lease(
        args=args,
        credential_loader=credential_loader,
    ) as lease:
        return lease.run_read(
            request_id=uuid.uuid4().hex,
            collector_name=collector_name,
            operation=operation,
            collect=collect,
        )


def run_typed_mdb_one_shot(
    *,
    args,
    command: list[str],
    credential_loader: Callable[[], Mapping[str, str | int]],
    collect: Callable[[Mapping[str, str | int], ObjectAlarmRuntimeLease], T],
) -> T:
    """Execute one MDB read through a fresh typed task-scoped Runtime."""

    return run_typed_object_alarm_one_shot(
        args=args,
        collector_name="mdbctl",
        operation={
            "command": list(command),
            "mode": str(args.mode),
            "timeout_seconds": int(args.timeout),
        },
        credential_loader=credential_loader,
        collect=collect,
    )


class TelnetSessionTransport:
    """Bind the existing login/framing implementation to a Runtime Telnet lane."""

    def __init__(
        self,
        *,
        connect_timeout: int,
        prompt_timeout: int,
        debug_label: str,
    ) -> None:
        self.connect_timeout = connect_timeout
        self.prompt_timeout = prompt_timeout
        self.debug_label = debug_label
        self.debug_dumper = None

    def bind_debug_context(self, debug_dumper, debug_label: str) -> None:
        self.debug_dumper = debug_dumper
        if debug_label:
            self.debug_label = debug_label

    def open_session(self, *, target, credentials):
        return telnet_connect(
            target.host,
            target.telnet_port,
            credentials.user,
            credentials.password,
            connect_timeout=self.connect_timeout,
            prompt_timeout=self.prompt_timeout,
            debug_dumper=self.debug_dumper,
            debug_label=self.debug_label,
        )

    def run_command(self, session, command: str, **kwargs: object):
        try:
            return run_cmd_result(
                session,
                command,
                timeout=int(kwargs.get("timeout", 20)),
                debug_dumper=kwargs.get("debug_dumper"),
                debug_name=str(kwargs.get("debug_name", "telnet")),
            )
        except OSError:
            return TelnetCommandResult(
                stdout="",
                returncode=None,
                framing_complete=False,
                timed_out=False,
                connection_closed=True,
                raw=b"",
            )

    @staticmethod
    def command_invalidates_session(_session, result) -> bool:
        return bool(
            not result.framing_complete
            or result.timed_out
            or result.connection_closed
        )

    @staticmethod
    def close_session(session) -> None:
        close_telnet(session)


class TelnetLaneSessionProxy:
    """Collector-compatible handle whose lifetime remains owned by the lease."""

    def __init__(self, lane) -> None:
        self._lane = lane

    def run_telnet_command(self, command: str, **kwargs: object):
        kwargs["replay_safe"] = True
        return self._lane.run_command(command, **kwargs)

    def release_telnet_client(self) -> None:
        return None

    def ensure_telnet_connected(self):
        return self._lane.ensure_connected()


class TelnetRuntimeLease:
    """Task-scoped adapter for Debug log and controlled-file collectors."""

    def __init__(
        self,
        *,
        args,
        credential_loader: Callable[[], Mapping[str, str | int]],
        lease_name: str,
        task_id: str,
        transport_factory=None,
    ) -> None:
        runtime = _load_runtime_module()
        self._closed = False
        self._runtime = runtime
        self.selector = runtime.CredentialSelector.for_telnet(
            user=str(getattr(args, "telnet_user", "")),
            user_env=str(getattr(args, "telnet_user_env", "")),
            password_env=str(getattr(args, "telnet_password_env", "")),
            environ=os.environ,
        )
        self.target = runtime.TargetSpec(
            host=str(args.ip),
            ssh_port=int(getattr(args, "ssh_port", 22)),
            telnet_port=int(args.telnet_port),
            redfish_port=int(getattr(args, "redfish_port", 443)),
            credential_selector_fingerprint=self.selector.fingerprint,
        )
        self.credentials = runtime.ResolvedTelnetCredentials.from_mapping(
            credential_loader()
        )
        self.task_run = runtime.OpenUBMCTaskRun(
            task_id=task_id,
        )
        selected_transport_factory = transport_factory or TelnetSessionTransport
        self.transport = selected_transport_factory(
            connect_timeout=int(args.connect_timeout),
            prompt_timeout=int(args.prompt_timeout),
            debug_label=f"{lease_name}_connect",
        )
        self.lane = self.task_run.telnet_lane(
            target=self.target,
            credentials=self.credentials,
            lease_name=lease_name,
            transport=self.transport,
        )
        self.session_proxy = TelnetLaneSessionProxy(self.lane)

    @property
    def telnet_epoch(self) -> int:
        return self.lane.telnet_epoch

    def credentials_mapping(self) -> dict[str, str | int]:
        return self.credentials.to_telnet_mapping()

    def bind_debug_context(self, debug_dumper, debug_label: str) -> None:
        binder = getattr(self.transport, "bind_debug_context", None)
        if callable(binder):
            binder(debug_dumper, debug_label)

    def connect(self):
        return self.lane.ensure_connected()

    def runtime_status(self) -> dict[str, object]:
        return self.task_run.runtime_status()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.lane.close()

    def __enter__(self) -> "TelnetRuntimeLease":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def open_telnet_lease(
    *,
    args,
    credential_loader: Callable[[], Mapping[str, str | int]],
    lease_name: str,
    task_id: str | None = None,
    transport_factory=None,
) -> TelnetRuntimeLease:
    return TelnetRuntimeLease(
        args=args,
        credential_loader=credential_loader,
        lease_name=lease_name,
        task_id=task_id or f"one-shot-{uuid.uuid4().hex}",
        transport_factory=transport_factory,
    )


def run_typed_telnet_one_shot(
    *,
    args,
    collector_name: str,
    operation: Mapping[str, object],
    credential_loader: Callable[[], Mapping[str, str | int]],
    collect: Callable[[Mapping[str, str | int], TelnetRuntimeLease], T],
) -> T:
    if not collector_name.strip():
        raise ValueError("collector_name must not be empty")
    if not isinstance(operation, Mapping):
        raise TypeError("operation must be a mapping")
    with open_telnet_lease(
        args=args,
        credential_loader=credential_loader,
        lease_name="debug-log-file",
    ) as lease:
        return collect(lease.credentials_mapping(), lease)


class _DebugObjectAlarmLease:
    """Collector-facing view of the DebugRun-owned SSH lane."""

    def __init__(self, lane) -> None:
        self.lane = lane

    @property
    def ssh_runner(self):
        return self._run_read_only_ssh

    def _run_read_only_ssh(self, *args, **kwargs):
        kwargs["replay_safe"] = True
        return self.lane.run_ssh(*args, **kwargs)

    def get_dbus_environment(self, loader: Callable[[], T]) -> T:
        return self.lane.get_dbus_environment(loader)

    def get_alarm_endpoint(self, loader: Callable[[], T]) -> T:
        return self.lane.get_alarm_endpoint(loader)

    def invalidate_alarm_endpoint(self) -> bool:
        return bool(self.lane.invalidate_alarm_endpoint())

    def cache_capability(self, name: str, value: T) -> T:
        return self.lane.cache_capability(name, value)


class _DebugTelnetLease:
    """Collector-facing view of the DebugRun-owned Telnet lane."""

    def __init__(self, lane, transport, credentials) -> None:
        self.lane = lane
        self.transport = transport
        self.credentials = credentials
        self.session_proxy = TelnetLaneSessionProxy(lane)

    @property
    def telnet_epoch(self) -> int:
        return self.lane.telnet_epoch

    def credentials_mapping(self) -> dict[str, str | int]:
        return self.credentials.to_telnet_mapping()

    def bind_debug_context(self, debug_dumper, debug_label: str) -> None:
        binder = getattr(self.transport, "bind_debug_context", None)
        if callable(binder):
            binder(debug_dumper, debug_label)

    def connect(self):
        return self.lane.ensure_connected()


class DebugRuntimeLease:
    """One single-target typed DebugRun with shared SSH/Telnet resources."""

    def __init__(
        self,
        *,
        args,
        credential_bundle: Mapping[str, Mapping[str, str | int]],
        task_id: str,
        ssh_transport_factory=None,
        telnet_transport_factory=None,
        evidence_max_records: int = 128,
        mutation_journal_store=None,
    ) -> None:
        runtime = _load_runtime_module()
        self._runtime = runtime
        self._closed = False
        self._telnet_lock = threading.RLock()
        self._telnet_transport_factory = telnet_transport_factory
        self._metrics_lock = threading.RLock()
        self._metrics = {
            "full_preflight_runs": 0,
            "preflight_refresh_runs": 0,
            "preflight_cache_hits": 0,
            "preflight_cache_misses": 0,
            "preflight_cache_stores": 0,
            "preflight_cache_invalidations": 0,
            "collector_invocations": 0,
        }
        self._preflight_capability_cache: dict[
            tuple[object, ...],
            dict[str, object],
        ] = {}
        self.ssh_selector = runtime.CredentialSelector.for_ssh(
            user=str(getattr(args, "ssh_user", "")),
            user_env=str(getattr(args, "ssh_user_env", "")),
            password_env=str(getattr(args, "ssh_password_env", "")),
            identity_file=str(getattr(args, "ssh_identity_file", "")),
            environ=os.environ,
        )
        self.telnet_selector = runtime.CredentialSelector.for_telnet(
            user=str(getattr(args, "telnet_user", "")),
            user_env=str(getattr(args, "telnet_user_env", "")),
            password_env=str(getattr(args, "telnet_password_env", "")),
            environ=os.environ,
        )
        host_key_policy = str(
            getattr(args, "ssh_host_key_policy", "")
            or os.environ.get("OPENUBMC_SSH_HOST_KEY_POLICY", "")
            or "insecure"
        )
        self.target = runtime.TargetSpec(
            host=str(args.ip),
            ssh_port=int(getattr(args, "ssh_port", 22)),
            telnet_port=int(getattr(args, "telnet_port", 23)),
            redfish_port=int(getattr(args, "redfish_port", 443)),
            credential_selector_fingerprint=self.ssh_selector.fingerprint,
            policy=runtime.TargetPolicy(ssh_host_key_policy=host_key_policy),
        )
        self._ssh_credentials = runtime.ResolvedSshCredentials.from_mapping(
            credential_bundle["ssh"]
        )
        resolver = runtime.CredentialResolver(
            lambda _selector: self._ssh_credentials
        )
        self.task_run = runtime.OpenUBMCTaskRun(
            task_id=task_id,
            credential_resolver=resolver,
            evidence_ledger=runtime.EvidenceLedger(
                max_records=evidence_max_records,
            ),
            mutation_journal_store=mutation_journal_store,
        )
        selected_ssh_transport = ssh_transport_factory or OpenSshControlMasterTransport
        self.ssh_transport = selected_ssh_transport(
            host_key_policy=str(getattr(args, "ssh_host_key_policy", "")),
            known_hosts_file=str(getattr(args, "ssh_known_hosts_file", "")),
            allow_insecure_host_key=bool(
                getattr(args, "allow_insecure_host_key", False)
            ),
        )
        self.ssh_lane = self.task_run.ssh_lane(
            target=self.target,
            credential_selector=self.ssh_selector,
            lease_name="debug-object-alarm",
            transport=self.ssh_transport,
        )
        self.object_alarm_lease = _DebugObjectAlarmLease(self.ssh_lane)

        self._telnet_credentials = runtime.ResolvedTelnetCredentials.from_mapping(
            credential_bundle["telnet"]
        )
        self.telnet_lane = None
        self.telnet_lease = None
        if not bool(getattr(args, "skip_telnet", False)):
            self.ensure_telnet(args, credential_bundle["telnet"])

    @property
    def ssh_runner(self):
        return self._run_read_only_ssh

    def _run_read_only_ssh(self, *args, **kwargs):
        kwargs["replay_safe"] = True
        return self.ssh_lane.run_ssh(*args, **kwargs)

    @property
    def telnet_session(self):
        return self.telnet_lease.session_proxy if self.telnet_lease is not None else None

    def ssh_credentials_mapping(self) -> dict[str, str | int]:
        return self._ssh_credentials.to_ssh_mapping()

    def telnet_credentials_mapping(self) -> dict[str, str | int]:
        return self._telnet_credentials.to_telnet_mapping()

    def ensure_telnet(
        self,
        args,
        credential_bundle: Mapping[str, str | int],
    ) -> None:
        """Attach the Telnet lane on first evidence profile that needs it."""

        with self._telnet_lock:
            if self._closed:
                raise RuntimeError("cannot attach Telnet to a closed Debug lease")
            if self.telnet_lane is not None:
                return
            self._telnet_credentials = (
                self._runtime.ResolvedTelnetCredentials.from_mapping(
                    credential_bundle
                )
            )
            selected_telnet_transport = (
                self._telnet_transport_factory or TelnetSessionTransport
            )
            transport_timeout = int(getattr(args, "timeout", 180))
            self.telnet_transport = selected_telnet_transport(
                connect_timeout=transport_timeout,
                prompt_timeout=transport_timeout,
                debug_label="debug-log-file-connect",
            )
            self.telnet_lane = self.task_run.telnet_lane(
                target=self.target,
                credentials=self._telnet_credentials,
                lease_name="debug-log-file",
                transport=self.telnet_transport,
            )
            self.telnet_lease = _DebugTelnetLease(
                self.telnet_lane,
                self.telnet_transport,
                self._telnet_credentials,
            )

    def run_ssh_read(
        self,
        *,
        request_id: str,
        collector_name: str,
        operation: Mapping[str, object],
        collect: Callable[[], T],
    ) -> T:
        request = self._runtime.RemoteReadRequest.create(
            request_id=request_id,
            target=self.target,
            credential_selector=self.ssh_selector,
            collector_name=collector_name,
            operation=operation,
        )
        return self.task_run.run_read(request, lambda _context: collect()).value

    def _preflight_cache_key(self, args) -> tuple[object, ...]:
        profile = (
            "mdb-only"
            if bool(getattr(args, "mdb_only", False))
            else "object-only"
            if bool(getattr(args, "skip_telnet", False))
            else "combined"
        )
        return (
            profile,
            str(getattr(args, "busctl_service", "")).strip(),
            tuple(sorted(getattr(args, "preflight_checks", []))),
        )

    def _preflight_epoch_signature(self, args) -> tuple[object, ...]:
        status = self.task_run.runtime_status()
        targets = status.get("targets")
        target_status = targets[0] if isinstance(targets, list) and targets else {}
        epochs = target_status.get("epochs", {}) if isinstance(target_status, dict) else {}
        lanes = epochs.get("lanes", {}) if isinstance(epochs, dict) else {}

        def lane_signature(name: str) -> tuple[object, ...]:
            lane = lanes.get(name) if isinstance(lanes, dict) else None
            if not isinstance(lane, dict):
                return (name, "not-configured", 0)
            return (
                name,
                str(lane.get("status", "unknown")),
                int(lane.get("epoch", 0)),
            )

        signature: list[object] = [
            int(epochs.get("target_epoch", 0)) if isinstance(epochs, dict) else 0,
            *lane_signature("ssh"),
        ]
        selected_checks = set(getattr(args, "preflight_checks", []))
        if (
            "TELNET" in selected_checks
            if selected_checks
            else not bool(getattr(args, "skip_telnet", False))
        ):
            signature.extend(lane_signature("telnet"))
        return tuple(signature)

    def cached_preflight_checks(self, args) -> dict[str, dict[str, object]] | None:
        key = self._preflight_cache_key(args)
        signature = self._preflight_epoch_signature(args)
        with self._metrics_lock:
            entry = self._preflight_capability_cache.get(key)
            if entry is None:
                self._metrics["preflight_cache_misses"] += 1
                return None
            if entry.get("epoch_signature") != signature:
                self._preflight_capability_cache.pop(key, None)
                self._metrics["preflight_cache_invalidations"] += 1
                self._metrics["preflight_cache_misses"] += 1
                return None
            checks = entry.get("checks")
            if not isinstance(checks, dict):
                self._preflight_capability_cache.pop(key, None)
                self._metrics["preflight_cache_invalidations"] += 1
                self._metrics["preflight_cache_misses"] += 1
                return None
            self._metrics["preflight_cache_hits"] += 1
            return copy.deepcopy(checks)

    def store_preflight_checks(
        self,
        args,
        checks: Mapping[str, Mapping[str, object]],
    ) -> None:
        key = self._preflight_cache_key(args)
        signature = self._preflight_epoch_signature(args)
        stored = {
            str(name): dict(value)
            for name, value in checks.items()
            if isinstance(value, Mapping)
        }
        if not stored:
            self.invalidate_preflight_checks(args)
            return
        with self._metrics_lock:
            self._preflight_capability_cache[key] = {
                "epoch_signature": signature,
                "checks": copy.deepcopy(stored),
            }
            self._metrics["preflight_cache_stores"] += 1

    def invalidate_preflight_checks(self, args) -> None:
        key = self._preflight_cache_key(args)
        with self._metrics_lock:
            if key in self._preflight_capability_cache:
                self._preflight_capability_cache.pop(key, None)
                self._metrics["preflight_cache_invalidations"] += 1

    def record_preflight_phase(self, mode: str) -> None:
        with self._metrics_lock:
            if mode == "full":
                self._metrics["full_preflight_runs"] += 1
            elif mode == "refresh":
                self._metrics["preflight_refresh_runs"] += 1
            else:
                raise ValueError(f"unsupported preflight mode: {mode}")

    def record_phase(self, name: str) -> None:
        with self._metrics_lock:
            if name == "preflight_start":
                self._metrics["full_preflight_runs"] += 1
            elif name == "preflight_end":
                self._metrics["preflight_refresh_runs"] += 1
            else:
                self._metrics["collector_invocations"] += 1

    def record_tool_result(self, collector: str, result: Mapping[str, object]) -> None:
        status = self.task_run.runtime_status()
        targets = status.get("targets")
        target_status = targets[0] if isinstance(targets, list) and targets else {}
        epochs = target_status.get("epochs", {}) if isinstance(target_status, dict) else {}
        lanes = epochs.get("lanes", {}) if isinstance(epochs, dict) else {}
        lane_epochs = {
            lane: int(value.get("epoch", 0))
            for lane, value in lanes.items()
            if isinstance(value, dict)
        }
        payload = result.get("payload")
        payload_dict = payload if isinstance(payload, dict) else {}
        child_result = payload_dict.get("result")
        child_result_dict = child_result if isinstance(child_result, dict) else {}
        artifact_reference = ""
        for key in ("artifact_reference", "artifact", "output_path"):
            value = child_result_dict.get(key)
            if isinstance(value, str) and value:
                artifact_reference = value
                break
        if not artifact_reference:
            written = child_result_dict.get("written_files")
            if isinstance(written, list):
                artifact_reference = next(
                    (str(value) for value in written if isinstance(value, str)),
                    "",
                )
        summary = str(result.get("code", "unknown"))
        error = str(result.get("error", ""))
        if error:
            summary = f"{summary}: {error}"
        self.task_run.evidence_ledger.append(
            target_fingerprint=self.target.fingerprint,
            collector=collector,
            target_epoch=int(epochs.get("target_epoch", 0))
            if isinstance(epochs, dict)
            else 0,
            lane_epochs=lane_epochs,
            freshness="fresh-request",
            status="ok" if bool(result.get("ok")) else str(result.get("code", "failed")),
            summary=summary,
            size_bytes=len(
                json.dumps(payload_dict, ensure_ascii=False, default=str).encode("utf-8")
            ),
            artifact_reference=artifact_reference,
        )

    def runtime_status(self) -> dict[str, object]:
        status = self.task_run.runtime_status()
        with self._metrics_lock:
            status["debug_run_metrics"] = dict(self._metrics)
            status["debug_preflight_cache"] = {
                "entry_count": len(self._preflight_capability_cache),
                "profiles": [
                    str(key[0])
                    for key in sorted(self._preflight_capability_cache)
                ],
            }
        return status

    def close(self) -> None:
        with self._telnet_lock:
            if self._closed:
                return
            self._closed = True
            if self.telnet_lane is not None:
                self.telnet_lane.close()
        self.ssh_lane.close()

    def __enter__(self) -> "DebugRuntimeLease":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def open_debug_runtime_lease(
    *,
    args,
    credential_bundle: Mapping[str, Mapping[str, str | int]],
    task_id: str | None = None,
    ssh_transport_factory=None,
    telnet_transport_factory=None,
    evidence_max_records: int = 128,
    mutation_journal_store=None,
) -> DebugRuntimeLease:
    return DebugRuntimeLease(
        args=args,
        credential_bundle=credential_bundle,
        task_id=task_id or f"debug-one-shot-{uuid.uuid4().hex}",
        ssh_transport_factory=ssh_transport_factory,
        telnet_transport_factory=telnet_transport_factory,
        evidence_max_records=evidence_max_records,
        mutation_journal_store=mutation_journal_store,
    )
