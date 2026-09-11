"""Production MCP backend for typed Live Patch mutations."""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import base64
import gzip
import hashlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import sys
import threading


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
_ADAPTER_NAME = "_openubmc_live_patch_target_runtime_adapter"
_adapter_spec = importlib.util.spec_from_file_location(
    _ADAPTER_NAME,
    SCRIPTS / "target_runtime_adapter.py",
)
if _adapter_spec is None or _adapter_spec.loader is None:
    raise ImportError("openubmc-live-patch Runtime adapter is unavailable")
_adapter = importlib.util.module_from_spec(_adapter_spec)
sys.modules[_ADAPTER_NAME] = _adapter
_adapter_spec.loader.exec_module(_adapter)
CanonicalTelnetTransport = _adapter.CanonicalTelnetTransport
LivePatchRuntimeAdapter = _adapter.LivePatchRuntimeAdapter
from openubmc_target_runtime import (  # noqa: E402
    CredentialResolver,
    CredentialSelector,
    MutationAuthorization,
    MutationExpectedTargetState,
    MutationJournalStore,
    OpenSshControlMasterTransport,
    OpenUBMCTaskRun,
    RemoteReadRequest,
    ResolvedSshCredentials,
    ResolvedTelnetCredentials,
    TargetPolicy,
    TargetIdentity,
    TargetSpec,
    TaskAuthorizationPolicy,
    effect_recovery_mode,
    load_selected_credentials_file,
    selected_credential_value,
    mutation_recovery_route,
)


_ALLOWED_REMOTE_ROOTS = ("/opt/bmc/apps/", "/opt/bmc/sr/", "/tmp/")
_SAFE_MODE = re.compile(r"[0-7]{3,4}")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")
# Target Runtime adds a 257-byte frame and the canonical Telnet input ceiling is
# 960 bytes. Keep command bodies at or below 700 bytes to retain framing headroom.
_TELNET_COMMAND_MAX_BYTES = 700


@dataclass
class _RootMountState:
    options: tuple[str, ...] = ()
    remounted: bool = False
    restored: bool = True

    @property
    def mode(self) -> str:
        return ",".join(self.options) or "not-inspected"


def _argument_text(arguments: Mapping[str, object], name: str) -> str:
    value = arguments.get(name, "")
    return str(value).strip() if isinstance(value, (str, int)) else ""


def _argument_bool(
    arguments: Mapping[str, object],
    name: str,
    *,
    default: bool = False,
) -> bool:
    value = arguments.get(name, default)
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a boolean")
    return value


def _default_credential_loader(
    arguments: Mapping[str, object],
) -> dict[str, dict[str, str | int]]:
    cached = arguments.get("_credential_values")
    if cached is None:
        values = load_selected_credentials_file()
    elif isinstance(cached, Mapping):
        values = {
            str(key): str(value)
            for key, value in cached.items()
            if isinstance(key, str) and isinstance(value, str)
        }
    else:
        raise TypeError("_credential_values must be an internal mapping")

    def selected(
        explicit_name: str,
        selector_name: str,
        defaults: tuple[str, ...],
    ) -> str:
        explicit = _argument_text(arguments, explicit_name)
        if explicit:
            return explicit
        selector = _argument_text(arguments, selector_name)
        names = ((selector,) if selector else ()) + defaults
        if values.get("__runtime_selected__") == "1":
            return selected_credential_value(values, (selector,) if selector else defaults) or ""
        for name in names:
            value = os.environ.get(name, values.get(name, ""))
            if value:
                return value
        return ""

    ssh_user = selected(
        "ssh_user", "ssh_user_env", ("OPENUBMC_SSH_USER",)
    )
    ssh_password = selected(
        "ssh_password", "ssh_password_env", ("OPENUBMC_SSH_PASSWORD",)
    )
    telnet_user = selected(
        "telnet_user",
        "telnet_user_env",
        ("OPENUBMC_TELNET_USER", "OPENUBMC_SSH_USER"),
    ) or ssh_user
    telnet_password = selected(
        "telnet_password",
        "telnet_password_env",
        ("OPENUBMC_TELNET_PASSWORD", "OPENUBMC_SSH_PASSWORD"),
    ) or ssh_password
    if not ssh_user or not telnet_user or not telnet_password:
        raise ValueError("Live Patch requires SSH user and Telnet credentials")
    return {
        "ssh": {
            "user": ssh_user,
            "password": ssh_password,
            "port": int(arguments.get("ssh_port", 22)),
            "identity_file": _argument_text(arguments, "ssh_identity_file") or values.get("OPENUBMC_SSH_IDENTITY_FILE", ""),
        },
        "telnet": {
            "user": telnet_user,
            "password": telnet_password,
            "port": int(arguments.get("telnet_port", 23)),
        },
    }


def _validate_remote_path(
    value: str,
    *,
    allowed_roots: tuple[str, ...] = _ALLOWED_REMOTE_ROOTS,
    allow_outside_roots: bool = False,
) -> str:
    if not value.startswith("/") or value.endswith("/"):
        raise ValueError("remote_path must be an absolute file path")
    if any(character in value for character in ("\x00", "\n", "\r")):
        raise ValueError("remote_path contains a control character")
    if ".." in PurePosixPath(value).parts:
        raise ValueError("remote_path cannot contain traversal")
    if allowed_roots and not allow_outside_roots and not value.startswith(
        allowed_roots
    ):
        raise ValueError("remote_path is outside the Live Patch authored roots")
    return value


def _authorized_root(
    value: str,
    *,
    allowed_roots: tuple[str, ...],
    allow_outside_roots: bool,
) -> str:
    if allow_outside_roots:
        return posixpath.dirname(value)
    matches = [root.rstrip("/") for root in allowed_roots if value.startswith(root)]
    if not matches:
        raise ValueError("remote path has no authored Live Patch root")
    return max(matches, key=len)


def _path_guard_command(
    paths: tuple[tuple[str, str, bool], ...],
) -> str:
    commands = ["set -eu", "command -v readlink >/dev/null 2>&1"]
    for value, root, require_exists in paths:
        parent = posixpath.dirname(value)
        value_q = shlex.quote(value)
        parent_q = shlex.quote(parent)
        root_q = shlex.quote(root)
        commands.extend(
            [
                f"root_real=$(readlink -f {root_q})",
                f"parent_real=$(readlink -f {parent_q})",
                f"test \"$root_real\" = {root_q}",
                f"test \"$parent_real\" = {parent_q}",
                "test -d \"$root_real\"",
                "test -d \"$parent_real\"",
                "case \"$parent_real/\" in \"$root_real/\"*) ;; *) exit 41 ;; esac",
                f"test ! -L {value_q}",
                f"if test -e {value_q}; then test -f {value_q}; fi",
            ]
        )
        if require_exists:
            commands.append(f"test -f {value_q}")
    commands.append("echo live_patch_paths_safe")
    return " && ".join(commands)


def _compressed_shell_command(script: str, *, phase: str) -> str:
    if phase not in {"b", "i", "r"}:
        raise ValueError("Live Patch compressed-shell phase is invalid")
    encoded = base64.b64encode(
        gzip.compress(script.encode("utf-8"), mtime=0)
    ).decode("ascii")
    command = (
        f"p={phase};"
        f"printf %s {shlex.quote(encoded)}|"
        "busybox base64 -d|busybox gzip -d|sh"
    )
    if len(command.encode("utf-8")) > _TELNET_COMMAND_MAX_BYTES:
        raise ValueError(
            "Live Patch operation is too long for bounded Telnet execution"
        )
    return command


def _atomic_backup_command(
    remote: str,
    backup: str,
    expected_sha: str,
    expected_mode: str,
    expected_uid: int,
    expected_gid: int,
    token: str,
) -> str:
    parent = posixpath.dirname(backup)
    name = posixpath.basename(backup)
    work = f".openubmc-live-patch-backup-{token}"
    payload = f"{work}/payload"
    return (
        f"(cd -P {shlex.quote(parent)} && "
        f"test \"$(pwd -P)\" = {shlex.quote(parent)} && "
        f"test ! -e {shlex.quote(name)} && test ! -L {shlex.quote(name)} && "
        f"test ! -e {shlex.quote(work)} && mkdir {shlex.quote(work)} && "
        f"cp -pP {shlex.quote(remote)} {shlex.quote(payload)} && "
        f"test -f {shlex.quote(payload)} && test ! -L {shlex.quote(payload)} && "
        f"backup_sha=$(sha256sum {shlex.quote(payload)} | awk '{{print $1}}') && "
        f"backup_mode=$(stat -c %a {shlex.quote(payload)}) && "
        f"backup_uid=$(stat -c %u {shlex.quote(payload)}) && "
        f"backup_gid=$(stat -c %g {shlex.quote(payload)}) && "
        f"test \"$backup_sha\" = {shlex.quote(expected_sha)} && "
        f"test \"$backup_mode\" = {shlex.quote(expected_mode)} && "
        f"test \"$backup_uid\" = {expected_uid} && "
        f"test \"$backup_gid\" = {expected_gid} && "
        f"mv {shlex.quote(payload)} {shlex.quote(name)} && "
        f"rmdir {shlex.quote(work)} && "
        "printf 'backup_sha256=%s\\nbackup_mode=%s\\nbackup_uid=%s\\nbackup_gid=%s\\n' "
        "\"$backup_sha\" \"$backup_mode\" \"$backup_uid\" \"$backup_gid\" && "
        "echo backup_ok)"
    )


def _atomic_install_command(
    staging: str,
    remote: str,
    mode: str,
    expected_sha: str,
    owner_uid: int | None,
    owner_gid: int | None,
    token: str,
) -> str:
    parent = posixpath.dirname(remote)
    name = posixpath.basename(remote)
    work = f".openubmc-live-patch-install-{token}"
    payload = f"{work}/payload"
    owner_command = ""
    owner_tests = ""
    if owner_uid is not None and owner_gid is not None:
        owner_command = f"chown {owner_uid}:{owner_gid} {shlex.quote(payload)} && "
        owner_tests = (
            f"test \"$remote_uid\" = {owner_uid} && "
            f"test \"$remote_gid\" = {owner_gid} && "
        )
    return (
        f"(cd -P {shlex.quote(parent)} && "
        f"test \"$(pwd -P)\" = {shlex.quote(parent)} && "
        f"test ! -L {shlex.quote(name)} && "
        f"if test -e {shlex.quote(name)}; then test -f {shlex.quote(name)}; fi && "
        f"test ! -e {shlex.quote(work)} && mkdir {shlex.quote(work)} && "
        f"cp -P {shlex.quote(staging)} {shlex.quote(payload)} && "
        f"test -f {shlex.quote(payload)} && test ! -L {shlex.quote(payload)} && "
        f"{owner_command}"
        f"chmod {shlex.quote(mode)} {shlex.quote(payload)} && "
        f"new_sha=$(sha256sum {shlex.quote(payload)} | awk '{{print $1}}') && "
        f"test \"$new_sha\" = {shlex.quote(expected_sha)} && "
        f"mv -f {shlex.quote(payload)} {shlex.quote(name)} && "
        f"rmdir {shlex.quote(work)} && "
        f"remote_sha=$(sha256sum {shlex.quote(name)} | awk '{{print $1}}') && "
        f"remote_mode=$(stat -c %a {shlex.quote(name)}) && "
        f"remote_uid=$(stat -c %u {shlex.quote(name)}) && "
        f"remote_gid=$(stat -c %g {shlex.quote(name)}) && "
        f"test \"$remote_sha\" = {shlex.quote(expected_sha)} && "
        f"test \"$remote_mode\" = {shlex.quote(mode)} && "
        f"{owner_tests}"
        f"rm -f {shlex.quote(staging)} && "
        "printf 'remote_sha256=%s\\nremote_mode=%s\\nremote_uid=%s\\nremote_gid=%s\\n' "
        "\"$remote_sha\" \"$remote_mode\" \"$remote_uid\" \"$remote_gid\" && "
        "echo deploy_ok)"
    )


def _atomic_restore_command(
    backup: str,
    remote: str,
    mode: str,
    token: str,
    expected_backup_sha: str,
    expected_uid: int,
    expected_gid: int,
) -> str:
    parent = posixpath.dirname(remote)
    name = posixpath.basename(remote)
    work = f".openubmc-live-patch-restore-{token}"
    payload = f"{work}/payload"
    return (
        f"(cd -P {shlex.quote(parent)} && "
        f"test \"$(pwd -P)\" = {shlex.quote(parent)} && "
        f"test ! -L {shlex.quote(name)} && "
        f"if test -e {shlex.quote(name)}; then test -f {shlex.quote(name)}; fi && "
        f"test ! -e {shlex.quote(work)} && mkdir {shlex.quote(work)} && "
        f"cp -pP {shlex.quote(backup)} {shlex.quote(payload)} && "
        f"test -f {shlex.quote(payload)} && test ! -L {shlex.quote(payload)} && "
        f"backup_sha=$(sha256sum {shlex.quote(payload)} | awk '{{print $1}}') && "
        f"backup_mode=$(stat -c %a {shlex.quote(payload)}) && "
        f"backup_uid=$(stat -c %u {shlex.quote(payload)}) && "
        f"backup_gid=$(stat -c %g {shlex.quote(payload)}) && "
        f"test \"$backup_sha\" = {shlex.quote(expected_backup_sha)} && "
        f"test \"$backup_uid\" = {expected_uid} && "
        f"test \"$backup_gid\" = {expected_gid} && "
        f"chmod {shlex.quote(mode)} {shlex.quote(payload)} && "
        f"mv -f {shlex.quote(payload)} {shlex.quote(name)} && "
        f"rmdir {shlex.quote(work)} && "
        f"remote_sha=$(sha256sum {shlex.quote(name)} | awk '{{print $1}}') && "
        f"remote_mode=$(stat -c %a {shlex.quote(name)}) && "
        f"remote_uid=$(stat -c %u {shlex.quote(name)}) && "
        f"remote_gid=$(stat -c %g {shlex.quote(name)}) && "
        "printf 'backup_sha256=%s\\nremote_sha256=%s\\nbackup_mode=%s\\nremote_mode=%s\\nbackup_uid=%s\\nremote_uid=%s\\nbackup_gid=%s\\nremote_gid=%s\\n' "
        "\"$backup_sha\" \"$remote_sha\" \"$backup_mode\" \"$remote_mode\" "
        "\"$backup_uid\" \"$remote_uid\" \"$backup_gid\" \"$remote_gid\" && "
        "test \"$backup_sha\" = \"$remote_sha\" && "
        f"test \"$remote_mode\" = {shlex.quote(mode)} && "
        "test \"$backup_uid\" = \"$remote_uid\" && "
        "test \"$backup_gid\" = \"$remote_gid\" && echo restore_ok)"
    )


def _atomic_remove_command(
    remote: str,
    expected_sha: str,
) -> str:
    parent = posixpath.dirname(remote)
    name = posixpath.basename(remote)
    return (
        f"(cd -P {shlex.quote(parent)} && "
        f"test \"$(pwd -P)\" = {shlex.quote(parent)} && "
        f"test -f {shlex.quote(name)} && test ! -L {shlex.quote(name)} && "
        f"remote_sha=$(sha256sum {shlex.quote(name)} | awk '{{print $1}}') && "
        f"test \"$remote_sha\" = {shlex.quote(expected_sha)} && "
        f"rm -f {shlex.quote(name)} && "
        f"test ! -e {shlex.quote(name)} && test ! -L {shlex.quote(name)} && "
        "printf 'removed_sha256=%s\n' \"$remote_sha\" && echo remove_ok)"
    )


def _root_mount_options(text: str) -> tuple[str, ...]:
    for line in reversed(text.splitlines()):
        options = tuple(
            item.strip() for item in line.strip().split(",") if item.strip()
        )
        if "ro" in options or "rw" in options:
            return options
    raise RuntimeError("Live Patch could not determine the root mount mode")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _file_metadata(text: str, prefix: str) -> dict[str, int | str]:
    values: dict[str, int | str] = {}
    for name in ("mode", "uid", "gid"):
        match = re.search(rf"\b{re.escape(prefix)}_{name}=([0-9]+)\b", text)
        if match is None:
            raise RuntimeError(
                f"Live Patch {prefix} {name} metadata is unavailable"
            )
        raw = match.group(1)
        if name == "mode":
            if _SAFE_MODE.fullmatch(raw) is None:
                raise RuntimeError("Live Patch target mode metadata is invalid")
            values[name] = raw
        else:
            values[name] = int(raw)
    return values


def _telnet_text(result: object, *, purpose: str) -> str:
    if not bool(getattr(result, "ok", False)):
        raise RuntimeError(f"Live Patch Telnet command failed during {purpose}")
    stdout = getattr(result, "stdout", "")
    return stdout if isinstance(stdout, str) else str(stdout)


def _telnet_stdout(result: object, *, marker: str) -> str:
    text = _telnet_text(result, purpose=marker)
    if marker not in text:
        raise RuntimeError(f"Live Patch Telnet command did not confirm {marker}")
    return text


def _require_path_guard(result: object) -> str:
    try:
        return _telnet_stdout(result, marker="live_patch_paths_safe")
    except RuntimeError as exc:
        raise RuntimeError("Live Patch symlink guard failed") from exc


def _require_path_guards(execution, context, paths) -> None:
    for path in paths:
        command = _path_guard_command((path,))
        if len(command.encode("utf-8")) > _TELNET_COMMAND_MAX_BYTES:
            raise ValueError(
                "Live Patch path is too long for bounded Telnet guard execution"
            )
        result = execution.run_telnet(
            command,
            timeout=min(20.0, context.remaining()),
        )
        _require_path_guard(result)


def _require_shell_codec(execution, context) -> None:
    result = execution.run_telnet(
        "busybox --list|busybox grep -qx base64&&"
        "busybox --list|busybox grep -qx gzip&&"
        "echo live_patch_codec_ready",
        timeout=min(20.0, context.remaining()),
    )
    _telnet_stdout(result, marker="live_patch_codec_ready")


def _prepare_root_mount(
    execution,
    context,
    *,
    no_remount: bool,
    state: _RootMountState,
) -> None:
    if no_remount:
        execution.journal.record_execution_evidence(
            root_mount_mode="not-inspected",
            root_mount_restored=True,
        )
        return
    inspected = execution.run_telnet(
        "awk '$2 == \"/\" {print $4; exit}' /proc/mounts",
        timeout=min(20.0, context.remaining()),
    )
    options = _root_mount_options(
        _telnet_text(inspected, purpose="root mount inspection")
    )
    state.options = options
    state.restored = "ro" not in options
    execution.journal.record_execution_evidence(
        root_mount_mode=state.mode,
        root_mount_restored=state.restored,
    )
    if "ro" not in options:
        if "rw" not in options:
            raise RuntimeError("Live Patch root mount mode is unknown")
        return
    execution.mark_effects_started()
    state.restored = False
    state.remounted = True
    remounted = execution.run_telnet(
        "mount -o remount,rw / && echo remount_rw_ok",
        timeout=min(20.0, context.remaining()),
    )
    _telnet_stdout(remounted, marker="remount_rw_ok")


def _restore_root_mount(execution, context, *, options: tuple[str, ...]) -> bool:
    if "ro" not in options:
        return True
    restored = execution.run_telnet(
        "mount -o remount,ro / && echo remount_ro_ok",
        timeout=min(20.0, context.remaining()),
    )
    _telnet_stdout(restored, marker="remount_ro_ok")
    return True


def _finalize_root_mount(
    execution,
    context,
    *,
    state: _RootMountState,
    primary_error: BaseException | None,
) -> None:
    try:
        if state.remounted:
            _restore_root_mount(
                execution,
                context,
                options=state.options,
            )
            state.restored = True
    except BaseException as restore_error:
        state.restored = False
        execution.journal.record_execution_evidence(
            root_mount_mode=state.mode,
            root_mount_restored=False,
        )
        if primary_error is not None:
            raise RuntimeError(
                "Live Patch mutation failed: "
                f"{primary_error}; root mount restoration also failed: "
                f"{restore_error}"
            ) from restore_error
        raise RuntimeError(
            f"Live Patch root mount restoration failed: {restore_error}"
        ) from restore_error
    execution.journal.record_execution_evidence(
        root_mount_mode=state.mode,
        root_mount_restored=state.restored,
    )


def _inspect_live_patch_target_identity(lane, context) -> TargetIdentity:
    result = lane.run_command(
        "product_id=$(tr -d '\\000' </sys/firmware/devicetree/base/model "
        "2>/dev/null||true); machine_id=$(cat /etc/machine-id 2>/dev/null||true); "
        "firmware_id=$(sed -n 's/^VERSION_ID=//p' /etc/os-release "
        "2>/dev/null|tr -d '\"'); reboot_anchor=$(cat "
        "/proc/sys/kernel/random/boot_id 2>/dev/null||true); "
        "printf 'product_id=%s\\nmachine_id=%s\\nfirmware_id=%s\\n"
        "reboot_anchor=%s\\n' \"$product_id\" \"$machine_id\" "
        "\"$firmware_id\" \"$reboot_anchor\"; "
        "echo live_patch_identity_inspected",
        timeout=min(20.0, context.remaining()),
    )
    text = _telnet_stdout(result, marker="live_patch_identity_inspected")

    def field_value(name: str) -> str:
        match = re.search(rf"(?m)^{name}=([^\r\n]*)$", text)
        return match.group(1).strip() if match is not None else ""

    identity = TargetIdentity(
        product_id=field_value("product_id"),
        machine_id=field_value("machine_id"),
        firmware_id=field_value("firmware_id"),
        reboot_anchor=field_value("reboot_anchor"),
    )
    if not identity.machine_id or not identity.reboot_anchor:
        raise RuntimeError("Live Patch target identity is unavailable")
    return identity


def _inspect_skynet_process_identity(lane, context) -> str:
    result = lane.run_command(
        "pid=$(pidof skynet 2>/dev/null | awk '{print $1}'); "
        "if test -n \"$pid\" && test -r \"/proc/$pid/stat\"; then "
        "start=$(awk '{print $22}' \"/proc/$pid/stat\"); "
        "printf 'skynet_process_identity=%s:%s\\n' \"$pid\" \"$start\"; "
        "else echo skynet_process_identity=absent; fi; "
        "echo live_patch_skynet_identity_inspected",
        timeout=min(20.0, context.remaining()),
    )
    text = _telnet_stdout(
        result,
        marker="live_patch_skynet_identity_inspected",
    )
    match = re.search(
        r"(?m)^skynet_process_identity=(absent|[0-9]+:[0-9]+)$",
        text,
    )
    if match is None:
        raise RuntimeError("Live Patch skynet process identity is unavailable")
    return match.group(1)


def _record_restart_boundary(execution, context, *, restart_scope: str) -> str:
    if restart_scope != "skynet":
        return ""
    identity = _inspect_skynet_process_identity(execution.telnet_lane, context)
    execution.journal.record_execution_evidence(
        restart_state=f"before:{identity}"
    )
    return identity


def _restart_baseline(restart_state: str) -> str:
    if restart_state.startswith("before:"):
        return restart_state.removeprefix("before:")
    if restart_state.startswith("completed:skynet:"):
        return restart_state.removeprefix("completed:skynet:")
    return ""


def _inspect_rollback_backup(execution, context, backup: str) -> dict[str, int | str]:
    result = execution.run_telnet(
        "backup_sha=$(sha256sum {backup} | awk '{{print $1}}') && "
        "backup_mode=$(stat -c %a {backup}) && "
        "backup_uid=$(stat -c %u {backup}) && "
        "backup_gid=$(stat -c %g {backup}) && "
        "printf 'backup_sha256=%s\\nbackup_mode=%s\\nbackup_uid=%s\\n"
        "backup_gid=%s\\n' "
        '"$backup_sha" "$backup_mode" "$backup_uid" "$backup_gid" && '
        "echo rollback_backup_inspected".format(backup=shlex.quote(backup)),
        timeout=min(20.0, context.remaining()),
    )
    text = _telnet_stdout(result, marker="rollback_backup_inspected")
    checksum = re.search(rf"\bbackup_sha256=({_SHA256.pattern})\b", text)
    if checksum is None:
        raise RuntimeError("Live Patch rollback backup checksum is unavailable")
    metadata = _file_metadata(text, "backup")
    return {
        "sha256": checksum.group(1).lower(),
        "uid": int(metadata["uid"]),
        "gid": int(metadata["gid"]),
    }


@dataclass(frozen=True)
class _LivePatchRecoverySnapshot:
    target_identity: TargetIdentity
    recovery_safe: bool
    safety_blockers: tuple[str, ...]
    remote_checksum: str
    remote_metadata: Mapping[str, int | str]
    backup_exists: bool | None
    backup_checksum: str
    backup_metadata: Mapping[str, int | str]
    root_mount_mode: str
    root_mount_restored: bool | None
    restart_observed: bool | None

    def evidence(
        self,
        *,
        recovery_safe: bool | None = None,
        additional_blockers: tuple[str, ...] = (),
    ) -> dict[str, object]:
        blockers = tuple(dict.fromkeys((*self.safety_blockers, *additional_blockers)))
        return {
            "target_identity": self.target_identity,
            "target_reachable": True,
            "recovery_safe": (
                self.recovery_safe if recovery_safe is None else recovery_safe
            ),
            "safety_blockers": list(blockers),
            "remote_checksum": self.remote_checksum,
            "remote_metadata": dict(self.remote_metadata),
            "backup_exists": self.backup_exists,
            "backup_checksum": self.backup_checksum,
            "root_mount_mode": self.root_mount_mode,
            "root_mount_restored": self.root_mount_restored,
            "restart_observed": self.restart_observed,
        }


def _inspect_live_patch_recovery(
    lane,
    context,
    *,
    remote: str,
    remote_root: str,
    backup: str,
    guard_backup: bool,
    root_mount_mode: str,
    unknown_mount_restored: bool | None,
    restart_scope: str,
    restart_state: str,
) -> _LivePatchRecoverySnapshot:
    guarded_paths = [(remote, remote_root, False)]
    if backup and guard_backup:
        guarded_paths.append((backup, "/tmp", False))
    for path in guarded_paths:
        command = _path_guard_command((path,))
        if len(command.encode("utf-8")) > _TELNET_COMMAND_MAX_BYTES:
            raise ValueError(
                "Live Patch recovery path is too long for bounded Telnet guard execution"
            )
        _require_path_guard(
            lane.run_command(command, timeout=min(20.0, context.remaining()))
        )

    target_identity = _inspect_live_patch_target_identity(lane, context)
    remote_result = lane.run_command(
        "if test -L {remote}; then echo remote_symlink; "
        "elif test -f {remote}; then "
        "remote_sha=$(sha256sum {remote} | awk '{{print $1}}'); "
        "remote_mode=$(stat -c %a {remote}); "
        "remote_uid=$(stat -c %u {remote}); "
        "remote_gid=$(stat -c %g {remote}); "
        "printf 'remote_sha256=%s\\nremote_mode=%s\\nremote_uid=%s\\nremote_gid=%s\\n' "
        '"$remote_sha" "$remote_mode" "$remote_uid" "$remote_gid"; '
        "echo remote_exists; else echo remote_missing; fi; "
        "echo live_patch_recovery_inspected".format(remote=shlex.quote(remote)),
        timeout=min(20.0, context.remaining()),
    )
    remote_text = _telnet_stdout(
        remote_result,
        marker="live_patch_recovery_inspected",
    )
    safety_blockers: list[str] = []
    if "remote_symlink" in remote_text:
        safety_blockers.append("remote_path_is_symlink")
    remote_checksum = ""
    remote_metadata: dict[str, int | str] = {}
    if "remote_exists" in remote_text:
        checksum = re.search(rf"\bremote_sha256=({_SHA256.pattern})\b", remote_text)
        if checksum is None:
            raise RuntimeError("Live Patch recovery target checksum is unavailable")
        remote_checksum = checksum.group(1).lower()
        remote_metadata = _file_metadata(remote_text, "remote")
    elif "remote_missing" not in remote_text:
        safety_blockers.append("remote_state_unavailable")

    backup_exists: bool | None = None
    backup_checksum = ""
    backup_metadata: dict[str, int | str] = {}
    if backup:
        backup_result = lane.run_command(
            "if test -L {backup}; then echo backup_symlink; "
            "elif test -f {backup}; then "
            "backup_sha=$(sha256sum {backup} | awk '{{print $1}}'); "
            "backup_mode=$(stat -c %a {backup}); "
            "backup_uid=$(stat -c %u {backup}); "
            "backup_gid=$(stat -c %g {backup}); "
            "printf 'backup_sha256=%s\\nbackup_mode=%s\\nbackup_uid=%s\\nbackup_gid=%s\\n' "
            '"$backup_sha" "$backup_mode" "$backup_uid" "$backup_gid"; '
            "echo backup_exists; else echo backup_missing; fi".format(
                backup=shlex.quote(backup)
            ),
            timeout=min(20.0, context.remaining()),
        )
        backup_text = _telnet_text(
            backup_result,
            purpose="Live Patch recovery backup inspection",
        )
        if "backup_exists" in backup_text:
            backup_exists = True
            checksum = re.search(
                rf"\bbackup_sha256=({_SHA256.pattern})\b",
                backup_text,
            )
            if checksum is not None:
                backup_checksum = checksum.group(1).lower()
                backup_metadata = _file_metadata(backup_text, "backup")
        elif "backup_missing" in backup_text or "backup_symlink" in backup_text:
            backup_exists = False

    mount_result = lane.run_command(
        "awk '$2 == \"/\" {print $4; exit}' /proc/mounts",
        timeout=min(20.0, context.remaining()),
    )
    mount_options = _root_mount_options(
        _telnet_text(
            mount_result,
            purpose="Live Patch recovery root mount inspection",
        )
    )
    original_mount = tuple(
        item
        for item in root_mount_mode.split(",")
        if item and item not in {"unknown", "not-inspected"}
    )
    if "ro" in original_mount or "rw" in original_mount:
        root_mount_restored: bool | None = (
            ("ro" in original_mount and "ro" in mount_options)
            or ("rw" in original_mount and "rw" in mount_options)
        )
    else:
        root_mount_restored = unknown_mount_restored
    if root_mount_restored is False:
        safety_blockers.append("root_mount_not_restored")

    restart_observed: bool | None = True
    if restart_scope == "skynet":
        before_restart = _restart_baseline(restart_state)
        current_restart = _inspect_skynet_process_identity(lane, context)
        restart_observed = bool(
            before_restart
            and before_restart != "absent"
            and current_restart != "absent"
            and current_restart != before_restart
        )
        if not restart_observed:
            safety_blockers.append("restart_not_observed")

    return _LivePatchRecoverySnapshot(
        target_identity=target_identity,
        recovery_safe=not safety_blockers,
        safety_blockers=tuple(safety_blockers),
        remote_checksum=remote_checksum,
        remote_metadata=remote_metadata,
        backup_exists=backup_exists,
        backup_checksum=backup_checksum,
        backup_metadata=backup_metadata,
        root_mount_mode=",".join(mount_options),
        root_mount_restored=root_mount_restored,
        restart_observed=restart_observed,
    )


@dataclass
class _LivePatchBinding:
    task_run: OpenUBMCTaskRun
    target: TargetSpec
    ssh_selector: CredentialSelector
    telnet_credentials: ResolvedTelnetCredentials
    ssh_transport: object
    telnet_transport: object

    def close(self) -> None:
        self.task_run.close()


class _LivePatchTask:
    def __init__(self, task_id: str, backend: "LivePatchMcpBackend") -> None:
        self.task_id = task_id
        self.backend = backend
        self._bindings: OrderedDict[
            tuple[object, ...], _LivePatchBinding
        ] = OrderedDict()
        self._binding_evictions = 0
        self._lock = threading.RLock()

    @staticmethod
    def _key(arguments: Mapping[str, object]) -> tuple[object, ...]:
        return (
            _argument_text(arguments, "ip").lower(),
            int(arguments.get("ssh_port", 22)),
            int(arguments.get("telnet_port", 23)),
            _argument_text(arguments, "ssh_user"),
            _argument_text(arguments, "ssh_user_env"),
            _argument_text(arguments, "ssh_password_env"),
            _argument_text(arguments, "ssh_password"),
            _argument_text(arguments, "ssh_identity_file"),
            _argument_text(arguments, "telnet_user"),
            _argument_text(arguments, "telnet_user_env"),
            _argument_text(arguments, "telnet_password_env"),
            _argument_text(arguments, "telnet_password"),
            _argument_text(arguments, "ssh_host_key_policy").lower(),
            _argument_text(arguments, "ssh_known_hosts_file"),
        )

    def binding_for(self, arguments: Mapping[str, object]) -> _LivePatchBinding:
        key = self._key(arguments)
        with self._lock:
            existing = self._bindings.get(key)
            if existing is not None:
                self._bindings.move_to_end(key)
                return existing
            binding = self.backend._create_binding(self.task_id, arguments)
            if len(self._bindings) >= self.backend.max_cached_bindings:
                _, victim = self._bindings.popitem(last=False)
                victim.close()
                self._binding_evictions += 1
            self._bindings[key] = binding
            return binding

    def close(self) -> None:
        with self._lock:
            bindings = list(self._bindings.values())
            self._bindings.clear()
        for binding in bindings:
            binding.close()

    def maintain(self) -> int:
        with self._lock:
            bindings = list(self._bindings.values())
        return sum(binding.task_run.prune_dead_connections() for binding in bindings)

    def status(self) -> dict[str, object]:
        with self._lock:
            bindings = list(self._bindings.values())
        return {
            "task_id": self.task_id,
            "target_count": len(bindings),
            "binding_cache_limit": self.backend.max_cached_bindings,
            "binding_evictions": self._binding_evictions,
            "targets": [binding.task_run.runtime_status() for binding in bindings],
        }


class LivePatchMcpBackend:
    """Apply and verify one file replacement under a durable mutation journal."""

    def __init__(
        self,
        *,
        journal_store: MutationJournalStore,
        credential_loader: Callable[
            [Mapping[str, object]], dict[str, dict[str, str | int]]
        ] = _default_credential_loader,
        ssh_transport_factory: Callable[[Mapping[str, object]], object] | None = None,
        telnet_transport_factory: Callable[[Mapping[str, object]], object] | None = None,
        max_cached_bindings: int = 32,
    ) -> None:
        if max_cached_bindings < 1:
            raise ValueError("max_cached_bindings must be positive")
        self.journal_store = journal_store
        self.credential_loader = credential_loader
        self.ssh_transport_factory = ssh_transport_factory
        self.telnet_transport_factory = telnet_transport_factory
        self.max_cached_bindings = int(max_cached_bindings)

    def open_task(self, task_id: str) -> _LivePatchTask:
        return _LivePatchTask(task_id, self)

    @staticmethod
    def close_task(task: _LivePatchTask) -> None:
        task.close()

    @staticmethod
    def maintain_task(task: _LivePatchTask) -> int:
        return task.maintain()

    @staticmethod
    def task_status(task: _LivePatchTask) -> dict[str, object]:
        return task.status()

    @staticmethod
    def _fresh_live_patch_verification(
        fresh,
        *,
        binding: _LivePatchBinding,
        remote: str,
        expected_sha: str,
        expected_metadata: Mapping[str, int | str],
        operation_id: str,
        context,
    ) -> dict[str, object]:
        if not expected_metadata:
            raise RuntimeError("Live Patch expected metadata is unavailable")
        request = RemoteReadRequest.create(
            request_id=(
                f"{operation_id}:fresh-checksum:"
                f"attempt-{fresh.verification_attempt}"
            ),
            target=binding.target,
            credential_selector=binding.ssh_selector,
            collector_name="live-patch-fresh-checksum",
            operation={
                "remote_path": remote,
                "expected_sha256": expected_sha,
                "expected_metadata": dict(expected_metadata),
            },
        )

        def collect(_read_context):
            lane = binding.task_run.telnet_lane(
                target=binding.target,
                credentials=binding.telnet_credentials,
                lease_name=LivePatchRuntimeAdapter.LEASE_NAME,
                transport=binding.telnet_transport,
            )
            expected_mode = str(expected_metadata["mode"])
            expected_uid = int(expected_metadata["uid"])
            expected_gid = int(expected_metadata["gid"])
            result = lane.run_command(
                "remote_sha=$(sha256sum {remote} | awk '{{print $1}}') && "
                "remote_mode=$(stat -c %a {remote}) && "
                "remote_uid=$(stat -c %u {remote}) && "
                "remote_gid=$(stat -c %g {remote}) && "
                "printf 'remote_sha256=%s\\nremote_mode=%s\\nremote_uid=%s\\nremote_gid=%s\\n' "
                '"$remote_sha" "$remote_mode" "$remote_uid" "$remote_gid" && '
                "test \"$remote_sha\" = {expected_sha} && "
                "test \"$remote_mode\" = {expected_mode} && "
                "test \"$remote_uid\" = {expected_uid} && "
                "test \"$remote_gid\" = {expected_gid} && echo verify_sha256".format(
                    remote=shlex.quote(remote),
                    expected_sha=shlex.quote(expected_sha),
                    expected_mode=shlex.quote(expected_mode),
                    expected_uid=expected_uid,
                    expected_gid=expected_gid,
                ),
                timeout=min(20.0, context.remaining()),
            )
            text = _telnet_stdout(result, marker="verify_sha256")
            if expected_sha not in text.lower():
                raise RuntimeError("fresh Live Patch checksum does not match")
            return {
                "remote_sha256": expected_sha,
                "remote_metadata": _file_metadata(text, "remote"),
            }

        verified = fresh.run_read(request, collect)
        return {
            **verified.value,
            "target_epoch": verified.target_epoch,
            "lane_epochs": verified.lane_epochs,
        }

    def _create_binding(
        self,
        task_id: str,
        arguments: Mapping[str, object],
    ) -> _LivePatchBinding:
        host = _argument_text(arguments, "ip")
        if not host:
            raise ValueError("Live Patch requires a bound ip")
        credentials = self.credential_loader(arguments)
        ssh_selector = CredentialSelector.for_ssh(
            user=str(credentials["ssh"].get("user", "")),
            user_env="",
            password_env=_argument_text(arguments, "ssh_password_env"),
            identity_file=str(credentials["ssh"].get("identity_file", "")),
            environ={},
        )
        telnet_selector = CredentialSelector.for_telnet(
            user=str(credentials["telnet"].get("user", "")),
            user_env="",
            password_env=_argument_text(arguments, "telnet_password_env"),
            environ={},
        )
        target = TargetSpec.for_credential_selectors(
            host=host,
            ssh_port=int(arguments.get("ssh_port", 22)),
            telnet_port=int(arguments.get("telnet_port", 23)),
            redfish_port=int(arguments.get("redfish_port", 443)),
            credential_selectors=(ssh_selector, telnet_selector),
            policy=TargetPolicy(
                read_only=False,
                ssh_host_key_policy=_argument_text(
                    arguments, "ssh_host_key_policy"
                )
                or "insecure",
            ),
        )
        ssh_credentials = ResolvedSshCredentials.from_mapping(credentials["ssh"])
        telnet_credentials = ResolvedTelnetCredentials.from_mapping(
            credentials["telnet"]
        )
        task_run = OpenUBMCTaskRun(
            task_id=task_id,
            credential_resolver=CredentialResolver(
                ssh_loader=lambda _selector: ssh_credentials
            ),
            mutation_journal_store=self.journal_store,
        )
        ssh_transport = (
            self.ssh_transport_factory(arguments)
            if self.ssh_transport_factory is not None
            else OpenSshControlMasterTransport(
                host_key_policy=target.policy.ssh_host_key_policy,
                known_hosts_file=_argument_text(
                    arguments, "ssh_known_hosts_file"
                ),
            )
        )
        telnet_transport = (
            self.telnet_transport_factory(arguments)
            if self.telnet_transport_factory is not None
            else CanonicalTelnetTransport()
        )
        return _LivePatchBinding(
            task_run=task_run,
            target=target,
            ssh_selector=ssh_selector,
            telnet_credentials=telnet_credentials,
            ssh_transport=ssh_transport,
            telnet_transport=telnet_transport,
        )

    def live_patch_run(
        self,
        task: _LivePatchTask,
        arguments: Mapping[str, object],
        context,
    ) -> dict[str, object]:
        context.raise_if_stopped()
        action = _argument_text(arguments, "action").lower().replace("-", "_")
        if action in {"", "apply"}:
            action = "live_patch"
        if action not in {"live_patch", "rollback"}:
            raise ValueError("Live Patch action must be apply or rollback")
        raw_policy = arguments.get("_task_authorization_policy")
        if raw_policy is not None:
            if not isinstance(raw_policy, Mapping):
                raise TypeError("_task_authorization_policy must be an object")
            authorization = TaskAuthorizationPolicy.from_public_dict(raw_policy)
        else:
            intent = _argument_text(arguments, "_task_intent") or _argument_text(
                arguments, "intent"
            )
            authorized_exceptions = arguments.get(
                "_task_authorized_exceptions",
                arguments.get("authorized_exceptions"),
            )
            if authorized_exceptions is not None and not isinstance(
                authorized_exceptions, Mapping
            ):
                raise TypeError("authorized_exceptions must be an object")
            authorization = MutationAuthorization.from_task_intent(
                intent,
                delivery_strategy=_argument_text(
                    arguments,
                    "_task_delivery_strategy",
                )
                or _argument_text(arguments, "delivery_strategy"),
                authorized_exceptions=authorized_exceptions,
            )
        allow_outside_roots = _argument_bool(arguments, "force_path")
        no_backup = _argument_bool(arguments, "no_backup")
        no_remount = _argument_bool(arguments, "no_remount")
        for exception_name, enabled in (
            ("force_path", allow_outside_roots),
            ("no_backup", no_backup),
            ("no_remount", no_remount),
        ):
            if enabled:
                authorization.require_exception(exception_name)
        remote = _validate_remote_path(
            _argument_text(arguments, "remote_path"),
            allow_outside_roots=allow_outside_roots,
        )
        remote_root = _authorized_root(
            remote,
            allowed_roots=_ALLOWED_REMOTE_ROOTS,
            allow_outside_roots=allow_outside_roots,
        )
        mode = _argument_text(arguments, "mode") or "644"
        if _SAFE_MODE.fullmatch(mode) is None:
            raise ValueError("Live Patch mode must be a 3- or 4-digit octal value")
        restart_scope = _argument_text(arguments, "restart_scope") or "none"
        binding = task.binding_for(arguments)
        minimum_target_epoch = arguments.get("_minimum_target_epoch", 0)
        if (
            isinstance(minimum_target_epoch, bool)
            or not isinstance(minimum_target_epoch, int)
            or minimum_target_epoch < 0
        ):
            raise TypeError("_minimum_target_epoch must be a non-negative integer")
        if minimum_target_epoch:
            binding.task_run.ensure_target_epoch(
                binding.target,
                minimum_target_epoch,
                reason="context-runtime-live-patch-sync",
            )
        adapter = LivePatchRuntimeAdapter(
            task_run=binding.task_run,
            target=binding.target,
            credential_selector=binding.ssh_selector,
            telnet_credentials=binding.telnet_credentials,
            telnet_transport=binding.telnet_transport,
            ssh_transport=(
                binding.ssh_transport if action == "live_patch" else None
            ),
        )
        recovery_mode = effect_recovery_mode(arguments)
        if action == "rollback":
            return self._rollback_run(
                arguments=arguments,
                context=context,
                authorization=authorization,
                binding=binding,
                adapter=adapter,
                remote=remote,
                remote_root=remote_root,
                mode=mode,
                restart_scope=restart_scope,
                recovery_mode=recovery_mode,
            )

        local = Path(_argument_text(arguments, "local_path")).expanduser().resolve()
        authored_local_sha = _argument_text(arguments, "artifact_sha256").lower()
        if authored_local_sha and _SHA256.fullmatch(authored_local_sha) is None:
            raise ValueError("Live Patch artifact_sha256 must be SHA-256")
        token = hashlib.sha256(context.operation_id.encode("utf-8")).hexdigest()[:16]
        staging = _argument_text(arguments, "staging_path") or (
            f"/tmp/.openubmc-live-patch-{token}"
        )
        staging = _validate_remote_path(staging, allowed_roots=("/tmp/",))
        backup_dir = _argument_text(arguments, "backup_dir") or "/tmp"
        backup_probe = _validate_remote_path(
            f"{backup_dir.rstrip('/')}/placeholder",
            allowed_roots=("/tmp/",),
        )
        backup_dir = posixpath.dirname(backup_probe)
        backup = f"{backup_dir}/{PurePosixPath(remote).name}.bak.{token}"
        expected_metadata: dict[str, int | str] = {}
        def mutation_operation(expected_sha: str) -> dict[str, object]:
            return {
                "local_path": str(local),
                "local_sha256": expected_sha,
                "remote_path": remote,
                "mode": mode,
                "staging_path": staging,
                "backup_path": backup,
                "backup_dir": backup_dir,
                "no_backup": no_backup,
                "no_remount": no_remount,
                "force_path": allow_outside_roots,
            }

        current_local_sha = _sha256(local) if local.is_file() else ""
        recovery_route = mutation_recovery_route(
            recovery_mode,
            binding.task_run.mutation_journals,
            operation_id=context.operation_id,
            action="live_patch",
            label="Live Patch",
            matches=lambda journal: bool(
                getattr(journal, "expected_checksum", "") or current_local_sha
            )
            and adapter.mutation_request(
                operation_id=str(getattr(journal, "operation_id", "")),
                restart_scope=restart_scope,
                operation=mutation_operation(
                    str(getattr(journal, "expected_checksum", ""))
                    or current_local_sha
                ),
                action="live_patch",
            ).fingerprint
            == str(getattr(journal, "operation_fingerprint", "")),
        )
        matching_journal = recovery_route.journal
        if matching_journal is not None:
            if (
                authored_local_sha
                and matching_journal.expected_checksum
                and authored_local_sha != matching_journal.expected_checksum
            ):
                raise ValueError(
                    "Live Patch artifact SHA-256 does not match the durable mutation"
                )
            operation = mutation_operation(
                matching_journal.expected_checksum or current_local_sha
            )
            if recovery_route.disposition == "terminal":
                result = adapter.run(
                    operation_id=context.operation_id,
                    authorization=authorization,
                    restart_scope=restart_scope,
                    operation=operation,
                    apply=lambda _execution: (_ for _ in ()).throw(
                        RuntimeError("terminal Live Patch replay invoked apply")
                    ),
                    verify=lambda _fresh: (_ for _ in ()).throw(
                        RuntimeError("terminal Live Patch replay invoked verify")
                    ),
                    action="live_patch",
                    operation_context=context,
                )
                return result.to_public_dict()
            if (
                recovery_route.disposition == "new"
                and recovery_mode is not None
            ):
                recovered = adapter.recover(
                    operation_id=matching_journal.operation_id,
                    authorization=authorization,
                    restart_scope=restart_scope,
                    operation=operation,
                    inspect=lambda _inspection: (_ for _ in ()).throw(
                        RuntimeError("replanned Live Patch recovery invoked inspect")
                    ),
                    verify=lambda _fresh: (_ for _ in ()).throw(
                        RuntimeError("replanned Live Patch recovery invoked verify")
                    ),
                    action="live_patch",
                    operation_context=context,
                )
                return recovered.to_transaction_dict(
                    target_fingerprint=binding.target.fingerprint
                )
            if recovery_route.disposition == "recover":
                return self._recover_uncertain_live_patch(
                    binding=binding,
                    adapter=adapter,
                    journal=matching_journal,
                    authorization=authorization,
                    context=context,
                    operation=operation,
                    remote=remote,
                    remote_root=remote_root,
                    mode=mode,
                    restart_scope=restart_scope,
                    expected_metadata=expected_metadata,
                )

        if not local.is_file():
            raise ValueError(f"Live Patch local_path is unavailable: {local}")
        local_sha = current_local_sha
        if authored_local_sha and local_sha != authored_local_sha:
            raise ValueError("Live Patch artifact SHA-256 does not match")
        operation = mutation_operation(local_sha)

        def apply(execution) -> dict[str, object]:
            execution.journal.record_execution_evidence(
                expected_checksum=local_sha,
            )
            mount = _RootMountState()
            try:
                guarded_paths = [
                    (remote, remote_root, False),
                    (staging, "/tmp", False),
                ]
                if not no_backup:
                    guarded_paths.append((backup, "/tmp", False))
                _require_path_guards(
                    execution,
                    context,
                    tuple(guarded_paths),
                )
                _require_shell_codec(execution, context)
                target_identity = _inspect_live_patch_target_identity(
                    execution.telnet_lane,
                    context,
                )
                execution.journal.record_target_identity(target_identity)
                _prepare_root_mount(
                    execution,
                    context,
                    no_remount=no_remount,
                    state=mount,
                )
                inspect = execution.run_telnet(
                    "if test -f {remote}; then sha256sum {remote} && "
                    "stat -c 'target_mode=%a target_uid=%u target_gid=%g' {remote} && "
                    "echo target_exists; "
                    "else echo target_missing; fi".format(
                        remote=shlex.quote(remote)
                    ),
                    timeout=min(20.0, context.remaining()),
                )
                inspect_text = _telnet_text(
                    inspect,
                    purpose="target inspection",
                )
                before_sha = ""
                before_metadata: dict[str, int | str] = {}
                if "target_exists" in inspect_text:
                    digests = _SHA256.findall(inspect_text)
                    if not digests:
                        raise RuntimeError(
                            "Live Patch target checksum is unavailable"
                        )
                    before_sha = digests[-1].lower()
                    before_metadata = _file_metadata(inspect_text, "target")
                elif "target_missing" not in inspect_text:
                    raise RuntimeError(
                        "Live Patch target existence was not established"
                    )
                execution.journal.record_execution_evidence(
                    before_checksum=before_sha or None,
                    expected_checksum=local_sha,
                )
                backup_reference = ""
                if "target_exists" in inspect_text and not no_backup:
                    execution.mark_effects_started()
                    backup_result = execution.run_telnet(
                        _compressed_shell_command(
                            _atomic_backup_command(
                                remote,
                                backup,
                                before_sha,
                                str(before_metadata["mode"]),
                                int(before_metadata["uid"]),
                                int(before_metadata["gid"]),
                                token,
                            ),
                            phase="b",
                        ),
                        timeout=min(30.0, context.remaining()),
                    )
                    _telnet_stdout(backup_result, marker="backup_ok")
                    execution.record_backup(backup)
                    backup_reference = backup
                execution.mark_effects_started()
                upload = execution.upload_file(
                    str(local), staging, timeout=min(120.0, context.remaining())
                )
                if int(getattr(upload, "returncode", 1)) != 0:
                    raise RuntimeError(
                        "Live Patch SSH upload failed: "
                        + str(getattr(upload, "stderr", ""))
                    )
                _require_path_guards(
                    execution,
                    context,
                    (
                        (remote, remote_root, False),
                        (staging, "/tmp", True),
                    ),
                )
                install = execution.run_telnet(
                    _compressed_shell_command(
                        _atomic_install_command(
                            staging,
                            remote,
                            mode,
                            local_sha,
                            (
                                int(before_metadata["uid"])
                                if before_metadata
                                else None
                            ),
                            (
                                int(before_metadata["gid"])
                                if before_metadata
                                else None
                            ),
                            token,
                        ),
                        phase="i",
                    ),
                    timeout=min(40.0, context.remaining()),
                )
                install_text = _telnet_stdout(install, marker="deploy_ok")
                if local_sha not in install_text.lower():
                    raise RuntimeError("Live Patch deployed checksum does not match")
                installed_metadata = _file_metadata(install_text, "remote")
                expected_metadata.clear()
                expected_metadata.update(installed_metadata)
                restart_before = _record_restart_boundary(
                    execution,
                    context,
                    restart_scope=restart_scope,
                )
                restart_command = (
                    "sync && killall skynet && echo restart_ok"
                    if restart_scope == "skynet"
                    else "sync && echo restart_ok"
                )
                restart = execution.run_telnet(
                    restart_command,
                    timeout=min(20.0, context.remaining()),
                )
                _telnet_stdout(restart, marker="restart_ok")
                return {
                    "ok": True,
                    "local_path": str(local),
                    "remote_path": remote,
                    "local_sha256": local_sha,
                    "remote_after_sha256": local_sha,
                    "remote_before_metadata": before_metadata,
                    "remote_after_metadata": installed_metadata,
                    "target_existed": bool(before_metadata),
                    "backup_reference": backup_reference,
                    "restart_scope": restart_scope,
                    "restart_state": (
                        f"completed:skynet:{restart_before}"
                        if restart_scope == "skynet"
                        else "completed:none"
                    ),
                    "root_mount_before": list(mount.options),
                    "root_mount_restored": True,
                    "install_output": install_text[-1024:],
                }
            finally:
                _finalize_root_mount(
                    execution,
                    context,
                    state=mount,
                    primary_error=sys.exc_info()[1],
                )

        def verify(fresh) -> dict[str, object]:
            return self._fresh_live_patch_verification(
                fresh,
                binding=binding,
                remote=remote,
                expected_sha=local_sha,
                expected_metadata=expected_metadata,
                operation_id=context.operation_id,
                context=context,
            )

        result = adapter.run(
            operation_id=context.operation_id,
            authorization=authorization,
            restart_scope=restart_scope,
            operation=operation,
            apply=apply,
            verify=verify,
            action="live_patch",
            operation_context=context,
        )
        context.raise_if_stopped()
        return result.to_public_dict()

    def _recover_uncertain_live_patch(
        self,
        *,
        binding: _LivePatchBinding,
        adapter: LivePatchRuntimeAdapter,
        journal,
        authorization: MutationAuthorization,
        context,
        operation: Mapping[str, object],
        remote: str,
        remote_root: str,
        mode: str,
        restart_scope: str,
        expected_metadata: dict[str, int | str],
    ) -> dict[str, object]:
        """Inspect an uncertain install before deciding whether verification is safe."""

        backup = journal.backup_reference
        if (
            not backup
            and journal.before_checksum
            and not bool(operation.get("no_backup", False))
        ):
            backup = str(operation.get("backup_path", ""))
        if backup:
            backup = _validate_remote_path(backup, allowed_roots=("/tmp/",))

        def inspect(_inspection_context) -> dict[str, object]:
            lane = binding.task_run.telnet_lane(
                target=binding.target,
                credentials=binding.telnet_credentials,
                lease_name=LivePatchRuntimeAdapter.LEASE_NAME,
                transport=binding.telnet_transport,
            )
            snapshot = _inspect_live_patch_recovery(
                lane,
                context,
                remote=remote,
                remote_root=remote_root,
                backup=backup,
                guard_backup=True,
                root_mount_mode=str(journal.root_mount_mode),
                unknown_mount_restored=journal.root_mount_restored,
                restart_scope=restart_scope,
                restart_state=str(journal.restart_state),
            )
            evidence_safe = snapshot.recovery_safe
            additional_blockers: list[str] = []
            if backup and snapshot.backup_exists is not True:
                evidence_safe = False
                additional_blockers.append("backup_unavailable")
            if (
                journal.before_checksum
                and snapshot.backup_checksum != journal.before_checksum
            ):
                evidence_safe = False
                additional_blockers.append("backup_checksum_mismatch")

            if snapshot.remote_checksum == journal.expected_checksum:
                expected_mode = format(int(mode, 8), "o")
                if snapshot.backup_metadata:
                    expected_uid = int(snapshot.backup_metadata["uid"])
                    expected_gid = int(snapshot.backup_metadata["gid"])
                elif not journal.before_checksum:
                    expected_uid = 0
                    expected_gid = 0
                else:
                    expected_uid = int(snapshot.remote_metadata.get("uid", -1))
                    expected_gid = int(snapshot.remote_metadata.get("gid", -1))
                if (
                    str(snapshot.remote_metadata.get("mode", "")) != expected_mode
                    or int(snapshot.remote_metadata.get("uid", -1)) != expected_uid
                    or int(snapshot.remote_metadata.get("gid", -1)) != expected_gid
                ):
                    evidence_safe = False
                    additional_blockers.append("remote_metadata_mismatch")
                expected_metadata.clear()
                expected_metadata.update(
                    {
                        "mode": expected_mode,
                        "uid": expected_uid,
                        "gid": expected_gid,
                    }
                )

            return snapshot.evidence(
                recovery_safe=evidence_safe,
                additional_blockers=tuple(additional_blockers),
            )

        recovered = adapter.recover(
            operation_id=journal.operation_id,
            authorization=authorization,
            restart_scope=restart_scope,
            operation=operation,
            inspect=inspect,
            verify=lambda fresh: self._fresh_live_patch_verification(
                fresh,
                binding=binding,
                remote=remote,
                expected_sha=str(operation["local_sha256"]),
                expected_metadata=expected_metadata,
                operation_id=journal.operation_id,
                context=context,
            ),
            action="live_patch",
            operation_context=context,
        )
        return {
            "operation_id": recovered.operation_id,
            "action": "live_patch",
            "target_fingerprint": binding.target.fingerprint,
            "epoch_before": recovered.journal.epoch_before,
            "epoch_after": (
                recovered.journal.epoch_after
                or recovered.journal.epoch_before
            ),
            "mutation": {
                "local_sha256": str(operation["local_sha256"]),
                "remote_after_sha256": (
                    recovered.journal.observed_checksum
                    or str(operation["local_sha256"])
                ),
                "remote_after_metadata": dict(expected_metadata),
                "root_mount_restored": recovered.journal.root_mount_restored,
                "recovery": recovered.to_public_dict(),
            },
            "verification": recovered.verification,
            "journal": recovered.journal.to_public_dict(),
            "idempotent_replay": False,
        }

    def _rollback_run(
        self,
        *,
        arguments: Mapping[str, object],
        context,
        authorization: MutationAuthorization,
        binding: _LivePatchBinding,
        adapter: LivePatchRuntimeAdapter,
        remote: str,
        remote_root: str,
        mode: str,
        restart_scope: str,
        recovery_mode,
    ) -> dict[str, object]:
        remove_created = _argument_bool(arguments, "remove_created")
        backup_text = _argument_text(arguments, "backup_path")
        expected_current_sha = _argument_text(
            arguments,
            "expected_current_sha256",
        ).lower()
        if remove_created:
            if backup_text:
                raise ValueError(
                    "Live Patch remove-created rollback cannot also use a backup"
                )
            if _SHA256.fullmatch(expected_current_sha) is None:
                raise ValueError(
                    "Live Patch remove-created rollback requires "
                    "expected_current_sha256"
                )
            backup = ""
        else:
            backup = _validate_remote_path(
                backup_text,
                allowed_roots=("/tmp/",),
            )
        no_remount = _argument_bool(arguments, "no_remount")
        token = hashlib.sha256(context.operation_id.encode("utf-8")).hexdigest()[:16]
        expected: dict[str, int | str] = {}
        operation = {
            "backup_path": backup,
            "remote_path": remote,
            "mode": mode,
            "no_remount": no_remount,
            "remove_created": remove_created,
            "expected_current_sha256": expected_current_sha,
            "force_path": _argument_bool(arguments, "force_path"),
        }

        def apply(execution) -> dict[str, object]:
            mount = _RootMountState()
            try:
                guarded_paths = [(remote, remote_root, remove_created)]
                if backup:
                    guarded_paths.append((backup, "/tmp", True))
                _require_path_guards(
                    execution,
                    context,
                    tuple(guarded_paths),
                )
                _require_shell_codec(execution, context)
                target_identity = _inspect_live_patch_target_identity(
                    execution.telnet_lane,
                    context,
                )
                execution.journal.record_target_identity(target_identity)
                rollback_backup: dict[str, int | str] = {}
                if remove_created:
                    expected["removed"] = "true"
                    execution.journal.record_expected_target_state(
                        MutationExpectedTargetState.absent()
                    )
                else:
                    rollback_backup = _inspect_rollback_backup(
                        execution,
                        context,
                        backup,
                    )
                    expected.update(
                        {
                            "sha256": str(rollback_backup["sha256"]),
                            "mode": format(int(mode, 8), "o"),
                            "uid": int(rollback_backup["uid"]),
                            "gid": int(rollback_backup["gid"]),
                        }
                    )
                    execution.record_backup(backup)
                    execution.journal.record_expected_target_state(
                        MutationExpectedTargetState.file(
                            str(expected["sha256"]),
                            {
                            "mode": expected["mode"],
                            "uid": expected["uid"],
                            "gid": expected["gid"],
                            },
                        )
                    )
                _prepare_root_mount(
                    execution,
                    context,
                    no_remount=no_remount,
                    state=mount,
                )
                execution.mark_effects_started()
                if remove_created:
                    removed = execution.run_telnet(
                        _compressed_shell_command(
                            _atomic_remove_command(
                                remote,
                                expected_current_sha,
                            ),
                            phase="r",
                        ),
                        timeout=min(40.0, context.remaining()),
                    )
                    restored_text = _telnet_stdout(removed, marker="remove_ok")
                    if expected_current_sha not in restored_text.lower():
                        raise RuntimeError(
                            "Live Patch remove-created checksum does not match"
                        )
                    remote_sha = ""
                    restored_metadata: dict[str, int | str] = {}
                    execution.journal.record_execution_evidence(
                        observed_checksum="",
                    )
                else:
                    restored = execution.run_telnet(
                        _compressed_shell_command(
                            _atomic_restore_command(
                                backup,
                                remote,
                                mode,
                                token,
                                str(rollback_backup["sha256"]),
                                int(rollback_backup["uid"]),
                                int(rollback_backup["gid"]),
                            ),
                            phase="r",
                        ),
                        timeout=min(40.0, context.remaining()),
                    )
                    restored_text = _telnet_stdout(restored, marker="restore_ok")
                    digests = _SHA256.findall(restored_text)
                    if (
                        len(digests) < 2
                        or digests[-2].lower() != digests[-1].lower()
                    ):
                        raise RuntimeError(
                            "Live Patch rollback checksum does not match"
                        )
                    remote_sha = digests[-1].lower()
                    restored_metadata = _file_metadata(restored_text, "remote")
                    execution.journal.record_execution_evidence(
                        observed_checksum=remote_sha,
                    )
                restart_before = _record_restart_boundary(
                    execution,
                    context,
                    restart_scope=restart_scope,
                )
                restart_command = (
                    "sync && killall skynet && echo restart_ok"
                    if restart_scope == "skynet"
                    else "sync && echo restart_ok"
                )
                restart = execution.run_telnet(
                    restart_command,
                    timeout=min(20.0, context.remaining()),
                )
                _telnet_stdout(restart, marker="restart_ok")
                return {
                    "ok": True,
                    "backup_reference": backup,
                    "remote_path": remote,
                    "remote_after_sha256": remote_sha,
                    "remote_after_metadata": restored_metadata,
                    "remote_removed": remove_created,
                    "restart_scope": restart_scope,
                    "restart_state": (
                        f"completed:skynet:{restart_before}"
                        if restart_scope == "skynet"
                        else "completed:none"
                    ),
                    "root_mount_before": list(mount.options),
                    "root_mount_restored": True,
                    "restore_output": restored_text[-1024:],
                }
            finally:
                _finalize_root_mount(
                    execution,
                    context,
                    state=mount,
                    primary_error=sys.exc_info()[1],
                )

        def verify(fresh) -> dict[str, object]:
            if remove_created:
                if expected.get("removed") != "true":
                    raise RuntimeError(
                        "Live Patch remove-created result is unavailable"
                    )
                request = RemoteReadRequest.create(
                    request_id=(
                        f"{context.operation_id}:fresh-rollback-missing:"
                        f"attempt-{fresh.verification_attempt}"
                    ),
                    target=binding.target,
                    credential_selector=binding.ssh_selector,
                    collector_name="live-patch-fresh-rollback-missing",
                    operation={
                        "remote_path": remote,
                        "expected_missing": True,
                    },
                )

                def collect_missing(_read_context):
                    lane = binding.task_run.telnet_lane(
                        target=binding.target,
                        credentials=binding.telnet_credentials,
                        lease_name=LivePatchRuntimeAdapter.LEASE_NAME,
                        transport=binding.telnet_transport,
                    )
                    result = lane.run_command(
                        "test ! -e {remote} && test ! -L {remote} && "
                        "echo verify_missing".format(
                            remote=shlex.quote(remote),
                        ),
                        timeout=min(20.0, context.remaining()),
                    )
                    _telnet_stdout(result, marker="verify_missing")
                    return {"remote_removed": True}

                verified = fresh.run_read(request, collect_missing)
                return {
                    **verified.value,
                    "target_epoch": verified.target_epoch,
                    "lane_epochs": verified.lane_epochs,
                }

            expected_sha = str(expected.get("sha256", ""))
            if not expected_sha:
                raise RuntimeError("Live Patch rollback checksum is unavailable")
            expected_mode = str(expected.get("mode", ""))
            expected_uid = expected.get("uid")
            expected_gid = expected.get("gid")
            if (
                _SAFE_MODE.fullmatch(expected_mode) is None
                or not isinstance(expected_uid, int)
                or not isinstance(expected_gid, int)
            ):
                raise RuntimeError("Live Patch rollback metadata is unavailable")
            request = RemoteReadRequest.create(
                request_id=(
                    f"{context.operation_id}:fresh-rollback-checksum:"
                    f"attempt-{fresh.verification_attempt}"
                ),
                target=binding.target,
                credential_selector=binding.ssh_selector,
                collector_name="live-patch-fresh-rollback-checksum",
                operation={
                    "remote_path": remote,
                    "expected_sha256": expected_sha,
                    "expected_metadata": {
                        "mode": expected_mode,
                        "uid": expected_uid,
                        "gid": expected_gid,
                    },
                },
            )

            def collect(_read_context):
                lane = binding.task_run.telnet_lane(
                    target=binding.target,
                    credentials=binding.telnet_credentials,
                    lease_name=LivePatchRuntimeAdapter.LEASE_NAME,
                    transport=binding.telnet_transport,
                )
                result = lane.run_command(
                    "remote_sha=$(sha256sum {remote} | awk '{{print $1}}') && "
                    "remote_mode=$(stat -c %a {remote}) && "
                    "remote_uid=$(stat -c %u {remote}) && "
                    "remote_gid=$(stat -c %g {remote}) && "
                    "printf 'remote_sha256=%s\\nremote_mode=%s\\nremote_uid=%s\\nremote_gid=%s\\n' "
                    "\"$remote_sha\" \"$remote_mode\" \"$remote_uid\" \"$remote_gid\" && "
                    "test \"$remote_sha\" = {expected_sha} && "
                    "test \"$remote_mode\" = {expected_mode} && "
                    "test \"$remote_uid\" = {expected_uid} && "
                    "test \"$remote_gid\" = {expected_gid} && echo verify_sha256".format(
                        remote=shlex.quote(remote),
                        expected_sha=shlex.quote(expected_sha),
                        expected_mode=shlex.quote(expected_mode),
                        expected_uid=expected_uid,
                        expected_gid=expected_gid,
                    ),
                    timeout=min(20.0, context.remaining()),
                )
                text = _telnet_stdout(result, marker="verify_sha256")
                if expected_sha not in text.lower():
                    raise RuntimeError(
                        "fresh Live Patch rollback checksum does not match"
                    )
                return {
                    "remote_sha256": expected_sha,
                    "remote_metadata": _file_metadata(text, "remote"),
                }

            verified = fresh.run_read(request, collect)
            return {
                **verified.value,
                "target_epoch": verified.target_epoch,
                "lane_epochs": verified.lane_epochs,
            }

        recovery_route = mutation_recovery_route(
            recovery_mode,
            binding.task_run.mutation_journals,
            operation_id=context.operation_id,
            action="rollback",
            label="Live Patch rollback",
            matches=lambda journal: adapter.mutation_request(
                operation_id=str(getattr(journal, "operation_id", "")),
                restart_scope=restart_scope,
                operation=operation,
                action="rollback",
            ).fingerprint
            == str(getattr(journal, "operation_fingerprint", "")),
        )
        matching_journal = recovery_route.journal
        if matching_journal is not None:
            if recovery_route.disposition == "terminal":
                replayed = adapter.run(
                    operation_id=context.operation_id,
                    authorization=authorization,
                    restart_scope=restart_scope,
                    operation=operation,
                    apply=lambda _execution: (_ for _ in ()).throw(
                        RuntimeError("terminal Live Patch rollback replay invoked apply")
                    ),
                    verify=lambda _fresh: (_ for _ in ()).throw(
                        RuntimeError("terminal Live Patch rollback replay invoked verify")
                    ),
                    action="rollback",
                    operation_context=context,
                )
                return replayed.to_public_dict()
            if (
                recovery_route.disposition == "new"
                and recovery_mode is not None
            ):
                recovered = adapter.recover(
                    operation_id=matching_journal.operation_id,
                    authorization=authorization,
                    restart_scope=restart_scope,
                    operation=operation,
                    inspect=lambda _inspection: (_ for _ in ()).throw(
                        RuntimeError("replanned rollback recovery invoked inspect")
                    ),
                    verify=lambda _fresh: (_ for _ in ()).throw(
                        RuntimeError("replanned rollback recovery invoked verify")
                    ),
                    action="rollback",
                    operation_context=context,
                )
                return recovered.to_transaction_dict(
                    target_fingerprint=binding.target.fingerprint
                )
            if recovery_route.disposition == "recover":
                if matching_journal.expected_missing is True:
                    expected["removed"] = "true"
                elif (
                    matching_journal.expected_checksum
                    and matching_journal.expected_metadata
                ):
                    expected.update(
                        {
                            "sha256": matching_journal.expected_checksum,
                            **dict(matching_journal.expected_metadata),
                        }
                    )

                def inspect(_inspection_context) -> dict[str, object]:
                    lane = binding.task_run.telnet_lane(
                        target=binding.target,
                        credentials=binding.telnet_credentials,
                        lease_name=LivePatchRuntimeAdapter.LEASE_NAME,
                        transport=binding.telnet_transport,
                    )
                    snapshot = _inspect_live_patch_recovery(
                        lane,
                        context,
                        remote=remote,
                        remote_root=remote_root,
                        backup=backup,
                        guard_backup=False,
                        root_mount_mode=str(matching_journal.root_mount_mode),
                        unknown_mount_restored=True if no_remount else False,
                        restart_scope=restart_scope,
                        restart_state=str(matching_journal.restart_state),
                    )
                    return snapshot.evidence()

                recovered = adapter.recover(
                    operation_id=matching_journal.operation_id,
                    authorization=authorization,
                    restart_scope=restart_scope,
                    operation=operation,
                    inspect=inspect,
                    verify=verify,
                    action="rollback",
                    operation_context=context,
                )
                return {
                    "operation_id": recovered.operation_id,
                    "action": "rollback",
                    "target_fingerprint": binding.target.fingerprint,
                    "epoch_before": recovered.journal.epoch_before,
                    "epoch_after": (
                        recovered.journal.epoch_after
                        or recovered.journal.epoch_before
                    ),
                    "mutation": {
                        "remote_after_sha256": (
                            recovered.journal.observed_checksum
                        ),
                        "remote_removed": (
                            remove_created
                            and not recovered.inspection.remote_checksum
                        ),
                        "root_mount_restored": (
                            recovered.journal.root_mount_restored
                        ),
                        "recovery": recovered.to_public_dict(),
                    },
                    "verification": recovered.verification,
                    "journal": recovered.journal.to_public_dict(),
                    "idempotent_replay": False,
                }

        result = adapter.run(
            operation_id=context.operation_id,
            authorization=authorization,
            restart_scope=restart_scope,
            operation=operation,
            apply=apply,
            verify=verify,
            action="rollback",
            operation_context=context,
        )
        context.raise_if_stopped()
        return result.to_public_dict()
