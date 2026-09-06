#!/usr/bin/env python3
"""Internal remote check implementations for openUBMC preflight."""
from __future__ import annotations

import argparse
import shlex

from _remote_common import (
    DbusEnvironment,
    SshControlMasterOpenError,
    build_posix_shell_command,
    detect_dbus_env,
    preview_lines,
    run_ssh,
    sanitize_remote_text,
    ssh_transport_details,
    ssh_transport_failure_code,
)
from _telnet_common import (
    TELNET_OUTPUT_LIMIT_CODE,
    TelnetOutputLimitExceeded,
    close_telnet,
    run_cmd_result,
    telnet_connect,
    telnet_output_limit_details,
)
from mdbctl_remote import classify_failure as classify_mdbctl_failure
from mdbctl_remote import is_success as mdbctl_is_success

PREFLIGHT_SMALL_OUTPUT_LIMIT_BYTES = 64 * 1024
PREFLIGHT_PROBE_STDOUT_LIMIT_BYTES = 1024 * 1024
PREFLIGHT_STDERR_LIMIT_BYTES = 64 * 1024


class CheckLines(list[str]):
    def __init__(
        self,
        values: list[str],
        *,
        transport: dict[str, object] | None = None,
        failure_code: str = "",
    ) -> None:
        super().__init__(values)
        self.transport = transport or {}
        self.failure_code = failure_code


def _transport_failure_lines(
    code: str, transport: dict[str, object]
) -> CheckLines:
    return CheckLines([code], transport=transport)


def check_ssh(
    args: argparse.Namespace,
    ssh: dict[str, str | int],
    debug_dumper=None,
    *,
    ssh_runner=None,
) -> tuple[bool, list[str]]:
    if not str(ssh.get("user", "")).strip():
        return False, ["OPENUBMC_SSH_USER is not configured"]
    remote_cmd = build_posix_shell_command("date '+%F %T %z'; uptime")
    selected_ssh_runner = ssh_runner or run_ssh
    cp = selected_ssh_runner(
        args.ip,
        str(ssh["user"]),
        str(ssh["password"]),
        remote_cmd,
        args.ssh_timeout,
        tty=True,
        port=int(ssh["port"]),
        identity_file=str(ssh["identity_file"]),
        debug_dumper=debug_dumper,
        debug_label="preflight_ssh",
        stdout_limit_bytes=PREFLIGHT_SMALL_OUTPUT_LIMIT_BYTES,
        stderr_limit_bytes=PREFLIGHT_STDERR_LIMIT_BYTES,
    )
    transport_code = ssh_transport_failure_code(cp)
    if transport_code:
        return False, _transport_failure_lines(
            transport_code, ssh_transport_details(cp)
        )
    stdout = sanitize_remote_text(cp.stdout or "")
    stderr = sanitize_remote_text(cp.stderr or "")
    lines = preview_lines(stdout, limit=4)
    if stderr:
        lines.extend(preview_lines(stderr, limit=2))
    audited_lines = CheckLines(lines, transport=ssh_transport_details(cp))
    if cp.returncode == 0 and lines:
        return True, audited_lines
    return False, audited_lines or CheckLines(
        [stderr or f"ssh preflight failed with exit code {cp.returncode}"],
        transport=ssh_transport_details(cp),
    )


def check_dbus_env(
    args: argparse.Namespace,
    ssh: dict[str, str | int],
    debug_dumper=None,
    *,
    ssh_runner=None,
    environment_cache=None,
) -> tuple[bool, list[str], dict[str, str]]:
    def load_environment():
        return detect_dbus_env(
            args.ip,
            str(ssh["user"]),
            str(ssh["password"]),
            args.ssh_timeout,
            port=int(ssh["port"]),
            identity_file=str(ssh["identity_file"]),
            debug_dumper=debug_dumper,
            debug_label="preflight_dbus_env",
            ssh_runner=ssh_runner,
        )

    try:
        env = (
            environment_cache(load_environment)
            if environment_cache is not None
            else load_environment()
        )
    except SshControlMasterOpenError as exc:
        env = DbusEnvironment(transport=ssh_transport_details(exc.completed))
    transport = getattr(env, "transport", {})
    lines = CheckLines([
        f"DBUS_SESSION_BUS_ADDRESS={env.get('DBUS_SESSION_BUS_ADDRESS', '')}",
        f"XDG_RUNTIME_DIR={env.get('XDG_RUNTIME_DIR', '')}",
    ], transport=transport)
    transport_code = str(transport.get("failure_code", ""))
    if transport_code:
        return False, _transport_failure_lines(transport_code, transport), env
    return bool(env.get("DBUS_SESSION_BUS_ADDRESS") and env.get("XDG_RUNTIME_DIR")), lines, env


def check_mdbctl(
    args: argparse.Namespace,
    ssh: dict[str, str | int],
    debug_dumper=None,
    *,
    ssh_runner=None,
) -> tuple[bool, list[str]]:
    remote_cmd = build_posix_shell_command("mdbctl lsclass", load_profile=True)
    selected_ssh_runner = ssh_runner or run_ssh
    cp = selected_ssh_runner(
        args.ip,
        str(ssh["user"]),
        str(ssh["password"]),
        remote_cmd,
        args.ssh_timeout,
        port=int(ssh["port"]),
        identity_file=str(ssh["identity_file"]),
        debug_dumper=debug_dumper,
        debug_label="preflight_mdbctl",
        stdout_limit_bytes=PREFLIGHT_PROBE_STDOUT_LIMIT_BYTES,
        stderr_limit_bytes=PREFLIGHT_STDERR_LIMIT_BYTES,
    )
    transport_code = ssh_transport_failure_code(cp)
    if transport_code:
        return False, _transport_failure_lines(
            transport_code, ssh_transport_details(cp)
        )
    stdout = sanitize_remote_text(cp.stdout or "")
    stderr = sanitize_remote_text(cp.stderr or "")
    lines = preview_lines(stdout, limit=3)
    if stderr:
        lines.extend(preview_lines(stderr, limit=2))
    success = mdbctl_is_success(cp, stdout, stderr)
    failure_code = "" if success else classify_mdbctl_failure(cp, stdout, stderr)
    audited_lines = CheckLines(
        lines,
        transport=ssh_transport_details(cp),
        failure_code=failure_code,
    )
    if success:
        return True, audited_lines
    if audited_lines:
        return False, audited_lines
    return False, CheckLines(
        [stderr or f"mdbctl login-shell failed with exit code {cp.returncode}"],
        transport=ssh_transport_details(cp),
        failure_code=failure_code,
    )


def check_busctl(
    args: argparse.Namespace,
    ssh: dict[str, str | int],
    env: dict[str, str],
    debug_dumper=None,
    *,
    ssh_runner=None,
) -> tuple[bool, list[str]]:
    dbus = env.get("DBUS_SESSION_BUS_ADDRESS", "")
    xdg = env.get("XDG_RUNTIME_DIR", "")
    if not (dbus and xdg):
        return False, ["DBUS/XDG env not detected"]
    busctl_probe = (
        f"busctl --user --no-pager tree {shlex.quote(args.busctl_service)}"
        if args.busctl_service
        else "busctl --user --no-pager list"
    )
    remote_cmd = (
        f"XDG_RUNTIME_DIR={shlex.quote(xdg)} "
        f"DBUS_SESSION_BUS_ADDRESS={shlex.quote(dbus)} "
        f"{busctl_probe}"
    )
    selected_ssh_runner = ssh_runner or run_ssh
    cp = selected_ssh_runner(
        args.ip,
        str(ssh["user"]),
        str(ssh["password"]),
        remote_cmd,
        args.ssh_timeout,
        port=int(ssh["port"]),
        identity_file=str(ssh["identity_file"]),
        debug_dumper=debug_dumper,
        debug_label="preflight_busctl",
        stdout_limit_bytes=PREFLIGHT_PROBE_STDOUT_LIMIT_BYTES,
        stderr_limit_bytes=PREFLIGHT_STDERR_LIMIT_BYTES,
    )
    transport_code = ssh_transport_failure_code(cp)
    if transport_code:
        return False, _transport_failure_lines(
            transport_code, ssh_transport_details(cp)
        )
    stdout = sanitize_remote_text(cp.stdout or "")
    stderr = sanitize_remote_text(cp.stderr or "")
    lines = preview_lines(stdout, limit=5)
    if stderr:
        lines.extend(preview_lines(stderr, limit=2))
    audited_lines = CheckLines(lines, transport=ssh_transport_details(cp))
    if cp.returncode == 0 and stdout:
        return True, audited_lines
    return False, audited_lines or CheckLines(
        [stderr or f"busctl probe failed with exit code {cp.returncode}"],
        transport=ssh_transport_details(cp),
    )


def check_telnet(
    args: argparse.Namespace,
    telnet: dict[str, str | int],
    debug_dumper=None,
    *,
    session=None,
) -> tuple[bool, list[str], bool]:
    try:
        if session is None:
            tn = telnet_connect(
                args.ip,
                int(telnet["port"]),
                str(telnet["user"]),
                str(telnet["password"]),
                connect_timeout=args.telnet_connect_timeout,
                prompt_timeout=args.telnet_prompt_timeout,
                debug_dumper=debug_dumper,
                debug_label="preflight_telnet_connect",
            )
        else:
            connector = getattr(session, "ensure_telnet_connected", None)
            if callable(connector):
                connector()
            tn = session
    except TelnetOutputLimitExceeded as exc:
        return (
            False,
            CheckLines(
                [TELNET_OUTPUT_LIMIT_CODE],
                transport=telnet_output_limit_details(exc),
            ),
            False,
        )
    except (RuntimeError, OSError) as exc:
        return False, [str(exc)], False

    try:
        date_result = run_cmd_result(
            tn,
            "date '+%F %T %z'",
            timeout=15,
            debug_dumper=debug_dumper,
            debug_name="preflight_telnet_date",
        )
        log_result = run_cmd_result(
            tn,
            "ls -1 /var/log/app.log /var/log/framework.log 2>/dev/null",
            timeout=15,
            debug_dumper=debug_dumper,
            debug_name="preflight_telnet_logs",
        )
        lines = preview_lines(date_result.stdout, limit=1) + preview_lines(
            log_result.stdout, limit=4
        )
        transport_ok = date_result.ok
        log_files_ok = log_result.ok and bool(log_result.stdout.strip())
        if not transport_ok:
            reason = (
                "telnet command timed out"
                if date_result.timed_out
                else "telnet connection closed before command completion"
            )
            return False, lines or [reason], False
        return True, lines or ["telnet connected"], log_files_ok
    except TelnetOutputLimitExceeded as exc:
        return (
            False,
            CheckLines(
                [TELNET_OUTPUT_LIMIT_CODE],
                transport=telnet_output_limit_details(exc),
            ),
            False,
        )
    finally:
        close_telnet(tn)


def check_telnet_time(
    args: argparse.Namespace,
    telnet: dict[str, str | int],
    debug_dumper=None,
    *,
    session=None,
) -> tuple[bool, list[str]]:
    """Refresh only the target clock on an existing Telnet lane."""

    try:
        if session is None:
            tn = telnet_connect(
                args.ip,
                int(telnet["port"]),
                str(telnet["user"]),
                str(telnet["password"]),
                connect_timeout=args.telnet_connect_timeout,
                prompt_timeout=args.telnet_prompt_timeout,
                debug_dumper=debug_dumper,
                debug_label="preflight_telnet_refresh_connect",
            )
        else:
            connector = getattr(session, "ensure_telnet_connected", None)
            if callable(connector):
                connector()
            tn = session
    except TelnetOutputLimitExceeded as exc:
        return False, CheckLines(
            [TELNET_OUTPUT_LIMIT_CODE],
            transport=telnet_output_limit_details(exc),
        )
    except (RuntimeError, OSError) as exc:
        return False, [str(exc)]

    try:
        result = run_cmd_result(
            tn,
            "date '+%F %T %z'",
            timeout=15,
            debug_dumper=debug_dumper,
            debug_name="preflight_telnet_refresh_date",
        )
        lines = preview_lines(result.stdout, limit=1)
        if result.ok:
            return True, lines or ["telnet connected"]
        reason = (
            "telnet command timed out"
            if result.timed_out
            else "telnet connection closed before command completion"
        )
        return False, lines or [reason]
    except TelnetOutputLimitExceeded as exc:
        return False, CheckLines(
            [TELNET_OUTPUT_LIMIT_CODE],
            transport=telnet_output_limit_details(exc),
        )
    finally:
        close_telnet(tn)
