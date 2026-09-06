#!/usr/bin/env python3
"""Internal recommendation and command builders for openUBMC preflight checks."""
from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path

FAILURE_CODES = {
    "SSH": "ssh_unavailable",
    "DBUS_ENV": "dbus_env_missing",
    "MDBCTL": "mdbctl_unavailable",
    "BUSCTL": "busctl_unavailable",
    "TELNET": "telnet_unavailable",
    "LOG_FILES": "log_files_unavailable",
}
RECOMMENDED_NEXT_STEPS = {
    "ok": (
        "Continue with busctl_remote.py for object queries, collect_logs.py "
        "for log queries, or read_remote_file.py for live file reads."
    ),
    "ssh_unavailable": "Fall back to local-only analysis or verify SSH credentials/port before object queries.",
    "ssh_user_missing": "Configure OPENUBMC_SSH_USER or pass --ssh-user before object queries.",
    "ssh_password_missing": "Configure OPENUBMC_SSH_PASSWORD, pass --ssh-password-env, or use --ssh-identity-file.",
    "ssh_auth_failed": "Verify the SSH username/password or key before object queries.",
    "ssh_tcp_timeout": "Check network route, TUN/proxy rules, firewall, or whether SSH port 22 is reachable.",
    "ssh_output_limit_exceeded": "Narrow the SSH-backed object query before retrying; the transport output exceeded its safety limit.",
    "ssh_transport_capture_failed": "Retry the bounded SSH probe; local pipe capture failed before complete evidence was available.",
    "ssh_client_missing": "Route host preparation to openubmc-environment-setup; the required local ssh executable is unavailable.",
    "ssh_host_key_verification_failed": "Verify the target host key and known-hosts source before retrying; do not disable verification silently.",
    "ssh_host_key_policy_invalid": "Use one of strict, accept-new, or insecure for SSH host-key handling.",
    "remote-command-unsupported": (
        "SSH endpoint accepts connections through a management CLI but does not "
        "provide a shell; do not retry mdbctl or busctl. Use a shell-capable SSH "
        "account, an independently available Telnet log/file lane, or an offline "
        "log bundle."
    ),
    "dbus_env_missing": "Run busctl_remote.py --print-env or open an interactive SSH shell to inspect DBUS/XDG.",
    "mdbctl_unavailable": "Prefer busctl_remote.py for object queries; do not keep retrying mdbctl.",
    "busctl_unavailable": "Open an interactive SSH shell and re-check DBUS/XDG before retrying busctl.",
    "telnet_unavailable": "Request a log bundle or restore Telnet access before log collection or live file reads.",
    "telnet_output_limit_exceeded": "Narrow the Telnet-backed query or request a bounded offline artifact; the receive ceiling was exceeded.",
    "log_files_unavailable": "Telnet is usable for live files, but default app/framework logs were not found; confirm log names or request a log bundle.",
    "preflight_failed": "Inspect failed_checks and follow the first failed check's recommended_next_step.",
}
OK_NEXT_STEPS = {
    "SSH": (
        "SSH transport is reachable; use the MDBCTL and BUSCTL checks below to "
        "determine whether object queries are available."
    ),
    "DBUS_ENV": "DBUS/XDG environment is ready for busctl object queries.",
    "MDBCTL": "mdbctl is ready for class/object exploration; use busctl when exact interfaces or signatures are required.",
    "BUSCTL": "busctl is ready for list, tree, metadata-only introspection, or reviewed property reads; generic method calls remain blocked.",
    "TELNET": "Telnet is ready for collect_logs.py and read_remote_file.py.",
    "LOG_FILES": "Default app.log/framework.log files are visible over Telnet.",
}
SCRIPT_DIR = Path(__file__).resolve().parent
IDENTITY_FILE_PLACEHOLDER = "<ssh-identity-file>"


def build_script_command(script_name: str, parts: list[str]) -> str:
    return " ".join(
        [shlex.quote(sys.executable), shlex.quote(str(SCRIPT_DIR / script_name))]
        + [shlex.quote(part) for part in parts]
    )


def build_ssh_script_flags(args: argparse.Namespace) -> list[str]:
    parts: list[str] = []
    if args.ssh_port != 22:
        parts.extend(["--ssh-port", str(args.ssh_port)])
    if args.ssh_user_env:
        parts.extend(["--ssh-user-env", args.ssh_user_env])
    elif args.ssh_user:
        parts.extend(["--ssh-user", args.ssh_user])
    if args.ssh_password_env:
        parts.extend(["--ssh-password-env", args.ssh_password_env])
    if args.ssh_identity_file:
        parts.extend(["--ssh-identity-file", IDENTITY_FILE_PLACEHOLDER])
    return parts


def build_telnet_script_flags(args: argparse.Namespace) -> list[str]:
    parts: list[str] = []
    if args.telnet_port != 23:
        parts.extend(["--telnet-port", str(args.telnet_port)])
    if args.telnet_user_env:
        parts.extend(["--telnet-user-env", args.telnet_user_env])
    elif args.telnet_user:
        parts.extend(["--telnet-user", args.telnet_user])
    if args.telnet_password_env:
        parts.extend(["--telnet-password-env", args.telnet_password_env])
    return parts


def build_connectivity_command(args: argparse.Namespace) -> str:
    cmd = ["ssh", "-o", "ConnectTimeout=5"]
    if args.ssh_port != 22:
        cmd.extend(["-p", str(args.ssh_port)])
    if args.ssh_user_env:
        target = f"${{{args.ssh_user_env}}}@{args.ip}"
        return " ".join([shlex.quote(part) for part in cmd] + [target, "exit"])
    if not args.ssh_user:
        target = f"${{OPENUBMC_SSH_USER}}@{args.ip}"
        return " ".join([shlex.quote(part) for part in cmd] + [target, "exit"])
    target = f"{args.ssh_user}@{args.ip}"
    return " ".join([shlex.quote(part) for part in cmd] + [shlex.quote(target), "exit"])


def build_recommended_command(
    code: str, args: argparse.Namespace, check_name: str = ""
) -> str:
    if code == "remote-command-unsupported":
        return ""
    if code == "ok" and check_name == "TELNET":
        return build_script_command(
            "collect_logs.py",
            ["--ip", args.ip]
            + build_telnet_script_flags(args)
            + ["--logs", "app.log", "--lines", "200", "--json", "--compact-json"],
        )
    if code == "ok" and check_name == "SSH":
        return ""
    if code in {"ok", "mdbctl_unavailable"}:
        parts = ["--ip", args.ip] + build_ssh_script_flags(args)
        if args.busctl_service:
            parts += ["--action", "tree", "--service", args.busctl_service]
        else:
            parts += ["--action", "list"]
        return build_script_command("busctl_remote.py", parts)
    if code in {"dbus_env_missing", "busctl_unavailable"}:
        return build_script_command(
            "busctl_remote.py",
            ["--ip", args.ip] + build_ssh_script_flags(args) + ["--print-env"],
        )
    if code == "ssh_client_missing":
        return "openubmc-environment-setup"
    if code.startswith("ssh_"):
        return build_connectivity_command(args)
    if code == "telnet_unavailable":
        return " ".join(["telnet", shlex.quote(args.ip), shlex.quote(str(args.telnet_port))])
    if code == "log_files_unavailable":
        return build_script_command(
            "read_remote_file.py",
            ["--ip", args.ip]
            + build_telnet_script_flags(args)
            + ["--path", "/etc/version.json", "--json", "--compact-json"],
        )
    return ""


def classify_ssh_failure(lines: list[str]) -> str:
    combined = "\n".join(lines).lower()
    if "openubmc_ssh_user is not configured" in combined or "no username" in combined:
        return "ssh_user_missing"
    if "ssh_askpass" in combined:
        return "ssh_password_missing"
    if "permission denied" in combined:
        return "ssh_auth_failed"
    if "ssh_client_missing" in combined or "ssh executable is unavailable" in combined:
        return "ssh_client_missing"
    if (
        "host key verification failed" in combined
        or "remote host identification has changed" in combined
        or "ssh_host_key_verification_failed" in combined
    ):
        return "ssh_host_key_verification_failed"
    timeout_markers = ("timed out", "connection timeout", "connection timed out")
    if any(marker in combined for marker in timeout_markers):
        return "ssh_tcp_timeout"
    return "ssh_unavailable"


def build_check_result(
    name: str,
    ok: bool,
    lines: list[str],
    args: argparse.Namespace,
    env: dict[str, str] | None = None,
) -> dict[str, object]:
    specific_failure_code = str(getattr(lines, "failure_code", ""))
    transport_failure_code = next(
        (
            line
            for line in lines
            if line
            in {
                "ssh_output_limit_exceeded",
                "ssh_transport_capture_failed",
                "ssh_client_missing",
                "ssh_host_key_verification_failed",
                "ssh_host_key_policy_invalid",
                "telnet_output_limit_exceeded",
            }
        ),
        "",
    )
    if ok:
        code = "ok"
    elif transport_failure_code:
        code = transport_failure_code
    elif specific_failure_code in RECOMMENDED_NEXT_STEPS:
        code = specific_failure_code
    elif name == "SSH":
        code = classify_ssh_failure(lines)
    else:
        code = FAILURE_CODES[name]
    result: dict[str, object] = {
        "ok": ok,
        "status": "OK" if ok else "FAIL",
        "code": code,
        "lines": lines,
        "recommended_next_step": OK_NEXT_STEPS[name] if ok else RECOMMENDED_NEXT_STEPS[code],
        "recommended_command": build_recommended_command(code, args, name),
    }
    if env is not None:
        result["env"] = env
    transport = getattr(lines, "transport", {})
    if transport:
        result["transport"] = transport
    return result
