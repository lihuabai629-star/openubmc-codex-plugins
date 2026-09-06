#!/usr/bin/env python3
"""Run busctl --user commands on openUBMC over SSH, auto-detecting DBUS/XDG env."""
from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from _cli_common import resolve_ssh_credentials
from _debug_dump import build_debug_dumper
from _json_common import build_json_payload as build_common_json_payload
from _remote_common import (
    build_filter_notice,
    detect_dbus_env,
    filter_text_output,
    run_ssh,
    sanitize_remote_text,
    ssh_transport_details,
    ssh_transport_failure_code,
    ssh_transport_failure_message,
)
from _target_runtime_adapter import (
    run_typed_object_alarm_one_shot,
)

BUSCTL_STDOUT_LIMIT_BYTES = 4 * 1024 * 1024
BUSCTL_STDERR_LIMIT_BYTES = 64 * 1024


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run busctl --user remotely with proper DBUS env.")
    parser.add_argument("--ip", required=True, help="BMC IP")
    parser.add_argument("--user", "--ssh-user", dest="ssh_user", default="", help="SSH user (or OPENUBMC_SSH_USER)")
    parser.add_argument("--port", "--ssh-port", dest="ssh_port", type=int, default=22, help="SSH port")
    parser.add_argument(
        "--user-env",
        "--ssh-user-env",
        dest="ssh_user_env",
        default="",
        help="Environment variable holding the SSH username",
    )
    parser.add_argument(
        "--password-env",
        "--ssh-password-env",
        dest="ssh_password_env",
        default="",
        help="Environment variable holding the SSH password",
    )
    parser.add_argument("--password", "--ssh-password", dest="ssh_password", default="")
    parser.add_argument(
        "--identity-file",
        "--ssh-identity-file",
        dest="ssh_identity_file",
        default="",
        help="SSH private key path",
    )
    parser.add_argument(
        "--action",
        choices=["list", "tree", "introspect", "get-property", "call"],
        default="list",
        help=(
            "busctl action (default: service-independent list); call requests "
            "are rejected by this generic helper"
        ),
    )
    parser.add_argument("--service", default="", help="Exact DBus service name")
    parser.add_argument(
        "--path",
        default="/",
        help="DBus object path for introspect/get-property or rejected call metadata",
    )
    parser.add_argument(
        "--interface",
        default="",
        help="Interface name for get-property or rejected call metadata",
    )
    parser.add_argument("--property", default="", help="Property name for get-property")
    parser.add_argument(
        "--method", default="", help="Method name recorded in a rejected call request"
    )
    parser.add_argument(
        "--signature", default="", help="Signature recorded in a rejected call request"
    )
    parser.add_argument(
        "--args", nargs="*", default=[], help="Arguments recorded in a rejected call request"
    )
    parser.add_argument("--dbus", default="", help="Override DBUS_SESSION_BUS_ADDRESS")
    parser.add_argument("--xdg", default="", help="Override XDG_RUNTIME_DIR")
    parser.add_argument("--timeout", type=int, default=120, help="SSH timeout seconds")
    parser.add_argument(
        "--grep",
        default="",
        help="Comma-separated keywords to keep from stdout (case-insensitive)",
    )
    limit_group = parser.add_mutually_exclusive_group()
    limit_group.add_argument("--head", type=int, default=None, help="Keep the first N stdout lines after filtering")
    limit_group.add_argument("--tail", type=int, default=None, help="Keep the last N stdout lines after filtering")
    parser.add_argument("--print-env", action="store_true", help="Only print detected DBUS/XDG env")
    parser.add_argument("--debug-dump", default="", help="Optional directory for raw SSH debug artifacts")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of text output")
    parser.add_argument("--compact-json", action="store_true", help="With --json, omit duplicated legacy top-level fields")
    parser.add_argument(
        "--structured",
        action="store_true",
        help="Legacy call-output flag retained for structured rejection; calls are disabled",
    )
    return parser.parse_args(argv)


def is_read_only_method(_method: str) -> bool:
    """A method name alone never establishes a read-only D-Bus call."""

    return False


def build_busctl_cmd(args: argparse.Namespace) -> str:
    if args.structured and args.action != "call":
        raise SystemExit("--structured currently supports --action call only")
    if args.action == "list":
        return "busctl --user --no-pager list"
    if args.action == "tree":
        if not args.service:
            raise SystemExit("tree requires --service")
        return f"busctl --user --no-pager tree {shlex.quote(args.service)}"
    if args.action == "introspect":
        if not args.service:
            raise SystemExit("introspect requires --service")
        return (
            f"busctl --user --no-pager --xml-interface introspect "
            f"{shlex.quote(args.service)} "
            f"{shlex.quote(args.path)}"
        )
    if args.action == "get-property":
        if not (args.service and args.interface and args.property):
            raise SystemExit(
                "get-property requires --service, --interface, and --property"
            )
        parts = [
            "busctl",
            "--user",
            "--no-pager",
            "get-property",
            args.service,
            args.path,
            args.interface,
            args.property,
        ]
        return " ".join(shlex.quote(part) for part in parts)
    raise SystemExit(
        "busctl_remote.py does not execute method calls; use a dedicated helper "
        "that binds live introspection to a fixed read-only request"
    )


def unwrap_string_pair(value: object) -> tuple[str, str] | None:
    current = value
    while isinstance(current, list) and len(current) == 1:
        current = current[0]
    if (
        isinstance(current, list)
        and len(current) == 2
        and all(isinstance(item, str) for item in current)
    ):
        return current[0], current[1]
    return None


def normalize_structured_busctl(stdout: str) -> dict[str, object]:
    raw = json.loads(stdout)
    result: dict[str, object] = {"type": raw.get("type", ""), "data": raw.get("data")}
    data = raw.get("data")
    if not (
        isinstance(data, list)
        and len(data) == 2
        and isinstance(data[0], int)
        and isinstance(data[1], list)
    ):
        return result

    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for item in data[1]:
        pair = unwrap_string_pair(item)
        if pair is None:
            return result
        key, value = pair
        if key in current:
            records.append(current)
            current = {}
        current[key] = value
    if current:
        records.append(current)
    if len(records) == data[0]:
        return {
            "type": raw.get("type", ""),
            "record_count": data[0],
            "records": records,
        }
    return result


def print_clean(stdout: str, stderr: str) -> None:
    clean_out = sanitize_remote_text(stdout)
    clean_err = sanitize_remote_text(stderr)
    if clean_out:
        print(clean_out)
    if clean_err:
        print(clean_err, file=sys.stderr)


def filter_stdout(stdout: str, grep_arg: str, head: int | None, tail: int | None) -> str:
    grep_keywords = [item.strip() for item in grep_arg.split(",") if item.strip()]
    if not (grep_keywords or head is not None or tail is not None):
        return stdout
    filtered = filter_text_output(stdout, grep_keywords=grep_keywords, head=head, tail=tail)
    if filtered:
        return filtered
    return build_filter_notice(grep_keywords, head, tail)


def build_json_payload(
    args: argparse.Namespace,
    *,
    ok: bool,
    code: str,
    returncode: int,
    stdout: str,
    stderr: str,
    dbus: str,
    xdg: str,
    structured: dict[str, object] | None = None,
    transport: dict[str, object] | None = None,
) -> dict[str, object]:
    transport_warnings = list((transport or {}).get("warnings", []))
    payload = build_common_json_payload(
        tool="busctl_remote",
        ip=args.ip,
        ok=ok,
        code=code,
        returncode=returncode,
        warnings=transport_warnings,
        request={
            "action": args.action,
            "service": args.service,
            "path": args.path,
            "interface": args.interface,
            "property": getattr(args, "property", ""),
            "method": args.method,
            "print_env": args.print_env,
            "grep": [item.strip() for item in args.grep.split(",") if item.strip()],
            "head": args.head,
            "tail": args.tail,
            "structured_requested": args.structured,
            "read_only": args.action != "call",
        },
        result={
            "stdout": stdout,
            "stdout_lines": stdout.splitlines(),
            "stderr": stderr,
            "stderr_lines": stderr.splitlines(),
            "dbus_env": {
                "DBUS_SESSION_BUS_ADDRESS": dbus,
                "XDG_RUNTIME_DIR": xdg,
            },
            "structured": structured,
            "transport": transport or {},
        },
    )
    if not args.compact_json:
        payload.update({
            "ip": args.ip,
            "ok": ok,
            "code": code,
            "returncode": returncode,
            "action": args.action,
            "service": args.service,
            "path": args.path,
            "interface": args.interface,
            "property": getattr(args, "property", ""),
            "method": args.method,
            "print_env": args.print_env,
            "structured": structured,
            "stdout": stdout,
            "stdout_lines": stdout.splitlines(),
            "stderr": stderr,
            "stderr_lines": stderr.splitlines(),
            "dbus_env": {
                "DBUS_SESSION_BUS_ADDRESS": dbus,
                "XDG_RUNTIME_DIR": xdg,
            },
            "transport": transport or {},
        })
    return payload


def emit_json_payload(payload: dict[str, object]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def main(
    *,
    ssh_runner=None,
    runtime_lease=None,
    _args: argparse.Namespace | None = None,
    _ssh: dict[str, str | int] | None = None,
) -> int:
    args = _args or parse_args()
    if args.ssh_port < 1 or args.ssh_port > 65535:
        raise SystemExit("--ssh-port must be between 1 and 65535")
    if args.timeout < 1:
        raise SystemExit("--timeout must be positive")
    if args.head is not None and args.head < 1:
        raise SystemExit("--head must be positive")
    if args.tail is not None and args.tail < 1:
        raise SystemExit("--tail must be positive")
    if args.structured and not args.json:
        raise SystemExit("--structured requires --json")
    if args.action == "call":
        message = (
            "busctl_remote.py rejects every method call because a method name "
            "cannot prove read-only behavior or bind a live endpoint/signature. "
            "Use active_alarms.py for current GetAlarmList evidence; route other "
            "method calls to a dedicated reviewed helper or the owning Skill."
        )
        if args.json:
            emit_json_payload(
                build_json_payload(
                    args,
                    ok=False,
                    code="write_operation_blocked",
                    returncode=4,
                    stdout="",
                    stderr=message,
                    dbus=args.dbus,
                    xdg=args.xdg,
                )
            )
        else:
            print(message, file=sys.stderr)
        return 4
    if ssh_runner is None:
        def collect_with_runtime(ssh, lease):
            return main(
                ssh_runner=lease.ssh_runner,
                runtime_lease=lease,
                _args=args,
                _ssh=dict(ssh),
            )

        return run_typed_object_alarm_one_shot(
            args=args,
            collector_name="busctl",
            operation={
                "action": args.action,
                "service": args.service,
                "path": args.path,
                "interface": args.interface,
                "property": args.property,
                "print_env": args.print_env,
            },
            credential_loader=lambda: resolve_ssh_credentials(args),
            collect=collect_with_runtime,
        )
    ssh = _ssh or resolve_ssh_credentials(args)
    debug_dumper = build_debug_dumper(args.debug_dump, secrets=[str(ssh["password"])])

    dbus = args.dbus
    xdg = args.xdg
    env_transport: dict[str, object] = {}
    if not (dbus and xdg):
        def load_env():
            return detect_dbus_env(
                args.ip,
                str(ssh["user"]),
                str(ssh["password"]),
                args.timeout,
                port=int(ssh["port"]),
                identity_file=str(ssh["identity_file"]),
                debug_dumper=debug_dumper,
                debug_label="busctl_env",
                ssh_runner=ssh_runner,
            )

        env = (
            runtime_lease.get_dbus_environment(load_env)
            if runtime_lease is not None
            else load_env()
        )
        env_transport = getattr(env, "transport", {})
        env_transport_code = str(env_transport.get("failure_code", ""))
        if env_transport_code:
            returncode = int(env_transport.get("returncode", 126))
            message = ssh_transport_failure_message(
                env_transport_code,
                "D-Bus environment detection",
            )
            if args.json:
                emit_json_payload(
                    build_json_payload(
                        args,
                        ok=False,
                        code=env_transport_code,
                        returncode=returncode,
                        stdout="",
                        stderr=message,
                        dbus="",
                        xdg="",
                        transport=env_transport,
                    )
                )
            else:
                print(message, file=sys.stderr)
            return returncode
        dbus = dbus or env.get("DBUS_SESSION_BUS_ADDRESS", "")
        xdg = xdg or env.get("XDG_RUNTIME_DIR", "")

    if args.print_env:
        stdout = f"DBUS_SESSION_BUS_ADDRESS={dbus}\nXDG_RUNTIME_DIR={xdg}".strip()
        if args.json:
            emit_json_payload(
                build_json_payload(
                    args,
                    ok=bool(dbus and xdg),
                    code="ok" if (dbus and xdg) else "dbus_env_missing",
                    returncode=0 if (dbus and xdg) else 2,
                    stdout=stdout,
                    stderr="",
                    dbus=dbus,
                    xdg=xdg,
                    transport=env_transport,
                )
            )
            return 0 if (dbus and xdg) else 2
        print_clean(stdout, "")
        return 0

    if not (dbus and xdg):
        stderr = "Failed to detect DBUS/XDG env; run interactively and pass --dbus/--xdg."
        if args.json:
            emit_json_payload(
                build_json_payload(
                    args,
                    ok=False,
                    code="dbus_env_missing",
                    returncode=2,
                    stdout="",
                    stderr=stderr,
                    dbus=dbus,
                    xdg=xdg,
                    transport=env_transport,
                )
            )
            return 2
        print(stderr, file=sys.stderr)
        return 2

    busctl_cmd = build_busctl_cmd(args)
    remote_cmd = (
        f"XDG_RUNTIME_DIR={shlex.quote(xdg)} "
        f"DBUS_SESSION_BUS_ADDRESS={shlex.quote(dbus)} "
        f"{busctl_cmd}"
    )
    cp = ssh_runner(
        args.ip,
        str(ssh["user"]),
        str(ssh["password"]),
        remote_cmd,
        args.timeout,
        tty=False,
        port=int(ssh["port"]),
        identity_file=str(ssh["identity_file"]),
        debug_dumper=debug_dumper,
        debug_label="busctl",
        stdout_limit_bytes=BUSCTL_STDOUT_LIMIT_BYTES,
        stderr_limit_bytes=BUSCTL_STDERR_LIMIT_BYTES,
    )
    transport = ssh_transport_details(cp)
    transport_code = ssh_transport_failure_code(cp)
    if transport_code:
        message = ssh_transport_failure_message(transport_code, "busctl")
        if args.json:
            emit_json_payload(
                build_json_payload(
                    args,
                    ok=False,
                    code=transport_code,
                    returncode=cp.returncode,
                    stdout="",
                    stderr=message,
                    dbus=dbus,
                    xdg=xdg,
                    transport=transport,
                )
            )
        else:
            print(message, file=sys.stderr)
        return cp.returncode
    clean_stdout = sanitize_remote_text(cp.stdout or "")
    clean_stderr = sanitize_remote_text(cp.stderr or "")
    structured: dict[str, object] | None = None
    structured_error = ""
    if args.structured and cp.returncode == 0:
        try:
            structured = normalize_structured_busctl(clean_stdout)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            structured_error = f"Cannot parse busctl JSON output: {exc}"
    filtered_stdout = (
        "" if structured is not None else filter_stdout(clean_stdout, args.grep, args.head, args.tail)
    )
    if args.json:
        effective_returncode = 3 if structured_error else cp.returncode
        emit_json_payload(
            build_json_payload(
                args,
                ok=effective_returncode == 0,
                code=(
                    "invalid_busctl_json"
                    if structured_error
                    else "ok" if cp.returncode == 0 else "remote_command_failed"
                ),
                returncode=effective_returncode,
                stdout=filtered_stdout,
                stderr=structured_error or clean_stderr,
                dbus=dbus,
                xdg=xdg,
                structured=structured,
                transport=transport,
            )
        )
        return effective_returncode
    print_clean(filtered_stdout, clean_stderr)
    return cp.returncode


if __name__ == "__main__":
    raise SystemExit(main())
