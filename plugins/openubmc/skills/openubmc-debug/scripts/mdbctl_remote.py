#!/usr/bin/env python3
"""Run mdbctl commands on openUBMC over SSH with environment-aware fallbacks."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
from dataclasses import dataclass
import json
import os
import re
import shlex
import sys
import subprocess

from _cli_common import resolve_ssh_credentials
from _debug_dump import build_debug_dumper
from _json_common import build_json_payload as build_common_json_payload
from _remote_common import (
    SSH_CAPTURE_ERROR_CODE,
    SSH_CAPTURE_ERROR_RETURN_CODE,
    SSH_CLIENT_MISSING_CODE,
    SSH_CLIENT_MISSING_RETURN_CODE,
    SSH_HOST_KEY_FAILURE_CODE,
    SSH_HOST_KEY_POLICY_ERROR_CODE,
    SSH_HOST_KEY_POLICY_ERROR_RETURN_CODE,
    SSH_OUTPUT_LIMIT_CODE,
    SSH_OUTPUT_LIMIT_RETURN_CODE,
    build_posix_shell_command,
    run_ssh,
    sanitize_remote_text,
    ssh_transport_details,
    ssh_transport_failure_code,
    ssh_transport_failure_message,
)
from _target_runtime_adapter import _load_runtime_module, run_typed_mdb_one_shot

CLASS_EXIT_CODES = {
    "remote-command-failed": 10,
    "empty-output": 11,
    "command-not-found": 12,
    "service-unknown": 13,
    "timeout": 14,
    "unknown": 15,
    "object-not-found": 16,
    "write-operation-blocked": 17,
    "remote-command-unsupported": 20,
    SSH_OUTPUT_LIMIT_CODE: SSH_OUTPUT_LIMIT_RETURN_CODE,
    SSH_CAPTURE_ERROR_CODE: SSH_CAPTURE_ERROR_RETURN_CODE,
    SSH_CLIENT_MISSING_CODE: SSH_CLIENT_MISSING_RETURN_CODE,
    SSH_HOST_KEY_FAILURE_CODE: 19,
    SSH_HOST_KEY_POLICY_ERROR_CODE: SSH_HOST_KEY_POLICY_ERROR_RETURN_CODE,
}
MDBCTL_STDOUT_LIMIT_BYTES = 8 * 1024 * 1024
MDBCTL_STDERR_LIMIT_BYTES = 64 * 1024
FAILURE_PRIORITY = {
    SSH_CLIENT_MISSING_CODE: 150,
    SSH_HOST_KEY_POLICY_ERROR_CODE: 145,
    SSH_HOST_KEY_FAILURE_CODE: 140,
    SSH_CAPTURE_ERROR_CODE: 120,
    SSH_OUTPUT_LIMIT_CODE: 110,
    "timeout": 100,
    "remote-command-failed": 90,
    "remote-command-unsupported": 85,
    "service-unknown": 80,
    "object-not-found": 70,
    "command-not-found": 60,
    "empty-output": 10,
    "unknown": 0,
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run mdbctl remotely with login-shell/skynet fallbacks.")
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
        "--mode",
        choices=["auto", "login-shell", "direct-skynet"],
        default="auto",
        help="Execution mode (default: auto)",
    )
    parser.add_argument("--timeout", type=int, default=60, help="SSH timeout seconds")
    parser.add_argument(
        "--print-classification",
        action="store_true",
        help="Print the final failure classification to stderr when the command does not succeed",
    )
    parser.add_argument("--debug-dump", default="", help="Optional directory for raw SSH debug artifacts")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of text output")
    parser.add_argument("--compact-json", action="store_true", help="With --json, omit duplicated legacy top-level fields")
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="mdbctl command, e.g. lsclass or lsobj DiscreteSensor",
    )
    return parser.parse_args(argv)


def normalize_command(parts: list[str]) -> list[str]:
    if parts and parts[0] == "--":
        parts = parts[1:]
    return parts or ["lsclass"]


def is_read_only_command(parts: list[str]) -> bool:
    return bool(_load_runtime_module().is_read_only_mdb_query(parts))


def build_login_shell_cmd(parts: list[str]) -> str:
    if not is_read_only_command(parts):
        raise ValueError("command does not match the reviewed read-only grammar")
    mdbctl_cmd = " ".join(shlex.quote(p) for p in (["mdbctl"] + parts))
    return build_posix_shell_command(mdbctl_cmd, load_profile=True)


def build_direct_skynet_cmd(parts: list[str]) -> str:
    if not is_read_only_command(parts):
        raise ValueError("command does not match the reviewed read-only grammar")
    line = " ".join(parts)
    return (
        f"printf '%s\\n' {shlex.quote(line)} | "
        "/opt/bmc/skynet/lua /opt/bmc/apps/mdbctl/service/mdbctl.lua"
    )


def classify_failure(cp: subprocess.CompletedProcess[str], stdout: str, stderr: str) -> str:
    transport_code = ssh_transport_failure_code(cp)
    if transport_code:
        return transport_code
    combined = f"{stdout}\n{stderr}".lower()
    if "timed out" in combined or cp.returncode == 124:
        return "timeout"
    if "command not found" in combined:
        return "command-not-found"
    if any(
        line.strip() == "command not supported"
        for line in combined.splitlines()
    ):
        return "remote-command-unsupported"
    if "serviceunknown" in combined or "not provided by any .service files" in combined:
        return "service-unknown"
    if (
        "object does not exist" in combined
        or "object not found" in combined
        or "unknownobject" in combined
    ):
        return "object-not-found"
    if any(line.strip().lower().startswith("failed:") for line in combined.splitlines()):
        return "remote-command-failed"
    if cp.returncode != 0:
        return "remote-command-failed"
    if not stdout.strip():
        return "empty-output"
    return "unknown"


def is_success(
    cp: subprocess.CompletedProcess[str],
    stdout: str,
    stderr: str,
    *,
    allow_empty: bool = False,
) -> bool:
    if cp.returncode != 0:
        return False
    if not stdout.strip() and not allow_empty:
        return False
    return classify_failure(cp, stdout, stderr) == "unknown"


def build_attempt(
    mode: str,
    classification: str,
    returncode: int,
    transport: dict[str, object] | None = None,
) -> dict[str, object]:
    attempt = {
        "mode": mode,
        "classification": classification,
        "returncode": returncode,
    }
    if transport:
        attempt["transport"] = transport
    return attempt


def select_final_failure(
    failures: list[tuple[str, subprocess.CompletedProcess[str], str, str]],
) -> tuple[str, subprocess.CompletedProcess[str], str, str] | None:
    if not failures:
        return None
    return max(failures, key=lambda item: FAILURE_PRIORITY.get(item[0], 0))


def build_json_payload(
    args: argparse.Namespace,
    command: list[str],
    *,
    ok: bool,
    code: str,
    returncode: int,
    selected_mode: str | None,
    stdout: str,
    stderr: str,
    attempts: list[dict[str, object]],
    hint: str,
    transport: dict[str, object] | None = None,
    fact: dict[str, object] | None = None,
) -> dict[str, object]:
    transport_warnings = list((transport or {}).get("warnings", []))
    payload = build_common_json_payload(
        tool="mdbctl_remote",
        ip=args.ip,
        ok=ok,
        code=code,
        returncode=returncode,
        warnings=transport_warnings,
        request={
            "requested_mode": args.mode,
            "command_parts": command,
            "read_only": is_read_only_command(command),
        },
        result={
            "selected_mode": selected_mode,
            "stdout": stdout,
            "stdout_lines": stdout.splitlines(),
            "stderr": stderr,
            "stderr_lines": stderr.splitlines(),
            "attempts": attempts,
            "hint": hint,
            "transport": transport or {},
            **({"fact": fact} if fact is not None else {}),
        },
    )
    if args.compact_json:
        return payload
    payload.update({
        "ip": args.ip,
        "ok": ok,
        "code": code,
        "returncode": returncode,
        "requested_mode": args.mode,
        "selected_mode": selected_mode,
        "command_parts": command,
        "stdout": stdout,
        "stdout_lines": stdout.splitlines(),
        "stderr": stderr,
        "stderr_lines": stderr.splitlines(),
        "attempts": attempts,
        "hint": hint,
        "transport": transport or {},
        **({"fact": fact} if fact is not None else {}),
    })
    return payload


def emit_json_payload(payload: dict[str, object]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


@dataclass(frozen=True)
class MdbExecutionResult:
    ok: bool
    code: str
    returncode: int
    selected_mode: str | None
    stdout: str
    stderr: str
    attempts: tuple[dict[str, object], ...]
    hint: str
    transport: dict[str, object]
    warning_lines: tuple[str, ...] = ()
    fact: dict[str, object] | None = None


_ABSENT_OBJECT_COMMANDS = frozenset({"lsprop", "getprop", "lsmethod"})
_ABSENT_OBJECT_RESPONSE = re.compile(
    r"(?:(?:Failed|Error):\s*)?"
    r"(?:org\.freedesktop\.DBus\.Error\.UnknownObject:\s*)?"
    r"Object (?:does not exist|not found)\.?",
    re.IGNORECASE,
)


def observed_absent_fact(
    command: list[str],
    *,
    classification: str,
    completed: subprocess.CompletedProcess[str],
    stdout: str,
    stderr: str,
) -> dict[str, object] | None:
    """Return typed absence evidence only for a bounded object read."""

    if (
        classification != "object-not-found"
        or completed.returncode not in {0, 1}
        or ssh_transport_failure_code(completed)
        or getattr(completed, "timed_out", False)
        or stderr.strip()
        or len(command) < 2
        or command[0] not in _ABSENT_OBJECT_COMMANDS
        or not is_read_only_command(command)
    ):
        return None
    if _ABSENT_OBJECT_RESPONSE.fullmatch(stdout.strip()) is None:
        return None
    return {
        "status": "observed_absent",
        "query": " ".join(command),
        "object": command[1],
        "command_parts": list(command),
    }


def execute_mdb_query(
    args: argparse.Namespace,
    command: list[str],
    ssh: dict[str, str | int],
    *,
    ssh_runner=None,
) -> MdbExecutionResult:
    """Perform the bounded MDB read without rendering the public CLI response."""

    if ssh_runner is None:
        ssh_runner = run_ssh

    debug_dumper = build_debug_dumper(
        args.debug_dump,
        secrets=[str(ssh["password"])],
    )
    attempt_specs: list[tuple[str, str]]
    if args.mode == "login-shell":
        attempt_specs = [("login-shell", build_login_shell_cmd(command))]
    elif args.mode == "direct-skynet":
        attempt_specs = [("direct-skynet", build_direct_skynet_cmd(command))]
    else:
        attempt_specs = [
            ("login-shell", build_login_shell_cmd(command)),
            ("direct-skynet", build_direct_skynet_cmd(command)),
        ]

    attempt_results: list[dict[str, object]] = []
    failures: list[tuple[str, subprocess.CompletedProcess[str], str, str]] = []
    warning_lines: list[str] = []

    for mode, remote_cmd in attempt_specs:
        cp = ssh_runner(
            args.ip,
            str(ssh["user"]),
            str(ssh["password"]),
            remote_cmd,
            args.timeout,
            port=int(ssh["port"]),
            identity_file=str(ssh["identity_file"]),
            debug_dumper=debug_dumper,
            debug_label=f"mdbctl_{mode}",
            stdout_limit_bytes=MDBCTL_STDOUT_LIMIT_BYTES,
            stderr_limit_bytes=MDBCTL_STDERR_LIMIT_BYTES,
        )
        transport = ssh_transport_details(cp)
        transport_code = ssh_transport_failure_code(cp)
        if transport_code:
            stdout = ""
            stderr = ""
        else:
            stdout = sanitize_remote_text(cp.stdout or "")
            stderr = sanitize_remote_text(cp.stderr or "")
        success = is_success(cp, stdout, stderr, allow_empty=False)
        classification = "ok" if success else classify_failure(cp, stdout, stderr)
        fact = observed_absent_fact(
            command,
            classification=classification,
            completed=cp,
            stdout=stdout,
            stderr=stderr,
        )
        if fact is not None:
            classification = "observed_absent"
        attempt_results.append(
            build_attempt(
                mode,
                classification,
                cp.returncode,
                transport if transport_code else None,
            )
        )
        if success or fact is not None:
            return MdbExecutionResult(
                ok=True,
                code=classification,
                returncode=0,
                selected_mode=mode,
                stdout=stdout,
                stderr=stderr,
                attempts=tuple(attempt_results),
                hint="",
                transport=transport,
                warning_lines=tuple(warning_lines),
                fact=fact,
            )
        failures.append((classification, cp, stdout, stderr))
        detail = (
            ssh_transport_failure_message(classification, "mdbctl")
            if transport_code
            else stderr or stdout or "no output"
        )
        warning_lines.append(
            f"[WARN] {mode} failed: classification={classification}: {detail}"
        )
        if classification in {
            SSH_CLIENT_MISSING_CODE,
            SSH_HOST_KEY_FAILURE_CODE,
            SSH_HOST_KEY_POLICY_ERROR_CODE,
        }:
            break

    selected_failure = select_final_failure(failures)
    if selected_failure is None:
        final_classification = "unknown"
        final_cp = None
        final_stdout = ""
        final_stderr = ""
    else:
        final_classification, final_cp, final_stdout, final_stderr = selected_failure
    final_transport = ssh_transport_details(final_cp) if final_cp is not None else {}

    hint = "[HINT] mdbctl remote fallback exhausted; try scripts/busctl_remote.py for service/tree/introspect checks."
    if final_classification == SSH_OUTPUT_LIMIT_CODE:
        hint = "SSH output exceeded the configured byte limit; narrow the MDB query."
    elif final_classification == SSH_CAPTURE_ERROR_CODE:
        hint = "SSH output capture failed; retry the bounded read or inspect the private debug dump."
    elif final_classification == "remote-command-unsupported":
        hint = (
            "SSH endpoint returned a management-CLI 'COMMAND NOT SUPPORTED' "
            "response; do not treat this lane as MDB/D-Bus access. Use a "
            "shell-capable SSH account or an independently available Telnet "
            "log/file lane."
        )
    elif final_classification in {
        SSH_CLIENT_MISSING_CODE,
        SSH_HOST_KEY_FAILURE_CODE,
        SSH_HOST_KEY_POLICY_ERROR_CODE,
    }:
        hint = ssh_transport_failure_message(final_classification, "mdbctl")
    return MdbExecutionResult(
        ok=False,
        code=final_classification,
        returncode=CLASS_EXIT_CODES.get(final_classification, 15),
        selected_mode=None,
        stdout=final_stdout,
        stderr=final_stderr,
        attempts=tuple(attempt_results),
        hint=hint,
        transport=final_transport,
        warning_lines=tuple(warning_lines),
    )


def emit_execution_result(
    args: argparse.Namespace,
    command: list[str],
    result: MdbExecutionResult,
) -> int:
    if args.json:
        emit_json_payload(
            build_json_payload(
                args,
                command,
                ok=result.ok,
                code=result.code,
                returncode=result.returncode,
                selected_mode=result.selected_mode,
                stdout=result.stdout,
                stderr=result.stderr,
                attempts=list(result.attempts),
                hint=result.hint,
                transport=result.transport,
                fact=result.fact,
            )
        )
        return result.returncode

    for warning in result.warning_lines:
        print(warning, file=sys.stderr)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    if result.ok:
        return 0
    if args.print_classification:
        print(f"[RESULT] classification={result.code}", file=sys.stderr)
    print(result.hint, file=sys.stderr)
    return result.returncode


def main(
    *,
    ssh_runner=None,
    _args: argparse.Namespace | None = None,
    _ssh: dict[str, str | int] | None = None,
) -> int:
    args = _args or parse_args()
    if args.ssh_port < 1 or args.ssh_port > 65535:
        raise SystemExit("--ssh-port must be between 1 and 65535")
    if args.timeout < 1:
        raise SystemExit("--timeout must be positive")
    command = normalize_command(args.command)
    read_only = is_read_only_command(command)
    if not read_only:
        message = (
            "Command does not match the reviewed read-only grammar; route remote "
            "state changes to the owning Skill with explicit authorization, "
            "target, and rollback boundaries."
        )
        if args.json:
            emit_json_payload(
                build_json_payload(
                    args,
                    command,
                    ok=False,
                    code="write-operation-blocked",
                    returncode=CLASS_EXIT_CODES["write-operation-blocked"],
                    selected_mode=None,
                    stdout="",
                    stderr=message,
                    attempts=[],
                    hint=message,
                )
            )
        else:
            print(message, file=sys.stderr)
        return CLASS_EXIT_CODES["write-operation-blocked"]

    if ssh_runner is not None or _ssh is not None:
        result = execute_mdb_query(
            args,
            command,
            _ssh or resolve_ssh_credentials(args),
            ssh_runner=ssh_runner,
        )
    else:
        result = run_typed_mdb_one_shot(
            args=args,
            command=command,
            credential_loader=lambda: resolve_ssh_credentials(args),
            collect=lambda ssh, lease: execute_mdb_query(
                args,
                command,
                dict(ssh),
                ssh_runner=lease.ssh_runner,
            ),
        )
    return emit_execution_result(args, command, result)


if __name__ == "__main__":
    raise SystemExit(main())
