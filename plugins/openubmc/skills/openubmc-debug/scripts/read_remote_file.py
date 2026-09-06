#!/usr/bin/env python3
"""Read a live BMC file over telnet with safe, bounded selectors."""
from __future__ import annotations

import argparse
import json
import os
import posixpath
import re
import shlex
import sys

from _cli_common import resolve_telnet_credentials
from _debug_dump import build_debug_dumper
from _json_common import build_json_payload as build_common_json_payload
from _telnet_common import (
    MAX_TELNET_INPUT_BYTES,
    TELNET_OUTPUT_LIMIT_CODE,
    TELNET_OUTPUT_LIMIT_RETURN_CODE,
    TelnetOutputLimitExceeded,
    close_telnet,
    framed_command_size,
    run_cmd_result,
    telnet_connect,
)
from _target_runtime_adapter import (
    run_typed_telnet_one_shot,
)

RC_MARKER = "__OPENUBMC_READ_RC__="
ERR_MARKER = "__OPENUBMC_READ_ERR__="
CONTENT_TRUNCATED_WARNING = "content_truncated_at_max_bytes"

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read a live BMC file over telnet.")
    parser.add_argument("--ip", required=True, help="BMC IP")
    parser.add_argument("--path", required=True, help="Remote file path to read")
    parser.add_argument(
        "--port",
        "--telnet-port",
        dest="telnet_port",
        type=int,
        default=23,
        help="Telnet port (default: 23)",
    )
    parser.add_argument(
        "--user",
        "--telnet-user",
        dest="telnet_user",
        default="",
        help="Telnet username when login prompt appears (or OPENUBMC_TELNET_USER)",
    )
    parser.add_argument(
        "--user-env",
        "--telnet-user-env",
        dest="telnet_user_env",
        default="",
        help="Environment variable holding the Telnet username",
    )
    parser.add_argument(
        "--password-env",
        "--telnet-password-env",
        dest="telnet_password_env",
        default="",
        help="Environment variable holding the Telnet password",
    )
    parser.add_argument("--password", "--telnet-password", dest="telnet_password", default="")
    parser.add_argument("--connect-timeout", type=int, default=10, help="Telnet connect timeout seconds")
    parser.add_argument("--prompt-timeout", type=int, default=5, help="Telnet prompt/login timeout seconds")
    parser.add_argument("--command-timeout", type=int, default=30, help="Telnet command timeout seconds")
    parser.add_argument(
        "--grep",
        default="",
        help="Comma-separated keywords; only keep matching lines (case-insensitive)",
    )
    parser.add_argument("--tail", type=int, default=0, help="Tail N lines after optional grep")
    parser.add_argument("--head", type=int, default=0, help="Head N lines after optional grep")
    parser.add_argument("--sed-range", default="", help="Inclusive line range START:END, for example 1:80")
    parser.add_argument("--decompress", action="store_true", help="Use zcat; defaults on automatically for .gz paths")
    parser.add_argument("--debug-dump", default="", help="Optional directory for raw Telnet debug artifacts")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=1024 * 1024,
        help="Maximum bytes returned by the remote pipeline (default: 1 MiB)",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of text output")
    parser.add_argument("--compact-json", action="store_true", help="With --json, omit duplicated legacy top-level fields")
    return parser.parse_args(argv)


def parse_sed_range(raw: str) -> tuple[int, int] | None:
    if not raw:
        return None
    match = re.fullmatch(r"(\d+):(\d+)", raw.strip())
    if not match:
        raise SystemExit("--sed-range must use START:END, for example 1:80")
    start = int(match.group(1))
    end = int(match.group(2))
    if start < 1 or end < start:
        raise SystemExit("--sed-range must be a positive inclusive range")
    return start, end


def normalize_keywords(raw: str) -> list[str]:
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def normalize_remote_path(path: str) -> str:
    raw_path = path.strip()
    if (
        not raw_path
        or not raw_path.startswith("/")
        or any(ord(character) < 32 or ord(character) == 127 for character in raw_path)
    ):
        raise ValueError(
            "remote path must be an absolute POSIX path without control characters"
        )
    normalized = posixpath.normpath(raw_path)
    if normalized == "/":
        raise ValueError("remote path must identify a file below /")
    return normalized


def remote_path_prefixes(path: str) -> list[str]:
    normalized = normalize_remote_path(path)
    if not normalized:
        raise ValueError("remote path must be an allowed absolute path")
    prefixes: list[str] = []
    current = ""
    for component in normalized.split("/"):
        if not component:
            continue
        current += f"/{component}"
        prefixes.append(current)
    return prefixes


def build_pipeline_command(
    path: str,
    *,
    decompress: bool,
    grep_keywords: list[str],
    tail: int,
    head: int,
    sed_range: tuple[int, int] | None,
    max_bytes: int = 1024 * 1024,
) -> str:
    quoted_path = shlex.quote(path)
    probe_bytes = max_bytes + 1
    if sed_range is not None:
        start, end = sed_range
        if decompress:
            command = f"zcat {quoted_path} | sed -n '{start},{end}p'"
        else:
            command = f"sed -n '{start},{end}p' {quoted_path}"
        return f"{command} | head -c {probe_bytes}"

    command = f"zcat {quoted_path}" if decompress else f"cat {quoted_path}"
    if grep_keywords:
        pattern = "|".join(re.escape(keyword) for keyword in grep_keywords)
        command += f" | grep -i -E {shlex.quote(pattern)}"
    if tail > 0:
        command += f" | tail -n {tail}"
    elif head > 0:
        command += f" | head -n {head}"
    return f"{command} | head -c {probe_bytes}"


def build_remote_command(path: str, pipeline_command: str) -> str:
    prefixes = remote_path_prefixes(path)
    quoted_path = shlex.quote(prefixes[-1])
    symlink_checks = " || ".join(
        f"[ -L {shlex.quote(prefix)} ]" for prefix in prefixes
    )
    inner = (
        "set -o pipefail 2>/dev/null || true; "
        f"if {symlink_checks} || [ ! -f {quoted_path} ]; then "
        f"printf '{ERR_MARKER}%s\\n' {quoted_path}; "
        "rc=3; "
        f"else {pipeline_command}; rc=$?; "
        "if [ \"$rc\" -eq 141 ]; then rc=0; fi; fi; "
        f"printf '\\n{RC_MARKER}%s\\n' \"$rc\""
    )
    return f"sh -lc {shlex.quote(inner)}"


def parse_command_output_bytes(data: bytes) -> tuple[int, str, bytes]:
    rc_marker = RC_MARKER.encode("ascii")
    trailer = re.search(
        rb"(?:^|\r?\n)"
        + re.escape(rc_marker)
        + rb"([0-9]{1,3})(?:\r?\n)?$",
        data,
    )
    if trailer is None:
        return 125, "", data

    return_code = int(trailer.group(1))
    if return_code > 255:
        return 125, "", data

    content = data[: trailer.start()]
    error_path = ""
    if return_code == 3:
        error_marker = ERR_MARKER.encode("ascii")
        error_match = re.fullmatch(
            re.escape(error_marker) + rb"([^\r\n]*)\r?\n?",
            content,
        )
        if error_match is not None:
            error_path = error_match.group(1).decode("utf-8", errors="replace").strip()
            content = b""
    return return_code, error_path, content


def parse_command_output_text(text: str) -> tuple[int, str, str]:
    return_code, error_path, content = parse_command_output_bytes(
        text.encode("utf-8")
    )
    return return_code, error_path, content.decode("utf-8", errors="replace")


def parse_command_output(text: str) -> tuple[int, str, list[str]]:
    return_code, error_path, content = parse_command_output_text(text)
    lines = [line for line in content.splitlines() if line.strip()]
    return return_code, error_path, lines


def bound_content_bytes(content: bytes, max_bytes: int) -> tuple[bytes, int, bool]:
    truncated = len(content) > max_bytes
    bounded = content[:max_bytes]
    return bounded, len(bounded), truncated


def bound_content(content: str, max_bytes: int) -> tuple[str, int, bool]:
    bounded, bytes_returned, truncated = bound_content_bytes(
        content.encode("utf-8"), max_bytes
    )
    return bounded.decode("utf-8", errors="replace"), bytes_returned, truncated


def build_empty_message(
    path: str,
    grep_keywords: list[str],
    tail: int,
    head: int,
    sed_range: tuple[int, int] | None,
) -> str:
    reasons: list[str] = []
    if grep_keywords:
        reasons.append(f"grep={','.join(grep_keywords)}")
    if tail > 0:
        reasons.append(f"tail={tail}")
    if head > 0:
        reasons.append(f"head={head}")
    if sed_range is not None:
        reasons.append(f"sed_range={sed_range[0]}:{sed_range[1]}")
    suffix = f" after filters ({'; '.join(reasons)})" if reasons else ""
    return f"[INFO] 0 matching lines for {path}{suffix}"


def build_json_payload(
    args: argparse.Namespace,
    *,
    ok: bool,
    code: str,
    returncode: int,
    grep_keywords: list[str],
    sed_range: tuple[int, int] | None,
    command: str,
    lines: list[str],
    empty_message: str,
    warnings: list[str],
    error: str = "",
    reported_path: str | None = None,
    bytes_returned: int = 0,
    truncated: bool = False,
    content_complete: bool = False,
) -> dict[str, object]:
    safe_path = args.path if reported_path is None else reported_path
    payload = build_common_json_payload(
        tool="read_remote_file",
        ip=args.ip,
        ok=ok,
        code=code,
        returncode=returncode,
        warnings=warnings,
        error=error,
        request={
            "path": safe_path,
            "grep_keywords": grep_keywords,
            "tail": args.tail,
            "head": args.head,
            "sed_range": f"{sed_range[0]}:{sed_range[1]}" if sed_range else "",
            "decompress_requested": args.decompress,
            "max_bytes": args.max_bytes,
            "command_timeout": args.command_timeout,
        },
        result={
            "path": safe_path,
            "command": command,
            "line_count": len(lines),
            "lines": lines,
            "empty": not bool(lines),
            "empty_message": empty_message,
            "bytes_returned": bytes_returned,
            "truncated": truncated,
            "content_complete": content_complete,
        },
    )
    if args.compact_json:
        return payload
    payload.update(
        {
            "ip": args.ip,
            "ok": ok,
            "code": code,
            "returncode": returncode,
            "path": safe_path,
            "grep_keywords": grep_keywords,
            "tail": args.tail,
            "head": args.head,
            "sed_range": f"{sed_range[0]}:{sed_range[1]}" if sed_range else "",
            "decompress_requested": args.decompress,
            "command_timeout": args.command_timeout,
            "lines": lines,
            "empty_message": empty_message,
            "bytes_returned": bytes_returned,
            "truncated": truncated,
            "content_complete": content_complete,
        }
    )
    return payload


def emit_json_payload(payload: dict[str, object]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def main(
    *,
    runtime_lease=None,
    _args: argparse.Namespace | None = None,
    _telnet: dict[str, str | int] | None = None,
    _session=None,
) -> int:
    args = _args or parse_args()
    grep_keywords = normalize_keywords(args.grep)
    sed_range = parse_sed_range(args.sed_range)
    if args.tail > 0 and args.head > 0:
        raise SystemExit("--tail and --head cannot be used together")
    if args.tail < 0 or args.head < 0:
        raise SystemExit("--tail and --head must be non-negative")
    if args.max_bytes < 1:
        raise SystemExit("--max-bytes must be positive")
    if (
        args.connect_timeout < 1
        or args.prompt_timeout < 1
        or args.command_timeout < 1
    ):
        raise SystemExit("Telnet timeouts must be positive")
    if sed_range is not None and (args.tail > 0 or args.head > 0):
        raise SystemExit("--sed-range cannot be combined with --tail or --head")
    if sed_range is not None and grep_keywords:
        raise SystemExit("--sed-range cannot be combined with --grep")

    try:
        args.path = normalize_remote_path(args.path)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    decompress = args.decompress or args.path.endswith(".gz")
    pipeline_command = build_pipeline_command(
        args.path,
        decompress=decompress,
        grep_keywords=grep_keywords,
        tail=args.tail,
        head=args.head,
        sed_range=sed_range,
        max_bytes=args.max_bytes,
    )
    remote_command = build_remote_command(args.path, pipeline_command)
    if framed_command_size(remote_command) > MAX_TELNET_INPUT_BYTES:
        raise SystemExit(
            "Remote file command exceeds the Telnet input-line limit; "
            "use a shorter path or narrower selector"
        )

    if _session is None:
        def collect_with_runtime(telnet, lease):
            return main(
                runtime_lease=lease,
                _args=args,
                _telnet=dict(telnet),
                _session=lease.session_proxy,
            )

        return run_typed_telnet_one_shot(
            args=args,
            collector_name="read-remote-file",
            operation={
                "path": args.path,
                "grep_keywords": list(grep_keywords),
                "tail": args.tail,
                "head": args.head,
                "sed_range": list(sed_range) if sed_range else [],
                "decompress": decompress,
                "max_bytes": args.max_bytes,
            },
            credential_loader=lambda: resolve_telnet_credentials(args),
            collect=collect_with_runtime,
        )
    telnet = _telnet or resolve_telnet_credentials(args)
    debug_dumper = build_debug_dumper(args.debug_dump, secrets=[str(telnet["password"])])
    try:
        if _session is None:
            tn = telnet_connect(
                args.ip,
                int(telnet["port"]),
                str(telnet["user"]),
                str(telnet["password"]),
                connect_timeout=args.connect_timeout,
                prompt_timeout=args.prompt_timeout,
                debug_dumper=debug_dumper,
                debug_label="read_remote_file_connect",
            )
        else:
            if runtime_lease is not None:
                runtime_lease.bind_debug_context(
                    debug_dumper,
                    "read_remote_file_connect",
                )
                runtime_lease.connect()
            tn = _session
    except (RuntimeError, OSError) as exc:
        output_limited = isinstance(exc, TelnetOutputLimitExceeded)
        code = TELNET_OUTPUT_LIMIT_CODE if output_limited else "telnet_connect_failed"
        returncode = TELNET_OUTPUT_LIMIT_RETURN_CODE if output_limited else 2
        error = (
            "Telnet output exceeded the configured byte limit"
            if output_limited
            else str(exc)
        )
        if args.json:
            emit_json_payload(
                build_json_payload(
                    args,
                    ok=False,
                    code=code,
                    returncode=returncode,
                    grep_keywords=grep_keywords,
                    sed_range=sed_range,
                    command=pipeline_command,
                    lines=[],
                    empty_message="",
                    warnings=[],
                    error=error,
                )
            )
            return returncode
        print(f"[ERROR] {error}", file=sys.stderr)
        return returncode

    try:
        try:
            command_result = run_cmd_result(
                tn,
                remote_command,
                timeout=args.command_timeout,
                debug_dumper=debug_dumper,
                debug_name=f"file_{args.path.rsplit('/', 1)[-1] or 'root'}",
            )
        except TelnetOutputLimitExceeded:
            error = "Telnet output exceeded the configured byte limit"
            if args.json:
                emit_json_payload(
                    build_json_payload(
                        args,
                        ok=False,
                        code=TELNET_OUTPUT_LIMIT_CODE,
                        returncode=TELNET_OUTPUT_LIMIT_RETURN_CODE,
                        grep_keywords=grep_keywords,
                        sed_range=sed_range,
                        command=pipeline_command,
                        lines=[],
                        empty_message="",
                        warnings=[],
                        error=error,
                    )
                )
            else:
                print(f"[ERROR] {error}", file=sys.stderr)
            return TELNET_OUTPUT_LIMIT_RETURN_CODE
    finally:
        close_telnet(tn)

    if not command_result.framing_complete:
        code = (
            "telnet_connection_closed"
            if command_result.connection_closed
            else "telnet_command_timeout"
        )
        error = "Telnet command did not complete its framing contract"
        if args.json:
            emit_json_payload(
                build_json_payload(
                    args,
                    ok=False,
                    code=code,
                    returncode=4,
                    grep_keywords=grep_keywords,
                    sed_range=sed_range,
                    command=pipeline_command,
                    lines=[],
                    empty_message="",
                    warnings=[],
                    error=error,
                )
            )
            return 4
        print(f"[ERROR] {error}", file=sys.stderr)
        return 4

    return_code, error_path, content_bytes = parse_command_output_bytes(
        command_result.raw
    )
    content_bytes, bytes_returned, truncated = bound_content_bytes(
        content_bytes, args.max_bytes
    )
    content = content_bytes.decode("utf-8", errors="replace")
    lines = [line for line in content.splitlines() if line.strip()]
    if grep_keywords and return_code == 1 and not lines and not error_path:
        return_code = 0
    empty_message = build_empty_message(args.path, grep_keywords, args.tail, args.head, sed_range) if not lines else ""
    warnings: list[str] = []
    if args.path.startswith("/var/log/"):
        warnings.append("Prefer collect_logs.py for app.log/framework.log or rotated /var/log triage.")
    if truncated:
        warnings.append(CONTENT_TRUNCATED_WARNING)
        if not args.json:
            print(f"[WARN] {CONTENT_TRUNCATED_WARNING}", file=sys.stderr)

    if return_code != 0:
        protocol_error = return_code == 125
        error = (
            "Remote command completed without the required return-code marker"
            if protocol_error
            else f"Cannot read {error_path or args.path} over Telnet"
        )
        if args.json:
            emit_json_payload(
                build_json_payload(
                    args,
                    ok=False,
                    code=(
                        "invalid_telnet_command_output"
                        if protocol_error
                        else "remote_file_unreadable"
                    ),
                    returncode=1,
                    grep_keywords=grep_keywords,
                    sed_range=sed_range,
                    command=pipeline_command,
                    lines=lines,
                    empty_message=empty_message,
                    warnings=warnings,
                    error=error,
                    bytes_returned=bytes_returned,
                    truncated=truncated,
                    content_complete=False,
                )
            )
            return 1
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1

    if args.json:
        emit_json_payload(
            build_json_payload(
                args,
                ok=True,
                code="ok",
                returncode=0,
                grep_keywords=grep_keywords,
                sed_range=sed_range,
                command=pipeline_command,
                lines=lines,
                empty_message=empty_message,
                warnings=warnings,
                bytes_returned=bytes_returned,
                truncated=truncated,
                content_complete=not truncated,
            )
        )
        return 0

    print(f"# {args.path}")
    if lines:
        print("\n".join(lines))
    else:
        print(empty_message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
