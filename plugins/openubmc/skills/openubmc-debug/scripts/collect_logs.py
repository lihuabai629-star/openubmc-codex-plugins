#!/usr/bin/env python3
"""Collect openUBMC logs over telnet, with optional login handling."""
from __future__ import annotations

import argparse
import json
import posixpath
import re
import shlex
import sys
from pathlib import Path
from _cli_common import resolve_telnet_credentials
from _debug_dump import build_debug_dumper
from _json_common import build_json_payload as build_common_json_payload
TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
LOG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
UTC_OFFSET_RE = re.compile(r"^([+-])(\d{2})(\d{2})$")
NUMBERED_LOG_LINE_RE = re.compile(r"^([1-9][0-9]*):(.*)$")
LOG_PATH_UNSAFE_RETURN_CODE = 77
LOG_PATH_UNSAFE_CODE = "log_path_unsafe"
LOG_PATH_UNSAFE_MARKER = "__OPENUBMC_LOG_PATH_UNSAFE__"
LOG_FILE_NOT_FOUND_RETURN_CODE = 78
LOG_FILE_NOT_FOUND_CODE = "log_file_not_found"
LOG_FILE_NOT_FOUND_MARKER = "__OPENUBMC_LOG_FILE_NOT_FOUND__"
LOG_FILE_UNREADABLE_RETURN_CODE = 79
LOG_FILE_UNREADABLE_CODE = "log_file_unreadable"
LOG_FILE_UNREADABLE_MARKER = "__OPENUBMC_LOG_FILE_UNREADABLE__"
MAX_LOG_NAME_BYTES = 128
MAX_KEYWORD_BYTES = 128
MAX_KEYWORDS = 200
MAX_LOG_ERROR_CHARS = 2000
DEFAULT_LOG_MAX_BYTES = 256 * 1024
HARD_MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_ROTATED_LIMIT = 32
ROTATION_DISCOVERY_MAX_CANDIDATES = MAX_ROTATED_LIMIT + 1
ROTATION_DISCOVERY_MAX_BYTES = 16 * 1024
CONTENT_TRUNCATED_WARNING = "content_truncated_at_max_bytes"
ROTATION_DISCOVERY_TRUNCATED_WARNING = "rotation_discovery_truncated"

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


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect app/framework logs via telnet.")
    parser.add_argument("--ip", required=True, help="BMC IP")
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
    parser.add_argument("--command-timeout", type=int, default=30, help="Per-command Telnet timeout seconds")
    parser.add_argument(
        "--logs",
        default="app.log,framework.log",
        help="Comma-separated log filenames under /var/log (default: app.log,framework.log)",
    )
    parser.add_argument("--lines", type=int, default=2000, help="Tail N lines per file")
    parser.add_argument("--include-rotated", action="store_true", help="Include .gz rotated logs")
    parser.add_argument(
        "--rotated-limit",
        type=int,
        default=3,
        help=(
            "Max rotated files per log when --include-rotated "
            f"(default: 3; hard max: {MAX_ROTATED_LIMIT})"
        ),
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_LOG_MAX_BYTES,
        help=(
            "Maximum bytes returned per selected log "
            f"(default: {DEFAULT_LOG_MAX_BYTES}; hard max: {HARD_MAX_LOG_BYTES})"
        ),
    )
    parser.add_argument("--since-boot", action="store_true", help="Filter lines since last boot")
    parser.add_argument(
        "--grep",
        default="",
        help="Comma-separated keywords; only keep lines containing any keyword (case-insensitive)",
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help="Optional directory to write output files; stdout otherwise",
    )
    parser.add_argument("--debug-dump", default="", help="Optional directory for raw Telnet debug artifacts")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of text output")
    parser.add_argument("--compact-json", action="store_true", help="With --json, omit duplicated legacy top-level fields")
    return parser.parse_args(argv)

def get_boot_time_str(tn, command_timeout: int = 30) -> str | None:
    now_result = run_cmd_result(tn, "date +%s", timeout=command_timeout)
    uptime_result = run_cmd_result(
        tn,
        "cut -d' ' -f1 /proc/uptime",
        timeout=command_timeout,
    )
    if not now_result.ok or not uptime_result.ok:
        return None
    now_raw = now_result.stdout
    uptime_raw = uptime_result.stdout
    try:
        now = int(now_raw.strip().splitlines()[-1])
        uptime = float(uptime_raw.strip().splitlines()[-1])
    except Exception:
        return None
    boot_epoch = now - int(uptime)
    boot_result = run_cmd_result(
        tn,
        f"date -d @{boot_epoch} '+%Y-%m-%d %H:%M:%S'",
        timeout=command_timeout,
    )
    if not boot_result.ok:
        return None
    boot_str = boot_result.stdout
    boot_str = boot_str.strip().splitlines()[-1] if boot_str.strip() else ""
    if not re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$", boot_str):
        return None
    return boot_str


def parse_utc_offset_minutes(raw: str) -> int | None:
    line = raw.strip().splitlines()[-1] if raw.strip() else ""
    match = UTC_OFFSET_RE.fullmatch(line)
    if not match:
        return None
    hours = int(match.group(2))
    minutes = int(match.group(3))
    if hours > 14 or minutes > 59 or (hours == 14 and minutes != 0):
        return None
    total = hours * 60 + minutes
    return -total if match.group(1) == "-" else total


def get_utc_offset_minutes(tn, command_timeout: int = 30) -> int | None:
    result = run_cmd_result(tn, "date +%z", timeout=command_timeout)
    if not result.ok:
        return None
    return parse_utc_offset_minutes(result.stdout)


def bound_content_bytes(content: bytes, max_bytes: int) -> tuple[bytes, int, bool]:
    truncated = len(content) > max_bytes
    bounded = content[:max_bytes]
    return bounded, len(bounded), truncated


def build_log_discovery_cmd(base: str, rotated_limit: int) -> str:
    """Build a remotely bounded current/rotation discovery command."""

    if rotated_limit < 1 or rotated_limit > MAX_ROTATED_LIMIT:
        raise ValueError("rotated-limit is outside the supported range")
    current_path = f"/var/log/{base}"
    quoted_current = shlex.quote(current_path)
    pattern = quoted_current + "*"
    candidate_limit = min(
        rotated_limit + 1,
        ROTATION_DISCOVERY_MAX_CANDIDATES,
    )
    probe_bytes = ROTATION_DISCOVERY_MAX_BYTES + 1
    inner = (
        "set +o pipefail 2>/dev/null || true; "
        f"p={quoted_current}; "
        "{ [ -e \"$p\" ] && printf '%s\\n' \"$p\"; "
        f"ls -1t {pattern} 2>/dev/null | "
        "awk -v p=\"$p\" '$0 != p' | "
        f"head -n {rotated_limit}; "
        f"}} | head -n {candidate_limit} | head -c {probe_bytes}"
    )
    return "sh -lc " + shlex.quote(inner)


def list_log_files(
    tn,
    base: str,
    include_rotated: bool,
    rotated_limit: int,
    command_timeout: int = 30,
    warnings: list[str] | None = None,
) -> list[str]:
    if include_rotated:
        ls_result = run_cmd_result(
            tn,
            build_log_discovery_cmd(base, rotated_limit),
            timeout=command_timeout,
        )
        if not ls_result.ok:
            return [f"/var/log/{base}"]
        bounded, _bytes_returned, bytes_truncated = bound_content_bytes(
            ls_result.raw,
            ROTATION_DISCOVERY_MAX_BYTES,
        )
        if bytes_truncated:
            if warnings is not None:
                _append_warning(warnings, ROTATION_DISCOVERY_TRUNCATED_WARNING)
            return [f"/var/log/{base}"]
        ls_out = bounded.decode("utf-8", errors="replace")
        files = [line.strip() for line in ls_out.splitlines() if line.strip()]
        candidate_limit = min(
            rotated_limit + 1,
            ROTATION_DISCOVERY_MAX_CANDIDATES,
        )
        if len(files) > candidate_limit:
            if warnings is not None:
                _append_warning(warnings, ROTATION_DISCOVERY_TRUNCATED_WARNING)
            files = files[:candidate_limit]
        current_path = f"/var/log/{base}"
        current = [p for p in files if p == current_path]
        rotated = [p for p in files if p != current_path]
        rotated = rotated[:rotated_limit]
        return current + rotated or [f"/var/log/{base}"]
    return [f"/var/log/{base}"]


def tail_file_cmd(path: str, lines: int) -> str:
    quoted_path = shlex.quote(path)
    if path.endswith(".gz"):
        return f"zcat {quoted_path} | tail -n {lines}"
    return f"tail -n {lines} {quoted_path}"


def normalize_absolute_remote_path(path: str) -> str:
    if not path or "\\" in path or re.search(r"[\x00-\x1f\x7f]", path):
        return ""
    raw_path = path.strip()
    if not raw_path.startswith("/"):
        return ""
    components = [component for component in raw_path.split("/") if component]
    if not components or any(component in {".", ".."} for component in components):
        return ""
    return posixpath.normpath(raw_path)


def normalize_log_candidate_path(path: str, base: str = "") -> str:
    normalized = normalize_absolute_remote_path(path)
    if posixpath.dirname(normalized) != "/var/log":
        return ""
    if base:
        basename = posixpath.basename(normalized)
        if basename != base:
            if not basename.startswith(base):
                return ""
            suffix = basename[len(base) :]
            if not suffix or suffix[0] not in ".-_":
                return ""
    return normalized


def remote_path_prefixes(path: str) -> list[str]:
    normalized = normalize_absolute_remote_path(path)
    if not normalized:
        raise ValueError("log path must be absolute and canonical")
    prefixes: list[str] = []
    current = ""
    for component in normalized.split("/"):
        if not component:
            continue
        current += f"/{component}"
        prefixes.append(current)
    return prefixes


def validate_log_names(logs: list[str]) -> list[str]:
    for name in logs:
        if (
            not LOG_NAME_RE.fullmatch(name)
            or ".." in name
            or len(name.encode("utf-8")) > MAX_LOG_NAME_BYTES
        ):
            raise SystemExit(
                f"invalid log filename {name!r}; use a basename under /var/log"
            )
    return logs


def build_log_read_cmd(
    path: str,
    lines: int,
    since_boot: str | None,
    keywords: list[str],
    *,
    number_lines: bool = False,
    max_bytes: int = DEFAULT_LOG_MAX_BYTES,
) -> str:
    if max_bytes < 1 or max_bytes > HARD_MAX_LOG_BYTES:
        raise ValueError("log max-bytes is outside the supported range")
    prefixes = remote_path_prefixes(path)
    normalized_path = prefixes[-1]
    quoted_path = shlex.quote(normalized_path)
    source = 'zcat "$p"' if normalized_path.endswith(".gz") else 'cat "$p"'
    if not (since_boot or keywords):
        pipeline_text = f"{source} | tail -n {lines}"
    else:
        pipeline = [source]
        if since_boot:
            pipeline.append(
                "awk -v cutoff="
                + shlex.quote(since_boot)
                + " 'substr($0, 1, 19) >= cutoff'"
            )
        if keywords:
            grep_args = " ".join(
                f"-e {shlex.quote(keyword)}" for keyword in keywords
            )
            line_flag = "-n " if number_lines else ""
            pipeline.append(f"grep {line_flag}-iF {grep_args}")
        pipeline.append(f"tail -n {lines}")
        pipeline_text = " | ".join(pipeline)
    pipeline_text += f" | head -c {max_bytes + 1}"
    quoted_parents = " ".join(shlex.quote(prefix) for prefix in prefixes[:-1])
    parent_guard = (
        f"for d in {quoted_parents}; do "
        f"[ -L \"$d\" ] && f {LOG_PATH_UNSAFE_RETURN_CODE} \"$u\"; "
        f"[ -e \"$d\" ] || f {LOG_FILE_NOT_FOUND_RETURN_CODE} \"$n\"; "
        f"[ -d \"$d\" ] || f {LOG_PATH_UNSAFE_RETURN_CODE} \"$u\"; "
        f"[ -x \"$d\" ] || f {LOG_FILE_UNREADABLE_RETURN_CODE} \"$r\"; "
        "done; "
        if quoted_parents
        else ""
    )
    return "sh -lc " + shlex.quote(
        "set -o pipefail 2>/dev/null || true; "
        f"u={shlex.quote(LOG_PATH_UNSAFE_MARKER)}; "
        f"n={shlex.quote(LOG_FILE_NOT_FOUND_MARKER)}; "
        f"r={shlex.quote(LOG_FILE_UNREADABLE_MARKER)}; "
        "f(){ printf '%s\\n' \"$2\"; exit \"$1\"; }; "
        f"{parent_guard}"
        f"p={quoted_path}; "
        f"[ -L \"$p\" ] && f {LOG_PATH_UNSAFE_RETURN_CODE} \"$u\"; "
        f"[ -e \"$p\" ] || f {LOG_FILE_NOT_FOUND_RETURN_CODE} \"$n\"; "
        f"[ -f \"$p\" ] || f {LOG_PATH_UNSAFE_RETURN_CODE} \"$u\"; "
        f"[ -r \"$p\" ] || f {LOG_FILE_UNREADABLE_RETURN_CODE} \"$r\"; "
        f"{pipeline_text}; x=$?; "
        "[ \"$x\" -eq 141 ] && x=0; exit \"$x\""
    )


def keyword_batches_for_log(
    path: str,
    lines: int,
    since_boot: str | None,
    keywords: list[str],
    *,
    max_bytes: int = DEFAULT_LOG_MAX_BYTES,
) -> list[list[str]]:
    """Keep each framed Telnet command below the interactive line boundary."""

    if not keywords:
        command = build_log_read_cmd(
            path,
            lines,
            since_boot,
            [],
            max_bytes=max_bytes,
        )
        if framed_command_size(command) > MAX_TELNET_INPUT_BYTES:
            raise ValueError("telnet_command_too_long")
        return [[]]

    batches: list[list[str]] = []
    current: list[str] = []
    for keyword in keywords:
        candidate = [*current, keyword]
        command = build_log_read_cmd(
            path,
            lines,
            since_boot,
            candidate,
            number_lines=True,
            max_bytes=max_bytes,
        )
        if framed_command_size(command) <= MAX_TELNET_INPUT_BYTES:
            current = candidate
            continue
        if not current:
            raise ValueError("telnet_command_too_long")
        batches.append(current)
        current = [keyword]
        command = build_log_read_cmd(
            path,
            lines,
            since_boot,
            current,
            number_lines=True,
            max_bytes=max_bytes,
        )
        if framed_command_size(command) > MAX_TELNET_INPUT_BYTES:
            raise ValueError("telnet_command_too_long")
    if current:
        batches.append(current)
    return batches


def parse_single_log_batch_records(
    content: str,
    lines: int,
    *,
    truncated: bool,
) -> list[tuple[int | None, str]]:
    """Preserve physical line numbers while tolerating legacy unnumbered output."""

    raw_lines = [line for line in content.splitlines() if line.strip()]
    if not raw_lines:
        return []
    first_match = NUMBERED_LOG_LINE_RE.fullmatch(raw_lines[0])
    if first_match is None:
        return [(None, line) for line in raw_lines[-lines:]]

    parsed: list[tuple[int | None, str]] = []
    for index, raw_line in enumerate(raw_lines):
        match = NUMBERED_LOG_LINE_RE.fullmatch(raw_line)
        if match is None:
            if truncated and index == len(raw_lines) - 1:
                break
            raise ValueError("numbered log output was malformed")
        parsed.append((int(match.group(1)), match.group(2)))
    return parsed[-lines:]


def parse_single_log_batch(content: str, lines: int, *, truncated: bool) -> list[str]:
    """Strip grep line numbers while tolerating one legacy unnumbered batch."""

    return [
        line
        for _line_number, line in parse_single_log_batch_records(
            content, lines, truncated=truncated
        )
    ]


def merge_numbered_log_batch_records(
    batch_contents: list[str],
    lines: int,
    *,
    truncated: bool = False,
) -> list[tuple[int, str]]:
    """Merge grep batches by physical line number without collapsing repeats."""

    records: dict[int, str] = {}
    for batch_index, content in enumerate(batch_contents):
        raw_lines = content.splitlines()
        for line_index, raw_line in enumerate(raw_lines):
            if not raw_line.strip():
                continue
            match = NUMBERED_LOG_LINE_RE.fullmatch(raw_line)
            if not match:
                if (
                    truncated
                    and batch_index == len(batch_contents) - 1
                    and line_index == len(raw_lines) - 1
                ):
                    break
                raise ValueError("numbered log output was malformed")
            line_number = int(match.group(1))
            line = match.group(2)
            previous = records.get(line_number)
            if previous is not None and previous != line:
                raise ValueError("numbered log output conflicted across batches")
            records[line_number] = line
    return [
        (line_number, records[line_number]) for line_number in sorted(records)
    ][-lines:]


def merge_numbered_log_batches(
    batch_contents: list[str],
    lines: int,
    *,
    truncated: bool = False,
) -> list[str]:
    return [
        line
        for _line_number, line in merge_numbered_log_batch_records(
            batch_contents, lines, truncated=truncated
        )
    ]


def filter_lines(lines: list[str], since_boot: str | None, keywords: list[str]) -> list[str]:
    result: list[str] = []
    for line in lines:
        keep = True
        if since_boot:
            m = TS_RE.match(line)
            if m:
                ts = m.group(1)
                if ts < since_boot:
                    keep = False
        if keep and keywords:
            low = line.lower()
            if not any(k in low for k in keywords):
                keep = False
        if keep:
            result.append(line)
    return result


def build_empty_message(path: str, since_boot: str | None, keywords: list[str]) -> str:
    reasons: list[str] = []
    if keywords:
        reasons.append(f"grep={','.join(keywords)}")
    if since_boot:
        reasons.append(f"since_boot>={since_boot}")
    suffix = f" after filters ({'; '.join(reasons)})" if reasons else ""
    return f"[INFO] 0 matching lines for {path}{suffix}"


def build_truncated_message(path: str, max_bytes: int) -> str:
    return (
        f"[WARN] Evidence for {path} reached the {max_bytes}-byte limit; "
        "absence is not established"
    )


def classify_log_read_failure(content: str) -> str | None:
    """Recognize shell diagnostics emitted by tail/zcat instead of log content."""
    for line in content.splitlines():
        normalized = line.strip().lower()
        if not normalized.startswith(("tail:", "cat:", "zcat:", "gzip:")):
            continue
        if "no such file" in normalized or "can't open" in normalized:
            return "log_file_not_found"
        if "permission denied" in normalized:
            return "log_file_unreadable"
        return "log_read_failed"
    return None


def classify_log_command_failure(returncode: int | None, content: str) -> str | None:
    explicit_codes = {
        LOG_PATH_UNSAFE_RETURN_CODE: LOG_PATH_UNSAFE_CODE,
        LOG_FILE_NOT_FOUND_RETURN_CODE: LOG_FILE_NOT_FOUND_CODE,
        LOG_FILE_UNREADABLE_RETURN_CODE: LOG_FILE_UNREADABLE_CODE,
    }
    if returncode in explicit_codes:
        return explicit_codes[returncode]
    if returncode not in {0, 1}:
        return classify_log_read_failure(content) or "log_read_failed"
    return classify_log_read_failure(content)


def log_failure_message(code: str, content: str) -> str:
    stable_messages = {
        LOG_PATH_UNSAFE_CODE: "log path is symbolic, non-regular, or otherwise unsafe",
        LOG_FILE_NOT_FOUND_CODE: "log file was not found",
        LOG_FILE_UNREADABLE_CODE: "log file is not readable",
        "telnet_command_too_long": "Telnet command exceeds the safe input-line limit",
        "telnet_command_timeout": "Telnet log command timed out before framing completed",
        "telnet_connection_closed": "Telnet connection closed before log command framing completed",
    }
    if code in stable_messages:
        return stable_messages[code]
    detail = content.strip() or "log read failed"
    if len(detail) > MAX_LOG_ERROR_CHARS:
        detail = detail[: MAX_LOG_ERROR_CHARS - 3] + "..."
    return detail


def _append_warning(warnings: list[str], warning: str) -> None:
    if warning not in warnings:
        warnings.append(warning)


def build_json_payload(
    args: argparse.Namespace,
    *,
    ok: bool,
    code: str,
    returncode: int,
    logs: list[str],
    keywords: list[str],
    boot_time: str | None,
    utc_offset_minutes: int | None,
    warnings: list[str],
    entries: list[dict[str, object]],
    error: str = "",
    written_files: list[str] | None = None,
) -> dict[str, object]:
    payload = build_common_json_payload(
        tool="collect_logs",
        ip=args.ip,
        ok=ok,
        code=code,
        returncode=returncode,
        warnings=warnings,
        error=error,
        request={
            "logs_requested": logs,
            "keywords": keywords,
            "since_boot_requested": args.since_boot,
            "lines": args.lines,
            "max_bytes": args.max_bytes,
            "include_rotated": args.include_rotated,
            "rotated_limit": args.rotated_limit,
            "command_timeout": args.command_timeout,
            "output_dir": args.output_dir or "",
        },
        result={
            "boot_time": boot_time,
            "utc_offset_minutes": utc_offset_minutes,
            "since_boot_applied": bool(args.since_boot and boot_time),
            "entries": entries,
            "written_files": written_files or [],
        },
    )
    if not args.compact_json:
        payload.update({
            "ip": args.ip,
            "ok": ok,
            "code": code,
            "returncode": returncode,
            "logs_requested": logs,
            "keywords": keywords,
            "since_boot_requested": args.since_boot,
            "boot_time": boot_time,
            "utc_offset_minutes": utc_offset_minutes,
            "warnings": warnings,
            "entries": entries,
            "error": error,
            "output_dir": args.output_dir or "",
            "command_timeout": args.command_timeout,
            "max_bytes": args.max_bytes,
            "written_files": written_files or [],
        })

    payload["redacted"] = False
    result = payload.get("result")
    if isinstance(result, dict):
        result["redacted"] = False
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
    if args.lines < 1:
        raise SystemExit("--lines must be positive")
    if args.rotated_limit < 1:
        raise SystemExit("--rotated-limit must be positive")
    if args.rotated_limit > MAX_ROTATED_LIMIT:
        raise SystemExit(
            f"--rotated-limit must be at most {MAX_ROTATED_LIMIT}"
        )
    if args.max_bytes < 1:
        raise SystemExit("--max-bytes must be positive")
    if args.max_bytes > HARD_MAX_LOG_BYTES:
        raise SystemExit(f"--max-bytes must be at most {HARD_MAX_LOG_BYTES}")
    if (
        args.connect_timeout < 1
        or args.prompt_timeout < 1
        or args.command_timeout < 1
    ):
        raise SystemExit("Telnet timeouts must be positive")
    if args.telnet_port < 1 or args.telnet_port > 65535:
        raise SystemExit("--telnet-port must be between 1 and 65535")
    logs = validate_log_names(
        [item.strip() for item in args.logs.split(",") if item.strip()]
    )
    if not logs:
        raise SystemExit("--logs must name at least one log file")
    keywords = [k.strip().lower() for k in args.grep.split(",") if k.strip()]
    if len(keywords) > MAX_KEYWORDS:
        raise SystemExit(f"--grep accepts at most {MAX_KEYWORDS} keywords")
    if any(len(keyword.encode("utf-8")) > MAX_KEYWORD_BYTES for keyword in keywords):
        raise SystemExit(
            f"each --grep keyword must be at most {MAX_KEYWORD_BYTES} bytes"
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
            collector_name="collect-logs",
            operation={
                "logs": list(logs),
                "lines": args.lines,
                "include_rotated": args.include_rotated,
                "rotated_limit": args.rotated_limit,
                "max_bytes": args.max_bytes,
                "since_boot": args.since_boot,
                "keywords": list(keywords),
            },
            credential_loader=lambda: resolve_telnet_credentials(args),
            collect=collect_with_runtime,
        )
    telnet = _telnet or resolve_telnet_credentials(args)
    debug_dumper = build_debug_dumper(args.debug_dump, secrets=[str(telnet["password"])])
    out_dir = Path(args.output_dir) if args.output_dir else None
    warnings: list[str] = []
    entries: list[dict[str, object]] = []
    written_files: list[str] = []
    read_failures: list[tuple[str, str, str]] = []
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        out_dir.chmod(0o700)

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
                debug_label="collect_logs_connect",
            )
        else:
            if runtime_lease is not None:
                runtime_lease.bind_debug_context(
                    debug_dumper,
                    "collect_logs_connect",
                )
                runtime_lease.connect()
            tn = _session
    except (RuntimeError, OSError) as exc:
        output_limited = isinstance(exc, TelnetOutputLimitExceeded)
        code = TELNET_OUTPUT_LIMIT_CODE if output_limited else "telnet_connect_failed"
        returncode = TELNET_OUTPUT_LIMIT_RETURN_CODE if output_limited else 2
        raw_error = (
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
                    logs=logs,
                    keywords=keywords,
                    boot_time=None,
                    utc_offset_minutes=None,
                    warnings=[],
                    entries=[],
                    error=raw_error,
                )
            )
            return returncode
        print(f"[ERROR] {raw_error}", file=sys.stderr)
        return returncode
    boot_str: str | None = None
    utc_offset_minutes: int | None = None
    try:
        utc_offset_minutes = get_utc_offset_minutes(tn, args.command_timeout)
        if utc_offset_minutes is None:
            warnings.append("utc_offset_unavailable")
        boot_str = (
            get_boot_time_str(tn, args.command_timeout)
            if args.since_boot
            else None
        )
        if args.since_boot and not boot_str:
            warnings.append("since_boot_unavailable")
            if not args.json:
                print("[WARN] Cannot compute boot time; --since-boot ignored", file=sys.stderr)
        for base in logs:
            files = list_log_files(
                tn,
                base,
                args.include_rotated,
                args.rotated_limit,
                args.command_timeout,
                warnings,
            )
            for path in files:
                normalized_path = normalize_log_candidate_path(path, base)
                reported_path = normalized_path or "***"
                bytes_returned = 0
                truncated = False
                content_complete = False
                line_numbers: list[int | None] = []
                if not normalized_path:
                    content = "log path rejected by local safety policy"
                    failure_code = LOG_PATH_UNSAFE_CODE
                else:
                    try:
                        keyword_batches = keyword_batches_for_log(
                            normalized_path,
                            args.lines,
                            boot_str,
                            keywords,
                            max_bytes=args.max_bytes,
                        )
                    except ValueError:
                        content = "Telnet command exceeds the safe input-line limit"
                        failure_code = "telnet_command_too_long"
                    else:
                        batch_contents: list[str] = []
                        failure_code = None
                        content = ""
                        for batch_index, keyword_batch in enumerate(keyword_batches):
                            remaining_bytes = args.max_bytes - bytes_returned
                            if remaining_bytes < 1:
                                truncated = True
                                break
                            cmd = build_log_read_cmd(
                                normalized_path,
                                args.lines,
                                boot_str,
                                keyword_batch,
                                number_lines=bool(keywords),
                                max_bytes=remaining_bytes,
                            )
                            command_result = run_cmd_result(
                                tn,
                                cmd,
                                timeout=args.command_timeout,
                                debug_dumper=debug_dumper,
                                debug_name=(
                                    f"log_{Path(normalized_path).name}"
                                    f"_batch_{batch_index}"
                                ),
                            )
                            if not command_result.framing_complete:
                                failure_code = (
                                    "telnet_connection_closed"
                                    if command_result.connection_closed
                                    else "telnet_command_timeout"
                                )
                                break
                            raw_probe = command_result.raw
                            probe_text = raw_probe.decode(
                                "utf-8",
                                errors="replace",
                            )
                            failure_code = classify_log_command_failure(
                                command_result.returncode,
                                probe_text,
                            )
                            if failure_code:
                                content = probe_text
                                break
                            bounded_raw, batch_bytes, batch_truncated = (
                                bound_content_bytes(raw_probe, remaining_bytes)
                            )
                            bytes_returned += batch_bytes
                            batch_contents.append(
                                bounded_raw.decode("utf-8", errors="replace")
                            )
                            if batch_truncated:
                                truncated = True
                                break
                            if (
                                bytes_returned >= args.max_bytes
                                and batch_index < len(keyword_batches) - 1
                            ):
                                truncated = True
                                break
                        if not failure_code:
                            try:
                                if keywords and len(keyword_batches) == 1:
                                    merged_records = parse_single_log_batch_records(
                                        batch_contents[0] if batch_contents else "",
                                        args.lines,
                                        truncated=truncated,
                                    )
                                elif keywords:
                                    merged_records = merge_numbered_log_batch_records(
                                        batch_contents,
                                        args.lines,
                                        truncated=truncated,
                                    )
                                else:
                                    merged_records = [
                                        (None, line)
                                        for line in "\n".join(batch_contents).splitlines()
                                        if line.strip()
                                    ][-args.lines :]
                            except ValueError as exc:
                                failure_code = "log_read_failed"
                                content = str(exc)
                            else:
                                line_numbers = [
                                    line_number for line_number, _line in merged_records
                                ]
                                merged_lines = [line for _line_number, line in merged_records]
                                content = "\n".join(merged_lines)
                                content_complete = not truncated
                raw_error = (
                    log_failure_message(failure_code, content)
                    if failure_code
                    else ""
                )
                raw_lines = (
                    []
                    if failure_code
                    else [line for line in content.splitlines() if line.strip()]
                )
                filtered_lines: list[str] = []
                filtered_line_numbers: list[int | None] = []
                for index, line in enumerate(raw_lines):
                    if filter_lines([line], boot_str, keywords):
                        filtered_lines.append(line)
                        filtered_line_numbers.append(
                            line_numbers[index] if index < len(line_numbers) else None
                        )
                raw_lines = filtered_lines
                line_numbers = filtered_line_numbers
                header = f"# {reported_path}"
                raw_empty_message = (
                    ""
                    if raw_lines or failure_code
                    else (
                        build_truncated_message(reported_path, args.max_bytes)
                        if truncated
                        else build_empty_message(reported_path, boot_str, keywords)
                    )
                )
                lines = "\n".join(raw_lines).splitlines()
                error = raw_error
                empty_message = raw_empty_message
                entry_warnings: list[str] = []
                if truncated:
                    _append_warning(warnings, CONTENT_TRUNCATED_WARNING)
                    _append_warning(entry_warnings, CONTENT_TRUNCATED_WARNING)
                body = "\n".join(lines) if lines else empty_message
                if failure_code:
                    read_failures.append((reported_path, failure_code, error))
                    body = f"[ERROR] {error}"
                entries.append(
                    {
                        "path": reported_path,
                        "header": header,
                        "ok": failure_code is None,
                        "code": failure_code or "ok",
                        "error": error,
                        "line_count": len(lines),
                        "lines": lines,
                        "line_numbers": line_numbers,
                        "empty": not bool(lines),
                        "empty_message": empty_message,
                        "bytes_returned": bytes_returned,
                        "truncated": truncated,
                        "content_complete": content_complete,
                        "warnings": entry_warnings,
                        "redacted": False,
                    }
                )
                if out_dir:
                    safe_name = (
                        reported_path.replace("/", "_").strip("_")
                        if normalized_path
                        else f"blocked_log_path_{len(entries)}"
                    ) + ".txt"
                    out_path = out_dir / safe_name
                    warning_lines = "".join(
                        f"# warning: {warning}\n"
                        for warning in entry_warnings
                    )
                    out_path.write_text(
                        header + "\n" + warning_lines + body + "\n",
                        encoding="utf-8",
                    )
                    out_path.chmod(0o600)
                    written_files.append(str(out_path))
                else:
                    if not args.json:
                        print(header)
                        for warning in entry_warnings:
                            print(f"[WARN] {warning}")
                        print(body)
                        print("")
    except TelnetOutputLimitExceeded:
        error = "Telnet output exceeded the configured byte limit"
        if args.json:
            emit_json_payload(
                build_json_payload(
                    args,
                    ok=False,
                    code=TELNET_OUTPUT_LIMIT_CODE,
                    returncode=TELNET_OUTPUT_LIMIT_RETURN_CODE,
                    logs=logs,
                    keywords=keywords,
                    boot_time=boot_str,
                    utc_offset_minutes=utc_offset_minutes,
                    warnings=warnings,
                    entries=entries,
                    error=error,
                    written_files=written_files,
                )
            )
        else:
            print(f"[ERROR] {error}", file=sys.stderr)
        return TELNET_OUTPUT_LIMIT_RETURN_CODE
    finally:
        close_telnet(tn)
    overall_ok = not read_failures
    overall_code = read_failures[0][1] if read_failures else "ok"
    overall_error = (
        "; ".join(f"{path}: {error}" for path, _, error in read_failures)
        if read_failures
        else ""
    )
    if args.json:
        emit_json_payload(
            build_json_payload(
                args,
                ok=overall_ok,
                code=overall_code,
                returncode=0 if overall_ok else 3,
                logs=logs,
                keywords=keywords,
                boot_time=boot_str,
                utc_offset_minutes=utc_offset_minutes,
                warnings=warnings,
                entries=entries,
                error=overall_error,
                written_files=written_files,
            )
        )
    return 0 if overall_ok else 3


if __name__ == "__main__":
    raise SystemExit(main())
