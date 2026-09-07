#!/usr/bin/env python3
"""Run a bmcgo command and fail if the log contains known failure signals."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path


DEFAULT_FAILURE_PATTERNS = [
    r"\b(ERROR|CRITICAL|FATAL)\b",
    r"\berror:",
    r"Traceback \(most recent call last\)",
    r"\bFAILED\b",
    r"(执行失败|构建失败|任务失败|任务\s+\S+\s+执行失败)",
    r"(ConanException|BmcGoException|No package matching|Missing prebuilt package)",
]

DEFAULT_IGNORE_PATTERNS = [
    r"\b0 failed\b",
    r"\bfailed:\s*0\b",
    r"\b0 FAILED\b",
    r"\bFailed validating\b",
]


def compile_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
    return [re.compile(pattern) for pattern in patterns]


def is_failure_line(line: str, patterns: list[re.Pattern[str]], ignore_patterns: list[re.Pattern[str]]) -> bool:
    ignored_spans = [match.span() for pattern in ignore_patterns for match in pattern.finditer(line)]
    return any(
        not any(start <= match.start() and match.end() <= end for start, end in ignored_spans)
        for pattern in patterns
        for match in pattern.finditer(line)
    )


def matched_failures(lines: list[str], patterns: list[re.Pattern[str]], ignore_patterns: list[re.Pattern[str]]) -> list[str]:
    matches = []
    for index, line in enumerate(lines, start=1):
        if is_failure_line(line, patterns, ignore_patterns):
            matches.append(f"{index}: {line.rstrip()}")
    return matches


def default_log_path() -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path("/tmp") / f"bmcgo-checked-{stamp}.log"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run bmcgo and scan the combined stdout/stderr log")
    parser.add_argument("--cwd", help="working directory for the command")
    parser.add_argument("--log", help="log file path; default is /tmp/bmcgo-checked-<timestamp>.log")
    parser.add_argument("--pattern", action="append", default=[], help="extra failure regex; repeatable")
    parser.add_argument("--ignore", action="append", default=[], help="extra ignore regex; repeatable")
    parser.add_argument("--no-default-patterns", action="store_true", help="use only --pattern regexes")
    parser.add_argument("cmd", nargs=argparse.REMAINDER, help="command after --, e.g. -- bmcgo build ...")
    args = parser.parse_args()

    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("provide command after --")

    log_path = Path(args.log) if args.log else default_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    failure_patterns = [] if args.no_default_patterns else list(DEFAULT_FAILURE_PATTERNS)
    failure_patterns.extend(args.pattern)
    patterns = compile_patterns(failure_patterns)
    ignore_patterns = compile_patterns([*DEFAULT_IGNORE_PATTERNS, *args.ignore])

    print(f"[bmcgo-check] cwd: {args.cwd or Path.cwd()}", flush=True)
    print(f"[bmcgo-check] log: {log_path}", flush=True)
    print(f"[bmcgo-check] cmd: {' '.join(cmd)}", flush=True)

    lines: list[str] = []
    with log_path.open("w", encoding="utf-8", errors="replace", newline="") as log:
        proc = subprocess.Popen(  # noqa: S603 - command is explicitly supplied by the caller.
            cmd,
            cwd=args.cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            lines.append(line)
            sys.stdout.write(line)
            sys.stdout.flush()
            log.write(line)
        rc = proc.wait()

    matches = matched_failures(lines, patterns, ignore_patterns)
    if rc != 0:
        print(f"[bmcgo-check] command exit code: {rc}", file=sys.stderr)
    if matches:
        print("[bmcgo-check] failure-looking log lines:", file=sys.stderr)
        for line in matches[-80:]:
            print(line, file=sys.stderr)
    return rc or (1 if matches else 0)


if __name__ == "__main__":
    raise SystemExit(main())
