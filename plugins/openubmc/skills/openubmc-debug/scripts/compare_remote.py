#!/usr/bin/env python3
"""Compare two or more openUBMC targets while preserving every target result."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse

from _cli_common import add_context_runtime_arguments


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect and compare two or more typed openUBMC Debug results."
    )
    parser.add_argument("--reference-ip", default="")
    parser.add_argument("--candidate-ip", action="append", default=[])
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--target-id", action="append", default=[])
    parser.add_argument("--keyword", default="")
    parser.add_argument("--mdb-query", action="append", dest="mdb_queries", default=[])
    parser.add_argument(
        "--mdb-expand-class",
        action="append",
        dest="mdb_expand_classes",
        default=[],
    )
    parser.add_argument("--mdb-concurrency", default="auto")
    parser.add_argument("--mdb-only", action="store_true")
    parser.add_argument("--logs", default="app.log,framework.log")
    parser.add_argument("--lines", type=int, default=200)
    parser.add_argument("--include-rotated", action="store_true")
    parser.add_argument("--rotated-limit", type=int, default=3)
    parser.add_argument("--log-max-bytes", type=int, default=262144)
    parser.add_argument("--file", action="append", dest="files", default=[])
    parser.add_argument("--tree-service", default="")
    parser.add_argument("--tree-head", type=int, default=20)
    parser.add_argument("--alarm-service", default="")
    parser.add_argument("--alarm-path", default="")
    parser.add_argument("--alarm-discovery-service-limit", type=int, default=16)
    parser.add_argument("--alarm-discovery-path-limit", type=int, default=64)
    parser.add_argument("--alarm-limit", type=int, default=100)
    parser.add_argument("--alarm-call-signature", default="")
    parser.add_argument("--alarm-call-arg", action="append", default=[])
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--deadline", type=int, default=600)
    parser.add_argument("--concurrency", default="auto")
    parser.add_argument("--source-root", default="")
    parser.add_argument("--source-max-matches", type=int, default=40)
    parser.add_argument("--correlate-alarm-limit", type=int, default=20)
    parser.add_argument("--correlation-time-window", type=int, default=300)
    parser.add_argument("--skip-telnet", action="store_true")
    parser.add_argument("--no-freshness", action="store_true")
    parser.add_argument("--no-source-correlation", action="store_true")
    parser.add_argument("--ssh-user", default="")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--ssh-user-env", default="")
    parser.add_argument("--ssh-password-env", default="")
    parser.add_argument("--ssh-password", default="")
    parser.add_argument("--ssh-identity-file", default="")
    parser.add_argument("--telnet-user", default="")
    parser.add_argument("--telnet-port", type=int, default=23)
    parser.add_argument("--telnet-user-env", default="")
    parser.add_argument("--telnet-password-env", default="")
    parser.add_argument("--telnet-password", default="")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--compact-json",
        action="store_true",
        help="Keep per-target workflow evidence compact in JSON output",
    )
    add_context_runtime_arguments(parser)
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def _targets(args: argparse.Namespace) -> list[dict[str, object]]:
    explicit = bool(args.reference_ip or args.candidate_ip)
    symmetric = bool(args.target)
    if explicit and symmetric:
        raise SystemExit(
            "use reference/candidate inputs or two symmetric --target values, not both"
        )
    if explicit:
        if not args.reference_ip or not args.candidate_ip:
            raise SystemExit(
                "--reference-ip requires at least one --candidate-ip"
            )
        targets = [{"ip": args.reference_ip, "role": "reference"}]
        targets.extend(
            {"ip": candidate, "role": "candidate"}
            for candidate in args.candidate_ip
        )
    else:
        if len(args.target) < 2:
            raise SystemExit("symmetric comparison requires at least two --target values")
        targets = [{"ip": value} for value in args.target]
    if args.target_id:
        if len(args.target_id) != len(targets):
            raise SystemExit("--target-id count must match the target count")
        for target, target_id in zip(targets, args.target_id):
            target["target_id"] = target_id
    return targets


def build_request(args: argparse.Namespace) -> dict[str, object]:
    if args.deadline < 1 or args.timeout < 1:
        raise SystemExit("--deadline and --timeout must be positive")
    return {
        "targets": _targets(args),
        "keyword": args.keyword,
        "mdb_queries": list(args.mdb_queries),
        "mdb_expand_classes": list(args.mdb_expand_classes),
        "mdb_concurrency": args.mdb_concurrency,
        "mdb_only": args.mdb_only,
        "logs": args.logs,
        "lines": args.lines,
        "include_rotated": args.include_rotated,
        "rotated_limit": args.rotated_limit,
        "log_max_bytes": args.log_max_bytes,
        "files": list(args.files),
        "tree_service": args.tree_service,
        "tree_head": args.tree_head,
        "alarm_service": args.alarm_service,
        "alarm_path": args.alarm_path,
        "alarm_discovery_service_limit": args.alarm_discovery_service_limit,
        "alarm_discovery_path_limit": args.alarm_discovery_path_limit,
        "alarm_limit": args.alarm_limit,
        "alarm_call_signature": args.alarm_call_signature,
        "alarm_call_args": list(args.alarm_call_arg),
        "timeout": args.timeout,
        "deadline": args.deadline,
        "concurrency": args.concurrency,
        "source_root": args.source_root,
        "source_max_matches": args.source_max_matches,
        "correlate_alarm_limit": args.correlate_alarm_limit,
        "correlation_time_window": args.correlation_time_window,
        "skip_telnet": args.skip_telnet,
        "no_freshness": args.no_freshness,
        "no_source_correlation": args.no_source_correlation,
        "ssh_user": args.ssh_user,
        "ssh_port": args.ssh_port,
        "ssh_user_env": args.ssh_user_env,
        "ssh_password_env": args.ssh_password_env,
        "ssh_identity_file": args.ssh_identity_file,
        "telnet_user": args.telnet_user,
        "telnet_port": args.telnet_port,
        "telnet_user_env": args.telnet_user_env,
        "telnet_password_env": args.telnet_password_env,
        "compact_json": args.compact_json,
    }


def main(argv: list[str] | None = None) -> int:
    """Enter the shared Context Runtime while preserving comparison inputs."""

    import target_runtime_cli

    return target_runtime_cli.run_compare_legacy(argv)


if __name__ == "__main__":
    raise SystemExit(main())
