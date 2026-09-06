#!/usr/bin/env python3
"""Plan the current changed runtime file; apply only with explicit live-patch intent."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from infer_live_patch import changed_files, infer_target, repo_root  # type: ignore  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", required=True, help="BMC IP address or hostname")
    parser.add_argument("--cwd", default=".", type=Path, help="Repository/worktree path")
    parser.add_argument("--app", default="", help="Explicit /opt/bmc/apps/<app> directory name")
    parser.add_argument("--include-untracked", action="store_true", help="Include untracked candidate files")
    parser.add_argument("--select", default="", help="Relative-path substring used to select one candidate")
    parser.add_argument("--mode", default="644", help="Remote chmod mode after copy")
    parser.add_argument("--apply", action="store_true", help="Apply the reviewed plan")
    parser.add_argument("--intent", choices=("live_patch",), help="Required named intent for --apply")
    parser.add_argument(
        "--authorize-live-patch",
        action="store_true",
        help="Confirm authorization.live_patch=true for this exact target and plan",
    )
    parser.add_argument(
        "--restart-scope",
        choices=("none", "skynet"),
        help="Required for --apply; explicit restart boundary",
    )
    parser.add_argument("--health-check", action="store_true", help="Poll framework health after deployment")
    parser.add_argument("--health-timeout", type=int, default=180, help="Max health polling seconds")
    parser.add_argument("--health-interval", type=int, default=15, help="Seconds between health polls")
    parser.add_argument(
        "--verify-mdbctl",
        action="append",
        default=[],
        help="Business verification mdbctl command; repeatable",
    )
    parser.add_argument("--health-wait", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--ssh-user", default="", help="SSH user; defaults to OPENUBMC_SSH_USER")
    parser.add_argument("--telnet-user", default="", help="Telnet user; defaults to OPENUBMC_TELNET_USER/SSH user")
    parser.add_argument("--ssh-password", default="", help="Direct SSH password for internal development")
    parser.add_argument("--telnet-password", default="", help="Direct Telnet password for internal development")
    parser.add_argument("--ssh-identity", type=Path, help="Optional SSH private key path")
    parser.add_argument("--known-hosts", type=Path, help="Optional SSH known_hosts path")
    parser.add_argument(
        "--host-key-policy",
        choices=("strict", "accept-new", "insecure"),
        default="insecure",
        help="BMC SSH host-key policy, default: insecure for replaceable lab targets",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON summary")
    return parser.parse_args()


def emit(payload: dict[str, Any], json_mode: bool, *, error: bool = False) -> None:
    if json_mode:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    if error:
        print(payload["error"], file=sys.stderr)
        for index, candidate in enumerate(payload.get("supported_candidates", []), 1):
            print(f"{index}. {candidate['relative']} -> {candidate['remote']}", file=sys.stderr)
        for candidate in payload.get("unsupported_candidates", []):
            print(f"unsupported: {candidate['relative']}: {candidate['reason']}", file=sys.stderr)
        return
    print("PLAN ONLY: no remote state was changed.")
    print(f"local:  {payload['local']}")
    print(f"remote: {payload['ip']}:{payload['remote']}")
    print(
        "Apply only after review with --apply --intent live_patch "
        "--authorize-live-patch --restart-scope <none|skynet>."
    )


def main() -> int:
    args = parse_args()
    root = repo_root(args.cwd.resolve())
    supported: list[dict[str, str]] = []
    unsupported: list[dict[str, str]] = []
    for relative in changed_files(root, args.include_untracked):
        is_test = (
            relative.startswith("test/")
            or "/test/" in relative
            or relative.startswith("tests/")
            or "/tests/" in relative
        )
        if is_test:
            continue
        remote, reason = infer_target(root, relative, args.app or None)
        candidate = {
            "relative": relative,
            "local": str((root / relative).resolve()),
            "remote": remote or "",
            "reason": reason,
        }
        (supported if remote else unsupported).append(candidate)

    if args.select:
        supported = [item for item in supported if args.select in item["relative"]]
        unsupported = [item for item in unsupported if args.select in item["relative"]]

    blocking_unsupported = [
        item
        for item in unsupported
        if item["reason"] != "file path does not match a supported live runtime pattern"
    ]
    if len(supported) != 1 or blocking_unsupported:
        payload: dict[str, Any] = {
            "ok": False,
            "error": "expected one supported candidate with no unresolved runtime mapping",
            "repo_root": str(root),
            "supported_candidates": supported,
            "unsupported_candidates": unsupported,
        }
        emit(payload, args.json, error=True)
        return 2

    if args.apply and args.intent != "live_patch":
        emit({"ok": False, "error": "--apply requires --intent live_patch"}, args.json, error=True)
        return 2
    if args.apply and not args.authorize_live_patch:
        emit(
            {
                "ok": False,
                "error": "--apply requires authorization.live_patch=true (--authorize-live-patch)",
            },
            args.json,
            error=True,
        )
        return 2
    if args.apply and args.restart_scope is None:
        emit(
            {"ok": False, "error": "--apply requires explicit --restart-scope <none|skynet>"},
            args.json,
            error=True,
        )
        return 2

    item = supported[0]
    plan: dict[str, Any] = {
        "ok": True,
        "dry_run": not args.apply,
        "authorization_live_patch": args.authorize_live_patch,
        "repo_root": str(root),
        "relative": item["relative"],
        "local": item["local"],
        "remote": item["remote"],
        "ip": args.ip,
        "mode": args.mode,
        "restart_scope": args.restart_scope,
        "will_restart": args.restart_scope not in (None, "none"),
        "health_check": args.health_check or bool(args.verify_mdbctl),
        "framework_health_requested": args.health_check,
        "health_timeout": args.health_wait if args.health_wait > 0 else args.health_timeout,
        "health_interval": args.health_interval,
        "verify_mdbctl": args.verify_mdbctl,
        "host_key_policy": args.host_key_policy,
    }
    if not args.apply:
        emit(plan, args.json)
        return 0

    command = [
        sys.executable,
        str(SCRIPT_DIR / "deploy_live_file.py"),
        "--ip",
        args.ip,
        "--local",
        item["local"],
        "--remote",
        item["remote"],
        "--mode",
        args.mode,
        "--apply",
        "--intent",
        "live_patch",
        "--authorize-live-patch",
        "--restart-scope",
        args.restart_scope,
        "--host-key-policy",
        args.host_key_policy,
    ]
    if args.health_check:
        command.extend(
            [
                "--health-check",
                "--health-timeout",
                str(args.health_wait if args.health_wait > 0 else args.health_timeout),
                "--health-interval",
                str(args.health_interval),
            ]
        )
    for verification in args.verify_mdbctl:
        command.extend(["--verify-mdbctl", verification])
    for flag, value in (
        ("--ssh-user", args.ssh_user),
        ("--telnet-user", args.telnet_user),
        ("--ssh-password", args.ssh_password),
        ("--telnet-password", args.telnet_password),
        ("--ssh-identity", str(args.ssh_identity) if args.ssh_identity else ""),
        ("--known-hosts", str(args.known_hosts) if args.known_hosts else ""),
    ):
        if value:
            command.extend([flag, value])
    if args.json:
        command.append("--json")
    return subprocess.call(command)


if __name__ == "__main__":
    raise SystemExit(main())
