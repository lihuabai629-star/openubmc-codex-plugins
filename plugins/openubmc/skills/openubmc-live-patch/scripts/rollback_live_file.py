#!/usr/bin/env python3
"""Plan a backup restore or removal of a checksum-matched created BMC file."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import secrets
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from deploy_live_file import (  # type: ignore  # noqa: E402
    ALLOWED_REMOTE_PREFIXES,
    LivePatchError,
    run_health_check,
    validate_remote_path,
)
from runtime_cli import RuntimeMutationFailed, run_runtime_mutation  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", required=True, help="BMC IP address or hostname")
    parser.add_argument("--backup", default="", help="Existing remote backup path")
    parser.add_argument(
        "--remove-created",
        action="store_true",
        help="Remove a target that the matching Live Patch created from absence.",
    )
    parser.add_argument(
        "--expected-current-sha256",
        default="",
        help="Required checksum guard for --remove-created.",
    )
    parser.add_argument("--remote", required=True, help="Remote target path to restore")
    parser.add_argument("--mode", default="644", help="Remote chmod mode after restore")
    parser.add_argument("--no-remount", action="store_true", help="Skip root mount discovery/remount")
    parser.add_argument(
        "--force-path",
        action="store_true",
        help="Allow a reviewed target outside /opt/bmc/apps, /opt/bmc/sr, or /tmp",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="Apply the reviewed rollback plan")
    mode.add_argument("--dry-run", action="store_true", help="Explicit alias for default plan-only behavior")
    parser.add_argument("--intent", choices=("live_patch",), help="Required named intent for --apply")
    parser.add_argument(
        "--authorize-live-patch",
        action="store_true",
        help="Confirm authorization.live_patch=true for this exact rollback target and plan",
    )
    parser.add_argument(
        "--restart-scope",
        choices=("none", "skynet"),
        help="Required for --apply; explicit restart boundary",
    )
    parser.add_argument("--health-check", action="store_true", help="Poll framework health after rollback")
    parser.add_argument("--health-timeout", type=int, default=180, help="Max health polling seconds")
    parser.add_argument("--health-interval", type=int, default=15, help="Seconds between health polls")
    parser.add_argument(
        "--verify-mdbctl",
        action="append",
        default=[],
        help="Business verification mdbctl command; repeatable",
    )
    parser.add_argument("--telnet-user", default="", help="Telnet user; defaults to OPENUBMC_TELNET_USER/SSH user")
    parser.add_argument("--ssh-user", default="", help="SSH selector used by the matching Apply.")
    parser.add_argument("--ssh-password", default="", help="Direct SSH password used by the matching Apply.")
    parser.add_argument("--telnet-password", default="", help="Direct Telnet password used by the matching Apply.")
    parser.add_argument("--ssh-identity", type=Path, help="SSH identity used by the matching Apply.")
    parser.add_argument("--known-hosts", type=Path, help="known_hosts used by the matching Apply.")
    parser.add_argument(
        "--host-key-policy",
        choices=("strict", "accept-new", "insecure"),
        default="insecure",
        help="SSH host-key policy used by the matching Apply.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON summary")
    return parser.parse_args()


def emit(payload: dict[str, Any], json_mode: bool, *, error: bool = False) -> None:
    if json_mode:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    if error:
        print(payload["error"], file=sys.stderr)
        return
    if payload.get("dry_run"):
        print("PLAN ONLY: no remote state was changed.")
        if payload.get("remove_created"):
            print(f"remove created target: {payload['remote']}")
        else:
            print(f"restore: {payload['backup']} -> {payload['remote']}")
        print(
            "Apply only after review with --apply --intent live_patch "
            "--authorize-live-patch --restart-scope <none|skynet>."
        )


def _runtime_rollback(args: argparse.Namespace, plan: dict[str, Any]) -> int:
    try:
        runtime_result = run_runtime_mutation(
            {
                "action": "rollback",
                "intent": args.intent or "live_patch",
                "ip": args.ip,
                "backup_path": args.backup,
                "remote_path": args.remote,
                "remove_created": args.remove_created,
                "expected_current_sha256": args.expected_current_sha256,
                "mode": args.mode,
                "restart_scope": args.restart_scope or "none",
                "deadline": max(1, args.health_timeout),
                "no_remount": args.no_remount,
                "force_path": args.force_path,
                "authorized_exceptions": {
                    "no_remount": args.no_remount,
                    "force_path": args.force_path,
                },
                "telnet_user": args.telnet_user,
                "telnet_password": args.telnet_password,
                "ssh_user": args.ssh_user,
                "ssh_password": args.ssh_password,
                "ssh_identity_file": str(args.ssh_identity or ""),
                "ssh_known_hosts_file": str(args.known_hosts or ""),
                "ssh_host_key_policy": args.host_key_policy,
            }
        )
    except RuntimeMutationFailed as exc:
        journal = exc.journal
        emit(
            {
                **plan,
                "ok": False,
                "dry_run": False,
                "error": str(exc),
                "root_mount_before": str(
                    journal.get("root_mount_mode", "")
                ).split(","),
                "root_mount_restored": journal.get(
                    "root_mount_restored", False
                ),
                "runtime_transaction": journal,
                "transcript": [],
            },
            args.json,
            error=True,
        )
        return 1

    mutation = runtime_result.get("mutation")
    mutation = mutation if isinstance(mutation, dict) else {}
    journal = runtime_result.get("journal")
    journal = journal if isinstance(journal, dict) else {}
    verification = runtime_result.get("verification")
    verification = verification if isinstance(verification, dict) else {}
    verification_marker = (
        "fresh_removal_verified=true"
        if verification.get("remote_removed") is True
        else "fresh_checksum_verified="
        + str(verification.get("remote_sha256", ""))
    )
    transcript = [
        str(value)
        for value in (
            mutation.get("restore_output"),
            verification_marker,
        )
        if value
    ]
    health = None
    if args.health_check or args.verify_mdbctl:
        health = run_health_check(
            args.ip,
            args.health_timeout,
            args.health_interval,
            args.verify_mdbctl,
            transcript,
            args.json,
        )
    ok = health is None or bool(health.get("ok"))
    mount_mode = str(journal.get("root_mount_mode", ""))
    emit(
        {
            **plan,
            "ok": ok,
            "dry_run": False,
            "health_check": health,
            "remote_after_sha256": verification.get(
                "remote_sha256",
                mutation.get("remote_after_sha256", ""),
            ),
            "remote_after_metadata": verification.get(
                "remote_metadata",
                mutation.get("remote_after_metadata", {}),
            ),
            "remote_removed": verification.get(
                "remote_removed",
                mutation.get("remote_removed", False),
            ),
            "root_mount_before": [
                item
                for item in mount_mode.split(",")
                if item and item != "not-inspected"
            ],
            "root_mount_restored": journal.get("root_mount_restored", True),
            "runtime_transaction": runtime_result,
            "transcript": transcript,
        },
        args.json,
    )
    return 0 if ok else 1


def main() -> int:
    args = parse_args()
    try:
        validate_remote_path(
            args.remote,
            "rollback target",
            allowed_prefixes=ALLOWED_REMOTE_PREFIXES,
            allow_outside_prefixes=args.force_path,
        )
        if bool(args.backup) == bool(args.remove_created):
            raise LivePatchError(
                "select exactly one rollback source: --backup or --remove-created"
            )
        if args.backup:
            validate_remote_path(
                args.backup,
                "rollback backup",
                allowed_prefixes=("/tmp/",),
            )
        elif re.fullmatch(
            r"[0-9a-fA-F]{64}",
            args.expected_current_sha256,
        ) is None:
            raise LivePatchError(
                "--remove-created requires --expected-current-sha256"
            )
        if not re.fullmatch(r"[0-7]{3,4}", args.mode):
            raise LivePatchError(f"mode must be a 3- or 4-digit octal value: {args.mode}")
    except LivePatchError as exc:
        emit(
            {"ok": False, "error": str(exc)},
            args.json,
            error=True,
        )
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

    plan: dict[str, Any] = {
        "ok": True,
        "dry_run": not args.apply,
        "authorization_live_patch": args.authorize_live_patch,
        "ip": args.ip,
        "backup": args.backup,
        "remote": args.remote,
        "remove_created": args.remove_created,
        "expected_current_sha256": args.expected_current_sha256.lower(),
        "mode": args.mode,
        "restart_scope": args.restart_scope,
        "will_restart": args.restart_scope not in (None, "none"),
        "will_remount": not args.no_remount,
        "force_path": args.force_path,
        "ssh_user": args.ssh_user,
        "ssh_password": args.ssh_password,
        "telnet_password": args.telnet_password,
        "ssh_identity": str(args.ssh_identity or ""),
        "known_hosts": str(args.known_hosts or ""),
        "host_key_policy": args.host_key_policy,
        "health_check_requested": args.health_check or bool(args.verify_mdbctl),
        "framework_health_requested": args.health_check,
        "verify_mdbctl": args.verify_mdbctl,
        "operation_token": secrets.token_hex(8),
    }
    if not args.apply:
        emit(plan, args.json)
        return 0

    return _runtime_rollback(args, plan)


if __name__ == "__main__":
    raise SystemExit(main())
