#!/usr/bin/env python3
"""Plan or apply one temporary file replacement on a live openUBMC BMC."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import posixpath
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any, Callable

from runtime_cli import RuntimeMutationFailed, run_runtime_mutation


ALLOWED_REMOTE_PREFIXES = ("/opt/bmc/apps/", "/opt/bmc/sr/", "/tmp/")
ROOT_MOUNT_OPTIONS_COMMAND = "awk '$2 == \"/\" {print $4; exit}' /proc/mounts"


class LivePatchError(RuntimeError):
    """An expected live-patch safety or execution failure."""


def validate_remote_path(
    value: str,
    label: str,
    *,
    allowed_prefixes: tuple[str, ...] = (),
    allow_outside_prefixes: bool = False,
    allow_directory: bool = False,
) -> str:
    if not value.startswith("/"):
        raise LivePatchError(f"{label} must be an absolute POSIX path: {value}")
    if any(character in value for character in ("\x00", "\n", "\r")):
        raise LivePatchError(f"{label} contains a control character")
    if ".." in PurePosixPath(value).parts or value != posixpath.normpath(value):
        raise LivePatchError(f"{label} must be canonical and cannot contain traversal: {value}")
    if not allow_directory and value.endswith("/"):
        raise LivePatchError(f"{label} must name a file: {value}")
    if allowed_prefixes and not allow_outside_prefixes:
        matches = any(value.startswith(prefix) or value == prefix.rstrip("/") for prefix in allowed_prefixes)
        if not matches:
            raise LivePatchError(f"{label} is outside allowed roots {allowed_prefixes}: {value}")
    return value


def authorized_root(
    path: str, allowed_prefixes: tuple[str, ...], *, force_path: bool = False
) -> str:
    if force_path:
        return posixpath.dirname(path)
    matches = [prefix.rstrip("/") for prefix in allowed_prefixes if path.startswith(prefix)]
    if not matches:
        raise LivePatchError(f"no authorized root for remote path: {path}")
    return max(matches, key=len)


def remote_path_guard_command(
    *,
    files: list[tuple[str, str, bool]],
    directories: list[tuple[str, str]],
) -> str:
    """Build a read-only remote guard for canonical roots and non-symlink paths."""

    commands = [
        "set -eu",
        "command -v readlink >/dev/null 2>&1",
    ]
    for path, root, require_exists in files:
        parent = posixpath.dirname(path)
        path_q = shlex.quote(path)
        parent_q = shlex.quote(parent)
        root_q = shlex.quote(root)
        commands.extend(
            [
                f"root_real=$(readlink -f {root_q})",
                f"parent_real=$(readlink -f {parent_q})",
                f"test \"$root_real\" = {root_q}",
                f"test \"$parent_real\" = {parent_q}",
                "test -d \"$root_real\"",
                "case \"$parent_real/\" in \"$root_real/\"*) ;; *) exit 41 ;; esac",
                f"test ! -L {path_q}",
                f"if test -e {path_q}; then test -f {path_q}; fi",
            ]
        )
        if require_exists:
            commands.append(f"test -f {path_q}")
    for path, root in directories:
        path_q = shlex.quote(path)
        root_q = shlex.quote(root)
        commands.extend(
            [
                f"root_real=$(readlink -f {root_q})",
                f"dir_real=$(readlink -f {path_q})",
                f"test \"$root_real\" = {root_q}",
                f"test \"$dir_real\" = {path_q}",
                "test -d \"$root_real\"",
                "test -d \"$dir_real\"",
                f"test ! -L {path_q}",
                "case \"$dir_real/\" in \"$root_real/\"*) ;; *) exit 42 ;; esac",
            ]
        )
    commands.append("echo live_patch_paths_safe")
    return " && ".join(commands)


def atomic_backup_command(remote: str, backup: str, expected_sha: str, token: str) -> str:
    backup_parent = posixpath.dirname(backup)
    backup_name = posixpath.basename(backup)
    work = f".live-patch-backup.{token}"
    return (
        f"(cd -P {shlex.quote(backup_parent)} && "
        f"test \"$(pwd -P)\" = {shlex.quote(backup_parent)} && "
        f"test ! -e {shlex.quote(backup_name)} && test ! -L {shlex.quote(backup_name)} && "
        f"mkdir {shlex.quote(work)} && "
        f"cp -P {shlex.quote(remote)} {shlex.quote(work + '/payload')} && "
        f"test -f {shlex.quote(work + '/payload')} && test ! -L {shlex.quote(work + '/payload')} && "
        f"backup_sha=$(sha256sum {shlex.quote(work + '/payload')} | awk '{{print $1}}') && "
        f"test \"$backup_sha\" = {shlex.quote(expected_sha)} && "
        f"mv {shlex.quote(work + '/payload')} {shlex.quote(backup_name)} && "
        f"rmdir {shlex.quote(work)} && "
        "printf 'backup_sha256=%s\\n' \"$backup_sha\" && echo backup_ok) || "
        "{ echo backup_failed; exit 1; }"
    )


def atomic_install_command(
    staging_payload: str,
    staging_dir: str,
    remote: str,
    mode: str,
    expected_sha: str,
    token: str,
) -> str:
    remote_parent = posixpath.dirname(remote)
    remote_name = posixpath.basename(remote)
    work = f".live-patch-install.{token}"
    payload = work + "/payload"
    return (
        f"(cd -P {shlex.quote(remote_parent)} && "
        f"test \"$(pwd -P)\" = {shlex.quote(remote_parent)} && "
        f"test ! -L {shlex.quote(remote_name)} && "
        f"if test -e {shlex.quote(remote_name)}; then test -f {shlex.quote(remote_name)}; fi && "
        f"mkdir {shlex.quote(work)} && "
        f"cp -P {shlex.quote(staging_payload)} {shlex.quote(payload)} && "
        f"test -f {shlex.quote(payload)} && test ! -L {shlex.quote(payload)} && "
        f"chmod {shlex.quote(mode)} {shlex.quote(payload)} && "
        f"new_sha=$(sha256sum {shlex.quote(payload)} | awk '{{print $1}}') && "
        f"test \"$new_sha\" = {shlex.quote(expected_sha)} && "
        f"mv -f {shlex.quote(payload)} {shlex.quote(remote_name)} && "
        f"rmdir {shlex.quote(work)} && "
        f"remote_sha=$(sha256sum {shlex.quote(remote_name)} | awk '{{print $1}}') && "
        f"test \"$remote_sha\" = {shlex.quote(expected_sha)} && "
        f"rm -f {shlex.quote(staging_payload)} && rmdir {shlex.quote(staging_dir)} && "
        "printf 'remote_sha256=%s\\n' \"$remote_sha\" && echo deploy_ok) || "
        "{ echo deploy_failed; exit 1; }"
    )


def atomic_restore_command(backup: str, remote: str, mode: str, token: str) -> str:
    remote_parent = posixpath.dirname(remote)
    remote_name = posixpath.basename(remote)
    work = f".live-patch-restore.{token}"
    payload = work + "/payload"
    return (
        f"(cd -P {shlex.quote(remote_parent)} && "
        f"test \"$(pwd -P)\" = {shlex.quote(remote_parent)} && "
        f"test ! -L {shlex.quote(remote_name)} && "
        f"if test -e {shlex.quote(remote_name)}; then test -f {shlex.quote(remote_name)}; fi && "
        f"mkdir {shlex.quote(work)} && "
        f"cp -P {shlex.quote(backup)} {shlex.quote(payload)} && "
        f"test -f {shlex.quote(payload)} && test ! -L {shlex.quote(payload)} && "
        f"backup_sha=$(sha256sum {shlex.quote(payload)} | awk '{{print $1}}') && "
        f"chmod {shlex.quote(mode)} {shlex.quote(payload)} && "
        f"mv -f {shlex.quote(payload)} {shlex.quote(remote_name)} && "
        f"rmdir {shlex.quote(work)} && "
        f"remote_sha=$(sha256sum {shlex.quote(remote_name)} | awk '{{print $1}}') && "
        "printf 'backup_sha256=%s\\nremote_sha256=%s\\n' \"$backup_sha\" \"$remote_sha\" && "
        "test \"$backup_sha\" = \"$remote_sha\" && echo restore_ok) || "
        "{ echo restore_failed; exit 1; }"
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def debug_scripts_path() -> Path:
    configured = os.environ.get("OPENUBMC_DEBUG_SCRIPTS", "").strip()
    scripts = (
        Path(configured).expanduser().resolve()
        if configured
        else Path(__file__).resolve().parents[2] / "openubmc-debug" / "scripts"
    )
    required = ("preflight_remote.py", "collect_logs.py", "mdbctl_remote.py")
    missing = [str(scripts / name) for name in required if not (scripts / name).is_file()]
    if missing:
        raise LivePatchError(
            "openubmc-debug verification scripts were not found. Install it as a sibling skill or set "
            f"OPENUBMC_DEBUG_SCRIPTS. Missing: {', '.join(missing)}"
        )
    return scripts


def ssh_stream_file(
    ip: str,
    user: str,
    password: str,
    identity: Path | None,
    known_hosts: Path | None,
    host_key_policy: str,
    local: Path,
    staging_dir: str,
    staging_payload: str,
    timeout: int,
) -> None:
    ssh_command = ["ssh"]
    command_env = os.environ.copy()
    command_env.pop("SSHPASS", None)
    command_env.pop("OPENUBMC_SSH_PASSWORD", None)
    command_env.pop("OPENUBMC_TELNET_PASSWORD", None)
    if password:
        if not shutil.which("sshpass"):
            raise LivePatchError("password SSH authentication requires sshpass in PATH")
        ssh_command = ["sshpass", "-e", "ssh"]
        command_env["SSHPASS"] = password
    ssh_command.extend(["-o", f"BatchMode={'no' if password else 'yes'}"])

    host_key_options = {
        "strict": ["-o", "StrictHostKeyChecking=yes"],
        "accept-new": ["-o", "StrictHostKeyChecking=accept-new"],
        "insecure": [
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
        ],
    }[host_key_policy]
    ssh_command.extend(host_key_options)
    if known_hosts:
        ssh_command.extend(["-o", f"UserKnownHostsFile={known_hosts}"])
    if identity:
        ssh_command.extend(["-i", str(identity)])
    ssh_command.extend(
        [
            "-o",
            "LogLevel=ERROR",
            f"{user}@{ip}",
            f"umask 077 && mkdir {shlex.quote(staging_dir)} && "
            f"cat > {shlex.quote(staging_payload)}",
        ]
    )
    completed = subprocess.run(
        ssh_command,
        env=command_env,
        input=local.read_bytes(),
        capture_output=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        detail = (
            completed.stderr.decode("utf-8", errors="ignore").strip()
            or completed.stdout.decode("utf-8", errors="ignore").strip()
            or f"exit {completed.returncode}"
        )
        raise LivePatchError(f"SSH staging failed: {detail}")


def rollback_command(
    ip: str,
    backup: str,
    remote: str,
    mode: str,
    restart_scope: str,
    force_path: bool,
    expected_current_sha256: str = "",
    no_remount: bool = False,
    ssh_user: str = "",
    ssh_password: str = "",
    telnet_password: str = "",
    ssh_identity: Path | None = None,
    known_hosts: Path | None = None,
    host_key_policy: str = "insecure",
) -> str:
    command = [
        sys.executable,
        str(Path(__file__).resolve().parent / "rollback_live_file.py"),
        "--ip",
        ip,
        "--remote",
        remote,
        "--mode",
        mode,
        "--restart-scope",
        restart_scope,
    ]
    if backup:
        command.extend(["--backup", backup])
    else:
        command.extend(
            [
                "--remove-created",
                "--expected-current-sha256",
                expected_current_sha256,
            ]
        )
    if force_path:
        command.append("--force-path")
    if no_remount:
        command.append("--no-remount")
    if ssh_user:
        command.extend(["--ssh-user", ssh_user])
    if ssh_password:
        command.extend(["--ssh-password", ssh_password])
    if telnet_password:
        command.extend(["--telnet-password", telnet_password])
    if ssh_identity:
        command.extend(["--ssh-identity", str(ssh_identity)])
    if known_hosts:
        command.extend(["--known-hosts", str(known_hosts)])
    command.extend(["--host-key-policy", host_key_policy])
    return " ".join(shlex.quote(part) for part in command)


def startup_status_from_logs(text: str) -> dict[str, Any]:
    status: dict[str, Any] = {
        "startup_complete": False,
        "startup_normal": False,
        "startup_line": "",
        "startup_errors_seen": False,
    }
    if "StartupCheck failed" in text or "init service failed" in text:
        status["startup_errors_seen"] = True
    matches = re.findall(r"check startup status completely[^\n\"]*", text)
    if not matches:
        return status
    line = matches[-1]
    status["startup_complete"] = True
    status["startup_line"] = line
    counts = re.search(r"total components count:\s*(\d+),\s*normal count:\s*(\d+)", line)
    status["startup_normal"] = bool(counts and counts.group(1) == counts.group(2))
    return status


def run_tool(command: list[str], timeout: int) -> dict[str, Any]:
    completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
    return {
        "cmd": command,
        "tool": Path(command[1]).name if len(command) > 1 else Path(command[0]).name,
        "returncode": completed.returncode,
        "stdout_tail": completed.stdout[-4000:],
        "stderr_tail": completed.stderr[-2000:],
    }


def run_health_check(
    ip: str,
    timeout_seconds: int,
    interval_seconds: int,
    verify_mdbctl: list[str],
    transcript: list[str],
    json_mode: bool,
) -> dict[str, Any]:
    scripts = debug_scripts_path()
    preflight_command = [sys.executable, str(scripts / "preflight_remote.py"), "--ip", ip, "--json"]
    logs_command = [
        sys.executable,
        str(scripts / "collect_logs.py"),
        "--ip",
        ip,
        "--logs",
        "app.log,framework.log",
        "--grep",
        "check startup status completely,StartupCheck failed,init service failed,abnormal components",
        "--lines",
        "260",
        "--since-boot",
        "--json",
    ]

    deadline = time.monotonic() + timeout_seconds
    attempts: list[dict[str, Any]] = []
    framework_ready = False
    while True:
        preflight = run_tool(preflight_command, timeout=90)
        logs = run_tool(logs_command, timeout=90)
        startup = startup_status_from_logs(logs["stdout_tail"])
        framework_ready = (
            preflight["returncode"] == 0
            and logs["returncode"] == 0
            and startup["startup_normal"]
            and not startup["startup_errors_seen"]
        )
        attempt = {
            "elapsed_seconds": max(0, int(timeout_seconds - (deadline - time.monotonic()))),
            "preflight_ok": preflight["returncode"] == 0,
            "logs_ok": logs["returncode"] == 0,
            "startup_status": startup,
            "preflight": preflight,
            "logs": logs,
        }
        attempts.append(attempt)
        line = (
            "health_poll "
            f"preflight_ok={attempt['preflight_ok']} "
            f"logs_ok={attempt['logs_ok']} "
            f"startup_complete={startup['startup_complete']} "
            f"startup_normal={startup['startup_normal']}"
        )
        transcript.append(line)
        if not json_mode:
            print(line)
            if startup["startup_line"]:
                print(startup["startup_line"])
        if framework_ready or time.monotonic() >= deadline:
            break
        time.sleep(interval_seconds)

    verification_results: list[dict[str, Any]] = []
    for mdbctl_command in verify_mdbctl:
        command = [
            sys.executable,
            str(scripts / "mdbctl_remote.py"),
            "--ip",
            ip,
            *shlex.split(mdbctl_command),
        ]
        result = run_tool(command, timeout=90)
        result["mdbctl_command"] = mdbctl_command
        verification_results.append(result)
        line = f"verify_mdbctl {mdbctl_command!r}: returncode={result['returncode']}"
        transcript.append(line)
        if not json_mode:
            print(line)
            if result["stdout_tail"]:
                print(result["stdout_tail"])
            if result["stderr_tail"]:
                print(result["stderr_tail"], file=sys.stderr)

    verification_ok = all(result["returncode"] == 0 for result in verification_results)
    return {
        "ok": framework_ready and verification_ok,
        "timeout_seconds": timeout_seconds,
        "interval_seconds": interval_seconds,
        "framework_ready": framework_ready,
        "verification_ok": verification_ok,
        "attempts": attempts,
        "verify_mdbctl": verification_results,
    }


def parse_root_mount_options(output: str) -> set[str]:
    for line in reversed(output.splitlines()):
        options = {item.strip() for item in line.strip().split(",") if item.strip()}
        if "ro" in options or "rw" in options:
            return options
    raise LivePatchError(f"could not determine root mount mode from: {output!r}")


def query_root_mount_options(telnet: Any, run_cmd: Callable[..., str]) -> set[str]:
    return parse_root_mount_options(run_cmd(telnet, ROOT_MOUNT_OPTIONS_COMMAND, timeout=20))


def restore_root_mount(
    ip: str,
    user: str,
    password: str,
    original_options: set[str],
    close_telnet: Callable[..., Any],
    run_cmd: Callable[..., str],
    telnet_connect: Callable[..., Any],
    record: Callable[[str], None],
) -> None:
    if "ro" not in original_options:
        return
    telnet = telnet_connect(ip, 23, user, password, connect_timeout=10, prompt_timeout=8)
    try:
        output = run_cmd(
            telnet,
            "mount -o remount,ro / && echo remount_ro_ok || echo remount_ro_failed",
            timeout=20,
        )
        record(output)
        if "remount_ro_ok" not in output or "remount_ro_failed" in output:
            raise LivePatchError(f"root read-only remount failed: {output!r}")
        restored = query_root_mount_options(telnet, run_cmd)
        if "ro" not in restored:
            raise LivePatchError(f"root filesystem did not return to read-only mode: {sorted(restored)}")
    finally:
        close_telnet(telnet)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", required=True, help="BMC IP address or hostname")
    parser.add_argument("--local", required=True, type=Path, help="Local file to deploy")
    parser.add_argument("--remote", required=True, help="Remote target path")
    parser.add_argument("--mode", default="644", help="Remote chmod mode after copy, default: 644")
    parser.add_argument("--tmp", default="", help="Remote staging path; default /tmp/<local>.live_patch_tmp")
    parser.add_argument("--backup-dir", default="/tmp", help="Remote backup directory, default: /tmp")
    parser.add_argument("--no-backup", action="store_true", help="Explicitly skip backing up an existing target")
    parser.add_argument("--no-remount", action="store_true", help="Skip root mount discovery/remount")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="Apply the reviewed plan")
    mode.add_argument("--dry-run", action="store_true", help="Explicit alias for the default plan-only behavior")
    parser.add_argument("--intent", choices=("live_patch",), help="Required named intent for --apply")
    parser.add_argument(
        "--authorize-live-patch",
        action="store_true",
        help="Confirm authorization.live_patch=true for this exact target and plan",
    )
    parser.add_argument(
        "--restart-scope",
        choices=("none", "skynet"),
        help="Required for --apply; 'none' syncs only, 'skynet' restarts the framework",
    )
    parser.add_argument(
        "--health-check",
        action="store_true",
        help="After deployment, poll until preflight and startup-complete logs are healthy",
    )
    parser.add_argument("--health-timeout", type=int, default=180, help="Max health polling seconds")
    parser.add_argument("--health-interval", type=int, default=15, help="Seconds between health polls")
    parser.add_argument(
        "--verify-mdbctl",
        action="append",
        default=[],
        help="Business verification command, for example 'lsobj ExpBoard'; repeatable",
    )
    parser.add_argument("--health-wait", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument(
        "--force-path",
        action="store_true",
        help="Allow a reviewed target outside /opt/bmc/apps, /opt/bmc/sr, or /tmp",
    )
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
    parser.add_argument("--timeout", type=int, default=60, help="Network command timeout seconds")
    parser.add_argument("--json", action="store_true", help="Emit JSON summary")
    return parser.parse_args()


def emit(payload: dict[str, Any], json_mode: bool, *, error: bool = False) -> None:
    if json_mode:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    if error:
        print(payload.get("error", "live patch failed"), file=sys.stderr)
        return
    if payload.get("dry_run"):
        print("PLAN ONLY: no remote state was changed.")
        print(f"local:  {payload['local']}")
        print(f"remote: {payload['ip']}:{payload['remote']}")
        print(
            "Apply only after review with --apply --intent live_patch "
            "--authorize-live-patch --restart-scope <none|skynet>."
        )


def gate_error(args: argparse.Namespace) -> str:
    if not args.apply:
        return ""
    if args.intent != "live_patch":
        return "--apply requires --intent live_patch"
    if not args.authorize_live_patch:
        return "--apply requires authorization.live_patch=true (--authorize-live-patch)"
    if args.restart_scope is None:
        return "--apply requires explicit --restart-scope <none|skynet>"
    return ""


def _runtime_execute(
    args: argparse.Namespace,
    plan: dict[str, Any],
) -> tuple[dict[str, Any], int]:
    runtime_arguments = {
        "action": "apply",
        "intent": args.intent or "live_patch",
        "ip": args.ip,
        "local_path": plan["local"],
        "remote_path": plan["remote"],
        "mode": args.mode,
        "restart_scope": args.restart_scope or "none",
        "deadline": max(1, args.timeout),
        "backup_dir": args.backup_dir,
        "no_backup": args.no_backup,
        "no_remount": args.no_remount,
        "force_path": args.force_path,
        "authorized_exceptions": {
            "no_backup": args.no_backup,
            "no_remount": args.no_remount,
            "force_path": args.force_path,
        },
        "ssh_user": args.ssh_user,
        "ssh_password": args.ssh_password,
        "telnet_user": args.telnet_user,
        "telnet_password": args.telnet_password,
        "ssh_identity_file": str(args.ssh_identity or ""),
        "ssh_known_hosts_file": str(args.known_hosts or ""),
        "ssh_host_key_policy": args.host_key_policy,
    }
    try:
        runtime_result = run_runtime_mutation(runtime_arguments)
    except RuntimeMutationFailed as exc:
        journal = exc.journal
        return (
            {
                **plan,
                "ok": False,
                "dry_run": False,
                "error": str(exc),
                "backup": journal.get("backup_reference", ""),
                "remote_before_sha256": journal.get("before_checksum", ""),
                "remote_after_sha256": journal.get("observed_checksum", ""),
                "restart_scope": args.restart_scope,
                "root_mount_before": str(
                    journal.get("root_mount_mode", "")
                ).split(","),
                "root_mount_restored": journal.get(
                    "root_mount_restored", False
                ),
                "runtime_transaction": journal,
                "transcript": [],
            },
            1,
        )

    mutation = runtime_result.get("mutation")
    mutation = mutation if isinstance(mutation, dict) else {}
    journal = runtime_result.get("journal")
    journal = journal if isinstance(journal, dict) else {}
    verification = runtime_result.get("verification")
    verification = verification if isinstance(verification, dict) else {}
    backup = str(
        mutation.get("backup_reference", journal.get("backup_reference", ""))
    )
    transcript = [
        str(value)
        for value in (
            mutation.get("install_output"),
            "fresh_checksum_verified=" + str(verification.get("remote_sha256", "")),
        )
        if value
    ]
    health = None
    if args.health_check or args.verify_mdbctl:
        health = run_health_check(
            args.ip,
            args.health_wait if args.health_wait > 0 else args.health_timeout,
            args.health_interval,
            args.verify_mdbctl,
            transcript,
            args.json,
        )
    target_existed = bool(mutation.get("target_existed", False))
    rollback = (
        rollback_command(
            args.ip,
            backup,
            plan["remote"],
            args.mode,
            args.restart_scope or "none",
            args.force_path,
            plan["local_sha256"],
            args.no_remount,
            args.ssh_user,
            args.ssh_password,
            args.telnet_password,
            args.ssh_identity,
            args.known_hosts,
            args.host_key_policy,
        )
        if backup or not target_existed
        else ""
    )
    ok = health is None or bool(health.get("ok"))
    mount_mode = str(journal.get("root_mount_mode", ""))
    summary = {
        **plan,
        "ok": ok,
        "dry_run": False,
        "backup": backup,
        "remote_before_sha256": journal.get("before_checksum", ""),
        "remote_after_sha256": verification.get(
            "remote_sha256",
            journal.get("observed_checksum", plan["local_sha256"]),
        ),
        "remote_before_metadata": mutation.get(
            "remote_before_metadata", {}
        ),
        "remote_after_metadata": verification.get(
            "remote_metadata",
            mutation.get("remote_after_metadata", {}),
        ),
        "rollback_plan_command": rollback,
        "restart_scope": args.restart_scope,
        "health_check": health,
        "root_mount_before": [
            item for item in mount_mode.split(",") if item and item != "not-inspected"
        ],
        "root_mount_restored": journal.get("root_mount_restored", True),
        "runtime_transaction": runtime_result,
        "transcript": transcript,
    }
    return summary, 0 if ok else 1


def execute(args: argparse.Namespace, plan: dict[str, Any]) -> tuple[dict[str, Any], int]:
    return _runtime_execute(args, plan)


def main() -> int:
    args = parse_args()
    local = args.local.expanduser().resolve()
    if not local.is_file():
        payload = {"ok": False, "error": f"local file does not exist: {local}"}
        emit(payload, args.json, error=True)
        return 2
    try:
        validate_remote_path(
            args.remote,
            "remote target",
            allowed_prefixes=ALLOWED_REMOTE_PREFIXES,
            allow_outside_prefixes=args.force_path,
        )
        validate_remote_path(
            args.tmp or f"/tmp/{local.name}.live_patch_tmp",
            "remote staging path",
            allowed_prefixes=("/tmp/",),
        )
        validate_remote_path(
            args.backup_dir,
            "backup directory",
            allowed_prefixes=("/tmp/",),
            allow_directory=True,
        )
        if not re.fullmatch(r"[0-7]{3,4}", args.mode):
            raise LivePatchError(f"mode must be a 3- or 4-digit octal value: {args.mode}")
    except LivePatchError as exc:
        payload = {"ok": False, "error": str(exc)}
        emit(payload, args.json, error=True)
        return 2

    error = gate_error(args)
    if error:
        emit({"ok": False, "error": error}, args.json, error=True)
        return 2

    local_sha = sha256_file(local)
    remote_tmp = args.tmp or f"/tmp/{local.name}.live_patch_tmp"
    operation_token = secrets.token_hex(8)
    staging_dir = f"{remote_tmp}.dir.{operation_token}"
    staging_payload = f"{staging_dir}/payload"
    try:
        validate_remote_path(
            staging_dir,
            "remote staging directory",
            allowed_prefixes=("/tmp/",),
            allow_directory=True,
        )
        validate_remote_path(
            staging_payload,
            "remote staging payload",
            allowed_prefixes=("/tmp/",),
        )
        remote_root = authorized_root(
            args.remote, ALLOWED_REMOTE_PREFIXES, force_path=args.force_path
        )
        staging_root = authorized_root(staging_dir, ("/tmp/",))
        backup_root = authorized_root(args.backup_dir.rstrip("/") + "/placeholder", ("/tmp/",))
    except LivePatchError as exc:
        emit({"ok": False, "error": str(exc)}, args.json, error=True)
        return 2
    plan = {
        "ok": True,
        "dry_run": not args.apply,
        "authorization_live_patch": args.authorize_live_patch,
        "ip": args.ip,
        "local": str(local),
        "remote": args.remote,
        "remote_tmp": remote_tmp,
        "staging_dir": staging_dir,
        "staging_payload": staging_payload,
        "operation_token": operation_token,
        "remote_root": remote_root,
        "staging_root": staging_root,
        "backup_root": backup_root,
        "mode": args.mode,
        "local_sha256": local_sha,
        "will_backup": not args.no_backup,
        "will_remount": not args.no_remount,
        "will_restart": args.restart_scope not in (None, "none"),
        "restart_scope": args.restart_scope,
        "will_health_check": args.health_check or bool(args.verify_mdbctl),
        "framework_health_requested": args.health_check,
        "health_timeout": args.health_wait if args.health_wait > 0 else args.health_timeout,
        "health_interval": args.health_interval,
        "verify_mdbctl": args.verify_mdbctl,
        "host_key_policy": args.host_key_policy,
    }
    if not args.apply:
        emit(plan, args.json)
        return 0

    try:
        summary, returncode = execute(args, plan)
    except Exception as exc:
        failure = {**plan, "ok": False, "dry_run": False, "error": str(exc)}
        emit(failure, args.json, error=True)
        return 1
    emit(summary, args.json)
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
