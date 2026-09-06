#!/usr/bin/env python3
"""Run a quick SSH/Telnet/DBus preflight against an openUBMC BMC."""
from __future__ import annotations

import argparse
import copy
from concurrent.futures import ThreadPoolExecutor
import json

from _cli_common import (
    resolve_debug_credentials,
    resolve_ssh_credentials,
    resolve_telnet_credentials,
)
from _debug_dump import build_debug_dumper
from _json_common import build_json_payload as build_common_json_payload
from _preflight_checks import (
    check_busctl,
    check_dbus_env,
    check_mdbctl,
    check_ssh,
    check_telnet,
    check_telnet_time,
)
from _preflight_recommendations import (
    RECOMMENDED_NEXT_STEPS,
    build_check_result,
    build_connectivity_command,
    build_recommended_command,
    build_script_command,
    build_ssh_script_flags,
    build_telnet_script_flags,
    classify_ssh_failure,
)
from _target_runtime_adapter import open_debug_runtime_lease


_PREFLIGHT_CHECK_NAMES = frozenset(
    {"SSH", "MDBCTL", "DBUS_ENV", "BUSCTL", "TELNET"}
)
_PREFLIGHT_CHECK_DEPENDENCIES = {
    "MDBCTL": frozenset({"SSH"}),
    "DBUS_ENV": frozenset({"SSH"}),
    "BUSCTL": frozenset({"SSH", "DBUS_ENV"}),
}


def _selected_preflight_checks(args: argparse.Namespace) -> frozenset[str]:
    requested = {
        str(name).strip().upper()
        for name in getattr(args, "preflight_checks", [])
        if str(name).strip()
    }
    unsupported = requested - _PREFLIGHT_CHECK_NAMES
    if unsupported:
        raise ValueError(
            "unsupported preflight checks: " + ", ".join(sorted(unsupported))
        )
    if not requested:
        if bool(getattr(args, "mdb_only", False)):
            requested = {"SSH", "MDBCTL"}
        else:
            requested = {"SSH", "MDBCTL", "DBUS_ENV", "BUSCTL"}
            if not bool(getattr(args, "skip_telnet", False)):
                requested.add("TELNET")
    selected = set(requested)
    for name in tuple(requested):
        selected.update(_PREFLIGHT_CHECK_DEPENDENCIES.get(name, ()))
    return frozenset(selected)


def _normalize_preflight_scope(args: argparse.Namespace) -> None:
    if getattr(args, "preflight_checks", []):
        selected = _selected_preflight_checks(args)
        args.skip_telnet = "TELNET" not in selected
        args.mdb_only = selected <= {"SSH", "MDBCTL"}
    elif getattr(args, "mdb_only", False):
        args.skip_telnet = True


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Preflight remote access for openUBMC debug sessions.")
    parser.add_argument("--ip", required=True, help="BMC IP")
    parser.add_argument("--ssh-user", default="", help="SSH username (or OPENUBMC_SSH_USER)")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port")
    parser.add_argument("--ssh-user-env", default="", help="Environment variable holding the SSH username")
    parser.add_argument("--ssh-password-env", default="", help="Environment variable holding the SSH password")
    parser.add_argument("--ssh-password", default="", help="SSH password in development mode")
    parser.add_argument("--ssh-identity-file", default="", help="SSH private key path")
    parser.add_argument("--ssh-timeout", type=int, default=15, help="SSH timeout seconds")
    parser.add_argument("--telnet-port", type=int, default=23, help="Telnet port")
    parser.add_argument("--telnet-user", default="", help="Telnet username (or OPENUBMC_TELNET_USER)")
    parser.add_argument("--telnet-user-env", default="", help="Environment variable holding the Telnet username")
    parser.add_argument("--telnet-password-env", default="", help="Environment variable holding the Telnet password")
    parser.add_argument("--telnet-password", default="", help="Telnet password in development mode")
    parser.add_argument("--telnet-connect-timeout", type=int, default=10, help="Telnet connect timeout seconds")
    parser.add_argument("--telnet-prompt-timeout", type=int, default=5, help="Telnet prompt/login timeout seconds")
    parser.add_argument(
        "--skip-telnet",
        action="store_true",
        help="Do not connect to Telnet or inspect the log/file capability",
    )
    parser.add_argument(
        "--mdb-only",
        action="store_true",
        help="Check only SSH freshness and the MDB object lane",
    )
    parser.add_argument(
        "--check",
        action="append",
        dest="preflight_checks",
        choices=sorted(_PREFLIGHT_CHECK_NAMES),
        default=[],
        help="Run only the named capability check and its required dependencies",
    )
    parser.add_argument(
        "--busctl-service",
        default="",
        help="Optional service used for a tree smoke check; default checks busctl list",
    )
    parser.add_argument("--debug-dump", default="", help="Optional directory for raw SSH/Telnet debug artifacts")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of text sections")
    parser.add_argument("--compact-json", action="store_true", help="With --json, omit duplicated legacy top-level fields")
    return parser.parse_args(argv)


def print_section(title: str, status: str, lines: list[str]) -> None:
    print(f"[{title}] {status}")
    for line in lines:
        print(f"  {line}")
    print("")


def summarize_capabilities(
    checks: dict[str, dict[str, object]],
) -> dict[str, object]:
    def ok(name: str) -> bool:
        return bool(checks.get(name, {}).get("ok"))

    ssh_transport = ok("SSH")
    dbus_env = ok("DBUS_ENV")
    mdbctl = ssh_transport and ok("MDBCTL")
    busctl = ssh_transport and dbus_env and ok("BUSCTL")
    active_alarm_transport = busctl
    remote_object = mdbctl or busctl
    remote_log_file = ok("TELNET")
    capabilities = {
        "remote_object": remote_object,
        "remote_log_file": remote_log_file,
        "combined_snapshot": remote_object and remote_log_file,
        "ssh_transport": ssh_transport,
        "dbus_env": dbus_env,
        "mdbctl": mdbctl,
        "busctl": busctl,
        "active_alarm_transport": active_alarm_transport,
        "active_alarm_endpoint_verified": False,
        # Compatibility/attemptability alias. Preflight does not enumerate or
        # call a GetAlarmList endpoint; the workflow must preserve any later
        # discovery/read failure instead of treating this as verified evidence.
        "active_alarms": active_alarm_transport,
        "telnet_logs_present": ok("LOG_FILES") if "LOG_FILES" in checks else None,
        # Compatibility aliases for existing callers.
        "ssh_object": remote_object,
        "telnet_files": remote_log_file,
        "telnet_logs": remote_log_file and (ok("LOG_FILES") if "LOG_FILES" in checks else True),
    }
    usable = bool(remote_object or remote_log_file)
    all_checks_ok = all(bool(item.get("ok")) for item in checks.values())
    if all_checks_ok:
        overall_code = "ok"
    elif usable:
        overall_code = "partial"
    else:
        overall_code = "unavailable"
    return {
        "usable": usable,
        "all_checks_ok": all_checks_ok,
        "overall_code": overall_code,
        "capabilities": capabilities,
        "capability_assurance": {
            "active_alarms": "transport_prerequisites_only",
            "active_alarm_endpoint_verified": False,
        },
    }


def summarize_preflight(
    args: argparse.Namespace,
    checks: dict[str, dict[str, object]],
) -> dict[str, object]:
    """Derive one authoritative status for CLI, JSON, and typed callers."""

    status = summarize_capabilities(checks)
    if getattr(args, "preflight_checks", []):
        selected = _selected_preflight_checks(args)
        passed_count = sum(
            bool(checks.get(name, {}).get("ok")) for name in selected
        )
        overall_ok = passed_count == len(selected)
        if overall_ok:
            overall_code = "ok"
        elif passed_count:
            overall_code = "partial"
        else:
            overall_code = "unavailable"
    else:
        overall_ok = bool(status["usable"])
        overall_code = str(status["overall_code"])
    status.update(
        {
            "overall_ok": overall_ok,
            "overall_code": overall_code,
            "returncode": 0 if overall_ok else 1,
        }
    )
    return status


def build_json_report_payload(
    args: argparse.Namespace,
    checks: dict[str, dict[str, object]],
    *,
    status: dict[str, object] | None = None,
) -> dict[str, object]:
    failed_checks = [name for name, item in checks.items() if not item["ok"]]
    failure_count = len(failed_checks)
    capability_status = status or summarize_preflight(args, checks)
    overall_ok = bool(capability_status["overall_ok"])
    overall_code = str(capability_status["overall_code"])
    management_cli_blocked = (
        checks.get("MDBCTL", {}).get("code") == "remote-command-unsupported"
    )
    if getattr(args, "preflight_checks", []) and overall_ok:
        overall_recommendation = (
            "The requested preflight scope passed; continue with the operation "
            "that required these checks."
        )
    elif capability_status["usable"]:
        overall_recommendation = (
            "Choose remote object, remote log/file, or combined snapshot from the "
            "reported capabilities; failed optional checks do not block a usable lane."
        )
    elif management_cli_blocked:
        overall_recommendation = RECOMMENDED_NEXT_STEPS[
            "remote-command-unsupported"
        ]
    elif failed_checks:
        overall_recommendation = RECOMMENDED_NEXT_STEPS[checks[failed_checks[0]]["code"]]
    else:
        overall_recommendation = "No usable remote evidence capability was detected."
    if management_cli_blocked and not capability_status["usable"]:
        overall_command = ""
    elif failed_checks:
        overall_command = checks[failed_checks[0]]["recommended_command"]
    else:
        overall_command = build_script_command(
            "workflow_remote.py",
            ["--ip", args.ip]
            + build_ssh_script_flags(args)
            + build_telnet_script_flags(args)
            + (["--skip-telnet"] if getattr(args, "skip_telnet", False) else [])
            + (["--mdb-only"] if getattr(args, "mdb_only", False) else [])
            + ["--json", "--compact-json"],
        )
    return build_common_json_payload(
        tool="preflight_remote",
        ip=args.ip,
        ok=overall_ok,
        code=overall_code,
        returncode=int(capability_status["returncode"]),
        warnings=[f"check_failed:{name}" for name in failed_checks],
        request={
            "ssh_port": args.ssh_port,
            "telnet_port": args.telnet_port,
            "telnet_skipped": bool(getattr(args, "skip_telnet", False)),
            "mdb_only": bool(getattr(args, "mdb_only", False)),
            "busctl_service": args.busctl_service,
        },
        result={
            "overall_ok": overall_ok,
            "all_checks_ok": bool(capability_status["all_checks_ok"]),
            "overall_code": overall_code,
            "capabilities": capability_status["capabilities"],
            "capability_assurance": capability_status["capability_assurance"],
            "failure_count": failure_count,
            "failed_checks": failed_checks,
            "recommended_next_step": overall_recommendation,
            "recommended_command": overall_command,
            "checks": checks,
        },
    )


def emit_json_report(
    args: argparse.Namespace,
    checks: dict[str, dict[str, object]],
    *,
    status: dict[str, object] | None = None,
) -> None:
    capability_status = status or summarize_preflight(args, checks)
    payload = build_json_report_payload(args, checks, status=capability_status)
    failed_checks = [name for name, item in checks.items() if not item["ok"]]
    failure_count = len(failed_checks)
    overall_code = str(capability_status["overall_code"])
    overall_recommendation = str(payload["result"]["recommended_next_step"])
    overall_command = str(payload["result"]["recommended_command"])
    if args.compact_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    payload.update(
        {
            "ip": args.ip,
            "overall_ok": bool(capability_status["overall_ok"]),
            "all_checks_ok": bool(capability_status["all_checks_ok"]),
            "overall_code": overall_code,
            "capabilities": capability_status["capabilities"],
            "capability_assurance": capability_status["capability_assurance"],
            "failure_count": failure_count,
            "failed_checks": failed_checks,
            "recommended_next_step": overall_recommendation,
            "recommended_command": overall_command,
            "checks": checks,
        }
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def run_preflight_checks(
    args: argparse.Namespace,
    ssh: dict[str, str | int],
    telnet: dict[str, str | int],
    debug_dumper=None,
    *,
    ssh_runner=None,
    environment_cache=None,
    telnet_session=None,
    check_observer=None,
) -> dict[str, tuple]:
    def observe(name: str, future) -> None:
        if check_observer is None:
            return

        def publish(completed) -> None:
            try:
                result = completed.result()
            except Exception:
                return
            check_observer(name, result)

        future.add_done_callback(publish)

    selected = _selected_preflight_checks(args)
    with ThreadPoolExecutor(max_workers=max(1, min(4, len(selected)))) as executor:
        ssh_future = None
        if "SSH" in selected:
            ssh_future = executor.submit(
                check_ssh,
                args,
                ssh,
                debug_dumper,
                ssh_runner=ssh_runner,
            )
            observe("SSH", ssh_future)
        dbus_future = None
        if "DBUS_ENV" in selected:
            dbus_future = executor.submit(
                check_dbus_env,
                args,
                ssh,
                debug_dumper,
                ssh_runner=ssh_runner,
                environment_cache=environment_cache,
            )
            observe("DBUS_ENV", dbus_future)
        mdbctl_future = None
        if "MDBCTL" in selected:
            mdbctl_future = executor.submit(
                check_mdbctl,
                args,
                ssh,
                debug_dumper,
                ssh_runner=ssh_runner,
            )
            observe("MDBCTL", mdbctl_future)
        telnet_future = None
        if "TELNET" in selected:
            telnet_future = executor.submit(
                check_telnet,
                args,
                telnet,
                debug_dumper,
                session=telnet_session,
            )
            observe("TELNET", telnet_future)

        dbus_result = None
        busctl_future = None
        if dbus_future is not None:
            dbus_result = dbus_future.result()
            if "BUSCTL" in selected:
                busctl_future = executor.submit(
                    check_busctl,
                    args,
                    ssh,
                    dbus_result[2],
                    debug_dumper,
                    ssh_runner=ssh_runner,
                )
                observe("BUSCTL", busctl_future)
        ssh_result = ssh_future.result() if ssh_future is not None else None
        mdbctl_result = (
            mdbctl_future.result() if mdbctl_future is not None else None
        )
        telnet_result = telnet_future.result() if telnet_future is not None else None
        busctl_result = (
            busctl_future.result() if busctl_future is not None else None
        )

    results: dict[str, tuple] = {}
    if ssh_result is not None:
        results["SSH"] = ssh_result
    if dbus_result is not None:
        results["DBUS_ENV"] = dbus_result
    if mdbctl_result is not None:
        results["MDBCTL"] = mdbctl_result
    if busctl_result is not None:
        results["BUSCTL"] = busctl_result
    if telnet_result is not None:
        results["TELNET"] = telnet_result
    if telnet_result is not None and len(telnet_result) >= 3:
        transport_ok, lines, log_files_ok = telnet_result
        results["TELNET"] = (transport_ok, lines)
        if transport_ok:
            results["LOG_FILES"] = (
                log_files_ok,
                [line for line in lines if line.startswith("/var/log/")]
                or ["Default app.log/framework.log files were not found"],
            )
    return results


def build_checks(
    args: argparse.Namespace,
    raw_results: dict[str, tuple],
) -> dict[str, dict[str, object]]:
    checks: dict[str, dict[str, object]] = {}
    if "SSH" in raw_results:
        ok, lines = raw_results["SSH"]
        checks["SSH"] = build_check_result("SSH", ok, lines, args)

    if "DBUS_ENV" in raw_results:
        env_ok, env_lines, env = raw_results["DBUS_ENV"]
        checks["DBUS_ENV"] = build_check_result(
            "DBUS_ENV", env_ok, env_lines, args, env=env
        )
    if "MDBCTL" in raw_results:
        ok, lines = raw_results["MDBCTL"]
        checks["MDBCTL"] = build_check_result("MDBCTL", ok, lines, args)
    if "BUSCTL" in raw_results:
        ok, lines = raw_results["BUSCTL"]
        checks["BUSCTL"] = build_check_result("BUSCTL", ok, lines, args)

    if "TELNET" in raw_results:
        ok, lines = raw_results["TELNET"]
        checks["TELNET"] = build_check_result("TELNET", ok, lines, args)
    if "LOG_FILES" in raw_results:
        ok, lines = raw_results["LOG_FILES"]
        checks["LOG_FILES"] = build_check_result("LOG_FILES", ok, lines, args)
    if (
        "MDBCTL" in checks
        and checks["MDBCTL"]["code"] == "remote-command-unsupported"
    ):
        recommendation = RECOMMENDED_NEXT_STEPS["remote-command-unsupported"]
        for name in ("DBUS_ENV", "BUSCTL"):
            if name not in checks:
                continue
            if checks[name]["ok"]:
                continue
            checks[name]["blocked_by"] = "remote-command-unsupported"
            checks[name]["recommended_next_step"] = recommendation
            checks[name]["recommended_command"] = ""
    return checks


def refresh_preflight_checks(
    args: argparse.Namespace,
    ssh: dict[str, str | int],
    telnet: dict[str, str | int],
    base_checks: dict[str, dict[str, object]],
    debug_dumper=None,
    *,
    ssh_runner=None,
    telnet_session=None,
    check_observer=None,
) -> dict[str, dict[str, object]]:
    """Refresh clock/uptime anchors without repeating capability discovery."""

    selected = _selected_preflight_checks(args)
    checks = {
        name: copy.deepcopy(value)
        for name, value in base_checks.items()
        if name in selected or (name == "LOG_FILES" and "TELNET" in selected)
    }
    if "SSH" in selected:
        ssh_ok, ssh_lines = check_ssh(
            args,
            ssh,
            debug_dumper,
            ssh_runner=ssh_runner,
        )
        if check_observer is not None:
            check_observer("SSH", (ssh_ok, ssh_lines))
        checks["SSH"] = build_check_result("SSH", ssh_ok, ssh_lines, args)
    if "TELNET" in selected and "TELNET" in checks:
        telnet_ok, telnet_lines = check_telnet_time(
            args,
            telnet,
            debug_dumper,
            session=telnet_session,
        )
        if check_observer is not None:
            check_observer("TELNET", (telnet_ok, telnet_lines))
        checks["TELNET"] = build_check_result(
            "TELNET", telnet_ok, telnet_lines, args
        )
    return checks


def execute_preflight(
    args: argparse.Namespace,
    ssh: dict[str, str | int],
    telnet: dict[str, str | int],
    *,
    ssh_runner=None,
    telnet_session=None,
    object_alarm_lease=None,
    refresh_checks: dict[str, dict[str, object]] | None = None,
    check_observer=None,
) -> int:
    """Execute preflight against already-resolved task-scoped resources."""

    debug_dumper = build_debug_dumper(
        args.debug_dump,
        secrets=[str(ssh["password"]), str(telnet["password"])],
    )
    selected_ssh_runner = (
        object_alarm_lease.ssh_runner
        if object_alarm_lease is not None
        else ssh_runner
    )
    if refresh_checks is not None:
        checks = refresh_preflight_checks(
            args,
            ssh,
            telnet,
            refresh_checks,
            debug_dumper=debug_dumper,
            ssh_runner=selected_ssh_runner,
            telnet_session=telnet_session,
            check_observer=check_observer,
        )
    else:
        raw_results = run_preflight_checks(
            args,
            ssh,
            telnet,
            debug_dumper=debug_dumper,
            ssh_runner=selected_ssh_runner,
            environment_cache=(
                object_alarm_lease.get_dbus_environment
                if object_alarm_lease is not None
                else None
            ),
            telnet_session=telnet_session,
            check_observer=check_observer,
        )
        checks = build_checks(args, raw_results)

    status = summarize_preflight(args, checks)
    if args.json:
        emit_json_report(args, checks, status=status)
    else:
        for title, result in checks.items():
            print_section(title, str(result["status"]), list(result["lines"]))

    return int(status["returncode"])


def run_typed_preflight_one_shot(args: argparse.Namespace) -> int:
    """Resolve credentials once and reuse one SSH/Telnet lease for preflight."""

    _normalize_preflight_scope(args)
    credentials = resolve_debug_credentials(
        args,
        include_telnet=not args.skip_telnet,
    )
    args.timeout = max(
        args.ssh_timeout,
        args.telnet_connect_timeout,
        args.telnet_prompt_timeout,
    )
    with open_debug_runtime_lease(
        args=args,
        credential_bundle=credentials,
        task_id="debug-preflight-one-shot",
    ) as lease:
        return execute_preflight(
            args,
            lease.ssh_credentials_mapping(),
            lease.telnet_credentials_mapping(),
            object_alarm_lease=lease.object_alarm_lease,
            telnet_session=lease.telnet_session,
        )


def main(
    *,
    _args: argparse.Namespace | None = None,
    _ssh: dict[str, str | int] | None = None,
    _telnet: dict[str, str | int] | None = None,
    ssh_runner=None,
    telnet_session=None,
    object_alarm_lease=None,
    _refresh_checks: dict[str, dict[str, object]] | None = None,
    _check_observer=None,
) -> int:
    args = _args or parse_args()
    _normalize_preflight_scope(args)
    if (
        _args is None
        and _ssh is None
        and _telnet is None
        and ssh_runner is None
        and telnet_session is None
        and object_alarm_lease is None
        and _refresh_checks is None
    ):
        return run_typed_preflight_one_shot(args)
    ssh = _ssh or resolve_ssh_credentials(args)
    telnet = (
        {"user": "", "password": "", "port": args.telnet_port}
        if args.skip_telnet
        else (_telnet or resolve_telnet_credentials(args))
    )
    return execute_preflight(
        args,
        ssh,
        telnet,
        ssh_runner=ssh_runner,
        telnet_session=telnet_session,
        object_alarm_lease=object_alarm_lease,
        refresh_checks=_refresh_checks,
        check_observer=_check_observer,
    )


if __name__ == "__main__":
    raise SystemExit(main())
