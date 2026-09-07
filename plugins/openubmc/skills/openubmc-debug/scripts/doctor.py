#!/usr/bin/env python3
"""Diagnose local openUBMC remote-access setup for internal development."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import json
import os
import socket
import subprocess
import time
from pathlib import Path

from _cli_common import (
    OS_IP_ENV,
    OS_SSH_PASSWORD_ENV,
    OS_SSH_USER_ENV,
    load_credentials_file,
    resolve_os_access,
)
from _json_common import build_json_payload as build_common_json_payload
from _remote_common import (
    run_ssh,
    ssh_transport_details,
    ssh_transport_failure_code,
    ssh_transport_failure_message,
)

SCRIPT_DIR = Path(__file__).resolve().parent

# This is the only OS-side command doctor is allowed to execute.  Keep it
# fixed, bounded, and read-only: doctor diagnoses access; it is not a remote
# command runner.
OS_SMOKE_PROBE_NAME = "host_identity_and_pci_sample"
OS_SMOKE_PROBE_COMMAND = "hostname; lspci -nn | head -n 10"
OS_SMOKE_STDOUT_LIMIT_BYTES = 64 * 1024
OS_SMOKE_STDERR_LIMIT_BYTES = 64 * 1024


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Diagnose SSH/Telnet/proxy readiness for openUBMC debug sessions.")
    parser.add_argument("--ip", required=True, help="BMC IP")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port")
    parser.add_argument("--telnet-port", type=int, default=23, help="Telnet port")
    parser.add_argument("--attempts", type=int, default=3, help="Repeated TCP attempts per port")
    parser.add_argument("--timeout", type=float, default=3.0, help="Connect/read timeout seconds")
    parser.add_argument(
        "--os-check",
        action="store_true",
        help="Also run the fixed read-only OS SSH smoke probe using OPENUBMC_OS_*",
    )
    parser.add_argument("--os-timeout", type=float, default=8.0, help="OS host SSH timeout seconds")
    parser.add_argument("--os-ip", default="", help="OS host IP, otherwise OPENUBMC_OS_IP")
    parser.add_argument("--os-ip-env", default="", help="Environment variable holding OS host IP")
    parser.add_argument("--os-ssh-user", default="", help="OS SSH user, otherwise OPENUBMC_OS_SSH_USER")
    parser.add_argument("--os-ssh-user-env", default="", help="Environment variable holding OS SSH user")
    parser.add_argument("--os-ssh-password-env", default="", help="Environment variable holding OS SSH password")
    parser.add_argument("--os-ssh-password", default="", help="OS SSH password in development mode")
    parser.add_argument("--os-ssh-port", default="", help="OS SSH port, otherwise OPENUBMC_OS_SSH_PORT")
    parser.add_argument("--os-ssh-port-env", default="", help="Environment variable holding OS SSH port")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--compact-json", action="store_true", help="Emit one-line JSON (implies --json)")
    return parser.parse_args(argv)


def build_credentials_summary() -> dict[str, bool]:
    file_values = load_credentials_file()

    def configured(env_name: str) -> bool:
        if env_name in os.environ:
            return bool(os.environ[env_name])
        return bool(file_values.get(env_name, ""))

    return {
        "ssh_user_configured": configured("OPENUBMC_SSH_USER"),
        "ssh_password_configured": configured("OPENUBMC_SSH_PASSWORD"),
        "telnet_user_configured": configured("OPENUBMC_TELNET_USER"),
        "telnet_password_configured": configured("OPENUBMC_TELNET_PASSWORD"),
        "os_ip_configured": configured(OS_IP_ENV),
        "os_ssh_user_configured": configured(OS_SSH_USER_ENV),
        "os_ssh_password_configured": configured(OS_SSH_PASSWORD_ENV),
    }


def proxy_env_summary() -> dict[str, str]:
    keys = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"]
    return {
        key: os.environ[key]
        for key in keys
        if key in os.environ
    }


def run_text_command(cmd: list[str], timeout: float = 5.0) -> tuple[int, str]:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:  # pragma: no cover - platform dependent in live runs
        return 124, f"{type(exc).__name__}: {exc}"
    return cp.returncode, (cp.stdout + cp.stderr).strip()


def classify_os_ssh_failure(text: str, returncode: int) -> str:
    lowered = text.lower()
    if "permission denied" in lowered or "authentication failed" in lowered:
        return "os_ssh_auth_failed"
    if "timed out" in lowered or "connection timeout" in lowered or returncode == 124:
        return "os_ssh_tcp_timeout"
    if "no route to host" in lowered:
        return "os_ssh_no_route"
    if "could not resolve hostname" in lowered or "name or service not known" in lowered:
        return "os_ssh_name_error"
    if "connection refused" in lowered:
        return "os_ssh_connection_refused"
    if "sshpass" in lowered and ("not found" in lowered or "no such file" in lowered):
        return "os_sshpass_missing"
    return "os_ssh_failed"


def _missing_os_access_result(code: str, message: str) -> dict[str, object]:
    return {
        "status": "skipped",
        "code": code,
        "message": message,
        "stdout_lines": [],
        "stderr_lines": [],
    }


def run_os_ssh_smoke(os_access: dict[str, str | int], args: argparse.Namespace) -> dict[str, object]:
    ip = str(os_access.get("ip", ""))
    user = str(os_access.get("user", ""))
    password = str(os_access.get("password", ""))
    port = int(os_access.get("port", 22))
    if not ip:
        return _missing_os_access_result("os_ip_missing", "OPENUBMC_OS_IP is not configured")
    if not user:
        return _missing_os_access_result("os_ssh_user_missing", "OPENUBMC_OS_SSH_USER is not configured")
    if not password:
        return _missing_os_access_result("os_ssh_password_missing", "OPENUBMC_OS_SSH_PASSWORD is not configured")
    safe_command = [
        "ssh",
        "<credential-source:OPENUBMC_OS_SSH_PASSWORD>",
        "<host-key-policy:audited-in-transport>",
        f"<target-port:{port}>",
        f"<fixed-read-only-probe:{OS_SMOKE_PROBE_NAME}>",
    ]
    started = time.time()
    cp = run_ssh(
        ip,
        user,
        password,
        OS_SMOKE_PROBE_COMMAND,
        float(args.os_timeout),
        port=port,
        host_key_policy="strict",
        stdout_limit_bytes=OS_SMOKE_STDOUT_LIMIT_BYTES,
        stderr_limit_bytes=OS_SMOKE_STDERR_LIMIT_BYTES,
    )
    elapsed_ms = int((time.time() - started) * 1000)
    stdout = cp.stdout or ""
    stderr = cp.stderr or ""
    transport = ssh_transport_details(cp)
    transport_code = ssh_transport_failure_code(cp)
    if transport_code:
        return {
            "status": "failed",
            "code": transport_code,
            "returncode": cp.returncode,
            "elapsed_ms": elapsed_ms,
            "command": safe_command,
            "stdout_lines": [],
            "stderr_lines": [
                ssh_transport_failure_message(transport_code, "OS SSH smoke probe")
            ],
            "transport": transport,
        }
    if cp.returncode == 0:
        return {
            "status": "ok",
            "code": "ok",
            "returncode": 0,
            "elapsed_ms": elapsed_ms,
            "command": safe_command,
            "stdout_lines": stdout.splitlines(),
            "stderr_lines": stderr.splitlines(),
            "transport": transport,
        }
    combined = f"{stdout}\n{stderr}"
    code = classify_os_ssh_failure(combined, cp.returncode)
    return {
        "status": "failed",
        "code": code,
        "returncode": cp.returncode,
        "elapsed_ms": elapsed_ms,
        "command": safe_command,
        "stdout_lines": stdout.splitlines(),
        "stderr_lines": stderr.splitlines(),
        "transport": transport,
    }


def ssh_config_summary(ip: str) -> dict[str, str]:
    code, output = run_text_command(["ssh", "-G", ip], timeout=5)
    wanted = {
        "hostname",
        "port",
        "user",
        "identityfile",
        "proxycommand",
        "proxyjump",
    }
    result: dict[str, str] = {"command_returncode": str(code)}
    for line in output.splitlines():
        if not line.strip() or " " not in line:
            continue
        key, value = line.split(None, 1)
        normalized_key = key.lower()
        if normalized_key not in wanted:
            continue
        result[normalized_key] = value
    return result


def route_summary(ip: str) -> dict[str, str | int]:
    code, output = run_text_command(["ip", "route", "get", ip], timeout=5)
    return {"command_returncode": code, "text": output}


def attempt_tcp(ip: str, port: int, *, timeout: float, read_banner: bool = False) -> dict[str, object]:
    sock = socket.socket()
    sock.settimeout(timeout)
    started = time.time()
    try:
        sock.connect((ip, port))
        elapsed_ms = int((time.time() - started) * 1000)
        result: dict[str, object] = {"ok": True, "elapsed_ms": elapsed_ms}
        if read_banner:
            sock.settimeout(min(timeout, 1.0))
            try:
                banner = sock.recv(128).decode("utf-8", errors="replace").strip()
            except Exception as exc:
                banner = f"recv-{type(exc).__name__}: {exc}"
            result["banner"] = banner
        return result
    except Exception as exc:
        elapsed_ms = int((time.time() - started) * 1000)
        return {"ok": False, "elapsed_ms": elapsed_ms, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        sock.close()


def summarize_port_attempts(attempts: list[dict[str, object]]) -> dict[str, object]:
    ok_count = sum(1 for item in attempts if item.get("ok"))
    failure_count = len(attempts) - ok_count
    if ok_count == len(attempts):
        status = "ok"
    elif ok_count == 0:
        status = "failed"
    else:
        status = "flaky"
    banner_sample = next((str(item.get("banner", "")) for item in attempts if item.get("banner")), "")
    return {
        "status": status,
        "attempt_count": len(attempts),
        "ok_count": ok_count,
        "failure_count": failure_count,
        "banner_sample": banner_sample,
        "attempts": attempts,
    }


def diagnose_ports(args: argparse.Namespace) -> dict[str, dict[str, object]]:
    attempts = max(1, args.attempts)
    return {
        "ssh": summarize_port_attempts([
            attempt_tcp(args.ip, args.ssh_port, timeout=args.timeout, read_banner=True)
            for _ in range(attempts)
        ]),
        "telnet": summarize_port_attempts([
            attempt_tcp(args.ip, args.telnet_port, timeout=args.timeout, read_banner=False)
            for _ in range(attempts)
        ]),
    }


def build_report(args: argparse.Namespace) -> dict[str, object]:
    ports = diagnose_ports(args)
    credentials = build_credentials_summary()
    route = route_summary(args.ip)
    ssh_config = ssh_config_summary(args.ip)
    proxy_env = proxy_env_summary()
    warnings: list[str] = []
    if ssh_config.get("proxycommand", "none") != "none" or ssh_config.get("proxyjump", "none") != "none":
        warnings.append("ssh_config_proxy_enabled")
    if ports["ssh"]["status"] == "flaky" or ports["telnet"]["status"] == "flaky":
        warnings.append("tcp_connectivity_flaky")
    if getattr(args, "os_check", False):
        os_ssh = run_os_ssh_smoke(resolve_os_access(args), args)
        if os_ssh.get("status") != "ok":
            warnings.append(str(os_ssh.get("code", "os_ssh_failed")))
    else:
        os_ssh = {"status": "not_requested", "code": "not_requested"}
    return {
        "credentials": credentials,
        "proxy_env": proxy_env,
        "ssh_config": ssh_config,
        "route": route,
        "ports": ports,
        "os_ssh": os_ssh,
        "warnings": warnings,
    }


def print_text_report(report: dict[str, object]) -> None:
    print("[credentials]")
    for key, value in dict(report["credentials"]).items():
        print(f"  {key}: {value}")
    print("[ports]")
    ports = dict(report["ports"])
    for name in ["ssh", "telnet"]:
        item = dict(ports[name])
        print(f"  {name}: {item['status']} ({item['ok_count']}/{item['attempt_count']} ok)")
        if item.get("banner_sample"):
            print(f"    banner: {item['banner_sample']}")
    print("[route]")
    print(f"  {dict(report['route']).get('text', '')}")
    print("[os_ssh]")
    os_ssh = dict(report.get("os_ssh", {}))
    print(f"  {os_ssh.get('status', 'not_requested')}: {os_ssh.get('code', 'not_requested')}")
    print("[warnings]")
    for warning in list(report["warnings"]):
        print(f"  {warning}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = build_report(args)
    ok = not report["warnings"] and all(dict(item)["status"] == "ok" for item in dict(report["ports"]).values())
    if args.json or args.compact_json:
        payload = build_common_json_payload(
            tool="doctor",
            ip=args.ip,
            ok=ok,
            code="ok" if ok else "doctor_warnings",
            returncode=0 if ok else 1,
            warnings=list(report["warnings"]),
            request={
                "ssh_port": args.ssh_port,
                "telnet_port": args.telnet_port,
                "attempts": args.attempts,
                "os_check": args.os_check,
                "os_probe": OS_SMOKE_PROBE_NAME if args.os_check else "",
            },
            result=report,
        )
        if args.compact_json:
            print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        else:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print_text_report(report)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
