#!/usr/bin/env python3
"""Pull an openUBMC one-click log bundle from a remote host."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import bz2
import datetime as dt
import getpass
import gzip
import ipaddress
import json
import lzma
import os
import pathlib
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import zlib
from dataclasses import dataclass, field
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request


DEFAULT_SEARCH_ROOTS = ["/tmp", "/var/tmp", "/data", "/home", "/opt"]
DEFAULT_NAME_GLOBS = [
    "*openUBMC*.tar.gz",
    "*openUBMC*.tar",
    "*oneclick*.tar.gz",
    "*dump*.tar.gz",
    "*log*.tar.gz",
]

_SECRET_ENV_NAME_TOKENS = (
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "SECRET",
    "TOKEN",
    "AUTHORIZATION",
    "COOKIE",
    "API_KEY",
    "APIKEY",
)


def sanitized_transport_environment() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if not any(token in name.upper() for token in _SECRET_ENV_NAME_TOKENS)
        and name != "SSHPASS"
    }
PATH_MARKER = "BUNDLE_PATH="
SCHEMA_VERSION = "1.0"
DEFAULT_REDFISH_BUNDLE_DIR = "/tmp"
DEFAULT_ANALYSIS_MAX_FILES = 8
DEFAULT_ANALYSIS_MAX_LINES = 3
DEFAULT_ANALYSIS_MAX_PATHS = 10
DEFAULT_EXTRACT_MAX_MEMBERS = 10_000
DEFAULT_EXTRACT_MAX_BYTES = 512 * 1024 * 1024
RETRYABLE_POLL_TOKENS = (
    "UNEXPECTED_EOF_WHILE_READING",
    "EOF occurred in violation of protocol",
    "Connection reset by peer",
    "Remote end closed connection without response",
    "Connection timed out",
    "Operation timed out",
    "The read operation timed out",
    "SSL_ERROR_SYSCALL",
    "timed out",
)
RETRYABLE_GATEWAY_HTTP_STATUS_TOKENS = (
    "HTTP 502",
    "HTTP 503",
    "HTTP 504",
)


class BundlePullError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ExtractionResult:
    extract_dir: pathlib.Path
    bundle_root: pathlib.Path


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True)
class RedfishSession:
    base_url: str
    token: str
    session_path: str
    proxy_mode: str = "auto"


@dataclass(frozen=True)
class BundleStageResult:
    remote_bundle_path: str
    local_bundle_path: pathlib.Path
    generation_ran: bool
    transport: str


def resolve_value(default_value: str, env_name: str, label: str) -> str:
    if env_name:
        if env_name not in os.environ:
            raise BundlePullError("missing_env", f"{label} 环境变量 {env_name} 未设置")
        return os.environ[env_name]
    return default_value


def resolve_secret(
    default_value: str,
    env_name: str,
    label: str,
    *,
    json_mode: bool,
    allow_empty: bool = False,
) -> str:
    if env_name:
        if env_name not in os.environ:
            raise BundlePullError("missing_env", f"{label} 环境变量 {env_name} 未设置")
        value = os.environ[env_name]
        if value or allow_empty:
            return value
        raise BundlePullError("missing_secret", f"{label} 环境变量 {env_name} 为空")
    if default_value:
        return default_value
    if allow_empty:
        return ""
    if json_mode:
        raise BundlePullError("missing_secret", f"JSON 模式必须提供 {label}；请显式传参或使用环境变量。")
    try:
        value = getpass.getpass(f"{label}: ")
    except EOFError as exc:
        raise BundlePullError("missing_secret", f"{label} 为必填。") from exc
    if not value:
        raise BundlePullError("missing_secret", f"{label} 为必填。")
    return value


def resolve_ip(ip: str, *, json_mode: bool) -> str:
    candidate = ip.strip()
    if candidate:
        return candidate
    if json_mode:
        raise BundlePullError("missing_ip", "JSON 模式必须显式传 --ip，因为交互输入已禁用。")
    try:
        candidate = input("目标 BMC IP 或主机名: ").strip()
    except EOFError as exc:
        raise BundlePullError("missing_ip", "必须提供目标 BMC IP 或主机名；请传 --ip 或按提示交互输入。") from exc
    if not candidate:
        raise BundlePullError("missing_ip", "必须提供目标 BMC IP 或主机名；请传 --ip 或按提示交互输入。")
    return candidate


def parse_remote_bundle_path(output: str) -> str:
    marker_matches: list[str] = []
    archive_matches: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip().strip("'\"")
        if not line:
            continue
        if line.startswith(PATH_MARKER):
            candidate = line[len(PATH_MARKER) :].strip().strip("'\"")
            if candidate:
                marker_matches.append(candidate)
            continue
        if line.startswith("/") and (line.endswith(".tar") or line.endswith(".tar.gz")):
            archive_matches.append(line)
    if marker_matches:
        return marker_matches[-1]
    if archive_matches:
        return archive_matches[-1]
    return ""


def decode_json_bytes(body: bytes) -> dict[str, object]:
    if not body:
        return {}
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundlePullError("redfish_bad_json", f"Failed to decode JSON response: {exc}") from exc
    if not isinstance(parsed, dict):
        raise BundlePullError("redfish_bad_json", "Expected a JSON object from Redfish response.")
    return parsed


def _analysis_core():
    """Resolve the same sibling core in source and immutable plugin layouts."""
    directory = pathlib.Path(__file__).resolve().parents[2] / "openubmc-log-bundle-analyzer" / "scripts"
    if not directory.is_dir():
        directory = pathlib.Path(__file__).resolve().parent / "_vendor/log_bundle_analyzer/scripts"
    sys.path.insert(0, str(directory))
    try:
        import log_bundle_analysis
        return log_bundle_analysis
    finally:
        sys.path.remove(str(directory))


def _reference_for_core(reference):
    # Legacy metadata lacks provenance; keep it explicitly unclassified.
    files = [
        dict(item, purpose=item.get("purpose", "Legacy caller log candidate"),
             component=item.get("component", "unknown"))
        if isinstance(item, dict) else item for item in reference.get("files", [])]
    for item in files:
        if isinstance(item, dict) and item.get("paths") and all(
                str(path).endswith(".log.gz") for path in item["paths"]):
            item.setdefault("artifact_format", "text")
    rules = reference.get("rules", [])
    if not rules:
        rules = [{"match_keywords": item["keywords"], "include": [item["name"]]}
                 for item in files if isinstance(item, dict) and item.get("keywords")]
    return dict(reference, rules=rules, files=files)


def load_reference_data(reference_path=None):
    return _analysis_core().load_reference_data(reference_path)


def parse_analysis_time_bound(value, *, label):
    try:
        return _analysis_core().parse_analysis_time_bound(value, label=label)
    except _analysis_core().BundleAnalysisError as error:
        raise BundlePullError(error.code, str(error)) from None


def comparable_datetime(value):
    return value.replace(tzinfo=dt.timezone.utc) if value.tzinfo is None else value.astimezone(dt.timezone.utc)


def parse_log_timestamp(line):
    return _analysis_core().parse_log_timestamp(line)


def select_logs_for_problem(problem, reference_data, *, max_files):
    return _analysis_core().select_logs_for_problem(
        problem, _analysis_core().normalize_reference_data(_reference_for_core(reference_data)),
        max_files=max_files)


def expand_log_paths(bundle_root, path_patterns):
    return _analysis_core().expand_log_paths(bundle_root, path_patterns)


def collect_evidence_lines(file_path, **kwargs):
    return _analysis_core().collect_evidence_lines(file_path, **kwargs)


@dataclass
class AnalysisBudget:
    """Compatibility receipt; reading remains owned by the shared analyzer."""
    max_bytes: int = 64 * 1024 * 1024
    max_line_bytes: int = 64 * 1024
    scanned_bytes: int = 0
    reasons: set[str] = field(default_factory=set)

    def receipt(self):
        return {"complete": not self.reasons, "reasons": sorted(self.reasons),
                "scanned_bytes": self.scanned_bytes}


def _coverage(scan):
    codes = {str(item.get("code")) for item in [*scan.get("errors", []), *scan.get("warnings", [])]}
    aliases = {"file_scan_truncated": "scan_bytes_exceeded",
               "scan_byte_limit_reached": "scan_bytes_exceeded",
               "total_scan_byte_limit_reached": "scan_bytes_exceeded",
               "line_too_long": "line_bytes_exceeded",
               "log_read_failed": "file_read_failed",
               "scan_file_limit_reached": "scan_files_exceeded",
               "path_discovery_limit_reached": "discovery_entries_exceeded"}
    reasons = {aliases.get(code, code) for code in codes}
    if not scan.get("complete", True) and not reasons:
        reasons.add("analysis_incomplete")
    return {"complete": scan.get("complete", False), "reasons": sorted(reasons),
            "scanned_bytes": scan.get("scanned_bytes", 0),
            "scanned_files": scan.get("scanned_path_count", 0),
            "discovered_entries": scan.get("path_discovery", {}).get("entries_examined", 0)}


def iter_text_lines(path, budget=None):
    budget = budget or AnalysisBudget()
    diagnostics = {}
    try:
        for _number, line in _analysis_core().iter_text_lines(
            path, max_bytes=max(0, budget.max_bytes - budget.scanned_bytes),
            max_line_bytes=budget.max_line_bytes, diagnostics=diagnostics):
            yield line
    finally:
        budget.scanned_bytes += diagnostics.get("bytes_read", 0)
        budget.reasons.update(_coverage(dict(diagnostics, complete=True))["reasons"])


def analyze_bundle(bundle_root, problem, *, reference_data=None,
                   max_files=DEFAULT_ANALYSIS_MAX_FILES, max_lines=DEFAULT_ANALYSIS_MAX_LINES,
                   since=None, until=None, scan_max_bytes=64 * 1024 * 1024,
                   max_line_bytes=64 * 1024, scan_max_files=512, discovery_max_entries=20_000):
    """Compatibility adapter: one scan, one catalog and one evidence implementation."""
    core = _analysis_core()
    try:
        result = core.analyze_bundle(
            bundle_root, problem,
            reference_data=_reference_for_core(reference_data) if reference_data is not None else None,
            max_files=max_files, max_lines=max_lines, since=since, until=until,
            max_total_bytes=scan_max_bytes, max_bytes_per_file=scan_max_bytes,
            max_paths_per_log=4096, max_line_bytes=max_line_bytes,
            max_scan_files=scan_max_files, max_discovery_entries=discovery_max_entries)
    except core.BundleAnalysisError as error:
        raise BundlePullError(error.code, str(error)) from None
    result["coverage"] = _coverage(result["scan"])
    return result


def build_remote_shell(inner: str) -> str:
    return "sh -lc " + shlex.quote(inner)


def build_discovery_command(search_roots: list[str], name_globs: list[str]) -> str:
    if not search_roots:
        raise BundlePullError("invalid_request", "At least one search root is required")
    if not name_globs:
        raise BundlePullError("invalid_request", "At least one name glob is required")
    roots = " ".join(shlex.quote(root) for root in search_roots)
    pattern_terms = " -o ".join(f"-name {shlex.quote(name_glob)}" for name_glob in name_globs)
    inner = (
        "set -eu; "
        f"find {roots} -type f \\( {pattern_terms} \\) -print0 2>/dev/null "
        "| xargs -0 -r ls -1t 2>/dev/null | head -n 1"
    )
    return build_remote_shell(inner)


def build_ssh_command(
    ip: str,
    user: str,
    password: str,
    port: int,
    identity_file: str,
    remote_command: str,
) -> list[str]:
    command: list[str] = []
    if password:
        if not shutil.which("sshpass"):
            raise BundlePullError("sshpass_missing", "sshpass not found; install it or use key-based auth")
        command.extend(["sshpass", "-d", "0"])
    command.extend(
        [
            "ssh",
            "-p",
            str(port),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
        ]
    )
    if identity_file:
        command.extend(["-i", identity_file, "-o", "IdentitiesOnly=yes"])
    command.extend([f"{user}@{ip}", remote_command])
    return command


def build_scp_command(
    ip: str,
    user: str,
    password: str,
    port: int,
    identity_file: str,
    remote_path: str,
    local_path: pathlib.Path,
) -> list[str]:
    command: list[str] = []
    if password:
        if not shutil.which("sshpass"):
            raise BundlePullError("sshpass_missing", "sshpass not found; install it or use key-based auth")
        command.extend(["sshpass", "-d", "0"])
    command.extend(
        [
            "scp",
            "-P",
            str(port),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
        ]
    )
    if identity_file:
        command.extend(["-i", identity_file, "-o", "IdentitiesOnly=yes"])
    command.extend([f"{user}@{ip}:{remote_path}", str(local_path)])
    return command


def build_base_url(ip: str, port: int) -> str:
    host = ip.strip()
    if not host:
        raise BundlePullError("missing_ip", "Target host IP or hostname is required.")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if port == 443:
        return f"https://{host}"
    return f"https://{host}:{port}"


def is_management_address(address: ipaddress._BaseAddress) -> bool:
    return any(
        [
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_reserved,
            address.is_unspecified,
        ]
    )


def resolve_host_addresses(host: str) -> list[ipaddress._BaseAddress]:
    addresses: list[ipaddress._BaseAddress] = []
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return addresses
    for record in records:
        sockaddr = record[4]
        if not sockaddr:
            continue
        try:
            addresses.append(ipaddress.ip_address(str(sockaddr[0])))
        except ValueError:
            continue
    return addresses


def should_bypass_proxy(url: str, *, proxy_mode: str = "auto") -> bool:
    if proxy_mode == "disable":
        return True
    if proxy_mode == "inherit":
        return False
    host = urllib_parse.urlparse(url).hostname
    if not host:
        return False
    if host.casefold() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return any(is_management_address(address) for address in resolve_host_addresses(host))
    return is_management_address(address)


def open_urllib_request(
    request: urllib_request.Request,
    *,
    url: str,
    timeout: int,
    ssl_context: ssl.SSLContext,
    proxy_mode: str = "auto",
):
    if should_bypass_proxy(url, proxy_mode=proxy_mode):
        opener = urllib_request.build_opener(
            urllib_request.ProxyHandler({}),
            urllib_request.HTTPSHandler(context=ssl_context),
            urllib_request.HTTPHandler(),
        )
        return opener.open(request, timeout=timeout)
    return urllib_request.urlopen(request, timeout=timeout, context=ssl_context)


def http_request(
    *,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    json_body: dict[str, object] | None = None,
    timeout: int,
    error_code: str,
    failure_message: str,
    proxy_mode: str = "auto",
) -> HttpResponse:
    request_headers = dict(headers or {})
    body: bytes | None = None
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib_request.Request(url, data=body, headers=request_headers, method=method)
    ssl_context = ssl._create_unverified_context()
    try:
        with open_urllib_request(request, url=url, timeout=timeout, ssl_context=ssl_context, proxy_mode=proxy_mode) as response:
            return HttpResponse(
                status=response.status,
                headers={key: value for key, value in response.headers.items()},
                body=response.read(),
            )
    except urllib_error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace").strip()
        suffix = f": HTTP {exc.code}" if exc.code else ""
        if detail:
            suffix = f"{suffix}: {detail}" if suffix else f": {detail}"
        raise BundlePullError(error_code, f"{failure_message}{suffix}") from exc
    except urllib_error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        detail = str(reason)
        retry_exc = BundlePullError(error_code, f"{failure_message}: {detail}")
        if is_retryable_transport_error(retry_exc) and shutil.which("curl"):
            return curl_http_request(
                method=method,
                url=url,
                headers=request_headers,
                json_body=json_body,
                timeout=timeout,
                error_code=error_code,
                failure_message=failure_message,
                proxy_mode=proxy_mode,
            )
        raise BundlePullError(error_code, f"{failure_message}: {reason}") from exc


def parse_curl_response(header_text: str) -> tuple[int, dict[str, str]]:
    sections: list[list[str]] = []
    current: list[str] = []
    for raw_line in header_text.replace("\r", "").splitlines():
        line = raw_line.rstrip()
        if not line:
            if current:
                sections.append(current)
                current = []
            continue
        current.append(line)
    if current:
        sections.append(current)
    if not sections:
        raise BundlePullError("curl_parse_failed", "curl did not return HTTP response headers.")
    final = sections[-1]
    status_line = final[0]
    try:
        status = int(status_line.split()[1])
    except (IndexError, ValueError) as exc:
        raise BundlePullError("curl_parse_failed", f"Failed to parse curl status line: {status_line}") from exc
    headers: dict[str, str] = {}
    for line in final[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    return status, headers


def curl_http_request(
    *,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    json_body: dict[str, object] | None = None,
    timeout: int,
    error_code: str,
    failure_message: str,
    proxy_mode: str = "auto",
) -> HttpResponse:
    with tempfile.TemporaryDirectory(prefix="openubmc-curl-") as tmp_dir:
        tmp_path = pathlib.Path(tmp_dir)
        header_path = tmp_path / "headers.txt"
        body_path = tmp_path / "body.bin"
        request_body_path = tmp_path / "request.json"
        command = [
            "curl",
            "-sS",
            "-k",
            "-D",
            str(header_path),
            "-o",
            str(body_path),
            "-X",
            method,
            "--max-time",
            str(timeout),
        ]
        if should_bypass_proxy(url, proxy_mode=proxy_mode):
            command.extend(["--noproxy", "*"])
        for key, value in (headers or {}).items():
            command.extend(["-H", f"{key}: {value}"])
        if json_body is not None:
            request_body_path.write_text(json.dumps(json_body), encoding="utf-8")
            command.extend(["-H", "Content-Type: application/json", "--data-binary", f"@{request_body_path}"])
        command.append(url)
        completed = subprocess.run(command, capture_output=True, text=True)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            suffix = f": {detail}" if detail else ""
            raise BundlePullError(error_code, f"{failure_message}{suffix}")
        status, parsed_headers = parse_curl_response(header_path.read_text(encoding="utf-8", errors="replace"))
        body = body_path.read_bytes()
        if status >= 400:
            detail = body.decode("utf-8", errors="replace").strip()
            suffix = f": HTTP {status}"
            if detail:
                suffix = f"{suffix}: {detail}"
            raise BundlePullError(error_code, f"{failure_message}{suffix}")
        return HttpResponse(status=status, headers=parsed_headers, body=body)


def redfish_request(
    session: RedfishSession,
    *,
    path: str,
    method: str = "GET",
    json_body: dict[str, object] | None = None,
    timeout: int,
    error_code: str,
    failure_message: str,
) -> HttpResponse:
    url = path if path.startswith("https://") else urllib_parse.urljoin(session.base_url, path)
    headers = {"X-Auth-Token": session.token} if session.token else {}
    retries = 2 if method in {"GET", "DELETE"} else 0
    attempt = 0
    while True:
        try:
            return http_request(
                method=method,
                url=url,
                headers=headers,
                json_body=json_body,
                timeout=timeout,
                error_code=error_code,
                failure_message=failure_message,
                proxy_mode=session.proxy_mode,
            )
        except BundlePullError as exc:
            attempt += 1
            if attempt > retries or not is_retryable_transport_error(exc):
                raise
            time.sleep(1)


def redfish_request_json(
    session: RedfishSession,
    *,
    path: str,
    method: str = "GET",
    json_body: dict[str, object] | None = None,
    timeout: int,
    error_code: str = "redfish_request_failed",
    failure_message: str = "Redfish request failed",
) -> dict[str, object]:
    response = redfish_request(
        session,
        path=path,
        method=method,
        json_body=json_body,
        timeout=timeout,
        error_code=error_code,
        failure_message=failure_message,
    )
    return decode_json_bytes(response.body)


def redfish_create_session(*, ip: str, user: str, password: str, port: int, timeout: int, proxy_mode: str = "auto") -> RedfishSession:
    base_url = build_base_url(ip, port)
    for attempt in range(4):
        try:
            response = http_request(
                method="POST",
                url=urllib_parse.urljoin(base_url, "/redfish/v1/SessionService/Sessions"),
                json_body={"UserName": user, "Password": password},
                timeout=timeout,
                error_code="redfish_auth_failed",
                failure_message="Failed to create Redfish session",
                proxy_mode=proxy_mode,
            )
            break
        except BundlePullError as exc:
            if attempt >= 3 or not is_retryable_redfish_auth_error(exc):
                raise
            time.sleep(1)
    token = response.headers.get("X-Auth-Token", "").strip()
    session_path = response.headers.get("Location", "").strip()
    if not token or not session_path:
        raise BundlePullError("redfish_auth_failed", "Redfish session response did not contain X-Auth-Token and Location.")
    return RedfishSession(base_url=base_url, token=token, session_path=session_path, proxy_mode=proxy_mode)


def redfish_delete_session(session: RedfishSession, *, timeout: int) -> None:
    redfish_request(
        session,
        path=session.session_path,
        method="DELETE",
        timeout=timeout,
        error_code="redfish_logout_failed",
        failure_message="Failed to delete Redfish session",
    )


def select_redfish_action_target(manager_payload: dict[str, object], action: str) -> str:
    oem_actions = (
        manager_payload.get("Actions", {})
        .get("Oem", {})
        .get("openUBMC", {})
    )
    if not isinstance(oem_actions, dict):
        raise BundlePullError("redfish_action_missing", "Manager Actions.Oem.openUBMC is missing.")
    candidates = {
        "dump": ["#Manager.Dump", "#Manager.CollectAllLog"],
        "quickdump": ["#Manager.QuickDump"],
    }.get(action, [])
    for key in candidates:
        target = oem_actions.get(key, {}).get("target")
        if isinstance(target, str) and target:
            return target
    raise BundlePullError("redfish_action_missing", f"Redfish action target for {action} was not found.")


def select_redfish_general_download_target(manager_payload: dict[str, object]) -> str:
    oem_actions = (
        manager_payload.get("Actions", {})
        .get("Oem", {})
        .get("openUBMC", {})
    )
    if not isinstance(oem_actions, dict):
        raise BundlePullError("redfish_action_missing", "Manager Actions.Oem.openUBMC is missing.")
    target = oem_actions.get("#Manager.GeneralDownload", {}).get("target")
    if isinstance(target, str) and target:
        return target
    raise BundlePullError("redfish_action_missing", "Redfish GeneralDownload action target was not found.")


def extract_redfish_task_path(response: HttpResponse) -> str:
    body = decode_json_bytes(response.body)
    task_path = body.get("@odata.id")
    if isinstance(task_path, str) and task_path:
        return task_path
    location = response.headers.get("Location", "").strip()
    if location.endswith("/Monitor"):
        return location[: -len("/Monitor")]
    if location:
        return location
    raise BundlePullError("redfish_task_missing", "Redfish task response did not contain a task path.")


def extract_redfish_task_message(task_payload: dict[str, object]) -> str:
    messages = task_payload.get("Messages")
    if isinstance(messages, dict):
        message = messages.get("Message")
        if isinstance(message, str) and message:
            return message
    if isinstance(messages, list):
        texts: list[str] = []
        for item in messages:
            if isinstance(item, dict):
                message = item.get("Message")
                if isinstance(message, str) and message:
                    texts.append(message)
        if texts:
            return "; ".join(texts)
    return ""


def build_redfish_bundle_path(action: str) -> str:
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    suffix = "quickdump" if action == "quickdump" else "dump"
    return f"{DEFAULT_REDFISH_BUNDLE_DIR}/codex_{suffix}_{timestamp}.tar.gz"


def parse_content_disposition_filename(headers: dict[str, str]) -> str:
    disposition = ""
    for key, value in headers.items():
        if key.lower() == "content-disposition":
            disposition = value
            break
    if not disposition:
        return ""
    for part in disposition.split(";"):
        part = part.strip()
        if part.lower().startswith("filename="):
            return part.split("=", 1)[1].strip().strip('"')
    return ""


def is_retryable_redfish_poll_error(exc: BundlePullError) -> bool:
    if exc.code != "redfish_task_poll_failed":
        return False
    return is_retryable_transport_error(exc)


def is_retryable_transport_error(exc: BundlePullError) -> bool:
    message = exc.message.casefold()
    return any(token.casefold() in message for token in RETRYABLE_POLL_TOKENS)


def is_retryable_redfish_auth_error(exc: BundlePullError) -> bool:
    if exc.code != "redfish_auth_failed":
        return False
    if is_retryable_transport_error(exc):
        return True
    message = exc.message.casefold()
    return any(token.casefold() in message for token in RETRYABLE_GATEWAY_HTTP_STATUS_TOKENS)


def should_fallback_quickdump_to_dump(exc: BundlePullError, *, requested_action: str) -> bool:
    return (
        requested_action == "quickdump"
        and exc.code == "redfish_collect_failed"
        and "featuredisabledandnotsupportoperation" in exc.message.casefold()
    )


def redfish_wait_for_task(
    session: RedfishSession,
    task_path: str,
    *,
    timeout: int,
    poll_interval: int,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    transient_failures = 0
    while True:
        try:
            task_payload = redfish_request_json(
                session,
                path=task_path,
                timeout=min(timeout, max(poll_interval + 5, 10)),
                error_code="redfish_task_poll_failed",
                failure_message="Failed to poll Redfish task",
            )
        except BundlePullError as exc:
            if is_retryable_redfish_poll_error(exc) and transient_failures < 3 and time.monotonic() < deadline:
                transient_failures += 1
                time.sleep(poll_interval)
                continue
            raise
        task_state = str(task_payload.get("TaskState", "")).strip()
        if task_state == "Completed":
            return task_payload
        if task_state in {"Exception", "Killed", "Cancelled", "Interrupted"}:
            message = extract_redfish_task_message(task_payload) or f"Task ended in state {task_state}"
            raise BundlePullError("redfish_task_failed", message)
        if time.monotonic() >= deadline:
            raise BundlePullError("redfish_task_timeout", f"Redfish task did not finish within {timeout}s.")
        time.sleep(poll_interval)


def redfish_download_bundle(
    session: RedfishSession,
    *,
    target: str,
    remote_path: str,
    local_dir: pathlib.Path,
    timeout: int,
) -> pathlib.Path:
    response = redfish_request(
        session,
        path=target,
        method="POST",
        json_body={"TransferProtocol": "HTTPS", "Path": remote_path},
        timeout=timeout,
        error_code="redfish_download_failed",
        failure_message="Failed to download bundle via Redfish",
    )
    local_dir.mkdir(parents=True, exist_ok=True)
    filename = parse_content_disposition_filename(response.headers) or pathlib.Path(remote_path).name or f"openubmc-redfish-{int(time.time())}.tar.gz"
    local_path = local_dir / filename
    local_path.write_bytes(response.body)
    return local_path


def run_checked(
    command: list[str],
    timeout: int,
    error_code: str,
    failure_message: str,
    *,
    secret_input: str = "",
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=sanitized_transport_environment(),
            input=(secret_input + "\n" if secret_input else None),
        )
    except subprocess.TimeoutExpired as exc:
        raise BundlePullError(error_code, f"{failure_message}: timed out after {timeout}s") from exc
    if completed.returncode != 0:
        stderr = (completed.stderr or completed.stdout or "").strip()
        detail = f": {stderr}" if stderr else ""
        raise BundlePullError(error_code, f"{failure_message}{detail}")
    return completed


def download_remote_bundle(
    *,
    ip: str,
    user: str,
    password: str,
    port: int,
    identity_file: str,
    remote_path: str,
    local_dir: pathlib.Path,
    timeout: int,
) -> pathlib.Path:
    local_dir.mkdir(parents=True, exist_ok=True)
    filename = pathlib.Path(remote_path).name or f"openubmc-bundle-{int(time.time())}.tar.gz"
    local_path = local_dir / filename
    command = build_scp_command(
        ip=ip,
        user=user,
        password=password,
        port=port,
        identity_file=identity_file,
        remote_path=remote_path,
        local_path=local_path,
    )
    run_checked(
        command,
        timeout=timeout,
        error_code="bundle_download_failed",
        failure_message="Failed to download remote bundle",
        secret_input=password,
    )
    return local_path


def run_ssh_bundle_flow(
    args: argparse.Namespace,
    *,
    ip: str,
    local_dir: pathlib.Path,
    search_roots: list[str],
    name_globs: list[str],
) -> BundleStageResult:
    ssh_user = resolve_value(args.ssh_user, args.ssh_user_env, "SSH 用户名")
    ssh_password = resolve_secret(
        args.ssh_password,
        args.ssh_password_env,
        "SSH 密码",
        json_mode=getattr(args, "json", False),
        allow_empty=bool(args.ssh_identity_file),
    )
    remote_bundle_path = args.remote_path.strip()
    generation_ran = False

    if args.remote_command:
        generation_ran = True
        generate_command = build_ssh_command(
            ip=ip,
            user=ssh_user,
            password=ssh_password,
            port=args.ssh_port,
            identity_file=args.ssh_identity_file,
            remote_command=build_remote_shell(args.remote_command),
        )
        generated = run_checked(
            generate_command,
            timeout=args.generate_timeout,
            error_code="remote_collect_failed",
            failure_message="Failed to generate remote bundle",
            secret_input=ssh_password,
        )
        remote_bundle_path = parse_remote_bundle_path(f"{generated.stdout}\n{generated.stderr}") or remote_bundle_path

    if not remote_bundle_path:
        discover_command = build_ssh_command(
            ip=ip,
            user=ssh_user,
            password=ssh_password,
            port=args.ssh_port,
            identity_file=args.ssh_identity_file,
            remote_command=build_discovery_command(search_roots, name_globs),
        )
        discovered = run_checked(
            discover_command,
            timeout=args.search_timeout,
            error_code="bundle_discovery_failed",
            failure_message="Failed to discover remote bundle",
            secret_input=ssh_password,
        )
        remote_bundle_path = parse_remote_bundle_path(discovered.stdout or "")

    if not remote_bundle_path:
        raise BundlePullError(
            "remote_bundle_not_found",
            "No remote bundle was found. Provide --remote-path or --remote-command, or widen --search-root/--name-glob.",
        )

    local_bundle_path = download_remote_bundle(
        ip=ip,
        user=ssh_user,
        password=ssh_password,
        port=args.ssh_port,
        identity_file=args.ssh_identity_file,
        remote_path=remote_bundle_path,
        local_dir=local_dir,
        timeout=args.download_timeout,
    )
    return BundleStageResult(
        remote_bundle_path=remote_bundle_path,
        local_bundle_path=local_bundle_path,
        generation_ran=generation_ran,
        transport="ssh",
    )


def run_redfish_bundle_flow_with_session(
    args: argparse.Namespace,
    *,
    ip: str,
    local_dir: pathlib.Path,
    session: RedfishSession,
    manager_payload: dict[str, object] | None = None,
) -> BundleStageResult:
    redfish_timeout = getattr(args, "redfish_timeout", 60)
    redfish_action = getattr(args, "redfish_action", "dump")
    redfish_manager_id = getattr(args, "redfish_manager_id", "1")
    redfish_task_timeout = getattr(args, "redfish_task_timeout", 900)
    redfish_poll_interval = getattr(args, "redfish_poll_interval", 5)
    if manager_payload is None:
        manager_payload = redfish_request_json(
            session,
            path=f"/redfish/v1/Managers/{redfish_manager_id}",
            timeout=redfish_timeout,
            error_code="redfish_manager_fetch_failed",
            failure_message="Failed to fetch Redfish manager resource",
        )
    download_target = select_redfish_general_download_target(manager_payload)
    remote_bundle_path = getattr(args, "remote_path", "").strip()
    generation_ran = False

    if not remote_bundle_path:
        generation_ran = True
        action_in_use = redfish_action
        action_target = select_redfish_action_target(manager_payload, action_in_use)
        remote_bundle_path = build_redfish_bundle_path(action_in_use)
        try:
            task_response = redfish_request(
                session,
                path=action_target,
                method="POST",
                json_body={"Type": "URI", "Content": remote_bundle_path},
                timeout=redfish_timeout,
                error_code="redfish_collect_failed",
                failure_message="Failed to trigger Redfish bundle collection",
            )
        except BundlePullError as exc:
            if not should_fallback_quickdump_to_dump(exc, requested_action=action_in_use):
                raise
            action_in_use = "dump"
            action_target = select_redfish_action_target(manager_payload, action_in_use)
            remote_bundle_path = build_redfish_bundle_path(action_in_use)
            task_response = redfish_request(
                session,
                path=action_target,
                method="POST",
                json_body={"Type": "URI", "Content": remote_bundle_path},
                timeout=redfish_timeout,
                error_code="redfish_collect_failed",
                failure_message="Failed to trigger Redfish bundle collection",
            )
        task_path = extract_redfish_task_path(task_response)
        redfish_wait_for_task(
            session,
            task_path,
            timeout=redfish_task_timeout,
            poll_interval=redfish_poll_interval,
        )

    local_bundle_path = redfish_download_bundle(
        session,
        target=download_target,
        remote_path=remote_bundle_path,
        local_dir=local_dir,
        timeout=getattr(args, "download_timeout", 1800),
    )
    return BundleStageResult(
        remote_bundle_path=remote_bundle_path,
        local_bundle_path=local_bundle_path,
        generation_ran=generation_ran,
        transport="redfish",
    )


def run_redfish_bundle_flow(
    args: argparse.Namespace,
    *,
    ip: str,
    local_dir: pathlib.Path,
) -> BundleStageResult:
    redfish_port = getattr(args, "redfish_port", 443)
    redfish_timeout = getattr(args, "redfish_timeout", 60)
    redfish_proxy = getattr(args, "redfish_proxy", "auto")
    redfish_user = resolve_value(getattr(args, "redfish_user", "Administrator"), getattr(args, "redfish_user_env", ""), "Redfish 用户名")
    redfish_password = resolve_secret(
        getattr(args, "redfish_password", ""),
        getattr(args, "redfish_password_env", ""),
        "Redfish 密码",
        json_mode=getattr(args, "json", False),
    )
    session = redfish_create_session(
        ip=ip,
        user=redfish_user,
        password=redfish_password,
        port=redfish_port,
        timeout=redfish_timeout,
        proxy_mode=redfish_proxy,
    )
    try:
        return run_redfish_bundle_flow_with_session(
            args,
            ip=ip,
            local_dir=local_dir,
            session=session,
        )
    finally:
        try:
            redfish_delete_session(session, timeout=redfish_timeout)
        except BundlePullError:
            pass


def ensure_safe_member_path(destination: pathlib.Path, member_name: str) -> None:
    if len(pathlib.PurePosixPath(member_name).parts) > 128:
        raise BundlePullError("extract_budget_exceeded", "Archive path depth exceeds 128 components")
    try:
        target_path = (destination / member_name).resolve()
    except (OSError, RuntimeError) as exc:
        raise BundlePullError("extract_failed", "Archive member path cannot be resolved safely") from exc
    destination_root = destination.resolve()
    if not target_path.is_relative_to(destination_root):
        raise BundlePullError("extract_failed", f"Unsafe archive member path: {member_name}")
    if len(target_path.relative_to(destination_root).parts) > 128:
        raise BundlePullError("extract_budget_exceeded", "Resolved archive path depth exceeds 128 components")


def locate_bundle_root(extract_dir: pathlib.Path) -> pathlib.Path:
    direct_root = extract_dir / "dump_info"
    if direct_root.is_dir():
        return extract_dir
    candidates = sorted(path for path in extract_dir.rglob("dump_info") if path.is_dir())
    if candidates:
        return candidates[0].parent
    raise BundlePullError("bundle_layout_invalid", "Extracted bundle does not contain dump_info/")


class BoundedArchiveReader:
    """Cap decompressed tar bytes before extended headers are parsed."""

    def __init__(self, stream, limit: int):
        self.stream = stream
        self.remaining = limit

    def read(self, size: int) -> bytes:
        data = self.stream.read(min(size, self.remaining + 1))
        if len(data) > self.remaining:
            raise BundlePullError("extract_budget_exceeded", "Decompressed archive stream budget exceeded")
        self.remaining -= len(data)
        return data


def open_archive_stream(path: pathlib.Path):
    with path.open("rb") as stream:
        magic = stream.read(6)
    if magic.startswith(b"\x1f\x8b"):
        return gzip.open(path, "rb")
    if magic.startswith(b"BZh"):
        return bz2.open(path, "rb")
    if magic.startswith(b"\xfd7zXZ\x00"):
        return lzma.open(path, "rb")
    return path.open("rb")


def extract_archive(
    archive_path: pathlib.Path,
    extract_parent: pathlib.Path,
    *,
    max_members: int = DEFAULT_EXTRACT_MAX_MEMBERS,
    max_bytes: int = DEFAULT_EXTRACT_MAX_BYTES,
    max_stream_bytes: int = 576 * 1024 * 1024,
) -> ExtractionResult:
    if min(max_members, max_bytes, max_stream_bytes) < 1:
        raise BundlePullError("invalid_request", "Archive resource limits must be positive")
    bundle_name = archive_path.name
    if bundle_name.endswith(".tar.gz"):
        bundle_name = bundle_name[: -len(".tar.gz")]
    elif bundle_name.endswith(".tar"):
        bundle_name = bundle_name[: -len(".tar")]
    extract_parent.mkdir(parents=True, exist_ok=True)
    extract_dir = pathlib.Path(tempfile.mkdtemp(prefix=bundle_name + "-", dir=extract_parent))
    try:
        with open_archive_stream(archive_path) as stream, tarfile.open(
            fileobj=BoundedArchiveReader(stream, max_stream_bytes), mode="r|"
        ) as archive:
            total_bytes = 0
            member_sizes: dict[str, int] = {}
            for count, member in enumerate(archive, start=1):
                if member.sparse is not None:
                    raise BundlePullError("extract_failed", "Sparse archive members are not supported for log extraction")
                size = max(0, member.size)
                if member.islnk():
                    if member.linkname not in member_sizes:
                        raise BundlePullError("extract_failed", "Archive hard link must refer to an earlier regular file")
                    size = member_sizes[member.linkname]
                if member.isfile() or member.islnk():
                    member_sizes[member.name] = size
                total_bytes += size
                if count > max_members or total_bytes > max_bytes:
                    raise BundlePullError("extract_budget_exceeded", "Archive member or expanded-byte budget exceeded")
                ensure_safe_member_path(extract_dir, member.name)
                archive.extract(member, extract_dir, filter="data")
        return ExtractionResult(extract_dir=extract_dir, bundle_root=locate_bundle_root(extract_dir))
    except (BundlePullError, tarfile.TarError, OSError, EOFError, lzma.LZMAError, zlib.error, RecursionError) as exc:
        shutil.rmtree(extract_dir)
        if isinstance(exc, BundlePullError):
            raise
        if isinstance(exc, RecursionError):
            raise BundlePullError("extract_budget_exceeded", "Archive extended-header nesting limit exceeded") from exc
        raise BundlePullError("extract_failed", f"Failed to extract {archive_path}: {exc}") from exc


def emit_result(payload: dict[str, object], *, json_mode: bool) -> None:
    if json_mode:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    print(f"REMOTE_BUNDLE_PATH={payload['result'].get('remote_bundle_path', '')}")
    print(f"LOCAL_BUNDLE_PATH={payload['result'].get('local_bundle_path', '')}")
    if payload["result"].get("extract_dir"):
        print(f"EXTRACT_DIR={payload['result']['extract_dir']}")
    if payload["result"].get("bundle_root"):
        print(f"BUNDLE_ROOT={payload['result']['bundle_root']}")
    if payload["result"].get("transport"):
        print(f"TRANSPORT={payload['result']['transport']}")
    analysis = payload["result"].get("analysis")
    if isinstance(analysis, dict):
        summary = analysis.get("summary")
        if summary:
            print(f"ANALYSIS_SUMMARY={summary}")
        selected_logs = analysis.get("selected_logs", [])
        if isinstance(selected_logs, list) and selected_logs:
            names = [item.get("name", "") for item in selected_logs if isinstance(item, dict) and item.get("name")]
            if names:
                print(f"ANALYSIS_SELECTED_LOGS={','.join(names)}")
    if payload["result"].get("next_step"):
        print(f"NEXT_STEP={payload['result']['next_step']}")


def build_payload(
    *,
    ok: bool,
    code: str,
    error: str,
    request: dict[str, object],
    result: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "pull_bundle",
        "ok": ok,
        "code": code,
        "error": error,
        "request": request,
        "result": result,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="从远端主机拉取 openUBMC 一键日志包。", add_help=False)
    parser._positionals.title = "位置参数"
    parser._optionals.title = "选项"
    parser.add_argument("-h", "--help", action="help", help="显示帮助信息并退出。")
    parser.add_argument("--ip", default="", help="目标 BMC IP 或主机名；不传时交互输入。")
    parser.add_argument(
        "--transport",
        choices=["auto", "redfish", "ssh"],
        default="auto",
        help="日志包采集方式；auto 优先 Redfish，必要时回退 SSH。",
    )
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH 端口，默认 22。")
    parser.add_argument("--ssh-user", default="Administrator", help="SSH 用户名。")
    parser.add_argument("--ssh-password", default="", help="SSH 密码；不建议直接写在命令行，优先用 --ssh-password-env。")
    parser.add_argument("--ssh-user-env", default="", help="保存 SSH 用户名的环境变量。")
    parser.add_argument("--ssh-password-env", default="", help="保存 SSH 密码的环境变量。")
    parser.add_argument("--ssh-identity-file", default="", help="SSH 私钥文件，用于 key-based auth。")
    parser.add_argument("--redfish-port", type=int, default=443, help="Redfish HTTPS 端口，默认 443。")
    parser.add_argument("--redfish-user", default="Administrator", help="Redfish 用户名。")
    parser.add_argument("--redfish-password", default="", help="Redfish 密码；不建议直接写在命令行，优先用 --redfish-password-env。")
    parser.add_argument("--redfish-user-env", default="", help="保存 Redfish 用户名的环境变量。")
    parser.add_argument("--redfish-password-env", default="", help="保存 Redfish 密码的环境变量。")
    parser.add_argument("--redfish-manager-id", default="1", help="Redfish manager id，默认 1。")
    parser.add_argument(
        "--redfish-proxy",
        choices=["auto", "inherit", "disable"],
        default="auto",
        help="Redfish 代理策略：auto 自动绕过私网管理地址，inherit 继承系统代理，disable 强制禁用代理。",
    )
    parser.add_argument(
        "--redfish-action",
        choices=["dump", "quickdump"],
        default="dump",
        help="未传 --remote-path 时触发的 Redfish 采集动作。",
    )
    parser.add_argument("--remote-path", default="", help="已知远端日志包路径；不传时自动生成或发现。")
    parser.add_argument(
        "--remote-command",
        default="",
        help="SSH 侧生成日志包的远端命令；建议输出 BUNDLE_PATH=/path/to/archive.tar.gz。",
    )
    parser.add_argument(
        "--search-root",
        action="append",
        dest="search_roots",
        default=[],
        help="SSH 自动发现日志包时的搜索目录，可重复传。",
    )
    parser.add_argument(
        "--name-glob",
        action="append",
        dest="name_globs",
        default=[],
        help="SSH 自动发现日志包时的文件名 glob，可重复传。",
    )
    parser.add_argument("--local-dir", default="", help="本地保存下载日志包的目录。")
    parser.add_argument("--extract-dir", default="", help="本地解压目录的父目录。")
    parser.add_argument("--problem", default="", help="解压后用于问题驱动选日志的问题描述。")
    parser.add_argument("--analysis-max-files", type=int, default=DEFAULT_ANALYSIS_MAX_FILES, help="最多分析的日志类型数量。")
    parser.add_argument("--analysis-max-lines", type=int, default=DEFAULT_ANALYSIS_MAX_LINES, help="每类日志最多抽取的证据行数。")
    parser.add_argument("--analysis-since", default="", help="只保留不早于该时间的分析证据，格式 YYYY-MM-DDTHH:MM:SS。")
    parser.add_argument("--analysis-until", default="", help="只保留不晚于该时间的分析证据，格式 YYYY-MM-DDTHH:MM:SS。")
    parser.add_argument("--no-extract", dest="extract", action="store_false", help="下载后不做本地解压。")
    parser.set_defaults(extract=True)
    parser.add_argument("--search-timeout", type=int, default=60, help="远端日志包发现超时时间，单位秒。")
    parser.add_argument("--generate-timeout", type=int, default=1800, help="远端日志包生成超时时间，单位秒。")
    parser.add_argument("--download-timeout", type=int, default=1800, help="日志包下载超时时间，单位秒。")
    parser.add_argument("--redfish-timeout", type=int, default=60, help="单次 Redfish 请求超时时间，单位秒。")
    parser.add_argument("--redfish-task-timeout", type=int, default=900, help="Redfish 采集任务超时时间，单位秒。")
    parser.add_argument("--redfish-poll-interval", type=int, default=5, help="Redfish 采集任务轮询间隔，单位秒。")
    parser.add_argument("--json", action="store_true", help="输出 JSON 结构化结果。")
    arguments = list(sys.argv[1:] if argv is None else argv)
    parsed = parser.parse_args(arguments)
    for transport in ("ssh", "redfish"):
        setattr(parsed, f"_{transport}_user_explicit",
                any(item.split("=", 1)[0] == f"--{transport}-user" for item in arguments))
    return parsed


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    import target_runtime_adapter

    search_roots = args.search_roots or list(DEFAULT_SEARCH_ROOTS)
    name_globs = args.name_globs or list(DEFAULT_NAME_GLOBS)
    request = {
        "ip": args.ip.strip(),
        "transport": args.transport,
        "ssh_port": args.ssh_port,
        "redfish_port": args.redfish_port,
        "redfish_action": args.redfish_action,
        "redfish_manager_id": args.redfish_manager_id,
        "redfish_proxy": args.redfish_proxy,
        "remote_path": args.remote_path,
        "remote_command": bool(args.remote_command),
        "problem": args.problem,
        "analysis_since": args.analysis_since,
        "analysis_until": args.analysis_until,
        "search_roots": search_roots,
        "name_globs": name_globs,
        "local_dir": args.local_dir,
        "extract_dir": args.extract_dir,
        "extract": args.extract,
    }

    try:
        ip = resolve_ip(args.ip, json_mode=args.json)
        args.ip = ip
        request["ip"] = ip
        local_dir = pathlib.Path(args.local_dir or f"/tmp/openubmc-log-analyzer/{ip}/bundles")
        extract_parent = pathlib.Path(args.extract_dir or local_dir / "extract")
        request["local_dir"] = str(local_dir)
        request["extract_dir"] = str(extract_parent)
        with target_runtime_adapter.open_log_bundle_runtime_lease(
            args=args
        ) as runtime_lease:
            stage_result = runtime_lease.collect(
                local_dir=local_dir,
                search_roots=search_roots,
                name_globs=name_globs,
            )

        extract_result: ExtractionResult | None = None
        if args.extract:
            extract_result = extract_archive(stage_result.local_bundle_path, extract_parent)
        if args.problem.strip() and extract_result is None:
            raise BundlePullError("invalid_request", "--problem requires extraction; remove --no-extract.")

        analysis: dict[str, object] | None = None
        if args.problem.strip() and extract_result is not None:
            analysis_since = parse_analysis_time_bound(args.analysis_since, label="--analysis-since")
            analysis_until = parse_analysis_time_bound(args.analysis_until, label="--analysis-until")
            if analysis_since and analysis_until and comparable_datetime(analysis_since) > comparable_datetime(analysis_until):
                raise BundlePullError("invalid_request", "--analysis-since 不能晚于 --analysis-until。")
            analysis = analyze_bundle(
                extract_result.bundle_root,
                args.problem.strip(),
                max_files=args.analysis_max_files,
                max_lines=args.analysis_max_lines,
                since=analysis_since,
                until=analysis_until,
            )

        result = {
            "remote_bundle_path": stage_result.remote_bundle_path,
            "local_bundle_path": str(stage_result.local_bundle_path),
            "extract_dir": str(extract_result.extract_dir) if extract_result else "",
            "bundle_root": str(extract_result.bundle_root) if extract_result else "",
            "generation_ran": stage_result.generation_ran,
            "transport": stage_result.transport,
            "next_step": ("复用 result.analysis 中的证据与覆盖缺口，完成日志结论；无需重复扫描。"
                          if analysis is not None else
                          "继续 openubmc-log-analyzer 的本地分析阶段，对 bundle_root（未解压时 local_bundle_path）分析。"),
        }
        if analysis is not None:
            result["analysis"] = analysis
        emit_result(
            build_payload(ok=True, code="ok", error="", request=request, result=result),
            json_mode=args.json,
        )
        return 0
    except (BundlePullError, target_runtime_adapter.pull_bundle.BundlePullError) as exc:
        emit_result(
            build_payload(
                ok=False,
                code=exc.code,
                error=exc.message,
                request=request,
                result={
                    "remote_bundle_path": "",
                    "local_bundle_path": "",
                    "extract_dir": "",
                    "bundle_root": "",
                    "generation_ran": False,
                    "next_step": "",
                },
            ),
            json_mode=args.json,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
