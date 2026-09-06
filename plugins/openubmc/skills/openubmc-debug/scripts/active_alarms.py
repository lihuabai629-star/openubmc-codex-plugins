#!/usr/bin/env python3
"""Discover and read current openUBMC alarms through the live D-Bus interface."""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
import xml.etree.ElementTree as ET

from _cli_common import resolve_ssh_credentials
from _debug_dump import build_debug_dumper
from _json_common import build_json_payload
from _remote_common import (
    detect_dbus_env,
    run_ssh,
    sanitize_remote_text,
    ssh_transport_details,
    ssh_transport_failure_code,
    ssh_transport_failure_message,
)
from _target_runtime_adapter import (
    run_typed_object_alarm_one_shot,
)
from _workflow_runtime import WorkflowDeadline
from busctl_remote import normalize_structured_busctl

SUPPORTED_SIGNATURES = {
    "a{ss}qqa(ss)": lambda limit: ["0", "0", str(limit), "0"],
}
STANDARD_ALARM_SERVICE = "bmc.kepler.event"
STANDARD_ALARM_PATH = "/bmc/kepler/Systems/1/Events"
DEFAULT_DISCOVERY_SERVICE_LIMIT = 16
DEFAULT_DISCOVERY_PATH_LIMIT = 64
MAX_INTROSPECTION_XML_BYTES = 1024 * 1024
MAX_INTROSPECTION_STDERR_BYTES = 64 * 1024
MAX_DISCOVERY_STDOUT_BYTES = 4 * 1024 * 1024
MAX_ALARM_RESULT_STDOUT_BYTES = 8 * 1024 * 1024
MAX_ALARM_TRANSPORT_STDERR_BYTES = 64 * 1024
SERVICE_NAME_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)+$"
)
OBJECT_PATH_RE = re.compile(r"^/(?:[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*)?$")
ALARM_SERVICE_RE = re.compile(r"alarm|event|alert", re.IGNORECASE)
STALE_ALARM_ENDPOINT_MARKERS = (
    "unknown interface",
    "unknown method",
    "unknown object",
    "no such object",
    "service unknown",
    "name has no owner",
    "not provided by any .service",
)
XML_NODE_START_RE = re.compile(
    r"<(?:[A-Za-z_][A-Za-z0-9_.-]*:)?node(?=[\s/>])"
)


class EndpointDiscoveryError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        returncode: int = 3,
        discovery: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.returncode = returncode
        self.discovery = discovery or {}


class IntrospectionMetadataError(ValueError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


def alarm_endpoint_is_stale(error: str) -> bool:
    normalized = error.casefold()
    return any(marker in normalized for marker in STALE_ALARM_ENDPOINT_MARKERS)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Auto-discover GetAlarmList and return current active alarms."
    )
    parser.add_argument("--ip", required=True, help="BMC IP")
    parser.add_argument("--user", "--ssh-user", dest="ssh_user", default="")
    parser.add_argument("--port", "--ssh-port", dest="ssh_port", type=int, default=22)
    parser.add_argument("--user-env", "--ssh-user-env", dest="ssh_user_env", default="")
    parser.add_argument(
        "--password-env", "--ssh-password-env", dest="ssh_password_env", default=""
    )
    parser.add_argument("--password", "--ssh-password", dest="ssh_password", default="")
    parser.add_argument(
        "--identity-file", "--ssh-identity-file", dest="ssh_identity_file", default=""
    )
    parser.add_argument(
        "--service",
        default="",
        help="Optional exact alarm service override; default discovers it",
    )
    parser.add_argument(
        "--path",
        default="",
        help="Optional exact alarm object path override; default discovers it",
    )
    parser.add_argument(
        "--discovery-service-limit",
        type=int,
        default=DEFAULT_DISCOVERY_SERVICE_LIMIT,
        help="Maximum candidate alarm/event services to inspect",
    )
    parser.add_argument(
        "--discovery-path-limit",
        type=int,
        default=DEFAULT_DISCOVERY_PATH_LIMIT,
        help="Maximum candidate alarm/event paths to inspect per service",
    )
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument(
        "--call-signature",
        default="",
        help="Verified GetAlarmList signature override; must match introspection",
    )
    parser.add_argument(
        "--call-arg",
        action="append",
        dest="call_args",
        default=[],
        help="Argument for --call-signature; repeat in call order",
    )
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument(
        "--deadline",
        type=int,
        default=300,
        help="End-to-end alarm discovery and read budget in seconds",
    )
    parser.add_argument("--debug-dump", default="")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--compact-json",
        action="store_true",
        help="With --json, omit duplicated legacy top-level alarm fields",
    )
    return parser.parse_args(argv)


def _xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _skip_xml_doctype(text: str, start: int) -> int:
    quote = ""
    subset_depth = 0
    index = start + len("<!DOCTYPE")
    while index < len(text):
        character = text[index]
        if quote:
            if character == quote:
                quote = ""
        elif character in {'"', "'"}:
            quote = character
        elif character == "[":
            subset_depth += 1
        elif character == "]" and subset_depth:
            subset_depth -= 1
        elif character == ">" and subset_depth == 0:
            return index + 1
        index += 1
    raise IntrospectionMetadataError(
        "invalid_introspection_xml",
        "XML introspection contains an unterminated DOCTYPE",
    )


def _xml_metadata_body(introspection: str) -> str:
    text = introspection
    if text.startswith("\ufeff"):
        text = text[1:]
    index = 0
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if text.startswith("<?", index):
            end = text.find("?>", index + 2)
            if end < 0:
                raise IntrospectionMetadataError(
                    "invalid_introspection_xml",
                    "XML introspection contains an unterminated processing instruction",
                )
            index = end + 2
            continue
        if text.startswith("<!--", index):
            end = text.find("-->", index + 4)
            if end < 0:
                raise IntrospectionMetadataError(
                    "invalid_introspection_xml",
                    "XML introspection contains an unterminated comment",
                )
            index = end + 3
            continue
        if text.startswith("<!DOCTYPE", index):
            index = _skip_xml_doctype(text, index)
            continue
        break
    body = text[index:]
    if not XML_NODE_START_RE.match(body):
        raise IntrospectionMetadataError(
            "invalid_introspection_xml",
            "XML introspection does not contain a top-level node document",
        )
    return body


def _discover_get_alarm_list_xml(
    introspection: str,
) -> list[tuple[str, str]]:
    # Some busctl versions concatenate the two PUBLIC identifiers in their
    # generated DOCTYPE without XML-required whitespace.  The metadata body is
    # still a valid <node> document.  Strip only the XML prolog so comments
    # containing a literal <node> cannot be mistaken for the document root and
    # no external DTD is loaded.
    size_bytes = len(introspection.encode("utf-8"))
    if size_bytes > MAX_INTROSPECTION_XML_BYTES:
        raise IntrospectionMetadataError(
            "introspection_xml_too_large",
            (
                "XML introspection exceeds the metadata size limit "
                f"({size_bytes} > {MAX_INTROSPECTION_XML_BYTES} bytes)"
            ),
            details={
                "size_bytes": size_bytes,
                "limit_bytes": MAX_INTROSPECTION_XML_BYTES,
            },
        )
    body = _xml_metadata_body(introspection)
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise IntrospectionMetadataError(
            "invalid_introspection_xml",
            f"Cannot parse XML introspection metadata: {exc}",
        ) from exc
    if _xml_local_name(root.tag) != "node":
        raise IntrospectionMetadataError(
            "invalid_introspection_xml",
            "XML introspection root is not a node element",
        )

    candidates: list[tuple[str, str]] = []
    for interface in root:
        if _xml_local_name(interface.tag) != "interface":
            continue
        interface_name = interface.attrib.get("name", "")
        for method in interface:
            if (
                _xml_local_name(method.tag) != "method"
                or method.attrib.get("name") != "GetAlarmList"
            ):
                continue
            input_signature = "".join(
                argument.attrib.get("type", "")
                for argument in method
                if _xml_local_name(argument.tag) == "arg"
                and argument.attrib.get("direction", "in") != "out"
            )
            candidates.append((interface_name, input_signature))
    return candidates


def _discover_get_alarm_list_table_candidates(
    introspection: str,
) -> list[tuple[str, str]]:
    current_interface = ""
    candidates: list[tuple[str, str]] = []
    for raw_line in introspection.splitlines():
        line = raw_line.strip()
        fields = line.split()
        if (
            len(fields) >= 2
            and fields[1] == "interface"
            and not fields[0].startswith(".")
        ):
            current_interface = fields[0]
            continue
        if (
            len(fields) >= 3
            and fields[0] == ".GetAlarmList"
            and fields[1] == "method"
        ):
            candidates.append((current_interface, fields[2]))
    return candidates


def _discover_get_alarm_list_candidates(
    introspection: str,
    *,
    allow_table: bool,
) -> list[tuple[str, str]]:
    if introspection.lstrip("\ufeff \t\r\n").startswith("<"):
        return _discover_get_alarm_list_xml(introspection)
    if allow_table:
        return _discover_get_alarm_list_table_candidates(introspection)
    raise IntrospectionMetadataError(
        "invalid_introspection_xml",
        "Live metadata introspection did not return an XML node document",
    )


def discover_get_alarm_list(introspection: str) -> tuple[str, str] | None:
    """Parse XML metadata from live discovery, with table text for offline compatibility."""

    candidates = _discover_get_alarm_list_candidates(
        introspection, allow_table=True
    )
    if len(candidates) > 1:
        raise IntrospectionMetadataError(
            "ambiguous_get_alarm_list_methods",
            "Multiple GetAlarmList methods were found in one introspection result",
            details={"candidate_count": len(candidates)},
        )
    return candidates[0] if candidates else None


def parse_alarm_services(busctl_list: str) -> list[str]:
    """Return well-known alarm/event service candidates in stable list order."""
    services: list[str] = []
    for raw_line in busctl_list.splitlines():
        fields = raw_line.strip().split()
        if not fields:
            continue
        name = fields[0]
        if (
            name == "NAME"
            or name.startswith(":")
            or not SERVICE_NAME_RE.fullmatch(name)
            or not ALARM_SERVICE_RE.search(name)
            or name in services
        ):
            continue
        services.append(name)
    return services


def parse_alarm_paths(busctl_tree: str) -> list[str]:
    """Return every valid path from an alarm/event service in stable order."""
    paths: list[str] = []
    for raw_line in busctl_tree.splitlines():
        slash = raw_line.find("/")
        if slash < 0:
            continue
        path = raw_line[slash:].strip().split()[0]
        if (
            not OBJECT_PATH_RE.fullmatch(path)
            or path in paths
        ):
            continue
        paths.append(path)
    return paths


def validate_endpoint_override(service: str, path: str) -> None:
    if service and not SERVICE_NAME_RE.fullmatch(service):
        raise EndpointDiscoveryError(
            "invalid_endpoint_override", f"Invalid D-Bus service override: {service!r}", returncode=2
        )
    if path and not OBJECT_PATH_RE.fullmatch(path):
        raise EndpointDiscoveryError(
            "invalid_endpoint_override", f"Invalid D-Bus object path override: {path!r}", returncode=2
        )


def remote_busctl_command(dbus: str, xdg: str, parts: list[str]) -> str:
    command = " ".join(shlex.quote(part) for part in parts)
    return (
        f"XDG_RUNTIME_DIR={shlex.quote(xdg)} "
        f"DBUS_SESSION_BUS_ADDRESS={shlex.quote(dbus)} {command}"
    )


def _bounded_utf8_prefix(text: str, limit_bytes: int | None) -> str:
    if limit_bytes is None:
        return text
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit_bytes:
        return text
    return encoded[:limit_bytes].decode("utf-8", errors="ignore")


def run_remote_busctl(
    args: argparse.Namespace,
    ssh: dict[str, str | int],
    debug_dumper,
    dbus: str,
    xdg: str,
    parts: list[str],
    label: str,
    deadline: WorkflowDeadline,
    discovery: dict[str, object],
    *,
    stdout_limit_bytes: int | None = MAX_DISCOVERY_STDOUT_BYTES,
    stderr_limit_bytes: int | None = MAX_ALARM_TRANSPORT_STDERR_BYTES,
    ssh_runner=None,
):
    if ssh_runner is None:
        ssh_runner = run_ssh
    remaining = deadline.remaining()
    if remaining <= 0:
        raise EndpointDiscoveryError(
            "alarm_discovery_deadline_exceeded",
            "Active-alarm discovery exhausted its end-to-end deadline",
            returncode=124,
            discovery=discovery,
        )
    timeout = min(float(args.timeout), remaining)
    deadline_capped = timeout < float(args.timeout)
    command = remote_busctl_command(dbus, xdg, parts)
    completed = ssh_runner(
        args.ip,
        str(ssh["user"]),
        str(ssh["password"]),
        command,
        timeout,
        port=int(ssh["port"]),
        identity_file=str(ssh["identity_file"]),
        debug_dumper=debug_dumper,
        debug_label=label,
        stdout_limit_bytes=stdout_limit_bytes,
        stderr_limit_bytes=stderr_limit_bytes,
    )
    if deadline.exhausted():
        raise EndpointDiscoveryError(
            "alarm_discovery_deadline_exceeded",
            "Active-alarm discovery exhausted its end-to-end deadline",
            returncode=124,
            discovery=discovery,
        )
    transport_code = ssh_transport_failure_code(completed)
    if transport_code:
        discovery["transport_failure"] = {
            "stage": label,
            "code": transport_code,
            **ssh_transport_details(completed),
        }
        raise EndpointDiscoveryError(
            transport_code,
            ssh_transport_failure_message(
                transport_code,
                "alarm discovery",
            ),
            returncode=completed.returncode,
            discovery=discovery,
        )
    stdout = _bounded_utf8_prefix(
        sanitize_remote_text(completed.stdout or ""), stdout_limit_bytes
    )
    stderr = _bounded_utf8_prefix(
        sanitize_remote_text(completed.stderr or ""), stderr_limit_bytes
    )
    if completed.returncode == 124 and deadline_capped:
        raise EndpointDiscoveryError(
            "alarm_discovery_deadline_exceeded",
            "Active-alarm discovery exhausted its end-to-end deadline",
            returncode=124,
            discovery=discovery,
        )
    return completed, stdout, stderr


def discover_alarm_endpoint(
    args: argparse.Namespace,
    ssh: dict[str, str | int],
    debug_dumper,
    dbus: str,
    xdg: str,
    deadline: WorkflowDeadline,
    *,
    ssh_runner=None,
) -> tuple[dict[str, str], dict[str, object]]:
    """Find one fully introspected GetAlarmList endpoint or fail closed."""
    validate_endpoint_override(args.service, args.path)
    discovery: dict[str, object] = {
        "mode": "explicit" if args.service and args.path else "automatic",
        "service_override": args.service or None,
        "path_override": args.path or None,
        "services": [],
        "paths": {},
        "introspection_failures": [],
    }

    if not args.service and not args.path:
        completed, stdout, stderr = run_remote_busctl(
            args,
            ssh,
            debug_dumper,
            dbus,
            xdg,
            [
                "busctl",
                "--user",
                "--no-pager",
                "--xml-interface",
                "introspect",
                STANDARD_ALARM_SERVICE,
                STANDARD_ALARM_PATH,
            ],
            "active_alarms_standard_endpoint",
            deadline,
            discovery,
            ssh_runner=ssh_runner,
            stdout_limit_bytes=MAX_INTROSPECTION_XML_BYTES + 1,
            stderr_limit_bytes=MAX_INTROSPECTION_STDERR_BYTES,
        )
        fast_path: dict[str, object] = {
            "service": STANDARD_ALARM_SERVICE,
            "path": STANDARD_ALARM_PATH,
            "ok": False,
        }
        if completed.returncode == 0:
            try:
                candidates = _discover_get_alarm_list_candidates(
                    stdout,
                    allow_table=False,
                )
            except IntrospectionMetadataError as exc:
                fast_path.update(
                    {
                        "code": exc.code,
                        "error": str(exc),
                    }
                )
            else:
                if len(candidates) == 1:
                    interface, signature = candidates[0]
                    endpoint = {
                        "service": STANDARD_ALARM_SERVICE,
                        "path": STANDARD_ALARM_PATH,
                        "interface": interface,
                        "signature": signature,
                    }
                    fast_path["ok"] = True
                    discovery.update(
                        {
                            "mode": "standard-fast-path",
                            "services": [STANDARD_ALARM_SERVICE],
                            "paths": {
                                STANDARD_ALARM_SERVICE: [STANDARD_ALARM_PATH]
                            },
                            "endpoint_candidates": [endpoint],
                            "standard_fast_path": fast_path,
                        }
                    )
                    return endpoint, discovery
                fast_path.update(
                    {
                        "code": (
                            "get_alarm_list_missing"
                            if not candidates
                            else "ambiguous_get_alarm_list_methods"
                        ),
                        "candidate_count": len(candidates),
                    }
                )
        else:
            fast_path.update(
                {
                    "code": "introspect_failed",
                    "error": stderr or stdout or "introspect_failed",
                }
            )
        discovery["standard_fast_path"] = fast_path

    if args.service:
        services = [args.service]
    else:
        completed, stdout, stderr = run_remote_busctl(
            args,
            ssh,
            debug_dumper,
            dbus,
            xdg,
            ["busctl", "--user", "--no-pager", "list"],
            "active_alarms_list",
            deadline,
            discovery,
            ssh_runner=ssh_runner,
        )
        if completed.returncode != 0:
            raise EndpointDiscoveryError(
                "alarm_service_discovery_failed",
                stderr or stdout or "busctl list failed",
                discovery=discovery,
            )
        services = parse_alarm_services(stdout)
        if len(services) > args.discovery_service_limit:
            discovery["services"] = services[: args.discovery_service_limit]
            discovery["service_candidates_truncated"] = True
            raise EndpointDiscoveryError(
                "alarm_discovery_truncated",
                "Alarm/event service candidates exceed the discovery limit; pass --service",
                discovery=discovery,
            )
        if not services:
            raise EndpointDiscoveryError(
                "alarm_service_not_found",
                "No alarm/event service candidate was found; pass --service and --path",
                discovery=discovery,
            )

    discovery["services"] = services
    endpoints: list[dict[str, str]] = []
    failures = discovery["introspection_failures"]
    assert isinstance(failures, list)
    path_map = discovery["paths"]
    assert isinstance(path_map, dict)

    for service_index, service in enumerate(services):
        if args.path:
            paths = [args.path]
        else:
            completed, stdout, stderr = run_remote_busctl(
                args,
                ssh,
                debug_dumper,
                dbus,
                xdg,
                ["busctl", "--user", "--no-pager", "tree", service],
                f"active_alarms_tree_{service_index}",
                deadline,
                discovery,
                ssh_runner=ssh_runner,
            )
            if completed.returncode != 0:
                failures.append(
                    {"service": service, "path": None, "error": stderr or stdout or "tree_failed"}
                )
                path_map[service] = []
                continue
            paths = parse_alarm_paths(stdout)
            if len(paths) > args.discovery_path_limit:
                path_map[service] = paths[: args.discovery_path_limit]
                discovery["path_candidates_truncated"] = True
                raise EndpointDiscoveryError(
                    "alarm_discovery_truncated",
                    "Alarm/event path candidates exceed the discovery limit; pass --path",
                    discovery=discovery,
                )
        path_map[service] = paths

        for path_index, path in enumerate(paths):
            completed, stdout, stderr = run_remote_busctl(
                args,
                ssh,
                debug_dumper,
                dbus,
                xdg,
                [
                    "busctl",
                    "--user",
                    "--no-pager",
                    "--xml-interface",
                    "introspect",
                    service,
                    path,
                ],
                f"active_alarms_introspect_{service_index}_{path_index}",
                deadline,
                discovery,
                ssh_runner=ssh_runner,
                stdout_limit_bytes=MAX_INTROSPECTION_XML_BYTES + 1,
                stderr_limit_bytes=MAX_INTROSPECTION_STDERR_BYTES,
            )
            if completed.returncode != 0:
                failures.append(
                    {
                        "service": service,
                        "path": path,
                        "error": stderr or stdout or "introspect_failed",
                    }
                )
                continue
            try:
                discovered = _discover_get_alarm_list_candidates(
                    stdout, allow_table=False
                )
            except IntrospectionMetadataError as exc:
                failure = {
                    "service": service,
                    "path": path,
                    "code": exc.code,
                    "error": str(exc),
                }
                failure.update(exc.details)
                failures.append(failure)
                continue
            for interface, signature in discovered:
                endpoints.append(
                    {
                        "service": service,
                        "path": path,
                        "interface": interface,
                        "signature": signature,
                    }
                )

    discovery["endpoint_candidates"] = endpoints
    if failures:
        code = (
            "introspect_failed"
            if args.service and args.path
            else "alarm_discovery_incomplete"
        )
        raise EndpointDiscoveryError(
            code,
            "Endpoint discovery was incomplete; pass an exact --service and --path override",
            discovery=discovery,
        )
    if not endpoints:
        raise EndpointDiscoveryError(
            "get_alarm_list_missing",
            "GetAlarmList was not found on any fully inspected candidate endpoint",
            returncode=4,
            discovery=discovery,
        )
    if len(endpoints) != 1:
        raise EndpointDiscoveryError(
            "ambiguous_alarm_endpoint",
            "Multiple GetAlarmList endpoints were found; pass exact --service and --path overrides",
            returncode=4,
            discovery=discovery,
        )
    return endpoints[0], discovery


def build_search_terms(records: list[dict[str, str]]) -> list[str]:
    terms: list[str] = []
    for record in records:
        for key in ("EventName", "EventCode"):
            value = record.get(key, "")
            if value and value not in terms:
                terms.append(value)
    return terms


def resolve_call_arguments(
    discovered_signature: str,
    override_signature: str,
    override_args: list[str],
    limit: int,
) -> tuple[str, list[str]]:
    if override_signature and override_signature != discovered_signature:
        raise ValueError("signature_override_mismatch")
    if override_signature:
        return override_signature, list(override_args)
    if discovered_signature not in SUPPORTED_SIGNATURES:
        raise ValueError("unsupported_alarm_signature")
    return discovered_signature, SUPPORTED_SIGNATURES[discovered_signature](limit)


def _with_legacy_fields(payload: dict[str, object]) -> dict[str, object]:
    result = payload.get("result")
    result_dict = result if isinstance(result, dict) else {}
    legacy = dict(payload)
    legacy.update(
        {
            "interface": result_dict.get("interface", ""),
            "signature": result_dict.get("signature", ""),
            "record_count": result_dict.get("record_count", 0),
            "records": result_dict.get("records", []),
            "search_terms": result_dict.get("search_terms", []),
        }
    )
    return legacy


def emit(
    payload: dict[str, object], as_json: bool, compact_json: bool = False
) -> None:
    if as_json:
        rendered = payload if compact_json else _with_legacy_fields(payload)
        print(json.dumps(rendered, indent=2, ensure_ascii=False))
        return
    if not payload["ok"]:
        print(f"[ERROR] {payload['code']}: {payload['error']}", file=sys.stderr)
        return
    result = payload["result"]
    print(
        f"interface={result['interface']} signature={result['signature']} "
        f"active_alarm_count={result['record_count']}"
    )
    for record in result["records"]:
        print(
            " | ".join(
                [
                    record.get("Severity", ""),
                    record.get("EventName", ""),
                    record.get("ComponentName", ""),
                    record.get("Description", ""),
                ]
            )
        )


def failure_payload(
    args: argparse.Namespace,
    code: str,
    returncode: int,
    error: str,
    *,
    service: str = "",
    path: str = "",
    interface: str = "",
    signature: str = "",
    discovery: dict[str, object] | None = None,
    transport: dict[str, object] | None = None,
) -> dict[str, object]:
    transport_warnings = list((transport or {}).get("warnings", []))
    return build_json_payload(
        tool="active_alarms",
        ip=args.ip,
        ok=False,
        code=code,
        returncode=returncode,
        warnings=transport_warnings,
        error=error,
        request={
            "service": args.service,
            "path": args.path,
            "limit": args.limit,
            "discovery_service_limit": args.discovery_service_limit,
            "discovery_path_limit": args.discovery_path_limit,
            "call_signature_override": args.call_signature,
            "call_args_override": args.call_args,
            "deadline": args.deadline,
        },
        result={
            "service": service,
            "path": path,
            "interface": interface,
            "signature": signature,
            "record_count": 0,
            "records": [],
            "search_terms": [],
            "discovery": discovery or {},
            "transport": transport or {},
        },
    )


def main(
    *,
    ssh_runner=None,
    runtime_lease=None,
    _args: argparse.Namespace | None = None,
    _ssh: dict[str, str | int] | None = None,
    _deadline: WorkflowDeadline | None = None,
    _endpoint_retry: bool = True,
) -> int:
    args = _args or parse_args()
    if args.limit < 1 or args.limit > 1000:
        raise SystemExit("--limit must be between 1 and 1000")
    if args.discovery_service_limit < 1:
        raise SystemExit("--discovery-service-limit must be positive")
    if args.discovery_path_limit < 1:
        raise SystemExit("--discovery-path-limit must be positive")
    if args.timeout < 1 or args.deadline < 1:
        raise SystemExit("--timeout and --deadline must be positive")
    try:
        validate_endpoint_override(args.service, args.path)
    except EndpointDiscoveryError as exc:
        payload = failure_payload(args, exc.code, exc.returncode, str(exc))
        emit(payload, args.json, args.compact_json)
        return exc.returncode
    if ssh_runner is None:
        def collect_with_runtime(ssh, lease):
            return main(
                ssh_runner=lease.ssh_runner,
                runtime_lease=lease,
                _args=args,
                _ssh=dict(ssh),
            )

        return run_typed_object_alarm_one_shot(
            args=args,
            collector_name="active-alarms",
            operation={
                "service": args.service,
                "path": args.path,
                "limit": args.limit,
                "discovery_service_limit": args.discovery_service_limit,
                "discovery_path_limit": args.discovery_path_limit,
                "deadline": args.deadline,
            },
            credential_loader=lambda: resolve_ssh_credentials(args),
            collect=collect_with_runtime,
        )
    ssh = _ssh or resolve_ssh_credentials(args)
    debug_dumper = build_debug_dumper(args.debug_dump, secrets=[str(ssh["password"])])
    deadline = _deadline or WorkflowDeadline(args.deadline)
    env_remaining = deadline.remaining()
    if env_remaining <= 0:
        payload = failure_payload(
            args,
            "alarm_discovery_deadline_exceeded",
            124,
            "Active-alarm discovery exhausted its end-to-end deadline",
        )
        emit(payload, args.json, args.compact_json)
        return 124
    env_timeout = min(float(args.timeout), env_remaining)
    def load_env():
        return detect_dbus_env(
            args.ip,
            str(ssh["user"]),
            str(ssh["password"]),
            env_timeout,
            port=int(ssh["port"]),
            identity_file=str(ssh["identity_file"]),
            debug_dumper=debug_dumper,
            debug_label="active_alarms_env",
            ssh_runner=ssh_runner,
        )

    env = (
        runtime_lease.get_dbus_environment(load_env)
        if runtime_lease is not None
        else load_env()
    )
    if deadline.exhausted():
        payload = failure_payload(
            args,
            "alarm_discovery_deadline_exceeded",
            124,
            "Active-alarm discovery exhausted its end-to-end deadline",
        )
        emit(payload, args.json, args.compact_json)
        return 124
    env_transport = getattr(env, "transport", {})
    env_transport_code = str(env_transport.get("failure_code", ""))
    if env_transport_code:
        payload = failure_payload(
            args,
            env_transport_code,
            int(env_transport.get("returncode", 126)),
            ssh_transport_failure_message(
                env_transport_code,
                "D-Bus environment detection",
            ),
            transport=env_transport,
        )
        emit(payload, args.json, args.compact_json)
        return int(payload["returncode"])
    dbus = env.get("DBUS_SESSION_BUS_ADDRESS", "")
    xdg = env.get("XDG_RUNTIME_DIR", "")
    if not (dbus and xdg):
        payload = failure_payload(
            args, "dbus_env_missing", 2, "Failed to detect DBUS/XDG environment"
        )
        emit(payload, args.json, args.compact_json)
        return 2

    def load_endpoint():
        return discover_alarm_endpoint(
            args,
            ssh,
            debug_dumper,
            dbus,
            xdg,
            deadline,
            ssh_runner=ssh_runner,
        )

    try:
        endpoint, discovery = (
            runtime_lease.get_alarm_endpoint(load_endpoint)
            if runtime_lease is not None and not args.service and not args.path
            else load_endpoint()
        )
    except EndpointDiscoveryError as exc:
        payload = failure_payload(
            args,
            exc.code,
            exc.returncode,
            str(exc),
            discovery=exc.discovery,
        )
        emit(payload, args.json, args.compact_json)
        return exc.returncode
    service = endpoint["service"]
    path = endpoint["path"]
    interface = endpoint["interface"]
    signature = endpoint["signature"]
    try:
        call_signature, call_args = resolve_call_arguments(
            signature,
            args.call_signature,
            args.call_args,
            args.limit,
        )
    except ValueError as exc:
        failure_code = str(exc)
    else:
        failure_code = ""
    if failure_code == "signature_override_mismatch":
        payload = failure_payload(
            args,
            "signature_override_mismatch",
            5,
            f"Override signature {args.call_signature} does not match introspection {signature}",
            service=service,
            path=path,
            interface=interface,
            signature=signature,
            discovery=discovery,
        )
        emit(payload, args.json, args.compact_json)
        return 5
    if failure_code == "unsupported_alarm_signature":
        payload = failure_payload(
            args,
            "unsupported_alarm_signature",
            5,
            f"Unsupported GetAlarmList signature: {signature}",
            service=service,
            path=path,
            interface=interface,
            signature=signature,
            discovery=discovery,
        )
        emit(payload, args.json, args.compact_json)
        return 5
    call_cmd = remote_busctl_command(
        dbus,
        xdg,
        [
            "busctl",
            "--user",
            "--json=short",
            "call",
            service,
            path,
            interface,
            "GetAlarmList",
            call_signature,
            *call_args,
        ],
    )
    call_remaining = deadline.remaining()
    if call_remaining <= 0:
        payload = failure_payload(
            args,
            "alarm_discovery_deadline_exceeded",
            124,
            "Active-alarm read exhausted its end-to-end deadline",
            service=service,
            path=path,
            interface=interface,
            signature=signature,
            discovery=discovery,
        )
        emit(payload, args.json, args.compact_json)
        return 124
    call_timeout = min(float(args.timeout), call_remaining)
    call_deadline_capped = call_timeout < float(args.timeout)
    call_cp = ssh_runner(
        args.ip,
        str(ssh["user"]),
        str(ssh["password"]),
        call_cmd,
        call_timeout,
        port=int(ssh["port"]),
        identity_file=str(ssh["identity_file"]),
        debug_dumper=debug_dumper,
        debug_label="active_alarms_call",
        stdout_limit_bytes=MAX_ALARM_RESULT_STDOUT_BYTES,
        stderr_limit_bytes=MAX_ALARM_TRANSPORT_STDERR_BYTES,
    )
    if deadline.exhausted():
        payload = failure_payload(
            args,
            "alarm_discovery_deadline_exceeded",
            124,
            "Active-alarm read exhausted its end-to-end deadline",
            service=service,
            path=path,
            interface=interface,
            signature=signature,
            discovery=discovery,
        )
        emit(payload, args.json, args.compact_json)
        return 124
    call_transport = ssh_transport_details(call_cp)
    call_transport_code = ssh_transport_failure_code(call_cp)
    if call_transport_code:
        payload = failure_payload(
            args,
            call_transport_code,
            call_cp.returncode,
            ssh_transport_failure_message(
                call_transport_code,
                "active-alarm read",
            ),
            service=service,
            path=path,
            interface=interface,
            signature=signature,
            discovery=discovery,
            transport=call_transport,
        )
        emit(payload, args.json, args.compact_json)
        return call_cp.returncode
    stdout = sanitize_remote_text(call_cp.stdout or "")
    if call_cp.returncode != 0:
        if call_cp.returncode == 124 and call_deadline_capped:
            payload = failure_payload(
                args,
                "alarm_discovery_deadline_exceeded",
                124,
                "Active-alarm read exhausted its end-to-end deadline",
                service=service,
                path=path,
                interface=interface,
                signature=signature,
                discovery=discovery,
            )
            emit(payload, args.json, args.compact_json)
            return 124
        error = sanitize_remote_text(call_cp.stderr or "") or stdout
        invalidator = getattr(runtime_lease, "invalidate_alarm_endpoint", None)
        if (
            _endpoint_retry
            and runtime_lease is not None
            and not args.service
            and not args.path
            and alarm_endpoint_is_stale(error)
            and callable(invalidator)
            and invalidator()
        ):
            return main(
                ssh_runner=ssh_runner,
                runtime_lease=runtime_lease,
                _args=args,
                _ssh=ssh,
                _deadline=deadline,
                _endpoint_retry=False,
            )
        payload = failure_payload(
            args,
            "get_alarm_list_failed",
            6,
            error,
            service=service,
            path=path,
            interface=interface,
            signature=signature,
            discovery=discovery,
            transport=call_transport,
        )
        emit(payload, args.json, args.compact_json)
        return 6
    try:
        structured = normalize_structured_busctl(stdout)
        records = structured["records"]
        record_count = structured["record_count"]
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        payload = failure_payload(
            args,
            "invalid_alarm_payload",
            7,
            f"Cannot normalize GetAlarmList output: {exc}",
            service=service,
            path=path,
            interface=interface,
            signature=signature,
            discovery=discovery,
            transport=call_transport,
        )
        emit(payload, args.json, args.compact_json)
        return 7
    if deadline.exhausted():
        payload = failure_payload(
            args,
            "alarm_discovery_deadline_exceeded",
            124,
            "Active-alarm read exhausted its end-to-end deadline",
            service=service,
            path=path,
            interface=interface,
            signature=signature,
            discovery=discovery,
        )
        emit(payload, args.json, args.compact_json)
        return 124

    payload = build_json_payload(
        tool="active_alarms",
        ip=args.ip,
        ok=True,
        code="ok",
        returncode=0,
        warnings=list(call_transport.get("warnings", [])),
        request={
            "service": args.service,
            "path": args.path,
            "limit": args.limit,
            "discovery_service_limit": args.discovery_service_limit,
            "discovery_path_limit": args.discovery_path_limit,
            "call_signature_override": args.call_signature,
            "call_args_override": args.call_args,
            "deadline": args.deadline,
        },
        result={
            "service": service,
            "path": path,
            "interface": interface,
            "signature": signature,
            "record_count": record_count,
            "records": records,
            "search_terms": build_search_terms(records),
            "discovery": discovery,
            "transport": call_transport,
        },
    )
    emit(payload, args.json, args.compact_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
