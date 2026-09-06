#!/usr/bin/env python3
"""Runtime contracts, deadlines, and compact rendering for workflow_remote."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Any

from _json_common import SCHEMA_VERSION
from _workflow_contracts import validate_child_result_contract


_COMPACT_TEXT_LIMIT = 512
_COMPACT_LINE_LIMIT = 20
_COMPACT_LOG_FALLBACK = 10
CHILD_EXIT_GRACE_SECONDS = 5.0
DEADLINE_EPSILON_SECONDS = 0.01
_CHILD_TIMEOUT_OPTIONS = {
    "--ssh-timeout",
    "--telnet-connect-timeout",
    "--telnet-prompt-timeout",
    "--timeout",
    "--deadline",
    "--connect-timeout",
    "--prompt-timeout",
    "--command-timeout",
}
_CAPTURE_INSTALL_LOCK = threading.RLock()


class _ThreadCaptureStream:
    """Route writes to the current thread's capture without swapping globals."""

    def __init__(self, fallback) -> None:
        self.fallback = fallback
        self._local = threading.local()

    def _stack(self) -> list[io.StringIO]:
        stack = getattr(self._local, "stack", None)
        if stack is None:
            stack = []
            self._local.stack = stack
        return stack

    def push(self, buffer: io.StringIO) -> None:
        self._stack().append(buffer)

    def pop(self) -> None:
        stack = self._stack()
        if stack:
            stack.pop()

    def write(self, value: str) -> int:
        stack = self._stack()
        return (stack[-1] if stack else self.fallback).write(value)

    def flush(self) -> None:
        stack = self._stack()
        (stack[-1] if stack else self.fallback).flush()

    def __getattr__(self, name: str):
        return getattr(self.fallback, name)


def _capture_proxy(name: str) -> _ThreadCaptureStream:
    with _CAPTURE_INSTALL_LOCK:
        current = getattr(sys, name)
        if isinstance(current, _ThreadCaptureStream):
            return current
        proxy = _ThreadCaptureStream(current)
        setattr(sys, name, proxy)
        return proxy


@contextlib.contextmanager
def _capture_thread_output():
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    stdout_proxy = _capture_proxy("stdout")
    stderr_proxy = _capture_proxy("stderr")
    stdout_proxy.push(stdout_buffer)
    stderr_proxy.push(stderr_buffer)
    try:
        yield stdout_buffer, stderr_buffer
    finally:
        stderr_proxy.pop()
        stdout_proxy.pop()
_COMPACT_ALARM_FIELDS = {
    "EventName",
    "EventCode",
    "OldEventCode",
    "ComponentName",
    "ComponentInstance",
    "ComponentLocation",
    "State",
    "Timestamp",
    "Severity",
}


def _compact_text(value: object, limit: int = _COMPACT_TEXT_LIMIT) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _compact_lines(
    value: object,
    *,
    limit: int = _COMPACT_LINE_LIMIT,
) -> tuple[list[str], int, bool]:
    lines = [str(line) for line in value] if isinstance(value, list) else []
    preview = [_compact_text(line) for line in lines[:limit]]
    truncated = len(lines) > limit or any(
        len(line) > _COMPACT_TEXT_LIMIT for line in lines[:limit]
    )
    return preview, len(lines), truncated


def _compact_alarm_record(record: dict[str, object]) -> dict[str, object]:
    compact = {
        key: value for key, value in record.items() if key in _COMPACT_ALARM_FIELDS
    }
    for key, value in record.items():
        lowered = key.casefold()
        if any(token in lowered for token in ("sample", "reading", "value", "threshold", "limit", "unit")):
            compact.setdefault(key, value)
    return compact


def _compact_mdb_properties(value: object) -> dict[str, dict[str, str]]:
    interfaces: dict[str, dict[str, str]] = {}
    current_interface = ""
    lines = value if isinstance(value, list) else []
    for raw_line in lines:
        line = str(raw_line)
        stripped = line.strip()
        if not stripped:
            continue
        if not line[:1].isspace():
            current_interface = stripped
            interfaces.setdefault(current_interface, {})
            continue
        if not current_interface or "=" not in stripped:
            continue
        name, raw_value = stripped.split("=", 1)
        if not name:
            continue
        interfaces[current_interface][name] = _compact_text(raw_value)
    return {
        interface: properties
        for interface, properties in interfaces.items()
        if properties
    }


def _compact_child_result(
    name: str,
    result: dict[str, object],
    request: dict[str, object] | None = None,
) -> dict[str, object]:
    compact = dict(result)
    if name in {"active_alarms", "active_alarms_end"}:
        records = result.get("records")
        if isinstance(records, list):
            compact["records"] = [
                _compact_alarm_record(record)
                for record in records
                if isinstance(record, dict)
            ]
        return compact

    if name in {"logs", "alarm_logs"}:
        entries = result.get("entries")
        if isinstance(entries, list):
            compact_entries: list[object] = []
            for entry in entries:
                if not isinstance(entry, dict):
                    compact_entries.append(entry)
                    continue
                item = {key: value for key, value in entry.items() if key != "lines"}
                preview, line_count, truncated = _compact_lines(entry.get("lines"), limit=5)
                item["line_count"] = entry.get("line_count", line_count)
                item["lines_preview"] = preview
                item["lines_truncated"] = truncated
                if isinstance(item.get("error"), str):
                    item["error"] = _compact_text(item["error"])
                compact_entries.append(item)
            compact["entries"] = compact_entries
        return compact

    if name.startswith("file:"):
        preview, line_count, truncated = _compact_lines(result.get("lines"))
        compact["lines"] = preview
        compact["line_count"] = result.get("line_count", line_count)
        compact["lines_truncated"] = truncated
        return compact

    if name in {"mdbctl", "busctl"} or name.startswith("mdbctl_"):
        preview, line_count, truncated = _compact_lines(result.get("stdout_lines"))
        compact["stdout_lines"] = preview
        compact["stdout"] = "\n".join(preview)
        compact["stdout_line_count"] = line_count
        compact["stdout_truncated"] = truncated
        stderr_preview, stderr_count, stderr_truncated = _compact_lines(
            result.get("stderr_lines"), limit=5
        )
        compact["stderr_lines"] = stderr_preview
        compact["stderr"] = "\n".join(stderr_preview)
        compact["stderr_line_count"] = stderr_count
        compact["stderr_truncated"] = stderr_truncated
        command_parts = (request or {}).get("command_parts")
        if (
            name.startswith("mdbctl")
            and isinstance(command_parts, list)
            and command_parts
            and command_parts[0] == "lsprop"
        ):
            properties = _compact_mdb_properties(result.get("stdout_lines"))
            compact["properties"] = properties
            compact["property_count"] = sum(
                len(interface_properties)
                for interface_properties in properties.values()
            )
        return compact

    if name in {"preflight_start", "preflight_end"}:
        checks = result.get("checks")
        if isinstance(checks, dict):
            compact_checks: dict[str, object] = {}
            for check_name, check in checks.items():
                if not isinstance(check, dict):
                    compact_checks[str(check_name)] = check
                    continue
                item = dict(check)
                preview, line_count, truncated = _compact_lines(check.get("lines"), limit=3)
                item["lines"] = preview
                item["line_count"] = line_count
                item["lines_truncated"] = truncated
                compact_checks[str(check_name)] = item
            compact["checks"] = compact_checks
        return compact

    return compact


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class WorkflowDeadline:
    """A monotonic end-to-end budget shared by every workflow lane."""

    budget_seconds: float
    started_monotonic: float = field(default_factory=time.monotonic)

    def remaining(self) -> float:
        return max(
            0.0,
            self.budget_seconds - (time.monotonic() - self.started_monotonic),
        )

    def exhausted(self) -> bool:
        return self.remaining() <= DEADLINE_EPSILON_SECONDS

    def cap_timeout(self, requested: float) -> tuple[float, bool]:
        remaining = self.remaining()
        return min(float(requested), remaining), remaining < float(requested)

    def as_result(self) -> dict[str, object]:
        remaining = self.remaining()
        return {
            "budget_seconds": self.budget_seconds,
            "remaining_seconds": round(remaining, 3),
            "elapsed_seconds": round(
                max(0.0, self.budget_seconds - remaining), 3
            ),
            "exhausted": remaining <= DEADLINE_EPSILON_SECONDS,
        }


def skipped_result(name: str, reason: str) -> dict[str, object]:
    return {
        "name": name,
        "ok": False,
        "code": "skipped",
        "returncode": None,
        "started_at": None,
        "completed_at": None,
        "command": [],
        "payload": None,
        "error": reason,
    }


def _failed_tool_result(
    name: str,
    command: list[str],
    started_at: str,
    *,
    code: str,
    returncode: int,
    error: str,
    payload: object = None,
) -> dict[str, object]:
    return {
        "name": name,
        "ok": False,
        "code": code,
        "returncode": returncode,
        "started_at": started_at,
        "completed_at": utc_now(),
        "command": command,
        "payload": payload,
        "error": error,
    }


def _infer_child_contract(command: list[str]) -> tuple[str, str]:
    expected_tool = ""
    for item in command[:3]:
        path = Path(item)
        if path.suffix == ".py":
            expected_tool = path.stem
            break
    expected_ip = ""
    try:
        index = command.index("--ip")
    except ValueError:
        pass
    else:
        if index + 1 < len(command):
            expected_ip = command[index + 1]
    return expected_tool, expected_ip


def _validate_child_contract(
    payload: object,
    *,
    expected_tool: str,
    expected_ip: str,
    expected_returncode: int,
) -> list[str]:
    if not isinstance(payload, dict):
        return ["payload must be a JSON object"]
    errors: list[str] = []
    if payload.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            "schema_version must be "
            f"{SCHEMA_VERSION!r}, got {payload.get('schema_version')!r}"
        )
    if expected_tool and payload.get("tool") != expected_tool:
        errors.append(
            f"tool must be {expected_tool!r}, got {payload.get('tool')!r}"
        )
    if expected_ip and payload.get("ip") != expected_ip:
        errors.append(f"ip must be {expected_ip!r}, got {payload.get('ip')!r}")
    for field_name, expected_type in (
        ("tool", str),
        ("ip", str),
        ("observed_at", str),
        ("ok", bool),
        ("code", str),
        ("normalized_code", str),
        ("request", dict),
        ("result", dict),
        ("warnings", list),
        ("error", str),
    ):
        if not isinstance(payload.get(field_name), expected_type):
            errors.append(f"{field_name} must be {expected_type.__name__}")
    payload_returncode = payload.get("returncode")
    if not isinstance(payload_returncode, int) or isinstance(payload_returncode, bool):
        errors.append("returncode must be int")
    elif payload_returncode != expected_returncode:
        errors.append(
            "returncode must match the child process status "
            f"{expected_returncode}, got {payload_returncode}"
        )
    warnings = payload.get("warnings")
    if isinstance(warnings, list) and not all(
        isinstance(warning, str) for warning in warnings
    ):
        errors.append("warnings entries must be str")
    code = payload.get("code")
    normalized_code = payload.get("normalized_code")
    if isinstance(code, str) and isinstance(normalized_code, str):
        expected_normalized = code.replace("-", "_")
        if normalized_code != expected_normalized:
            errors.append(
                f"normalized_code must be {expected_normalized!r}, "
                f"got {normalized_code!r}"
            )
    observed_at = payload.get("observed_at")
    if isinstance(observed_at, str):
        try:
            parsed_observed_at = datetime.fromisoformat(observed_at)
        except ValueError:
            errors.append("observed_at must be an ISO-8601 timestamp")
        else:
            if (
                parsed_observed_at.tzinfo is None
                or parsed_observed_at.utcoffset() is None
            ):
                errors.append("observed_at must include a numeric timezone offset")
    return errors


def run_json_tool(
    name: str,
    command: list[str],
    env: dict[str, str],
    timeout: int | float,
    *,
    deadline: WorkflowDeadline | None = None,
    exit_grace: int | float = CHILD_EXIT_GRACE_SECONDS,
) -> dict[str, object]:
    """Run one child CLI and preserve its validated JSON contract.

    ``timeout`` remains the child's remote-work budget.  The parent waits a
    small additional bounded interval so a child that reaches its own deadline
    can serialize a structured failure and exit instead of losing that evidence
    to a simultaneous outer ``TimeoutExpired``.  The workflow deadline still
    caps the combined work and exit-wait interval.
    """

    started_at = utc_now()
    work_timeout = float(timeout)
    completion_grace = max(0.0, float(exit_grace))
    effective_timeout = work_timeout + completion_grace
    deadline_limited = False
    if deadline is not None:
        effective_timeout, deadline_limited = deadline.cap_timeout(effective_timeout)
        if effective_timeout <= 0:
            return _failed_tool_result(
                name,
                command,
                started_at,
                code="workflow_deadline_exceeded",
                returncode=124,
                error="Workflow deadline was exhausted before the tool started",
            )
    reserved_grace = min(
        completion_grace,
        max(0.0, effective_timeout - 1.0),
    )
    bounded_work_timeout = min(
        work_timeout,
        max(1.0, effective_timeout - reserved_grace),
    )
    child_timeout = max(1, int(bounded_work_timeout))
    executed_command = list(command)
    for index, option in enumerate(executed_command[:-1]):
        if option not in _CHILD_TIMEOUT_OPTIONS:
            continue
        try:
            configured = int(executed_command[index + 1])
        except (TypeError, ValueError):
            continue
        executed_command[index + 1] = str(min(configured, child_timeout))
    try:
        cp = subprocess.run(
            executed_command,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        code = (
            "workflow_deadline_exceeded"
            if deadline_limited or (deadline is not None and deadline.exhausted())
            else "tool_timeout"
        )
        scope = "workflow deadline" if code == "workflow_deadline_exceeded" else "tool timeout"
        duration = (
            f"{effective_timeout:g}s"
            if code == "workflow_deadline_exceeded" or completion_grace <= 0
            else (
                f"{work_timeout:g}s plus {completion_grace:g}s "
                "child-exit grace"
            )
        )
        return _failed_tool_result(
            name,
            executed_command,
            started_at,
            code=code,
            returncode=124,
            error=f"{scope} exceeded after {duration}",
        )
    except OSError as exc:
        return _failed_tool_result(
            name,
            executed_command,
            started_at,
            code="tool_start_failed",
            returncode=126,
            error=str(exc),
        )

    stdout = cp.stdout.strip()
    try:
        payload = json.loads(stdout) if stdout else None
    except json.JSONDecodeError as exc:
        return _failed_tool_result(
            name,
            executed_command,
            started_at,
            code="invalid_tool_output",
            returncode=cp.returncode,
            error=f"Invalid JSON output: {exc}",
        )

    expected_tool, expected_ip = _infer_child_contract(executed_command)
    contract_errors = _validate_child_contract(
        payload,
        expected_tool=expected_tool,
        expected_ip=expected_ip,
        expected_returncode=cp.returncode,
    )
    if not contract_errors and isinstance(payload, dict):
        contract_errors.extend(
            validate_child_result_contract(payload, expected_tool=expected_tool)
        )
    if contract_errors:
        return _failed_tool_result(
            name,
            executed_command,
            started_at,
            code="invalid_tool_contract",
            returncode=cp.returncode,
            error="; ".join(contract_errors),
            payload=payload,
        )

    payload_ok = bool(payload.get("ok")) if isinstance(payload, dict) else False
    code = (
        str(payload.get("code", "unknown"))
        if isinstance(payload, dict)
        else "invalid_tool_output"
    )
    error = str(payload.get("error", "")) if isinstance(payload, dict) else ""
    if not error and cp.returncode != 0:
        error = cp.stderr.strip() or stdout
    return {
        "name": name,
        "ok": cp.returncode == 0 and payload_ok,
        "code": code,
        "returncode": cp.returncode,
        "started_at": started_at,
        "completed_at": utc_now(),
        "command": executed_command,
        "payload": payload,
        "error": error,
    }


def run_python_json_tool(
    name: str,
    command: list[str],
    invoke,
    timeout: int | float,
    *,
    deadline: WorkflowDeadline | None = None,
) -> dict[str, object]:
    """Invoke one existing CLI entry point in-process and validate its JSON.

    The collector remains responsible for its transport timeout.  This wrapper
    caps the public timeout arguments against the shared workflow deadline,
    captures the unchanged CLI envelope, and applies the same contract checks
    as :func:`run_json_tool` without starting a Python helper process.
    """

    started_at = utc_now()
    effective_timeout = float(timeout)
    if deadline is not None:
        effective_timeout, _limited = deadline.cap_timeout(effective_timeout)
        if effective_timeout <= 0:
            return _failed_tool_result(
                name,
                command,
                started_at,
                code="workflow_deadline_exceeded",
                returncode=124,
                error="Workflow deadline was exhausted before the tool started",
            )
    child_timeout = max(1, int(effective_timeout))
    executed_command = list(command)
    for index, option in enumerate(executed_command[:-1]):
        if option not in _CHILD_TIMEOUT_OPTIONS:
            continue
        try:
            configured = int(executed_command[index + 1])
        except (TypeError, ValueError):
            continue
        executed_command[index + 1] = str(min(configured, child_timeout))

    try:
        with _capture_thread_output() as (stdout_buffer, stderr_buffer):
            raw_returncode = invoke(executed_command)
        returncode = 0 if raw_returncode is None else int(raw_returncode)
    except SystemExit as exc:
        returncode = int(exc.code) if isinstance(exc.code, int) else 2
    except Exception as exc:
        return _failed_tool_result(
            name,
            executed_command,
            started_at,
            code="tool_execution_failed",
            returncode=126,
            error=str(exc),
        )

    stdout = stdout_buffer.getvalue().strip()
    stderr = stderr_buffer.getvalue().strip()
    try:
        payload = json.loads(stdout) if stdout else None
    except json.JSONDecodeError as exc:
        return _failed_tool_result(
            name,
            executed_command,
            started_at,
            code="invalid_tool_output",
            returncode=returncode,
            error=f"Invalid JSON output: {exc}",
        )

    expected_tool, expected_ip = _infer_child_contract(executed_command)
    contract_errors = _validate_child_contract(
        payload,
        expected_tool=expected_tool,
        expected_ip=expected_ip,
        expected_returncode=returncode,
    )
    if not contract_errors and isinstance(payload, dict):
        contract_errors.extend(
            validate_child_result_contract(payload, expected_tool=expected_tool)
        )
    if contract_errors:
        return _failed_tool_result(
            name,
            executed_command,
            started_at,
            code="invalid_tool_contract",
            returncode=returncode,
            error="; ".join(contract_errors),
            payload=payload,
        )

    payload_ok = bool(payload.get("ok")) if isinstance(payload, dict) else False
    code = (
        str(payload.get("code", "unknown"))
        if isinstance(payload, dict)
        else "invalid_tool_output"
    )
    error = str(payload.get("error", "")) if isinstance(payload, dict) else ""
    if not error and returncode != 0:
        error = stderr or stdout
    return {
        "name": name,
        "ok": returncode == 0 and payload_ok,
        "code": code,
        "returncode": returncode,
        "started_at": started_at,
        "completed_at": utc_now(),
        "command": executed_command,
        "payload": payload,
        "error": error,
    }


def compact_tool_result(tool_result: dict[str, object]) -> dict[str, object]:
    """Keep evidence once while dropping wrapper/child envelope duplication."""

    payload = tool_result.get("payload")
    payload_dict = payload if isinstance(payload, dict) else {}
    name = str(tool_result.get("name", ""))
    request = payload_dict.get("request", {})
    request_dict = request if isinstance(request, dict) else {}
    result = payload_dict.get("result", {})
    result_dict = result if isinstance(result, dict) else {}
    compact_result = _compact_child_result(name, result_dict, request_dict)
    return {
        "name": tool_result.get("name"),
        "ok": bool(tool_result.get("ok")),
        "code": tool_result.get("code", "unknown"),
        "returncode": tool_result.get("returncode"),
        "started_at": tool_result.get("started_at"),
        "completed_at": tool_result.get("completed_at"),
        "observed_at": payload_dict.get("observed_at")
        or tool_result.get("completed_at"),
        "command": tool_result.get("command", []),
        "request": request_dict,
        "error": tool_result.get("error", ""),
        "warnings": payload_dict.get("warnings", []),
        "result": compact_result,
    }


def _compact_lanes(lanes: dict[str, object]) -> dict[str, object]:
    compact: dict[str, object] = {}
    for lane_name, lane_value in lanes.items():
        if not isinstance(lane_value, dict):
            compact[lane_name] = lane_value
            continue
        lane_result: dict[str, object] = {}
        for name, value in lane_value.items():
            if name == "files" and isinstance(value, dict):
                lane_result[name] = {
                    path: compact_tool_result(item)
                    for path, item in value.items()
                    if isinstance(item, dict)
                }
            elif isinstance(value, dict) and "code" in value:
                lane_result[name] = compact_tool_result(value)
            else:
                lane_result[name] = value
        compact[lane_name] = lane_result
    return compact


def _compact_correlation(correlation: dict[str, object]) -> dict[str, object]:
    compact = dict(correlation)
    source_search = compact.get("source_search")
    if isinstance(source_search, dict):
        source_compact = dict(source_search)
        matches = source_compact.get("matches")
        source_compact["match_count"] = len(matches) if isinstance(matches, list) else 0
        source_compact.pop("hits", None)
        source_compact.pop("matches", None)
        compact["source_search"] = source_compact
    records = compact.get("records")
    if isinstance(records, list):
        compact_records: list[object] = []
        for record in records:
            if not isinstance(record, dict):
                compact_records.append(record)
                continue
            item = dict(record)
            for legacy_field in (
                "source_hits",
                "log_hits",
                "instance_log_hits",
                "time_aligned_log_hits",
                "complete_log_hits",
            ):
                item.pop(legacy_field, None)
            compact_records.append(item)
        compact["records"] = compact_records
    evidence_pool = compact.get("evidence_pool")
    if isinstance(evidence_pool, dict):
        pool = dict(evidence_pool)
        source_matches = pool.get("source_matches")
        if isinstance(source_matches, list):
            compact_sources: list[object] = []
            for match in source_matches:
                if not isinstance(match, dict):
                    compact_sources.append(match)
                    continue
                item = dict(match)
                text = str(item.get("text", ""))
                item["text"] = _compact_text(text)
                item["text_truncated"] = bool(
                    item.get("line_truncated") or len(text) > _COMPACT_TEXT_LIMIT
                )
                compact_sources.append(item)
            pool["source_matches"] = compact_sources

        alarm_refs: set[int] = set()
        if isinstance(records, list):
            for record in records:
                if not isinstance(record, dict):
                    continue
                alarm_refs.update(
                    int(ref) for ref in record.get("log_refs", []) if isinstance(ref, int)
                )
                evidence = record.get("evidence")
                if isinstance(evidence, dict):
                    for dimension in evidence.values():
                        if not isinstance(dimension, dict):
                            continue
                        alarm_refs.update(
                            int(ref)
                            for ref in dimension.get("log_refs", [])
                            if isinstance(ref, int)
                        )
        workflow_refs = {
            int(ref)
            for ref in compact.get("workflow_keyword_refs", [])
            if isinstance(ref, int)
        }

        def indexed_lines(value: object, refs: set[int]) -> list[dict[str, object]]:
            lines = list(value) if isinstance(value, list) else []
            selected = sorted(ref for ref in refs if 0 <= ref < len(lines))
            if not selected:
                selected = list(range(min(len(lines), _COMPACT_LOG_FALLBACK)))
            compact_lines: list[dict[str, object]] = []
            for index in selected:
                raw = lines[index]
                item = dict(raw) if isinstance(raw, dict) else {"text": str(raw)}
                text = str(item.get("text", ""))
                item["id"] = index
                item["text"] = _compact_text(text)
                item["text_truncated"] = bool(
                    item.get("text_truncated") or len(text) > _COMPACT_TEXT_LIMIT
                )
                compact_lines.append(item)
            return compact_lines

        pool["alarm_log_lines"] = indexed_lines(
            pool.get("alarm_log_lines"), alarm_refs
        )
        pool["workflow_log_lines"] = indexed_lines(
            pool.get("workflow_log_lines"), workflow_refs
        )
        compact["evidence_pool"] = pool
    compact.pop("workflow_keyword_hits", None)
    return compact


def _compact_freshness(freshness: dict[str, object]) -> dict[str, object]:
    compact: dict[str, object] = {}
    endpoint_names = {
        "preflight_end",
        "active_alarms_end",
        "version_end",
        "uptime_end",
    }
    for key, value in freshness.items():
        if key in endpoint_names and isinstance(value, dict):
            endpoint = compact_tool_result(value)
            result = endpoint.get("result")
            result_dict = result if isinstance(result, dict) else {}
            if key == "preflight_end":
                endpoint["result"] = {
                    field: result_dict.get(field)
                    for field in (
                        "overall_ok",
                        "all_checks_ok",
                        "overall_code",
                        "capabilities",
                        "capability_assurance",
                        "failed_checks",
                    )
                    if field in result_dict
                }
            elif key == "active_alarms_end":
                endpoint["result"] = {
                    field: result_dict.get(field)
                    for field in ("interface", "signature", "record_count")
                    if field in result_dict
                }
            compact[key] = endpoint
        else:
            compact[key] = value
    return compact


def compact_workflow_payload(payload: dict[str, object]) -> dict[str, object]:
    """Render the workflow's agent-facing, de-duplicated JSON form."""

    result = payload.get("result")
    result_dict = result if isinstance(result, dict) else {}
    compact_result: dict[str, Any] = {
        "started_at": result_dict.get("started_at"),
        "completed_at": result_dict.get("completed_at"),
        "deadline": result_dict.get("deadline", {}),
        "capabilities": result_dict.get("capabilities", {}),
        "source_root_resolution": result_dict.get("source_root_resolution", {}),
        "preflight_start": compact_tool_result(
            result_dict.get("preflight_start", {})
            if isinstance(result_dict.get("preflight_start"), dict)
            else {}
        ),
        "lanes": _compact_lanes(
            result_dict.get("lanes", {})
            if isinstance(result_dict.get("lanes"), dict)
            else {}
        ),
        "freshness": _compact_freshness(
            result_dict.get("freshness", {})
            if isinstance(result_dict.get("freshness"), dict)
            else {}
        ),
        "correlation": _compact_correlation(
            result_dict.get("correlation", {})
            if isinstance(result_dict.get("correlation"), dict)
            else {}
        ),
        "summary": result_dict.get("summary", {}),
        "runtime": result_dict.get("runtime", {}),
    }
    return {
        "schema_version": payload.get("schema_version"),
        "tool": payload.get("tool"),
        "ip": payload.get("ip"),
        "observed_at": payload.get("observed_at"),
        "ok": payload.get("ok"),
        "code": payload.get("code"),
        "normalized_code": payload.get("normalized_code"),
        "returncode": payload.get("returncode"),
        "warnings": payload.get("warnings", []),
        "error": payload.get("error", ""),
        "request": payload.get("request", {}),
        "result": compact_result,
    }
