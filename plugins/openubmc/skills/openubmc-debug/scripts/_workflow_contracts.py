#!/usr/bin/env python3
"""Minimal semantic result contracts for workflow child CLIs."""
from __future__ import annotations


def _validate_preflight_result(result: dict[str, object]) -> list[str]:
    errors: list[str] = []
    capabilities = result.get("capabilities")
    if not isinstance(capabilities, dict):
        errors.append("result.capabilities must be dict")
    else:
        if not capabilities:
            errors.append("result.capabilities must not be empty on success")
        for name, value in capabilities.items():
            if not isinstance(name, str):
                errors.append("result.capabilities keys must be str")
            if not isinstance(value, bool) and value is not None:
                errors.append(f"result.capabilities[{name!r}] must be bool or null")

    checks = result.get("checks")
    if not isinstance(checks, dict):
        errors.append("result.checks must be dict")
    else:
        if not checks:
            errors.append("result.checks must not be empty on success")
        for name, check in checks.items():
            prefix = f"result.checks[{name!r}]"
            if not isinstance(name, str):
                errors.append("result.checks keys must be str")
            if not isinstance(check, dict):
                errors.append(f"{prefix} must be dict")
                continue
            if not isinstance(check.get("ok"), bool):
                errors.append(f"{prefix}.ok must be bool")
            lines = check.get("lines")
            if lines is not None and (
                not isinstance(lines, list)
                or not all(isinstance(line, str) for line in lines)
            ):
                errors.append(f"{prefix}.lines must be list[str] when present")
    return errors


def _validate_active_alarm_result(result: dict[str, object]) -> list[str]:
    errors: list[str] = []
    for field in ("service", "path", "interface", "signature"):
        value = result.get(field)
        if not isinstance(value, str) or not value:
            errors.append(f"result.{field} must be non-empty str")

    records = result.get("records")
    if not isinstance(records, list):
        errors.append("result.records must be list")
        records = None
    elif not all(isinstance(record, dict) for record in records):
        errors.append("result.records entries must be dict")

    record_count = result.get("record_count")
    if (
        not isinstance(record_count, int)
        or isinstance(record_count, bool)
        or record_count < 0
    ):
        errors.append("result.record_count must be non-negative int")
    elif records is not None and record_count != len(records):
        errors.append("result.record_count must match len(result.records)")
    return errors


def _validate_log_result(result: dict[str, object]) -> list[str]:
    entries = result.get("entries")
    if not isinstance(entries, list):
        return ["result.entries must be list"]

    errors: list[str] = []
    for index, entry in enumerate(entries):
        prefix = f"result.entries[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{prefix} must be dict")
            continue
        path = entry.get("path")
        if not isinstance(path, str) or not path:
            errors.append(f"{prefix}.path must be non-empty str")
        lines = entry.get("lines")
        if not isinstance(lines, list) or not all(
            isinstance(line, str) for line in lines
        ):
            errors.append(f"{prefix}.lines must be list[str]")
            lines = None
        line_count = entry.get("line_count")
        if (
            not isinstance(line_count, int)
            or isinstance(line_count, bool)
            or line_count < 0
        ):
            errors.append(f"{prefix}.line_count must be non-negative int")
        elif lines is not None and line_count != len(lines):
            errors.append(f"{prefix}.line_count must match len({prefix}.lines)")
        bytes_returned = entry.get("bytes_returned")
        if (
            not isinstance(bytes_returned, int)
            or isinstance(bytes_returned, bool)
            or bytes_returned < 0
        ):
            errors.append(f"{prefix}.bytes_returned must be non-negative int")
        truncated = entry.get("truncated")
        if not isinstance(truncated, bool):
            errors.append(f"{prefix}.truncated must be bool")
        content_complete = entry.get("content_complete")
        if not isinstance(content_complete, bool):
            errors.append(f"{prefix}.content_complete must be bool")
        elif isinstance(truncated, bool) and content_complete == truncated:
            errors.append(f"{prefix}.content_complete must equal not truncated")

        line_numbers = entry.get("line_numbers")
        if line_numbers is not None:
            if not isinstance(line_numbers, list) or not all(
                line_number is None
                or (
                    isinstance(line_number, int)
                    and not isinstance(line_number, bool)
                    and line_number >= 0
                )
                for line_number in line_numbers
            ):
                errors.append(f"{prefix}.line_numbers must be list[int | null]")
            elif lines is not None and len(line_numbers) != len(lines):
                errors.append(
                    f"{prefix}.line_numbers must match len({prefix}.lines)"
                )
    return errors


def _validate_file_result(result: dict[str, object]) -> list[str]:
    errors: list[str] = []
    path = result.get("path")
    if not isinstance(path, str) or not path:
        errors.append("result.path must be non-empty str")
    lines = result.get("lines")
    if not isinstance(lines, list) or not all(
        isinstance(line, str) for line in lines
    ):
        errors.append("result.lines must be list[str]")
        lines = None
    line_count = result.get("line_count")
    if (
        not isinstance(line_count, int)
        or isinstance(line_count, bool)
        or line_count < 0
    ):
        errors.append("result.line_count must be non-negative int")
    elif lines is not None and line_count != len(lines):
        errors.append("result.line_count must match len(result.lines)")
    bytes_returned = result.get("bytes_returned")
    if (
        not isinstance(bytes_returned, int)
        or isinstance(bytes_returned, bool)
        or bytes_returned < 0
    ):
        errors.append("result.bytes_returned must be non-negative int")
    truncated = result.get("truncated")
    if not isinstance(truncated, bool):
        errors.append("result.truncated must be bool")
    content_complete = result.get("content_complete")
    if not isinstance(content_complete, bool):
        errors.append("result.content_complete must be bool")
    elif isinstance(truncated, bool) and content_complete == truncated:
        errors.append("result.content_complete must equal not truncated")
    return errors


def validate_child_result_contract(
    payload: dict[str, object], *, expected_tool: str
) -> list[str]:
    """Validate only fields consumed by the parent workflow.

    Failed child envelopes may carry stage-specific partial results, so their
    public failure evidence remains valid after the common envelope check.
    """

    if not payload.get("ok"):
        return []
    result = payload["result"]
    assert isinstance(result, dict)
    if expected_tool == "preflight_remote":
        return _validate_preflight_result(result)
    if expected_tool == "active_alarms":
        return _validate_active_alarm_result(result)
    if expected_tool == "collect_logs":
        return _validate_log_result(result)
    if expected_tool == "read_remote_file":
        return _validate_file_result(result)
    return []
