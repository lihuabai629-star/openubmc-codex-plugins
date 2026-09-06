#!/usr/bin/env python3
"""Freshness snapshot extraction and conservative comparison."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import re
from typing import Any


_BMC_TIME_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s+[+-]\d{4})$"
)
_ALARM_IDENTITY_FIELDS = (
    "EventCode",
    "EventName",
    "ComponentInstance",
    "ComponentLocation",
    "ComponentName",
)
_ALARM_PAYLOAD_FIELDS = (
    "State",
    "Severity",
    "Timestamp",
    "sample",
    "reading",
    "value",
    "threshold",
    "limit",
    "unit",
)


def payload_result(tool_result: dict[str, object]) -> dict[str, Any]:
    payload = tool_result.get("payload")
    if not isinstance(payload, dict):
        return {}
    result = payload.get("result")
    return result if isinstance(result, dict) else {}


def snapshot_available(tool_result: dict[str, object]) -> bool:
    if "ok" in tool_result and not bool(tool_result.get("ok")):
        return False
    return bool(payload_result(tool_result))


def preflight_checks(result: dict[str, object]) -> dict[str, dict[str, object]]:
    checks = payload_result(result).get("checks")
    if not isinstance(checks, dict):
        return {}
    return {
        str(name): item
        for name, item in checks.items()
        if isinstance(item, dict)
    }


def preflight_capabilities(result: dict[str, object]) -> dict[str, bool]:
    raw = payload_result(result).get("capabilities")
    capabilities = raw if isinstance(raw, dict) else {}
    checks = preflight_checks(result)
    remote_object_hint = bool(
        capabilities.get("remote_object", capabilities.get("ssh_object"))
    )

    def detailed_capability(
        capability_name: str,
        check_name: str,
        *,
        fallback: bool,
    ) -> bool:
        if capability_name in capabilities:
            return bool(capabilities[capability_name])
        if check_name in checks:
            return check_ok(checks, check_name)
        return fallback

    ssh_transport = detailed_capability(
        "ssh_transport", "SSH", fallback=remote_object_hint
    )
    dbus_env = detailed_capability(
        "dbus_env", "DBUS_ENV", fallback=remote_object_hint
    )
    mdbctl = ssh_transport and detailed_capability(
        "mdbctl", "MDBCTL", fallback=remote_object_hint
    )
    busctl = (
        ssh_transport
        and dbus_env
        and detailed_capability("busctl", "BUSCTL", fallback=remote_object_hint)
    )
    active_alarm_transport = detailed_capability(
        "active_alarm_transport", "BUSCTL", fallback=busctl
    ) and busctl
    active_alarms = bool(
        capabilities.get("active_alarms", active_alarm_transport)
    ) and active_alarm_transport
    remote_object = mdbctl or busctl
    if "remote_log_file" in capabilities or "telnet_files" in capabilities:
        remote_log_file = bool(
            capabilities.get("remote_log_file", capabilities.get("telnet_files"))
        )
    else:
        remote_log_file = check_ok(checks, "TELNET")
    if "telnet_logs" in capabilities:
        telnet_logs = remote_log_file and bool(capabilities["telnet_logs"])
    elif capabilities.get("telnet_logs_present") is not None:
        telnet_logs = remote_log_file and bool(capabilities["telnet_logs_present"])
    elif "LOG_FILES" in checks:
        telnet_logs = remote_log_file and check_ok(checks, "LOG_FILES")
    else:
        telnet_logs = remote_log_file
    return {
        "remote_object": remote_object,
        "remote_log_file": remote_log_file,
        "combined_snapshot": remote_object and remote_log_file,
        "ssh_transport": ssh_transport,
        "dbus_env": dbus_env,
        "mdbctl": mdbctl,
        "busctl": busctl,
        "active_alarm_transport": active_alarm_transport,
        "active_alarm_endpoint_verified": bool(
            capabilities.get("active_alarm_endpoint_verified", False)
        ),
        "active_alarms": active_alarms,
        "telnet_logs": telnet_logs,
    }


def check_ok(checks: dict[str, dict[str, object]], name: str) -> bool:
    item = checks.get(name)
    return bool(item and item.get("ok"))


def alarm_records(tool_result: dict[str, object]) -> list[dict[str, object]]:
    records = payload_result(tool_result).get("records")
    if not isinstance(records, list):
        return []
    return [record for record in records if isinstance(record, dict)]


def _record_value(record: dict[str, object], field: str) -> str:
    if field in record:
        return str(record.get(field, ""))
    wanted = field.casefold()
    for key, value in record.items():
        if str(key).casefold() == wanted:
            return str(value)
    return ""


def alarm_identity(record: dict[str, object]) -> tuple[str, ...]:
    """Return fields that identify the alarm independently of mutable payload."""

    return tuple(_record_value(record, field) for field in _ALARM_IDENTITY_FIELDS)


def alarm_payload(record: dict[str, object]) -> tuple[str, ...]:
    """Return state and measurement fields whose changes must remain visible."""

    return tuple(_record_value(record, field) for field in _ALARM_PAYLOAD_FIELDS)


def _payload_dict(payload: tuple[str, ...]) -> dict[str, str]:
    return dict(zip(_ALARM_PAYLOAD_FIELDS, payload))


def alarm_summary(tool_result: dict[str, object]) -> dict[str, object]:
    records = alarm_records(tool_result)
    raw_count = payload_result(tool_result).get("record_count")
    record_count = raw_count if isinstance(raw_count, int) else len(records)
    return {
        "available": snapshot_available(tool_result),
        "record_count": record_count,
        "identities": [alarm_identity(record) for record in records],
        "payloads": [alarm_payload(record) for record in records],
    }


def _expanded_counter_difference(
    left: Counter[tuple[str, ...]], right: Counter[tuple[str, ...]]
) -> list[list[str]]:
    expanded: list[list[str]] = []
    for identity in sorted(left):
        for _ in range(max(0, left[identity] - right[identity])):
            expanded.append(list(identity))
    return expanded


def compare_alarm_snapshots(
    before: dict[str, object], after: dict[str, object]
) -> dict[str, object]:
    before_summary = alarm_summary(before)
    after_summary = alarm_summary(after)
    comparable = bool(before_summary["available"] and after_summary["available"])
    result: dict[str, object] = {
        "comparable": comparable,
        "identity_fields": list(_ALARM_IDENTITY_FIELDS),
        "payload_fields": list(_ALARM_PAYLOAD_FIELDS),
        "before_count": before_summary["record_count"],
        "after_count": after_summary["record_count"],
        "added": [],
        "removed": [],
        "identity_changed": None,
        "payload_changed": None,
        "payload_changes": [],
        "changed": None,
        "reason": "" if comparable else "one_or_both_alarm_snapshots_unavailable",
    }
    if not comparable:
        return result
    before_counter = Counter(before_summary["identities"])
    after_counter = Counter(after_summary["identities"])
    before_groups: defaultdict[
        tuple[str, ...], list[tuple[str, ...]]
    ] = defaultdict(list)
    after_groups: defaultdict[
        tuple[str, ...], list[tuple[str, ...]]
    ] = defaultdict(list)
    for identity, payload in zip(
        before_summary["identities"], before_summary["payloads"]
    ):
        before_groups[identity].append(payload)
    for identity, payload in zip(
        after_summary["identities"], after_summary["payloads"]
    ):
        after_groups[identity].append(payload)

    payload_changes: list[dict[str, object]] = []
    for identity in sorted(set(before_groups).intersection(after_groups)):
        before_payloads = Counter(before_groups[identity])
        after_payloads = Counter(after_groups[identity])
        unchanged = before_payloads & after_payloads
        before_remaining = list((before_payloads - unchanged).elements())
        after_remaining = list((after_payloads - unchanged).elements())
        before_remaining.sort()
        after_remaining.sort()
        for before_payload, after_payload in zip(before_remaining, after_remaining):
            changed_fields = [
                field
                for field, before_value, after_value in zip(
                    _ALARM_PAYLOAD_FIELDS, before_payload, after_payload
                )
                if before_value != after_value
            ]
            if changed_fields:
                payload_changes.append(
                    {
                        "identity": list(identity),
                        "before": _payload_dict(before_payload),
                        "after": _payload_dict(after_payload),
                        "changed_fields": changed_fields,
                    }
                )

    identity_changed = before_counter != after_counter
    payload_changed = bool(payload_changes)
    result.update(
        {
            "added": _expanded_counter_difference(after_counter, before_counter),
            "removed": _expanded_counter_difference(before_counter, after_counter),
            "identity_changed": identity_changed,
            "payload_changed": payload_changed,
            "payload_changes": payload_changes,
            "changed": identity_changed or payload_changed,
        }
    )
    return result


def file_lines(tool_result: dict[str, object]) -> list[str]:
    lines = payload_result(tool_result).get("lines")
    return [str(line) for line in lines] if isinstance(lines, list) else []


def compare_file_snapshots(
    before: dict[str, object], after: dict[str, object]
) -> dict[str, object]:
    before_lines = file_lines(before)
    after_lines = file_lines(after)
    comparable = bool(snapshot_available(before) and snapshot_available(after))
    return {
        "comparable": comparable,
        "before": before_lines,
        "after": after_lines,
        "changed": before_lines != after_lines if comparable else None,
        "reason": "" if comparable else "one_or_both_file_snapshots_unavailable",
    }


def _parse_uptime(lines: list[str]) -> float | None:
    if not lines:
        return None
    try:
        value = float(lines[0].split()[0])
    except (ValueError, IndexError):
        return None
    return value if value >= 0 else None


def _parse_snapshot_time(
    tool_result: dict[str, object], *fields: str
) -> datetime | None:
    for field in fields:
        raw = tool_result.get(field)
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = datetime.fromisoformat(raw)
            except ValueError:
                continue
            if parsed.tzinfo is not None:
                return parsed
    return None


def _observation_elapsed_seconds(
    before: dict[str, object], after: dict[str, object]
) -> float | None:
    before_time = _parse_snapshot_time(
        before, "completed_at", "observed_at", "started_at"
    )
    after_time = _parse_snapshot_time(
        after, "completed_at", "observed_at", "started_at"
    )
    if before_time is None or after_time is None:
        return None
    elapsed = (after_time - before_time).total_seconds()
    return elapsed if elapsed >= 0 else None


def _observation_elapsed_bounds(
    before: dict[str, object], after: dict[str, object]
) -> tuple[float | None, float | None]:
    before_start = _parse_snapshot_time(
        before, "started_at", "observed_at", "completed_at"
    )
    before_end = _parse_snapshot_time(
        before, "completed_at", "observed_at", "started_at"
    )
    after_start = _parse_snapshot_time(
        after, "started_at", "observed_at", "completed_at"
    )
    after_end = _parse_snapshot_time(
        after, "completed_at", "observed_at", "started_at"
    )
    if None in (before_start, before_end, after_start, after_end):
        return None, None
    assert before_start is not None
    assert before_end is not None
    assert after_start is not None
    assert after_end is not None
    lower = max(0.0, (after_start - before_end).total_seconds())
    upper = (after_end - before_start).total_seconds()
    return (lower, upper) if upper >= 0 else (None, None)


def compare_uptime_snapshots(
    before: dict[str, object],
    after: dict[str, object],
    *,
    bmc_elapsed_seconds: float | None = None,
    reboot_tolerance_seconds: float = 5.0,
) -> dict[str, object]:
    before_seconds = _parse_uptime(file_lines(before))
    after_seconds = _parse_uptime(file_lines(after))
    comparable = bool(
        snapshot_available(before)
        and snapshot_available(after)
        and before_seconds is not None
        and after_seconds is not None
    )
    observation_elapsed = _observation_elapsed_seconds(before, after)
    observation_elapsed_lower, observation_elapsed_upper = _observation_elapsed_bounds(
        before, after
    )
    valid_bmc_elapsed = (
        float(bmc_elapsed_seconds)
        if isinstance(bmc_elapsed_seconds, (int, float))
        and not isinstance(bmc_elapsed_seconds, bool)
        and bmc_elapsed_seconds >= 0
        else None
    )
    if observation_elapsed_lower is not None and observation_elapsed_lower > 0:
        elapsed_for_reboot = observation_elapsed_lower
        elapsed_source = "observer"
    elif valid_bmc_elapsed is not None:
        elapsed_for_reboot = valid_bmc_elapsed
        elapsed_source = "bmc_clock"
    else:
        elapsed_for_reboot = None
        elapsed_source = "unavailable"
    uptime_growth = after_seconds - before_seconds if comparable else None
    expected_after = (
        before_seconds + elapsed_for_reboot
        if comparable and elapsed_for_reboot is not None
        else None
    )
    uptime_gap = (
        expected_after - after_seconds
        if expected_after is not None and after_seconds is not None
        else None
    )
    direct_regression = bool(
        comparable
        and before_seconds is not None
        and after_seconds is not None
        and after_seconds < before_seconds
    )
    hidden_reboot = bool(
        comparable
        and uptime_gap is not None
        and uptime_gap > max(0.0, reboot_tolerance_seconds)
    )
    return {
        "comparable": comparable,
        "before_seconds": before_seconds,
        "after_seconds": after_seconds,
        "elapsed_seconds": uptime_growth,
        "observation_elapsed_seconds": observation_elapsed,
        "observation_elapsed_lower_bound_seconds": observation_elapsed_lower,
        "observation_elapsed_upper_bound_seconds": observation_elapsed_upper,
        "bmc_elapsed_seconds": valid_bmc_elapsed,
        "elapsed_source": elapsed_source,
        "expected_after_seconds": expected_after,
        "uptime_gap_seconds": uptime_gap,
        "hidden_reboot_detected": hidden_reboot if comparable else None,
        "reboot_detected": direct_regression or hidden_reboot if comparable else None,
        "reboot_detection_complete": bool(
            comparable and (direct_regression or elapsed_for_reboot is not None)
        ),
        "changed": before_seconds != after_seconds if comparable else None,
        "reason": "" if comparable else "uptime_snapshot_unavailable_or_invalid",
    }


def compare_preflight(
    before: dict[str, object], after: dict[str, object]
) -> dict[str, object]:
    before_checks = preflight_checks(before)
    after_checks = preflight_checks(after)
    comparable = bool(
        snapshot_available(before)
        and snapshot_available(after)
        and before_checks
        and after_checks
    )
    if not comparable:
        return {
            "comparable": False,
            "changed": None,
            "changes": [],
            "reason": "one_or_both_preflight_snapshots_unavailable",
        }
    names = sorted(set(before_checks) | set(after_checks))
    changes = []
    for name in names:
        before_ok = bool(before_checks.get(name, {}).get("ok"))
        after_ok = bool(after_checks.get(name, {}).get("ok"))
        if before_ok != after_ok:
            changes.append(
                {"check": name, "before_ok": before_ok, "after_ok": after_ok}
            )
    return {
        "comparable": True,
        "changed": bool(changes),
        "changes": changes,
        "reason": "",
    }


def extract_bmc_time(preflight: dict[str, object]) -> str | None:
    checks = preflight_checks(preflight)
    for check_name in ("SSH", "TELNET"):
        lines = checks.get(check_name, {}).get("lines")
        if not isinstance(lines, list):
            continue
        for raw_line in lines:
            line = str(raw_line).strip()
            match = _BMC_TIME_RE.match(line)
            if match:
                return match.group(1)
    return None


def compare_bmc_time_snapshots(
    before: dict[str, object], after: dict[str, object]
) -> dict[str, object]:
    before_time = extract_bmc_time(before)
    after_time = extract_bmc_time(after)
    comparable = bool(
        snapshot_available(before)
        and snapshot_available(after)
        and before_time
        and after_time
    )
    elapsed_seconds: float | None = None
    if comparable:
        try:
            before_dt = datetime.strptime(before_time, "%Y-%m-%d %H:%M:%S %z")
            after_dt = datetime.strptime(after_time, "%Y-%m-%d %H:%M:%S %z")
        except ValueError:
            comparable = False
        else:
            elapsed_seconds = (after_dt - before_dt).total_seconds()
    return {
        "comparable": comparable,
        "before": before_time,
        "after": after_time,
        "elapsed_seconds": elapsed_seconds if comparable else None,
        "clock_moved_backwards": elapsed_seconds < 0 if comparable else None,
        "changed": before_time != after_time if comparable else None,
        "reason": "" if comparable else "bmc_time_snapshot_unavailable_or_invalid",
    }
