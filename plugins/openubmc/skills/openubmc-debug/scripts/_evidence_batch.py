#!/usr/bin/env python3
"""Pure, bounded summaries of already captured Debug alarm and log results.

Pointers in this module are relative to the supplied tool result, never newly
issued Evidence identities. Runtime remains the authority for collection.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Mapping


BATCH_SCHEMA = "openubmc-debug.evidence-batch.v1"
MAX_EVENTS = 2048
_LOG_TIME = re.compile(
    r"^\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d"
    r"(?:\.\d{1,6})?(?:Z|[+-]\d\d:?\d\d)?(?=$|\s)"
)


def _result(value: Mapping[str, object]) -> Mapping[str, object]:
    payload = value.get("payload")
    result = payload.get("result") if isinstance(payload, Mapping) else None
    return result if isinstance(result, Mapping) else {}


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    )


def normalize_timestamp(raw: object, utc_offset_minutes: int | None = None) -> dict[str, object]:
    """Convert an epoch or explicit-offset clock; never assume local timezone."""
    if raw is None or raw == "":
        return {"status": "missing", "raw": raw, "utc": None}
    if type(raw) is int or isinstance(raw, str) and raw.isdecimal():
        try:
            epoch = int(raw)
            if epoch < 0:
                raise ValueError("negative epoch")
            return {"status": "known", "raw": raw,
                    "utc": datetime.fromtimestamp(epoch, timezone.utc).isoformat()}
        except (OverflowError, ValueError, OSError):
            return {"status": "parse_failed", "raw": raw, "utc": None}
    if not isinstance(raw, str):
        return {"status": "parse_failed", "raw": str(raw)[:128], "utc": None}
    match = _LOG_TIME.match(raw)
    candidate = match.group(0) if match is not None else raw
    if len(candidate) > 128:
        return {"status": "parse_failed", "raw": candidate[:128], "utc": None}
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return {"status": "parse_failed", "raw": candidate, "utc": None}
    if parsed.tzinfo is None:
        if (type(utc_offset_minutes) is not int
                or not -14 * 60 <= utc_offset_minutes <= 14 * 60):
            return {"status": "timezone_unknown", "raw": candidate, "utc": None}
        parsed = parsed.replace(tzinfo=timezone(timedelta(minutes=utc_offset_minutes)))
    return {"status": "known", "raw": candidate,
            "utc": parsed.astimezone(timezone.utc).isoformat()}


def _complete(tool_result: Mapping[str, object], *, collection: str) -> bool:
    payload = _result(tool_result)
    if tool_result.get("ok") is not True or not payload:
        return False
    if payload.get("content_complete", True) is not True or payload.get("truncated") is True:
        return False
    warnings = tool_result.get("warnings")
    if isinstance(warnings, list) and any("truncat" in str(item).casefold() for item in warnings):
        return False
    if collection == "logs":
        entries = payload.get("entries")
        return isinstance(entries, list) and all(
            isinstance(entry, Mapping)
            and isinstance(entry.get("lines"), list)
            and entry.get("ok", True) is True
            and entry.get("content_complete", True) is True
            and entry.get("truncated", False) is False
            for entry in entries
        )
    records = payload.get("records")
    return (isinstance(records, list) and
            type(payload.get("record_count", len(records))) is int and
            payload.get("record_count", len(records)) == len(records))


def _collapse(items: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str, str], dict[str, object]] = {}
    for item in items:
        key = (str(item["kind"]), str(item["source"]), _canonical(item["value"]))
        group = grouped.get(key)
        if group is None:
            group = {key: value for key, value in item.items() if key != "ref"}
            group["count"] = 0
            group["refs"] = []
            grouped[key] = group
        group["count"] = int(group["count"]) + 1
        group["refs"].append(item["ref"])
    return list(grouped.values())


def summarize_captured_snapshot(
    *, target: str | None, source_version: str | None, target_epoch: int | None,
    alarms: Mapping[str, object], logs: Mapping[str, object],
    utc_offset_minutes: int | None = None,
) -> dict[str, object]:
    """Summarize captured helper results without changing or fetching their raw data."""
    if not isinstance(alarms, Mapping) or not isinstance(logs, Mapping):
        raise ValueError("captured alarm and log results are required")
    alarm_result, log_result = _result(alarms), _result(logs)
    alarm_values = alarm_result.get("records", [])
    entries = log_result.get("entries", [])
    if not isinstance(alarm_values, list) or not isinstance(entries, list):
        raise ValueError("captured alarm records and log entries must be lists")
    if len(alarm_values) > MAX_EVENTS or len(entries) > MAX_EVENTS:
        raise ValueError("captured evidence exceeds the batch record budget")
    captured_offset = log_result.get("utc_offset_minutes")
    offset_conflict = (utc_offset_minutes is not None and captured_offset is not None
                       and utc_offset_minutes != captured_offset)
    offset = (None if offset_conflict else utc_offset_minutes
              if utc_offset_minutes is not None else captured_offset)
    offset_valid = type(offset) is int and -14 * 60 <= offset <= 14 * 60
    items: list[dict[str, object]] = []
    for index, event in enumerate(alarm_values):
        if not isinstance(event, Mapping):
            raise ValueError("captured alarm record is malformed")
        value = dict(event)
        items.append({
            "kind": "alarm", "source": str(alarms.get("tool", "active_alarms")),
            "value": value, "fingerprint": _digest(value),
            "time": normalize_timestamp(value.get("Timestamp")),
            "sequence_status": "unknown", "ref": {"pointer": f"/alarms/payload/result/records/{index}"},
        })
    line_count = 0
    for entry_index, entry in enumerate(entries):
        if not isinstance(entry, Mapping) or not isinstance(entry.get("lines"), list):
            raise ValueError("captured log entry is malformed")
        path = str(entry.get("path", ""))
        numbers = entry.get("line_numbers")
        for line_index, raw in enumerate(entry["lines"]):
            line_count += 1
            if line_count + len(alarm_values) > MAX_EVENTS:
                raise ValueError("captured evidence exceeds the batch record budget")
            text = str(raw)
            number = (numbers[line_index] if isinstance(numbers, list) and line_index < len(numbers)
                      and type(numbers[line_index]) is int else None)
            items.append({
                "kind": "log", "source": str(logs.get("tool", "collect_logs")) + ":" + path,
                "value": text, "fingerprint": _digest(text),
                "time": normalize_timestamp(text, offset),
                "sequence_status": "known" if number is not None else "missing",
                "ref": {"pointer": f"/logs/payload/result/entries/{entry_index}/lines/{line_index}",
                        "path": path, "line_number": number},
            })
    groups = _collapse(items)
    uncertainties: set[str] = set()
    captured_targets = (alarms.get("ip"), logs.get("ip"))
    if any(not isinstance(value, str) or not value.strip() for value in captured_targets):
        uncertainties.add("target_source_unknown")
    elif not target or any(value != target for value in captured_targets):
        uncertainties.add("target_source_conflict")
    if offset_conflict:
        uncertainties.add("timezone_offset_conflict")
    elif offset is not None and not offset_valid:
        uncertainties.add("timezone_offset_invalid")
    if not target:
        uncertainties.add("target_unknown")
    if not source_version:
        uncertainties.add("source_version_unknown")
    if type(target_epoch) is not int or target_epoch < 0:
        uncertainties.add("target_epoch_unknown")
    if not _complete(alarms, collection="alarms") or not _complete(logs, collection="logs"):
        uncertainties.add("partial_collection")
    for group in groups:
        if group["time"]["status"] != "known":
            uncertainties.add("time_" + str(group["time"]["status"]))
        if group["kind"] == "log" and group["sequence_status"] == "missing":
            uncertainties.add("missing_sequence")
    return {
        "schema": BATCH_SCHEMA,
        "target": target, "source_version": source_version, "target_epoch": target_epoch,
        "utc_offset_minutes": offset if offset_valid else None,
        "collection_complete": not bool(uncertainties & {
            "partial_collection", "target_source_unknown", "target_source_conflict",
        }),
        "counts": {"raw": len(items), "unique": len(groups),
                   "duplicates_collapsed": len(items) - len(groups)},
        "uncertainties": sorted(uncertainties), "groups": groups,
    }


def compare_snapshots(before: Mapping[str, object], after: Mapping[str, object]) -> dict[str, object]:
    """Compare exact captured values only inside the same target/version/epoch."""
    reasons: list[str] = []
    if before.get("schema") != BATCH_SCHEMA or after.get("schema") != BATCH_SCHEMA:
        reasons.append("unsupported_batch_schema")
    if not before.get("target") or before.get("target") != after.get("target"):
        reasons.append("target_mismatch_or_unknown")
    for field, unknown, conflict in (
        ("source_version", "source_version_unknown", "source_version_conflict"),
        ("target_epoch", "target_epoch_unknown", "stale_epoch"),
    ):
        left, right = before.get(field), after.get(field)
        valid = (type(left) is int and type(right) is int and left >= 0 and right >= 0
                 if field == "target_epoch" else isinstance(left, str) and bool(left)
                 and isinstance(right, str) and bool(right))
        if not valid:
            reasons.append(unknown)
        elif left != right:
            reasons.append(conflict)
    if before.get("collection_complete") is not True or after.get("collection_complete") is not True:
        reasons.append("partial_collection")
    for reason in ("target_source_unknown", "target_source_conflict"):
        if reason in before.get("uncertainties", []) or reason in after.get("uncertainties", []):
            reasons.append(reason)
    result: dict[str, object] = {"comparable": not reasons, "status": "comparable" if not reasons else "incomparable",
                                 "reasons": reasons, "added": [], "removed": [], "changed": None}
    if reasons:
        return result
    def index(batch: Mapping[str, object]) -> tuple[Counter[tuple[str, str, str]], dict[tuple[str, str, str], object], dict[tuple[str, str, str], str]]:
        counts: Counter[tuple[str, str, str]] = Counter()
        refs: dict[tuple[str, str, str], object] = {}
        fingerprints: dict[tuple[str, str, str], str] = {}
        for group in batch["groups"]:
            key = (str(group["kind"]), str(group["source"]), _canonical(group["value"]))
            counts[key] += int(group["count"])
            refs[key] = group["refs"]
            fingerprints[key] = str(group["fingerprint"])
        return counts, refs, fingerprints
    old, old_refs, old_fingerprints = index(before)
    new, new_refs, new_fingerprints = index(after)
    for key in sorted(set(old) | set(new)):
        if new[key] > old[key]:
            result["added"].append({"kind": key[0], "source": key[1], "fingerprint": new_fingerprints[key],
                                    "count": new[key] - old[key], "refs": new_refs[key]})
        elif old[key] > new[key]:
            result["removed"].append({"kind": key[0], "source": key[1], "fingerprint": old_fingerprints[key],
                                      "count": old[key] - new[key], "refs": old_refs[key]})
    result["changed"] = bool(result["added"] or result["removed"])
    return result


def collapse_compact_lines(lines: list[dict[str, object]]) -> list[dict[str, object]]:
    """Group exact displayed lines while retaining every original correlation ID."""
    groups: dict[tuple[str, str, str, str], dict[str, object]] = {}
    for line in lines:
        key = (str(line.get("target", "")), str(line.get("source", "")),
               str(line.get("path", "")), str(line.get("_raw_text", line.get("text", ""))))
        group = groups.get(key)
        if group is None:
            group = dict(line)
            group.pop("_raw_text", None)
            group["ids"] = []
            group["pointers"] = []
            groups[key] = group
        group["ids"].append(line.get("id"))
        group["pointers"].append({field: line.get(field) for field in
                                  ("entry_index", "line_index", "line_number")})
        group["text_truncated"] = bool(group.get("text_truncated") or line.get("text_truncated"))
    for group in groups.values():
        group["count"] = len(group["ids"])
    return list(groups.values())
