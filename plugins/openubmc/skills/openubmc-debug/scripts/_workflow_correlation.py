#!/usr/bin/env python3
"""Bounded source search and conservative alarm evidence correlation."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import re

from _workflow_freshness import alarm_identity, alarm_records, payload_result
from _workflow_source import (
    search_source_terms,
    source_dimensions as classify_source_dimensions,
    source_search_tool_available,
)


_SAMPLE_LOG_RE = re.compile(
    r"\b(?:sample|reading|value|current|measured)\s*[:=]\s*[-+]?\d",
    re.IGNORECASE,
)
_THRESHOLD_LOG_RE = re.compile(
    r"\b(?:threshold|limit|lower|upper|min|max)\s*[:=]\s*[-+]?\d",
    re.IGNORECASE,
)


def log_line_records(tool_result: dict[str, object]) -> list[dict[str, object]]:
    """Return stable, self-describing references for bounded log evidence."""

    entries = payload_result(tool_result).get("entries")
    if not isinstance(entries, list):
        return []
    records: list[dict[str, object]] = []
    for entry_index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("lines"), list):
            continue
        path = str(entry.get("path", ""))
        physical_numbers = entry.get("line_numbers")
        for line_index, line in enumerate(entry["lines"]):
            line_number = (
                physical_numbers[line_index]
                if isinstance(physical_numbers, list)
                and line_index < len(physical_numbers)
                and isinstance(physical_numbers[line_index], int)
                else None
            )
            records.append(
                {
                    "id": len(records),
                    "path": path,
                    "entry_index": entry_index,
                    "line_index": line_index,
                    "line_number": line_number,
                    "text": str(line),
                    "text_truncated": False,
                }
            )
    return records


def log_lines(tool_result: dict[str, object]) -> list[str]:
    return [str(record["text"]) for record in log_line_records(tool_result)]


def stable_alarm_terms(record: dict[str, object]) -> list[str]:
    terms: list[str] = []
    for field in ("EventName", "EventCode"):
        value = str(record.get(field, "")).strip()
        if value and value not in terms:
            terms.append(value)
    return terms


def instance_alarm_terms(record: dict[str, object]) -> list[str]:
    terms: list[str] = []
    for field in ("ComponentLocation", "ComponentName"):
        value = str(record.get(field, "")).strip()
        if len(value) >= 3 and value not in terms:
            terms.append(value)
    return terms


def _normalized_instance_term(term: str) -> str:
    return re.sub(r"\s+", " ", term.strip()).casefold()


def _literal_token_matches(line: str, term: str) -> bool:
    return bool(
        re.search(
            rf"(?<!\w){re.escape(term)}(?!\w)",
            line,
            re.IGNORECASE,
        )
    )


def line_matches_alarm_instance(
    line: str,
    record: dict[str, object],
    unique_component_terms: set[str] | None = None,
) -> bool:
    """Match only unambiguous component text or explicitly labelled instances."""

    for term in instance_alarm_terms(record):
        normalized = _normalized_instance_term(term)
        if unique_component_terms is not None and normalized not in unique_component_terms:
            continue
        if _literal_token_matches(line, term):
            return True
    instance = str(record.get("ComponentInstance", "")).strip()
    if not instance or not re.fullmatch(r"[A-Za-z0-9_.-]+", instance):
        return False
    labelled_instance = re.compile(
        rf"\b(?:instance|slot|card|psu|fan|component|device|sensor|port)"
        rf"\s*[:#=_-]?\s*{re.escape(instance)}\b",
        re.IGNORECASE,
    )
    return bool(labelled_instance.search(line))


def alarm_epoch(record: dict[str, object]) -> int | None:
    raw = str(record.get("Timestamp", "")).strip()
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def log_epoch(line: str, utc_offset_minutes: int | None = None) -> int | None:
    if (
        not isinstance(utc_offset_minutes, int)
        or isinstance(utc_offset_minutes, bool)
        or not -14 * 60 <= utc_offset_minutes <= 14 * 60
    ):
        return None
    try:
        parsed = datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None
    log_timezone = timezone(timedelta(minutes=utc_offset_minutes))
    return int(parsed.replace(tzinfo=log_timezone).timestamp())


def _alarm_log_utc_offset_minutes(
    alarm_logs_result: dict[str, object],
) -> int | None:
    raw = payload_result(alarm_logs_result).get("utc_offset_minutes")
    if isinstance(raw, int) and not isinstance(raw, bool) and -14 * 60 <= raw <= 14 * 60:
        return raw
    return None


def _line_matches_state(line: str, state: str) -> bool:
    normalized = state.strip().casefold()
    if normalized.startswith("deassert"):
        return bool(
            re.search(
                r"\b(?:deassert(?:ed|ion)?|clear(?:ed)?|recover(?:ed)?)\b",
                line,
                re.IGNORECASE,
            )
        )
    if normalized.startswith("assert"):
        return bool(re.search(r"\bassert(?:ed|ion)?\b", line, re.IGNORECASE))
    return False


def _since_boot_status(alarm_logs_result: dict[str, object]) -> dict[str, object]:
    payload = alarm_logs_result.get("payload")
    payload_dict = payload if isinstance(payload, dict) else {}
    request = payload_dict.get("request")
    request_dict = request if isinstance(request, dict) else {}
    result = payload_dict.get("result")
    result_dict = result if isinstance(result, dict) else {}
    warnings = payload_dict.get("warnings")
    warning_list = [str(item) for item in warnings] if isinstance(warnings, list) else []
    requested = bool(request_dict.get("since_boot_requested"))
    boot_time = result_dict.get("boot_time")
    tool_ok = bool(alarm_logs_result.get("ok"))
    applied = bool(requested and boot_time and tool_ok)
    reasons: list[str] = []
    if not tool_ok:
        reasons.append(str(alarm_logs_result.get("code", "alarm_log_search_failed")))
    if not requested:
        reasons.append("since_boot_not_confirmed")
    elif not boot_time:
        reasons.append("boot_time_unavailable")
    reasons.extend(
        warning for warning in warning_list if "since-boot" in warning or "boot time" in warning
    )
    return {
        "requested": requested,
        "applied": applied,
        "degraded": not applied,
        "boot_time": boot_time,
        "reasons": list(dict.fromkeys(reasons)),
    }


def _evidence_dimension(
    *,
    present: bool,
    source_refs: list[int] | None = None,
    log_refs: list[int] | None = None,
) -> dict[str, object]:
    return {
        "present": present,
        "source_refs": source_refs or [],
        "log_refs": log_refs or [],
    }


def _implementation_alignment(
    matches: list[dict[str, object]],
) -> tuple[list[str], list[int]]:
    """Return source files that contain one coherent implementation candidate.

    Exact-string search can identify candidate implementation files, but it cannot
    prove ownership or a caller/callee relationship.  Keep the alignment local to
    one file so dimensions from unrelated modules, tests, or examples cannot be
    stitched together before the caller performs semantic source analysis.
    """

    path_dimensions: dict[str, set[str]] = {}
    path_refs: dict[str, list[int]] = {}
    for match in matches:
        path = str(match.get("path", "")).strip()
        if not path:
            continue
        dimensions = classify_source_dimensions(
            str(match.get("text", "")), path
        )
        path_dimensions.setdefault(path, set()).update(dimensions)
        try:
            ref = int(match["id"])
        except (KeyError, TypeError, ValueError):
            continue
        path_refs.setdefault(path, []).append(ref)

    available_dimensions = {
        dimension
        for dimensions in path_dimensions.values()
        for dimension in dimensions
    }
    required = {"emit", "trigger"}
    # If the bounded source hits themselves expose measurement dimensions,
    # keep those dimensions in the same candidate file. Runtime-only sample
    # and threshold evidence is aligned separately on one log reference.
    required.update(
        dimension
        for dimension in ("sample", "threshold")
        if dimension in available_dimensions
    )
    paths = sorted(
        path for path, dimensions in path_dimensions.items() if required <= dimensions
    )
    refs = sorted(
        {
            ref
            for path in paths
            for ref in path_refs.get(path, [])
        }
    )
    return paths, refs


def build_correlation(
    active_result: dict[str, object],
    alarm_logs_result: dict[str, object],
    *,
    source_root: str,
    max_matches: int,
    alarm_limit: int,
    timeout: int | float,
    workflow_keyword: str,
    enabled: bool,
    workflow_logs_result: dict[str, object] | None = None,
    time_window: int = 300,
) -> dict[str, object]:
    records = alarm_records(active_result)[:alarm_limit]
    alarm_line_records = log_line_records(alarm_logs_result)
    workflow_line_records = log_line_records(
        workflow_logs_result or alarm_logs_result
    )
    alarm_lines = [str(record["text"]) for record in alarm_line_records]
    workflow_lines = [str(record["text"]) for record in workflow_line_records]
    alarm_terms: list[str] = []
    for record in records:
        for term in stable_alarm_terms(record):
            if term not in alarm_terms:
                alarm_terms.append(term)
    source_terms = list(alarm_terms)
    if workflow_keyword and workflow_keyword not in source_terms:
        source_terms.append(workflow_keyword)
    source_search = (
        search_source_terms(source_root, source_terms, max_matches, timeout)
        if enabled
        else {
            "ok": False,
            "code": "skipped",
            "method": "none",
            "rg_available": source_search_tool_available(),
            "matches": [],
            "hits": [],
            "per_term": {},
            "truncated": False,
            "timed_out": False,
            "error": "Source correlation disabled",
        }
    )
    source_matches = source_search.get("matches")
    source_pool = source_matches if isinstance(source_matches, list) else []
    since_boot = _since_boot_status(alarm_logs_result)
    utc_offset_minutes = _alarm_log_utc_offset_minutes(alarm_logs_result)
    alarm_line_epochs = [
        log_epoch(line, utc_offset_minutes) for line in alarm_lines
    ]

    component_counts: Counter[str] = Counter()
    for record in records:
        component_counts.update(
            _normalized_instance_term(term) for term in instance_alarm_terms(record)
        )
    unique_component_terms = {
        term for term, count in component_counts.items() if count == 1
    }

    correlations: list[dict[str, object]] = []
    for record in records:
        terms = stable_alarm_terms(record)
        term_set = set(terms)
        record_source_matches = [
            match
            for match in source_pool
            if isinstance(match, dict)
            and term_set.intersection(str(term) for term in match.get("terms", []))
        ]
        source_refs = [int(match["id"]) for match in record_source_matches]
        source_dimensions = {
            dimension: [
                int(match["id"])
                for match in record_source_matches
                if dimension
                in classify_source_dimensions(
                    str(match.get("text", "")), str(match.get("path", ""))
                )
            ]
            for dimension in ("definition", "emit", "trigger", "sample", "threshold")
        }
        # A stable literal hit is definition/reference evidence, never emit/trigger proof.
        if source_refs and not source_dimensions["definition"]:
            source_dimensions["definition"] = list(source_refs)

        stable_log_refs = [
            index
            for index, line in enumerate(alarm_lines)
            if any(_literal_token_matches(line, term) for term in terms)
        ]
        instance_refs = [
            index
            for index in stable_log_refs
            if line_matches_alarm_instance(
                alarm_lines[index], record, unique_component_terms
            )
        ]
        record_epoch = alarm_epoch(record)
        time_refs = [
            index
            for index in stable_log_refs
            if record_epoch is not None
            and alarm_line_epochs[index] is not None
            and abs(int(alarm_line_epochs[index]) - record_epoch) <= time_window
        ]
        state_refs = [
            index
            for index in stable_log_refs
            if _line_matches_state(alarm_lines[index], str(record.get("State", "")))
        ]
        sample_refs = [
            index for index in stable_log_refs if _SAMPLE_LOG_RE.search(alarm_lines[index])
        ]
        threshold_refs = [
            index
            for index in stable_log_refs
            if _THRESHOLD_LOG_RE.search(alarm_lines[index])
        ]
        identity_aligned_refs = sorted(
            set(instance_refs).intersection(time_refs).intersection(state_refs)
        )
        measurement_expected = bool(
            source_dimensions["sample"]
            or source_dimensions["threshold"]
            or sample_refs
            or threshold_refs
        )
        implementation_paths, implementation_refs = _implementation_alignment(
            record_source_matches
        )
        measurement_aligned_refs = sorted(
            set(sample_refs).intersection(threshold_refs)
        )
        runtime_aligned_refs = (
            sorted(set(identity_aligned_refs).intersection(measurement_aligned_refs))
            if measurement_expected
            else list(identity_aligned_refs)
        )
        evidence = {
            "definition": _evidence_dimension(
                present=bool(source_dimensions["definition"]),
                source_refs=source_dimensions["definition"],
            ),
            "emit": _evidence_dimension(
                present=bool(source_dimensions["emit"]),
                source_refs=source_dimensions["emit"],
            ),
            "trigger": _evidence_dimension(
                present=bool(source_dimensions["trigger"]),
                source_refs=source_dimensions["trigger"],
            ),
            "state": _evidence_dimension(
                present=bool(state_refs), log_refs=state_refs
            ),
            "instance": _evidence_dimension(
                present=bool(instance_refs), log_refs=instance_refs
            ),
            "time": _evidence_dimension(present=bool(time_refs), log_refs=time_refs),
            "sample": _evidence_dimension(
                present=bool(sample_refs),
                source_refs=source_dimensions["sample"],
                log_refs=sample_refs,
            ),
            "threshold": _evidence_dimension(
                present=bool(threshold_refs),
                source_refs=source_dimensions["threshold"],
                log_refs=threshold_refs,
            ),
            "identity_alignment": _evidence_dimension(
                present=bool(identity_aligned_refs), log_refs=identity_aligned_refs
            ),
            "measurement_alignment": _evidence_dimension(
                present=bool(measurement_aligned_refs),
                log_refs=measurement_aligned_refs,
            ),
            "runtime_alignment": _evidence_dimension(
                present=bool(runtime_aligned_refs), log_refs=runtime_aligned_refs
            ),
            "implementation_alignment": _evidence_dimension(
                present=bool(implementation_paths), source_refs=implementation_refs
            ),
        }
        identity_dimensions = ("definition", "state", "instance", "time")
        root_dimensions = [
            *identity_dimensions,
            "emit",
            "trigger",
            "implementation_alignment",
        ]
        if measurement_expected:
            root_dimensions.extend(["sample", "threshold"])
        missing_dimensions = [
            dimension
            for dimension in root_dimensions
            if not bool(evidence[dimension]["present"])
        ]
        blocked_by = list(missing_dimensions)
        identity_dimensions_present = all(
            bool(evidence[dimension]["present"])
            for dimension in ("state", "instance", "time")
        )
        if identity_dimensions_present and not identity_aligned_refs:
            blocked_by.append("identity_alignment")
        if measurement_expected and not runtime_aligned_refs:
            blocked_by.append("measurement_alignment")
        if record_epoch is not None and utc_offset_minutes is None:
            blocked_by.append("utc_offset")
        if bool(since_boot["degraded"]):
            blocked_by.append("since_boot")
        identity_complete = bool(
            evidence["definition"]["present"]
            and identity_aligned_refs
            and not bool(since_boot["degraded"])
        )
        implementation_candidate = bool(
            identity_complete
            and evidence["emit"]["present"]
            and evidence["trigger"]["present"]
            and evidence["implementation_alignment"]["present"]
            and (not measurement_expected or runtime_aligned_refs)
            and not blocked_by
        )
        # Literal search and a matching runtime line still do not prove that the
        # candidate file owns the running behavior or is reached by the relevant
        # caller.  That semantic relationship must come from CodeGraph/direct
        # source inspection and is intentionally outside this bounded helper.
        if implementation_candidate:
            blocked_by.append("call_path_or_owner")
        root_complete = False
        if implementation_candidate:
            level = "implementation_candidate"
        elif identity_complete:
            level = "identity_timeline"
        elif any(bool(item["present"]) for item in evidence.values()):
            level = "partial"
        else:
            level = "none"
        if runtime_aligned_refs and measurement_expected:
            evidence_scope = "instance_time_state_measurement"
        elif identity_aligned_refs:
            evidence_scope = "instance_time_state"
        elif instance_refs and time_refs:
            evidence_scope = "instance_time"
        elif instance_refs:
            evidence_scope = "instance"
        elif time_refs:
            evidence_scope = "alarm_type_time"
        elif stable_log_refs:
            evidence_scope = "alarm_type"
        else:
            evidence_scope = "none"

        correlations.append(
            {
                "identity": list(alarm_identity(record)),
                "stable_terms": terms,
                "instance_terms": instance_alarm_terms(record),
                "eligible_instance_terms": [
                    term
                    for term in instance_alarm_terms(record)
                    if _normalized_instance_term(term) in unique_component_terms
                ],
                "source_refs": source_refs,
                "log_refs": stable_log_refs,
                "evidence": evidence,
                "measurement_expected": measurement_expected,
                "implementation_candidate_paths": implementation_paths,
                "source_evidence": bool(source_refs),
                "log_evidence": bool(stable_log_refs),
                "state_evidence": bool(state_refs),
                "instance_evidence": bool(instance_refs),
                "timestamp_evidence": bool(time_refs),
                "log_evidence_scope": evidence_scope,
                "utc_offset_minutes": utc_offset_minutes,
                "completeness": {
                    "level": level,
                    "identity_timeline_complete": identity_complete,
                    "root_cause_complete": root_complete,
                    "blocked_by": list(dict.fromkeys(blocked_by)),
                },
                "correlation_complete": root_complete,
                "missing_dimensions": list(dict.fromkeys(blocked_by)),
                # Full JSON compatibility fields. Compact JSON drops these copies.
                "source_hits": [
                    source_search.get("hits", [])[ref]
                    for ref in source_refs
                    if isinstance(source_search.get("hits"), list)
                    and ref < len(source_search.get("hits", []))
                ],
                "log_hits": [alarm_lines[index] for index in stable_log_refs],
                "instance_log_hits": [alarm_lines[index] for index in instance_refs],
                "time_aligned_log_hits": [alarm_lines[index] for index in time_refs],
                "complete_log_hits": [
                    alarm_lines[index] for index in runtime_aligned_refs
                ],
            }
        )

    keyword_refs = (
        [
            index
            for index, line in enumerate(workflow_lines)
            if workflow_keyword.casefold() in line.casefold()
        ]
        if workflow_keyword
        else []
    )
    return {
        "source_search": source_search,
        "since_boot": since_boot,
        "alarm_log_search": {
            "ok": bool(alarm_logs_result.get("ok")),
            "code": str(alarm_logs_result.get("code", "unknown")),
            "terms": alarm_terms,
        },
        "evidence_pool": {
            "source_matches": source_pool,
            "alarm_log_lines": alarm_line_records,
            "workflow_log_lines": workflow_line_records,
            "alarm_log_utc_offset_minutes": utc_offset_minutes,
        },
        "records_considered": len(records),
        "records": correlations,
        "workflow_keyword": workflow_keyword,
        "workflow_keyword_refs": keyword_refs,
        "workflow_keyword_hits": [workflow_lines[index] for index in keyword_refs],
    }
