"""Stable evidence grouping and bounded event-anchor correlation."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import datetime as dt
import hashlib
import re


MAX_FINDING_EVIDENCE = 8
MAX_FINDINGS = 50
MAX_EVENT_CORRELATIONS = 20
MAX_EVENT_CANDIDATES_PER_ANCHOR = 8
FAILURE_TERMS = ("critical", "fatal", "panic", "segfault", "error", "failed", "failure", "失败", "异常")
GENERIC_COMPONENT_TOKENS = {
    "app",
    "business",
    "component",
    "components",
    "framework",
    "log",
    "logger",
    "operation",
    "per",
    "runtime",
    "service",
    "system",
}
LEADING_TIMESTAMP_RE = re.compile(
    r"^\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s*"
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HEX_RE = re.compile(r"\b0x[0-9a-f]+\b", re.IGNORECASE)
NUMBER_RE = re.compile(r"\b\d+\b")
SEMANTIC_CODE_RE = re.compile(
    r"(?i)\b(?:status(?:_code)?|error(?:_code)?|errno|err(?:or)?|code|http)\s*[=:]?\s*(-?\d{3,5})\b"
)
PRINCIPAL_AT_HOST_RE = re.compile(r"\b[^\s,]+@(?:<ip>|[^\s,]+)")
AUTH_PRINCIPAL_RE = re.compile(r"\buser\s+[^\s,]+\s+authentication\s+failed\b", re.IGNORECASE)
LOG_COMPONENT_RE = re.compile(
    r"\s(?P<component>[A-Za-z][\w.-]{1,63})\s+"
    r"(?:TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|CRITICAL|FATAL):"
)


def _timestamp_value(value: object) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.timestamp()


def _canonical_message(line: str) -> str:
    value = LEADING_TIMESTAMP_RE.sub("", line.casefold())
    value = IPV4_RE.sub("<ip>", value)
    value = PRINCIPAL_AT_HOST_RE.sub("<principal>@<host>", value)
    value = AUTH_PRINCIPAL_RE.sub("user <principal> authentication failed", value)
    value = HEX_RE.sub("<hex>", value)
    semantic_codes: list[str] = []

    def protect_code(match: re.Match[str]) -> str:
        semantic_codes.append(match.group(1))
        return f"__semantic_code_{len(semantic_codes) - 1}__"

    value = SEMANTIC_CODE_RE.sub(protect_code, value)
    value = NUMBER_RE.sub("<n>", value)
    for index, code in enumerate(semantic_codes):
        value = value.replace(f"__semantic_code_{index}__", f"<code:{code}>")
    return " ".join(value.split())


def _reported_severity(line: str) -> str:
    normalized = line.casefold()
    if any(term in normalized for term in ("critical", "fatal", "panic", "segfault")):
        return "critical"
    if any(term in normalized for term in ("error", "failed", "failure", "失败", "异常")):
        return "error"
    if "warn" in normalized:
        return "warning"
    return "unclassified"


def _finding_strength(items: list[dict[str, object]]) -> str:
    classes = {str(item.get("match_class", "")) for item in items}
    if "direct_failure" in classes:
        return "direct_signal"
    if "problem_context" in classes:
        return "problem_context"
    return "generic_signal"


def build_evidence_findings(evidence: list[dict[str, object]]) -> list[dict[str, object]]:
    groups: dict[str, list[dict[str, object]]] = {}
    for item in evidence:
        line = str(item.get("line", ""))
        log = str(item.get("log", ""))
        if not line or not log:
            continue
        canonical = _canonical_message(line)
        component = str(item.get("component", "")).casefold()
        path = str(item.get("path", ""))
        path_family = path.rsplit("/", 1)[0]
        digest = hashlib.sha256(
            f"{log}\0{component}\0{path_family}\0{canonical}".encode("utf-8")
        ).hexdigest()[:16]
        groups.setdefault(digest, []).append(item)

    findings: list[dict[str, object]] = []
    for digest, items in groups.items():
        items.sort(
            key=lambda item: (
                _timestamp_value(item.get("timestamp")) or float("inf"),
                str(item.get("path", "")),
                int(item.get("line_number", 0)),
            )
        )
        timestamps = [str(item["timestamp"]) for item in items if isinstance(item.get("timestamp"), str)]
        representative = items[-1]
        sampled = any(bool(item.get("sampled_from_larger_set")) for item in items)
        sampled_count = len(items)
        findings.append(
            {
                "finding_id": f"log-signal-{digest}",
                "revision": 1,
                "kind": "log_signal",
                "reported_severity": _reported_severity(str(representative.get("line", ""))),
                "evidence_strength": _finding_strength(items),
                "sampled_occurrence_count": sampled_count,
                "count_is_lower_bound": sampled,
                "count_complete": not sampled,
                "logs": sorted({str(item.get("log", "")) for item in items if item.get("log")}),
                "components": sorted(
                    {str(item.get("component", "")) for item in items if item.get("component")}
                ),
                "sampled_first_timestamp": timestamps[0] if timestamps else "",
                "sampled_last_timestamp": timestamps[-1] if timestamps else "",
                "representative": {
                    "path": representative.get("path", ""),
                    "line_number": representative.get("line_number", 0),
                    "timestamp": representative.get("timestamp", ""),
                    "line": representative.get("line", ""),
                    **(
                        {"source_revision": representative["source_revision"]}
                        if representative.get("source_revision")
                        else {}
                    ),
                },
                "evidence": [
                    {
                        "path": item.get("path", ""),
                        "line_number": item.get("line_number", 0),
                        "timestamp": item.get("timestamp", ""),
                        **(
                            {"source_revision": item["source_revision"]}
                            if item.get("source_revision")
                            else {}
                        ),
                    }
                    for item in items[:MAX_FINDING_EVIDENCE]
                ],
            }
        )
    findings.sort(
        key=lambda finding: (
            -int(finding["sampled_occurrence_count"]),
            str(finding.get("finding_id", "")),
        )
    )
    return findings[:MAX_FINDINGS]


def _component_tokens(item: dict[str, object]) -> set[str]:
    tokens: set[str] = set()
    component = str(item.get("component", ""))
    for token in re.findall(r"[A-Za-z][\w.-]{1,63}", component.casefold()):
        if token not in GENERIC_COMPONENT_TOKENS:
            tokens.add(token)

    line = LEADING_TIMESTAMP_RE.sub("", str(item.get("line", "")))
    if str(item.get("log", "")) == "operation.log":
        fields = [field.strip().casefold() for field in line.split(",")]
        if len(fields) >= 3 and re.fullmatch(r"[a-z][\w.-]{1,63}", fields[2]):
            tokens.add(fields[2])
    match = LOG_COMPONENT_RE.search(f" {line}")
    if match:
        tokens.add(match.group("component").casefold())
    return tokens - GENERIC_COMPONENT_TOKENS


def _event_pointer(item: dict[str, object]) -> dict[str, object]:
    pointer = {
        "log": item.get("log", ""),
        "path": item.get("path", ""),
        "line_number": item.get("line_number", 0),
        "timestamp": item.get("timestamp", ""),
    }
    # Keep the catalog revision attached to every derived pointer.  A source
    # revision is optional (the bundled heuristic catalog has none), but when
    # present it must survive correlation so consumers can reproduce which
    # definition was used.
    if item.get("source_revision"):
        pointer["source_revision"] = item["source_revision"]
    return pointer


def is_operation_failure_anchor(item: dict[str, object]) -> bool:
    if str(item.get("match_class", "")) == "direct_failure":
        return True
    normalized = str(item.get("line", "")).casefold()
    for term in FAILURE_TERMS:
        if term.isascii():
            pattern = rf"(?<![A-Za-z0-9_]){re.escape(term.casefold())}(?![A-Za-z0-9_])"
            if re.search(pattern, normalized):
                return True
        elif term in normalized:
            return True
    return False


def operation_event_anchor_id(anchor: dict[str, object]) -> str:
    digest = hashlib.sha256(
        f"{anchor.get('path', '')}:{anchor.get('line_number', 0)}:{anchor.get('timestamp', '')}".encode("utf-8")
    ).hexdigest()[:16]
    return f"operation-event-{digest}"


def event_candidate_details(
    anchor: dict[str, object],
    candidate: dict[str, object],
    *,
    window_seconds: int,
) -> dict[str, object] | None:
    """Return non-causal candidate context when timestamps are comparable."""
    if window_seconds <= 0 or candidate.get("log") == "operation.log":
        return None
    anchor_time = _timestamp_value(anchor.get("timestamp"))
    candidate_time = _timestamp_value(candidate.get("timestamp"))
    if anchor_time is None or candidate_time is None:
        return None
    anchor_timestamp = str(anchor.get("timestamp", ""))
    candidate_timestamp = str(candidate.get("timestamp", ""))
    anchor_is_aware = bool(re.search(r"(?:Z|[+-]\d{2}:?\d{2})$", anchor_timestamp))
    candidate_is_aware = bool(re.search(r"(?:Z|[+-]\d{2}:?\d{2})$", candidate_timestamp))
    if candidate_is_aware != anchor_is_aware:
        return None
    delta_seconds = int(round(candidate_time - anchor_time))
    if abs(delta_seconds) > window_seconds:
        return None
    return {
        **_event_pointer(candidate),
        "delta_seconds": delta_seconds,
        "shared_components": sorted(_component_tokens(anchor) & _component_tokens(candidate)),
    }


def event_candidate_sort_key(item: dict[str, object]) -> tuple[bool, int, str, int]:
    return (
        not bool(item.get("shared_components")),
        abs(int(item.get("delta_seconds", 0))),
        str(item.get("path", "")),
        int(item.get("line_number", 0)),
    )


def build_event_correlations(
    timeline: list[dict[str, object]],
    *,
    window_seconds: int,
    scan_complete: bool = True,
    candidate_details_by_anchor: dict[str, list[dict[str, object]]] | None = None,
    anchors: list[dict[str, object]] | None = None,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    if window_seconds <= 0:
        return [], []
    selected_anchors = list(anchors) if anchors is not None else [
        item
        for item in timeline
        if item.get("log") == "operation.log" and is_operation_failure_anchor(item)
    ]
    correlations: list[dict[str, object]] = []
    unmatched: list[dict[str, object]] = []
    for anchor in selected_anchors[:MAX_EVENT_CORRELATIONS]:
        anchor_id = operation_event_anchor_id(anchor)
        if candidate_details_by_anchor is None:
            candidates = [
                details
                for candidate in timeline
                if candidate is not anchor
                for details in [
                    event_candidate_details(anchor, candidate, window_seconds=window_seconds)
                ]
                if details is not None
            ]
        else:
            candidates = [
                {key: value for key, value in details.items() if not str(key).startswith("_")}
                for details in candidate_details_by_anchor.get(anchor_id, [])
                if isinstance(details, dict)
            ]
        candidates.sort(key=event_candidate_sort_key)
        if not candidates:
            unmatched.append(
                {
                    "anchor_id": anchor_id,
                    "anchor": _event_pointer(anchor),
                    "reason": (
                        "candidate_scan_incomplete"
                        if not scan_complete
                        else "no_other_selected_log_evidence_within_window"
                    ),
                    "candidate_scan_complete": scan_complete,
                }
            )
            continue
        has_shared_component = any(candidate["shared_components"] for candidate in candidates)
        correlations.append(
            {
                "anchor_id": anchor_id,
                "anchor": _event_pointer(anchor),
                "basis": [
                    "temporal_proximity",
                    *(["shared_component"] if has_shared_component else []),
                ],
                "candidates": candidates[:MAX_EVENT_CANDIDATES_PER_ANCHOR],
                "interpretation": "candidate_context_not_causality",
                "candidate_scan_complete": scan_complete,
            }
        )
    return correlations, unmatched
