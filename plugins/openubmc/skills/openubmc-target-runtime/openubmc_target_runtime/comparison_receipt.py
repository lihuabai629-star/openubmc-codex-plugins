"""Runtime-owned evidence derived from existing Debug comparison algorithms."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json

from .comparison_targets import comparison_target_identities
from .contracts import RUNTIME_API_VERSION
from .redaction import is_secret_key, redact_text

COMPARISON_RECEIPT_SCHEMA = f"{RUNTIME_API_VERSION}/comparison-receipt-v1"
_SCOPE_FIELDS = (
    "profile", "mdb_only", "mdb_queries", "mdb_expand_classes", "files", "logs",
    "tree_service", "active_alarms", "alarm_service", "include_rotated", "skip_telnet",
)


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _items(value: object) -> Sequence[object]:
    return (
        value if isinstance(value, Sequence)
        and not isinstance(value, (str, bytes, bytearray)) else ()
    )


def _text(value: object) -> str:
    return redact_text(value).strip() if isinstance(value, str) else ""


def _public(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): _public(item)
            for key, item in value.items() if not is_secret_key(key)
        }
    if isinstance(value, (list, tuple)):
        return [_public(item) for item in value]
    return redact_text(value) if isinstance(value, str) else copy.deepcopy(value)


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), default=str,
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _incomplete(value: object) -> bool:
    if isinstance(value, Mapping):
        if (
            ("ok" in value and value["ok"] is not True)
            or ("content_complete" in value and value["content_complete"] is not True)
            or _text(value.get("status")) in {
                "partial", "unavailable", "not_checked", "failed",
            }
        ):
            return True
        return any(
            (str(key).endswith("truncated") and item is not False) or _incomplete(item)
            for key, item in value.items()
        )
    return any(_incomplete(item) for item in _items(value))


def _time(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(_text(value))
        return parsed if parsed.utcoffset() is not None else None
    except ValueError:
        return None


@dataclass(frozen=True)
class ComparisonSource:
    target_id: str
    address: str
    role: str
    source_digest: str
    evidence_ids: tuple[str, ...]
    scope_digest: str
    freshness: str
    observed_at: str
    status: str

    def to_public_dict(self) -> dict[str, object]:
        return {
            "target_id": self.target_id, "address": self.address, "role": self.role,
            "source_digest": self.source_digest,
            "evidence_ids": list(self.evidence_ids),
            "scope_digest": self.scope_digest, "freshness": self.freshness,
            "observed_at": self.observed_at, "status": self.status,
        }


@dataclass(frozen=True)
class ComparisonReceipt:
    """A derived diagnostic fact; Run and Evidence lifecycle stay Runtime-owned."""

    receipt_id: str
    status: str
    conclusion: str
    mode: str
    sources: tuple[ComparisonSource, ...]
    scope: Mapping[str, object]
    freshness: Mapping[str, object]
    differences: tuple[Mapping[str, object], ...]
    incomparable_reasons: tuple[str, ...]

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": COMPARISON_RECEIPT_SCHEMA,
            "receipt_id": self.receipt_id,
            "status": self.status,
            "conclusion": self.conclusion,
            "mode": self.mode,
            "sources": [source.to_public_dict() for source in self.sources],
            "scope": copy.deepcopy(dict(self.scope)),
            "freshness": copy.deepcopy(dict(self.freshness)),
            "difference_count": len(self.differences),
            "differences": copy.deepcopy(list(self.differences)),
            "incomparable_reasons": list(self.incomparable_reasons),
        }


def _comparison_differences(
    comparison: Mapping[str, object], reasons: list[str],
) -> list[Mapping[str, object]]:
    differences: list[Mapping[str, object]] = []
    raw = comparison.get("differences")
    for name in ("differences", "candidate_comparisons", "value_groups"):
        if name in comparison and (
            not isinstance(comparison[name], list)
            or any(not isinstance(item, Mapping) for item in _items(comparison[name]))
        ):
            reasons.append(f"{name}_invalid")
    if isinstance(raw, list):
        differences.extend(dict(item) for item in raw if isinstance(item, Mapping))
    elif (
        raw is None and not comparison.get("candidate_comparisons")
        and not comparison.get("value_groups")
    ):
        reasons.append("differences_not_visible")
    for item in _items(comparison.get("candidate_comparisons")):
        if not isinstance(item, Mapping):
            reasons.append("candidate_comparison_invalid")
            continue
        for difference in _comparison_differences(item, reasons):
            differences.append({
                **dict(difference),
                "reference_target_id": _text(item.get("reference_target_id")),
                "candidate_target_id": _text(item.get("candidate_target_id")),
            })
    for item in _items(comparison.get("value_groups")):
        if isinstance(item, Mapping):
            differences.append({"kind": "value-groups", **dict(item)})
    card = _mapping(comparison.get("diff_card"))
    if "diff_card" in comparison and not card:
        reasons.append("diff_card_invalid")
    if card.get("scope_equal") is False:
        reasons.append("scope_mismatch")
    if card.get("freshness_equal") is False:
        reasons.append("freshness_mismatch")
    for path in _items(card.get("incomparable_paths")):
        reasons.append(f"incomparable_path:{_text(path)}")
    if any(_mapping(card.get("quality_flags")).values()):
        reasons.append("comparison_quality_partial")
    if card and (
        card.get("status") != "complete"
        or card.get("comparability") != "comparable"
        or _text(card.get("conclusion")) not in {"same", "different"}
    ):
        reasons.append("comparison_inconclusive")
    if card.get("conclusion") == "different" and not differences:
        reasons.append("differences_not_visible")
    if _text(comparison.get("status")) not in {"complete", "passed", "ok"}:
        reasons.append("comparison_incomplete")
    if _incomplete(comparison):
        reasons.append("comparison_content_incomplete")
    return differences


def build_comparison_receipt(
    value: Mapping[str, object],
    arguments: Mapping[str, object],
    evidence_ids: Sequence[str],
    *,
    source_results_complete: bool,
) -> ComparisonReceipt:
    """Bind an algorithm result to Runtime targets and persisted Evidence.

    The caller supplies evaluability of the requested diagnostic facts. An empty
    difference list cannot establish that missing or partial facts are equal.
    """

    expected = _items(arguments.get("targets"))
    if not all(isinstance(item, Mapping) for item in expected):
        raise ValueError("ComparisonReceipt requires the Runtime target scope")
    identities = comparison_target_identities(expected)
    returned = [_mapping(item) for item in _items(value.get("targets"))]
    reasons: list[str] = []
    if not source_results_complete:
        reasons.append("source_results_incomplete")
    bound_evidence = tuple(dict.fromkeys(
        _text(item) for item in _items(evidence_ids) if _text(item)
    ))
    if not bound_evidence:
        reasons.append("source_evidence_missing")
    expected_ids = {identity for _role, identity in identities}
    if any(_text(item.get("target_id")) not in expected_ids for item in returned):
        reasons.append("unexpected_target")
    sources: list[ComparisonSource] = []
    times: list[datetime] = []
    boundaries: list[str] = []
    for target, (role, identity) in zip(expected, identities, strict=True):
        matches = [
            item for item in returned if _text(item.get("target_id")) == identity
        ]
        selected = matches[0] if len(matches) == 1 else {}
        result = _mapping(selected.get("result"))
        body = _mapping(result.get("result"))
        address = _text(target.get("ip") or target.get("address"))
        status = "complete"
        if len(matches) > 1:
            status = "duplicate"
        elif not selected or not result:
            status = "missing"
        elif (
            not address or _text(selected.get("role")) != role
            or any(
                result.get(name) and _text(result[name]) != address
                for name in ("ip", "address")
            )
        ):
            status = "identity_mismatch"
        elif (
            _text(selected.get("status")) not in {"ok", "completed"}
            or result.get("ok") is not True or _incomplete(result)
        ):
            status = "partial"
        if status != "complete":
            reasons.append(f"{identity}:{status}")
        request = _mapping(result.get("request"))
        source_scope = _mapping(result.get("evidence_scope")) or {
            name: request[name] for name in _SCOPE_FIELDS if name in request
        }
        if "evidence_scope" in result and not _mapping(result["evidence_scope"]):
            reasons.append(f"{identity}:scope_invalid")
        if not source_scope:
            reasons.append(f"{identity}:scope_unknown")
        source_freshness = (
            _mapping(result.get("freshness")) or _mapping(body.get("freshness"))
        )
        freshness = _text(source_freshness.get("status")) or "unknown"
        if freshness != "fresh" or (
            "complete" in source_freshness and source_freshness["complete"] is not True
        ):
            reasons.append(f"{identity}:freshness_unverified")
        observed_at = _text(
            result.get("observed_at") or body.get("completed_at")
            or selected.get("completed_at")
        )
        observed_time = _time(observed_at)
        if observed_time is None:
            reasons.append(f"{identity}:observation_time_unknown")
        else:
            times.append(observed_time)
        boundary = result.get("freshness_boundary")
        boundaries.append(_digest(boundary) if boundary is not None else "")
        sources.append(ComparisonSource(
            target_id=identity, address=address, role=role,
            source_digest=_digest(result) if result else "",
            evidence_ids=bound_evidence,
            scope_digest=_digest(source_scope) if source_scope else "",
            freshness=freshness, observed_at=observed_at, status=status,
        ))
    if len({source.scope_digest for source in sources}) != 1:
        reasons.append("scope_mismatch")
    if any(boundaries) and len(set(boundaries)) != 1:
        reasons.append("freshness_mismatch")
    differences = _comparison_differences(_mapping(value.get("comparison")), reasons)
    reasons = list(dict.fromkeys(reasons))
    conclusion = "inconclusive" if reasons else "different" if differences else "same"
    partial = not source_results_complete or any(
        source.status != "complete" for source in sources
    )
    status = "complete" if not reasons else "partial" if partial else "incomparable"
    scope = _public({
        name: arguments[name] for name in _SCOPE_FIELDS if name in arguments
    })
    fresh = all(source.freshness == "fresh" for source in sources) and not any(
        "freshness" in reason or "observation_time" in reason for reason in reasons
    )
    freshness = {
        "status": "fresh" if fresh else "unverified",
        "window_start": min(times).isoformat() if times else "",
        "window_end": max(times).isoformat() if times else "",
        "boundary_digest": boundaries[0] if len(set(boundaries)) == 1 else "",
    }
    mode = (
        "reference-candidate" if any(role == "reference" for role, _ in identities)
        else "symmetric"
    )
    payload = {
        "schema": COMPARISON_RECEIPT_SCHEMA,
        "sources": [source.to_public_dict() for source in sources],
        "scope": scope, "freshness": freshness, "differences": differences,
        "incomparable_reasons": reasons, "mode": mode,
    }
    return ComparisonReceipt(
        receipt_id="comparison-" + _digest(payload).removeprefix("sha256:")[:24],
        status=status, conclusion=conclusion, mode=mode,
        sources=tuple(sources), scope=scope, freshness=freshness,
        differences=tuple(_public(differences)), incomparable_reasons=tuple(reasons),
    )
