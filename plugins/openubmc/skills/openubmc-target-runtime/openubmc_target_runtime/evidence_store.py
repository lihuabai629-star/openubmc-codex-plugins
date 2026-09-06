"""Bounded operator discovery for Runtime-owned Evidence metadata."""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
import json
import math
from typing import Protocol

from .contracts import RUNTIME_API_VERSION


EVIDENCE_QUERY_SCHEMA = f"{RUNTIME_API_VERSION}/evidence-query-v1"
EVIDENCE_QUERY_DEFAULT_ITEMS = 20
EVIDENCE_QUERY_MAX_ITEMS = 100
EVIDENCE_QUERY_MAX_SCAN_REFERENCES = 4096
EVIDENCE_QUERY_MAX_BYTES = 64 * 1024
_EVIDENCE_QUERY_ITEM_BUDGET = EVIDENCE_QUERY_MAX_BYTES - 4096
EVIDENCE_QUERY_MAX_CASE_ID = 128
EVIDENCE_QUERY_MAX_FILTER = 256


class EvidenceQueryRepository(Protocol):
    def evidence_query_candidates(
        self,
        query: "EvidenceQuery",
        *,
        limit: int,
    ) -> tuple[dict[str, object], ...]: ...


@dataclass(frozen=True)
class EvidenceQuery:
    case_id: str = ""
    target_id: str = ""
    producer: str = ""
    workflow_definition_id: str = ""
    observed_after: float | None = None
    observed_before: float | None = None
    limit: int = EVIDENCE_QUERY_DEFAULT_ITEMS
    deduplicate: bool = True

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "EvidenceQuery":
        limit = int(value.get("limit", EVIDENCE_QUERY_DEFAULT_ITEMS))
        if limit < 1 or limit > EVIDENCE_QUERY_MAX_ITEMS:
            raise ValueError(
                f"evidence query limit must be between 1 and {EVIDENCE_QUERY_MAX_ITEMS}"
            )
        observed_after = value.get("observed_after")
        observed_before = value.get("observed_before")
        after = float(observed_after) if observed_after is not None else None
        before = float(observed_before) if observed_before is not None else None
        if after is not None and not math.isfinite(after):
            raise ValueError("observed_after must be finite")
        if before is not None and not math.isfinite(before):
            raise ValueError("observed_before must be finite")
        if after is not None and after < 0:
            raise ValueError("observed_after must be non-negative")
        if before is not None and before < 0:
            raise ValueError("observed_before must be non-negative")
        if after is not None and before is not None and after > before:
            raise ValueError("observed_after must not be later than observed_before")
        deduplicate = value.get("deduplicate", True)
        if not isinstance(deduplicate, bool):
            raise TypeError("deduplicate must be a boolean")
        strings = {
            "case_id": (str(value.get("case_id", "")).strip(), EVIDENCE_QUERY_MAX_CASE_ID),
            "target_id": (str(value.get("target_id", "")).strip(), EVIDENCE_QUERY_MAX_FILTER),
            "producer": (str(value.get("producer", "")).strip(), EVIDENCE_QUERY_MAX_FILTER),
            "workflow_definition_id": (
                str(value.get("workflow_definition_id", "")).strip(),
                EVIDENCE_QUERY_MAX_FILTER,
            ),
        }
        for name, (text, maximum) in strings.items():
            if len(text) > maximum:
                raise ValueError(f"{name} must contain at most {maximum} characters")
        return cls(
            case_id=strings["case_id"][0],
            target_id=strings["target_id"][0],
            producer=strings["producer"][0],
            workflow_definition_id=strings["workflow_definition_id"][0],
            observed_after=after,
            observed_before=before,
            limit=limit,
            deduplicate=deduplicate,
        )


def _text(value: object, *, maximum: int = 256) -> str:
    return str(value)[:maximum]


def _non_negative_int(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _content_key(reference: Mapping[str, object]) -> str:
    blob_id = _text(reference.get("blob_id", ""), maximum=64)
    if not blob_id:
        blob_id = _text(reference.get("evidence_id", ""), maximum=128)
    return blob_id


@dataclass
class _EvidenceGroup:
    canonical: Mapping[str, object]
    reference_count: int
    cases: set[str]
    targets: set[str]
    generations: set[str]


def _project(
    group: _EvidenceGroup,
) -> dict[str, object]:
    reference = group.canonical
    return {
        "case_id": _text(reference.get("case_id", ""), maximum=128),
        "evidence_id": _text(reference.get("evidence_id", ""), maximum=128),
        "content_digest": _text(reference.get("blob_id", ""), maximum=64),
        "media_type": _text(reference.get("media_type", ""), maximum=128),
        "byte_count": _non_negative_int(reference.get("byte_count", 0)),
        "target_id": _text(reference.get("target_id", "")),
        "generation": _text(reference.get("generation", "")),
        "producer": _text(reference.get("producer", "")),
        "provenance": _text(reference.get("provenance", "")),
        "observed_at": float(reference.get("observed_at", 0.0)),
        "target_epoch": reference.get("target_epoch"),
        "workflow_definition_id": _text(
            reference.get("workflow_definition_id", "")
        ),
        "workflow_definition_version": _non_negative_int(
            reference.get("workflow_definition_version", 0)
        ),
        "workflow_cycle_id": _text(reference.get("workflow_cycle_id", "")),
        "workflow_step_id": _text(reference.get("workflow_step_id", "")),
        "workflow_attempt": _non_negative_int(reference.get("workflow_attempt", 0)),
        "reference_count": group.reference_count,
        "case_count": len(group.cases),
        "target_count": len(group.targets),
        "generation_count": len(group.generations),
    }


class EvidenceQueryService:
    """Deep operator module for bounded metadata lookup and content folding."""

    def __init__(self, repository: EvidenceQueryRepository) -> None:
        self._repository = repository

    def query(self, arguments: Mapping[str, object]) -> dict[str, object]:
        query = EvidenceQuery.from_mapping(arguments)
        raw = self._repository.evidence_query_candidates(
            query,
            limit=EVIDENCE_QUERY_MAX_SCAN_REFERENCES + 1,
        )
        scan_truncated = len(raw) > EVIDENCE_QUERY_MAX_SCAN_REFERENCES
        references = raw[:EVIDENCE_QUERY_MAX_SCAN_REFERENCES]

        grouped: OrderedDict[str, _EvidenceGroup] = OrderedDict()
        unique_content = {_content_key(reference) for reference in references}
        for index, reference in enumerate(references):
            key = _content_key(reference) if query.deduplicate else "\0".join(
                (
                    _text(reference.get("evidence_id", ""), maximum=128),
                    _text(reference.get("case_id", ""), maximum=128),
                    str(index),
                )
            )
            existing = grouped.get(key)
            case = _text(reference.get("case_id", ""), maximum=128)
            target = _text(reference.get("target_id", ""))
            generation = _text(reference.get("generation", ""))
            if existing is None:
                grouped[key] = _EvidenceGroup(
                    canonical=reference,
                    reference_count=1,
                    cases={case},
                    targets={target},
                    generations={generation},
                )
            else:
                existing.reference_count += 1
                existing.cases.add(case)
                existing.targets.add(target)
                existing.generations.add(generation)

        items: list[dict[str, object]] = []
        byte_truncated = False
        for group in grouped.values():
            if len(items) >= query.limit:
                break
            item = _project(group)
            candidate = {
                "schema": EVIDENCE_QUERY_SCHEMA,
                "items": [*items, item],
            }
            rendered_bytes = len(
                json.dumps(candidate, separators=(",", ":")).encode("utf-8")
            )
            if rendered_bytes > _EVIDENCE_QUERY_ITEM_BUDGET:
                byte_truncated = True
                break
            items.append(item)

        selected_count = len(grouped)
        truncated = (
            scan_truncated
            or byte_truncated
            or selected_count > len(items)
        )
        return {
            "schema": EVIDENCE_QUERY_SCHEMA,
            "filters": {
                "case_id": _text(query.case_id, maximum=128),
                "target_id": _text(query.target_id),
                "producer": _text(query.producer),
                "workflow_definition_id": _text(query.workflow_definition_id),
                "observed_after": query.observed_after,
                "observed_before": query.observed_before,
                "deduplicate": query.deduplicate,
            },
            "matched_reference_count": len(references),
            "matched_reference_count_is_lower_bound": scan_truncated,
            "unique_content_count": len(unique_content),
            "returned_item_count": len(items),
            "truncated": truncated,
            "items": items,
        }
