"""Typed durable diagnosis semantics derived from persisted Domain results."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
import copy
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re

from .capabilities import CAPABILITY_ALIASES
from .comparison_receipt import build_comparison_receipt
from .comparison_targets import comparison_target_identities
from .contracts import RUNTIME_API_VERSION
from .diagnostic_request import DiagnosticRequestPlan
from .redaction import is_secret_key, redact_text


DIAGNOSTIC_RECEIPT_SCHEMA = f"{RUNTIME_API_VERSION}/diagnostic-receipt-v1"
DIAGNOSTIC_RECEIPT_MAX_BYTES = 32 * 1024
DIAGNOSTIC_RECEIPT_MAX_PREVIEW_RESULTS = 64
DIAGNOSTIC_RECEIPT_MAX_STORED_RESULTS = 1024
_ADVICE_SCHEMA = "openubmc-debug.diagnostic-advice.v1"
_ADVICE_MAX_BYTES = 16 * 1024
_ADVICE_STAGES = ("hardware_discovery", "mdb", "northbound")
_DIAGNOSIS_FIELDS = (
    "symptom",
    "root_cause",
    "mechanism",
    "affected_surface",
    "code_owner",
    "call_path",
)
_DIAGNOSTIC_REQUEST_FIELDS = (
    "files",
    "logs",
    "tree_service",
    "tree_head",
    "mdb_queries",
    "mdb_expand_classes",
    "mdb_only",
    "alarm_service",
    "source_correlation_requested",
)
_DIAGNOSTIC_VALUE_METADATA_FIELDS = frozenset(
    {"content_complete", "content_compacted", "projection_truncated", "truncated"}
)
_DIAGNOSTIC_SUMMARY_LOW_VALUE_FIELDS = _DIAGNOSTIC_VALUE_METADATA_FIELDS | {
    "bytes_returned",
    "command",
    "empty",
    "line_count",
    "stderr",
    "stderr_lines",
}
_DIAGNOSTIC_SUMMARY_FIELD_PRIORITY = {
    name: index
    for index, name in enumerate(
        (
            "root_cause",
            "symptom",
            "lines",
            "lines_preview",
            "empty_message",
            "warnings",
            "stdout_lines",
            "stdout",
            "records",
            "entries",
            "properties",
            "differences",
            "status",
            "state",
            "value",
            "name",
            "path",
        )
    )
}
_DIAGNOSTIC_PROJECTION_TRUNCATION_FIELDS = frozenset(
    {
        "lines_truncated",
        "projection_truncated",
        "stderr_truncated",
        "stdout_truncated",
        "text_truncated",
    }
)
_DIAGNOSTIC_SUMMARY_COMPLETE_KINDS = frozenset(
    {
        "active-alarms",
        "diagnostic-correlation",
        "diagnostic-comparison",
        "mdb",
        "mdb-class-expansion",
        "service-list",
        "service-tree",
        "target-clock",
    }
)


class DiagnosticStatus(str, Enum):
    BLOCKED = "blocked"
    PARTIAL = "partial"
    COMPLETE = "complete"

    @classmethod
    def parse(cls, value: object) -> "DiagnosticStatus":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip())
        except ValueError:
            return cls.BLOCKED


class DiagnosticItemStatus(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    NOT_CHECKED = "not_checked"

    @classmethod
    def parse(cls, value: object) -> "DiagnosticItemStatus":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip())
        except ValueError:
            return cls.NOT_CHECKED


class DiagnosticCapabilityStatus(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    NOT_CHECKED = "not_checked"

    @classmethod
    def parse(cls, value: object) -> "DiagnosticCapabilityStatus":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip())
        except ValueError:
            return cls.NOT_CHECKED


class DiagnosticFreshnessStatus(str, Enum):
    UNKNOWN = "unknown"
    PARTIAL = "partial"
    FRESH = "fresh"
    COMPLETE = "complete"
    STALE = "stale"
    UNAVAILABLE = "unavailable"

    @classmethod
    def parse(cls, value: object) -> "DiagnosticFreshnessStatus":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip())
        except ValueError:
            return cls.UNKNOWN


def _count(value: object, default: int = 0) -> int:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        else default
    )


@dataclass(frozen=True)
class DiagnosticCoverage:
    requested: int
    evaluable: int
    unavailable: int
    not_checked: int
    complete: bool
    visible_evaluable: int | None = None
    visible_unavailable: int | None = None
    visible_not_checked: int | None = None
    compacted: int = 0

    @classmethod
    def from_public_dict(cls, value: Mapping[str, object]) -> "DiagnosticCoverage":
        requested = _count(value.get("requested"))
        return cls(
            requested=requested,
            evaluable=_count(value.get("evaluable")),
            unavailable=_count(value.get("unavailable")),
            not_checked=_count(value.get("not_checked")),
            complete=value.get("complete") is True,
            visible_evaluable=(
                _count(value.get("visible_evaluable"))
                if "visible_evaluable" in value
                else None
            ),
            visible_unavailable=(
                _count(value.get("visible_unavailable"))
                if "visible_unavailable" in value
                else None
            ),
            visible_not_checked=(
                _count(value.get("visible_not_checked"))
                if "visible_not_checked" in value
                else None
            ),
            compacted=_count(value.get("compacted")),
        )

    def to_public_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "requested": self.requested,
            "evaluable": self.evaluable,
            "unavailable": self.unavailable,
            "not_checked": self.not_checked,
            "complete": self.complete,
        }
        if self.visible_evaluable is not None:
            result["visible_evaluable"] = self.visible_evaluable
        if self.visible_unavailable is not None:
            result["visible_unavailable"] = self.visible_unavailable
        if self.visible_not_checked is not None:
            result["visible_not_checked"] = self.visible_not_checked
        if self.compacted:
            result["compacted"] = self.compacted
        return result

@dataclass(frozen=True)
class DiagnosticResult:
    result_id: str
    kind: str
    request: str
    status: DiagnosticItemStatus
    observed_at: str = ""
    gap: str = ""
    value: object | None = None
    evidence_ids: tuple[str, ...] = ()
    projection_truncated: bool = False

    @classmethod
    def from_public_dict(cls, value: Mapping[str, object]) -> "DiagnosticResult":
        raw_ids = value.get("evidence_ids", [])
        return cls(
            result_id=str(value.get("result_id", "")).strip(),
            kind=str(value.get("kind", "")).strip(),
            request=str(value.get("request", "")).strip(),
            status=DiagnosticItemStatus.parse(value.get("status")),
            observed_at=str(value.get("observed_at", "")).strip(),
            gap=str(value.get("gap", "")).strip(),
            value=value.get("value"),
            evidence_ids=tuple(
                str(item)
                for item in (
                    raw_ids
                    if isinstance(raw_ids, Sequence)
                    and not isinstance(raw_ids, (str, bytes, bytearray))
                    else ()
                )
            ),
            projection_truncated=value.get("projection_truncated") is True,
        )

    def to_public_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "result_id": self.result_id,
            "status": self.status.value,
        }
        if self.kind:
            result["kind"] = self.kind
        if self.request:
            result["request"] = self.request
        if self.evidence_ids:
            result["evidence_ids"] = list(self.evidence_ids)
        if self.observed_at:
            result["observed_at"] = self.observed_at
        if self.gap:
            result["gap"] = self.gap
        if self.value is not None:
            result["value"] = self.value
        if self.projection_truncated:
            result["projection_truncated"] = True
        return result

    def compacted_for_agent(self) -> "DiagnosticResult":
        tracker = [False]
        compacted_value = (
            _bounded_public(
                self.value,
                truncated=tracker,
                max_depth=2,
                max_items=6,
                max_string=192,
            )
            if self.value is not None
            else None
        )
        if tracker[0]:
            compacted_value = _without_compacted_placeholders(compacted_value)
            summary = _bounded_diagnostic_value_summary(self.value)
            if summary is not None:
                if isinstance(compacted_value, Mapping):
                    compacted_value = {**compacted_value, **summary}
                else:
                    compacted_value = summary
        status = self.status
        gap = self.gap
        if (
            status is DiagnosticItemStatus.AVAILABLE
            and not diagnostic_result_value_evaluable(compacted_value)
        ):
            compacted_value = _bounded_diagnostic_value_summary(self.value)
            tracker[0] = True
            if not diagnostic_result_value_evaluable(compacted_value):
                status = DiagnosticItemStatus.NOT_CHECKED
                gap = gap or "result_not_evaluable_after_compaction"
        result_id = _bounded_text(self.result_id, 128)
        kind = _bounded_text(self.kind, 128)
        request = _bounded_text(self.request, 192)
        observed_at = _bounded_text(self.observed_at, 128)
        gap = _bounded_text(gap, 192)
        evidence_ids = tuple(
            _bounded_text(item, 128) for item in self.evidence_ids[:6]
        )
        text_truncated = any(
            (
                result_id != self.result_id,
                kind != self.kind,
                request != self.request,
                observed_at != self.observed_at,
                gap != self.gap,
                evidence_ids != self.evidence_ids,
            )
        )
        return replace(
            self,
            result_id=result_id,
            kind=kind,
            request=request,
            status=status,
            observed_at=observed_at,
            gap=gap,
            value=compacted_value,
            evidence_ids=evidence_ids,
            projection_truncated=(
                self.projection_truncated or tracker[0] or text_truncated
            ),
        )

    def compacted_identity_for_agent(
        self,
        *,
        minimal: bool = False,
    ) -> "DiagnosticResult":
        was_available = self.status is DiagnosticItemStatus.AVAILABLE
        gap = (
            "result_preview_compacted"
            if was_available
            else self.gap
        )
        return replace(
            self,
            result_id=_bounded_text(self.result_id, 64),
            kind="" if minimal else _bounded_text(self.kind, 48),
            request="" if minimal else _bounded_text(self.request, 96),
            status=(
                DiagnosticItemStatus.NOT_CHECKED if was_available else self.status
            ),
            observed_at="" if minimal else _bounded_text(self.observed_at, 64),
            gap=_bounded_text(gap or "result_not_visible", 96),
            value=None,
            evidence_ids=(),
            projection_truncated=True,
        )

    def compacted_for_storage(self) -> "DiagnosticResult":
        compacted_value = (
            _bounded_diagnostic_value_summary(
                self.value,
                max_samples=2,
                max_string=96,
            )
            if self.value is not None
            else None
        )
        status = self.status
        gap = self.gap
        if (
            status is DiagnosticItemStatus.AVAILABLE
            and not diagnostic_result_value_evaluable(compacted_value)
        ):
            compacted_value = _bounded_diagnostic_value_summary(self.value)
            if not diagnostic_result_value_evaluable(compacted_value):
                status = DiagnosticItemStatus.NOT_CHECKED
                gap = gap or "result_not_visible_after_redaction"
        return replace(
            self,
            result_id=_bounded_text(self.result_id, 128),
            kind=_bounded_text(self.kind, 48),
            request=_bounded_text(self.request, 96),
            status=status,
            observed_at=_bounded_text(self.observed_at, 64),
            gap=_bounded_text(gap, 96),
            value=compacted_value,
            evidence_ids=tuple(
                _bounded_text(item, 64) for item in self.evidence_ids[:2]
            ),
            projection_truncated=True,
        )


@dataclass(frozen=True)
class DiagnosticFreshness:
    status: DiagnosticFreshnessStatus
    observed_at: str
    complete: bool | None = None
    unavailable_dimensions: tuple[object, ...] = ()
    lost_dimensions: tuple[object, ...] = ()
    stale_evidence: tuple[object, ...] = ()

    @classmethod
    def from_public_dict(cls, value: Mapping[str, object]) -> "DiagnosticFreshness":
        def items(name: str) -> tuple[object, ...]:
            raw = value.get(name, [])
            return (
                tuple(raw)
                if isinstance(raw, Sequence)
                and not isinstance(raw, (str, bytes, bytearray))
                else ()
            )

        return cls(
            status=DiagnosticFreshnessStatus.parse(value.get("status")),
            observed_at=str(value.get("observed_at", "")).strip(),
            complete=(value.get("complete") is True if "complete" in value else None),
            unavailable_dimensions=items("unavailable_dimensions"),
            lost_dimensions=items("lost_dimensions"),
            stale_evidence=items("stale_evidence"),
        )

    def to_public_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "status": self.status.value,
            "observed_at": self.observed_at,
        }
        if self.complete is not None:
            result["complete"] = self.complete
        for name, values in (
            ("unavailable_dimensions", self.unavailable_dimensions),
            ("lost_dimensions", self.lost_dimensions),
            ("stale_evidence", self.stale_evidence),
        ):
            if values:
                result[name] = list(values)
        return result

    def compacted_for_agent(
        self,
        *,
        minimal: bool = False,
    ) -> "DiagnosticFreshness":
        return replace(
            self,
            observed_at=_bounded_text(self.observed_at, 128),
            unavailable_dimensions=tuple(
                _bounded_public(
                    item,
                    max_depth=2,
                    max_items=4,
                    max_string=128,
                )
                for item in (() if minimal else self.unavailable_dimensions[:4])
            ),
            lost_dimensions=tuple(
                _bounded_public(
                    item,
                    max_depth=2,
                    max_items=4,
                    max_string=128,
                )
                for item in (() if minimal else self.lost_dimensions[:4])
            ),
            stale_evidence=tuple(
                _bounded_public(
                    item,
                    max_depth=2,
                    max_items=4,
                    max_string=128,
                )
                for item in (() if minimal else self.stale_evidence[:4])
            ),
        )


@dataclass(frozen=True)
class DiagnosticEvidenceRef:
    evidence_id: str
    target_id: str = ""
    observed_at: object = ""
    target_epoch: object = None
    byte_count: object = None

    @classmethod
    def from_public_dict(cls, value: Mapping[str, object]) -> "DiagnosticEvidenceRef":
        return cls(
            evidence_id=str(value.get("evidence_id", "")).strip(),
            target_id=str(value.get("target_id", "")).strip(),
            observed_at=value.get("observed_at", ""),
            target_epoch=value.get("target_epoch"),
            byte_count=value.get("byte_count"),
        )

    def to_public_dict(self, *, minimal: bool = False) -> dict[str, object]:
        result: dict[str, object] = {
            "evidence_id": _bounded_text(self.evidence_id, 128)
        }
        if minimal:
            return result
        for name, value in (
            ("target_id", self.target_id),
            ("observed_at", self.observed_at),
            ("target_epoch", self.target_epoch),
            ("byte_count", self.byte_count),
        ):
            if value is not None and value != "":
                result[name] = _bounded_public(
                    value,
                    max_depth=2,
                    max_items=4,
                    max_string=128,
                )
        return result


@dataclass(frozen=True)
class DiagnosticCompactedResultSet:
    status: DiagnosticItemStatus
    gap: str
    result_ids: tuple[str, ...]

    @classmethod
    def from_public_dict(
        cls,
        value: Mapping[str, object],
    ) -> "DiagnosticCompactedResultSet":
        raw_ids = value.get("result_ids", [])
        return cls(
            status=DiagnosticItemStatus.parse(value.get("status")),
            gap=str(value.get("gap", "")).strip(),
            result_ids=tuple(
                str(item).strip()
                for item in (
                    raw_ids
                    if isinstance(raw_ids, Sequence)
                    and not isinstance(raw_ids, (str, bytes, bytearray))
                    else ()
                )
                if str(item).strip()
            ),
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "gap": self.gap,
            "result_ids": list(self.result_ids),
        }


@dataclass(frozen=True)
class DiagnosticReceipt:
    """Typed durable diagnosis semantics before AgentGateway projection."""

    receipt_id: str
    operation: str
    status: DiagnosticStatus
    coverage: DiagnosticCoverage
    results: tuple[DiagnosticResult, ...]
    freshness: DiagnosticFreshness
    capabilities: tuple[tuple[str, DiagnosticCapabilityStatus], ...]
    truncated: bool
    content_complete: bool
    evidence: tuple[DiagnosticEvidenceRef, ...]
    gaps: tuple[str, ...]
    compacted_results: DiagnosticCompactedResultSet | None = None
    schema: str = DIAGNOSTIC_RECEIPT_SCHEMA
    content_compacted: bool = False
    diagnostic_advice: Mapping[str, object] | None = None
    diagnostic_advice_omitted: str = ""

    @classmethod
    def from_public_dict(
        cls, value: Mapping[str, object]
    ) -> "DiagnosticReceipt":
        raw_results = value.get("results", [])
        raw_evidence = value.get("evidence", [])
        raw_gaps = value.get("gaps", [])
        raw_compacted_results = value.get("compacted_results")
        raw_capabilities = _mapping(value.get("capabilities"))
        receipt = cls(
            receipt_id=str(value.get("receipt_id", "")).strip(),
            operation=str(value.get("operation", "")).strip(),
            status=DiagnosticStatus.parse(value.get("status")),
            coverage=DiagnosticCoverage.from_public_dict(
                _mapping(value.get("coverage"))
            ),
            results=tuple(
                DiagnosticResult.from_public_dict(item)
                for item in (
                    raw_results
                    if isinstance(raw_results, Sequence)
                    and not isinstance(raw_results, (str, bytes, bytearray))
                    else ()
                )
                if isinstance(item, Mapping)
            ),
            freshness=DiagnosticFreshness.from_public_dict(
                _mapping(value.get("freshness"))
            ),
            capabilities=tuple(
                (str(name), DiagnosticCapabilityStatus.parse(state))
                for name, state in raw_capabilities.items()
            ),
            truncated=value.get("truncated") is True,
            content_complete=value.get("content_complete") is True,
            evidence=tuple(
                DiagnosticEvidenceRef.from_public_dict(item)
                for item in (
                    raw_evidence
                    if isinstance(raw_evidence, Sequence)
                    and not isinstance(raw_evidence, (str, bytes, bytearray))
                    else ()
                )
                if isinstance(item, Mapping)
            ),
            gaps=tuple(
                str(item)
                for item in (
                    raw_gaps
                    if isinstance(raw_gaps, Sequence)
                    and not isinstance(raw_gaps, (str, bytes, bytearray))
                    else ()
                )
            ),
            compacted_results=(
                DiagnosticCompactedResultSet.from_public_dict(
                    raw_compacted_results
                )
                if isinstance(raw_compacted_results, Mapping)
                else None
            ),
            schema=str(value.get("schema") or DIAGNOSTIC_RECEIPT_SCHEMA),
            content_compacted=value.get("content_compacted") is True,
            diagnostic_advice=_stored_diagnostic_advice(value.get("diagnostic_advice"), raw_evidence),
            diagnostic_advice_omitted=(
                str(value.get("diagnostic_advice_omitted", ""))
                if value.get("diagnostic_advice_omitted") in {"projection_budget", "persistence_budget"}
                else ""
            ),
        )
        validation_gaps = receipt._validation_gaps()
        if not validation_gaps:
            return receipt
        normalized_results = tuple(
            replace(
                item,
                status=DiagnosticItemStatus.NOT_CHECKED,
                gap=item.gap or "result_not_evaluable",
                value=None,
            )
            if item.status is DiagnosticItemStatus.AVAILABLE
            and not diagnostic_result_value_evaluable(item.value)
            else item
            for item in receipt.results
        )
        compacted_count = (
            len(receipt.compacted_results.result_ids)
            if receipt.compacted_results is not None
            else 0
        )
        identity_count = len(normalized_results) + compacted_count
        requested = max(receipt.coverage.requested, identity_count)
        available_results = sum(
            item.status is DiagnosticItemStatus.AVAILABLE
            for item in normalized_results
        )
        unavailable_results = sum(
            item.status is DiagnosticItemStatus.UNAVAILABLE
            for item in normalized_results
        )
        not_checked_results = sum(
            item.status is DiagnosticItemStatus.NOT_CHECKED
            for item in normalized_results
        )
        if receipt.compacted_results is not None:
            if (
                receipt.compacted_results.status
                is DiagnosticItemStatus.UNAVAILABLE
            ):
                unavailable_results += compacted_count
            else:
                not_checked_results += compacted_count
        not_checked_results += max(0, requested - identity_count)
        gaps = list(receipt.gaps)
        for gap in ("diagnostic_receipt_invalid", *validation_gaps):
            if gap not in gaps:
                gaps.append(gap)
        return replace(
            receipt,
            status=(
                DiagnosticStatus.PARTIAL
                if available_results > 0
                else DiagnosticStatus.BLOCKED
            ),
            coverage=replace(
                receipt.coverage,
                requested=requested,
                evaluable=available_results,
                unavailable=unavailable_results,
                not_checked=not_checked_results,
                complete=False,
            ),
            results=normalized_results,
            gaps=tuple(gaps),
        )

    def _validation_gaps(self) -> tuple[str, ...]:
        gaps: list[str] = []
        coverage = self.coverage
        result_ids = [item.result_id for item in self.results]
        compacted_result_ids = (
            list(self.compacted_results.result_ids)
            if self.compacted_results is not None
            else []
        )
        all_result_ids = [*result_ids, *compacted_result_ids]
        if len(all_result_ids) != coverage.requested:
            gaps.append("diagnostic_result_identity_count_mismatch")
        if (
            any(not result_id for result_id in all_result_ids)
            or len(set(all_result_ids)) != len(all_result_ids)
        ):
            gaps.append("diagnostic_result_identity_invalid")
        accounted = (
            coverage.evaluable + coverage.unavailable + coverage.not_checked
        )
        if coverage.requested != accounted:
            gaps.append("diagnostic_coverage_count_mismatch")
        non_evaluable_available = sum(
            item.status is DiagnosticItemStatus.AVAILABLE
            and not diagnostic_result_value_evaluable(item.value)
            for item in self.results
        )
        if non_evaluable_available:
            gaps.append("diagnostic_available_result_not_evaluable")
        result_counts = {
            DiagnosticItemStatus.AVAILABLE: sum(
                item.status is DiagnosticItemStatus.AVAILABLE
                for item in self.results
            ),
            DiagnosticItemStatus.UNAVAILABLE: sum(
                item.status is DiagnosticItemStatus.UNAVAILABLE
                for item in self.results
            ),
            DiagnosticItemStatus.NOT_CHECKED: sum(
                item.status is DiagnosticItemStatus.NOT_CHECKED
                for item in self.results
            ),
        }
        visible_counts = dict(result_counts)
        if self.compacted_results is not None:
            visible_counts[self.compacted_results.status] += len(
                self.compacted_results.result_ids
            )
        claimed_visible = (
            coverage.visible_evaluable,
            coverage.visible_unavailable,
            coverage.visible_not_checked,
        )
        if any(value is not None for value in claimed_visible):
            if any(value is None for value in claimed_visible):
                gaps.append("diagnostic_visible_coverage_incomplete")
            else:
                expected_visible = (
                    visible_counts[DiagnosticItemStatus.AVAILABLE],
                    visible_counts[DiagnosticItemStatus.UNAVAILABLE],
                    visible_counts[DiagnosticItemStatus.NOT_CHECKED],
                )
                if claimed_visible != expected_visible:
                    gaps.append("diagnostic_visible_coverage_count_mismatch")
                if sum(claimed_visible) != coverage.requested:
                    gaps.append("diagnostic_visible_coverage_scope_mismatch")
        elif self.content_compacted:
            gaps.append("diagnostic_visible_coverage_missing")
        if self.status is DiagnosticStatus.COMPLETE or coverage.complete:
            if self.status is not DiagnosticStatus.COMPLETE or not coverage.complete:
                gaps.append("diagnostic_completion_status_mismatch")
            if coverage.unavailable or coverage.not_checked:
                gaps.append("diagnostic_complete_has_coverage_gaps")
            if not self.content_compacted:
                if len(self.results) != coverage.requested:
                    gaps.append("diagnostic_complete_result_count_mismatch")
                if result_counts[DiagnosticItemStatus.AVAILABLE] != coverage.requested:
                    gaps.append("diagnostic_complete_results_not_available")
        return tuple(gaps)

    def to_public_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schema": self.schema,
            "receipt_id": self.receipt_id,
            "operation": self.operation,
            "status": self.status.value,
            "coverage": self.coverage.to_public_dict(),
            "results": [item.to_public_dict() for item in self.results],
            "freshness": self.freshness.to_public_dict(),
            "capabilities": {
                name: status.value for name, status in self.capabilities
            },
            "truncated": self.truncated,
            "content_complete": self.content_complete,
            "evidence": [item.to_public_dict() for item in self.evidence],
            "gaps": list(self.gaps),
        }
        if self.content_compacted:
            result["content_compacted"] = True
        if self.compacted_results is not None:
            result["compacted_results"] = self.compacted_results.to_public_dict()
        if self.diagnostic_advice is not None:
            result["diagnostic_advice"] = copy.deepcopy(dict(self.diagnostic_advice))
        if self.diagnostic_advice_omitted:
            result["diagnostic_advice_omitted"] = self.diagnostic_advice_omitted
        return result

    def status_for_agent_acceptance(self) -> DiagnosticStatus:
        """Classify whether the persisted receipt is fully evaluable by an Agent."""
        return self.agent_acceptance_for(self.status, self.coverage)

    @staticmethod
    def agent_acceptance_for(
        source_status: DiagnosticStatus,
        coverage: DiagnosticCoverage,
    ) -> DiagnosticStatus:
        """Classify Agent evaluability without rewriting source completion."""

        if source_status is DiagnosticStatus.BLOCKED:
            return source_status
        visible = (
            coverage.visible_evaluable,
            coverage.visible_unavailable,
            coverage.visible_not_checked,
        )
        if all(value is None for value in visible):
            return source_status
        visible_evaluable = coverage.visible_evaluable or 0
        if source_status is DiagnosticStatus.COMPLETE and (
            visible_evaluable == coverage.requested
            and (coverage.visible_unavailable or 0) == 0
            and (coverage.visible_not_checked or 0) == 0
        ):
            return source_status
        return (
            DiagnosticStatus.PARTIAL
            if visible_evaluable > 0
            else DiagnosticStatus.BLOCKED
        )

    def compacted_for_agent(self) -> "DiagnosticReceipt":
        selected_items: list[DiagnosticResult] = []
        for item in self.results:
            compacted = item.compacted_for_agent()
            selected_items.append(
                item if compacted.status is not item.status else compacted
            )
        selected = tuple(selected_items)
        visible_evaluable = sum(
            item.status is DiagnosticItemStatus.AVAILABLE for item in selected
        )
        visible_unavailable = sum(
            item.status is DiagnosticItemStatus.UNAVAILABLE for item in selected
        )
        visible_not_checked = sum(
            item.status is DiagnosticItemStatus.NOT_CHECKED for item in selected
        )
        if self.compacted_results is not None:
            compacted_count = len(self.compacted_results.result_ids)
            if (
                self.compacted_results.status
                is DiagnosticItemStatus.UNAVAILABLE
            ):
                visible_unavailable += compacted_count
            else:
                visible_not_checked += compacted_count
        compacted = max(self.coverage.compacted, self.coverage.requested)
        coverage = replace(
            self.coverage,
            visible_evaluable=visible_evaluable,
            visible_unavailable=visible_unavailable,
            visible_not_checked=visible_not_checked,
            compacted=compacted,
        )
        gaps = list(self.gaps[:5])
        if "diagnostic_receipt_compacted" not in gaps:
            gaps.append("diagnostic_receipt_compacted")
        return replace(
            self,
            coverage=coverage,
            results=selected,
            freshness=self.freshness.compacted_for_agent(),
            capabilities=tuple(
                (_bounded_text(name, 32), status)
                for name, status in self.capabilities[:8]
            ),
            truncated=self.truncated,
            content_complete=self.content_complete,
            evidence=self.evidence[:8],
            gaps=tuple(_bounded_text(gap, 128) for gap in gaps[:8]),
            schema=_bounded_text(self.schema, 128),
            receipt_id=_bounded_text(self.receipt_id, 128),
            operation=_bounded_text(self.operation, 128),
            content_compacted=True,
            diagnostic_advice=None,
            diagnostic_advice_omitted=("projection_budget" if self.diagnostic_advice else self.diagnostic_advice_omitted),
        )
    def bounded_for_persistence(self) -> "DiagnosticReceipt":
        if len(_json_bytes(self.to_public_dict())) <= DIAGNOSTIC_RECEIPT_MAX_BYTES:
            return self
        if self.diagnostic_advice is not None:
            return replace(self, diagnostic_advice=None, diagnostic_advice_omitted="persistence_budget").bounded_for_persistence()
        stored_results = self.results[:DIAGNOSTIC_RECEIPT_MAX_STORED_RESULTS]
        preview_limit = min(
            DIAGNOSTIC_RECEIPT_MAX_PREVIEW_RESULTS,
            len(stored_results),
        )
        compacted: DiagnosticReceipt | None = None
        while preview_limit >= 0:
            preview_results = tuple(
                item.compacted_for_storage()
                for item in stored_results[:preview_limit]
            )
            compacted_ids = tuple(
                _bounded_text(item.result_id, 64)
                for item in stored_results[preview_limit:]
            )
            visible_evaluable = sum(
                item.status is DiagnosticItemStatus.AVAILABLE
                for item in preview_results
            )
            visible_unavailable = sum(
                item.status is DiagnosticItemStatus.UNAVAILABLE
                for item in preview_results
            )
            visible_not_checked = (
                sum(
                    item.status is DiagnosticItemStatus.NOT_CHECKED
                    for item in preview_results
                )
                + len(compacted_ids)
            )
            gaps = list(self.gaps[:5])
            omitted = max(0, self.coverage.requested - len(stored_results))
            if omitted:
                gaps.append(f"{omitted}_diagnostic_items_compacted")
            if "diagnostic_receipt_compacted" not in gaps:
                gaps.append("diagnostic_receipt_compacted")
            compacted = replace(
                self,
                coverage=replace(
                    self.coverage,
                    visible_evaluable=visible_evaluable,
                    visible_unavailable=visible_unavailable,
                    visible_not_checked=visible_not_checked,
                    compacted=max(
                        self.coverage.compacted,
                        self.coverage.requested,
                    ),
                ),
                results=preview_results,
                freshness=self.freshness.compacted_for_agent(),
                capabilities=self.capabilities[:8],
                truncated=self.truncated,
                content_complete=self.content_complete,
                evidence=self.evidence[:8],
                gaps=tuple(_bounded_text(gap, 128) for gap in gaps[:8]),
                compacted_results=(
                    DiagnosticCompactedResultSet(
                        status=DiagnosticItemStatus.NOT_CHECKED,
                        gap="result_preview_compacted",
                        result_ids=compacted_ids,
                    )
                ) if compacted_ids else None,
                content_compacted=True,
            )
            if len(_json_bytes(compacted.to_public_dict())) <= DIAGNOSTIC_RECEIPT_MAX_BYTES:
                return compacted
            if preview_limit == 0:
                break
            preview_limit //= 2
        assert compacted is not None
        compacted_ids = tuple(
            _bounded_text(item.result_id, 32)
            for item in stored_results
        )
        minimal = replace(
            compacted,
            coverage=replace(
                compacted.coverage,
                visible_evaluable=0,
                visible_unavailable=0,
                visible_not_checked=len(compacted_ids),
                compacted=self.coverage.requested,
            ),
            results=(),
            freshness=self.freshness.compacted_for_agent(minimal=True),
            capabilities=self.capabilities[:8],
            evidence=tuple(
                replace(
                    item,
                    target_id="",
                    observed_at="",
                    target_epoch=None,
                    byte_count=None,
                )
                for item in self.evidence[:8]
            ),
            compacted_results=(
                DiagnosticCompactedResultSet(
                    status=DiagnosticItemStatus.NOT_CHECKED,
                    gap="result_preview_compacted",
                    result_ids=compacted_ids,
                )
            ) if compacted_ids else None,
        )
        if len(_json_bytes(minimal.to_public_dict())) <= DIAGNOSTIC_RECEIPT_MAX_BYTES:
            return minimal
        return replace(
            minimal,
            compacted_results=None,
            gaps=tuple(
                (*minimal.gaps[:7], "diagnostic_result_identities_exceed_budget")
            ),
        )


def latest_diagnostic_receipt(
    projection: Mapping[str, object],
) -> DiagnosticReceipt | None:
    """Return the latest receipt in the current workflow cycle.

    Phase receipts supersede Domain operation receipts, so every Runtime reader
    observes the same diagnosis lineage after a diagnosis Gate is accepted.
    """

    cycle_id = str(projection.get("workflow_cycle_id") or "cycle-1").strip()
    for collection_name in ("phase_records", "operations"):
        records = projection.get(collection_name, [])
        if not isinstance(records, list):
            continue
        for record in reversed(records):
            if not isinstance(record, Mapping):
                continue
            record_cycle = str(record.get("workflow_cycle_id") or "").strip()
            if (record_cycle or "cycle-1") != cycle_id:
                continue
            candidate = record.get("diagnostic_receipt")
            if isinstance(candidate, Mapping):
                return DiagnosticReceipt.from_public_dict(candidate)
    return None


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def _bounded_text(value: object, limit: int = 512) -> str:
    text = redact_text(value).strip()
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    return encoded[: limit - 3].decode("utf-8", errors="ignore") + "..."


def _bounded_public(
    value: object,
    *,
    depth: int = 0,
    truncated: list[bool] | None = None,
    max_depth: int = 4,
    max_items: int = 16,
    max_string: int = 512,
) -> object:
    tracker = truncated if truncated is not None else [False]
    if isinstance(value, str):
        bounded = _bounded_text(value, max_string)
        if bounded != redact_text(value).strip():
            tracker[0] = True
        return bounded
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if depth >= max_depth:
        tracker[0] = True
        return "<compacted>"
    if isinstance(value, Mapping):
        public_items = [
            (key, item)
            for key, item in value.items()
            if not is_secret_key(str(key))
        ]
        if len(public_items) != len(value):
            tracker[0] = True
        if len(public_items) > max_items:
            tracker[0] = True
        bounded: dict[str, object] = {}
        for key, item in public_items[:max_items]:
            bounded_key = _bounded_text(key, 128)
            if bounded_key != redact_text(key).strip():
                tracker[0] = True
            bounded[bounded_key] = _bounded_public(
                item,
                depth=depth + 1,
                truncated=tracker,
                max_depth=max_depth,
                max_items=max_items,
                max_string=max_string,
            )
        return bounded
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        if len(value) > max_items:
            tracker[0] = True
        return [
            _bounded_public(
                item,
                depth=depth + 1,
                truncated=tracker,
                max_depth=max_depth,
                max_items=max_items,
                max_string=max_string,
            )
            for item in list(value)[:max_items]
        ]
    return _bounded_text(value, max_string)


def diagnostic_result_value_evaluable(value: object) -> bool:
    """Return whether a bounded result still contains substantive visible content."""

    if isinstance(value, Mapping):
        return any(
            diagnostic_result_value_evaluable(item)
            for key, item in value.items()
            if str(key) not in _DIAGNOSTIC_VALUE_METADATA_FIELDS
            and not is_secret_key(str(key))
        )
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        return any(diagnostic_result_value_evaluable(item) for item in value)
    if isinstance(value, str):
        return bool(value.strip()) and value.strip() != "<compacted>"
    return value is not None


def _without_compacted_placeholders(value: object) -> object | None:
    if isinstance(value, Mapping):
        compacted = {
            str(key): selected
            for key, item in value.items()
            if (selected := _without_compacted_placeholders(item)) is not None
        }
        return compacted or None
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        compacted = [
            selected
            for item in value
            if (selected := _without_compacted_placeholders(item)) is not None
        ]
        return compacted or None
    if isinstance(value, str) and value.strip() == "<compacted>":
        return None
    return value


def _bounded_diagnostic_value_summary(
    value: object,
    *,
    max_samples: int = 4,
    max_string: int = 192,
) -> object | None:
    samples: list[dict[str, object]] = []
    visited = 0

    def collect(current: object, path: str, depth: int) -> None:
        nonlocal visited
        if len(samples) >= max_samples or visited >= 64 or depth > 8:
            return
        visited += 1
        if isinstance(current, Mapping):
            existing_summary = current.get("summary")
            if isinstance(existing_summary, Sequence) and not isinstance(
                existing_summary, (str, bytes, bytearray)
            ):
                preserved = len(samples)
                for index, item in enumerate(existing_summary[:8]):
                    summary_item = _mapping(item)
                    selected = (
                        summary_item.get("value")
                        if summary_item
                        else item
                    )
                    bounded = _bounded_public(selected, max_string=max_string)
                    if not diagnostic_result_value_evaluable(bounded):
                        continue
                    samples.append(
                        {
                            "path": _bounded_text(
                                summary_item.get("path")
                                or f"{path}.summary[{index}]",
                                192,
                            ),
                            "value": bounded,
                        }
                    )
                    if len(samples) >= max_samples:
                        return
                if len(samples) > preserved:
                    return
            prioritized = sorted(
                enumerate(current.items()),
                key=lambda entry: (
                    _DIAGNOSTIC_SUMMARY_FIELD_PRIORITY.get(
                        str(entry[1][0]),
                        len(_DIAGNOSTIC_SUMMARY_FIELD_PRIORITY),
                    ),
                    entry[0],
                ),
            )
            for _index, (key, item) in prioritized:
                name = str(key)
                if (
                    name in _DIAGNOSTIC_SUMMARY_LOW_VALUE_FIELDS
                    or is_secret_key(name)
                ):
                    continue
                collect(item, f"{path}.{name}", depth + 1)
                if len(samples) >= max_samples:
                    return
            return
        if isinstance(current, Sequence) and not isinstance(
            current, (str, bytes, bytearray)
        ):
            for index, item in enumerate(current[:8]):
                collect(item, f"{path}[{index}]", depth + 1)
                if len(samples) >= max_samples:
                    return
            return
        bounded = _bounded_public(current, max_string=max_string)
        if diagnostic_result_value_evaluable(bounded):
            samples.append(
                {
                    "path": _bounded_text(path, 192),
                    "value": bounded,
                }
            )

    collect(value, "$", 0)
    return {"summary": samples} if samples else None


def _fingerprint(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _diagnostic_content_with_flags(
    value: Mapping[str, object],
) -> tuple[dict[str, object], bool]:

    containers = (
        value,
        _mapping(value.get("diagnosis")),
        _mapping(value.get("analysis")),
    )
    selected: dict[str, object] = {}
    truncated = False
    for name in _DIAGNOSIS_FIELDS:
        for container in containers:
            candidate = container.get(name)
            if isinstance(candidate, str) and candidate.strip():
                bounded = _bounded_text(candidate)
                selected[name] = bounded
                if bounded != redact_text(candidate).strip():
                    truncated = True
                break
    return selected, truncated


def diagnostic_content(value: Mapping[str, object]) -> dict[str, object]:
    """Return only explicit, agent-evaluable diagnostic conclusions."""

    return _diagnostic_content_with_flags(value)[0]


def diagnostic_content_evaluable(value: Mapping[str, object]) -> bool:
    return bool(diagnostic_content(value))


def _tool_status(value: object) -> str:
    tool = _mapping(value)
    if not tool:
        return "not_checked"
    if tool.get("ok") is True:
        result = _mapping(tool.get("result"))
        if not result:
            result = _mapping(_mapping(tool.get("payload")).get("result"))
        return "available" if result else "not_checked"
    return (
        "not_checked"
        if str(tool.get("code", "")).strip().lower()
        in {"", "skipped", "not_checked"}
        else "unavailable"
    )


def _content_flags(value: object) -> tuple[bool, list[bool]]:
    truncated = False
    completeness: list[bool] = []
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, Mapping):
            for key, item in current.items():
                name = str(key).lower()
                if (
                    name.endswith("truncated")
                    and name not in _DIAGNOSTIC_PROJECTION_TRUNCATION_FIELDS
                    and item is True
                ):
                    truncated = True
                if name == "content_complete" and isinstance(item, bool):
                    completeness.append(item)
                pending.append(item)
        elif isinstance(current, Sequence) and not isinstance(
            current, (str, bytes, bytearray)
        ):
            pending.extend(current)
    return truncated, completeness


def _diagnostic_result_content_complete(item: Mapping[str, object]) -> bool:
    source_truncated, completeness = _content_flags(item.get("value"))
    if source_truncated:
        return False
    if completeness:
        return all(completeness)
    return str(item.get("kind", "")) in _DIAGNOSTIC_SUMMARY_COMPLETE_KINDS


def _tool_result(
    *,
    result_id: str,
    kind: str,
    request: str,
    tool: object,
    evidence_ids: list[str],
) -> dict[str, object]:
    child = _mapping(tool)
    item: dict[str, object] = {
        "result_id": result_id,
        "kind": kind,
        "request": _bounded_text(request, 1024),
        "status": _tool_status(child),
        "evidence_ids": evidence_ids,
    }
    if child:
        payload = _mapping(child.get("payload"))
        item["observed_at"] = _bounded_text(
            child.get("observed_at")
            or payload.get("observed_at")
            or child.get("completed_at"),
            128,
        )
        result = child.get("result")
        if not isinstance(result, Mapping):
            result = payload.get("result")
        if isinstance(result, Mapping):
            projection_truncated = [False]
            bounded_result = _bounded_public(
                result,
                truncated=projection_truncated,
            )
            if (
                isinstance(bounded_result, Mapping)
                and diagnostic_result_value_evaluable(bounded_result)
            ):
                item["value"] = bounded_result
            elif item["status"] == "available":
                item["status"] = "not_checked"
                item["gap"] = (
                    "result_not_evaluable"
                    if bounded_result
                    else "result_not_visible_after_redaction"
                )
            if projection_truncated[0]:
                item["projection_truncated"] = True
        error = _bounded_text(child.get("error") or payload.get("error"), 256)
        if error:
            item["gap"] = error
        elif (
            item["status"] == "not_checked"
            and child.get("ok") is True
            and "gap" not in item
        ):
            item["gap"] = "result_not_visible"
    elif item["status"] == "not_checked":
        item["gap"] = "result_not_visible"
    return item


def _plain_result(
    *,
    result_id: str,
    kind: str,
    request: str,
    value: object,
    observed_at: object,
    evidence_ids: list[str],
) -> dict[str, object]:
    selected = _mapping(value)
    projection_truncated = [False]
    bounded = _bounded_public(selected, truncated=projection_truncated)
    visible = (
        isinstance(bounded, Mapping)
        and diagnostic_result_value_evaluable(bounded)
    )
    return {
        "result_id": result_id,
        "kind": kind,
        "request": _bounded_text(request, 1024),
        "status": "available" if visible else "not_checked",
        "observed_at": _bounded_text(observed_at, 128),
        **({"value": bounded} if visible else {}),
        **(
            {"projection_truncated": True}
            if projection_truncated[0]
            else {}
        ),
        **(
            {
                "gap": (
                    "result_not_evaluable"
                    if bounded
                    else "result_not_visible_after_redaction"
                    if selected
                    else "result_not_visible"
                )
            }
            if not visible
            else {}
        ),
        "evidence_ids": evidence_ids,
    }


def _aggregate_tool_result(
    *,
    result_id: str,
    kind: str,
    request: str,
    tools: Mapping[str, object],
    evidence_ids: list[str],
) -> dict[str, object]:
    children = [(name, _mapping(tool)) for name, tool in tools.items()]
    statuses: list[str] = []
    values: dict[str, object] = {}
    projection_truncated = [False]
    observed_at = ""
    gaps: list[str] = []
    for name, child in children:
        child_status = _tool_status(child)
        payload = _mapping(child.get("payload"))
        result = child.get("result")
        if not isinstance(result, Mapping):
            result = payload.get("result")
        if isinstance(result, Mapping) and result:
            bounded_result = _bounded_public(
                result,
                truncated=projection_truncated,
            )
            if (
                isinstance(bounded_result, Mapping)
                and diagnostic_result_value_evaluable(bounded_result)
            ):
                values[name] = bounded_result
            elif child_status == "available":
                child_status = "not_checked"
                gaps.append(
                    f"{name}: "
                    + (
                        "result_not_evaluable"
                        if bounded_result
                        else "result_not_visible_after_redaction"
                    )
                )
        statuses.append(child_status)
        observed_at = observed_at or _bounded_text(
            child.get("observed_at")
            or payload.get("observed_at")
            or child.get("completed_at"),
            128,
        )
        error = _bounded_text(child.get("error") or payload.get("error"), 128)
        if error:
            gaps.append(error)
    status = (
        "available"
        if statuses and all(item == "available" for item in statuses)
        else "unavailable"
        if any(item == "unavailable" for item in statuses)
        else "not_checked"
    )
    item: dict[str, object] = {
        "result_id": result_id,
        "kind": kind,
        "request": _bounded_text(request, 1024),
        "status": status,
        "observed_at": observed_at,
        "evidence_ids": evidence_ids,
    }
    if values:
        item["value"] = values
    if projection_truncated[0]:
        item["projection_truncated"] = True
    if status != "available":
        item["gap"] = "; ".join(gaps[:4]) or "result_not_visible"
    return item


def _correlation_result(
    *,
    value: object,
    observed_at: object,
    evidence_ids: list[str],
) -> dict[str, object]:
    selected = _mapping(value)
    source_search = _mapping(selected.get("source_search"))
    code = str(source_search.get("code", "")).strip().lower()
    error = _bounded_text(source_search.get("error"), 192)
    if code == "skipped":
        return {
            "result_id": "correlation",
            "kind": "diagnostic-correlation",
            "request": "bounded alarm/log/source correlation",
            "status": "not_checked",
            "observed_at": _bounded_text(observed_at, 128),
            "gap": error or "source_correlation_skipped",
            "evidence_ids": evidence_ids,
        }
    if source_search and source_search.get("ok") is False:
        return {
            "result_id": "correlation",
            "kind": "diagnostic-correlation",
            "request": "bounded alarm/log/source correlation",
            "status": "unavailable",
            "observed_at": _bounded_text(observed_at, 128),
            "gap": error or code or "source_correlation_unavailable",
            "evidence_ids": evidence_ids,
        }
    return _plain_result(
        result_id="correlation",
        kind="diagnostic-correlation",
        request="bounded alarm/log/source correlation",
        value=selected,
        observed_at=observed_at,
        evidence_ids=evidence_ids,
    )


def _diagnostic_request(
    value: Mapping[str, object],
    arguments: Mapping[str, object],
) -> dict[str, object]:
    runtime_request = {
        name: arguments[name]
        for name in _DIAGNOSTIC_REQUEST_FIELDS
        if name in arguments
    }
    return runtime_request or dict(_mapping(value.get("request")))


def _expected_comparison_scope(
    arguments: Mapping[str, object],
) -> tuple[tuple[Mapping[str, object], ...], tuple[tuple[str, str], ...]]:
    raw_targets = arguments.get("targets", [])
    targets = tuple(
        _mapping(target)
        for target in (
            raw_targets
            if isinstance(raw_targets, Sequence)
            and not isinstance(raw_targets, (str, bytes, bytearray))
            else ()
        )
        if isinstance(target, Mapping)
    )
    identities = comparison_target_identities(targets) if targets else ()
    return targets, identities


def _diagnostic_scope_limit_result(
    evidence_ids: list[str],
) -> list[dict[str, object]]:
    return [
        {
            "result_id": "diagnostic-scope",
            "kind": "diagnostic-scope",
            "request": "Runtime-owned diagnostic result identities",
            "status": "not_checked",
            "gap": "runtime_diagnostic_scope_exceeds_1024_result_identities",
            "evidence_ids": evidence_ids,
        }
    ]


def _structured_results(
    value: Mapping[str, object],
    evidence_ids: list[str],
    arguments: Mapping[str, object],
) -> list[dict[str, object]]:
    request = _diagnostic_request(value, arguments)
    plan = DiagnosticRequestPlan.from_mapping(request)
    if plan.result_count > DIAGNOSTIC_RECEIPT_MAX_STORED_RESULTS:
        return _diagnostic_scope_limit_result(evidence_ids)
    runtime_result = _mapping(value.get("result"))
    lanes = _mapping(runtime_result.get("lanes"))
    ssh = _mapping(lanes.get("ssh"))
    telnet = _mapping(lanes.get("telnet"))
    files = _mapping(telnet.get("files"))
    results: list[dict[str, object]] = []
    from .systemd_contract import systemd_unit_summaries
    for selector_id, child in _mapping(runtime_result.get("systemd")).items():
        child = _mapping(child)
        results.append({
            "result_id": "systemd-" + str(selector_id), "kind": "systemd",
            "request": ", ".join(str(name) for name in child.get("requested", [])),
            "status": "available" if child.get("complete") is True else "unavailable",
            "value": {"boot_id": child.get("boot_id"), "gaps": child.get("gaps", []),
                "units": systemd_unit_summaries(child)},
            "observed_at": child.get("completed_at") or value.get("observed_at"),
            "evidence_ids": evidence_ids,
        })
    result_id_counts: dict[str, int] = {}
    for index, path in enumerate(plan.files, start=1):
        base_result_id, kind = {
            "/etc/version.json": ("version", "target-version"),
            "/proc/uptime": ("uptime", "target-uptime"),
        }.get(path, (f"file-{index}", "target-file"))
        occurrence = result_id_counts.get(base_result_id, 0) + 1
        result_id_counts[base_result_id] = occurrence
        result_id = (
            base_result_id
            if occurrence == 1
            else f"{base_result_id}-{occurrence}"
        )
        results.append(
            _tool_result(
                result_id=result_id,
                kind=kind,
                request=path,
                tool=files.get(path),
                evidence_ids=evidence_ids,
            )
        )
    if plan.include_target_clock:
        freshness = _mapping(runtime_result.get("freshness")) or _mapping(
            value.get("freshness")
        )
        raw_delta = _mapping(freshness.get("bmc_time_delta"))
        target_clock = {
            name: raw_delta[name]
            for name in (
                "before",
                "after",
                "elapsed_seconds",
                "comparable",
                "clock_moved_backwards",
            )
            if name in raw_delta
        }
        if raw_delta:
            results.append(
                _plain_result(
                    result_id="target-clock",
                    kind="target-clock",
                    request="BMC clock movement during diagnosis",
                    value=target_clock,
                    observed_at=(
                        value.get("observed_at")
                        or runtime_result.get("completed_at")
                    ),
                    evidence_ids=evidence_ids,
                )
            )
        else:
            results.append(
                {
                    "result_id": "target-clock",
                    "kind": "target-clock",
                    "request": "BMC clock movement during diagnosis",
                    "status": "not_checked",
                    "observed_at": _bounded_text(
                        value.get("observed_at")
                        or runtime_result.get("completed_at"),
                        128,
                    ),
                    "gap": "target_clock_not_returned",
                    "evidence_ids": evidence_ids,
                }
            )
    if plan.logs:
        results.append(
            _tool_result(
                result_id="logs",
                kind="bounded-logs",
                request=plan.logs,
                tool=telnet.get("logs"),
                evidence_ids=evidence_ids,
            )
        )
    if plan.tree_requested:
        results.append(
            _tool_result(
                result_id="service",
                kind="service-tree" if plan.tree_service else "service-list",
                request=plan.tree_service or "bounded service list",
                tool=ssh.get("busctl"),
                evidence_ids=evidence_ids,
            )
        )
    for index, query in enumerate(plan.mdb_queries, start=1):
        name = "mdbctl" if index == 1 else f"mdbctl_{index}"
        results.append(
            _tool_result(
                result_id=f"mdb-{index}",
                kind="mdb",
                request=query,
                tool=ssh.get(name),
                evidence_ids=evidence_ids,
            )
        )
    for index, class_name in enumerate(plan.mdb_expand_classes, start=1):
        prefix = f"mdbctl_expand_{index}"
        results.append(
            _aggregate_tool_result(
                result_id=f"mdb-expand-{index}",
                kind="mdb-class-expansion",
                request=class_name,
                tools={
                    name: child
                    for name, child in ssh.items()
                    if name == prefix or name.startswith(prefix + "_")
                },
                evidence_ids=evidence_ids,
            )
        )
    if plan.active_alarms_requested:
        results.append(
            _tool_result(
                result_id="active-alarms",
                kind="active-alarms",
                request=plan.alarm_service or "active alarms",
                tool=ssh.get("active_alarms"),
                evidence_ids=evidence_ids,
            )
        )
    if plan.source_correlation_requested:
        results.append(
            _correlation_result(
                value=runtime_result.get("correlation"),
                observed_at=value.get("observed_at")
                or runtime_result.get("completed_at"),
                evidence_ids=evidence_ids,
            )
        )
    return results


def _comparison_results(
    value: Mapping[str, object],
    evidence_ids: list[str],
    arguments: Mapping[str, object],
) -> list[dict[str, object]]:
    raw_targets = value.get("targets", [])
    if not isinstance(raw_targets, Sequence) or isinstance(
        raw_targets, (str, bytes, bytearray)
    ):
        raw_targets = []
    common_arguments = {
        name: item for name, item in arguments.items() if name != "targets"
    }
    returned_targets = [
        _mapping(raw_target)
        for raw_target in raw_targets
        if isinstance(raw_target, Mapping)
    ]
    try:
        expected_targets, expected_identities = _expected_comparison_scope(arguments)
    except ValueError as exc:
        return [
            {
                "result_id": "target-scope",
                "kind": "diagnostic-target-scope",
                "request": "Runtime-owned multi-target scope",
                "status": "not_checked",
                "gap": _bounded_text(exc, 192),
                "evidence_ids": evidence_ids,
            }
        ]
    if returned_targets and not expected_targets:
        return [
            {
                "result_id": "target-scope",
                "kind": "diagnostic-target-scope",
                "request": "Runtime-owned multi-target scope",
                "status": "not_checked",
                "gap": "runtime_target_scope_not_visible",
                "evidence_ids": evidence_ids,
            }
        ]
    targets_by_identity: dict[str, list[Mapping[str, object]]] = {}
    for target in returned_targets:
        target_id = str(target.get("target_id", "")).strip()
        if not target_id:
            continue
        targets_by_identity.setdefault(
            target_id, []
        ).append(target)

    results: list[dict[str, object]] = []
    for index, (expected_target, (_role, identity)) in enumerate(
        zip(expected_targets, expected_identities, strict=True),
        start=1,
    ):
        matching_targets = targets_by_identity.get(identity, [])
        target = matching_targets.pop(0) if matching_targets else {}
        child = _mapping(target.get("result"))
        target_arguments = dict(common_arguments)
        target_arguments.update(expected_target)
        child_results = _structured_results(
            child,
            evidence_ids,
            target_arguments,
        )
        if (
            len(results) + len(child_results) + 1
            > DIAGNOSTIC_RECEIPT_MAX_STORED_RESULTS
        ):
            return _diagnostic_scope_limit_result(evidence_ids)
        for child_result in child_results:
            projected = dict(child_result)
            projected["result_id"] = (
                f"target-{index}-{child_result.get('result_id', 'diagnosis')}"
            )
            projected["request"] = _bounded_text(
                f"target-{index}: {child_result.get('request', '')}",
                1024,
            )
            results.append(projected)
        if not child_results:
            target_status = str(target.get("status", "")).strip().lower()
            results.append(
                {
                    "result_id": f"target-{index}-diagnosis",
                    "kind": "target-diagnosis",
                    "request": f"target-{index} bounded diagnosis",
                    "status": (
                        "unavailable" if target_status == "failed" else "not_checked"
                    ),
                    "gap": _bounded_text(
                        target.get("error") or "result_not_visible",
                        192,
                    ),
                    "evidence_ids": evidence_ids,
                }
            )
    comparison = _mapping(value.get("comparison"))
    if comparison:
        if not expected_targets:
            return [{
                "result_id": "target-scope",
                "kind": "diagnostic-target-scope",
                "request": "Runtime-owned multi-target scope",
                "status": "not_checked",
                "gap": "runtime_target_scope_not_visible",
                "evidence_ids": evidence_ids,
            }]
        comparison_receipt = build_comparison_receipt(
            value,
            arguments,
            evidence_ids,
            source_results_complete=bool(results) and all(
                item.get("status") == "available"
                and _diagnostic_result_content_complete(item)
                for item in results
            ),
        )
        comparison_value = comparison_receipt.to_public_dict()
        comparison_value["content_complete"] = comparison_receipt.status == "complete"
        result = _plain_result(
            result_id="comparison",
            kind="diagnostic-comparison",
            request="bounded multi-target comparison",
            value=comparison_value,
            observed_at=value.get("observed_at"),
            evidence_ids=evidence_ids,
        )
        if comparison_receipt.status != "complete":
            result["status"] = "unavailable"
            result["gap"] = f"comparison_{comparison_receipt.status}"
        results.append(result)
    elif len(expected_targets) >= 2:
        results.append(
            {
                "result_id": "comparison",
                "kind": "diagnostic-comparison",
                "request": "bounded multi-target comparison",
                "status": "not_checked",
                "gap": "comparison_not_visible",
                "evidence_ids": evidence_ids,
            }
        )
    return results


def _target_results(value: Mapping[str, object]) -> list[Mapping[str, object]]:
    raw_targets = value.get("targets", [])
    if not isinstance(raw_targets, Sequence) or isinstance(
        raw_targets, (str, bytes, bytearray)
    ):
        return []
    return [
        _mapping(_mapping(target).get("result"))
        for target in raw_targets
        if isinstance(target, Mapping)
    ]


def _diagnostic_freshness(
    value: Mapping[str, object],
    arguments: Mapping[str, object],
) -> Mapping[str, object]:
    runtime_result = _mapping(value.get("result"))
    try:
        expected_targets, expected_identities = _expected_comparison_scope(arguments)
    except ValueError:
        return {"status": "unknown"}
    raw_targets = value.get("targets", [])
    returned_targets = (
        [_mapping(target) for target in raw_targets if isinstance(target, Mapping)]
        if isinstance(raw_targets, Sequence)
        and not isinstance(raw_targets, (str, bytes, bytearray))
        else []
    )
    unavailable_dimensions: list[object] = []
    lost_dimensions: list[object] = []
    stale_evidence: list[object] = []
    if expected_targets:
        by_id = {
            str(target.get("target_id", "")).strip(): target
            for target in returned_targets
            if str(target.get("target_id", "")).strip()
        }
        target_freshness: list[Mapping[str, object]] = []
        for _role, target_id in expected_identities:
            freshness = _mapping(
                _mapping(
                    _mapping(
                        _mapping(by_id.get(target_id, {})).get("result")
                    ).get("result")
                ).get("freshness")
            )
            target_freshness.append(freshness)
            target_status = str(
                freshness.get("status") or "unknown"
            ).strip().lower()
            if not freshness or target_status in {"unknown", "unavailable"}:
                unavailable_dimensions.append(
                    {"target_id": target_id, "dimension": "freshness"}
                )
            elif freshness.get("complete") is False:
                unavailable_dimensions.append(
                    {
                        "target_id": target_id,
                        "dimension": "freshness",
                        "reason": "incomplete",
                    }
                )
            for name, selected in (
                ("unavailable_dimensions", unavailable_dimensions),
                ("lost_dimensions", lost_dimensions),
                ("stale_evidence", stale_evidence),
            ):
                raw_items = freshness.get(name, [])
                if not isinstance(raw_items, Sequence) or isinstance(
                    raw_items, (str, bytes, bytearray)
                ):
                    continue
                for item in raw_items:
                    scoped = (
                        dict(item)
                        if isinstance(item, Mapping)
                        else {"detail": item}
                    )
                    scoped.setdefault("target_id", target_id)
                    selected.append(scoped)
            if target_status == "stale" and not freshness.get("stale_evidence"):
                stale_evidence.append(
                    {"target_id": target_id, "reason": "freshness_status_stale"}
                )
    else:
        raw = _mapping(runtime_result.get("freshness")) or _mapping(
            value.get("freshness")
        )
        if raw:
            return raw
        target_freshness = [
            _mapping(_mapping(target.get("result")).get("freshness"))
            for target in _target_results(value)
        ]
    statuses = [
        str(_mapping(item).get("status") or "unknown").strip().lower()
        for item in target_freshness
    ]
    if not statuses:
        return {}
    if stale_evidence:
        status = "stale"
    elif all(item in {"fresh", "complete"} for item in statuses) and not (
        unavailable_dimensions or lost_dimensions
    ):
        status = "fresh"
    elif any(item in {"fresh", "complete", "partial"} for item in statuses) or (
        unavailable_dimensions or lost_dimensions
    ):
        status = "partial"
    else:
        status = "unknown"
    return {
        "status": status,
        **(
            {"complete": status == "fresh"}
            if expected_targets
            else {}
        ),
        **(
            {"unavailable_dimensions": unavailable_dimensions}
            if unavailable_dimensions
            else {}
        ),
        **(
            {"lost_dimensions": lost_dimensions}
            if lost_dimensions
            else {}
        ),
        **(
            {"stale_evidence": stale_evidence}
            if stale_evidence
            else {}
        ),
    }


def _normalized_diagnostic_freshness(
    value: Mapping[str, object],
) -> dict[str, object]:
    normalized = dict(value)
    status = _bounded_text(value.get("status"), 32).lower() or "unknown"
    unavailable_dimensions = tuple(
        value.get("unavailable_dimensions", [])
        if isinstance(value.get("unavailable_dimensions"), Sequence)
        and not isinstance(
            value.get("unavailable_dimensions"), (str, bytes, bytearray)
        )
        else ()
    )
    lost_dimensions = tuple(
        value.get("lost_dimensions", [])
        if isinstance(value.get("lost_dimensions"), Sequence)
        and not isinstance(value.get("lost_dimensions"), (str, bytes, bytearray))
        else ()
    )
    stale_evidence = tuple(
        value.get("stale_evidence", [])
        if isinstance(value.get("stale_evidence"), Sequence)
        and not isinstance(value.get("stale_evidence"), (str, bytes, bytearray))
        else ()
    )
    if stale_evidence:
        status = "stale"
    elif (
        status in {"complete", "fresh"}
        and (
            unavailable_dimensions
            or lost_dimensions
            or value.get("complete") is False
        )
    ):
        status = "partial"
    normalized["status"] = status
    if (
        "complete" in value
        or unavailable_dimensions
        or lost_dimensions
        or stale_evidence
    ):
        normalized["complete"] = (
            status in {"complete", "fresh"}
            and not unavailable_dimensions
            and not lost_dimensions
            and not stale_evidence
            and value.get("complete") is not False
        )
    return normalized


def _diagnostic_capabilities(value: Mapping[str, object]) -> Mapping[str, object]:
    runtime_result = _mapping(value.get("result"))
    raw = _mapping(runtime_result.get("capabilities"))
    if raw:
        return raw
    target_capabilities = [
        _mapping(_mapping(target.get("result")).get("capabilities"))
        for target in _target_results(value)
    ]
    names = {
        str(name)
        for capabilities in target_capabilities
        for name in capabilities
    }
    aggregate: dict[str, object] = {}
    for name in names:
        states = [capabilities.get(name) for capabilities in target_capabilities]
        aggregate[name] = (
            True
            if states and all(state is True for state in states)
            else False
            if any(state is False for state in states)
            else None
        )
    return aggregate


def _advice_pointer(document: object, pointer: object) -> object:
    if (not isinstance(pointer, str) or not pointer.startswith("/") or len(pointer) > 512
            or pointer.count("/") > 16 or re.search(r"~(?![01])", pointer)):
        raise ValueError("invalid advice pointer")
    current = document
    for segment in pointer[1:].split("/"):
        segment = segment.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", segment):
                raise ValueError("invalid advice array index")
            current = current[int(segment)]
        elif isinstance(current, Mapping):
            current = current[segment]
        else:
            raise ValueError("advice pointer does not resolve")
    return current


def _stored_diagnostic_advice(raw: object, evidence: object) -> dict[str, object] | None:
    """Read optional advisory metadata independently of diagnostic truth/coverage."""
    if not isinstance(raw, Mapping) or raw.get("schema") != _ADVICE_SCHEMA:
        return None
    try:
        if (len(json.dumps(raw, ensure_ascii=False, allow_nan=False).encode()) > _ADVICE_MAX_BYTES
                or raw.get("status") != "advisory" or raw.get("rule_version") != 1
                or set(raw) - {"schema", "rule_version", "status", "target", "device", "snapshot", "facts",
                               "hypotheses", "next_observations", "fault_chain", "source_bindings"}):
            return None
        facts, hypotheses, proposed = raw["facts"], raw["hypotheses"], raw["next_observations"]
        if (not isinstance(facts, list) or len(facts) > 24 or not isinstance(hypotheses, list)
                or len(hypotheses) != 3 or not isinstance(proposed, list) or len(proposed) > 1):
            return None
        evidence_ids = {item.get("evidence_id") for item in evidence if isinstance(item, Mapping)}
        if not evidence_ids:
            return None
        refs = []
        for fact in facts:
            reference = fact["evidence_ref"]
            if (fact.get("stage") not in _ADVICE_STAGES or fact.get("status") not in {"observed", "unknown"}
                    or not isinstance(reference, Mapping)
                    or not isinstance(reference.get("evidence_ids"), list)
                    or not reference["evidence_ids"] or not set(reference["evidence_ids"]) <= evidence_ids
                    or (type(fact.get("present")) is not bool if fact["status"] == "observed" else fact.get("present") is not None)):
                return None
            refs.append(reference)
        patterns = {
            "hardware_not_discovered": (False, False, False),
            "mdb_not_created": (True, False, False),
            "northbound_not_published": (True, True, False),
        }
        if {candidate.get("id") for candidate in hypotheses} != set(patterns):
            return None
        selected = {fact["stage"]: fact for fact in facts if fact["target"] == raw["target"]}
        for candidate in hypotheses:
            supporting, contradicting = [], []
            for stage, expected in zip(_ADVICE_STAGES, patterns[candidate["id"]]):
                fact = selected.get(stage, {})
                if fact.get("status") == "observed":
                    destination = supporting if fact["present"] is expected else contradicting
                    destination.append(fact["evidence_ref"])
            status = "contradicted" if contradicting else "fulfilled" if len(supporting) == 3 else "unknown"
            if (candidate.get("status") != status or candidate.get("supporting_refs") != supporting
                    or candidate.get("contradicting_refs") != contradicting):
                return None
        from .semantic_runtime import ObservationQuery
        for suggestion in proposed:
            if suggestion.get("stage") not in _ADVICE_STAGES or suggestion["query"].get("target") != raw["target"]:
                return None
            ObservationQuery.from_query(suggestion["query"])
            stage = suggestion["stage"]
            if selected.get(stage, {}).get("status") == "observed":
                return None
            index = _ADVICE_STAGES.index(stage)
            remaining = {item["id"] for item in hypotheses if item["status"] != "contradicted"}
            expected = {
                "present": [name for name, values in patterns.items() if name in remaining and values[index]],
                "absent": [name for name, values in patterns.items() if name in remaining and not values[index]],
            }
            if not all(expected.values()) or suggestion.get("expected_outcomes") != expected:
                return None
        projected = copy.deepcopy(dict(raw))
        # ComparisonReceipt owns comparison provenance. The helper's standalone
        # chain is not persisted as Runtime advice without that separate binding.
        projected.pop("fault_chain", None)
        return projected
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return None


def _advice_source_current(source: Mapping[str, object], reference: Mapping[str, object],
                           at: datetime, max_age: int) -> bool:
    body = _mapping(source.get("raw")) if source.get("schema") == f"{RUNTIME_API_VERSION}/observation-source-v1" else source
    freshness = _mapping(_mapping(body.get("result")).get("freshness", body.get("freshness")))
    observed = source.get("observed_at") or freshness.get("observed_at")
    if observed != reference.get("observed_at") or not isinstance(observed, str):
        return False
    observed_at = datetime.fromisoformat(observed.replace("Z", "+00:00"))
    if (observed_at.tzinfo is None or not 0 <= (at - observed_at).total_seconds() <= max_age
            or not (body.get("ok") is True or body.get("status") == "complete")
            or freshness.get("status") not in {"fresh", "live", "complete"}
            or freshness.get("complete", True) is not True
            or any(freshness.get(name) for name in ("stale_evidence", "lost_dimensions", "unavailable_dimensions"))):
        return False
    if "valid_until" in freshness:
        expires = datetime.fromisoformat(str(freshness["valid_until"]).replace("Z", "+00:00"))
        if expires.tzinfo is None or at >= expires:
            return False
    if body is not source and (source.get("reusable") is not True
                               or type(source.get("fresh_until")) not in {int, float}
                               or at.timestamp() >= source["fresh_until"]):
        return False
    for pointer in (reference["device_pointer"] + "/_", reference["value_pointer"]):
        tokens = pointer[1:].split("/")
        ancestors = [source, *(_advice_pointer(source, "/" + "/".join(tokens[:length]))
                              for length in range(1, len(tokens)))]
        for node in ancestors:
            if isinstance(node, Mapping) and (
                node.get("ok", True) is not True or node.get("content_complete", True) is not True
                or node.get("status") in {"partial", "stale", "unavailable", "not_checked", "failed", "unknown"}
                or any(item is not False for key, item in node.items() if key.endswith("truncated"))
            ):
                return False
    return True


def _project_diagnostic_advice(
    capture: Mapping[str, object], raw: object, evidence: Sequence[Mapping[str, object]],
) -> dict[str, object] | None:
    """Bind helper source pointers to the actual operation payload before persistence."""
    if not isinstance(raw, Mapping):
        return None
    try:
        if len(json.dumps(raw, ensure_ascii=False, allow_nan=False).encode()) > _ADVICE_MAX_BYTES:
            return None
        advice = copy.deepcopy(dict(raw))
        bindings = advice["source_bindings"]
        if not isinstance(bindings, list) or not 1 <= len(bindings) <= 8:
            return None
        sources = {}
        for binding in bindings:
            pointer = binding["source_pointer"]
            if pointer != "" and not re.fullmatch(r"(?:/result)?/targets/(?:0|[1-9][0-9]*)/result", pointer):
                return None
            source = capture if pointer == "" else _advice_pointer(capture, pointer)
            if (not isinstance(source, Mapping) or "sha256:" + _fingerprint(source) != binding["source_digest"]
                    or binding["source_id"] in sources):
                return None
            sources[binding["source_id"]] = (binding, source)
        snapshot = advice["snapshot"]
        at = datetime.fromisoformat(snapshot["at"].replace("Z", "+00:00"))
        max_age = snapshot["max_age_seconds"]
        if (at.tzinfo is None or type(max_age) is not int or not 1 <= max_age <= 900
                or not 0 <= (datetime.now(timezone.utc) - at).total_seconds() <= max_age
                or snapshot.get("scope") != "captured_snapshot"):
            return None
        references = {}
        for fact in advice["facts"]:
            reference = fact["evidence_ref"]
            binding, source = sources[reference["source_id"]]
            if reference["source_digest"] != binding["source_digest"]:
                return None
            identity = _advice_pointer(source, reference["device_pointer"])
            observed = _advice_pointer(source, reference["value_pointer"])
            if not reference["value_pointer"].startswith(reference["device_pointer"] + "/"):
                return None
            if fact["target"] != (source.get("ip") or _mapping(source.get("scope")).get("target")):
                return None
            if fact["status"] == "observed":
                if not _advice_source_current(source, reference, at, max_age):
                    return None
                source_epoch = source.get("target_epoch")
                if "target_epoch" not in source:
                    targets = _mapping(_mapping(_mapping(source.get("result")).get("runtime")).get("status")).get("targets", [])
                    matched = [item for item in targets if isinstance(item, Mapping)
                               and _mapping(item.get("target")).get("host") == fact["target"]] if isinstance(targets, list) else []
                    source_epoch = _mapping(matched[0].get("epochs")).get("target_epoch") if len(matched) == 1 else None
                if (type(observed) is not bool or observed is not fact["present"]
                        or not isinstance(identity, Mapping)
                        or any(identity.get(key) != item for key, item in advice["device"].items())
                        or type(reference.get("target_epoch")) is not int or reference["target_epoch"] < 0
                        or reference.get("target_epoch") != source_epoch
                        or reference.get("target_epoch") != snapshot["target_epochs"].get(fact["target"])):
                    return None
            references[_fingerprint(reference)] = {
                **reference, "source_pointer": binding["source_pointer"],
                "evidence_ids": [item["evidence_id"] for item in evidence if item.get("evidence_id")],
            }
        def bind(value: object) -> object:
            if isinstance(value, Mapping):
                if "source_id" in value and "device_pointer" in value:
                    return copy.deepcopy(references[_fingerprint(value)])
                return {key: bind(item) for key, item in value.items()}
            if isinstance(value, list):
                return [bind(item) for item in value]
            return value
        return _stored_diagnostic_advice(bind(advice), evidence)
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError):
        return None


def build_diagnostic_receipt(
    operation: str,
    value: Mapping[str, object],
    arguments: Mapping[str, object],
    evidence_refs: Sequence[Mapping[str, object]],
    *,
    closeout_stage: str,
) -> DiagnosticReceipt | None:
    """Form one durable typed diagnosis result without embedding raw Evidence."""

    if closeout_stage not in {"diagnosis", "verification"}:
        return None
    if closeout_stage == "verification" and not any(
        name in arguments for name in _DIAGNOSTIC_REQUEST_FIELDS
    ):
        return None
    raw_advice = value.get("diagnostic_advice")
    # Advisory metadata must not affect evidence completeness or comparison authority.
    value = {key: item for key, item in value.items() if key != "diagnostic_advice"}
    reference_ids = [
        _bounded_text(reference.get("evidence_id"), 128)
        for reference in evidence_refs[:8]
        if _bounded_text(reference.get("evidence_id"), 128)
    ]
    request = _diagnostic_request(value, arguments)
    raw_targets = arguments.get("targets", [])
    target_count = (
        len(raw_targets)
        if isinstance(raw_targets, Sequence)
        and not isinstance(raw_targets, (str, bytes, bytearray))
        and raw_targets
        else 1
    )
    requested_result_count = DiagnosticRequestPlan.from_mapping(
        request
    ).total_result_count(target_count=target_count)
    if requested_result_count > DIAGNOSTIC_RECEIPT_MAX_STORED_RESULTS:
        results = _diagnostic_scope_limit_result(reference_ids)
    else:
        results = _comparison_results(value, reference_ids, arguments)
        if not results:
            results = _structured_results(value, reference_ids, arguments)
    diagnosis, diagnosis_truncated = _diagnostic_content_with_flags(value)
    source_truncated, source_completeness = _content_flags(value)
    diagnosis_content_complete = (
        not diagnosis_truncated
        and not source_truncated
        and (not source_completeness or all(source_completeness))
    )
    if not results:
        results = (
            [
                {
                    "result_id": "diagnosis",
                    "kind": "diagnosis",
                    "request": "bounded diagnosis",
                    "status": "available",
                    "value": {
                        **diagnosis,
                        "truncated": source_truncated,
                        "content_complete": diagnosis_content_complete,
                    },
                    **(
                        {"projection_truncated": True}
                        if diagnosis_truncated
                        else {}
                    ),
                    "evidence_ids": reference_ids,
                }
            ]
            if diagnosis
            else [
                {
                    "result_id": "diagnosis",
                    "kind": "diagnosis",
                    "request": "bounded diagnosis",
                    "status": "not_checked",
                    "evidence_ids": reference_ids,
                }
            ]
        )
    requested = len(results)
    evaluable = sum(item.get("status") == "available" for item in results)
    unavailable = sum(item.get("status") == "unavailable" for item in results)
    not_checked = sum(item.get("status") == "not_checked" for item in results)
    observed_at = _bounded_text(
        value.get("observed_at")
        or _mapping(value.get("result")).get("completed_at"),
        128,
    )
    references = [
        {
            key: _bounded_public(reference[key])
            for key in (
                "evidence_id",
                "target_id",
                "observed_at",
                "target_epoch",
                "byte_count",
            )
            if key in reference
        }
        for reference in evidence_refs[:8]
    ]
    truncated, _completeness = _content_flags(results)
    available_results_are_complete = all(
        _diagnostic_result_content_complete(item)
        for item in results
        if item.get("status") == "available"
    )
    raw_freshness = _normalized_diagnostic_freshness(
        _diagnostic_freshness(value, arguments)
    )
    freshness_status = (
        _bounded_text(raw_freshness.get("status"), 32) or "unknown"
    )
    content_complete = (
        evaluable == requested
        and unavailable == 0
        and not_checked == 0
        and not truncated
        and available_results_are_complete
    )
    coverage_complete = (
        content_complete
        and bool(observed_at)
        and freshness_status in {"complete", "fresh"}
    )
    gaps: list[str] = []
    if evaluable == 0:
        gaps.append("diagnostic_result_not_visible")
    if unavailable:
        gaps.append(f"{unavailable}_diagnostic_items_unavailable")
    if not_checked:
        gaps.append(f"{not_checked}_diagnostic_items_not_checked")
    if truncated:
        gaps.append("content_truncated")
    if not content_complete and evaluable:
        gaps.append("diagnostic_content_incomplete")
    if freshness_status not in {"complete", "fresh"}:
        gaps.append(f"freshness_{freshness_status}")
    elif not observed_at:
        gaps.append("freshness_observed_at_missing")
    raw_capabilities = _diagnostic_capabilities(value)
    capabilities = {
        name: (
            "not_checked"
            if runtime_name not in raw_capabilities
            or raw_capabilities.get(runtime_name) is None
            else "available"
            if raw_capabilities.get(runtime_name) is True
            else "unavailable"
        )
        for name, runtime_name in CAPABILITY_ALIASES.items()
    }
    receipt: dict[str, object] = {
        "schema": DIAGNOSTIC_RECEIPT_SCHEMA,
        "operation": operation,
        "status": (
            "blocked"
            if evaluable == 0
            else "complete"
            if coverage_complete
            else "partial"
        ),
        "coverage": {
            "requested": requested,
            "evaluable": evaluable,
            "unavailable": unavailable,
            "not_checked": not_checked,
            "complete": coverage_complete,
        },
        "results": results,
        "freshness": {
            "status": freshness_status,
            "observed_at": observed_at,
            **{
                name: _bounded_public(raw_freshness[name])
                for name in (
                    "complete",
                    "unavailable_dimensions",
                    "lost_dimensions",
                    "stale_evidence",
                )
                if name in raw_freshness
            },
        },
        "capabilities": capabilities,
        "truncated": truncated,
        "content_complete": content_complete,
        "evidence": references,
        "gaps": gaps,
    }
    receipt["receipt_id"] = "diagnostic-" + _fingerprint(
        {"arguments": _bounded_public(arguments), **receipt}
    )[:24]
    advice = _project_diagnostic_advice(value, raw_advice, references)
    if advice is not None:
        receipt["diagnostic_advice"] = advice
    return DiagnosticReceipt.from_public_dict(receipt).bounded_for_persistence()
