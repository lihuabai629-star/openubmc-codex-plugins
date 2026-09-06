"""Typed, Runtime-owned diagnosis acceptance records."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass


_VERIFICATION_STATUSES = frozenset({"verified", "partial", "unverified", "blocked"})


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"DiagnosisRecord {field} must be a non-empty string")
    return value.strip()


def _strings(value: object, field: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"DiagnosisRecord {field} must be an array of strings")
    values = tuple(_text(item, f"{field}[]") for item in value)
    if not allow_empty and not values:
        raise ValueError(f"DiagnosisRecord {field} must not be empty")
    if len(values) != len(set(values)):
        raise ValueError(f"DiagnosisRecord {field} must not contain duplicates")
    return values


@dataclass(frozen=True)
class DiagnosisRecord:
    """A human/domain conclusion distinct from diagnostic collection receipt."""

    root_cause: str
    evidence_ids: tuple[str, ...]
    causal_chain: tuple[str, ...]
    code_owner: str
    contradictions: tuple[str, ...]
    remaining_gaps: tuple[str, ...]
    verification_status: str
    record_id: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "DiagnosisRecord":
        record = cls(
            root_cause=_text(value.get("root_cause"), "root_cause"),
            evidence_ids=_strings(value.get("evidence_ids"), "evidence_ids"),
            causal_chain=_strings(value.get("causal_chain"), "causal_chain"),
            code_owner=_text(value.get("code_owner"), "code_owner"),
            contradictions=_strings(value.get("contradictions"), "contradictions", allow_empty=True),
            remaining_gaps=_strings(value.get("remaining_gaps"), "remaining_gaps", allow_empty=True),
            verification_status=_text(value.get("verification_status"), "verification_status").lower(),
            record_id=str(value.get("record_id", "")).strip(),
        )
        if record.verification_status not in _VERIFICATION_STATUSES:
            raise ValueError(
                "DiagnosisRecord verification_status must be one of "
                + ", ".join(sorted(_VERIFICATION_STATUSES))
            )
        if record.verification_status == "verified" and record.contradictions:
            raise ValueError("verified DiagnosisRecord cannot contain contradictions")
        return record

    @property
    def accepted(self) -> bool:
        return self.verification_status == "verified" and not self.contradictions

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": "openubmc.target-runtime.v1/diagnosis-record-v1",
            "record_id": self.record_id,
            "root_cause": self.root_cause,
            "evidence_ids": list(self.evidence_ids),
            "causal_chain": list(self.causal_chain),
            "code_owner": self.code_owner,
            "contradictions": list(self.contradictions),
            "remaining_gaps": list(self.remaining_gaps),
            "verification_status": self.verification_status,
        }


def parse_diagnosis_record(value: object) -> DiagnosisRecord:
    if not isinstance(value, Mapping):
        raise ValueError("DiagnosisRecord must be an object")
    return DiagnosisRecord.from_mapping(value)


def accepted_diagnosis_record(projection: Mapping[str, object]) -> DiagnosisRecord | None:
    """Read current native acceptance; historical receipts remain readable only."""
    cycle_id = str(projection.get("workflow_cycle_id") or "cycle-1")
    receipt_ids: set[str] = set()
    for collection_name in ("operations", "phase_records"):
        records = projection.get(collection_name, [])
        if isinstance(records, list):
            for record in records:
                if isinstance(record, Mapping) and str(record.get("workflow_cycle_id") or "cycle-1") == cycle_id:
                    receipt = record.get("diagnostic_receipt")
                    if isinstance(receipt, Mapping) and str(receipt.get("receipt_id", "")):
                        receipt_ids.add(str(receipt["receipt_id"]))
    for phase in reversed(list(projection.get("phase_records", []))):
        if not isinstance(phase, Mapping) or phase.get("phase_type") != "diagnosis.acceptance":
            continue
        if str(phase.get("workflow_cycle_id") or "cycle-1") != cycle_id:
            continue
        value = phase.get("diagnosis_record")
        if (
            phase.get("status") != "completed"
            or phase.get("native_run_fact") is not True
            or not isinstance(value, Mapping)
            or value.get("schema") != "openubmc.target-runtime.v1/diagnosis-record-v1"
            or value.get("run_id") != projection.get("case_id")
            or value.get("workflow_cycle_id") != cycle_id
            or value.get("target_version") != projection.get("target_version", 1)
            or not str(value.get("source_receipt_id", ""))
            or str(value.get("source_receipt_id")) not in receipt_ids
        ):
            return None
        try:
            record = parse_diagnosis_record(value)
        except ValueError:
            return None
        return record if record.accepted and record.record_id else None
    return None


def requires_diagnosis_record(projection: Mapping[str, object]) -> bool:
    intent = projection.get("intent")
    return intent in {"diagnose-and-fix", "bundle-and-diagnose"} or (
        intent == "diagnosis-only" and projection.get("entry_domain") != "log_analyzer"
    )


__all__ = [
    "DiagnosisRecord", "accepted_diagnosis_record", "parse_diagnosis_record",
    "requires_diagnosis_record",
]
