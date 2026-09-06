"""Reviewed Session Outcome feedback without executable-rule promotion."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
import time
from typing import Protocol

from .contracts import RUNTIME_API_VERSION
from .redaction import redact_text
from .replay import CaseReplayBundle, CaseReplayService, redact_replay_value


SESSION_OUTCOME_SCHEMA = f"{RUNTIME_API_VERSION}/session-outcome-v1"
SESSION_OUTCOME_SUMMARY_SCHEMA = f"{RUNTIME_API_VERSION}/session-outcome-summary-v1"
SESSION_OUTCOME_ARTIFACT_SCHEMA = f"{RUNTIME_API_VERSION}/session-outcome-artifact-v1"
SESSION_OUTCOME_LABELS = frozenset(
    {
        "completed",
        "partial",
        "failed",
        "user-corrected",
        "false-success",
        "evidence-gap",
        "contract-gap",
    }
)
PROMOTION_TARGETS = frozenset({"golden-scenario", "knowledge", "adr"})
REVIEW_STATES = frozenset({"recorded", "reviewed", "approved", "rejected", "promoted"})


class SessionOutcomeError(ValueError):
    """Raised when feedback governance invariants are violated."""


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _fingerprint(value: object) -> str:
    return "sha256:" + hashlib.sha256(_json_bytes(value)).hexdigest()


def _required_text(value: object, name: str) -> str:
    selected = str(value).strip()
    if not selected:
        raise SessionOutcomeError(f"{name} is required")
    return redact_text(selected)


@dataclass(frozen=True)
class SessionOutcomeRecord:
    outcome_id: str
    session_id: str
    case_id: str
    replay_fingerprint: str
    workflow: str
    domain: str
    outcome: str
    gap_type: str
    summary: str
    details: Mapping[str, object]
    architecture_decision: bool
    review_state: str
    reviewer: str
    approver: str
    promotion: Mapping[str, object] | None
    created_at: float
    updated_at: float

    def __post_init__(self) -> None:
        if self.outcome not in SESSION_OUTCOME_LABELS:
            raise SessionOutcomeError(f"unsupported Session Outcome: {self.outcome}")
        if self.review_state not in REVIEW_STATES:
            raise SessionOutcomeError(f"unsupported review state: {self.review_state}")
        if self.outcome in {"evidence-gap", "contract-gap"} and not self.gap_type:
            raise SessionOutcomeError(f"{self.outcome} requires gap_type")

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": SESSION_OUTCOME_SCHEMA,
            "outcome_id": self.outcome_id,
            "session_id": self.session_id,
            "case_id": self.case_id,
            "replay_fingerprint": self.replay_fingerprint,
            "workflow": self.workflow,
            "domain": self.domain,
            "outcome": self.outcome,
            "gap_type": self.gap_type,
            "summary": self.summary,
            "details": dict(self.details),
            "architecture_decision": self.architecture_decision,
            "review_state": self.review_state,
            "reviewer": self.reviewer,
            "approver": self.approver,
            "promotion": dict(self.promotion) if self.promotion is not None else None,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "redacted": True,
            "execution_rule_eligible": False,
        }

    @classmethod
    def from_public_dict(cls, value: Mapping[str, object]) -> "SessionOutcomeRecord":
        if value.get("schema") != SESSION_OUTCOME_SCHEMA:
            raise SessionOutcomeError("unsupported Session Outcome schema")
        details = value.get("details", {})
        promotion = value.get("promotion")
        if not isinstance(details, Mapping):
            raise SessionOutcomeError("Session Outcome details must be an object")
        if promotion is not None and not isinstance(promotion, Mapping):
            raise SessionOutcomeError("Session Outcome promotion must be an object")
        return cls(
            outcome_id=str(value.get("outcome_id", "")),
            session_id=str(value.get("session_id", "")),
            case_id=str(value.get("case_id", "")),
            replay_fingerprint=str(value.get("replay_fingerprint", "")),
            workflow=str(value.get("workflow", "")),
            domain=str(value.get("domain", "")),
            outcome=str(value.get("outcome", "")),
            gap_type=str(value.get("gap_type", "")),
            summary=str(value.get("summary", "")),
            details=dict(details),
            architecture_decision=bool(value.get("architecture_decision", False)),
            review_state=str(value.get("review_state", "")),
            reviewer=str(value.get("reviewer", "")),
            approver=str(value.get("approver", "")),
            promotion=dict(promotion) if isinstance(promotion, Mapping) else None,
            created_at=float(value.get("created_at", 0.0)),
            updated_at=float(value.get("updated_at", 0.0)),
        )


class SessionOutcomeRepository(Protocol):
    def get(self, outcome_id: str) -> SessionOutcomeRecord | None: ...

    def save(self, record: SessionOutcomeRecord) -> None: ...

    def list(self) -> tuple[SessionOutcomeRecord, ...]: ...

    def status(self) -> Mapping[str, object]: ...


class InMemorySessionOutcomeRepository:
    def __init__(self) -> None:
        self._records: dict[str, SessionOutcomeRecord] = {}
        self._lock = threading.RLock()

    def get(self, outcome_id: str) -> SessionOutcomeRecord | None:
        with self._lock:
            return self._records.get(outcome_id)

    def save(self, record: SessionOutcomeRecord) -> None:
        with self._lock:
            self._records[record.outcome_id] = record

    def list(self) -> tuple[SessionOutcomeRecord, ...]:
        with self._lock:
            return tuple(
                sorted(self._records.values(), key=lambda item: (item.created_at, item.outcome_id))
            )

    def status(self) -> Mapping[str, object]:
        with self._lock:
            return {"adapter": "memory", "outcome_count": len(self._records)}


class SQLiteSessionOutcomeRepository:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS session_outcomes ("
                "outcome_id TEXT PRIMARY KEY, document_json TEXT NOT NULL, "
                "created_at REAL NOT NULL, updated_at REAL NOT NULL)"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        return connection

    def get(self, outcome_id: str) -> SessionOutcomeRecord | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT document_json FROM session_outcomes WHERE outcome_id = ?",
                (outcome_id,),
            ).fetchone()
        return (
            SessionOutcomeRecord.from_public_dict(json.loads(row["document_json"]))
            if row is not None
            else None
        )

    def save(self, record: SessionOutcomeRecord) -> None:
        document = json.dumps(record.to_public_dict(), ensure_ascii=True, sort_keys=True)
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO session_outcomes "
                "(outcome_id, document_json, created_at, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(outcome_id) DO UPDATE SET "
                "document_json = excluded.document_json, updated_at = excluded.updated_at",
                (record.outcome_id, document, record.created_at, record.updated_at),
            )

    def list(self) -> tuple[SessionOutcomeRecord, ...]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT document_json FROM session_outcomes ORDER BY created_at, outcome_id"
            ).fetchall()
        return tuple(
            SessionOutcomeRecord.from_public_dict(json.loads(row["document_json"]))
            for row in rows
        )

    def status(self) -> Mapping[str, object]:
        with self._lock, self._connect() as connection:
            count = connection.execute(
                "SELECT COUNT(*) AS count FROM session_outcomes"
            ).fetchone()["count"]
        return {"adapter": "sqlite", "outcome_count": int(count)}


class SessionOutcomeService:
    """Record and promote reviewed feedback through one governance interface."""

    def __init__(
        self,
        repository: SessionOutcomeRepository,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.repository = repository
        self._clock = clock

    def record(
        self,
        *,
        session_id: str,
        case_id: str,
        replay_fingerprint: str,
        workflow: str,
        domain: str,
        outcome: str,
        summary: str,
        gap_type: str = "",
        details: Mapping[str, object] | None = None,
        architecture_decision: bool = False,
    ) -> SessionOutcomeRecord:
        label = str(outcome).strip().lower()
        if label not in SESSION_OUTCOME_LABELS:
            raise SessionOutcomeError(f"unsupported Session Outcome: {outcome}")
        public_details = redact_replay_value(dict(details or {}))
        assert isinstance(public_details, Mapping)
        identity = {
            "session_id": _required_text(session_id, "session_id"),
            "case_id": _required_text(case_id, "case_id"),
            "replay_fingerprint": _required_text(
                replay_fingerprint, "replay_fingerprint"
            ),
            "workflow": _required_text(workflow, "workflow"),
            "domain": _required_text(domain, "domain"),
            "outcome": label,
            "gap_type": redact_text(str(gap_type).strip()),
            "summary": _required_text(summary, "summary"),
            "details": dict(public_details),
            "architecture_decision": bool(architecture_decision),
        }
        outcome_id = "session-outcome-" + _fingerprint(identity).split(":", 1)[1][:24]
        existing = self.repository.get(outcome_id)
        if existing is not None:
            return existing
        now = self._clock()
        record = SessionOutcomeRecord(
            outcome_id=outcome_id,
            **identity,
            review_state="recorded",
            reviewer="",
            approver="",
            promotion=None,
            created_at=now,
            updated_at=now,
        )
        self.repository.save(record)
        return record

    def transition(
        self,
        outcome_id: str,
        *,
        action: str,
        actor: str,
    ) -> SessionOutcomeRecord:
        record = self.repository.get(_required_text(outcome_id, "outcome_id"))
        if record is None:
            raise SessionOutcomeError(f"unknown Session Outcome: {outcome_id}")
        selected_action = str(action).strip().lower()
        selected_actor = _required_text(actor, "actor")
        if selected_action == "review" and record.review_state == "recorded":
            updated = replace(
                record,
                review_state="reviewed",
                reviewer=selected_actor,
                updated_at=self._clock(),
            )
        elif selected_action == "approve" and record.review_state == "reviewed":
            if selected_actor == record.reviewer:
                raise SessionOutcomeError("approval requires an independent actor")
            updated = replace(
                record,
                review_state="approved",
                approver=selected_actor,
                updated_at=self._clock(),
            )
        elif selected_action == "reject" and record.review_state in {"recorded", "reviewed"}:
            updated = replace(
                record,
                review_state="rejected",
                reviewer=record.reviewer or selected_actor,
                updated_at=self._clock(),
            )
        else:
            raise SessionOutcomeError(
                f"cannot {selected_action or '<empty>'} Session Outcome in "
                f"{record.review_state} state"
            )
        self.repository.save(updated)
        return updated

    def summary(self) -> dict[str, object]:
        records = self.repository.list()
        counts = Counter(
            (item.workflow, item.domain, item.outcome, item.gap_type)
            for item in records
        )
        return {
            "schema": SESSION_OUTCOME_SUMMARY_SCHEMA,
            "total": len(records),
            "groups": [
                {
                    "workflow": key[0],
                    "domain": key[1],
                    "outcome": key[2],
                    "gap_type": key[3],
                    "count": count,
                }
                for key, count in sorted(counts.items())
            ],
            "review_states": dict(sorted(Counter(item.review_state for item in records).items())),
        }

    def promote(
        self,
        outcome_id: str,
        *,
        target: str,
        payload: Mapping[str, object],
    ) -> dict[str, object]:
        record = self.repository.get(_required_text(outcome_id, "outcome_id"))
        if record is None:
            raise SessionOutcomeError(f"unknown Session Outcome: {outcome_id}")
        if record.review_state != "approved":
            raise SessionOutcomeError("Session Outcome must be reviewed and approved")
        selected_target = str(target).strip().lower()
        if selected_target not in PROMOTION_TARGETS:
            raise SessionOutcomeError(f"unsupported promotion target: {target}")
        if record.architecture_decision and selected_target != "adr":
            raise SessionOutcomeError(
                "hard-to-reverse architecture conclusions must be promoted as ADR"
            )
        if selected_target == "adr" and not record.architecture_decision:
            raise SessionOutcomeError("ADR promotion requires architecture_decision=true")

        public_payload = redact_replay_value(dict(payload))
        assert isinstance(public_payload, Mapping)
        content: dict[str, object]
        if selected_target == "golden-scenario":
            raw_bundle = public_payload.get("replay_bundle")
            if not isinstance(raw_bundle, Mapping):
                raise SessionOutcomeError("Golden Scenario promotion requires replay_bundle")
            try:
                bundle = CaseReplayBundle.from_public_dict(raw_bundle)
                replay_result = CaseReplayService.replay(bundle).to_public_dict()
            except (TypeError, ValueError) as exc:
                raise SessionOutcomeError(f"invalid Golden Scenario replay: {exc}") from exc
            if bundle.fingerprint != record.replay_fingerprint:
                raise SessionOutcomeError("Golden Scenario replay fingerprint mismatch")
            content = {
                "replay_bundle": bundle.to_public_dict(),
                "replay_result": replay_result,
            }
        elif selected_target == "knowledge":
            content = {
                "title": _required_text(public_payload.get("title", ""), "title"),
                "content": _required_text(public_payload.get("content", ""), "content"),
            }
        else:
            content = {
                "title": _required_text(public_payload.get("title", ""), "title"),
                "decision": _required_text(public_payload.get("decision", ""), "decision"),
                "context": _required_text(public_payload.get("context", ""), "context"),
                "consequences": _required_text(
                    public_payload.get("consequences", ""), "consequences"
                ),
            }
        artifact_body = {
            "schema": SESSION_OUTCOME_ARTIFACT_SCHEMA,
            "target": selected_target,
            "source_outcome_id": record.outcome_id,
            "case_reference": f"case://{record.case_id}",
            "replay_reference": f"replay://{record.replay_fingerprint}",
            "workflow": record.workflow,
            "domain": record.domain,
            "outcome": record.outcome,
            "gap_type": record.gap_type,
            "summary": record.summary,
            "content": content,
            "redacted": True,
            "reviewed_by": record.reviewer,
            "approved_by": record.approver,
            "executable": False,
            "execution_rule_effect": "none",
        }
        artifact = {**artifact_body, "artifact_id": _fingerprint(artifact_body)}
        updated = replace(
            record,
            review_state="promoted",
            promotion=artifact,
            updated_at=self._clock(),
        )
        self.repository.save(updated)
        return artifact

    def status(self) -> dict[str, object]:
        return {
            "schema": SESSION_OUTCOME_SCHEMA,
            **dict(self.repository.status()),
            "execution_rule_promotion": False,
        }
