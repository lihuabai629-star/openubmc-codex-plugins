"""Versioned Run ledger decisions and persistence seam contracts."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import re
from typing import ContextManager, Protocol

from .contracts import RUNTIME_API_VERSION
from .semantic_runtime import RunTurn, project_run_turn
from .workflow import WORKFLOW_DEFINITION_SCHEMA, WorkflowDefinition


RUN_EVENT_SCHEMA = f"{RUNTIME_API_VERSION}/run-event-v1"
RUN_DECISION_SCHEMA = f"{RUNTIME_API_VERSION}/run-decision-v1"
RUN_DECISION_VERSION = 1

_LEGACY_RUN_EVENT_KINDS = (
    "CaseOpened",
    "CaseUpdated",
    "DeliveryStrategySelected",
    "OperationProgressed",
    "RunCancelled",
    "RunGateOpened",
    "RunGateSubmitted",
    "RunOutcomeRecorded",
    "RunPhaseRecorded",
)
_SUPPORTED_UNVERSIONED_RUN_EVENT_KINDS = (
    "CaseClosed",
    "CaseOpened",
    "CaseUpdated",
    "CloseoutRecorded",
    "DeliveryStrategySelected",
    "EvidenceAttached",
    "OperationAccepted",
    "OperationProgressed",
    "OperationReconciled",
    "OperationStarted",
    "OperationTerminal",
    "RunCancelled",
    "RunDecisionCommitted",
    "RunGateOpened",
    "RunGateSubmitted",
    "RunIncidentRaised",
    "RunIncidentResolved",
    "RunOutcomeRecorded",
    "RunPhaseRecorded",
    "RunVerificationDeferred",
    "WorkflowCycleStarted",
    "WorkflowStepsInvalidated",
)

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class RunStoreError(ValueError):
    """Base error for the durable RunStore seam."""


class RunDecisionConflict(RunStoreError):
    """Raised when a command identity is rebound or its revision is stale."""


class RunEventSchemaError(RunStoreError):
    """Raised when a persisted Run event cannot be read without changing meaning."""


def persisted_run_support() -> dict[str, object]:
    """Describe the current-only writer and read-only legacy Run support window."""

    return {
        "current_run_decision_version": RUN_DECISION_VERSION,
        "current_run_event_version": 1,
        "accepted_unversioned_event_kinds": list(
            _SUPPORTED_UNVERSIONED_RUN_EVENT_KINDS
        ),
        "legacy_event_kinds": list(_LEGACY_RUN_EVENT_KINDS),
        "legacy_mode": "read-only-upcast",
        "unknown_version_behavior": "reject",
    }


@dataclass(frozen=True)
class RunEvent:
    """One versioned append-only fact emitted by RunEngine."""

    kind: str
    payload: Mapping[str, object]
    operation_id: str = ""
    version: int = 1

    def __post_init__(self) -> None:
        if _SAFE_ID.fullmatch(self.kind) is None:
            raise RunEventSchemaError("Run event kind must be a safe identifier")
        if self.operation_id and _SAFE_ID.fullmatch(self.operation_id) is None:
            raise RunEventSchemaError(
                "Run event operation_id must be a safe identifier"
            )
        if self.version != 1:
            raise RunEventSchemaError(
                f"unsupported Run event version: {self.version}"
            )
        if "_run_event_schema" in self.payload or "_run_event_version" in self.payload:
            raise RunEventSchemaError(
                "Run event payload must not override persistence schema metadata"
            )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": RUN_EVENT_SCHEMA,
            "version": self.version,
            "kind": self.kind,
            "operation_id": self.operation_id,
            "payload": dict(self.payload),
        }

    def for_persistence(self) -> "PersistedRunEvent":
        return PersistedRunEvent(
            kind=self.kind,
            operation_id=self.operation_id,
            payload={
                "_run_event_schema": RUN_EVENT_SCHEMA,
                "_run_event_version": self.version,
                **dict(self.payload),
            },
        )


@dataclass(frozen=True)
class PersistedRunEvent:
    kind: str
    payload: Mapping[str, object]
    operation_id: str = ""


@dataclass(frozen=True)
class RunDecision:
    """The complete durable result of accepting one RunCommand."""

    run_id: str
    command_id: str
    input_digest: str
    expected_revision: int
    events: tuple[RunEvent, ...]
    turn: RunTurn
    effect_intent: Mapping[str, object] | None = None
    version: int = RUN_DECISION_VERSION

    def __post_init__(self) -> None:
        if _SAFE_ID.fullmatch(self.run_id) is None:
            raise RunStoreError("RunDecision run_id must be a safe identifier")
        if _SAFE_ID.fullmatch(self.command_id) is None:
            raise RunStoreError("RunDecision command_id must be a safe identifier")
        if _SHA256.fullmatch(self.input_digest) is None:
            raise RunStoreError("RunDecision input_digest must be SHA-256")
        if (
            isinstance(self.expected_revision, bool)
            or not isinstance(self.expected_revision, int)
            or self.expected_revision < 0
        ):
            raise RunStoreError(
                "RunDecision expected_revision must be a non-negative integer"
            )
        if self.turn.run_id != self.run_id:
            raise RunStoreError("RunDecision Turn belongs to a different Run")
        if self.version != RUN_DECISION_VERSION:
            raise RunStoreError(
                f"unsupported RunDecision version: {self.version}"
            )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": RUN_DECISION_SCHEMA,
            "version": self.version,
            "run_id": self.run_id,
            "command_id": self.command_id,
            "input_digest": self.input_digest,
            "expected_revision": self.expected_revision,
            "events": [event.to_public_dict() for event in self.events],
            "turn": self.turn.to_public_dict(),
            "effect_intent": (
                dict(self.effect_intent)
                if isinstance(self.effect_intent, Mapping)
                else None
            ),
        }


@dataclass(frozen=True)
class CommittedRunDecision:
    projection: Mapping[str, object]
    turn: RunTurn
    effect_intent: Mapping[str, object] | None = None
    replayed: bool = False


@dataclass(frozen=True)
class LoadedRun:
    projection: Mapping[str, object] | None
    decision: CommittedRunDecision | None = None


class RunDecisionDraft(Protocol):
    @property
    def expected_revision(self) -> int: ...

    @property
    def events(self) -> tuple[RunEvent, ...]: ...

    @property
    def effect_intent(self) -> Mapping[str, object] | None: ...

    def stage(
        self,
        *,
        events: tuple[RunEvent, ...],
        effect_intent: Mapping[str, object] | None = None,
    ) -> None: ...

    def accept(self) -> None: ...


class _RunDraftBuffer(Protocol):
    def begin(self, run_id: str) -> ContextManager[RunDecisionDraft]: ...

    def reattach(self, run_id: str, task_id: str) -> None: ...


@dataclass(frozen=True)
class RunCommitRequest:
    run_id: str
    command_id: str
    input_digest: str
    build: Callable[[RunDecisionDraft], RunDecision | None]
    retry_conflicts: bool
    exhausted_message: str
    task_id: str = ""


class RunStore(Protocol):
    """Small persistence Interface used by RunEngine decisions."""

    def load(
        self,
        run_id: str,
        *,
        command_id: str = "",
        input_digest: str = "",
        task_id: str = "",
    ) -> LoadedRun: ...

    def commit(
        self,
        request: RunDecision | RunCommitRequest,
    ) -> CommittedRunDecision | None: ...


class RunEventRepository(Protocol):
    def load(self, run_id: str) -> Mapping[str, object] | None: ...

    def commit(
        self,
        run_id: str,
        *,
        expected_revision: int,
        events: tuple[RunEvent, ...],
    ) -> Mapping[str, object]: ...


class EventRunStore:
    """Append RunDecision facts through one expected-revision transaction."""

    def __init__(
        self,
        repository: RunEventRepository,
        *,
        draft_buffer: _RunDraftBuffer | None = None,
        fact_projector: Callable[
            [Mapping[str, object]], tuple[Mapping[str, object], ...]
        ] | None = None,
    ) -> None:
        self.repository = repository
        self._draft_buffer = draft_buffer
        self.fact_projector = fact_projector

    def load(
        self,
        run_id: str,
        *,
        command_id: str = "",
        input_digest: str = "",
        task_id: str = "",
    ) -> LoadedRun:
        projection = self.repository.load(run_id)
        decision = None
        if command_id:
            if not input_digest:
                raise RunStoreError("RunStore load requires an input digest")
            recorded = self._recorded_decision(projection, command_id)
            if isinstance(projection, Mapping) and isinstance(recorded, Mapping):
                decision = self._replayed_decision(
                    projection,
                    recorded,
                    input_digest=input_digest,
                )
                if task_id and self._draft_buffer is not None:
                    self._draft_buffer.reattach(run_id, task_id)
        return LoadedRun(projection=projection, decision=decision)

    @staticmethod
    def _recorded_decision(
        projection: Mapping[str, object] | None, command_id: str
    ) -> Mapping[str, object] | None:
        if not isinstance(projection, Mapping):
            return None
        raw_decisions = projection.get("run_decisions", [])
        if not isinstance(raw_decisions, list):
            return None
        return next(
            (
                item
                for item in reversed(raw_decisions)
                if isinstance(item, Mapping)
                and item.get("command_id") == command_id
            ),
            None,
        )

    def _replayed_decision(
        self,
        projection: Mapping[str, object],
        recorded: Mapping[str, object],
        *,
        input_digest: str,
    ) -> CommittedRunDecision:
        if recorded.get("schema") != RUN_DECISION_SCHEMA:
            raise RunEventSchemaError(
                "persisted RunDecision has an unsupported schema"
            )
        if recorded.get("version") != RUN_DECISION_VERSION:
            raise RunEventSchemaError(
                "persisted RunDecision has an unsupported version"
            )
        if recorded.get("input_digest") != input_digest:
            raise RunDecisionConflict(
                "Run command identity is already bound to different input"
            )
        raw_turn = recorded.get("turn")
        if not isinstance(raw_turn, Mapping):
            raise RunEventSchemaError(
                "persisted RunDecision is missing its Turn"
            )
        current_turn = projection.get("current_turn")
        if isinstance(current_turn, Mapping) and current_turn:
            raw_turn = current_turn
        base_turn = RunTurn.from_public_dict(raw_turn)
        return CommittedRunDecision(
            projection=dict(projection),
            turn=project_run_turn(
                projection,
                run_id=str(projection.get("case_id") or base_turn.run_id),
                use_current_gate=True,
                use_projected_next_action=True,
                base_turn=base_turn,
                facts=(
                    self.fact_projector(projection)
                    if self.fact_projector is not None
                    else None
                ),
            ),
            effect_intent=(
                dict(recorded["effect_intent"])
                if isinstance(recorded.get("effect_intent"), Mapping)
                else None
            ),
            replayed=True,
        )

    def _commit_decision(self, decision: RunDecision) -> CommittedRunDecision:
        current = self.repository.load(decision.run_id)
        recorded = self._recorded_decision(current, decision.command_id)
        if isinstance(current, Mapping) and isinstance(recorded, Mapping):
            return self._replayed_decision(
                current,
                recorded,
                input_digest=decision.input_digest,
            )
        decision_record = RunEvent(
            kind="RunDecisionCommitted",
            operation_id=decision.command_id,
            payload={
                "schema": RUN_DECISION_SCHEMA,
                "version": decision.version,
                "command_id": decision.command_id,
                "input_digest": decision.input_digest,
                "turn": decision.turn.to_public_dict(),
                "effect_intent": (
                    dict(decision.effect_intent)
                    if isinstance(decision.effect_intent, Mapping)
                    else None
                ),
            },
        )
        try:
            projection = self.repository.commit(
                decision.run_id,
                expected_revision=decision.expected_revision,
                events=tuple(
                    event.for_persistence()
                    for event in (*decision.events, decision_record)
                ),
            )
        except Exception as exc:
            if getattr(exc, "code", "") != "revision_conflict":
                raise
            current = self.repository.load(decision.run_id)
            recorded = self._recorded_decision(current, decision.command_id)
            if isinstance(current, Mapping) and isinstance(recorded, Mapping):
                try:
                    return self._replayed_decision(
                        current,
                        recorded,
                        input_digest=decision.input_digest,
                    )
                except RunStoreError as replay_exc:
                    raise replay_exc from exc
            raise RunDecisionConflict(
                "RunDecision expected revision is stale"
            ) from exc
        return CommittedRunDecision(
            projection=dict(projection),
            turn=decision.turn,
            effect_intent=(
                dict(decision.effect_intent)
                if isinstance(decision.effect_intent, Mapping)
                else None
            ),
        )

    def commit(
        self,
        request: RunDecision | RunCommitRequest,
    ) -> CommittedRunDecision | None:
        if isinstance(request, RunDecision):
            return self._commit_decision(request)
        if self._draft_buffer is None:
            raise RunStoreError(
                "RunStore command commits require a command-local draft buffer"
            )
        for attempt in range(4):
            loaded = self.load(
                request.run_id,
                command_id=request.command_id,
                input_digest=request.input_digest,
                task_id=request.task_id,
            )
            if loaded.decision is not None:
                return loaded.decision
            with self._draft_buffer.begin(request.run_id) as draft:
                decision = request.build(draft)
                if decision is None:
                    return None
                try:
                    committed = self._commit_decision(decision)
                except RunDecisionConflict:
                    if not request.retry_conflicts or attempt >= 3:
                        raise
                    continue
                draft.accept()
                return committed
        raise RunDecisionConflict(request.exhausted_message)


def _legacy_workflow_definition(value: object) -> object:
    if not isinstance(value, Mapping) or not value:
        return value
    schema = value.get("schema")
    if schema not in {None, "", WORKFLOW_DEFINITION_SCHEMA}:
        raise RunEventSchemaError(
            f"unsupported workflow definition schema: {schema}"
        )
    candidate = {**dict(value), "schema": WORKFLOW_DEFINITION_SCHEMA}
    try:
        return WorkflowDefinition.from_public_dict(candidate).to_public_dict()
    except (TypeError, ValueError) as exc:
        raise RunEventSchemaError(
            f"persisted workflow definition cannot be upcast: {exc}"
        ) from exc


def upcast_run_events(
    event: Mapping[str, object],
) -> tuple[dict[str, object], ...]:
    """Normalize known legacy Run facts or reject an unknown declared schema."""

    normalized = dict(event)
    raw_payload = event.get("payload", {})
    if not isinstance(raw_payload, Mapping):
        raise RunEventSchemaError(
            "persisted Run event payload is not an object"
        )
    payload = dict(raw_payload)
    declared_schema = payload.get("_run_event_schema")
    declared_version = payload.get("_run_event_version")
    if declared_schema not in {None, "", RUN_EVENT_SCHEMA}:
        raise RunEventSchemaError(
            f"unsupported persisted Run event schema: {declared_schema}"
        )
    if declared_version not in {None, RUN_DECISION_VERSION}:
        raise RunEventSchemaError(
            f"unsupported persisted Run event version: {declared_version}"
        )
    kind = str(event.get("kind", ""))
    if (
        declared_schema in {None, ""}
        and kind not in _SUPPORTED_UNVERSIONED_RUN_EVENT_KINDS
    ):
        raise RunEventSchemaError(
            f"unsupported unversioned persisted Run event kind: {kind}"
        )
    if kind in {
        "CaseOpened",
        "DeliveryStrategySelected",
        "CaseUpdated",
    } and "workflow_definition" in payload:
        payload["workflow_definition"] = _legacy_workflow_definition(
            payload.get("workflow_definition")
        )
    if kind == "RunGateOpened":
        raw_gate = payload.get("gate")
        if isinstance(raw_gate, Mapping):
            gate = dict(raw_gate)
            if "schema_digest" not in gate and gate.get("gate_schema_digest"):
                gate["schema_digest"] = gate.get("gate_schema_digest")
            payload["gate"] = gate
    elif kind in {"RunGateSubmitted", "RunCancelled"}:
        if "schema_digest" not in payload and payload.get("gate_schema_digest"):
            payload["schema_digest"] = payload.get("gate_schema_digest")
    elif kind == "RunOutcomeRecorded" and not isinstance(
        payload.get("outcome"), Mapping
    ):
        payload = {
            "_run_event_schema": payload.get("_run_event_schema"),
            "_run_event_version": payload.get("_run_event_version"),
            "outcome": {
                key: value
                for key, value in payload.items()
                if key not in {"_run_event_schema", "_run_event_version"}
            },
        }
    elif kind == "RunPhaseRecorded":
        raw_phase = payload.get("phase")
        if not isinstance(raw_phase, Mapping):
            raise RunEventSchemaError("RunPhaseRecorded is missing its phase fact")
        phase = dict(raw_phase)
        kind = "RunGateSubmitted"
        payload = _legacy_gate_submission(phase)
    elif kind == "OperationProgressed" and "phase_record" in payload:
        raw_phase = payload.get("phase_record")
        if not isinstance(raw_phase, Mapping):
            raise RunEventSchemaError(
                "legacy OperationProgressed phase_record is not an object"
            )
        phase = dict(raw_phase)
        status = str(phase.get("status", payload.get("status", "")))
        phase["status"] = status
        kind = "RunGateSubmitted"
        payload = _legacy_gate_submission(phase)
    elif kind == "RunDecisionCommitted":
        if payload.get("schema") != RUN_DECISION_SCHEMA:
            raise RunEventSchemaError(
                "unsupported persisted RunDecision schema: "
                + str(payload.get("schema"))
            )
        if payload.get("version") != RUN_DECISION_VERSION:
            raise RunEventSchemaError(
                "unsupported persisted RunDecision version: "
                + str(payload.get("version"))
            )
    normalized["kind"] = kind
    normalized["payload"] = payload
    return (normalized,)


def _legacy_gate_submission(phase: Mapping[str, object]) -> dict[str, object]:
    """Translate a retired phase writer fact into the current Gate fact."""

    gate_version = phase.get("gate_version", 0)
    if isinstance(gate_version, bool) or not isinstance(gate_version, int):
        gate_version = 0
    return {
        "gate_id": str(phase.get("gate_id", "")),
        "gate_version": gate_version,
        "schema_digest": str(
            phase.get("gate_schema_digest", phase.get("schema_digest", ""))
        ).removeprefix("sha256:"),
        "submission_id": str(phase.get("submission_id", "")),
        "submission_digest": str(phase.get("submission_digest", "")),
        "actor": str(phase.get("producer_identity", "")),
        "status": str(phase.get("status", "")),
        "summary": str(phase.get("summary", "")),
        "recorded_at": phase.get("recorded_at", 0.0),
        "phase": dict(phase),
    }
