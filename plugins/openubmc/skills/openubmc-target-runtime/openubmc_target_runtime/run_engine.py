"""Automatic observation and durable Run progression behind one semantic seam."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, replace
from enum import Enum
import json
import math
import time
from typing import Protocol

from .artifact_store import LocalArtifactStore
from .effect_activity import active_operation
from .semantic_runtime import (
    AgentPreflightError,
    ArtifactRef,
    AssuranceUnavailable,
    CancelIncident,
    CancelRun,
    CommandConflict,
    Gate,
    GateConflict,
    GatePreflightError,
    Incident,
    ObservationQuery,
    ObservationRef,
    ObservationResult,
    Outcome,
    PreflightContext,
    PreflightReason,
    ReferenceViolation,
    ReconcileRun,
    ResumeRun,
    RunCommand,
    RunTurn,
    SemanticRuntimePort,
    StartRun,
    SubmitGate,
    fingerprint,
    json_bytes,
    project_run_turn,
    run_command_identity,
    run_id_for_command,
)
from .run_store import (
    CommittedRunDecision,
    RunCommitRequest,
    RunDecision,
    RunDecisionConflict,
    RunDecisionDraft,
    RunEvent,
    RunStore,
)
from .effect_runner import (
    EffectExecution,
    EffectIntent,
    EffectRunMode,
    EffectSettlementMode,
    LocalEffectRunner,
    PreparedEffect,
)
from .capability import EffectClass
from .comparison_receipt import COMPARISON_RECEIPT_SCHEMA
from .diagnostic_receipt import (
    DiagnosticItemStatus,
    DiagnosticStatus,
    build_diagnostic_receipt,
    latest_diagnostic_receipt,
)
from .diagnosis_record import (
    accepted_diagnosis_record,
    parse_diagnosis_record,
    requires_diagnosis_record,
)
from .observation import (
    aggregate_observation_partitions,
    observation_consistency,
    observation_completion_window_matches,
    observation_improves,
    observation_reusable,
    observation_target_scope_matches,
    qualify_observation,
    reusable_selector_fragments,
    selected_scope_complete,
)
from .workflow import (
    DEFAULT_PHASE_REGISTRY,
    DEFAULT_WORKFLOW_DEFINITIONS,
    WorkflowDefinitions,
)
from .validation_readiness import (
    BUILD_STATUSES,
    DEPENDENCY_RESOLUTIONS,
    DEPENDENCY_STATUSES,
    HARDWARE_COVERAGE_STATUSES,
    OFFICIAL_UT_STATUSES,
    SUPPLEMENTARY_STATUSES,
    ValidationReadinessError,
    assess_validation_payload,
    normalize_hardware_protocol,
)


WORKFLOW_INTERNAL_MAX_STEPS = 64
EFFECT_SETTLEMENT_STATUSES = frozenset(
    {"accepted", "running", "blocked", "mutation_outcome_unknown"}
)
class RunTransitionKind(str, Enum):
    GATE_OPENED = "gate_opened"
    RUN_CANCELLED = "run_cancelled"
    INCIDENT_RAISED = "incident_raised"
    INCIDENT_RESOLVED = "incident_resolved"
    VERIFICATION_DEFERRED = "verification_deferred"
    OUTCOME_RECORDED = "outcome_recorded"


class GateSchemaViolation(GateConflict):
    """Typed schema failure used by RunEngine without parsing error prose."""

    def __init__(
        self,
        message: str,
        *,
        path: str,
        rule: str,
        fields: tuple[str, ...] = (),
    ) -> None:
        super().__init__(message)
        self.path = path
        self.rule = rule
        self.fields = fields


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _text(value: object) -> str:
    return str(value).strip() if value is not None else ""


def _evidence_contains_protocol(value: object, protocol: str) -> bool:
    if isinstance(value, Mapping):
        for name, item in value.items():
            if _text(name).lower() in {"protocol", "interface"} and (
                normalize_hardware_protocol(item) == protocol
            ):
                return True
            if _evidence_contains_protocol(item, protocol):
                return True
        return False
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        return any(_evidence_contains_protocol(item, protocol) for item in value)
    return False


def _evidence_supports_device(
    value: object,
    device_id: str,
    protocol: str,
) -> bool:
    if isinstance(value, Mapping):
        normalized_protocol = normalize_hardware_protocol(protocol)
        identifiers = {
            _text(value.get(name))
            for name in ("device_id", "id", "name", "object_id")
            if _text(value.get(name))
        }
        protocols = {
            normalize_hardware_protocol(value.get(name))
            for name in ("protocol", "Protocol", "interface", "Interface")
            if _text(value.get(name))
        }
        if device_id in identifiers and normalized_protocol in protocols:
            return True
        for name, item in value.items():
            if _text(name) == device_id and _evidence_contains_protocol(
                item,
                normalized_protocol,
            ):
                return True
            if _evidence_supports_device(item, device_id, normalized_protocol):
                return True
        return False
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        return any(
            _evidence_supports_device(item, device_id, protocol)
            for item in value
        )
    return False


def _projection(snapshot: Mapping[str, object]) -> Mapping[str, object]:
    return _mapping(snapshot.get("projection"))


def _continuation(snapshot: Mapping[str, object]) -> Mapping[str, object]:
    return _mapping(snapshot.get("continuation"))


def _string_schema(*, enum: list[str] | None = None) -> dict[str, object]:
    schema: dict[str, object] = {"type": "string", "minLength": 1}
    if enum is not None:
        schema["enum"] = enum
    return schema


def _string_array_schema() -> dict[str, object]:
    return {
        "type": "array",
        "items": {"type": "string", "minLength": 1},
    }


def _artifact_ref_schema(kind: str, *, require_version: bool) -> dict[str, object]:
    required = [
        "handle",
        "digest",
        "kind",
        "size",
        "provenance",
        "retention_hint",
        "target",
        "run_id",
    ]
    if require_version:
        required.append("version")
    return {
        "type": "object",
        "required": required,
        "properties": {
            "schema": {"type": "string"},
            "handle": _string_schema(),
            "digest": {"type": "string", "minLength": 64, "maxLength": 71},
            "kind": {"type": "string", "enum": [kind]},
            "size": {"type": "integer", "minimum": 0},
            "provenance": _string_schema(),
            "retention_hint": _string_schema(),
            "version": _string_schema(),
            "target": _string_schema(),
            "run_id": _string_schema(),
        },
        "additionalProperties": False,
    }


def _validation_result_schema() -> dict[str, object]:
    return {
        "type": "array",
        "items": {
            "type": "object",
            "required": ["kind", "status", "summary", "commands", "evidence_ids"],
            "properties": {
                "kind": {
                    "type": "string",
                    "enum": ["official_ut", "build", "supplementary"],
                },
                "status": {
                    "type": "string",
                    "enum": sorted(
                        OFFICIAL_UT_STATUSES
                        | BUILD_STATUSES
                        | SUPPLEMENTARY_STATUSES
                    ),
                },
                "summary": _string_schema(),
                "commands": _string_array_schema(),
                "evidence_ids": _string_array_schema(),
                "dependency_readiness_id": _string_schema(),
            },
            "additionalProperties": False,
        },
    }


def _dependency_readiness_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": [
            "readiness_id",
            "status",
            "resolution",
            "summary",
            "check_commands",
            "evidence_ids",
            "attempt_count",
            "reused_by",
        ],
        "properties": {
            "readiness_id": _string_schema(),
            "status": {"type": "string", "enum": sorted(DEPENDENCY_STATUSES)},
            "resolution": {
                "type": "string",
                "enum": sorted(DEPENDENCY_RESOLUTIONS),
            },
            "summary": _string_schema(),
            "check_commands": _string_array_schema(),
            "evidence_ids": _string_array_schema(),
            "attempt_count": {"type": "integer", "minimum": 1, "maximum": 1},
            "reused_by": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["official_ut", "build"],
                },
            },
        },
        "additionalProperties": False,
    }


def _hardware_coverage_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": [
            "status",
            "required_protocols",
            "devices",
            "evidence_ids",
            "gaps",
        ],
        "properties": {
            "status": {
                "type": "string",
                "enum": sorted(HARDWARE_COVERAGE_STATUSES - {"not_reported"}),
            },
            "required_protocols": {
                "type": "array",
                "items": {"type": "string", "enum": ["NVMe", "SATA", "SAS"]},
            },
            "devices": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["device_id", "protocol"],
                    "properties": {
                        "device_id": _string_schema(),
                        "protocol": {
                            "type": "string",
                            "enum": ["NVMe", "SATA", "SAS"],
                        },
                    },
                    "additionalProperties": False,
                },
            },
            "evidence_ids": _string_array_schema(),
            "gaps": _string_array_schema(),
        },
        "additionalProperties": False,
    }


def _validation_payload_properties() -> dict[str, object]:
    return {
        "dependency_readiness": _dependency_readiness_schema(),
        "validation_results": _validation_result_schema(),
        "hardware_coverage": _hardware_coverage_schema(),
    }


def gate_input_schema(
    phase_type: str,
    *,
    delivery_strategy: str,
    artifact_metadata: Mapping[str, object],
) -> dict[str, object]:
    descriptor = DEFAULT_PHASE_REGISTRY.require(phase_type)
    artifact_kind = _text(artifact_metadata.get("artifact_kind"))
    artifact_schema = (
        _artifact_ref_schema(
            artifact_kind,
            require_version=bool(
                artifact_metadata.get("artifact_requires_version")
            ),
        )
        if artifact_kind
        else None
    )
    if phase_type == "developer.change":
        payload_properties: dict[str, object] = {
            "source_revision": _string_schema(),
            "authored_files": _string_array_schema(),
            "verification_plan": _string_array_schema(),
            "design": {"type": "object", "additionalProperties": True},
            **_validation_payload_properties(),
            "source_delivery": {
                "type": "string",
                "enum": ["local_only", "committed", "pushed", "pull_request"],
            },
            "known_gaps": _string_array_schema(),
            "remote_path": _string_schema(),
            "restart_scope": _string_schema(),
        }
        if artifact_schema is not None:
            payload_properties["artifact_ref"] = artifact_schema
        completed_required = [
            "source_revision",
            "authored_files",
            "verification_plan",
        ]
        if delivery_strategy == "live-patch":
            if artifact_schema is None:
                raise GateConflict(
                    "live-patch delivery requires a registered artifact Domain Pack"
                )
            completed_required.extend(
                ["artifact_ref", "remote_path", "restart_scope"]
            )
    elif phase_type == "diagnosis.acceptance":
        payload_properties = {
            "root_cause": _string_schema(),
            "evidence_ids": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "causal_chain": {**_string_array_schema(), "minItems": 1},
            "code_owner": _string_schema(),
            "contradictions": _string_array_schema(),
            "remaining_gaps": _string_array_schema(),
            "verification_status": _string_schema(
                enum=["verified", "partial", "unverified", "blocked"],
            ),
        }
        completed_required = list(descriptor.required_fields)
    elif phase_type == "build.artifact":
        payload_properties = {
            "source_revision": _string_schema(),
            "package_binding": _string_schema(enum=["package_binding_verified"]),
            "upgrade_eligible": {"type": "boolean", "enum": [True]},
            "evidence_ids": {**_string_array_schema(), "minItems": 1},
            "component_versions": {"type": "array"},
            "build_commands": _string_array_schema(),
            "build_logs": _string_array_schema(),
            "known_gaps": _string_array_schema(),
            **_validation_payload_properties(),
        }
        if artifact_schema is None:
            raise GateConflict(
                "build-upgrade delivery requires a registered artifact Domain Pack"
            )
        payload_properties["artifact_ref"] = artifact_schema
        completed_required = [
            "source_revision",
            "artifact_ref",
            "package_binding",
            "upgrade_eligible",
            "evidence_ids",
        ]
    else:
        raise GateConflict(f"unsupported Agent Gate phase: {phase_type}")
    schema = {
        "type": "object",
        "required": ["status", "summary", "payload"],
        "properties": {
            "status": {
                "type": "string",
                "enum": ["completed", "failed", "cancelled"],
            },
            "summary": _string_schema(),
            "payload": {
                "type": "object",
                "properties": payload_properties,
                "additionalProperties": False,
            },
        },
        "additionalProperties": False,
        "allOf": [
            {
                "if": {"properties": {"status": {"const": "completed"}}},
                "then": {
                    "properties": {
                        "payload": {"required": completed_required}
                    }
                },
            }
        ],
        "receipt_schema": descriptor.receipt_schema,
    }
    return schema


class ObservationDriver(Protocol):
    def observe_once(
        self,
        query: ObservationQuery,
        *,
        assured: bool,
        task_id: str,
        operation_id: str,
        prior: Mapping[str, object] | None = None,
    ) -> Mapping[str, object]: ...

    def persist_observation(
        self,
        raw: Mapping[str, object],
        *,
        query: ObservationQuery,
        assurance: str,
        task_id: str = "",
    ) -> Mapping[str, object]: ...


class RunDriver(Protocol):
    def start_run(
        self,
        command: StartRun,
        *,
        task_id: str,
        operation_id: str,
    ) -> Mapping[str, object]: ...

    def run_snapshot(self, run_id: str) -> Mapping[str, object]: ...

    def domain_metadata(self, operation: str) -> Mapping[str, object]: ...

    def domain_artifact_metadata(
        self,
        phase_type: str,
    ) -> Mapping[str, object]: ...

    def derive_closeout(
        self,
        run_id: str,
        *,
        terminal_status: str,
    ) -> Mapping[str, object]: ...

    def read_evidence(
        self,
        run_id: str,
        evidence_id: str,
        *,
        target_id: str,
    ) -> Mapping[str, object]: ...

    def prepare_step(
        self,
        run_id: str,
        *,
        operation: str,
        workflow_step_id: str,
        task_id: str,
    ) -> PreparedEffect | None: ...

    def effect_transition(
        self,
        intent: EffectIntent,
        *,
        result: Mapping[str, object] | None,
        error: BaseException | None,
        settlement_mode: EffectSettlementMode,
    ) -> "RunTransition": ...

@dataclass(frozen=True)
class RunTransition:
    """One exact transition batch translated by the persistence adapter."""

    events: tuple[RunEvent, ...]

    def __post_init__(self) -> None:
        if not self.events:
            raise ValueError("Run transition requires at least one event")

class ObservationEngine:
    """Collect, automatically assure when useful, and persist one observation."""

    def __init__(self, driver: ObservationDriver) -> None:
        self.driver = driver

    @staticmethod
    def _needs_assurance(
        raw: Mapping[str, object], query: ObservationQuery
    ) -> bool:
        consistency = observation_consistency(raw)
        if consistency and consistency.get("classification") != "coherent":
            return True
        result = _mapping(raw.get("result"))
        return not selected_scope_complete(raw, query) or not bool(
            _text(raw.get("observed_at"))
            or _text(result.get("completed_at"))
            or _text(result.get("started_at"))
        )

    def _reuse_selector_scope(
        self, query: ObservationQuery, *, task_id: str, operation_id: str
    ) -> Mapping[str, object] | None:
        lookup = getattr(self.driver, "reusable_observation", None)
        if not callable(lookup):
            return None
        prior = lookup(target=query.target, task_id=task_id, operation_id=operation_id)
        if not isinstance(prior, Mapping):
            return None
        prior_query = ObservationQuery.from_query(_mapping(prior.get("scope")))
        fragments, missing = reusable_selector_fragments(query, prior_query, _mapping(prior.get("raw")))
        if not fragments:
            return None
        collected = list(fragments)
        if missing:
            missing_query = replace(query, selectors=missing)
            for index, partition in enumerate(missing_query.collection_partitions(), start=1):
                part = self.driver.observe_once(
                    partition, assured=False, task_id=task_id,
                    operation_id=f"{operation_id}-missing-{index}",
                )
                collected.append((partition, part))
        # Reconstruct in the requested value order; aggregation never lets a
        # cached value migrate to a different selector or MDB query position.
        ordered = []
        for selector in query.selectors:
            for value in selector.values:
                for part_query, part in collected:
                    selected = next((item for item in part_query.selectors if item.selector_id == selector.selector_id and item.kind == selector.kind and value in item.values), None)
                    if selected is None:
                        continue
                    single_query = replace(query, selectors=(selector.with_values((value,)),))
                    pieces, _ = reusable_selector_fragments(single_query, part_query, part)
                    ordered.extend(pieces)
                    break
        if not observation_completion_window_matches(*(raw for _part, raw in ordered)):
            return None
        combined = aggregate_observation_partitions(query, tuple(ordered))
        combined = qualify_observation(combined, query, scope_complete=selected_scope_complete(combined, query))
        if not observation_reusable(combined):
            return None
        combined["evidence_plan"] = {
            "source_observation_ref": dict(_mapping(prior.get("source"))),
            "reused_selectors": [item.to_public_dict() for part, _raw in fragments for item in part.selectors],
            "collected_selectors": [item.to_public_dict() for item in missing],
        }
        return combined

    def observe(
        self,
        query: ObservationQuery,
        *,
        task_id: str,
        operation_id: str,
    ) -> ObservationResult:
        reused = self._reuse_selector_scope(query, task_id=task_id, operation_id=operation_id)
        if reused is not None:
            source = self.driver.persist_observation(
                reused, query=query, assurance="reused", task_id=task_id,
            )
            return ObservationResult(
                query=query, raw=dict(reused), assurance="reused",
                observation_ref=ObservationRef.from_public_dict(source), source=dict(source),
            )
        partitions = query.collection_partitions()

        def collect(
            *,
            assured: bool,
            attempt_operation_id: str,
            prior_parts: tuple[Mapping[str, object], ...] | None = None,
        ) -> tuple[dict[str, object], tuple[Mapping[str, object], ...]]:
            if prior_parts is not None and len(prior_parts) != len(partitions):
                raise ValueError("prior observation partition count changed")
            collected: list[tuple[ObservationQuery, Mapping[str, object]]] = []
            raw_parts: list[Mapping[str, object]] = []
            for index, partition in enumerate(partitions, start=1):
                partition_operation_id = (
                    attempt_operation_id
                    if len(partitions) == 1
                    else f"{attempt_operation_id}-partition-{index}"
                )
                part = self.driver.observe_once(
                    partition,
                    assured=assured,
                    task_id=task_id,
                    operation_id=partition_operation_id,
                    prior=(prior_parts[index - 1] if prior_parts else None),
                )
                if prior_parts is not None and not observation_target_scope_matches(
                    prior_parts[index - 1], part
                ):
                    raise AssuranceUnavailable(
                        "assured partition target identity or epoch changed"
                    )
                raw_parts.append(part)
                collected.append((partition, part))
            return (
                aggregate_observation_partitions(query, tuple(collected)),
                tuple(raw_parts),
            )

        raw, fast_parts = collect(
            assured=False,
            attempt_operation_id=operation_id,
        )
        raw = qualify_observation(
            raw,
            query,
            scope_complete=selected_scope_complete(raw, query),
        )
        fast_raw = raw
        assurance = "fast"
        if self._needs_assurance(raw, query):
            try:
                raw, _assured_parts = collect(
                    assured=True,
                    attempt_operation_id=f"{operation_id}-assured",
                    prior_parts=fast_parts,
                )
                raw = qualify_observation(
                    raw,
                    query,
                    scope_complete=selected_scope_complete(raw, query),
                )
            except AssuranceUnavailable:
                fallback = dict(raw)
                raw_gaps = fallback.get("gaps", [])
                gaps = list(raw_gaps) if isinstance(raw_gaps, list) else []
                gaps.append(
                    "automatic assurance unavailable; preserved the fast observation"
                )
                fallback["gaps"] = gaps
                raw = fallback
            except (ConnectionError, OSError, TimeoutError) as exc:
                fallback = dict(raw)
                raw_gaps = fallback.get("gaps", [])
                gaps = list(raw_gaps) if isinstance(raw_gaps, list) else []
                gaps.append(
                    "automatic assurance failed; preserved the fast observation "
                    f"({type(exc).__name__})"
                )
                fallback["gaps"] = gaps
                raw = fallback
            else:
                if observation_improves(raw, fast_raw):
                    assurance = "assured"
                else:
                    fallback = dict(fast_raw)
                    raw_gaps = fallback.get("gaps", [])
                    gaps = list(raw_gaps) if isinstance(raw_gaps, list) else []
                    gaps.append(
                        "automatic assurance did not improve selector temporal consistency"
                    )
                    fallback["gaps"] = gaps
                    raw = fallback
        source = self.driver.persist_observation(
            raw,
            query=query,
            assurance=assurance,
            task_id=task_id,
        )
        return ObservationResult(
            query=query,
            raw=dict(raw),
            assurance=assurance,
            observation_ref=(
                ObservationRef.from_public_dict(source)
                if observation_reusable(raw)
                else None
            ),
            source=dict(source),
        )


class RunEngine:
    """The semantic transition authority for Agent Runs."""

    def __init__(
        self,
        driver: RunDriver,
        *,
        run_store: RunStore | None = None,
        artifact_store: LocalArtifactStore | None = None,
        effect_runner: LocalEffectRunner | None = None,
        fact_projector: Callable[
            [Mapping[str, object]], tuple[Mapping[str, object], ...]
        ] | None = None,
        workflow_definitions: WorkflowDefinitions = DEFAULT_WORKFLOW_DEFINITIONS,
    ) -> None:
        if run_store is None:
            raise ValueError("RunStore is required")
        self.driver = driver
        self.run_store: RunStore = run_store
        self.artifact_store = artifact_store or LocalArtifactStore()
        self.effect_runner = effect_runner
        self.fact_projector = fact_projector
        self.workflow_definitions = workflow_definitions
        self._active_transaction: ContextVar[RunDecisionDraft | None] = (
            ContextVar(f"openubmc_run_decision_{id(self)}", default=None)
        )

    def _stage(
        self,
        events: tuple[RunEvent, ...],
        *,
        effect_intent: Mapping[str, object] | None = None,
    ) -> None:
        transaction = self._active_transaction.get()
        if transaction is None:
            raise CommandConflict("Run transition requires an active RunDecision")
        transaction.stage(events=events, effect_intent=effect_intent)

    def _commit_run_decision(
        self,
        *,
        run_id: str,
        command_id: str,
        input_digest: str,
        build: Callable[[RunDecisionDraft], RunDecision | None],
        retry_conflicts: bool,
        exhausted_message: str,
        task_id: str = "",
    ) -> CommittedRunDecision | None:
        """Commit one atomic RunDecision through the RunStore load/commit seam."""

        def build_with_context(draft: RunDecisionDraft) -> RunDecision | None:
            token = self._active_transaction.set(draft)
            try:
                return build(draft)
            finally:
                self._active_transaction.reset(token)

        try:
            return self.run_store.commit(
                RunCommitRequest(
                    run_id=run_id,
                    command_id=command_id,
                    input_digest=input_digest,
                    build=build_with_context,
                    retry_conflicts=retry_conflicts,
                    exhausted_message=exhausted_message,
                    task_id=task_id,
                )
            )
        except RunDecisionConflict as exc:
            raise CommandConflict(str(exc)) from exc

    def attach_operator_evidence(
        self,
        run_id: str,
        reference: Mapping[str, object],
        *,
        operation_id: str,
    ) -> tuple[Mapping[str, object], bool]:
        """Append one Operator/CI EvidenceAttached fact through RunEngine."""

        evidence_id = _text(reference.get("evidence_id"))
        if not evidence_id:
            raise ValueError("operator evidence requires an evidence_id")
        command_id = _text(operation_id) or evidence_id
        input_digest = fingerprint(
            {
                "schema": "openubmc.target-runtime/operator-evidence-attach-v1",
                "run_id": run_id,
                "evidence": dict(reference),
            }
        )
        prior = self.run_store.load(
            run_id,
            command_id=command_id,
            input_digest=input_digest,
        ).decision
        if prior is not None:
            persisted = next(
                (
                    item
                    for item in prior.projection.get("evidence_refs", [])
                    if isinstance(item, Mapping)
                    and _text(item.get("evidence_id")) == evidence_id
                ),
                None,
            )
            if not isinstance(persisted, Mapping):
                raise CommandConflict(
                    "operator evidence decision did not persist its Evidence fact"
                )
            return dict(persisted), True

        existing: Mapping[str, object] | None = None

        def build(transaction: RunDecisionDraft) -> RunDecision | None:
            nonlocal existing
            snapshot = self.driver.run_snapshot(run_id)
            projection = _projection(snapshot)
            if not projection:
                raise ValueError(f"run {run_id} is unavailable")
            if (
                _text(projection.get("status")) in {"terminal", "cancelled"}
                or bool(_mapping(projection.get("run_outcome")))
            ):
                raise ValueError(f"run {run_id} no longer accepts evidence")
            existing = next(
                (
                    item
                    for item in projection.get("evidence_refs", [])
                    if isinstance(item, Mapping)
                    and _text(item.get("evidence_id")) == evidence_id
                ),
                None,
            )
            if isinstance(existing, Mapping):
                return None
            self._stage(
                (
                    RunEvent(
                        "EvidenceAttached",
                        {"evidence": dict(reference)},
                        command_id,
                    ),
                )
            )
            return RunDecision(
                run_id=run_id,
                command_id=command_id,
                input_digest=input_digest,
                expected_revision=transaction.expected_revision,
                events=transaction.events,
                turn=self._turn(snapshot),
            )

        committed = self._commit_run_decision(
            run_id=run_id,
            command_id=command_id,
            input_digest=input_digest,
            build=build,
            retry_conflicts=True,
            exhausted_message="operator EvidenceAttached decision could not converge",
        )
        if committed is None:
            if isinstance(existing, Mapping):
                return dict(existing), True
            raise CommandConflict("operator EvidenceAttached decision was not built")
        persisted = next(
            (
                item
                for item in committed.projection.get("evidence_refs", [])
                if isinstance(item, Mapping)
                and _text(item.get("evidence_id")) == evidence_id
            ),
            None,
        )
        if not isinstance(persisted, Mapping):
            raise CommandConflict("operator EvidenceAttached fact is unavailable")
        return dict(persisted), False

    def _apply_transition(
        self,
        run_id: str,
        kind: RunTransitionKind,
        payload: Mapping[str, object],
        *,
        operation_id: str,
    ) -> Mapping[str, object]:
        try:
            transition_kind = RunTransitionKind(kind)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"unsupported Run transition kind: {kind}") from exc
        event_payload: Mapping[str, object]
        events: tuple[RunEvent, ...]
        if transition_kind is RunTransitionKind.GATE_OPENED:
            gate = payload.get("gate")
            if not isinstance(gate, Mapping):
                raise ValueError("gate_opened transition requires a Gate")
            event_payload = {"gate": dict(gate)}
            events = (
                RunEvent("RunGateOpened", event_payload, operation_id),
            )
        elif transition_kind is RunTransitionKind.RUN_CANCELLED:
            gate = payload.get("gate")
            incident = payload.get("incident")
            if isinstance(gate, Mapping):
                event_payload = {
                    "gate_id": _text(gate.get("gate_id")),
                    "gate_version": int(gate.get("gate_version", 0)),
                    "schema_digest": _text(gate.get("schema_digest")),
                    "submission_id": _text(payload.get("submission_id")),
                    "submission_digest": _text(
                        payload.get("submission_digest")
                    ),
                    "actor": "runtime",
                    "status": "cancelled",
                    "summary": "run cancelled at the current gate",
                    "recorded_at": time.time(),
                }
            elif isinstance(incident, Mapping):
                event_payload = {
                    "incident_id": _text(incident.get("incident_id")),
                    "actor": "runtime",
                    "status": "cancelled",
                    "summary": "run cancelled at the current incident",
                    "recorded_at": time.time(),
                }
            else:
                raise ValueError("run_cancelled transition requires a Gate or Incident")
            events = (
                RunEvent("RunCancelled", event_payload, operation_id),
            )
        elif transition_kind is RunTransitionKind.INCIDENT_RAISED:
            incident = payload.get("incident")
            if not isinstance(incident, Mapping):
                raise ValueError("incident_raised transition requires an Incident")
            events = (
                RunEvent(
                    "RunIncidentRaised",
                    {"incident": dict(incident)},
                    operation_id,
                ),
            )
        elif transition_kind is RunTransitionKind.INCIDENT_RESOLVED:
            events = (
                RunEvent(
                    "RunIncidentResolved",
                    {
                        "incident_id": _text(payload.get("incident_id")),
                        "resolution": _text(payload.get("resolution")) or "resolved",
                    },
                    operation_id,
                ),
            )
        elif transition_kind is RunTransitionKind.VERIFICATION_DEFERRED:
            events = (
                RunEvent(
                    "RunVerificationDeferred",
                    {
                        "workflow_step_id": _text(
                            payload.get("workflow_step_id")
                        ),
                        "next_action": (
                            "resume the Run to retry fresh target verification"
                        ),
                    },
                    operation_id,
                ),
            )
        elif transition_kind is RunTransitionKind.OUTCOME_RECORDED:
            normalized = _text(payload.get("status")).lower()
            if normalized not in {"completed", "failed", "cancelled"}:
                raise ValueError(
                    "Run Outcome status must be completed, failed, or cancelled"
                )
            derived = self.driver.derive_closeout(
                run_id,
                terminal_status=normalized,
            )
            closeout = _mapping(derived.get("closeout"))
            effective_status = normalized
            if (
                normalized == "completed"
                and _text(closeout.get("closure_status"))
                not in {"verified", "completed_in_scope"}
            ):
                effective_status = "failed"
            summary = _text(payload.get("summary"))
            outcome = {
                "status": effective_status,
                "summary": (
                    _text(closeout.get("summary"))
                    if effective_status != normalized
                    else summary or _text(closeout.get("summary"))
                ),
                "acceptance": closeout.get(
                    "checks", closeout.get("acceptance", [])
                ),
                "closeout_fingerprint": _text(closeout.get("fingerprint")),
            }
            outcome["outcome_id"] = "outcome-" + fingerprint(
                {"run_id": run_id, **outcome}
            )[:32]
            events = (
                RunEvent(
                    "CloseoutRecorded",
                    {
                        "closeout": dict(closeout),
                        "closeout_markdown": _text(
                            derived.get("closeout_markdown")
                        ),
                        "closeout_bundle": derived.get("closeout_bundle"),
                    },
                    f"{operation_id}-closeout",
                ),
                RunEvent(
                    "RunOutcomeRecorded",
                    {"outcome": outcome},
                    operation_id,
                ),
            )
        else:  # pragma: no cover - Enum exhaustiveness guard
            raise ValueError(
                f"unsupported Run transition kind: {transition_kind.value}"
            )
        self._stage(events)
        return self.driver.run_snapshot(run_id)

    @staticmethod
    def _run_id(snapshot: Mapping[str, object]) -> str:
        return _text(_projection(snapshot).get("case_id"))

    @staticmethod
    def _submission_record(
        snapshot: Mapping[str, object], submission_id: str
    ) -> Mapping[str, object] | None:
        projection = _projection(snapshot)
        records = projection.get("gate_submissions", [])
        if not isinstance(records, list):
            records = projection.get("phase_records", [])
        if not isinstance(records, list):
            return None
        return next(
            (
                record
                for record in reversed(records)
                if isinstance(record, Mapping)
                and _text(record.get("submission_id")) == submission_id
            ),
            None,
        )

    def _current_gate(
        self,
        snapshot: Mapping[str, object],
        *,
        operation_id: str,
    ) -> Gate | None:
        projection = _projection(snapshot)
        continuation = _continuation(snapshot)
        if not _text(continuation.get("required_phase_type")):
            return None
        persisted = projection.get("current_gate")
        if isinstance(persisted, Mapping) and persisted:
            if (
                _text(persisted.get("workflow_cycle_id"))
                != _text(continuation.get("workflow_cycle_id") or "cycle-1")
                or _text(persisted.get("workflow_step_id"))
                != _text(continuation.get("required_workflow_step_id"))
            ):
                raise GateConflict("persisted Gate does not match the Run continuation")
            return Gate.from_public_dict(persisted)
        phase_type = _text(continuation.get("required_phase_type"))
        owner = _text(continuation.get("required_skill"))
        step_id = _text(continuation.get("required_workflow_step_id"))
        cycle_id = _text(continuation.get("workflow_cycle_id") or "cycle-1")
        delivery = _text(projection.get("delivery_strategy"))
        schema = gate_input_schema(
            phase_type,
            delivery_strategy=delivery,
            artifact_metadata=self.driver.domain_artifact_metadata(phase_type),
        )
        schema_digest = fingerprint(schema)
        prior_versions = [
            int(item.get("gate_version", 0))
            for item in projection.get("run_gates", [])
            if isinstance(item, Mapping)
            and _text(item.get("workflow_cycle_id")) == cycle_id
            and _text(item.get("workflow_step_id")) == step_id
            and isinstance(item.get("gate_version", 0), int)
            and not isinstance(item.get("gate_version", 0), bool)
        ]
        version = max(prior_versions, default=0) + 1
        gate_id = "gate-" + fingerprint(
            {
                "run_id": projection.get("case_id", ""),
                "workflow_definition": projection.get("workflow_definition", {}),
                "workflow_cycle_id": cycle_id,
                "workflow_step_id": step_id,
                "phase_type": phase_type,
                "gate_version": version,
                "schema_digest": schema_digest,
            }
        )[:32]
        gate = Gate(
            gate_id=gate_id,
            version=version,
            name=phase_type,
            owner=owner,
            input_schema=schema,
            schema_digest=schema_digest,
        )
        persisted_snapshot = self._apply_transition(
            self._run_id(snapshot),
            RunTransitionKind.GATE_OPENED,
            {
                "gate": {
                    **gate.to_public_dict(),
                    "run_id": self._run_id(snapshot),
                    "workflow_cycle_id": cycle_id,
                    "workflow_step_id": step_id,
                }
            },
            operation_id=operation_id,
        )
        current = _projection(persisted_snapshot).get("current_gate")
        if not isinstance(current, Mapping):
            raise GateConflict("Gate persistence did not return an open Gate")
        return Gate.from_public_dict(current)

    @staticmethod
    def _gate_preflight_context(
        command: SubmitGate | CancelRun,
        gate: Gate,
    ) -> PreflightContext:
        return PreflightContext(
            action_kind=("respond" if isinstance(command, SubmitGate) else "control"),
            run_id=command.run_id,
            command=("" if isinstance(command, SubmitGate) else "cancel"),
            gate_id=gate.gate_id,
            gate_version=gate.version,
            schema_digest=f"sha256:{gate.schema_digest}",
            submission_id=command.submission_id,
            response=(
                dict(command.response)
                if isinstance(command, SubmitGate)
                else {}
            ),
        )

    @classmethod
    def _validate_gate(cls, command: SubmitGate | CancelRun, gate: Gate) -> None:
        mismatches = (
            (
                "gate_id",
                command.gate_id != gate.gate_id,
                "Gate submission targets a different gate_id",
            ),
            (
                "gate_version",
                command.gate_version != gate.version,
                "Gate submission targets a stale gate_version",
            ),
            (
                "schema_digest",
                command.schema_digest != gate.schema_digest,
                "Gate submission targets a different schema digest",
            ),
        )
        for field_name, mismatched, message in mismatches:
            if mismatched:
                raise GatePreflightError(
                    message,
                    reason=PreflightReason.GATE_BINDING,
                    field=field_name,
                    limit={"binding": "current Gate"},
                    context=cls._gate_preflight_context(command, gate),
                )

    @staticmethod
    def _validate_duplicate_gate(
        command: SubmitGate | CancelRun,
        prior: Mapping[str, object],
    ) -> None:
        if command.gate_id != _text(prior.get("gate_id")):
            raise GateConflict("duplicate submission targets a different gate_id")
        if command.gate_version != int(prior.get("gate_version", 0)):
            raise GateConflict("duplicate submission targets a stale gate_version")
        prior_digest = _text(
            prior.get("schema_digest") or prior.get("gate_schema_digest")
        ).removeprefix("sha256:")
        if command.schema_digest != prior_digest:
            raise GateConflict("duplicate submission targets a different schema digest")

    @staticmethod
    def _validate_schema_value(
        value: object,
        schema: Mapping[str, object],
        *,
        path: str,
    ) -> None:
        expected_type = schema.get("type")
        valid_type = {
            "object": isinstance(value, Mapping),
            "array": isinstance(value, list),
            "string": isinstance(value, str),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "boolean": isinstance(value, bool),
        }.get(str(expected_type), True)
        if not valid_type:
            raise GateSchemaViolation(
                f"{path} has the wrong type",
                path=path,
                rule="wrong_type",
            )
        enum = schema.get("enum")
        if isinstance(enum, list) and value not in enum:
            raise GateSchemaViolation(
                f"{path} is not an allowed value",
                path=path,
                rule="enum",
            )
        if isinstance(value, str):
            minimum = schema.get("minLength")
            maximum = schema.get("maxLength")
            if isinstance(minimum, int) and len(value) < minimum:
                raise GateSchemaViolation(
                    f"{path} must not be empty",
                    path=path,
                    rule="min_length",
                )
            if isinstance(maximum, int) and len(value) > maximum:
                raise GateSchemaViolation(
                    f"{path} exceeds its length limit",
                    path=path,
                    rule="max_length",
                )
        if isinstance(value, int) and not isinstance(value, bool):
            minimum = schema.get("minimum")
            if isinstance(minimum, int) and value < minimum:
                raise GateSchemaViolation(
                    f"{path} is below its minimum",
                    path=path,
                    rule="minimum",
                )
            maximum = schema.get("maximum")
            if isinstance(maximum, int) and value > maximum:
                raise GateSchemaViolation(
                    f"{path} exceeds its maximum",
                    path=path,
                    rule="maximum",
                )
        if isinstance(value, Mapping):
            properties = _mapping(schema.get("properties"))
            required = schema.get("required", [])
            if isinstance(required, list):
                missing = [name for name in required if name not in value]
                if missing:
                    raise GateSchemaViolation(
                        f"{path} omits required fields: {', '.join(missing)}",
                        path=path,
                        rule="required",
                        fields=tuple(str(name) for name in missing),
                    )
            if schema.get("additionalProperties") is False:
                unexpected = sorted(set(value) - set(properties))
                if unexpected:
                    raise GateSchemaViolation(
                        f"{path} contains undeclared fields: {', '.join(unexpected)}",
                        path=path,
                        rule="additional_properties",
                        fields=tuple(str(name) for name in unexpected),
                    )
            for name, item in value.items():
                child_schema = properties.get(name)
                if isinstance(child_schema, Mapping):
                    RunEngine._validate_schema_value(
                        item, child_schema, path=f"{path}.{name}"
                    )
        if isinstance(value, list):
            minimum = schema.get("minItems")
            if isinstance(minimum, int) and len(value) < minimum:
                raise GateSchemaViolation(
                    f"{path} requires at least {minimum} item(s)",
                    path=path,
                    rule="min_items",
                )
            item_schema = schema.get("items")
            if isinstance(item_schema, Mapping):
                for index, item in enumerate(value):
                    RunEngine._validate_schema_value(
                        item, item_schema, path=f"{path}[{index}]"
                    )

    @staticmethod
    def _completed_payload_required(gate: Gate) -> list[str]:
        all_of = gate.input_schema.get("allOf", [])
        if not isinstance(all_of, list) or not all_of:
            return []
        first = _mapping(all_of[0])
        then = _mapping(first.get("then"))
        properties = _mapping(then.get("properties"))
        payload = _mapping(properties.get("payload"))
        required = payload.get("required", [])
        return [str(name) for name in required] if isinstance(required, list) else []

    @staticmethod
    def _artifact_preflight_context(
        *,
        command: SubmitGate,
        gate: Gate,
        projection: Mapping[str, object],
    ) -> PreflightContext:
        payload_schema = _mapping(
            _mapping(gate.input_schema.get("properties")).get("payload")
        )
        artifact_schema = _mapping(
            _mapping(payload_schema.get("properties")).get("artifact_ref")
        )
        artifact_properties = _mapping(artifact_schema.get("properties"))
        expected_kinds = _mapping(artifact_properties.get("kind")).get("enum", [])
        targets = projection.get("targets", [])
        target = ""
        if isinstance(targets, list) and targets and isinstance(targets[0], Mapping):
            target = _text(targets[0].get("address"))
        return replace(
            RunEngine._gate_preflight_context(command, gate),
            target=target,
            artifact_kind=(
                str(expected_kinds[0])
                if isinstance(expected_kinds, list) and expected_kinds
                else ""
            ),
            version_required="version" in artifact_properties,
            required_payload_fields=tuple(
                RunEngine._completed_payload_required(gate)
            ),
        )

    def _normalized_response(
        self,
        command: SubmitGate,
        *,
        gate: Gate,
        projection: Mapping[str, object],
    ) -> dict[str, object]:
        response = _mapping(command.response)
        try:
            self._validate_schema_value(response, gate.input_schema, path="response")
        except GateSchemaViolation as exc:
            artifact_path = "response.payload.artifact_ref"
            artifact_field = ""
            if exc.path == artifact_path and exc.rule == "required":
                artifact_field = next(
                    (
                        name
                        for name in ("target", "run_id")
                        if name in exc.fields
                    ),
                    "",
                )
            elif exc.path in {
                f"{artifact_path}.target",
                f"{artifact_path}.run_id",
            }:
                artifact_field = exc.path.rsplit(".", 1)[-1]
            if not artifact_field:
                raise
            raise GatePreflightError(
                str(exc),
                reason=PreflightReason.ARTIFACT_BINDING,
                field=f"{artifact_path}.{artifact_field}",
                limit={"binding": "current Run and target"},
                context=self._artifact_preflight_context(
                    command=command,
                    gate=gate,
                    projection=projection,
                ),
            ) from exc
        status = _text(response.get("status")).lower()
        summary = _text(response.get("summary"))
        raw_payload = response.get("payload", {})
        if not isinstance(raw_payload, Mapping):
            raise GateConflict("Gate response payload must be an object")
        if status == "completed":
            missing = [
                name
                for name in self._completed_payload_required(gate)
                if name not in raw_payload
            ]
            if missing:
                if "artifact_ref" in missing:
                    raise GatePreflightError(
                        "Gate response payload omits required fields: "
                        + ", ".join(missing),
                        reason=PreflightReason.ARTIFACT_REQUIRED,
                        field="response.payload.artifact_ref",
                        limit={"binding": "current Run and target"},
                        context=self._artifact_preflight_context(
                            command=command,
                            gate=gate,
                            projection=projection,
                        ),
                    )
                raise GateConflict(
                    "Gate response payload omits required fields: "
                    + ", ".join(missing)
                )
        payload = dict(raw_payload)
        if gate.name == "build.artifact" and status == "completed":
            if (
                payload.get("package_binding") != "package_binding_verified"
                or payload.get("upgrade_eligible") is not True
            ):
                raise GateConflict(
                    "completed build.artifact requires verified package binding "
                    "and upgrade_eligible=true"
                )
            if not all(
                isinstance(item, str) and item.strip()
                for item in payload.get("evidence_ids", [])
            ):
                raise GateConflict("build.artifact evidence_ids must not be blank")
        raw_artifact_ref = payload.get("artifact_ref")
        if isinstance(raw_artifact_ref, Mapping):
            artifact_path = "response.payload.artifact_ref"
            for binding_field in ("target", "run_id"):
                binding_value = raw_artifact_ref.get(binding_field)
                if not isinstance(binding_value, str) or not binding_value.strip():
                    raise GatePreflightError(
                        f"ArtifactRef {binding_field} is required",
                        reason=PreflightReason.ARTIFACT_BINDING,
                        field=f"{artifact_path}.{binding_field}",
                        limit={"binding": "current Run and target"},
                        context=self._artifact_preflight_context(
                            command=command,
                            gate=gate,
                            projection=projection,
                        ),
                    )
            artifact_ref = ArtifactRef.from_public_dict(raw_artifact_ref)
            payload_schema = _mapping(
                _mapping(gate.input_schema.get("properties")).get("payload")
            )
            artifact_schema = _mapping(
                _mapping(payload_schema.get("properties")).get("artifact_ref")
            )
            kind_schema = _mapping(
                _mapping(artifact_schema.get("properties")).get("kind")
            )
            expected_kinds = kind_schema.get("enum", [])
            targets = projection.get("targets", [])
            expected_target = ""
            if (
                isinstance(targets, list)
                and targets
                and isinstance(targets[0], Mapping)
            ):
                expected_target = _text(targets[0].get("address"))
            if expected_target and artifact_ref.target != expected_target:
                raise GatePreflightError(
                    "ArtifactRef target does not match the Run target",
                    reason=PreflightReason.ARTIFACT_BINDING,
                    field="response.payload.artifact_ref.target",
                    limit={"binding": "current Run and target"},
                    context=self._artifact_preflight_context(
                        command=command,
                        gate=gate,
                        projection=projection,
                    ),
                )
            expected_run_id = _text(projection.get("case_id"))
            if expected_run_id and artifact_ref.run_id != expected_run_id:
                raise GatePreflightError(
                    "ArtifactRef run_id does not match the current Run",
                    reason=PreflightReason.ARTIFACT_BINDING,
                    field="response.payload.artifact_ref.run_id",
                    limit={"binding": "current Run and target"},
                    context=self._artifact_preflight_context(
                        command=command,
                        gate=gate,
                        projection=projection,
                    ),
                )
            if not artifact_ref.handle.startswith("artifact://"):
                self.artifact_store.register(
                    artifact_ref,
                    created_by_effect=(
                        command.submission_id
                        or command.command_id
                        or f"gate-{command.gate_id}-{command.gate_version}"
                    ),
                )
            artifact_path = self.artifact_store.resolve(
                artifact_ref,
                expected_kinds=(
                    str(kind) for kind in expected_kinds
                ) if isinstance(expected_kinds, list) else (),
                expected_target=expected_target,
                expected_run_id=expected_run_id,
            )
            payload["artifact_ref"] = artifact_ref.to_public_dict()
            payload["artifact_sha256"] = artifact_ref.digest
            if artifact_ref.version:
                payload["product_version"] = artifact_ref.version
        if gate.name in {"developer.change", "build.artifact"}:
            assessment_payload = dict(payload)
            diagnostic_receipt = latest_diagnostic_receipt(projection)
            allowed_hardware_evidence_ids = (
                tuple(item.evidence_id for item in diagnostic_receipt.evidence)
                if diagnostic_receipt is not None
                else ()
            )
            try:
                assessment = assess_validation_payload(
                    assessment_payload,
                    allowed_hardware_evidence_ids=(
                        allowed_hardware_evidence_ids
                    ),
                )
            except ValidationReadinessError as exc:
                raise GateConflict(str(exc)) from exc
            self._validate_hardware_coverage_evidence(
                projection=projection,
                diagnostic_receipt=diagnostic_receipt,
                hardware_coverage=assessment.hardware_coverage,
            )
            assessment_fields = assessment.payload_fields(
                phase_type=gate.name,
                phase_status=status,
                has_artifact=isinstance(raw_artifact_ref, Mapping),
            )
            build_summary = _mapping(
                _mapping(assessment_fields.get("validation_summary")).get("build")
            )
            if (
                gate.name == "build.artifact"
                and status == "completed"
                and build_summary.get("acceptance") != "passed"
            ):
                raise GateConflict(
                    "completed build.artifact requires build status compiled; "
                    "return failed for compile or dependency-graph failure"
                )
            if gate.name == "build.artifact" and status == "failed":
                raw_results = assessment_fields.get("validation_results", [])
                build_results = [
                    item
                    for item in raw_results
                    if isinstance(item, Mapping) and item.get("kind") == "build"
                ] if isinstance(raw_results, list) else []
                if (
                    not assessment.dependency_readiness
                    or len(build_results) != 1
                    or build_results[0].get("status")
                    not in {"compile_failed", "dependency_graph_blocked"}
                ):
                    raise GateConflict(
                        "failed build.artifact requires dependency_readiness and "
                        "validation_results classified as compile_failed or "
                        "dependency_graph_blocked"
                    )
            payload.update(assessment_fields)
        return {"status": status, "summary": summary, "payload": payload}

    def _validate_hardware_coverage_evidence(
        self,
        *,
        projection: Mapping[str, object],
        diagnostic_receipt: object,
        hardware_coverage: Mapping[str, object],
    ) -> None:
        devices = hardware_coverage.get("devices", [])
        if not isinstance(devices, Sequence) or isinstance(
            devices, (str, bytes, bytearray)
        ) or not devices:
            return
        evidence_ids = hardware_coverage.get("evidence_ids", [])
        references = {
            item.evidence_id: item
            for item in getattr(diagnostic_receipt, "evidence", ())
        }
        bodies: list[object] = []
        for evidence_id in evidence_ids if isinstance(evidence_ids, list) else []:
            reference = references.get(str(evidence_id))
            if reference is None:
                continue
            try:
                evidence = self.driver.read_evidence(
                    _text(projection.get("case_id")),
                    reference.evidence_id,
                    target_id=reference.target_id,
                )
                bodies.append(json.loads(_text(evidence.get("body"))))
            except Exception as exc:
                raise GateConflict(
                    "hardware coverage Evidence could not be evaluated: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc
        for device in devices:
            if not isinstance(device, Mapping):
                continue
            device_id = _text(device.get("device_id"))
            protocol = _text(device.get("protocol"))
            if not any(
                _evidence_supports_device(body, device_id, protocol)
                for body in bodies
            ):
                raise GateConflict(
                    "hardware coverage Evidence does not support device "
                    f"{device_id} protocol {protocol}"
                )

    def _phase_fact(
        self,
        command: SubmitGate,
        *,
        gate: Gate,
        response: Mapping[str, object],
        projection: Mapping[str, object],
        operation_id: str,
        input_digest: str,
    ) -> dict[str, object]:
        phase_descriptor = DEFAULT_PHASE_REGISTRY.require(gate.name)
        persisted_gate = _mapping(projection.get("current_gate"))
        cycle_id = _text(
            persisted_gate.get("workflow_cycle_id")
            or projection.get("workflow_cycle_id")
            or "cycle-1"
        )
        step_id = _text(persisted_gate.get("workflow_step_id"))
        definition = self.workflow_definitions.definition_for(projection)
        step = next(
            candidate for candidate in definition.steps if candidate.step_id == step_id
        )
        prior_attempts = [
            int(item.get("workflow_attempt", item.get("phase_attempt", 0)) or 0)
            for item in projection.get("phase_records", [])
            if isinstance(item, Mapping)
            and _text(item.get("phase_type")) == gate.name
            and _text(item.get("workflow_cycle_id")) == cycle_id
        ]
        attempt = max(prior_attempts, default=0) + 1
        identity = self.workflow_definitions.step_identity(
            projection,
            step=step,
            attempt=attempt,
            input_fingerprint=input_digest,
            target_epoch=0,
        )
        payload = dict(_mapping(response.get("payload")))
        record = {
            "phase_type": gate.name,
            "producer_identity": DEFAULT_PHASE_REGISTRY.canonical_producer(
                gate.name,
                gate.owner,
            ),
            "receipt_schema": phase_descriptor.receipt_schema,
            "operation_id": operation_id,
            "status": _text(response.get("status")),
            "summary": _text(response.get("summary")),
            "recorded_at": time.time(),
            "gate_id": gate.gate_id,
            "gate_version": gate.version,
            "gate_schema_digest": gate.schema_digest,
            "submission_id": command.submission_id,
            "submission_digest": input_digest,
            "workflow_cycle_id": cycle_id,
            "workflow_step_id": step_id,
            "phase_attempt": attempt,
            "target_version": identity.target_version,
            "workflow_definition_id": identity.workflow_definition_id,
            "workflow_definition_version": identity.workflow_version,
            "workflow_definition_fingerprint": identity.workflow_fingerprint,
            "workflow_execution_id": identity.execution_id,
            "workflow_attempt": identity.attempt,
            "workflow_input_fingerprint": identity.input_fingerprint,
            "workflow_target_epoch": identity.target_epoch,
            "native_run_fact": True,
            **payload,
        }
        if gate.name == "diagnosis.acceptance" and record["status"] == "completed":
            try:
                diagnosis = parse_diagnosis_record(payload)
            except ValueError as exc:
                raise GateConflict(str(exc)) from exc
            if not diagnosis.accepted:
                raise GateConflict(
                    "completed diagnosis acceptance requires verified DiagnosisRecord"
                )
            prior = latest_diagnostic_receipt(projection)
            if prior is None:
                raise GateConflict(
                    "diagnosis acceptance requires a Runtime diagnostic receipt"
                )
            for item in prior.results:
                comparison = _mapping(item.value)
                if not (
                    item.result_id == "comparison"
                    or item.kind == "diagnostic-comparison"
                    or comparison.get("schema") == COMPARISON_RECEIPT_SCHEMA
                ):
                    continue
                if (
                    item.status is not DiagnosticItemStatus.AVAILABLE
                    or comparison.get("status") != "complete"
                    or comparison.get("conclusion") not in ("same", "different")
                    or comparison.get("content_complete") is not True
                    or comparison.get("incomparable_reasons")
                ):
                    raise GateConflict(
                        "diagnosis acceptance requires an evaluable comparison; "
                        "collect complete target evidence before verifying the comparison"
                    )
            requested_evidence_ids = diagnosis.evidence_ids
            available_evidence = {
                item.evidence_id: item.to_public_dict() for item in prior.evidence
            }
            run_target_ids = {
                _text(item.get("target_id"))
                for item in projection.get("targets", [])
                if isinstance(item, Mapping) and _text(item.get("target_id"))
            }
            for evidence_id in requested_evidence_ids:
                if evidence_id in available_evidence:
                    continue
                attached: Mapping[str, object] = {}
                for target_id in run_target_ids:
                    try:
                        loaded = self.driver.read_evidence(
                            command.run_id,
                            evidence_id,
                            target_id=target_id,
                        )
                    except Exception:
                        continue
                    candidate = loaded.get("evidence")
                    if isinstance(candidate, Mapping):
                        attached = candidate
                        break
                if (
                    _text(attached.get("case_id")) == command.run_id
                    and _text(attached.get("target_id")) in run_target_ids
                    and _text(attached.get("workflow_cycle_id")) == cycle_id
                    and _text(attached.get("producer"))
                    == "operator-evidence-attach"
                    and _text(attached.get("evidence_type"))
                    == "workflow-diagnosis-record"
                ):
                    available_evidence[evidence_id] = dict(attached)
            unknown_evidence = sorted(
                set(requested_evidence_ids) - set(available_evidence)
            )
            if unknown_evidence:
                raise GateConflict(
                    "diagnosis evidence_ids are not bound to the current receipt: "
                    + ", ".join(unknown_evidence)
                )
            start_input = _mapping(projection.get("start_input"))
            start_observation = _mapping(start_input.get("observation_ref"))
            observed_at = (
                _text(start_observation.get("observed_at"))
                or prior.freshness.observed_at
            )
            if not observed_at:
                raise GateConflict(
                    "diagnosis evidence has no Runtime-owned observation time"
                )
            runtime_freshness = prior.freshness.to_public_dict()
            if (
                start_observation
                and prior.freshness.status.value == "unknown"
                and not prior.freshness.unavailable_dimensions
                and not prior.freshness.lost_dimensions
                and not prior.freshness.stale_evidence
            ):
                runtime_freshness = {"status": "fresh", "complete": True}
            record["supersedes_diagnostic_receipt_id"] = prior.receipt_id
            if (
                runtime_freshness.get("status") not in {"fresh", "complete"}
                or runtime_freshness.get("complete") is False
                or any(runtime_freshness.get(field) for field in (
                    "unavailable_dimensions", "lost_dimensions", "stale_evidence",
                ))
            ):
                raise GateConflict(
                    "diagnosis response requires fresh Runtime-bound evidence"
                )
            diagnosis = replace(diagnosis, record_id="diagnosis-" + input_digest[:32])
            record["diagnosis_record"] = {
                **diagnosis.to_public_dict(),
                "run_id": command.run_id,
                "workflow_cycle_id": cycle_id,
                "target_version": projection.get("target_version", 1),
                "observed_at": observed_at,
                "source_receipt_id": prior.receipt_id,
            }
            # Historical Closeout readers consume these fields; the typed record
            # remains authoritative, and collection coverage is never rewritten.
            record["known_gaps"] = list(diagnosis.remaining_gaps)
        return record

    @classmethod
    def _diagnosis_accepted(cls, projection: Mapping[str, object]) -> bool:
        return accepted_diagnosis_record(projection) is not None

    @staticmethod
    def _current_incident(projection: Mapping[str, object]) -> Incident | None:
        raw = projection.get("current_incident")
        if not isinstance(raw, Mapping) or not raw:
            return None
        return Incident.from_public_dict(raw)

    @staticmethod
    def _outcome(projection: Mapping[str, object]) -> Outcome | None:
        raw = projection.get("run_outcome")
        if not isinstance(raw, Mapping) or not raw:
            return None
        return Outcome(
            status=_text(raw.get("status")),
            summary=_text(raw.get("summary")),
            acceptance=raw.get("acceptance", []),
        )

    def _unknown_mutation(
        self,
        projection: Mapping[str, object],
    ) -> Mapping[str, object] | None:
        return next(
            (
                item
                for item in reversed(list(projection.get("operations", [])))
                if isinstance(item, Mapping)
                and (
                    _text(item.get("status")) == "mutation_outcome_unknown"
                    or (
                        _text(item.get("status")) == "blocked"
                        and bool(
                            self.driver.domain_metadata(
                                _text(item.get("operation"))
                            ).get("mutation")
                        )
                    )
                )
            ),
            None,
        )

    @staticmethod
    def _terminal_step(
        projection: Mapping[str, object]
    ) -> tuple[str, Mapping[str, object]] | None:
        states = projection.get("workflow_step_states", {})
        if not isinstance(states, Mapping):
            return None
        return next(
            (
                (str(step_id), state)
                for step_id, state in states.items()
                if isinstance(state, Mapping)
                and _text(state.get("workflow_cycle_id"))
                == _text(projection.get("workflow_cycle_id") or "cycle-1")
                and _text(state.get("status")) in {"failed", "cancelled"}
            ),
            None,
        )

    def _mutation_completed_before_verification(
        self,
        projection: Mapping[str, object],
    ) -> bool:
        states = projection.get("workflow_step_states", {})
        return isinstance(states, Mapping) and any(
            isinstance(state, Mapping)
            and bool(
                self.driver.domain_metadata(_text(state.get("name"))).get(
                    "mutation"
                )
            )
            and _text(state.get("status")) in {"completed", "verified", "succeeded"}
            for state in states.values()
        )

    def _validate_step_artifact(
        self,
        snapshot: Mapping[str, object],
        *,
        operation: str,
    ) -> None:
        domain_metadata = self.driver.domain_metadata(operation)
        phase_type = _text(domain_metadata.get("artifact_phase"))
        artifact_kind = _text(domain_metadata.get("artifact_kind"))
        if not phase_type or not artifact_kind:
            return
        projection = _projection(snapshot)
        if any(
            isinstance(item, Mapping)
            and _text(item.get("operation")) == operation
            and _text(item.get("status")) in {"accepted", "running"}
            for item in projection.get("operations", [])
        ):
            # The bytes were verified before this durable Effect was accepted.
            # Recovery is journal-first and may not require the local artifact.
            return
        phase = next(
            (
                record
                for record in reversed(list(projection.get("phase_records", [])))
                if isinstance(record, Mapping)
                and _text(record.get("phase_type")) == phase_type
                and _text(record.get("status")) == "completed"
            ),
            None,
        )
        if not isinstance(phase, Mapping):
            return
        raw_reference = phase.get("artifact_ref")
        if not isinstance(raw_reference, Mapping) or not raw_reference:
            return
        reference = ArtifactRef.from_public_dict(raw_reference)
        targets = projection.get("targets", [])
        expected_target = ""
        if isinstance(targets, list) and targets and isinstance(targets[0], Mapping):
            expected_target = _text(targets[0].get("address"))
        path = self.artifact_store.resolve(
            reference,
            expected_kinds=(artifact_kind,),
            expected_target=expected_target,
            expected_run_id=self._run_id(snapshot),
        )
        persisted_digest = _text(phase.get("artifact_sha256")).removeprefix(
            "sha256:"
        )
        if persisted_digest and persisted_digest != reference.digest:
            raise ReferenceViolation(
                "persisted artifact digest does not match the ArtifactRef"
            )
        persisted_path = _text(phase.get("artifact_path"))
        if persisted_path and persisted_path != str(path):
            raise ReferenceViolation(
                "persisted artifact path does not match the ArtifactRef"
            )

    @staticmethod
    def _step_summary(
        projection: Mapping[str, object], step: Mapping[str, object]
    ) -> str:
        operation_id = _text(step.get("operation_id"))
        for record in reversed(list(projection.get("phase_records", []))):
            if (
                isinstance(record, Mapping)
                and _text(record.get("operation_id")) == operation_id
            ):
                return _text(record.get("summary"))
        for record in reversed(list(projection.get("operations", []))):
            if (
                isinstance(record, Mapping)
                and _text(record.get("operation_id")) == operation_id
            ):
                return _text(record.get("summary"))
        return "workflow step did not complete"

    def _turn(
        self,
        snapshot: Mapping[str, object],
        *,
        gate: Gate | Mapping[str, object] | None = None,
        observation_ref: ObservationRef | None = None,
        state: str = "",
        next_action: str = "",
    ) -> RunTurn:
        projection = _projection(snapshot)
        turn = project_run_turn(
            projection,
            run_id=self._run_id(snapshot),
            gate=gate,
            state=state,
            next_action=next_action,
            observation_ref=observation_ref,
            facts=(
                self.fact_projector(projection)
                if self.fact_projector is not None
                else ()
            ),
        )
        if self.effect_runner is not None and turn.progress:
            raw_intent = self._active_effect_intent(projection)
            if isinstance(raw_intent, Mapping):
                activity = getattr(self.effect_runner, "activity", None)
                heartbeat = (
                    activity(EffectIntent.from_mapping(raw_intent))
                    if callable(activity)
                    else {}
                )
                if heartbeat:
                    turn = replace(turn, progress={**turn.progress, "heartbeat": heartbeat})
        return turn

    def _record_incident(
        self,
        snapshot: Mapping[str, object],
        *,
        code: str,
        message: str,
        effect_id: str,
        operation_id: str,
    ) -> Mapping[str, object]:
        run_id = self._run_id(snapshot)
        incident = Incident(
            incident_id="incident-" + fingerprint(
                {
                    "run_id": run_id,
                    "code": code,
                    "effect_id": effect_id,
                    "message": message,
                }
            )[:32],
            code=code,
            message=message,
            effect_id=effect_id,
        )
        return self._apply_transition(
            run_id,
            RunTransitionKind.INCIDENT_RAISED,
            {"incident": incident.to_public_dict()},
            operation_id=operation_id,
        )

    def _schedule_unknown_recovery(
        self,
        snapshot: Mapping[str, object],
        *,
        operation_id: str,
    ) -> RunTurn:
        projection = _projection(snapshot)
        unknown = self._unknown_mutation(projection)
        if unknown is None:
            run_id = self._run_id(snapshot)
            terminal = self._outcome(projection) is not None
            raise AgentPreflightError(
                "run has no unknown mutation to reconcile",
                reason=PreflightReason.RECONCILE_PRECONDITION,
                field="command",
                limit={
                    "precondition": "same Run has an unknown mutation outcome"
                },
                context=PreflightContext(run_id=run_id, terminal=terminal),
            )
        effect_id = _text(unknown.get("operation_id"))
        intent = self._effect_intent_for_operation(
            projection,
            effect_id=effect_id,
            operation=_text(unknown.get("operation")),
        )
        if intent is not None and self.effect_runner is not None:
            self._stage((), effect_intent=intent.to_public_dict())
            return self._turn(
                snapshot,
                state="running",
                next_action="reconcile the same durable Effect identity",
            )
        current_incident = self._current_incident(projection)
        if (
            current_incident is not None
            and current_incident.code == "mutation_outcome_unknown"
            and current_incident.effect_id == effect_id
        ):
            return self._turn(snapshot, state="incident")
        snapshot = self._record_incident(
            snapshot,
            code="mutation_outcome_unknown",
            message=(
                "mutation outcome cannot be reconciled without its durable "
                "Effect intent and local EffectRunner"
            ),
            effect_id=effect_id,
            operation_id=f"{operation_id}-incident",
        )
        return self._turn(snapshot, state="incident")

    def _advance(
        self,
        snapshot: Mapping[str, object],
        *,
        task_id: str,
        operation_id: str,
        observation_ref: ObservationRef | None = None,
    ) -> RunTurn:
        for _step_index in range(WORKFLOW_INTERNAL_MAX_STEPS):
            projection = _projection(snapshot)
            outcome = self._outcome(projection)
            if outcome is not None:
                return self._turn(snapshot, observation_ref=observation_ref)
            if _text(projection.get("status")) == "cancelled":
                snapshot = self._apply_transition(
                    self._run_id(snapshot),
                    RunTransitionKind.OUTCOME_RECORDED,
                    {
                        "status": "cancelled",
                        "summary": "run cancelled at the current gate",
                    },
                    operation_id=f"{operation_id}-cancelled-outcome",
                )
                continue
            current_incident = self._current_incident(projection)
            unknown = self._unknown_mutation(projection)
            if (
                unknown is None
                and current_incident is not None
                and current_incident.code == "mutation_outcome_unknown"
            ):
                snapshot = self._apply_transition(
                    self._run_id(snapshot),
                    RunTransitionKind.INCIDENT_RESOLVED,
                    {"incident_id": current_incident.incident_id},
                    operation_id=f"{operation_id}-incident-resolved",
                )
                continue
            if unknown is not None and current_incident is None:
                return self._schedule_unknown_recovery(
                    snapshot,
                    operation_id=f"{operation_id}-auto-reconcile",
                )
            if unknown is not None:
                return self._turn(snapshot, state="incident")
            if current_incident is not None:
                if current_incident.code == "artifact_reference_invalid":
                    try:
                        self._validate_step_artifact(
                            snapshot,
                            operation=current_incident.effect_id,
                        )
                    except (OSError, ReferenceViolation):
                        return self._turn(snapshot, state="incident")
                    snapshot = self._apply_transition(
                        self._run_id(snapshot),
                        RunTransitionKind.INCIDENT_RESOLVED,
                        {"incident_id": current_incident.incident_id},
                        operation_id=f"{operation_id}-incident-resolved",
                    )
                    continue
                if current_incident.code == "domain_execution_failed":
                    snapshot = self._apply_transition(
                        self._run_id(snapshot),
                        RunTransitionKind.INCIDENT_RESOLVED,
                        {
                            "incident_id": current_incident.incident_id,
                            "resolution": "retrying domain preparation",
                        },
                        operation_id=f"{operation_id}-incident-resolved",
                    )
                    continue
                return self._turn(snapshot, state="incident")
            terminal = self._terminal_step(projection)
            if terminal is not None:
                terminal_step_id, terminal_step = terminal
                if (
                    _text(terminal_step.get("name")) == "debug_collect"
                    and _text(terminal_step.get("status")) == "failed"
                    and self._mutation_completed_before_verification(projection)
                ):
                    snapshot = self._apply_transition(
                        self._run_id(snapshot),
                        RunTransitionKind.VERIFICATION_DEFERRED,
                        {"workflow_step_id": terminal_step_id},
                        operation_id=f"{operation_id}-verification-deferred",
                    )
                    return self._turn(
                        snapshot,
                        state="running",
                        next_action="resume the Run to retry fresh target verification",
                    )
                status = _text(terminal_step.get("status"))
                snapshot = self._apply_transition(
                    self._run_id(snapshot),
                    RunTransitionKind.OUTCOME_RECORDED,
                    {
                        "status": status,
                        "summary": self._step_summary(projection, terminal_step),
                    },
                    operation_id=f"{operation_id}-outcome",
                )
                continue
            continuation = _continuation(snapshot)
            if bool(continuation.get("workflow_complete")):
                if requires_diagnosis_record(projection) and not self._diagnosis_accepted(projection):
                    snapshot = self._record_incident(
                        snapshot,
                        code="diagnosis_not_accepted",
                        message="terminal diagnosis requires a verified DiagnosisRecord",
                        effect_id="debug_run",
                        operation_id=f"{operation_id}-diagnosis-incident",
                    )
                    return self._turn(snapshot, state="incident")
                snapshot = self._apply_transition(
                    self._run_id(snapshot),
                    RunTransitionKind.OUTCOME_RECORDED,
                    {"status": "completed", "summary": "workflow completed"},
                    operation_id=f"{operation_id}-outcome",
                )
                continue
            required_phase = _text(continuation.get("required_phase_type"))
            if required_phase:
                if (
                    required_phase == "developer.change"
                    and _text(projection.get("intent")) == "diagnose-and-fix"
                    and not self._diagnosis_accepted(projection)
                ):
                    snapshot = self._record_incident(
                        snapshot,
                        code="diagnosis_not_accepted",
                        message=(
                            "developer.change requires a complete evaluable "
                            "Runtime diagnostic receipt"
                        ),
                        effect_id="debug_run",
                        operation_id=f"{operation_id}-diagnosis-incident",
                    )
                    return self._turn(
                        snapshot,
                        observation_ref=observation_ref,
                        state="incident",
                    )
                gate = self._current_gate(
                    snapshot,
                    operation_id=f"{operation_id}-gate",
                )
                if gate is None:
                    raise GateConflict("Run continuation did not produce a Gate")
                return self._turn(
                    self.driver.run_snapshot(self._run_id(snapshot)),
                    gate=gate,
                    observation_ref=observation_ref,
                    state="waiting_response",
                    next_action="respond to the current Gate",
                )
            required_operation = _text(continuation.get("required_operation"))
            workflow_step_id = _text(
                continuation.get("required_workflow_step_id")
            )
            if required_operation:
                try:
                    self._validate_step_artifact(
                        snapshot,
                        operation=required_operation,
                    )
                except (OSError, ReferenceViolation) as exc:
                    snapshot = self._record_incident(
                        snapshot,
                        code="artifact_reference_invalid",
                        message=f"{type(exc).__name__}: {exc}",
                        effect_id=required_operation,
                        operation_id=f"{operation_id}-incident",
                    )
                    return self._turn(snapshot, state="incident")
                try:
                    prepared = self.driver.prepare_step(
                        self._run_id(snapshot),
                        operation=required_operation,
                        workflow_step_id=workflow_step_id,
                        task_id=task_id,
                    )
                    if prepared is not None:
                        effect_started_at = time.time()
                        domain_metadata = self.driver.domain_metadata(
                            required_operation
                        )
                        effect_owner = _text(
                            continuation.get("required_skill")
                        ) or _text(domain_metadata.get("owner_skill"))
                        if not effect_owner:
                            workflow = _mapping(
                                _projection(snapshot).get("workflow_definition")
                            )
                            steps = workflow.get("steps", [])
                            if isinstance(steps, list):
                                effect_owner = next(
                                    (
                                        _text(item.get("owner"))
                                        for item in steps
                                        if isinstance(item, Mapping)
                                        and _text(item.get("step_id"))
                                        == workflow_step_id
                                        and _text(item.get("owner"))
                                    ),
                                    "",
                                )
                        effect_timeout = prepared.intent.arguments.get(
                            "deadline",
                            domain_metadata.get("timeout_seconds", 600),
                        )
                        if (
                            isinstance(effect_timeout, bool)
                            or not isinstance(effect_timeout, (int, float))
                            or not math.isfinite(effect_timeout)
                            or effect_timeout <= 0
                        ):
                            raise ValueError("Effect deadline must be a positive finite number")
                        self._stage(
                            (
                                RunEvent(
                                    "OperationAccepted",
                                    prepared.accepted_payload,
                                    prepared.intent.effect_id,
                                ),
                                RunEvent(
                                    "OperationStarted",
                                    {},
                                    prepared.intent.effect_id,
                                ),
                                RunEvent(
                                    "OperationProgressed",
                                    {
                                        "status": "running",
                                        "owner": effect_owner,
                                        "phase": workflow_step_id,
                                        "started_at": effect_started_at,
                                        "deadline_at": effect_started_at + effect_timeout,
                                        "next_actions": [
                                            "reattach to the same durable Effect identity"
                                        ],
                                        "case_status": "running",
                                    },
                                    prepared.intent.effect_id,
                                ),
                            ),
                            effect_intent=prepared.intent.to_public_dict(),
                        )
                    snapshot = self.driver.run_snapshot(self._run_id(snapshot))
                except Exception as exc:
                    snapshot = self.driver.run_snapshot(self._run_id(snapshot))
                    if self._unknown_mutation(_projection(snapshot)) is not None:
                        continue
                    terminal = self._terminal_step(_projection(snapshot))
                    if terminal is not None:
                        continue
                    snapshot = self._record_incident(
                        snapshot,
                        code="domain_execution_failed",
                        message=f"{type(exc).__name__}: {exc}",
                        effect_id=required_operation,
                        operation_id=f"{operation_id}-incident",
                    )
                    return self._turn(snapshot, state="incident")
                state = _mapping(
                    _mapping(_projection(snapshot).get("workflow_step_states")).get(
                        workflow_step_id
                    )
                )
                if _text(state.get("status")) in {"accepted", "running"}:
                    return self._turn(
                        snapshot,
                        observation_ref=observation_ref,
                        state="running",
                        next_action="resume the Run to reattach to the current Effect",
                    )
                continue
            snapshot = self._record_incident(
                snapshot,
                code="invalid_run_continuation",
                message="Run has no Gate, operation, or terminal Outcome",
                effect_id="",
                operation_id=f"{operation_id}-incident",
            )
            return self._turn(snapshot, state="incident")
        snapshot = self._record_incident(
            snapshot,
            code="internal_step_limit",
            message="workflow exceeded the internal 64-step progression limit",
            effect_id="",
            operation_id=f"{operation_id}-incident-limit",
        )
        return self._turn(snapshot, state="incident")

    def _submit_gate(
        self,
        command: SubmitGate,
        *,
        task_id: str,
        operation_id: str,
    ) -> RunTurn:
        snapshot = self.driver.run_snapshot(command.run_id)
        _command_id, submission_digest = run_command_identity(
            command,
            operation_id=operation_id,
        )
        prior = self._submission_record(snapshot, command.submission_id)
        if prior is not None:
            self._validate_duplicate_gate(command, prior)
            persisted_gate = next(
                (
                    item
                    for item in _projection(snapshot).get("run_gates", [])
                    if isinstance(item, Mapping)
                    and _text(item.get("gate_id")) == command.gate_id
                    and int(item.get("gate_version", 0)) == command.gate_version
                ),
                None,
            )
            if not isinstance(persisted_gate, Mapping):
                raise GateConflict("duplicate submission Gate is unavailable")
            gate = Gate.from_public_dict(persisted_gate)
            response = self._normalized_response(
                command, gate=gate, projection=_projection(snapshot)
            )
            if _text(prior.get("submission_digest")) != submission_digest:
                raise CommandConflict(
                    "submission_id was already used with different Gate input"
                )
            return self._advance(
                snapshot,
                task_id=task_id,
                operation_id=f"{operation_id}-duplicate",
            )
        incident = self._current_incident(_projection(snapshot))
        if incident is not None:
            raise GateConflict(
                "Run is waiting at an Incident; resolve or cancel the Incident "
                "before submitting a Gate"
            )
        gate = self._current_gate(snapshot, operation_id=f"{operation_id}-gate")
        if gate is None:
            raise GateConflict("Run is not waiting at a Gate")
        self._validate_gate(command, gate)
        response = self._normalized_response(
            command, gate=gate, projection=_projection(snapshot)
        )
        response_operation_id = f"{operation_id}-response"
        phase = self._phase_fact(
            command,
            gate=gate,
            response=response,
            projection=_projection(snapshot),
            operation_id=response_operation_id,
            input_digest=submission_digest,
        )
        self._stage(
            (
                RunEvent(
                    "RunGateSubmitted",
                    {
                        "gate_id": gate.gate_id,
                        "gate_version": gate.version,
                        "schema_digest": gate.schema_digest,
                        "submission_id": command.submission_id,
                        "submission_digest": submission_digest,
                        "actor": phase["producer_identity"],
                        "status": response["status"],
                        "summary": response["summary"],
                        "recorded_at": phase["recorded_at"],
                        "phase": phase,
                    },
                    response_operation_id,
                ),
            )
        )
        snapshot = self.driver.run_snapshot(command.run_id)
        return self._advance(
            snapshot,
            task_id=task_id,
            operation_id=operation_id,
        )

    def _cancel_run(
        self,
        command: CancelRun | CancelIncident,
        *,
        task_id: str,
        operation_id: str,
    ) -> RunTurn:
        snapshot = self.driver.run_snapshot(command.run_id)
        summary: str
        if isinstance(command, CancelIncident):
            incident = self._current_incident(_projection(snapshot))
            if incident is None:
                raise CommandConflict("Run is not waiting at an Incident")
            if incident.incident_id != command.incident_id:
                raise CommandConflict("incident_id does not match the current Incident")
            snapshot = self._apply_transition(
                command.run_id,
                RunTransitionKind.INCIDENT_RESOLVED,
                {"incident_id": incident.incident_id, "resolution": "cancelled"},
                operation_id=f"{operation_id}-incident-resolved",
            )
            snapshot = self._apply_transition(
                command.run_id,
                RunTransitionKind.RUN_CANCELLED,
                {"incident": incident.to_public_dict()},
                operation_id=f"{operation_id}-cancel",
            )
            summary = "run cancelled at the current incident"
        else:
            _command_id, submission_digest = run_command_identity(
                command,
                operation_id=operation_id,
            )
            prior = self._submission_record(snapshot, command.submission_id)
            if prior is not None:
                self._validate_duplicate_gate(command, prior)
                if _text(prior.get("submission_digest")) != submission_digest:
                    raise CommandConflict(
                        "submission_id was already used with different Gate input"
                    )
            else:
                gate = self._current_gate(
                    snapshot, operation_id=f"{operation_id}-gate"
                )
                if gate is None:
                    raise GateConflict("Run is not waiting at a Gate")
                self._validate_gate(command, gate)
                snapshot = self._apply_transition(
                    command.run_id,
                    RunTransitionKind.RUN_CANCELLED,
                    {
                        "gate": gate.to_public_dict(),
                        "submission_id": command.submission_id,
                        "submission_digest": submission_digest,
                    },
                    operation_id=f"{operation_id}-cancel",
                )
            summary = "run cancelled at the current gate"
        snapshot = self._apply_transition(
            command.run_id,
            RunTransitionKind.OUTCOME_RECORDED,
            {
                "status": "cancelled",
                "summary": summary,
            },
            operation_id=f"{operation_id}-outcome",
        )
        return self._turn(snapshot, state="cancelled")

    def _execute_uncommitted(
        self,
        command: RunCommand,
        *,
        task_id: str,
        operation_id: str,
    ) -> RunTurn:
        if isinstance(command, StartRun):
            snapshot = self.driver.start_run(
                command,
                task_id=task_id,
                operation_id=operation_id,
            )
            return self._advance(
                snapshot,
                task_id=task_id,
                operation_id=operation_id,
                observation_ref=command.observation_ref,
            )
        if isinstance(command, (CancelRun, CancelIncident)):
            return self._cancel_run(
                command,
                task_id=task_id,
                operation_id=operation_id,
            )
        if isinstance(command, SubmitGate):
            return self._submit_gate(
                command,
                task_id=task_id,
                operation_id=operation_id,
            )
        if isinstance(command, ReconcileRun):
            snapshot = self.driver.run_snapshot(command.run_id)
            return self._schedule_unknown_recovery(
                snapshot,
                operation_id=operation_id,
            )
        if isinstance(command, ResumeRun):
            snapshot = self.driver.run_snapshot(command.run_id)
            prior_gate = _mapping(_projection(snapshot).get("current_gate"))
            turn = self._advance(
                snapshot,
                task_id=task_id,
                operation_id=operation_id,
            )
            current_gate = (
                turn.gate.to_public_dict()
                if isinstance(turn.gate, Gate)
                else dict(turn.gate)
                if isinstance(turn.gate, Mapping)
                else {}
            )
            same_gate = bool(prior_gate) and all(
                _text(prior_gate.get(name)) == _text(current_gate.get(name))
                for name in ("gate_id", "gate_version", "schema_digest")
            )
            if same_gate and turn.state == "waiting_response":
                return replace(
                    turn,
                    response_required=True,
                    progress={
                        "status": "no_progress",
                        "reason": "response_required",
                    },
                )
            return turn
        raise TypeError(f"unsupported RunCommand: {type(command).__name__}")

    @staticmethod
    def _effect_intent_for_operation(
        projection: Mapping[str, object],
        *,
        effect_id: str,
        operation: str,
    ) -> EffectIntent | None:
        intents = projection.get("effect_intents", [])
        if not isinstance(intents, list):
            return None
        raw_intent = next(
            (
                item
                for item in reversed(intents)
                if isinstance(item, Mapping)
                and _text(item.get("effect_id")) == effect_id
                and _text(item.get("operation")) == operation
            ),
            None,
        )
        return (
            EffectIntent.from_mapping(raw_intent)
            if isinstance(raw_intent, Mapping)
            else None
        )

    @staticmethod
    def _active_effect_intent(
        projection: Mapping[str, object],
    ) -> Mapping[str, object] | None:
        active_ids = {
            _text(item.get("operation_id"))
            for item in projection.get("operations", [])
            if isinstance(item, Mapping)
            and _text(item.get("status")) in EFFECT_SETTLEMENT_STATUSES
        }
        if not active_ids:
            return None
        intents = projection.get("effect_intents", [])
        if not isinstance(intents, list):
            return None
        return next(
            (
                item
                for item in reversed(intents)
                if isinstance(item, Mapping)
                and _text(item.get("effect_id")) in active_ids
            ),
            None,
        )

    def _commit_recovery_incident(self, intent: EffectIntent) -> RunTurn:
        command_id = "incident-" + fingerprint(
            {"run_id": intent.run_id, "effect_id": intent.effect_id}
        )[:32]
        input_digest = fingerprint(
            {
                "schema": "openubmc.semantic-runtime/recovery-incident-v1",
                "run_id": intent.run_id,
                "effect_id": intent.effect_id,
            }
        )
        def build(transaction: RunDecisionDraft) -> RunDecision:
            snapshot = self._record_incident(
                self.driver.run_snapshot(intent.run_id),
                code="mutation_outcome_unknown",
                message=(
                    "Mutation recovery could not prove the durable Effect "
                    "outcome without reapplying it"
                ),
                effect_id=intent.effect_id,
                operation_id=f"{intent.effect_id}-recovery-incident",
            )
            return RunDecision(
                run_id=intent.run_id,
                command_id=command_id,
                input_digest=input_digest,
                expected_revision=transaction.expected_revision,
                events=transaction.events,
                turn=self._turn(snapshot, state="incident"),
            )

        committed = self._commit_run_decision(
            run_id=intent.run_id,
            command_id=command_id,
            input_digest=input_digest,
            build=build,
            retry_conflicts=True,
            exhausted_message="recovery Incident decision could not converge",
        )
        if committed is None:
            raise CommandConflict("recovery Incident decision was not built")
        return committed.turn

    def _settle_effect(
        self,
        committed,
        *,
        task_id: str,
        deadline_at: float,
    ) -> RunTurn:
        if self.effect_runner is None:
            return committed.turn
        projection = committed.projection
        raw_intent = self._active_effect_intent(projection)
        if not isinstance(raw_intent, Mapping):
            return committed.turn
        intent = EffectIntent.from_mapping(raw_intent)
        if (
            committed.turn.state == "incident"
            and not self.effect_runner.has_seen(intent)
            and not (
                committed.turn.incident is not None
                and committed.turn.incident.code == "effect_deadline_exceeded"
            )
        ):
            return committed.turn
        unknown = self._unknown_mutation(projection)
        recovery_required = (
            isinstance(unknown, Mapping)
            and _text(unknown.get("operation_id")) == intent.effect_id
        )
        mode = (
            EffectRunMode.RECOVER
            if recovery_required
            else EffectRunMode.DISPATCH
            if isinstance(committed.effect_intent, Mapping)
            and _text(committed.effect_intent.get("effect_id")) == intent.effect_id
            and not committed.replayed
            else EffectRunMode.REATTACH
            if self.effect_runner.has_seen(intent)
            else EffectRunMode.RECOVER
        )
        recovery_boundary_persisted = False
        reattach_attempt = 0
        while True:
            latest_snapshot = self.driver.run_snapshot(intent.run_id)
            latest_projection = _projection(latest_snapshot)
            if latest_projection.get("run_outcome"):
                return self._turn(latest_snapshot)
            current_incident = _mapping(latest_projection.get("current_incident"))
            if current_incident.get("code") == "effect_deadline_exceeded":
                has_execution = getattr(self.effect_runner, "has_execution", None)
                if callable(has_execution) and not has_execution(intent):
                    # A deadline never authorizes another mutation dispatch.
                    # With no local result to attach, inspect the same journal;
                    # read-only Effects may safely repeat under the same ID.
                    mode = EffectRunMode.RECOVER
            operation = active_operation(latest_projection)
            effect_deadline = operation.get("deadline_at")
            if (
                isinstance(effect_deadline, (int, float))
                and not isinstance(effect_deadline, bool)
                and effect_deadline <= time.time()
                and not bool(
                    getattr(self.effect_runner, "has_settled", lambda _intent: False)(intent)
                )
                and mode is not EffectRunMode.RECOVER
                and operation.get("operation_id") == intent.effect_id
            ):
                return self._commit_deadline_incident(intent)
            latest_active = self._active_effect_intent(latest_projection)
            if not (
                isinstance(latest_active, Mapping)
                and _text(latest_active.get("effect_id")) == intent.effect_id
            ):
                remaining = deadline_at - time.monotonic()
                if remaining <= 0:
                    return self._turn(
                        latest_snapshot,
                        state="running",
                        next_action=(
                            "resume the Run to advance after the completed Effect"
                        ),
                    )
                resume_operation_id = "resume-" + fingerprint(
                    {
                        "run_id": intent.run_id,
                        "effect_id": intent.effect_id,
                    }
                )[:32]
                return self.execute(
                    ResumeRun(
                        intent.run_id,
                        command_id=resume_operation_id,
                        caller_deadline=remaining,
                    ),
                    task_id=task_id,
                    operation_id=resume_operation_id,
                )
            latest_unknown = self._unknown_mutation(latest_projection)
            if (
                isinstance(latest_unknown, Mapping)
                and _text(latest_unknown.get("operation_id")) == intent.effect_id
            ):
                mode = EffectRunMode.RECOVER
            if (
                mode is EffectRunMode.RECOVER
                and intent.effect_class is not EffectClass.READ_ONLY
                and not recovery_boundary_persisted
            ):
                recovery_boundary_persisted = (
                    self._persist_effect_recovery_boundary(intent)
                )
                if not recovery_boundary_persisted:
                    snapshot = self.driver.run_snapshot(intent.run_id)
                    return self._turn(
                        snapshot,
                        state="running",
                        next_action="resume the Run after the settled Effect",
                    )
            settlement_generation = 0
            if intent.effect_class is EffectClass.READ_ONLY:
                operation = next(
                    (
                        item
                        for item in reversed(
                            list(latest_projection.get("operations", []))
                        )
                        if isinstance(item, Mapping)
                        and _text(item.get("operation_id")) == intent.effect_id
                    ),
                    {},
                )
                settlement_generation = int(
                    operation.get("evidence_retry_generation", 0)
                )

            def claim_effect() -> bool:
                claimed_projection = _projection(
                    self.driver.run_snapshot(intent.run_id)
                )
                claimed_active = self._active_effect_intent(claimed_projection)
                if not (
                    isinstance(claimed_active, Mapping)
                    and _text(claimed_active.get("effect_id")) == intent.effect_id
                ):
                    return False
                if claimed_projection.get("run_outcome"):
                    return False
                claimed_operation = active_operation(claimed_projection)
                claimed_deadline = claimed_operation.get("deadline_at")
                if (
                    mode is not EffectRunMode.RECOVER
                    and isinstance(claimed_deadline, (int, float))
                    and not isinstance(claimed_deadline, bool)
                    and claimed_deadline <= time.time()
                ):
                    return False
                if intent.effect_class is not EffectClass.READ_ONLY:
                    claimed_unknown = self._unknown_mutation(claimed_projection)
                    if (
                        mode is not EffectRunMode.RECOVER
                        and isinstance(claimed_unknown, Mapping)
                        and _text(claimed_unknown.get("operation_id"))
                        == intent.effect_id
                    ):
                        return False
                    return True
                claimed_operation = next(
                    (
                        item
                        for item in reversed(
                            list(claimed_projection.get("operations", []))
                        )
                        if isinstance(item, Mapping)
                        and _text(item.get("operation_id")) == intent.effect_id
                    ),
                    {},
                )
                return int(
                    claimed_operation.get("evidence_retry_generation", 0)
                ) == settlement_generation

            execution = self.effect_runner.ensure(
                intent,
                mode=mode,
                settlement_generation=settlement_generation,
                claim=claim_effect,
            )
            if execution is None:
                continue
            recovery_attempted = (
                execution.mode is EffectRunMode.RECOVER
                and intent.effect_class is not EffectClass.READ_ONLY
            )
            remaining = deadline_at - time.monotonic()
            settled = bool(
                getattr(self.effect_runner, "has_settled", lambda _: False)(intent)
            )
            if (
                not settled and mode is not EffectRunMode.RECOVER
                and isinstance(effect_deadline, (int, float))
                and not isinstance(effect_deadline, bool)
            ):
                remaining = min(remaining, effect_deadline - time.time())
            if remaining <= 0 and not settled:
                if (
                    mode is not EffectRunMode.RECOVER
                    and isinstance(effect_deadline, (int, float))
                    and not isinstance(effect_deadline, bool)
                    and effect_deadline <= time.time()
                ):
                    return self._commit_deadline_incident(intent)
                snapshot = self.driver.run_snapshot(intent.run_id)
                return self._turn(
                    snapshot,
                    state="running",
                    next_action="resume the Run to reattach to the current Effect",
                )
            if not self.effect_runner.wait(execution, remaining):
                if (
                    mode is not EffectRunMode.RECOVER
                    and isinstance(effect_deadline, (int, float))
                    and not isinstance(effect_deadline, bool)
                    and effect_deadline <= time.time()
                ):
                    return self._commit_deadline_incident(intent)
                snapshot = self.driver.run_snapshot(intent.run_id)
                return self._turn(
                    snapshot,
                    state="running",
                    next_action="resume the Run to reattach to the current Effect",
                )
            committed = self._commit_effect_result(
                intent,
                execution,
                settlement_mode=(
                    EffectSettlementMode.RECONCILE
                    if recovery_attempted
                    else EffectSettlementMode.DISPATCH
                ),
            )
            snapshot = {
                "projection": committed.projection,
                "continuation": self.driver.run_snapshot(intent.run_id).get(
                    "continuation", {}
                ),
            }
            projection = committed.projection
            active = self._active_effect_intent(projection)
            effect_remains_active = (
                isinstance(active, Mapping)
                and _text(active.get("effect_id")) == intent.effect_id
            )
            unknown = self._unknown_mutation(projection)
            if recovery_attempted and unknown is not None:
                incident = self._commit_recovery_incident(intent)
                self.effect_runner.acknowledge(
                    intent,
                    execution,
                    retain_for_reattach=False,
                )
                return incident
            self.effect_runner.acknowledge(
                intent,
                execution,
                retain_for_reattach=effect_remains_active,
            )
            if effect_remains_active:
                if (
                    isinstance(unknown, Mapping)
                    and _text(unknown.get("operation_id")) == intent.effect_id
                ):
                    mode = EffectRunMode.RECOVER
                    continue
                mode = EffectRunMode.REATTACH
                delay = min(1.0, 0.2 * (2 ** min(reattach_attempt, 3)))
                reattach_attempt += 1
                remaining = deadline_at - time.monotonic()
                if remaining <= delay:
                    return self._turn(
                        snapshot,
                        state="running",
                        next_action=(
                            "resume the Run to reattach to the current Effect"
                        ),
                    )
                time.sleep(delay)
                continue
            remaining = deadline_at - time.monotonic()
            if remaining <= 0:
                return self._turn(
                    snapshot,
                    state="running",
                    next_action="resume the Run to advance after the completed Effect",
                )
            resume_operation_id = "resume-" + fingerprint(
                {
                    "run_id": intent.run_id,
                    "effect_id": intent.effect_id,
                }
            )[:32]
            return self.execute(
                ResumeRun(
                    intent.run_id,
                    command_id=resume_operation_id,
                    caller_deadline=remaining,
                ),
                task_id=task_id,
                operation_id=resume_operation_id,
            )

    def _commit_deadline_incident(self, intent: EffectIntent) -> RunTurn:
        command_id = "effect-deadline-" + fingerprint(
            {"run_id": intent.run_id, "effect_id": intent.effect_id}
        )[:32]
        input_digest = fingerprint({"effect_id": intent.effect_id, "reason": "deadline"})

        def build(transaction: RunDecisionDraft) -> RunDecision | None:
            snapshot = self.driver.run_snapshot(intent.run_id)
            projection = _projection(snapshot)
            current = self._active_effect_intent(projection)
            incident = _mapping(projection.get("current_incident"))
            operation = active_operation(projection)
            effect_deadline = operation.get("deadline_at")
            if (
                projection.get("run_outcome")
                or not isinstance(current, Mapping)
                or current.get("effect_id") != intent.effect_id
                or operation.get("operation_id") != intent.effect_id
                or not isinstance(effect_deadline, (int, float))
                or isinstance(effect_deadline, bool)
                or effect_deadline > time.time()
                or (incident and incident.get("code") != "effect_deadline_exceeded")
                or bool(getattr(self.effect_runner, "has_settled", lambda _: False)(intent))
            ):
                return None
            snapshot = self._record_incident(
                snapshot,
                code="effect_deadline_exceeded",
                message=(
                    "Effect exceeded its durable deadline; no replacement execution is admitted. "
                    "Resume to inspect the existing result; an uncertain mutation requires "
                    "read-only reconciliation of the same MutationJournal."
                ),
                effect_id=intent.effect_id,
                operation_id=command_id,
            )
            return RunDecision(
                run_id=intent.run_id, command_id=command_id,
                input_digest=input_digest, expected_revision=transaction.expected_revision,
                events=transaction.events, turn=self._turn(snapshot, state="incident"),
            )

        committed = self._commit_run_decision(
            run_id=intent.run_id, command_id=command_id, input_digest=input_digest,
            build=build, retry_conflicts=True,
            exhausted_message="Effect deadline Incident could not converge",
        )
        if committed is None:
            return self._turn(self.driver.run_snapshot(intent.run_id))
        return committed.turn

    def _commit_effect_result(
        self,
        intent: EffectIntent,
        execution: EffectExecution,
        *,
        settlement_mode: EffectSettlementMode,
    ) -> CommittedRunDecision:
        future = execution.future
        error = future.exception()
        result = None if error is not None else future.result()
        outcome_identity: dict[str, object] = {
            "schema": "openubmc.semantic-runtime/effect-result-v1",
            "run_id": intent.run_id,
            "effect_id": intent.effect_id,
            "settlement_mode": settlement_mode.value,
        }
        if intent.effect_class is EffectClass.READ_ONLY:
            outcome_identity["evidence_retry_generation"] = int(
                execution.settlement_generation
            )
        if error is None:
            outcome_identity["result"] = result
        else:
            outcome_identity["error"] = {
                "type": type(error).__name__,
                "code": str(getattr(error, "code", "")),
                "message": str(error),
                "recovery_status": (
                    dict(recovery_status)
                    if isinstance(
                        (recovery_status := getattr(error, "recovery_status", None)),
                        Mapping,
                    )
                    else None
                ),
                "mutation_outcome": str(
                    getattr(error, "mutation_outcome", "")
                ),
                "mutation_journal_stage": str(
                    getattr(error, "mutation_journal_stage", "")
                ),
                "mutation_effects_started": bool(
                    getattr(error, "mutation_effects_started", False)
                ),
            }
        input_digest = fingerprint(outcome_identity)
        command_id = "effect-result-" + input_digest[:32]
        def build(transaction: RunDecisionDraft) -> RunDecision:
            current = _projection(self.driver.run_snapshot(intent.run_id))
            incident = _mapping(current.get("current_incident"))
            transition = self.driver.effect_transition(
                intent,
                result=result,
                error=error,
                settlement_mode=settlement_mode,
            )
            self._stage(transition.events)
            settled = any(
                event.kind in {"OperationTerminal", "OperationReconciled"}
                and _text(event.payload.get("status")) not in EFFECT_SETTLEMENT_STATUSES
                for event in transition.events
            )
            if (
                incident.get("code") == "effect_deadline_exceeded"
                and incident.get("effect_id") == intent.effect_id
                and settled
            ):
                self._stage((RunEvent(
                    "RunIncidentResolved",
                    {
                        "incident_id": incident.get("incident_id"),
                        "resolution": "existing Effect settled",
                    },
                    intent.effect_id,
                ),))
            snapshot = self.driver.run_snapshot(intent.run_id)
            return RunDecision(
                run_id=intent.run_id,
                command_id=command_id,
                input_digest=input_digest,
                expected_revision=transaction.expected_revision,
                events=transaction.events,
                turn=self._turn(
                    snapshot,
                    state="running",
                    next_action="resume the Run after the settled Effect",
                ),
            )

        committed = self._commit_run_decision(
            run_id=intent.run_id,
            command_id=command_id,
            input_digest=input_digest,
            build=build,
            retry_conflicts=True,
            exhausted_message="Effect result decision could not converge",
        )
        if committed is None:
            raise CommandConflict("Effect result decision was not built")
        return committed

    def _persist_effect_recovery_boundary(self, intent: EffectIntent) -> bool:
        command_id = "recover-" + fingerprint(
            {"run_id": intent.run_id, "effect_id": intent.effect_id}
        )[:32]
        input_digest = fingerprint(
            {
                "schema": "openubmc.semantic-runtime/effect-recovery-v1",
                "run_id": intent.run_id,
                "effect_id": intent.effect_id,
            }
        )
        def build(transaction: RunDecisionDraft) -> RunDecision | None:
            snapshot = self.driver.run_snapshot(intent.run_id)
            projection = _projection(snapshot)
            current = next(
                (
                    item
                    for item in reversed(list(projection.get("operations", [])))
                    if isinstance(item, Mapping)
                    and _text(item.get("operation_id")) == intent.effect_id
                ),
                None,
            )
            if not isinstance(current, Mapping):
                raise CommandConflict(
                    "persisted Effect is missing from its Run projection"
                )
            if _text(current.get("operation")) != intent.operation:
                raise CommandConflict(
                    "persisted Effect identity is bound to another operation"
                )
            if _text(current.get("status")) not in EFFECT_SETTLEMENT_STATUSES:
                return None
            return RunDecision(
                run_id=intent.run_id,
                command_id=command_id,
                input_digest=input_digest,
                expected_revision=transaction.expected_revision,
                events=transaction.events,
                turn=self._turn(
                    snapshot,
                    state="running",
                    next_action="reconcile the same durable Effect identity",
                ),
                effect_intent=intent.to_public_dict(),
            )

        return self._commit_run_decision(
            run_id=intent.run_id,
            command_id=command_id,
            input_digest=input_digest,
            build=build,
            retry_conflicts=True,
            exhausted_message="Effect recovery decision could not converge",
        ) is not None

    def _bind_reconcile_command(self, command: ReconcileRun) -> ReconcileRun:
        projection = _projection(self.driver.run_snapshot(command.run_id))
        unknown = self._unknown_mutation(projection)
        raw_intents = projection.get("effect_intents", [])
        intents = raw_intents if isinstance(raw_intents, list) else []
        effect_id = (
            _text(unknown.get("operation_id"))
            if isinstance(unknown, Mapping)
            else next(
                (
                    _text(item.get("effect_id"))
                    for item in reversed(intents)
                    if isinstance(item, Mapping)
                    and _text(item.get("effect_class")) != EffectClass.READ_ONLY.value
                    and _text(item.get("effect_id"))
                ),
                "",
            )
        )
        if not effect_id:
            return command
        if command.effect_id and command.effect_id != effect_id:
            raise CommandConflict("reconcile command is bound to another Effect identity")
        return replace(
            command,
            effect_id=effect_id,
            command_id="reconcile-"
            + fingerprint(
                {"run_id": command.run_id, "effect_id": effect_id}
            )[:32],
            input_digest="",
        )

    def execute(
        self,
        command: RunCommand,
        *,
        task_id: str,
        operation_id: str,
    ) -> RunTurn:
        deadline_at = time.monotonic() + float(
            getattr(command, "caller_deadline", 120.0)
        )
        if isinstance(command, ReconcileRun):
            command = self._bind_reconcile_command(command)
        command_id, input_digest = run_command_identity(
            command,
            operation_id=operation_id,
        )
        run_id = run_id_for_command(command, command_id=command_id)
        try:
            replayed = self.run_store.load(
                run_id,
                command_id=command_id,
                input_digest=input_digest,
                task_id=task_id,
            ).decision
        except RunDecisionConflict as exc:
            if isinstance(command, (SubmitGate, CancelRun)):
                snapshot = self.driver.run_snapshot(command.run_id)
                prior = self._submission_record(snapshot, command.submission_id)
                if prior is not None:
                    self._validate_duplicate_gate(command, prior)
            raise CommandConflict(str(exc)) from exc
        if replayed is not None:
            initial_revision = int(replayed.projection.get("revision", -1))
            turn = self._settle_effect(
                replayed,
                task_id=task_id,
                deadline_at=deadline_at,
            )
            if isinstance(
                command,
                (SubmitGate, CancelRun, CancelIncident, ReconcileRun),
            ):
                current = _projection(self.driver.run_snapshot(run_id))
                if int(current.get("revision", -1)) == initial_revision:
                    return replace(
                        turn,
                        progress={
                            "status": "no_progress",
                            "reason": "unchanged_command_replayed",
                        },
                    )
            return turn

        no_progress_turn: RunTurn | None = None

        def build(transaction: RunDecisionDraft) -> RunDecision | None:
            nonlocal no_progress_turn
            turn = self._execute_uncommitted(
                command,
                task_id=task_id,
                operation_id=operation_id,
            )
            if turn.run_id != run_id:
                raise CommandConflict(
                    "Run command produced a Turn for a different Run"
                )
            if (
                isinstance(command, ResumeRun)
                and _text(_mapping(turn.progress).get("status")) == "no_progress"
                and not transaction.events
                and transaction.effect_intent is None
            ):
                no_progress_turn = turn
                return None
            return RunDecision(
                run_id=run_id,
                command_id=command_id,
                input_digest=input_digest,
                expected_revision=transaction.expected_revision,
                events=transaction.events,
                turn=turn,
                effect_intent=transaction.effect_intent,
            )

        committed = self._commit_run_decision(
            run_id=run_id,
            command_id=command_id,
            input_digest=input_digest,
            build=build,
            retry_conflicts=isinstance(command, ResumeRun),
            exhausted_message="RunDecision could not converge",
            task_id=task_id,
        )
        if committed is None:
            if no_progress_turn is not None:
                return no_progress_turn
            raise CommandConflict("RunDecision was not built")

        return self._settle_effect(
            committed,
            task_id=task_id,
            deadline_at=deadline_at,
        )


class SemanticRuntime(SemanticRuntimePort):
    """Compose ObservationEngine and RunEngine behind the two-method seam."""

    def __init__(
        self,
        observation_engine: ObservationEngine,
        run_engine: RunEngine,
    ) -> None:
        self._observation_engine = observation_engine
        self._run_engine = run_engine

    def observe(
        self,
        query: ObservationQuery,
        *,
        task_id: str,
        operation_id: str,
    ) -> ObservationResult:
        return self._observation_engine.observe(
            query,
            task_id=task_id,
            operation_id=operation_id,
        )

    def execute(
        self,
        command: RunCommand,
        *,
        task_id: str,
        operation_id: str,
    ) -> RunTurn:
        return self._run_engine.execute(
            command,
            task_id=task_id,
            operation_id=operation_id,
        )
