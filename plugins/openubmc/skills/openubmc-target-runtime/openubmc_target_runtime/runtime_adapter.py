"""Adapt composed Runtime Modules to the typed RunEngine driver seam."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from .agent_gateway import ResultProjector
from .capability import DomainExecutor, EffectClass
from .catalog import OperationCatalog
from .context_runtime import (
    AUTOMATIC_OBSERVATION_REUSE_MAX_AGE_SECONDS,
    ContextRuntime,
    EvidenceUnavailable,
    IdempotencyConflict,
)
from .effect_runner import EffectIntent, EffectSettlementMode, PreparedEffect
from .observation import (
    observation_completion_window_matches,
    observation_reusable,
    observation_target_scope_known,
    observation_target_scope_matches,
    qualify_observation,
    selected_scope_complete,
)
from .run_engine import RunTransition
from .semantic_runtime import (
    CancelRun,
    CommandConflict,
    Gate,
    GateConflict,
    ObservationQuery,
    ObservationRef,
    StartRun,
    SubmitGate,
    run_command_semantic_input,
    run_id_for_command,
)


class DomainRuntimePort(Protocol):
    def observe_direct(
        self,
        operation: str,
        arguments: Mapping[str, object],
        *,
        task_id: str,
        operation_id: str,
    ) -> Mapping[str, object]: ...

    def execute_effect(
        self,
        intent: EffectIntent,
        *,
        recovery: bool = False,
    ) -> Mapping[str, object]: ...


def _mapping_or_empty(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


class RuntimeSemanticAdapter:
    """Translate typed Runtime commands without transport knowledge."""

    def __init__(
        self,
        *,
        catalog: OperationCatalog,
        context_runtime: ContextRuntime,
        domain_executor: DomainExecutor,
        domain_runtime: DomainRuntimePort,
        agent_projector: ResultProjector,
    ) -> None:
        self.catalog = catalog
        self.context_runtime = context_runtime
        self.domain_executor = domain_executor
        self.domain_runtime = domain_runtime
        self.agent_projector = agent_projector

    @staticmethod
    def _reattach_gate_submission(
        snapshot: Mapping[str, object],
        command: SubmitGate | CancelRun,
        *,
        gate: Gate,
        submission_digest: str,
    ) -> bool:
        projection = _mapping_or_empty(snapshot.get("projection"))
        submissions = projection.get("gate_submissions", [])
        prior = (
            next(
                (
                    item
                    for item in reversed(submissions)
                    if isinstance(item, Mapping)
                    and str(item.get("submission_id", ""))
                    == command.submission_id
                ),
                None,
            )
            if isinstance(submissions, list)
            else None
        )
        if not isinstance(prior, Mapping):
            return False
        if (
            str(prior.get("gate_id", "")) != gate.gate_id
            or int(prior.get("gate_version", 0)) != gate.version
            or str(prior.get("schema_digest", "")).removeprefix("sha256:")
            != gate.schema_digest
        ):
            raise GateConflict(
                "concurrent submission targets a different Gate binding"
            )
        if str(prior.get("submission_digest", "")) != submission_digest:
            raise CommandConflict(
                "submission_id was concurrently used with different Gate input"
            )
        return True

    def observe_once(
        self,
        query: ObservationQuery,
        *,
        assured: bool,
        task_id: str,
        operation_id: str,
        prior: Mapping[str, object] | None = None,
    ) -> Mapping[str, object]:
        arguments = query.runtime_arguments(assured=assured)
        if isinstance(prior, Mapping):
            arguments["_agent_prior_observation"] = dict(prior)
        return self.domain_runtime.observe_direct(
            "debug_collect",
            arguments,
            task_id=task_id,
            operation_id=operation_id,
        )

    def run_snapshot(self, run_id: str) -> Mapping[str, object]:
        projection = self.context_runtime.read_case(run_id)
        return {
            "projection": projection,
            "continuation": self.context_runtime.continuation_for(projection),
        }

    def domain_metadata(self, operation: str) -> Mapping[str, object]:
        return self.domain_executor.metadata_for(operation)

    def domain_artifact_metadata(
        self,
        phase_type: str,
    ) -> Mapping[str, object]:
        return self.domain_executor.artifact_metadata_for_phase(phase_type)

    def persist_observation(
        self,
        raw: Mapping[str, object],
        *,
        query: ObservationQuery,
        assurance: str,
        task_id: str = "",
    ) -> Mapping[str, object]:
        return self.context_runtime.persist_observation(
            raw,
            scope=query.to_public_dict(),
            assurance=assurance,
            task_id=task_id,
        )

    def start_run(
        self,
        command: StartRun,
        *,
        task_id: str,
        operation_id: str,
    ) -> Mapping[str, object]:
        start_input = run_command_semantic_input(command)
        run_id = run_id_for_command(command, command_id=command.command_id)
        try:
            existing = self.context_runtime.reattach_semantic_run(
                run_id,
                task_id=task_id,
                start_command_id=command.command_id,
                start_input_digest=command.input_digest,
            )
        except IdempotencyConflict as exc:
            raise CommandConflict(str(exc)) from exc
        if existing is not None:
            return self.run_snapshot(run_id)
        if command.entry_operation and command.intent == "diagnosis-only":
            entry_policy = self.domain_executor.policy_for(
                command.entry_operation
            )
            if entry_policy.effect_class is not EffectClass.READ_ONLY:
                raise ValueError(
                    "entry_operation must select a READ_ONLY Domain Pack"
                )
        arguments: dict[str, object] = {
            "intent": command.intent,
            "final_purpose": command.purpose,
            "include_closeout_bundle": False,
        }
        if command.targets:
            arguments["targets"] = [
                target.to_public_dict() for target in command.targets
            ]
        else:
            arguments["ip"] = command.target
        selected_entry = command.entry_operation
        if command.intent == "upgrade-and-verify" and len(command.targets) > 1:
            if selected_entry not in {"", "upgrade_run", "upgrade_batch"}:
                raise ValueError("multi-target upgrade requires the Upgrade batch Domain Pack")
            self.domain_executor.policy_for("upgrade_batch")
            selected_entry = "upgrade_batch"
        if selected_entry:
            arguments["_context_entry_operation"] = selected_entry
            arguments["entry_arguments"] = dict(command.entry_arguments or {})
        if command.delivery_strategy:
            arguments["delivery_strategy"] = command.delivery_strategy
        seeded_raw: Mapping[str, object] | None = None
        selected_ref = command.observation_ref
        if (
            selected_ref is None and not command.targets
            and command.intent in {"diagnosis-only", "diagnose-and-fix"}
            and command.entry_operation in {"", "debug_run"}
            and not command.entry_arguments
        ):
            selected_ref = self.reusable_observation_ref(
                target=command.target, task_id=task_id, operation_id=operation_id,
            )
        if selected_ref is not None:
            source = selected_ref.to_source_dict()
            stored = self.context_runtime.load_observation(source)
            if stored.get("reusable", True) is not True:
                raise ValueError(
                    "ObservationRef does not contain a temporally coherent live scope"
                )
            fresh_until = stored.get("fresh_until", 0)
            if (
                isinstance(fresh_until, bool)
                or not isinstance(fresh_until, (int, float))
                or float(fresh_until) < self.context_runtime.clock()
            ):
                raise ValueError(
                    "ObservationRef is older than the Runtime reuse window"
                )
            stored_scope = _mapping_or_empty(stored.get("scope"))
            query = ObservationQuery.from_query(stored_scope)
            if query.target != command.target:
                raise ValueError("ObservationRef target does not match the Run target")
            if selected_ref.target != command.target:
                raise ValueError(
                    "ObservationRef target metadata does not match the Run"
                )
            raw = _mapping_or_empty(stored.get("raw"))
            expected = self.agent_projector.observation(
                raw,
                query,
                assurance=str(stored.get("assurance", "fast")),
                source=source,
            )
            if expected.get("status") != "complete":
                raise ValueError("only a complete ObservationRef can seed a Run")
            seeded_raw = raw
            # This Runtime selection is persisted separately from the original
            # caller digest, so a replay never selects a different observation.
            start_input["observation_ref"] = selected_ref.to_public_dict()

        try:
            projection = self.context_runtime.open_semantic_run(
                arguments,
                task_id=task_id,
                run_id=run_id,
                start_command_id=command.command_id,
                start_input_digest=command.input_digest,
                start_input=start_input,
            )
        except IdempotencyConflict as exc:
            raise CommandConflict(str(exc)) from exc
        if seeded_raw is not None:
            prepared, derived_id = (
                self.context_runtime.prepare_semantic_run_operation(
                    projection,
                    operation="debug_run",
                    workflow_step_id=str(
                        self.context_runtime.continuation_for(projection).get(
                            "required_workflow_step_id", ""
                        )
                    ),
                )
            )
            self.context_runtime.invoke_domain(
                self.catalog.require("debug_run"),
                prepared,
                task_id=run_id,
                operation_id=derived_id,
                executor=lambda: seeded_raw,
            )
        return self.run_snapshot(run_id)

    def reusable_observation_ref(
        self, *, target: str, task_id: str, operation_id: str,
        require_temporal_match: bool = False,
    ) -> ObservationRef | None:
        source = self.context_runtime.find_reusable_observation(task_id=task_id, target=target)
        if source is None:
            return None
        try:
            stored = self.context_runtime.load_observation(source)
            raw = _mapping_or_empty(stored.get("raw"))
            query = ObservationQuery.from_query(_mapping_or_empty(stored.get("scope")))
            if not observation_target_scope_known(raw) or not selected_scope_complete(raw, query):
                return None
            projected = self.agent_projector.observation(
                raw, query, assurance=str(stored.get("assurance", "fast")), source=source,
            )
            if projected.get("status") != "complete":
                return None
            probe_query = ObservationQuery.from_query({
                "target": target,
                "selectors": [{"id": "runtime-scope", "kind": "capability", "names": ["ssh"]}],
            })
            probe = self.observe_once(
                probe_query, assured=False, task_id=task_id,
                operation_id=f"{operation_id}-observation-scope",
            )
            probe = qualify_observation(probe, probe_query, scope_complete=selected_scope_complete(probe, probe_query))
            if (
                not observation_reusable(probe)
                or not observation_target_scope_known(probe)
                or not observation_target_scope_matches(raw, probe)
                or (require_temporal_match and not observation_completion_window_matches(raw, probe))
                or stored.get("fresh_until", 0) < self.context_runtime.clock()
                or not 0 <= self.context_runtime.clock() - stored.get("persisted_at", 0) <= AUTOMATIC_OBSERVATION_REUSE_MAX_AGE_SECONDS
            ):
                return None
            return ObservationRef.from_public_dict(source)
        except (EvidenceUnavailable, ConnectionError, OSError, TimeoutError, ValueError, TypeError):
            return None

    def reusable_observation(
        self, *, target: str, task_id: str, operation_id: str
    ) -> Mapping[str, object] | None:
        reference = self.reusable_observation_ref(
            target=target, task_id=task_id, operation_id=operation_id,
            require_temporal_match=True,
        )
        if reference is None:
            return None
        source = reference.to_source_dict()
        try:
            return {**self.context_runtime.load_observation(source), "source": reference.to_public_dict()}
        except (EvidenceUnavailable, OSError, ValueError):
            return None

    def derive_closeout(
        self,
        run_id: str,
        *,
        terminal_status: str,
    ) -> Mapping[str, object]:
        return self.context_runtime.derive_run_closeout(
            run_id,
            terminal_status=terminal_status,
        )

    def read_evidence(
        self,
        run_id: str,
        evidence_id: str,
        *,
        target_id: str,
    ) -> Mapping[str, object]:
        return self.context_runtime.read_evidence(
            run_id,
            evidence_id,
            target_id=target_id,
        )

    def prepare_step(
        self,
        run_id: str,
        *,
        operation: str,
        workflow_step_id: str,
        task_id: str,
    ) -> PreparedEffect | None:
        projection = self.context_runtime.read_case(run_id)
        arguments, derived_id = (
            self.context_runtime.prepare_semantic_run_operation(
                projection,
                operation=operation,
                workflow_step_id=workflow_step_id,
            )
        )
        policy = self.domain_executor.policy_for(operation)
        return self.context_runtime.prepare_semantic_run_effect(
            run_id,
            operation=operation,
            arguments=arguments,
            operation_id=derived_id,
            effect_class=policy.effect_class,
        )

    def execute_effect(self, intent: EffectIntent) -> Mapping[str, object]:
        return self.domain_runtime.execute_effect(intent)

    def recover_effect(self, intent: EffectIntent) -> Mapping[str, object]:
        if intent.effect_class is EffectClass.READ_ONLY:
            return self.execute_effect(intent)
        return self.domain_runtime.execute_effect(intent, recovery=True)

    def effect_transition(
        self,
        intent: EffectIntent,
        *,
        result: Mapping[str, object] | None,
        error: BaseException | None,
        settlement_mode: EffectSettlementMode,
    ) -> RunTransition:
        return RunTransition(
            events=self.context_runtime.prepare_effect_transition(
                intent,
                result=result,
                error=error,
                settlement_mode=settlement_mode,
            )
        )
