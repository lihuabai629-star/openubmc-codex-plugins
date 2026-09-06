"""Typed task intent, handoff, and cross-domain workflow coordination."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
import re
import threading
from typing import Generic, TypeVar

from .contracts import (
    RUNTIME_API_VERSION,
    CredentialSelector,
    TargetSpec,
    _fingerprint,
)
from .mutation import TaskAuthorizationPolicy
from .operation_contracts import DEFAULT_OPERATION_CONTRACTS
from .workflow import DEFAULT_WORKFLOW_REGISTRY


ORCHESTRATION_SCHEMA = f"{RUNTIME_API_VERSION}/task-orchestration"
_TARGET_ROLES = frozenset({"reference", "candidate", "symmetric"})
_DOMAINS = frozenset(DEFAULT_OPERATION_CONTRACTS.domain_to_entry_operation())
_OUTCOME_STATUSES = frozenset(
    {"succeeded", "modified", "verified", "failed", "not_executed"}
)

ValueT = TypeVar("ValueT")


def enforce_fresh_verification(arguments: Mapping[str, object]) -> dict[str, object]:
    """Return workflow arguments with freshness collection enabled."""

    selected = dict(arguments)
    selected["no_freshness"] = False
    return selected


@dataclass(frozen=True)
class WorkflowStep:
    domain: str
    phase: str
    canonical_name: str = ""
    kind: str = "operation"

    @property
    def key(self) -> str:
        return f"{self.domain}:{self.phase}"

    def to_public_dict(self) -> dict[str, str]:
        return {"domain": self.domain, "phase": self.phase, "key": self.key}


@dataclass(frozen=True)
class TaskTargetBinding:
    """One role-bound target with secret-free credential selectors."""

    target_id: str
    role: str
    target: TargetSpec
    credential_selectors: tuple[CredentialSelector, ...]

    def __post_init__(self) -> None:
        target_id = self.target_id.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", target_id):
            raise ValueError("target_id must be a safe 1-128 character identifier")
        role = self.role.strip().lower()
        if role not in _TARGET_ROLES:
            raise ValueError("target role must be reference, candidate, or symmetric")
        if not self.credential_selectors:
            raise ValueError("target binding requires at least one credential selector")
        transports = [selector.transport for selector in self.credential_selectors]
        if len(transports) != len(set(transports)):
            raise ValueError("target binding may contain only one selector per transport")
        for selector in self.credential_selectors:
            self.target.validate_credential_selector(selector)
        object.__setattr__(self, "target_id", target_id)
        object.__setattr__(self, "role", role)

    def selector(self, transport: str) -> CredentialSelector:
        for selector in self.credential_selectors:
            if selector.transport == transport:
                return selector
        raise KeyError(f"target {self.target_id} has no {transport} credential selector")

    def to_public_dict(self) -> dict[str, object]:
        return {
            "target_id": self.target_id,
            "role": self.role,
            "target": self.target.to_public_dict(),
            "credential_selectors": {
                selector.transport: selector.to_public_dict()
                for selector in self.credential_selectors
            },
        }


class TaskIntentKind(str, Enum):
    DIAGNOSIS_ONLY = "diagnosis-only"
    DIAGNOSE_AND_FIX = "diagnose-and-fix"
    LIVE_PATCH = "live-patch"
    ROLLBACK = "rollback"
    UPGRADE_AND_VERIFY = "upgrade-and-verify"
    BUNDLE_AND_DIAGNOSE = "bundle-and-diagnose"

    @classmethod
    def parse(cls, value: str) -> "TaskIntentKind":
        normalized = str(value).strip().lower().replace("_", "-")
        aliases = {
            "diagnose": cls.DIAGNOSIS_ONLY,
            "debug-only": cls.DIAGNOSIS_ONLY,
            "diagnosis-only": cls.DIAGNOSIS_ONLY,
            "verify-delivery": cls.DIAGNOSIS_ONLY,
            "diagnose-and-fix": cls.DIAGNOSE_AND_FIX,
            "live-patch": cls.LIVE_PATCH,
            "rollback": cls.ROLLBACK,
            "upgrade-and-verify": cls.UPGRADE_AND_VERIFY,
            "bundle-and-diagnose": cls.BUNDLE_AND_DIAGNOSE,
        }
        try:
            return aliases[normalized]
        except KeyError as exc:
            raise ValueError(f"unsupported task intent: {value}") from exc

    @classmethod
    def public_values(cls) -> list[str]:
        return [kind.value for kind in cls]


class DeliveryStrategy(str, Enum):
    SOURCE_ONLY = "source-only"
    LIVE_PATCH = "live-patch"
    BUILD_UPGRADE = "build-upgrade"

    @classmethod
    def parse(cls, value: str | None) -> "DeliveryStrategy":
        normalized = str(value or "source-only").strip().lower().replace("_", "-")
        try:
            return cls(normalized)
        except ValueError as exc:
            raise ValueError(f"unsupported delivery strategy: {value}") from exc

    @classmethod
    def public_values(cls) -> list[str]:
        return [strategy.value for strategy in cls]


def _canonical_workflow_steps(
    intent: TaskIntentKind,
    entry_domain: str,
    delivery_strategy: DeliveryStrategy | None = None,
) -> tuple[WorkflowStep, ...]:
    definition = DEFAULT_WORKFLOW_REGISTRY.resolve(
        intent=intent.value,
        entry_domain=entry_domain,
        delivery_strategy=(
            delivery_strategy.value if delivery_strategy is not None else ""
        ),
    )
    steps: list[WorkflowStep] = []
    for step in definition.steps:
        if step.kind == "operation":
            contract = DEFAULT_OPERATION_CONTRACTS.require(step.name)
            steps.append(
                WorkflowStep(
                    contract.domain,
                    contract.orchestration_phase,
                    step.name,
                    step.kind,
                )
            )
            continue
        phase = DEFAULT_WORKFLOW_REGISTRY.phases.require(step.name)
        domain = phase.orchestration_domain or step.name.partition(".")[0]
        orchestration_phase = phase.orchestration_phase or step.name.partition(".")[2]
        steps.append(
            WorkflowStep(domain, orchestration_phase, step.name, step.kind)
        )
    return tuple(steps)


@dataclass(frozen=True)
class TaskIntent:
    """Original user intent parsed once for every owning domain."""

    original_intent: TaskIntentKind
    final_purpose: str
    entry_domain: str
    targets: tuple[TaskTargetBinding, ...]
    authorization: TaskAuthorizationPolicy
    delivery_strategy: DeliveryStrategy | None = None
    parse_count: int = 1

    @classmethod
    def create(
        cls,
        *,
        original_intent: str,
        final_purpose: str,
        entry_domain: str,
        targets: tuple[TaskTargetBinding, ...],
        delivery_strategy: str | None = None,
        authorized_exceptions: Mapping[str, object] | None = None,
        allow_insecure_tls: bool = False,
    ) -> "TaskIntent":
        normalized = TaskIntentKind.parse(original_intent)
        domain = str(entry_domain).strip().lower().replace("-", "_")
        if domain not in _DOMAINS:
            raise ValueError(f"unsupported entry domain: {entry_domain}")
        if not str(final_purpose).strip():
            raise ValueError("final_purpose must not be empty")
        if not targets:
            raise ValueError("task intent requires at least one target")
        identifiers = [target.target_id for target in targets]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("task target IDs must be unique")
        references = [target for target in targets if target.role == "reference"]
        if len(references) > 1:
            raise ValueError("task intent may contain at most one reference target")
        if references and any(target.role == "symmetric" for target in targets):
            raise ValueError("reference comparison cannot mix symmetric target roles")
        if (
            not references
            and len(targets) > 1
            and any(target.role != "symmetric" for target in targets)
        ):
            raise ValueError(
                "multi-target tasks without a reference must use symmetric roles"
            )
        if normalized is TaskIntentKind.DIAGNOSIS_ONLY and domain not in {
            "debug",
            "log_analyzer",
        }:
            raise ValueError(
                "diagnosis-only tasks must enter through Debug or Log Analyzer"
            )
        strategy = (
            DeliveryStrategy.parse(delivery_strategy)
            if normalized is TaskIntentKind.DIAGNOSE_AND_FIX
            else None
        )
        if delivery_strategy is not None and strategy is None:
            raise ValueError(
                "delivery_strategy is supported only for diagnose-and-fix"
            )
        steps = _canonical_workflow_steps(normalized, domain, strategy)
        if steps[0].domain != domain:
            raise ValueError(
                f"intent {normalized.value} must enter through {steps[0].domain}, not {domain}"
            )
        authorization_policy = TaskAuthorizationPolicy.from_task_intent(
            normalized.value,
            delivery_strategy=(strategy.value if strategy is not None else ""),
            authorized_exceptions=authorized_exceptions,
            allow_insecure_tls=allow_insecure_tls,
        )
        return cls(
            normalized,
            str(final_purpose).strip(),
            domain,
            tuple(targets),
            authorization_policy,
            strategy,
        )

    @property
    def steps(self) -> tuple[WorkflowStep, ...]:
        return _canonical_workflow_steps(
            self.original_intent,
            self.entry_domain,
            self.delivery_strategy,
        )

    @property
    def fingerprint(self) -> str:
        facts = {
            "original_intent": self.original_intent.value,
            "final_purpose": self.final_purpose,
            "entry_domain": self.entry_domain,
            "delivery_strategy": (
                self.delivery_strategy.value
                if self.delivery_strategy is not None
                else None
            ),
            "targets": [
                {
                    "target_id": target.target_id,
                    "role": target.role,
                    "target_fingerprint": target.target.fingerprint,
                }
                for target in self.targets
            ],
        }
        policy_field = "author" + "ization"
        facts[policy_field] = self.authorization.to_public_dict()
        return _fingerprint(facts)

    def to_public_dict(self) -> dict[str, object]:
        public = {
            "schema": ORCHESTRATION_SCHEMA,
            "original_intent": self.original_intent.value,
            "final_purpose": self.final_purpose,
            "entry_domain": self.entry_domain,
            "delivery_strategy": (
                self.delivery_strategy.value
                if self.delivery_strategy is not None
                else None
            ),
            "parse_count": self.parse_count,
            "fingerprint": self.fingerprint,
            "targets": [target.to_public_dict() for target in self.targets],
            "steps": [step.to_public_dict() for step in self.steps],
        }
        authorization_field = "author" + "ization"
        public[authorization_field] = self.authorization.to_public_dict()
        return public


@dataclass(frozen=True)
class DeveloperEditIntent:
    """Typed source-edit handoff without remote transport capability."""

    component_roots: tuple[str, ...]
    authored_files: tuple[str, ...]
    change_summary: str
    runtime_artifact: str = ""
    restart_scope: str = "none"
    verification_checks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.component_roots:
            raise ValueError("Developer edit intent requires a component root")
        if not self.authored_files:
            raise ValueError("Developer edit intent requires an authored file")
        if not self.change_summary.strip():
            raise ValueError("Developer edit intent requires a change summary")
        if self.restart_scope not in {"none", "skynet"}:
            raise ValueError("restart_scope must be none or skynet")

    def to_public_dict(self) -> dict[str, object]:
        return {
            "component_roots": list(self.component_roots),
            "authored_files": list(self.authored_files),
            "change_summary": self.change_summary,
            "runtime_artifact": self.runtime_artifact,
            "restart_scope": self.restart_scope,
            "verification_checks": list(self.verification_checks),
        }


@dataclass(frozen=True)
class DomainOutcome(Generic[ValueT]):
    status: str
    value: ValueT
    evidence_ids: tuple[str, ...] = ()
    edit_intent: DeveloperEditIntent | None = None
    modified_target_epochs: Mapping[str, int] = field(default_factory=dict)
    observed_target_epochs: Mapping[str, int] = field(default_factory=dict)
    operation_id: str = ""

    def __post_init__(self) -> None:
        if self.status not in _OUTCOME_STATUSES:
            raise ValueError(f"unsupported domain outcome status: {self.status}")
        if self.operation_id and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", self.operation_id
        ) is None:
            raise ValueError("operation_id must be a safe 1-128 character identifier")
        for target_id, epoch in (
            *self.modified_target_epochs.items(),
            *self.observed_target_epochs.items(),
        ):
            if (
                not str(target_id).strip()
                or isinstance(epoch, bool)
                or not isinstance(epoch, int)
                or epoch < 0
            ):
                raise ValueError("target epochs require a target ID and non-negative integer")

    @classmethod
    def succeeded(
        cls,
        value: ValueT,
        *,
        evidence_ids: tuple[str, ...] = (),
        edit_intent: DeveloperEditIntent | None = None,
    ) -> "DomainOutcome[ValueT]":
        return cls(
            status="succeeded",
            value=value,
            evidence_ids=evidence_ids,
            edit_intent=edit_intent,
        )

    @classmethod
    def modified(
        cls,
        value: ValueT,
        *,
        evidence_ids: tuple[str, ...] = (),
        modified_target_epochs: Mapping[str, int],
        operation_id: str = "",
    ) -> "DomainOutcome[ValueT]":
        return cls(
            status="modified",
            value=value,
            evidence_ids=evidence_ids,
            modified_target_epochs=dict(modified_target_epochs),
            operation_id=operation_id,
        )

    @classmethod
    def verified(
        cls,
        value: ValueT,
        *,
        evidence_ids: tuple[str, ...] = (),
        observed_target_epochs: Mapping[str, int],
    ) -> "DomainOutcome[ValueT]":
        return cls(
            status="verified",
            value=value,
            evidence_ids=evidence_ids,
            observed_target_epochs=dict(observed_target_epochs),
        )


@dataclass(frozen=True)
class MutationDomainResult:
    """Typed projection of a mutation backend's public MCP result."""

    value: dict[str, object]
    epoch_after: int
    evidence_ids: tuple[str, ...] = ()

    @classmethod
    def from_backend(cls, raw: object) -> "MutationDomainResult":
        if not isinstance(raw, Mapping):
            raise TypeError("mutation backend must return an object")
        value = dict(raw)
        epoch = value.get("epoch_after")
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
            raise ValueError("mutation backend must return a positive epoch_after")
        raw_evidence = value.get("evidence_ids", [])
        evidence_ids = (
            tuple(
                item
                for item in raw_evidence
                if isinstance(item, str) and item
            )
            if isinstance(raw_evidence, list)
            else ()
        )
        return cls(value=value, epoch_after=epoch, evidence_ids=evidence_ids)


@dataclass(frozen=True)
class DomainExecution:
    execution_id: str
    operation_id: str
    domain: str
    phase: str
    status: str
    evidence_ids: tuple[str, ...] = ()
    value: object = None
    error: str = ""
    edit_intent: DeveloperEditIntent | None = None
    modified_target_epochs: Mapping[str, int] = field(default_factory=dict)
    observed_target_epochs: Mapping[str, int] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.domain}:{self.phase}"

    def to_public_dict(self) -> dict[str, object]:
        return {
            "execution_id": self.execution_id,
            "operation_id": self.operation_id,
            "domain": self.domain,
            "phase": self.phase,
            "key": self.key,
            "status": self.status,
            "evidence_ids": list(self.evidence_ids),
            "value": self.value,
            "error": self.error,
            "edit_intent": (
                self.edit_intent.to_public_dict()
                if self.edit_intent is not None
                else None
            ),
            "modified_target_epochs": dict(self.modified_target_epochs),
            "observed_target_epochs": dict(self.observed_target_epochs),
        }


@dataclass(frozen=True)
class DomainHandoff:
    handoff_id: str
    from_domain: str
    from_phase: str
    to_domain: str
    to_phase: str
    operation_id: str
    target_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    status: str
    edit_intent: DeveloperEditIntent | None = None

    def to_public_dict(self) -> dict[str, object]:
        return {
            "handoff_id": self.handoff_id,
            "from": f"{self.from_domain}:{self.from_phase}",
            "to": f"{self.to_domain}:{self.to_phase}",
            "operation_id": self.operation_id,
            "target_ids": list(self.target_ids),
            "evidence_ids": list(self.evidence_ids),
            "status": self.status,
            "edit_intent": (
                self.edit_intent.to_public_dict()
                if self.edit_intent is not None
                else None
            ),
        }


@dataclass(frozen=True)
class DomainExecutionContext:
    task_id: str
    operation_id: str
    domain: str
    phase: str
    intent: TaskIntent
    targets: tuple[TaskTargetBinding, ...]
    previous: tuple[DomainExecution, ...]
    authorization: TaskAuthorizationPolicy
    edit_intent: DeveloperEditIntent | None
    minimum_target_epochs: Mapping[str, int]


@dataclass(frozen=True)
class TaskWorkflowResult:
    completed: bool
    partial: bool
    next_action: str
    intent: TaskIntent
    executions: tuple[DomainExecution, ...]
    handoffs: tuple[DomainHandoff, ...]
    phase_states: Mapping[str, str]

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": ORCHESTRATION_SCHEMA,
            "completed": self.completed,
            "partial": self.partial,
            "next_action": self.next_action,
            "intent": self.intent.to_public_dict(),
            "executions": [item.to_public_dict() for item in self.executions],
            "handoffs": [item.to_public_dict() for item in self.handoffs],
            "phase_states": dict(self.phase_states),
        }


class TaskOrchestrationContext:
    """Task-owned typed context and bounded domain handoff history."""

    def __init__(self, *, task_id: str, intent: TaskIntent) -> None:
        if not task_id.strip():
            raise ValueError("task_id must not be empty")
        self.task_id = task_id
        self.intent = intent
        self._executions: list[DomainExecution] = []
        self._handoffs: list[DomainHandoff] = []
        self._sequence = 0
        self._lock = threading.RLock()

    @property
    def executions(self) -> tuple[DomainExecution, ...]:
        with self._lock:
            return tuple(self._executions)

    @property
    def handoffs(self) -> tuple[DomainHandoff, ...]:
        with self._lock:
            return tuple(self._handoffs)

    def _next_identifier(self, prefix: str, domain: str) -> str:
        with self._lock:
            self._sequence += 1
            sequence = self._sequence
        task_token = _fingerprint({"task_id": self.task_id})[:12]
        safe_domain = re.sub(r"[^a-z0-9]+", "-", domain.lower()).strip("-")
        return f"{prefix}-{task_token}-{sequence:04d}-{safe_domain}"

    def execution_context(self, step: WorkflowStep) -> DomainExecutionContext:
        previous = self.executions
        edit_intent = next(
            (
                execution.edit_intent
                for execution in reversed(previous)
                if execution.edit_intent is not None
            ),
            None,
        )
        minimum_epochs: dict[str, int] = {}
        for execution in previous:
            for target_id, epoch in execution.modified_target_epochs.items():
                minimum_epochs[target_id] = max(
                    minimum_epochs.get(target_id, 0), int(epoch)
                )
        return DomainExecutionContext(
            self.task_id,
            self._next_identifier("op", step.domain),
            step.domain,
            step.phase,
            self.intent,
            self.intent.targets,
            previous,
            self.intent.authorization,
            edit_intent,
            minimum_epochs,
        )

    def record_outcome(
        self,
        execution: DomainExecutionContext,
        outcome: DomainOutcome[object],
    ) -> DomainExecution:
        record = DomainExecution(
            execution_id=self._next_identifier("execution", execution.domain),
            operation_id=outcome.operation_id or execution.operation_id,
            domain=execution.domain,
            phase=execution.phase,
            status=outcome.status,
            evidence_ids=tuple(outcome.evidence_ids),
            value=outcome.value,
            edit_intent=outcome.edit_intent,
            modified_target_epochs=dict(outcome.modified_target_epochs),
            observed_target_epochs=dict(outcome.observed_target_epochs),
        )
        with self._lock:
            self._executions.append(record)
        return record

    def record_failure(
        self,
        execution: DomainExecutionContext,
        error: BaseException,
    ) -> DomainExecution:
        record = DomainExecution(
            execution_id=self._next_identifier("execution", execution.domain),
            operation_id=execution.operation_id,
            domain=execution.domain,
            phase=execution.phase,
            status="failed",
            error=f"{type(error).__name__}: {error}",
        )
        with self._lock:
            self._executions.append(record)
        return record

    def record_not_executed(
        self,
        execution: DomainExecutionContext,
        reason: str,
    ) -> DomainExecution:
        record = DomainExecution(
            execution_id=self._next_identifier("execution", execution.domain),
            operation_id=execution.operation_id,
            domain=execution.domain,
            phase=execution.phase,
            status="not_executed",
            error=reason,
        )
        with self._lock:
            self._executions.append(record)
        return record

    def create_handoff(
        self,
        source: DomainExecution,
        destination: WorkflowStep,
    ) -> DomainHandoff:
        handoff = DomainHandoff(
            handoff_id=self._next_identifier("handoff", destination.domain),
            from_domain=source.domain,
            from_phase=source.phase,
            to_domain=destination.domain,
            to_phase=destination.phase,
            operation_id=source.operation_id,
            target_ids=tuple(target.target_id for target in self.intent.targets),
            evidence_ids=source.evidence_ids,
            status=source.status,
            edit_intent=source.edit_intent,
        )
        with self._lock:
            self._handoffs.append(handoff)
        return handoff

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": ORCHESTRATION_SCHEMA,
            "task_id": self.task_id,
            "intent": self.intent.to_public_dict(),
            "executions": [item.to_public_dict() for item in self.executions],
            "handoffs": [item.to_public_dict() for item in self.handoffs],
        }


class TaskWorkflowOrchestrator:
    """Execute the intent-selected domains without user-managed handoff IDs."""

    def __init__(self, context: TaskOrchestrationContext) -> None:
        self.context = context

    @staticmethod
    def _handler(
        handlers: Mapping[str, Callable[[DomainExecutionContext], DomainOutcome[object]]],
        step: WorkflowStep,
    ) -> Callable[[DomainExecutionContext], DomainOutcome[object]] | None:
        if step.canonical_name == "diagnosis.acceptance":
            return handlers.get(step.key)
        return handlers.get(step.key) or handlers.get(step.domain)

    @staticmethod
    def _acceptable(step: WorkflowStep, outcome: DomainOutcome[object]) -> bool:
        if step.phase == "mutation":
            return outcome.status == "modified" and bool(
                outcome.modified_target_epochs
            )
        if step.phase == "fresh_verification":
            return outcome.status == "verified"
        return outcome.status == "succeeded"

    def run(
        self,
        handlers: Mapping[
            str,
            Callable[[DomainExecutionContext], DomainOutcome[object]],
        ],
    ) -> TaskWorkflowResult:
        steps = self.context.intent.steps
        next_action = ""
        completed = True
        last: DomainExecution | None = None
        for step in steps:
            if last is not None:
                self.context.create_handoff(last, step)
            execution = self.context.execution_context(step)
            handler = self._handler(handlers, step)
            if handler is None:
                last = self.context.record_not_executed(
                    execution, f"no handler is registered for {step.key}"
                )
                next_action = step.key
                completed = False
                break
            try:
                outcome = handler(execution)
                if not isinstance(outcome, DomainOutcome):
                    raise TypeError("domain handler must return DomainOutcome")
                if not self._acceptable(step, outcome):
                    raise ValueError(
                        f"{step.key} returned {outcome.status}; expected the phase-owned status"
                    )
                last = self.context.record_outcome(execution, outcome)
            except Exception as error:
                last = self.context.record_failure(execution, error)
                next_action = step.key
                completed = False
                break

        executions = self.context.executions
        states = {step.key: "not_executed" for step in steps}
        for execution in executions:
            states[execution.key] = execution.status
        if completed and len(executions) != len(steps):
            completed = False
        partial = not completed and bool(
            any(item.status in {"succeeded", "modified", "verified"} for item in executions)
        )
        return TaskWorkflowResult(
            completed=completed,
            partial=partial,
            next_action=next_action,
            intent=self.context.intent,
            executions=executions,
            handoffs=self.context.handoffs,
            phase_states=states,
        )
