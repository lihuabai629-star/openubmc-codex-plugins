"""Canonical versioned workflow definitions and execution identities."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
import hashlib
import json
import re

from .contracts import RUNTIME_API_VERSION
from .operation_contracts import DEFAULT_OPERATION_CONTRACTS


WORKFLOW_DEFINITION_SCHEMA = f"{RUNTIME_API_VERSION}/workflow-definition-v1"
WORKFLOW_DEFINITION_VERSION = 3
_STEP_KINDS = frozenset({"operation", "phase"})
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


def _fingerprint(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class PhaseDescriptor:
    name: str
    owner: str
    receipt_schema: str
    required_fields: tuple[str, ...]
    orchestration_domain: str = ""
    orchestration_phase: str = ""
    closeout_stage: str = ""
    aliases: tuple[str, ...] = ()
    producer_aliases: tuple[str, ...] = ()
    allow_empty_list_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _SAFE_ID.fullmatch(self.name):
            raise ValueError("phase name must be a safe identifier")
        if not _SAFE_ID.fullmatch(self.owner):
            raise ValueError("phase owner must be a safe identifier")
        if not self.receipt_schema.strip():
            raise ValueError("phase receipt_schema must not be empty")
        if len(self.required_fields) != len(set(self.required_fields)):
            raise ValueError(f"phase {self.name} has duplicate required fields")
        if len(self.allow_empty_list_fields) != len(
            set(self.allow_empty_list_fields)
        ):
            raise ValueError(f"phase {self.name} has duplicate empty-allowed fields")
        if not set(self.allow_empty_list_fields).issubset(self.required_fields):
            raise ValueError(
                f"phase {self.name} empty-allowed fields must also be required"
            )
        if len(self.aliases) != len(set(self.aliases)):
            raise ValueError(f"phase {self.name} has duplicate aliases")
        if self.name in self.aliases:
            raise ValueError(f"phase {self.name} must not alias itself")
        if any(_SAFE_ID.fullmatch(alias) is None for alias in self.aliases):
            raise ValueError(f"phase {self.name} has an invalid alias")
        if len(self.producer_aliases) != len(set(self.producer_aliases)):
            raise ValueError(f"phase {self.name} has duplicate producer aliases")
        if self.owner in self.producer_aliases:
            raise ValueError(f"phase {self.name} must not alias its owner")
        if any(
            _SAFE_ID.fullmatch(alias) is None for alias in self.producer_aliases
        ):
            raise ValueError(f"phase {self.name} has an invalid producer alias")

    def to_public_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "owner": self.owner,
            "receipt_schema": self.receipt_schema,
            "required_fields": list(self.required_fields),
            "orchestration_domain": self.orchestration_domain,
            "orchestration_phase": self.orchestration_phase,
            "closeout_stage": self.closeout_stage,
            "aliases": list(self.aliases),
            "producer_aliases": list(self.producer_aliases),
            "allow_empty_list_fields": list(self.allow_empty_list_fields),
        }


class PhaseRegistry:
    """Canonical phase ownership and receipt contract registry."""

    def __init__(self, descriptors: Sequence[PhaseDescriptor]) -> None:
        registered: dict[str, PhaseDescriptor] = {}
        aliases: dict[str, str] = {}
        for descriptor in descriptors:
            if descriptor.name in registered:
                raise ValueError(f"duplicate phase descriptor: {descriptor.name}")
            if descriptor.name in aliases:
                raise ValueError(
                    f"phase name conflicts with alias: {descriptor.name}"
                )
            registered[descriptor.name] = descriptor
            for alias in descriptor.aliases:
                if alias in registered or alias in aliases:
                    raise ValueError(f"duplicate phase alias: {alias}")
                aliases[alias] = descriptor.name
        self._descriptors = registered
        self._aliases = aliases

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._descriptors))

    def canonical_name(self, name: str) -> str:
        normalized = str(name).strip().lower()
        return self._aliases.get(normalized, normalized)

    def require(self, name: str) -> PhaseDescriptor:
        canonical = self.canonical_name(name)
        try:
            return self._descriptors[canonical]
        except KeyError as exc:
            raise ValueError(f"unregistered workflow phase: {name}") from exc

    def canonical_producer(self, name: str, producer: str) -> str:
        descriptor = self.require(name)
        selected = str(producer).strip()
        if selected == descriptor.owner or selected in descriptor.producer_aliases:
            return descriptor.owner
        raise ValueError(
            f"{descriptor.name} producer_identity must be {descriptor.owner}"
        )

    def validate_receipt(
        self,
        name: str,
        *,
        producer: str,
        receipt: Mapping[str, object],
    ) -> PhaseDescriptor:
        descriptor = self.require(name)
        self.canonical_producer(descriptor.name, producer)
        missing = []
        for field in descriptor.required_fields:
            if field not in receipt:
                missing.append(field)
                continue
            value = receipt[field]
            if field in descriptor.allow_empty_list_fields:
                if not isinstance(value, list):
                    missing.append(field)
            elif value is None or value == "" or value == () or value == []:
                missing.append(field)
        if missing:
            raise ValueError(
                f"{name} receipt omits required fields: {', '.join(missing)}"
            )
        return descriptor

    def to_public_dict(self) -> dict[str, object]:
        return {
            name: descriptor.to_public_dict()
            for name, descriptor in sorted(self._descriptors.items())
        }


@dataclass(frozen=True)
class WorkflowStepDefinition:
    step_id: str
    kind: str
    name: str
    owner: str
    receipt_schema: str = ""
    target_id: str = ""

    def __post_init__(self) -> None:
        if not _SAFE_ID.fullmatch(self.step_id):
            raise ValueError("workflow step_id must be a safe identifier")
        if self.kind not in _STEP_KINDS:
            raise ValueError(f"unsupported workflow step kind: {self.kind}")
        if not _SAFE_ID.fullmatch(self.name):
            raise ValueError("workflow step name must be a safe identifier")
        if not _SAFE_ID.fullmatch(self.owner):
            raise ValueError("workflow step owner must be a safe identifier")
        if self.kind == "phase" and not self.receipt_schema:
            raise ValueError("phase workflow steps require a receipt schema")
        if self.target_id and not _SAFE_ID.fullmatch(self.target_id):
            raise ValueError("workflow step target_id must be a safe identifier")

    def to_public_dict(self) -> dict[str, object]:
        return {
            "step_id": self.step_id,
            "kind": self.kind,
            "name": self.name,
            "owner": self.owner,
            "receipt_schema": self.receipt_schema,
            **({"target_id": self.target_id} if self.target_id else {}),
        }

    @classmethod
    def from_public_dict(
        cls, value: Mapping[str, object]
    ) -> "WorkflowStepDefinition":
        return cls(
            step_id=str(value.get("step_id", "")),
            kind=str(value.get("kind", "")),
            name=str(value.get("name", "")),
            owner=str(value.get("owner", "")),
            receipt_schema=str(value.get("receipt_schema", "")),
            target_id=str(value.get("target_id", "")),
        )


@dataclass(frozen=True)
class WorkflowDefinition:
    definition_id: str
    version: int
    intent: str
    entry_domain: str
    entry_operation: str
    delivery_strategy: str
    steps: tuple[WorkflowStepDefinition, ...]

    def __post_init__(self) -> None:
        if not _SAFE_ID.fullmatch(self.definition_id):
            raise ValueError("workflow definition_id must be a safe identifier")
        if isinstance(self.version, bool) or self.version <= 0:
            raise ValueError("workflow definition version must be positive")
        if not self.intent.strip():
            raise ValueError("workflow intent must not be empty")
        if not self.steps:
            raise ValueError("workflow definition requires at least one step")
        step_ids = [step.step_id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("workflow definition step IDs must be unique")

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.identity_facts())

    def identity_facts(self) -> dict[str, object]:
        return {
            "schema": WORKFLOW_DEFINITION_SCHEMA,
            "definition_id": self.definition_id,
            "version": self.version,
            "intent": self.intent,
            "entry_domain": self.entry_domain,
            "entry_operation": self.entry_operation,
            "delivery_strategy": self.delivery_strategy,
            "steps": [step.to_public_dict() for step in self.steps],
        }

    def to_public_dict(self) -> dict[str, object]:
        return {**self.identity_facts(), "fingerprint": self.fingerprint}

    @classmethod
    def from_public_dict(cls, value: Mapping[str, object]) -> "WorkflowDefinition":
        if value.get("schema") != WORKFLOW_DEFINITION_SCHEMA:
            raise ValueError("unsupported workflow definition schema")
        raw_steps = value.get("steps")
        if not isinstance(raw_steps, list):
            raise ValueError("workflow definition steps must be an array")
        if not all(isinstance(step, Mapping) for step in raw_steps):
            raise ValueError("workflow definition steps must contain objects")
        definition = cls(
            definition_id=str(value.get("definition_id", "")),
            version=int(value.get("version", 0)),
            intent=str(value.get("intent", "")),
            entry_domain=str(value.get("entry_domain", "")),
            entry_operation=str(value.get("entry_operation", "")),
            delivery_strategy=str(value.get("delivery_strategy", "")),
            steps=tuple(
                WorkflowStepDefinition.from_public_dict(step)
                for step in raw_steps
            ),
        )
        recorded = str(value.get("fingerprint", ""))
        if recorded and recorded != definition.fingerprint:
            raise ValueError("workflow definition fingerprint mismatch")
        return definition


@dataclass(frozen=True)
class StepIdentity:
    workflow_definition_id: str
    workflow_version: int
    workflow_fingerprint: str
    cycle_id: str
    step_id: str
    attempt: int
    input_fingerprint: str
    target_version: int
    target_epoch: int

    def __post_init__(self) -> None:
        if self.attempt <= 0:
            raise ValueError("step attempt must be positive")
        if self.target_version <= 0:
            raise ValueError("target version must be positive")
        if self.target_epoch < 0:
            raise ValueError("target epoch must be non-negative")
        for name, value in (
            ("workflow_fingerprint", self.workflow_fingerprint),
            ("input_fingerprint", self.input_fingerprint),
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError(f"{name} must be a SHA-256 fingerprint")

    @property
    def execution_id(self) -> str:
        return "step-" + _fingerprint(self.to_public_dict())[:32]

    def to_public_dict(self) -> dict[str, object]:
        return {
            "workflow_definition_id": self.workflow_definition_id,
            "workflow_version": self.workflow_version,
            "workflow_fingerprint": self.workflow_fingerprint,
            "cycle_id": self.cycle_id,
            "step_id": self.step_id,
            "attempt": self.attempt,
            "input_fingerprint": self.input_fingerprint,
            "target_version": self.target_version,
            "target_epoch": self.target_epoch,
        }


class WorkflowRegistry:
    """Resolve one immutable WorkflowDefinition from public Case facts."""

    def __init__(
        self,
        *,
        phases: PhaseRegistry,
        operation_owners: Mapping[str, str],
        routes: Sequence["WorkflowRoute"] = (),
        strict_entry_operations: frozenset[str] = frozenset(),
    ) -> None:
        self.phases = phases
        self.operation_owners = dict(operation_owners)
        self.strict_entry_operations = frozenset(strict_entry_operations)
        unknown_strict_operations = (
            self.strict_entry_operations - self.operation_owners.keys()
        )
        if unknown_strict_operations:
            raise ValueError(
                "strict workflow entry operation has no owner: "
                + ", ".join(sorted(unknown_strict_operations))
            )
        registered: dict[tuple[str, str, str, str], WorkflowRoute] = {}
        for route in routes:
            key = route.selector
            if key in registered:
                raise ValueError(
                    "duplicate workflow route: " + "/".join(part or "*" for part in key)
                )
            for kind, name in route.steps:
                if kind == "phase":
                    self.phases.require(name)
                elif kind == "operation":
                    if name not in self.operation_owners:
                        raise ValueError(f"workflow operation has no owner: {name}")
                else:
                    raise ValueError(f"unsupported workflow step kind: {kind}")
            registered[key] = route
        self._routes = tuple(routes)

    def extend(
        self,
        *,
        operation_owners: Mapping[str, str],
        routes: Sequence["WorkflowRoute"] = (),
        strict_entry_operations: frozenset[str] = frozenset(),
    ) -> "WorkflowRegistry":
        combined_owners = dict(self.operation_owners)
        for operation, owner in operation_owners.items():
            current = combined_owners.get(operation)
            if current is not None and current != owner:
                raise ValueError(f"workflow operation owner drift: {operation}")
            combined_owners[operation] = owner
        return WorkflowRegistry(
            phases=self.phases,
            operation_owners=combined_owners,
            routes=(*self._routes, *routes),
            strict_entry_operations=(
                self.strict_entry_operations | strict_entry_operations
            ),
        )

    def _step(self, index: int, kind: str, name: str) -> WorkflowStepDefinition:
        step_id = f"step-{index:02d}-{name.replace('.', '-')}"
        if kind == "phase":
            phase = self.phases.require(name)
            return WorkflowStepDefinition(
                step_id,
                kind,
                name,
                phase.owner,
                phase.receipt_schema,
            )
        try:
            owner = self.operation_owners[name]
        except KeyError as exc:
            raise ValueError(f"workflow operation has no owner: {name}") from exc
        return WorkflowStepDefinition(step_id, kind, name, owner)

    def resolve(
        self,
        *,
        intent: str,
        entry_domain: str = "",
        entry_operation: str = "",
        delivery_strategy: str = "",
    ) -> WorkflowDefinition:
        normalized_intent = str(intent or "diagnosis-only").strip().lower().replace("_", "-")
        domain = str(entry_domain).strip().lower().replace("-", "_")
        operation = str(entry_operation).strip()
        delivery = (
            str(delivery_strategy or "source-only")
            .strip()
            .lower()
            .replace("_", "-")
        )
        if operation:
            if operation not in self.operation_owners:
                raise ValueError(f"workflow operation has no owner: {operation}")
            matching_entry_routes = [
                route
                for route in self._routes
                if route.entry_operation
                if route.matches(
                    intent=normalized_intent,
                    entry_domain=domain,
                    entry_operation=operation,
                    delivery_strategy=(
                        delivery if normalized_intent == "diagnose-and-fix" else ""
                    ),
                )
            ]
            if matching_entry_routes:
                raw = max(
                    matching_entry_routes,
                    key=lambda route: route.specificity,
                ).steps
            elif normalized_intent == "diagnosis-only":
                raw = (("operation", operation),)
                if domain != "log_analyzer" and "diagnosis.acceptance" in self.phases.names():
                    raw += (("phase", "diagnosis.acceptance"),)
            elif operation in self.strict_entry_operations:
                raise ValueError(
                    "workflow entry operation has no typed route: " + operation
                )
            else:
                route = self._resolve_route(
                    intent=normalized_intent,
                    entry_domain=domain,
                    entry_operation="",
                    delivery_strategy=(
                        delivery if normalized_intent == "diagnose-and-fix" else ""
                    ),
                )
                raw = route.steps
        else:
            route = self._resolve_route(
                intent=normalized_intent,
                entry_domain=domain,
                entry_operation="",
                delivery_strategy=(
                    delivery if normalized_intent == "diagnose-and-fix" else ""
                ),
            )
            raw = route.steps
        steps = tuple(
            self._step(index, kind, name)
            for index, (kind, name) in enumerate(raw, start=1)
        )
        route = operation or domain or steps[0].name
        definition_id = ".".join(
            part
            for part in (
                normalized_intent,
                route.replace("_", "-"),
                delivery if normalized_intent == "diagnose-and-fix" else "",
            )
            if part
        )
        return WorkflowDefinition(
            definition_id=definition_id,
            version=WORKFLOW_DEFINITION_VERSION,
            intent=normalized_intent,
            entry_domain=domain,
            entry_operation=operation,
            delivery_strategy=(
                delivery if normalized_intent == "diagnose-and-fix" else ""
            ),
            steps=steps,
        )

    def _resolve_route(
        self,
        *,
        intent: str,
        entry_domain: str,
        entry_operation: str,
        delivery_strategy: str,
    ) -> "WorkflowRoute":
        candidates = [
            route
            for route in self._routes
            if route.matches(
                intent=intent,
                entry_domain=entry_domain,
                entry_operation=entry_operation,
                delivery_strategy=delivery_strategy,
            )
        ]
        if not candidates:
            raise ValueError(
                "workflow route is unavailable: "
                f"intent={intent}, entry_domain={entry_domain or '*'}, "
                f"delivery_strategy={delivery_strategy or '*'}"
            )
        return max(candidates, key=lambda route: route.specificity)

    def infer_legacy_intent(
        self,
        projection: Mapping[str, object],
    ) -> str:
        operations = tuple(
            item
            for item in projection.get("operations", ())
            if isinstance(item, Mapping)
        )
        operation_names = frozenset(
            str(item.get("operation", "")) for item in operations
        )
        candidates = [
            route
            for route in self._routes
            if route.legacy_matches(operations, operation_names)
        ]
        if not candidates:
            return ""
        return max(candidates, key=lambda route: route.legacy_specificity).intent


@dataclass(frozen=True)
class WorkflowRoute:
    """Declarative selector and ordered steps for one workflow route."""

    intent: str
    steps: tuple[tuple[str, str], ...]
    entry_domain: str = ""
    entry_operation: str = ""
    delivery_strategy: str = ""
    legacy_operations: frozenset[str] = frozenset()
    legacy_input_equals: tuple[tuple[str, str, str], ...] = ()

    def __post_init__(self) -> None:
        normalized_intent = self.intent.strip().lower().replace("_", "-")
        if not normalized_intent:
            raise ValueError("workflow route intent is required")
        if not self.steps:
            raise ValueError(f"workflow route {normalized_intent} requires steps")
        object.__setattr__(self, "intent", normalized_intent)
        object.__setattr__(
            self,
            "entry_domain",
            self.entry_domain.strip().lower().replace("-", "_"),
        )
        object.__setattr__(
            self,
            "entry_operation",
            self.entry_operation.strip(),
        )
        object.__setattr__(
            self,
            "delivery_strategy",
            self.delivery_strategy.strip().lower().replace("_", "-"),
        )

    @property
    def selector(self) -> tuple[str, str, str, str]:
        return (
            self.intent,
            self.entry_domain,
            self.entry_operation,
            self.delivery_strategy,
        )

    @property
    def specificity(self) -> int:
        return (
            1
            + bool(self.entry_domain)
            + bool(self.entry_operation)
            + bool(self.delivery_strategy)
        )

    @property
    def legacy_specificity(self) -> tuple[int, int]:
        return (len(self.legacy_input_equals), len(self.legacy_operations))

    def matches(
        self,
        *,
        intent: str,
        entry_domain: str,
        entry_operation: str,
        delivery_strategy: str,
    ) -> bool:
        return (
            self.intent == intent
            and (not self.entry_domain or self.entry_domain == entry_domain)
            and self.entry_operation == entry_operation
            and (
                not self.delivery_strategy
                or self.delivery_strategy == delivery_strategy
            )
        )

    def legacy_matches(
        self,
        operations: Sequence[Mapping[str, object]],
        operation_names: frozenset[str],
    ) -> bool:
        if not self.legacy_operations or not self.legacy_operations.issubset(
            operation_names
        ):
            return False
        for operation_name, input_name, expected in self.legacy_input_equals:
            if not any(
                str(operation.get("operation", "")) == operation_name
                and isinstance(operation.get("inputs"), Mapping)
                and str(operation["inputs"].get(input_name, "")).strip().lower()
                == expected
                for operation in operations
            ):
                return False
        return True


class WorkflowDefinitions:
    """Versioned deterministic workflow structure with no external I/O."""

    def __init__(self, registry: WorkflowRegistry) -> None:
        self.registry = registry

    @staticmethod
    def bind_target_scope(definition: WorkflowDefinition,
                          targets: Sequence[Mapping[str, object]]) -> WorkflowDefinition:
        """Freeze one rollout and distinct fresh verification for every target."""
        if definition.intent != "upgrade-and-verify" or definition.entry_operation != "upgrade_batch" or len(targets) < 2:
            return definition
        if not any(step.name in {"upgrade_run", "upgrade_batch"} for step in definition.steps):
            return definition
        steps: list[WorkflowStepDefinition] = []
        upgraded = False
        for step in definition.steps:
            if step.name in {"upgrade_run", "upgrade_batch"}:
                step = replace(step, name="upgrade_batch")
                upgraded = True
            if step.name == "debug_collect" and upgraded:
                for target in targets:
                    target_id = str(target.get("target_id", ""))
                    steps.append(replace(step, target_id=target_id,
                                         step_id=f"step-{len(steps) + 1:02d}-debug_collect"))
            else:
                steps.append(replace(step, step_id=f"step-{len(steps) + 1:02d}-{step.name}"))
        return replace(definition, definition_id=definition.definition_id + ".batch", steps=tuple(steps))

    def definition_for(self, projection: Mapping[str, object]) -> WorkflowDefinition:
        recorded = projection.get("workflow_definition")
        if isinstance(recorded, Mapping) and recorded:
            return WorkflowDefinition.from_public_dict(recorded)
        intent = str(projection.get("intent", "diagnosis-only"))
        normalized_intent = intent.strip().lower().replace("_", "-")
        if normalized_intent in {"", "diagnosis-only"}:
            intent = self.registry.infer_legacy_intent(projection) or intent
        definition = self.registry.resolve(
            intent=intent,
            entry_domain=str(projection.get("entry_domain", "")),
            entry_operation=str(projection.get("entry_operation", "")),
            delivery_strategy=str(projection.get("delivery_strategy", "")),
        )
        targets = projection.get("targets", [])
        return self.bind_target_scope(definition, targets if isinstance(targets, list) else [])

    def step_identity(
        self,
        projection: Mapping[str, object],
        *,
        step: WorkflowStepDefinition,
        attempt: int,
        input_fingerprint: str,
        target_epoch: int,
    ) -> StepIdentity:
        definition = self.definition_for(projection)
        return StepIdentity(
            workflow_definition_id=definition.definition_id,
            workflow_version=definition.version,
            workflow_fingerprint=definition.fingerprint,
            cycle_id=str(projection.get("workflow_cycle_id", "cycle-1")),
            step_id=step.step_id,
            attempt=attempt,
            input_fingerprint=input_fingerprint,
            target_version=int(projection.get("target_version", 1)),
            target_epoch=target_epoch,
        )

    def semantic_cursor(
        self,
        projection: Mapping[str, object],
        *,
        nodes: Sequence[Mapping[str, object]],
        acceptance_plan_id: str,
        context_facts: Mapping[str, object] | None = None,
    ) -> str:
        definition = self.definition_for(projection)
        return _fingerprint(
            {
                "schema": f"{WORKFLOW_DEFINITION_SCHEMA}/semantic-cursor",
                "workflow_definition_id": definition.definition_id,
                "workflow_version": definition.version,
                "workflow_fingerprint": definition.fingerprint,
                "workflow_cycle_id": str(
                    projection.get("workflow_cycle_id", "cycle-1")
                ),
                "target_version": int(projection.get("target_version", 1)),
                "acceptance_plan_id": acceptance_plan_id,
                "context_facts": dict(context_facts or {}),
                "nodes": list(nodes),
            }
        )


DEFAULT_PHASE_REGISTRY = PhaseRegistry(
    (
        PhaseDescriptor(
            "diagnosis.acceptance",
            "openubmc-debug",
            f"{RUNTIME_API_VERSION}/diagnosis-acceptance-receipt-v1",
            (
                "root_cause", "evidence_ids", "causal_chain", "code_owner",
                "contradictions", "remaining_gaps", "verification_status",
            ),
            "debug",
            "accept",
            "diagnosis",
            ("diagnosis", "diagnosis.result"),
            ("openubmc-debug-skill",),
            ("contradictions", "remaining_gaps"),
        ),
        PhaseDescriptor(
            "developer.change",
            "openubmc-developer",
            f"{RUNTIME_API_VERSION}/developer-change-receipt-v1",
            ("source_revision", "summary", "authored_files", "verification_plan"),
            "developer",
            "edit",
            "development",
            ("developer", "developer.edit", "developer:edit"),
            ("developer", "developer-skill"),
        ),
        PhaseDescriptor(
            "build.artifact",
            "openubmc-build",
            f"{RUNTIME_API_VERSION}/build-artifact-receipt-v1",
            (
                "source_revision",
                "summary",
                "artifact_path",
                "artifact_sha256",
                "product_version",
            ),
            "build",
            "package",
            "build",
            ("build", "build.package", "build:package"),
            ("build", "build-skill"),
        ),
    )
)

DEFAULT_WORKFLOW_REGISTRY = WorkflowRegistry(
    phases=DEFAULT_PHASE_REGISTRY,
    operation_owners=DEFAULT_OPERATION_CONTRACTS.operation_owners(),
    routes=(
        WorkflowRoute(
            "bundle-and-diagnose",
            (
                ("operation", "log_bundle_collect"), ("operation", "debug_run"),
                ("phase", "diagnosis.acceptance"),
            ),
            legacy_operations=frozenset({"log_bundle_collect", "debug_run"}),
        ),
        WorkflowRoute(
            "live-patch",
            (("operation", "live_patch_run"), ("operation", "debug_collect")),
            legacy_operations=frozenset({"live_patch_run"}),
        ),
        WorkflowRoute(
            "rollback",
            (("operation", "live_patch_run"), ("operation", "debug_collect")),
            legacy_operations=frozenset({"live_patch_run"}),
            legacy_input_equals=(("live_patch_run", "action", "rollback"),),
        ),
        WorkflowRoute(
            "upgrade-and-verify",
            (("operation", "upgrade_run"), ("operation", "debug_collect")),
            legacy_operations=frozenset({"upgrade_run"}),
        ),
        WorkflowRoute(
            "upgrade-and-verify",
            (("operation", "upgrade_batch"), ("operation", "debug_collect")),
            entry_operation="upgrade_batch",
        ),
        WorkflowRoute(
            "diagnose-and-fix",
            (
                ("operation", "debug_run"),
                ("phase", "diagnosis.acceptance"),
                ("phase", "developer.change"),
            ),
            delivery_strategy="source-only",
        ),
        WorkflowRoute(
            "diagnose-and-fix",
            (
                ("operation", "debug_run"),
                ("phase", "diagnosis.acceptance"),
                ("phase", "developer.change"),
                ("operation", "live_patch_run"),
                ("operation", "debug_collect"),
            ),
            delivery_strategy="live-patch",
        ),
        WorkflowRoute(
            "diagnose-and-fix",
            (
                ("operation", "debug_run"),
                ("phase", "diagnosis.acceptance"),
                ("phase", "developer.change"),
                ("phase", "build.artifact"),
                ("operation", "upgrade_run"),
                ("operation", "debug_collect"),
            ),
            delivery_strategy="build-upgrade",
        ),
        WorkflowRoute(
            "diagnosis-only",
            (("operation", "log_bundle_collect"),),
            entry_domain="log_analyzer",
        ),
        WorkflowRoute(
            "diagnosis-only",
            (("operation", "debug_run"), ("phase", "diagnosis.acceptance")),
        ),
    ),
)

DEFAULT_WORKFLOW_DEFINITIONS = WorkflowDefinitions(DEFAULT_WORKFLOW_REGISTRY)

# Compatibility aliases for stored code and callers that still use the old name.
WorkflowKernel = WorkflowDefinitions
DEFAULT_WORKFLOW_KERNEL = DEFAULT_WORKFLOW_DEFINITIONS
