"""Compose the Runtime Core object graph behind one private seam."""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from .agent_gateway import AgentGateway, ResultProjector
from .artifact_store import LocalArtifactStore, SQLiteArtifactRepository
from .capability import (
    CallableDomainAdapter,
    CapabilityDescriptor,
    CapabilityRegistry,
    DomainAdapter,
    DomainExecutor,
    DomainPack,
    DomainPackAuthorContract,
    DomainPackConformanceSuite,
    DomainReceipt,
    RuntimeSDKContext,
)
from .catalog import OperationCatalog, OperationDescriptor
from .compatibility import (
    CompatibilityTelemetry,
    CompatibilityTelemetryRepository,
    InMemoryCompatibilityTelemetryRepository,
    SQLiteCompatibilityTelemetryRepository,
)
from .context_runtime import (
    AGENT_ENVELOPE_MAX_BYTES,
    BlobRepository,
    ContextRuntime,
    RuntimeRepository,
    SQLiteRuntimeRepository,
)
from .domain_packs import builtin_domain_pack_contracts
from .domain_runtime import RuntimeDomainExecution
from .effect_runner import LocalEffectRunner
from .evidence_store import EvidenceQueryService
from .incident import IncidentMetrics
from .operation_contracts import DEFAULT_OPERATION_CONTRACTS
from .run_engine import ObservationEngine, RunEngine, SemanticRuntime
from .run_store import EventRunStore
from .runtime_adapter import RuntimeSemanticAdapter
from .semantic_runtime import SemanticRuntimePort
from .workflow import (
    DEFAULT_WORKFLOW_DEFINITIONS,
    WorkflowDefinitions,
    WorkflowRoute,
)


DomainTransportInvoker = Callable[
    [str, RuntimeSDKContext, Mapping[str, object]],
    Mapping[str, object],
]
DomainPackExtensions = Callable[
    [CapabilityRegistry, Mapping[str, CallableDomainAdapter]],
    Iterable[DomainPackAuthorContract],
]


@dataclass(frozen=True)
class RuntimeCompositionOptions:
    context_repository: RuntimeRepository | None = None
    blob_repository: BlobRepository | None = None
    compatibility_telemetry_repository: (
        CompatibilityTelemetryRepository | None
    ) = None
    context_runtime: ContextRuntime | None = None
    envelope_max_bytes: int = AGENT_ENVELOPE_MAX_BYTES
    max_cached_projections: int = 64
    max_cached_projection_bytes: int = 8 * 1024 * 1024
    retention_seconds: float = 7 * 24 * 60 * 60
    storage_soft_limit_bytes: int = 1024 * 1024 * 1024
    orchestrated_backend: bool = False
    domain_pack_extensions: DomainPackExtensions | None = None
    artifact_store: LocalArtifactStore | None = None


class _AgentRuntimePort:
    def __init__(
        self,
        semantic_runtime: SemanticRuntime,
        gateway: AgentGateway,
    ) -> None:
        self._semantic_runtime = semantic_runtime
        self._gateway = gateway

    @property
    def semantic_runtime(self) -> SemanticRuntimePort:
        return self._semantic_runtime

    def observe(
        self,
        arguments: Mapping[str, object],
        *,
        task_id: str,
        operation_id: str,
    ) -> dict[str, object]:
        return self._gateway.observe(
            arguments,
            task_id=task_id,
            operation_id=operation_id,
        )

    def execute(
        self,
        arguments: Mapping[str, object],
        *,
        task_id: str,
        operation_id: str,
    ) -> dict[str, object]:
        return self._gateway.execute(
            arguments,
            task_id=task_id,
            operation_id=operation_id,
        )

    def error(
        self,
        operation: str,
        exc: Exception,
        *,
        arguments: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        return self._gateway.error(
            operation,
            exc,
            arguments=arguments,
        )


class _RuntimeOperatorPort:
    def __init__(
        self,
        context_runtime: ContextRuntime,
        artifact_store: LocalArtifactStore,
        run_engine: RunEngine,
    ) -> None:
        self._context_runtime = context_runtime
        self._artifact_store = artifact_store
        self._run_engine = run_engine
        self._evidence_query = EvidenceQueryService(context_runtime.repository)

    def replay_service(self):
        from .replay import CaseReplayService

        return CaseReplayService(self._context_runtime.repository)

    def maintain(self) -> Mapping[str, object]:
        return {
            **dict(self._context_runtime.maintain()),
            "artifact_gc": self._artifact_store.garbage_collect(),
        }

    def status(self) -> Mapping[str, object]:
        return {
            **dict(self._context_runtime.status()),
            "artifact_store": self._artifact_store.status(),
        }

    def operator_projection(self, *, task_id: str) -> Mapping[str, object]:
        return self._context_runtime.operator_projection(task_id=task_id)

    def restore_domain_arguments(
        self,
        task_id: str,
        operation: str,
        arguments: Mapping[str, object],
    ) -> dict[str, object]:
        return self._context_runtime.restore_domain_arguments(
            task_id,
            operation,
            arguments,
        )

    def wrap_status(
        self,
        value: Mapping[str, object],
        *,
        task_id: str,
        operation_id: str,
    ) -> dict[str, object]:
        return self._context_runtime.wrap_status(
            value,
            task_id=task_id,
            operation_id=operation_id,
        )

    def wrap_read(
        self,
        value: object,
        *,
        operation: str,
        operation_id: str,
        case_id: str,
    ) -> dict[str, object]:
        return self._context_runtime.wrap_read(
            value,
            operation=operation,
            operation_id=operation_id,
            case_id=case_id,
        )

    def wrap_result(
        self,
        value: Mapping[str, object],
        *,
        operation: str,
        operation_id: str,
        case_id: str,
    ) -> dict[str, object]:
        """Wrap an Operator command result without describing it as a read."""

        return self._context_runtime.wrap_operator_result(
            value,
            operation=operation,
            operation_id=operation_id,
            case_id=case_id,
        )

    def read_case_projection(self, case_id: str) -> Mapping[str, object]:
        return self._context_runtime.read_case(case_id)

    def dispatch(
        self,
        name: str,
        arguments: Mapping[str, object],
        *,
        operation_id: str,
    ) -> dict[str, object] | None:
        if name == "case_read":
            case_id = str(arguments.get("case_id", "")).strip()
            return self.wrap_read(
                self._context_runtime.read_case(case_id),
                operation=name,
                operation_id=operation_id,
                case_id=case_id,
            )
        if name == "evidence_read":
            case_id = str(arguments.get("case_id", "")).strip()
            value = self._context_runtime.read_evidence(
                case_id,
                str(arguments.get("evidence_id", "")).strip(),
                offset=int(arguments.get("offset", 0)),
                limit=int(arguments.get("limit", 65536)),
                target_id=str(arguments.get("target_id", "")),
                generation=str(arguments.get("generation", "")),
            )
            return self.wrap_read(
                value,
                operation=name,
                operation_id=operation_id,
                case_id=case_id,
            )
        if name == "evidence_attach":
            run_id = str(arguments.get("run_id", "")).strip()
            target = str(arguments.get("target", "")).strip()
            path = str(arguments.get("path", "")).strip()
            expected_sha256 = str(arguments.get("sha256", "")).strip()
            evidence_type = str(arguments.get("evidence_type", "")).strip()
            if evidence_type == "firmware-recovery-artifact":
                artifact_path = Path(path).expanduser()
                if not artifact_path.is_absolute():
                    raise ValueError("evidence path must be absolute")
                artifact_path = artifact_path.absolute()
                artifact_target = self._context_runtime.operator_evidence_target(
                    run_id, target=target
                )
                artifact_ref = self._artifact_store.find(
                    kind="openubmc-hpm",
                    target=artifact_target,
                    run_id=run_id,
                    created_by_effect=operation_id,
                )
                if artifact_ref is not None:
                    normalized_expected = expected_sha256.removeprefix(
                        "sha256:"
                    ).lower()
                    if normalized_expected != artifact_ref.digest:
                        raise ValueError(
                            "recovery Artifact Effect identity is already bound "
                            "to a different SHA-256"
                        )
                else:
                    self._context_runtime.operator_evidence_target(
                        run_id,
                        target=target,
                        require_open=True,
                    )
                    artifact_ref = self._artifact_store.put(
                        artifact_path,
                        kind="openubmc-hpm",
                        provenance="operator-evidence-attach",
                        retention_hint="run-lifetime",
                        target=artifact_target,
                        run_id=run_id,
                        created_by_effect=operation_id,
                        expected_sha256=expected_sha256,
                    )
                prepared = self._context_runtime.prepare_artifact_evidence(
                    run_id,
                    target=artifact_target,
                    artifact_ref=artifact_ref.to_public_dict(),
                    evidence_type=evidence_type,
                )
            else:
                prepared = self._context_runtime.prepare_file_evidence(
                    run_id,
                    target=target,
                    path=path,
                    expected_sha256=expected_sha256,
                    evidence_type=evidence_type,
                    operation_id=operation_id,
                )
            reference, replayed = self._run_engine.attach_operator_evidence(
                run_id,
                prepared["evidence"],
                operation_id=operation_id,
            )
            value = {
                "schema": "openubmc.target-runtime/operator-evidence-attach-v1",
                "run_id": run_id,
                "attached": True,
                "idempotent_replay": bool(
                    prepared.get("already_attached") or replayed
                ),
                "evidence_type": prepared["evidence_type"],
                "evidence": dict(reference),
            }
            return self.wrap_result(
                value,
                operation=name,
                operation_id=operation_id,
                case_id=run_id,
            )
        if name == "evidence_query":
            return self.wrap_read(
                self._evidence_query.query(arguments),
                operation=name,
                operation_id=operation_id,
                case_id="",
            )
        if name == "case_close":
            case_id = str(arguments.get("case_id", "")).strip()
            value = self._context_runtime.close_case(
                case_id,
                expected_revision=int(arguments.get("expected_revision", -1)),
            )
            return self.wrap_read(
                value,
                operation=name,
                operation_id=operation_id,
                case_id=case_id,
            )
        if name == "case_forget":
            case_id = str(arguments.get("case_id", "")).strip()
            value = self._context_runtime.forget_case(case_id)
            return self.wrap_read(
                value,
                operation=name,
                operation_id=operation_id,
                case_id="",
            )
        return None

    def unbind_task(self, task_id: str) -> None:
        self._context_runtime.repository.unbind_task(task_id)

    def error_result(
        self,
        exc: Exception,
        *,
        operation: str,
        arguments: Mapping[str, object],
        task_id: str,
        operation_id: str,
    ) -> Mapping[str, object]:
        return self._context_runtime.error_result(
            exc,
            operation=operation,
            arguments=arguments,
            task_id=task_id,
            operation_id=operation_id,
        )


class _RuntimeTransportPort:
    """Hide Runtime assembly behind the MCP transport operations it needs."""

    def __init__(
        self,
        *,
        catalog: OperationCatalog,
        capability_registry: CapabilityRegistry,
        domain_executor: DomainExecutor,
        compatibility_telemetry: CompatibilityTelemetry,
        incident_metrics: IncidentMetrics,
        domain_runtime: RuntimeDomainExecution,
        context_runtime: ContextRuntime,
        artifact_store: LocalArtifactStore,
        orchestrated_backend: bool,
    ) -> None:
        self._catalog = catalog
        self._capability_registry = capability_registry
        self._domain_executor = domain_executor
        self._compatibility_telemetry = compatibility_telemetry
        self._incident_metrics = incident_metrics
        self._domain_runtime = domain_runtime
        self._context_runtime = context_runtime
        self._artifact_store = artifact_store
        self._orchestrated_backend = orchestrated_backend

    def descriptors(self) -> tuple[object, ...]:
        return self._catalog.descriptors()

    def require_operation(self, name: str) -> OperationDescriptor:
        return self._catalog.require(name)

    def validate_arguments(
        self,
        name: str,
        arguments: Mapping[str, object],
    ) -> None:
        self._catalog.validate_arguments(name, arguments)

    def status(self) -> dict[str, object]:
        return {
            "capability_registry": self._capability_registry.to_public_dict(),
            "domain_packs": list(self._domain_executor.pack_descriptors()),
            "domain_pack_conformance": self._domain_executor.conformance_report(),
            "compatibility_telemetry": self._compatibility_telemetry.status(),
            "incident_metrics": self._incident_metrics.status(),
            "artifact_store": self._artifact_store.status(),
        }

    def invoke_domain(
        self,
        operation: str,
        arguments: Mapping[str, object],
        *,
        task_id: str,
        operation_id: str,
        context_mode: str,
        external_context_marker: bool,
    ) -> dict[str, object]:
        descriptor = self._catalog.require(operation)
        context_arguments: Mapping[str, object] = arguments
        domain_arguments = {
            key: value
            for key, value in arguments.items()
            if key not in {"case_id", "expected_revision", "idempotency_key"}
            and not key.startswith("_workflow_")
            and key != "_context_defaults_inferred"
        }
        if context_mode == "authoritative" and not external_context_marker:
            domain_arguments.pop("workflow", None)
            if self._orchestrated_backend:
                domain_arguments["_context_authoritative"] = True
        if descriptor.mutation or operation == "debug_collect":
            minimum_target_epoch = self._context_runtime.minimum_target_epoch(
                task_id,
                arguments,
            )
            domain_arguments.setdefault(
                "_minimum_target_epoch",
                minimum_target_epoch,
            )
            if operation == "debug_collect" and minimum_target_epoch > 0:
                context_arguments = dict(arguments)
                context_arguments.setdefault(
                    "_minimum_target_epoch",
                    minimum_target_epoch,
                )
        executor = lambda: self._domain_runtime.execute_value(
            operation,
            domain_arguments,
            task_id=task_id,
            operation_id=operation_id,
        )
        if context_mode == "shadow":
            legacy_value = executor()
            return self._context_runtime.shadow_domain(
                descriptor,
                context_arguments,
                task_id=task_id,
                operation_id=operation_id,
                value=legacy_value,
            )
        if external_context_marker and self._orchestrated_backend:
            return dict(executor())
        return self._context_runtime.invoke_domain(
            descriptor,
            context_arguments,
            task_id=task_id,
            operation_id=operation_id,
            executor=executor,
        )


class _RuntimeLifecyclePort:
    def __init__(self, effect_runner: LocalEffectRunner) -> None:
        self._effect_runner = effect_runner

    def close(self) -> None:
        self._effect_runner.close()


class _RuntimeTestSupport:
    """Private internal seams retained only for existing conformance tests."""

    def __init__(
        self,
        *,
        catalog: OperationCatalog,
        capability_registry: CapabilityRegistry,
        domain_executor: DomainExecutor,
        context_runtime: ContextRuntime,
        projector: ResultProjector,
        semantic_runtime: SemanticRuntime,
        observation_engine: ObservationEngine,
        run_engine: RunEngine,
        gateway: AgentGateway,
        lifecycle: _RuntimeLifecyclePort,
    ) -> None:
        self.catalog = catalog
        self.capability_registry = capability_registry
        self.domain_executor = domain_executor
        self.context_runtime = context_runtime
        self.projector = projector
        self.semantic_runtime = semantic_runtime
        self.observation_engine = observation_engine
        self.run_engine = run_engine
        self.gateway = gateway
        self._lifecycle = lifecycle

    @property
    def effect_runner(self) -> LocalEffectRunner:
        return self._lifecycle._effect_runner

    @effect_runner.setter
    def effect_runner(self, value: LocalEffectRunner) -> None:
        self._lifecycle._effect_runner = value


@dataclass(frozen=True)
class _RuntimeComposition:
    agent: _AgentRuntimePort
    transport: _RuntimeTransportPort
    operator: _RuntimeOperatorPort
    lifecycle: _RuntimeLifecyclePort
    artifact_store: LocalArtifactStore
    _test: _RuntimeTestSupport


class _CompatibilityBindingAdapter:
    def __init__(self, pack: DomainPack, adapter: DomainAdapter) -> None:
        self.pack = pack
        self.adapter = adapter

    def execute(
        self,
        context: RuntimeSDKContext,
        arguments: Mapping[str, object],
    ) -> DomainReceipt | Mapping[str, object]:
        value = self.adapter.execute(context, arguments)
        receipt_value = value.value if isinstance(value, DomainReceipt) else value
        bound_value = self.pack.bind_compatibility_receipt(
            receipt_value,
            operation_id=context.operation_id,
            arguments=arguments,
        )
        if isinstance(value, DomainReceipt):
            return replace(value, value=bound_value)
        return bound_value


def _bind_compatibility_receipts(pack: DomainPack) -> DomainPack:
    adapter = _CompatibilityBindingAdapter(pack, pack.adapter)
    reconciler = (
        _CompatibilityBindingAdapter(pack, pack.reconciler)
        if pack.reconciler is not None
        else None
    )
    return replace(pack, adapter=adapter, reconciler=reconciler)


def compose_runtime(
    definitions: Iterable[Mapping[str, object]],
    *,
    catalog_backend: object,
    invoke_domain_transport: DomainTransportInvoker,
    options: RuntimeCompositionOptions,
) -> _RuntimeComposition:
    """Build one Runtime Core object graph for a transport Adapter."""

    definitions = tuple(dict(definition) for definition in definitions)
    definition_names = tuple(str(definition["name"]) for definition in definitions)
    definition_name_set = set(definition_names)
    contracts = DEFAULT_OPERATION_CONTRACTS.contracts()
    contract_names = tuple(
        contract.name
        for contract in contracts
        if contract.name in definition_name_set
    )
    contract_by_name = {contract.name: contract for contract in contracts}
    if definition_names != contract_names or definition_name_set - set(
        contract_by_name
    ):
        raise RuntimeError(
            "operation definitions and contract metadata are out of sync"
        )
    catalog = OperationCatalog(
        (
            contract_by_name[str(definition["name"])].operation_descriptor(
                definition
            )
            for definition in definitions
        ),
        backend=catalog_backend,
    )
    capability_descriptors: list[CapabilityDescriptor] = []
    for operation_descriptor in catalog.descriptors():
        contract = DEFAULT_OPERATION_CONTRACTS.require(
            operation_descriptor.name
        )
        if contract.domain:
            capability_descriptors.append(
                contract.capability_descriptor(
                    operation_descriptor.input_schema
                )
            )
    capability_registry = CapabilityRegistry(capability_descriptors)
    transport_adapters = {
        descriptor.operation: CallableDomainAdapter(
            lambda sdk_context, sdk_arguments, operation=descriptor.operation: (
                invoke_domain_transport(operation, sdk_context, sdk_arguments)
            )
        )
        for descriptor in capability_registry.descriptors()
    }
    default_domain_pack_contracts = builtin_domain_pack_contracts(
        capability_registry,
        transport_adapters,
    )
    extension_definitions = (
        tuple(
            options.domain_pack_extensions(
                capability_registry,
                transport_adapters,
            )
        )
        if options.domain_pack_extensions is not None
        else ()
    )
    if any(
        not isinstance(definition, DomainPackAuthorContract)
        for definition in extension_definitions
    ):
        raise TypeError("Domain Pack extensions require author contracts")
    capability_registry = capability_registry.extend(
        definition.descriptor for definition in extension_definitions
    )
    catalog_names = set(catalog.names())
    new_extension_operations = {
        definition.operation
        for definition in extension_definitions
        if definition.operation not in catalog_names
    }
    catalog = catalog.extend(
        definition.operation_descriptor()
        for definition in extension_definitions
        if definition.operation in new_extension_operations
    )
    workflow_definitions = WorkflowDefinitions(
        DEFAULT_WORKFLOW_DEFINITIONS.registry.extend(
            operation_owners={
                definition.operation: definition.descriptor.owner_skill
                for definition in extension_definitions
            },
            routes=tuple(
                WorkflowRoute(
                    definition.workflow.intent,
                    (
                        ("operation", definition.operation),
                        (
                            "operation",
                            definition.workflow.verification_operation,
                        ),
                    ),
                    entry_operation=definition.operation,
                )
                for definition in extension_definitions
                if definition.workflow is not None
            ),
            strict_entry_operations=frozenset(
                definition.operation
                for definition in extension_definitions
            ),
        )
    )
    default_operations = {
        contract.operation for contract in default_domain_pack_contracts
    }
    extension_operations = {
        definition.operation
        for definition in extension_definitions
    }
    overlap = default_operations & extension_operations
    if overlap:
        raise ValueError(
            "Domain Pack extensions cannot replace Runtime Packs: "
            + ", ".join(sorted(overlap))
        )
    conformance_suite = DomainPackConformanceSuite()
    authored_packs = conformance_suite.bind(
        capability_registry,
        (*default_domain_pack_contracts, *extension_definitions),
    )
    domain_packs = tuple(
        _bind_compatibility_receipts(pack)
        for pack in authored_packs
    )
    conformance_report = conformance_suite.validate(
        capability_registry,
        domain_packs,
    )
    for pack in domain_packs:
        transport_adapters.pop(pack.descriptor.operation, None)
    domain_executor = DomainExecutor(
        capability_registry,
        transport_adapters,
        packs=domain_packs,
        conformance_report=conformance_report,
    )
    if options.context_runtime is not None and new_extension_operations:
        raise ValueError(
            "new Domain Pack operations require Runtime-owned ContextRuntime"
        )
    context_runtime = options.context_runtime or ContextRuntime(
        catalog,
        repository=options.context_repository,
        blob_repository=options.blob_repository,
        envelope_max_bytes=options.envelope_max_bytes,
        max_cached_projections=options.max_cached_projections,
        max_cached_projection_bytes=options.max_cached_projection_bytes,
        retention_seconds=options.retention_seconds,
        storage_soft_limit_bytes=options.storage_soft_limit_bytes,
        workflow_definitions=workflow_definitions,
        operation_stages={
            definition.operation: definition.closeout_stage
            for definition in extension_definitions
            if definition.closeout_stage
        },
    )
    base_context_repository = context_runtime.repository.base_repository
    telemetry_repository = options.compatibility_telemetry_repository
    if telemetry_repository is None:
        telemetry_repository = (
            SQLiteCompatibilityTelemetryRepository(base_context_repository.path)
            if isinstance(base_context_repository, SQLiteRuntimeRepository)
            else InMemoryCompatibilityTelemetryRepository()
        )
    compatibility_telemetry = CompatibilityTelemetry(telemetry_repository)
    agent_projector = ResultProjector()
    if options.artifact_store is not None:
        artifact_store = options.artifact_store
    elif isinstance(base_context_repository, SQLiteRuntimeRepository):
        artifact_store = LocalArtifactStore(
            content_root=base_context_repository.path.parent / "artifacts",
            repository=SQLiteArtifactRepository(base_context_repository.path),
        )
    else:
        artifact_store = LocalArtifactStore()
    domain_runtime = RuntimeDomainExecution(
        catalog=catalog,
        capability_registry=capability_registry,
        domain_executor=domain_executor,
        artifact_store=artifact_store,
        context_authoritative=options.orchestrated_backend,
    )
    semantic_adapter = RuntimeSemanticAdapter(
        catalog=catalog,
        context_runtime=context_runtime,
        domain_executor=domain_executor,
        domain_runtime=domain_runtime,
        agent_projector=agent_projector,
    )
    effect_runner = LocalEffectRunner(
        semantic_adapter.execute_effect,
        semantic_adapter.recover_effect,
    )
    observation_engine = ObservationEngine(semantic_adapter)
    run_engine = RunEngine(
        semantic_adapter,
        run_store=EventRunStore(
            context_runtime.repository.base_repository,
            draft_buffer=context_runtime.repository,
            fact_projector=agent_projector.run_facts,
        ),
        artifact_store=artifact_store,
        effect_runner=effect_runner,
        fact_projector=agent_projector.run_facts,
        workflow_definitions=workflow_definitions,
    )
    semantic_runtime = SemanticRuntime(
        observation_engine,
        run_engine,
    )
    incident_metrics = IncidentMetrics(context_runtime.repository)
    agent_gateway = AgentGateway(
        semantic_runtime,
        projector=agent_projector,
    )
    lifecycle = _RuntimeLifecyclePort(effect_runner)
    return _RuntimeComposition(
        agent=_AgentRuntimePort(
            semantic_runtime,
            agent_gateway,
        ),
        transport=_RuntimeTransportPort(
            catalog=catalog,
            capability_registry=capability_registry,
            domain_executor=domain_executor,
            compatibility_telemetry=compatibility_telemetry,
            incident_metrics=incident_metrics,
            domain_runtime=domain_runtime,
            context_runtime=context_runtime,
            artifact_store=artifact_store,
            orchestrated_backend=options.orchestrated_backend,
        ),
        operator=_RuntimeOperatorPort(context_runtime, artifact_store, run_engine),
        lifecycle=lifecycle,
        artifact_store=artifact_store,
        _test=_RuntimeTestSupport(
            catalog=catalog,
            capability_registry=capability_registry,
            domain_executor=domain_executor,
            context_runtime=context_runtime,
            projector=agent_projector,
            semantic_runtime=semantic_runtime,
            observation_engine=observation_engine,
            run_engine=run_engine,
            gateway=agent_gateway,
            lifecycle=lifecycle,
        ),
    )
