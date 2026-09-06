"""Canonical Runtime operation metadata shared by MCP, SDK, and Workflow."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .capability import CapabilityDescriptor, EffectClass
from .catalog import OperationDescriptor
from .contracts import RUNTIME_API_VERSION


OPERATION_CONTRACT_SCHEMA = f"{RUNTIME_API_VERSION}/operation-contract-v1"


@dataclass(frozen=True)
class RuntimeOperationContract:
    name: str
    domain: str = ""
    lifecycle: str = "invoke"
    handler_name: str | None = None
    mutation: bool = False
    effect_class: EffectClass | None = None
    workflow_entry: bool = False
    credential_values: bool = False
    capability: str = ""
    owner_skill: str = ""
    timeout_seconds: float = 0.0
    evidence_types: tuple[str, ...] = ()
    orchestration_phase: str = ""
    closeout_stage: str = ""
    exposure: str = "internal"
    audience: str = "internal"
    cost_hint: str = "unbounded"
    scope_contract: str = "legacy-operation"
    result_projector: str = "agent-envelope"

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Runtime operation name is required")
        if self.domain:
            required = {
                "handler_name": self.handler_name,
                "capability": self.capability,
                "owner_skill": self.owner_skill,
                "orchestration_phase": self.orchestration_phase,
                "closeout_stage": self.closeout_stage,
            }
            missing = [name for name, value in required.items() if not value]
            if missing or self.timeout_seconds <= 0 or not self.evidence_types:
                raise ValueError(
                    f"domain operation {self.name} has incomplete metadata: "
                    + ", ".join(missing)
                )
        elif any(
            (
                self.handler_name,
                self.capability,
                self.owner_skill,
                self.timeout_seconds,
                self.evidence_types,
                self.orchestration_phase,
                self.closeout_stage,
                self.workflow_entry,
                self.credential_values,
                self.mutation,
                self.effect_class,
            )
        ):
            raise ValueError(
                f"control operation {self.name} must not declare domain capability metadata"
            )

    def operation_descriptor(
        self,
        definition: Mapping[str, object],
    ) -> OperationDescriptor:
        return OperationDescriptor.from_tool_definition(
            definition,
            lifecycle=self.lifecycle,
            handler_name=self.handler_name,
            mutation=self.mutation,
            exposure=self.exposure,
            audience=self.audience,
            cost_hint=self.cost_hint,
            scope_contract=self.scope_contract,
            result_projector=self.result_projector,
        )

    @property
    def resolved_effect_class(self) -> EffectClass:
        return self.effect_class or (
            EffectClass.RECONCILABLE_MUTATION
            if self.mutation
            else EffectClass.READ_ONLY
        )

    def capability_descriptor(
        self,
        input_schema: Mapping[str, object],
    ) -> CapabilityDescriptor:
        if not self.domain:
            raise ValueError(f"control operation {self.name} has no Runtime capability")
        effect_class = self.resolved_effect_class
        return CapabilityDescriptor(
            operation=self.name,
            capability=self.capability,
            owner_skill=self.owner_skill,
            input_schema=input_schema,
            output_schema={"type": "object", "additionalProperties": True},
            timeout_seconds=self.timeout_seconds,
            evidence_types=self.evidence_types,
            mutation=effect_class is not EffectClass.READ_ONLY,
            effect_class=effect_class,
        )


@dataclass(frozen=True)
class LogBundleStageContract:
    operation: str
    input_kind: str
    output_kind: str
    capability: str
    timeout_seconds: float
    evidence_types: tuple[str, ...]
    phase: str
    description: str
    input_redacted: bool = False
    output_redacted: bool = False
    cost_hint: str = "medium"
    problem_required: bool = False

    def operation_contract(self) -> RuntimeOperationContract:
        return RuntimeOperationContract(
            self.operation,
            domain="log_analyzer",
            lifecycle="read",
            handler_name=self.operation,
            capability=self.capability,
            owner_skill="openubmc-log-analyzer",
            timeout_seconds=self.timeout_seconds,
            evidence_types=self.evidence_types,
            orchestration_phase=self.phase,
            closeout_stage=self.phase,
            exposure="internal",
            audience="internal",
            cost_hint=self.cost_hint,
            scope_contract="artifact-bound",
            result_projector="artifact-ref",
        )


LOG_BUNDLE_STAGE_CONTRACTS = (
    LogBundleStageContract(
        operation="log_bundle_index",
        input_kind="openubmc-log-bundle",
        output_kind="openubmc-log-index",
        capability="openubmc.logs.index",
        timeout_seconds=120.0,
        evidence_types=("diagnostic-bundle-index",),
        phase="bundle_index",
        description="Build a bounded local index for a verified Log Bundle ArtifactRef.",
    ),
    LogBundleStageContract(
        operation="log_bundle_query",
        input_kind="openubmc-log-index",
        output_kind="openubmc-log-query",
        capability="openubmc.logs.query",
        timeout_seconds=120.0,
        evidence_types=("bounded-log-query",),
        phase="bundle_query",
        description="Run one bounded redacted query over a verified Log Bundle index.",
        output_redacted=True,
        problem_required=True,
    ),
    LogBundleStageContract(
        operation="log_bundle_export",
        input_kind="openubmc-log-query",
        output_kind="openubmc-log-report",
        capability="openubmc.logs.export",
        timeout_seconds=60.0,
        evidence_types=("redacted-log-report",),
        phase="bundle_export",
        description="Persist one redacted report from a verified Log Bundle query ArtifactRef.",
        input_redacted=True,
        output_redacted=True,
        cost_hint="small",
    ),
)


class RuntimeOperationContractRegistry:
    """One metadata interface for transport, workflow, and SDK consumers."""

    def __init__(self, contracts: Iterable[RuntimeOperationContract]) -> None:
        ordered: list[RuntimeOperationContract] = []
        by_name: dict[str, RuntimeOperationContract] = {}
        for contract in contracts:
            if contract.name in by_name:
                raise ValueError(f"duplicate Runtime operation contract: {contract.name}")
            ordered.append(contract)
            by_name[contract.name] = contract
        if not ordered:
            raise ValueError("Runtime operation contract registry must not be empty")
        self._ordered = tuple(ordered)
        self._by_name = by_name

    def contracts(self) -> tuple[RuntimeOperationContract, ...]:
        return self._ordered

    def require(self, name: str) -> RuntimeOperationContract:
        try:
            return self._by_name[name]
        except KeyError as exc:
            raise ValueError(f"unknown Runtime operation contract: {name}") from exc

    def domain_contracts(self) -> tuple[RuntimeOperationContract, ...]:
        return tuple(contract for contract in self._ordered if contract.domain)

    def operation_owners(self) -> dict[str, str]:
        return {
            contract.name: contract.owner_skill
            for contract in self.domain_contracts()
        }

    def operation_domains(self) -> dict[str, str]:
        return {
            contract.name: contract.domain
            for contract in self.domain_contracts()
        }

    def domain_to_entry_operation(self) -> dict[str, str]:
        return {
            contract.domain: contract.name
            for contract in self.domain_contracts()
            if contract.workflow_entry
        }

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": OPERATION_CONTRACT_SCHEMA,
            "operations": [
                {
                    "name": contract.name,
                    "domain": contract.domain,
                    "lifecycle": contract.lifecycle,
                    "handler_name": contract.handler_name,
                    "mutation": contract.mutation,
                    "effect_class": contract.resolved_effect_class.value,
                    "workflow_entry": contract.workflow_entry,
                    "credential_values": contract.credential_values,
                    "capability": contract.capability,
                    "owner_skill": contract.owner_skill,
                    "timeout_seconds": contract.timeout_seconds,
                    "evidence_types": list(contract.evidence_types),
                    "orchestration_phase": contract.orchestration_phase,
                    "closeout_stage": contract.closeout_stage,
                    "exposure": contract.exposure,
                    "audience": contract.audience,
                    "cost_hint": contract.cost_hint,
                    "scope_contract": contract.scope_contract,
                    "result_projector": contract.result_projector,
                }
                for contract in self._ordered
            ],
        }


def _operator_contract(
    name: str,
    *,
    lifecycle: str = "invoke",
) -> RuntimeOperationContract:
    """Keep operator exposure and audience as one internal metadata invariant."""

    return RuntimeOperationContract(
        name,
        lifecycle=lifecycle,
        exposure="operator",
        audience="operator",
    )


DEFAULT_OPERATION_CONTRACTS = RuntimeOperationContractRegistry(
    (
        RuntimeOperationContract(
            "debug_run",
            domain="debug",
            handler_name="debug_run",
            workflow_entry=True,
            credential_values=True,
            capability="openubmc.debug.diagnose",
            owner_skill="openubmc-debug",
            timeout_seconds=300.0,
            evidence_types=("diagnosis", "runtime-observation"),
            orchestration_phase="diagnosis",
            closeout_stage="diagnosis",
        ),
        RuntimeOperationContract(
            "debug_collect",
            domain="debug",
            handler_name="debug_collect",
            credential_values=True,
            capability="openubmc.debug.verify",
            owner_skill="openubmc-debug",
            timeout_seconds=180.0,
            evidence_types=("runtime-verification", "acceptance-outcome"),
            orchestration_phase="fresh_verification",
            closeout_stage="verification",
        ),
        RuntimeOperationContract(
            "log_bundle_collect",
            domain="log_analyzer",
            handler_name="log_bundle_collect",
            workflow_entry=True,
            credential_values=True,
            capability="openubmc.logs.bundle",
            owner_skill="openubmc-log-analyzer",
            timeout_seconds=600.0,
            evidence_types=("diagnostic-bundle", "collection-outcome"),
            orchestration_phase="bundle",
            closeout_stage="bundle",
            effect_class=EffectClass.IDEMPOTENT_MUTATION,
        ),
        *(stage.operation_contract() for stage in LOG_BUNDLE_STAGE_CONTRACTS),
        RuntimeOperationContract(
            "live_patch_run",
            domain="live_patch",
            handler_name="live_patch_run",
            mutation=True,
            workflow_entry=True,
            credential_values=True,
            capability="openubmc.delivery.live-patch",
            owner_skill="openubmc-live-patch",
            timeout_seconds=600.0,
            evidence_types=("mutation-journal", "deployment-verification"),
            orchestration_phase="mutation",
            closeout_stage="live_patch",
        ),
        RuntimeOperationContract(
            "upgrade_run",
            domain="upgrade",
            handler_name="upgrade_run",
            mutation=True,
            workflow_entry=True,
            credential_values=True,
            capability="openubmc.delivery.upgrade",
            owner_skill="openubmc-upgrade",
            timeout_seconds=1800.0,
            evidence_types=("mutation-journal", "deployment-identity"),
            orchestration_phase="mutation",
            closeout_stage="upgrade",
        ),
        RuntimeOperationContract(
            "upgrade_batch",
            domain="upgrade",
            handler_name="upgrade_batch",
            mutation=True,
            credential_values=True,
            capability="openubmc.delivery.upgrade.batch",
            owner_skill="openubmc-upgrade",
            timeout_seconds=3600.0,
            evidence_types=("mutation-journal", "deployment-identity"),
            orchestration_phase="mutation",
            closeout_stage="upgrade",
        ),
        _operator_contract("case_read", lifecycle="read"),
        _operator_contract("evidence_attach"),
        _operator_contract("evidence_query", lifecycle="read"),
        _operator_contract("evidence_read", lifecycle="read"),
        _operator_contract("case_replay_export", lifecycle="read"),
        _operator_contract("case_replay_run", lifecycle="read"),
        _operator_contract("session_outcome_record"),
        _operator_contract("session_outcome_summary", lifecycle="read"),
        _operator_contract("session_outcome_transition"),
        _operator_contract("session_outcome_promote"),
        _operator_contract("case_close", lifecycle="close"),
        _operator_contract("case_forget", lifecycle="close"),
        _operator_contract("runtime_status", lifecycle="status"),
    )
)
