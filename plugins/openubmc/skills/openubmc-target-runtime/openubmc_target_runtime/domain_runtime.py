"""Runtime-owned Domain execution, normalization, and Artifact resolution."""
from __future__ import annotations

from collections.abc import Mapping

from .artifact_store import LocalArtifactStore
from .capability import (
    CapabilityRegistry,
    DomainExecutor,
    EffectRecoveryMode,
    RuntimeSDKContext,
)
from .catalog import OperationCatalog, OperationDescriptor
from .effect_runner import EffectIntent
from .semantic_runtime import ArtifactRef


def canonicalize_tool_arguments(
    name: str,
    arguments: Mapping[str, object],
) -> dict[str, object]:
    canonical = dict(arguments)
    inferred_defaults = False
    for field in ("intent", "delivery_strategy"):
        value = canonical.get(field)
        if isinstance(value, str):
            canonical[field] = value.strip().lower().replace("_", "-")
    intent = canonical.get("intent")
    if not isinstance(intent, str) or not intent.strip():
        inferred_intent = {
            "live_patch_run": "live-patch",
            "upgrade_run": "upgrade-and-verify",
        }.get(name)
        if inferred_intent:
            canonical["intent"] = inferred_intent
            inferred_defaults = True
    if name == "live_patch_run":
        action = canonical.get("action")
        if isinstance(action, str):
            normalized = action.strip().lower().replace("-", "_")
            if normalized == "live_patch":
                canonical["action"] = "apply"
        expected_current = canonical.get("expected_current_sha256")
        if isinstance(expected_current, str) and not expected_current.strip():
            canonical.pop("expected_current_sha256", None)
    intent = canonical.get("intent")
    delivery = canonical.get("delivery_strategy")
    if (
        intent == "diagnose-and-fix"
        and (not isinstance(delivery, str) or not delivery.strip())
    ):
        workflow = canonical.get("workflow")
        inferred = ""
        if isinstance(workflow, Mapping):
            has_build_upgrade = "build" in workflow or "upgrade" in workflow
            has_live_patch = "live_patch" in workflow
            if has_build_upgrade and has_live_patch:
                raise ValueError(
                    "diagnose-and-fix workflow cannot mix live_patch with build/upgrade"
                )
            if has_build_upgrade:
                inferred = "build-upgrade"
            elif has_live_patch:
                inferred = "live-patch"
            elif "developer" in workflow:
                inferred = "source-only"
        if not inferred and name == "live_patch_run":
            inferred = "live-patch"
        elif not inferred and name == "upgrade_run":
            inferred = "build-upgrade"
        canonical["delivery_strategy"] = inferred or "source-only"
    elif not isinstance(delivery, str) or not delivery.strip():
        if intent in {"live-patch", "rollback"}:
            canonical["delivery_strategy"] = "live-patch"
        elif intent == "upgrade-and-verify":
            canonical["delivery_strategy"] = "build-upgrade"
    if inferred_defaults:
        canonical["_context_defaults_inferred"] = True
    return canonical


def validate_boolean_argument_types(
    descriptor: OperationDescriptor,
    arguments: Mapping[str, object],
) -> None:
    properties = descriptor.input_schema.get("properties", {})
    if not isinstance(properties, Mapping):
        return
    for field, schema in properties.items():
        if (
            field in arguments
            and isinstance(schema, Mapping)
            and schema.get("type") == "boolean"
            and not isinstance(arguments[field], bool)
        ):
            raise TypeError(f"{field} must be a boolean")


class RuntimeDomainExecution:
    """Own DomainExecutor calls and the Runtime-side Effect contract."""

    def __init__(
        self,
        *,
        catalog: OperationCatalog,
        capability_registry: CapabilityRegistry,
        domain_executor: DomainExecutor,
        artifact_store: LocalArtifactStore,
        context_authoritative: bool,
    ) -> None:
        self.catalog = catalog
        self.capability_registry = capability_registry
        self.domain_executor = domain_executor
        self.artifact_store = artifact_store
        self.context_authoritative = context_authoritative

    @staticmethod
    def _timeout(arguments: Mapping[str, object]) -> float:
        raw = arguments.get("deadline", 600)
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise ValueError("deadline must be a positive number")
        timeout = float(raw)
        if timeout <= 0:
            raise ValueError("deadline must be a positive number")
        return timeout

    def execute_value(
        self,
        name: str,
        domain_arguments: Mapping[str, object],
        *,
        task_id: str,
        operation_id: str,
        recovery_mode: EffectRecoveryMode | None = None,
    ) -> dict[str, object]:
        capability_descriptor = self.capability_registry.require(name)
        timeout = min(
            self._timeout(domain_arguments),
            capability_descriptor.timeout_seconds,
        )
        bounded_arguments = dict(domain_arguments)
        raw_artifact_ref = bounded_arguments.get("artifact_ref")
        if isinstance(raw_artifact_ref, Mapping) and raw_artifact_ref:
            reference = ArtifactRef.from_public_dict(raw_artifact_ref)
            pack = self.domain_executor.pack_for(name)
            contract = pack.artifact_contract if pack is not None else None
            if contract is None:
                raise ValueError("Domain Effect does not accept an ArtifactRef")
            expected_kind = contract.artifact_kind
            expected_target = str(bounded_arguments.get("ip", "")).strip()
            if expected_target and reference.target != expected_target:
                raise ValueError("Domain Effect ArtifactRef targets another BMC")
            if reference.run_id != task_id:
                raise ValueError("Domain Effect ArtifactRef belongs to another Run")
            artifact_path = (
                self.artifact_store.path_for(reference)
                if recovery_mode is EffectRecoveryMode.RECONCILE
                else self.artifact_store.resolve(
                    reference,
                    expected_kinds=(expected_kind,) if expected_kind else (),
                    expected_target=expected_target,
                    expected_run_id=task_id,
                    require_redacted=contract.require_redacted,
                )
            )
            bounded_arguments["artifact_ref"] = reference.to_public_dict()
            bounded_arguments.update(
                contract.runtime_arguments(reference, artifact_path)
            )
        execute = (
            self.domain_executor.reconcile
            if recovery_mode is EffectRecoveryMode.RECONCILE
            else self.domain_executor.execute
        )
        domain_result = execute(
            name,
            context=RuntimeSDKContext(
                task_id=task_id,
                operation_id=operation_id,
                timeout_seconds=timeout,
                target_id=str(bounded_arguments.get("target_id", "")),
                minimum_target_epoch=int(
                    bounded_arguments.get("_minimum_target_epoch", 0)
                ),
                recovery_mode=recovery_mode,
            ),
            arguments=bounded_arguments,
        )
        result = dict(domain_result.value)
        pack = self.domain_executor.pack_for(name)
        result_contract = (
            pack.result_artifact_contract if pack is not None else None
        )
        if result_contract is not None:
            reference = result_contract.bind(
                domain_result.action,
                domain_result.receipt,
            )
            self.artifact_store.resolve(
                reference,
                expected_kinds=(result_contract.artifact_kind,),
                expected_target=str(bounded_arguments.get("ip", "")).strip(),
                expected_run_id=task_id,
                require_redacted=result_contract.require_redacted,
            )
        if isinstance(raw_artifact_ref, Mapping) and raw_artifact_ref:
            reference = ArtifactRef.from_public_dict(raw_artifact_ref)
            result.setdefault("artifact_ref", reference.to_public_dict())
            result.setdefault("artifact_sha256", reference.digest)
            if reference.version:
                result.setdefault("product_version", reference.version)
        return result

    def execute_effect(
        self,
        intent: EffectIntent,
        *,
        recovery: bool = False,
    ) -> Mapping[str, object]:
        descriptor = self.catalog.require(intent.operation)
        if recovery and not descriptor.mutation:
            raise ValueError("only Mutation Effects require reconcile recovery")
        domain_arguments = {
            key: value
            for key, value in intent.arguments.items()
            if key not in {"case_id", "expected_revision", "idempotency_key"}
            and not key.startswith("_workflow_")
            and key
            not in {
                "_context_defaults_inferred",
                "_context_workflow_step",
            }
        }
        if self.context_authoritative:
            domain_arguments["_context_authoritative"] = True
        return self.execute_value(
            intent.operation,
            domain_arguments,
            task_id=intent.run_id,
            operation_id=intent.effect_id,
            recovery_mode=(
                EffectRecoveryMode.RECONCILE if recovery else None
            ),
        )

    def observe_direct(
        self,
        name: str,
        arguments: Mapping[str, object],
        *,
        task_id: str,
        operation_id: str,
    ) -> dict[str, object]:
        if name not in {"debug_collect", "debug_run"}:
            raise ValueError(f"unsupported observation adapter: {name}")
        descriptor = self.catalog.require(name)
        raw_arguments = dict(arguments)
        capability_names = raw_arguments.pop("_agent_capability_names", [])
        selectors = raw_arguments.pop("_agent_selectors", [])
        assured = raw_arguments.pop("_agent_assured", False)
        prior_observation = raw_arguments.pop("_agent_prior_observation", None)
        if not isinstance(capability_names, list) or not all(
            isinstance(item, str) for item in capability_names
        ):
            raise TypeError("_agent_capability_names must be an array of strings")
        if not isinstance(selectors, list) or not all(
            isinstance(item, Mapping) for item in selectors
        ):
            raise TypeError("_agent_selectors must be an array of objects")
        if not isinstance(assured, bool):
            raise TypeError("_agent_assured must be a boolean")
        if prior_observation is not None and not isinstance(
            prior_observation,
            Mapping,
        ):
            raise TypeError("_agent_prior_observation must be an object")
        canonical = canonicalize_tool_arguments(name, raw_arguments)
        for internal_name in (
            "_task_authorization_policy",
            "_task_intent",
            "_task_delivery_strategy",
            "_task_authorized_exceptions",
            "_credential_values",
            "_credential_values_by_target",
        ):
            canonical.pop(internal_name, None)
        validate_boolean_argument_types(descriptor, canonical)
        self.catalog.validate_arguments(name, canonical)
        domain_arguments = {
            key: value
            for key, value in canonical.items()
            if key not in {"case_id", "expected_revision", "idempotency_key"}
            and not key.startswith("_workflow_")
            and key != "_context_defaults_inferred"
        }
        domain_arguments.pop("workflow", None)
        if self.context_authoritative:
            domain_arguments["_context_authoritative"] = True
        domain_arguments["_agent_observation"] = True
        domain_arguments["_agent_capability_names"] = list(capability_names)
        domain_arguments["_agent_selectors"] = [dict(item) for item in selectors]
        domain_arguments["_agent_assured"] = assured
        if isinstance(prior_observation, Mapping):
            domain_arguments["_agent_prior_observation"] = dict(
                prior_observation
            )
        return self.execute_value(
            name,
            domain_arguments,
            task_id=task_id,
            operation_id=operation_id,
        )
