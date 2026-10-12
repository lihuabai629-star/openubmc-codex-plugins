"""Built-in Domain Pack registrations for proven Runtime mutation domains."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib

from .capability import (
    ArtifactContract,
    CapabilityRegistry,
    DomainAdapter,
    DomainPack,
    DomainPackAuthorContract,
    DomainPackConformanceExample,
    DomainPackConformanceSuite,
    DomainReceipt,
    EffectClass,
    ResultArtifactContract,
    mutation_receipt_verifier,
)
from .operation_contracts import LOG_BUNDLE_STAGE_CONTRACTS
from .contracts import TargetIdentity
from .property_state import PropertyContract, PropertyValue, PropertyObservation, PropertyMutationState


def _live_patch_journal_action(arguments: Mapping[str, object]) -> str:
    action = str(arguments.get("action", "")).strip().lower().replace("-", "_")
    return "rollback" if action == "rollback" else "live_patch"


def _property_receipt_valid(action, receipt, *, verification: bool = False) -> bool:
    try:
        journal = receipt.value["journal"]
        state = PropertyMutationState.from_value(journal["property_state"])
        if (journal.get("action") != "mdb_property_modify" or state.contract.target.strip().lower() !=
                str(action.arguments.get("ip", "")).strip().lower()):
            return False
        if verification:
            if (journal["operation_id"] != action.arguments["_runtime_property_mutation_id"] or
                    journal.get("task_id") != action.context.task_id):
                return False
            observation = PropertyObservation.from_value(receipt.value["property_observation"])
            return (journal["stage"] == "verified" and
                    receipt.status == ("verified" if state.matches(observation) else "blocked"))
        if not mutation_receipt_verifier(action, receipt, journal_action="mdb_property_modify"):
            return False
        return (state.contract.contract_id == action.arguments["contract_id"]
                and state.expected == PropertyValue.from_value(action.arguments["expected_value"])
                and state.desired == PropertyValue.from_value(action.arguments["value"]))
    except (KeyError, TypeError, ValueError):
        return False


def _property_pack_contracts(registry, adapters) -> tuple[DomainPackAuthorContract, ...]:
    if "mdb_property_modify" not in adapters:
        return ()
    # Pure data conformance; these objects never contact a target.
    contract = PropertyContract(
        contract_id="interval", target="conformance-target", service="bmc.example.Owner",
        path="/bmc/example/Dashboard_0", interface="bmc.example.Configuration", property="Interval",
        object="Dashboard_0", base_type="U32", minimum=5, maximum=3600, source_sha256="c" * 64,
        firmware_id="fixture-v1", firmware_service="bmc.example.BMC", firmware_path="/bmc/example/BMC_00",
        firmware_interface="bmc.example.BMC", firmware_property="Version",
        generation_interface="bmc.example.Configuration", generation_property="Generation",
        override_interface="bmc.example.Configuration", override_property="OverrideActive",
        allowed_ssh_users=("operator",), persistence="runtime",
    )
    before = PropertyObservation(TargetIdentity(machine_id="fixture", firmware_id="fixture-v1", reboot_anchor="boot"),
        contract.fingerprint, ":1.2", "generation-1", PropertyValue("U32", 30), PropertyValue("U32", 30),
        False, True, "2026-01-01T00:00:00Z")
    state = PropertyMutationState(contract, before.value, PropertyValue("U32", 60), before)
    observation = PropertyObservation(before.target_identity, before.contract_digest, before.owner, before.generation,
        state.desired, state.desired, False, True, "2026-01-01T00:00:01Z")
    journal = {"schema": "openubmc.target-runtime.v1/mutation-journal", "task_id": "conformance-mdb_property_modify",
        "operation_id": "effect-conformance-mdb_property_modify", "operation_fingerprint": "a" * 64,
        "target_fingerprint": "b" * 64, "action": "mdb_property_modify", "stage": "verified",
        "effects_started": True, "property_state": state.to_public_dict()}
    mutation = DomainPackAuthorContract(
        descriptor=registry.require("mdb_property_modify"), name="mdb-property-modify", version="1",
        effect_class=EffectClass.RECONCILABLE_MUTATION, adapter=adapters["mdb_property_modify"],
        reconciler=adapters["mdb_property_modify"], verifier=_property_receipt_valid,
        journal_action=lambda _arguments: "mdb_property_modify", closeout_stage="property_update",
        conformance_example=DomainPackConformanceExample(arguments={"ip": contract.target,
            "contract_id": contract.contract_id, "expected_value": state.expected.to_public_dict(),
            "value": state.desired.to_public_dict()},
            receipt=DomainReceipt("mdb_property_modify", "verified", {"journal": journal,
                "operation_id": journal["operation_id"]})),
    )
    if "mdb_property_verify" not in adapters:
        raise ValueError("property mutation requires its read-only verifier")
    verification = DomainPackAuthorContract(
        descriptor=registry.require("mdb_property_verify"), name="mdb-property-verify", version="1",
        effect_class=EffectClass.READ_ONLY, adapter=adapters["mdb_property_verify"],
        verifier=lambda action, receipt: _property_receipt_valid(action, receipt, verification=True),
        closeout_stage="verification", conformance_example=DomainPackConformanceExample(
            arguments={"ip": contract.target, "_runtime_property_mutation_id": journal["operation_id"]},
            receipt=DomainReceipt("mdb_property_verify", "verified", {"journal": {**journal, "task_id": "conformance-mdb_property_verify"},
                "property_observation": observation.to_public_dict()})),
    )
    return mutation, verification


def _upgrade_journal_action(_arguments: Mapping[str, object]) -> str:
    return "upgrade"


def _mutation_conformance_example(
    operation: str,
    *,
    arguments: Mapping[str, object],
    journal_action: str,
) -> DomainPackConformanceExample:
    digest = str(arguments.get("artifact_sha256", "")).removeprefix("sha256:")
    return DomainPackConformanceExample(
        arguments={
            **dict(arguments),
            "ip": "conformance-target",
        },
        receipt=DomainReceipt(
            operation=operation,
            status="verified",
            value={
                "operation_id": f"effect-conformance-{operation}",
                "journal": {
                    "schema": "openubmc.target-runtime.v1/mutation-journal",
                    "task_id": f"conformance-{operation}",
                    "operation_id": f"effect-conformance-{operation}",
                    "operation_fingerprint": "a" * 64,
                    "target_fingerprint": "b" * 64,
                    "action": journal_action,
                    "stage": "verified",
                    "effects_started": True,
                    "expected_checksum": digest,
                },
            },
        ),
    )


def _artifact_ref(kind: str, *, target: str, run_id: str) -> dict[str, object]:
    digest = "c" * 64
    return {
        "handle": f"artifact://sha256/{digest}",
        "digest": digest,
        "kind": kind,
        "size": 1,
        "provenance": "domain-pack-conformance",
        "retention_hint": "temporary",
        "target": target,
        "run_id": run_id,
    }


def _batch_conformance_example() -> DomainPackConformanceExample:
    operation_id = "effect-conformance-upgrade_batch"
    target_id, host = "target-1", "conformance-target"
    suffix = hashlib.sha256(f"{target_id}\0{host}\0{443}".encode()).hexdigest()[:20]
    child_id = f"{operation_id}:target-{suffix}"
    journal = {
        "schema": "openubmc.target-runtime.v1/mutation-journal",
        "task_id": "conformance-upgrade_batch", "operation_id": child_id,
        "operation_fingerprint": "a" * 64, "target_fingerprint": "b" * 64,
        "action": "upgrade", "stage": "verified", "effects_started": True,
        "expected_checksum": "e" * 64,
    }
    return DomainPackConformanceExample(
        arguments={"targets": [{"target_id": target_id, "ip": host}],
                   "artifact_path": "/conformance/product.hpm", "artifact_sha256": "e" * 64,
                   "product_version": "1.0.0"},
        receipt=DomainReceipt(operation="upgrade_batch", status="succeeded", value={
            "batch_operation_id": operation_id, "status": "completed", "ok": True,
            "outcome_status": "succeeded", "target_epochs": {target_id: 1}, "epoch_after": 1,
            "total": 1, "succeeded": 1, "failed": 0, "unknown": 0, "skipped": 0,
            "targets": [{"target_id": target_id, "ip": host, "redfish_port": 443,
                         "operation_id": child_id, "requested_operation_id": child_id,
                         "epoch_after": 1,
                         "target_fingerprint": "b" * 64, "status": "completed", "journal": journal}],
        }),
    )


def _artifact_stage_conformance_example(
    operation: str,
    *,
    input_kind: str,
    output_kind: str,
) -> DomainPackConformanceExample:
    task_id = f"conformance-{operation}"
    return DomainPackConformanceExample(
        arguments={
            "ip": "conformance-target",
            "artifact_ref": _artifact_ref(
                input_kind,
                target="conformance-target",
                run_id=task_id,
            ),
        },
        receipt=DomainReceipt(
            operation=operation,
            status="succeeded",
            value={
                "artifact_ref": _artifact_ref(
                    output_kind,
                    target="conformance-target",
                    run_id=task_id,
                )
            },
        ),
    )


def builtin_domain_pack_contracts(
    registry: CapabilityRegistry,
    adapters: Mapping[str, DomainAdapter],
) -> tuple[DomainPackAuthorContract, ...]:
    """Author Runtime-owned mutation and local Artifact stage contracts."""

    definitions = {
        "live_patch_run": {
            "name": "live-patch",
            "closeout_stage": "live_patch",
            "artifact_phase": "developer.change",
            "artifact_contract": ArtifactContract(
                path_fields=("local_path", "backup_path"),
                digest_field="artifact_sha256",
                artifact_kind="openubmc-live-patch",
            ),
            "journal_action": _live_patch_journal_action,
            "conformance_example": _mutation_conformance_example(
                "live_patch_run",
                arguments={
                    "action": "apply",
                    "local_path": "/conformance/unit.lua",
                    "artifact_sha256": "d" * 64,
                },
                journal_action="live_patch",
            ),
        },
        "upgrade_run": {
            "name": "upgrade",
            "closeout_stage": "upgrade",
            "artifact_phase": "build.artifact",
            "artifact_contract": ArtifactContract(
                path_fields=("artifact_path",),
                digest_field="artifact_sha256",
                version_field="product_version",
                artifact_kind="openubmc-hpm",
                required=True,
            ),
            "journal_action": _upgrade_journal_action,
            "conformance_example": _mutation_conformance_example(
                "upgrade_run",
                arguments={
                    "artifact_path": "/conformance/product.hpm",
                    "artifact_sha256": "e" * 64,
                    "product_version": "1.0.0",
                },
                journal_action="upgrade",
            ),
        },
    }
    contracts: list[DomainPackAuthorContract] = []
    contracts.extend(_property_pack_contracts(registry, adapters))
    # Batch upgrade uses the same mutation journal contract as the single
    # target operation; the backend creates one child operation per target.
    try:
        registry.require("upgrade_batch")
        has_upgrade_batch = "upgrade_batch" in adapters
    except ValueError:
        has_upgrade_batch = False
    if has_upgrade_batch:
        definitions["upgrade_batch"] = {
            **definitions["upgrade_run"],
            "name": "upgrade-batch",
            "artifact_phase": "",
            "conformance_example": _batch_conformance_example(),
        }
    for operation, definition in definitions.items():
        adapter = adapters.get(operation)
        if adapter is None:
            continue
        journal_action = definition["journal_action"]
        contracts.append(
            DomainPackAuthorContract(
                descriptor=registry.require(operation),
                name=str(definition["name"]),
                version="1",
                effect_class=EffectClass.RECONCILABLE_MUTATION,
                adapter=adapter,
                reconciler=adapter,
                verifier=(
                    lambda action, receipt, resolve=journal_action: (
                        mutation_receipt_verifier(
                            action,
                            receipt,
                            journal_action=resolve(action.arguments),
                        )
                    )
                ),
                artifact_contract=definition["artifact_contract"],
                artifact_phase=str(definition["artifact_phase"]),
                journal_action=journal_action,
                conformance_example=definition["conformance_example"],
                closeout_stage=str(definition["closeout_stage"]),
            )
        )
    for stage in LOG_BUNDLE_STAGE_CONTRACTS:
        adapter = adapters.get(stage.operation)
        if adapter is None:
            continue
        result_contract = ResultArtifactContract(
            stage.output_kind,
            require_redacted=stage.output_redacted,
        )
        contracts.append(
            DomainPackAuthorContract(
                descriptor=registry.require(stage.operation),
                name=stage.operation.replace("_", "-"),
                version="1",
                effect_class=EffectClass.READ_ONLY,
                adapter=adapter,
                verifier=(
                    lambda action, receipt, contract=result_contract: (
                        contract.bind(action, receipt) is not None
                    )
                ),
                artifact_contract=ArtifactContract(
                    path_fields=("_artifact_path",),
                    digest_field="_artifact_sha256",
                    artifact_kind=stage.input_kind,
                    required=True,
                    reference_required=True,
                    require_redacted=stage.input_redacted,
                ),
                result_artifact_contract=result_contract,
                conformance_example=_artifact_stage_conformance_example(
                    stage.operation,
                    input_kind=stage.input_kind,
                    output_kind=stage.output_kind,
                ),
            )
        )
    return tuple(contracts)


def builtin_domain_packs(
    registry: CapabilityRegistry,
    adapters: Mapping[str, DomainAdapter],
) -> tuple[DomainPack, ...]:
    """Bind built-in author contracts through the public conformance seam."""

    return DomainPackConformanceSuite().bind(
        registry,
        builtin_domain_pack_contracts(registry, adapters),
    )
