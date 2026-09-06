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


def _live_patch_journal_action(arguments: Mapping[str, object]) -> str:
    action = str(arguments.get("action", "")).strip().lower().replace("-", "_")
    return "rollback" if action == "rollback" else "live_patch"


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
