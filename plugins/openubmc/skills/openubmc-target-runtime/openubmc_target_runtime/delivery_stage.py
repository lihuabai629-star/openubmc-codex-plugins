"""Explicit delivery-stage semantics for closeout claims.

The legacy case stages remain useful for ownership, but they do not by
themselves prove product delivery.  This module maps accepted stage receipts
to the ordered delivery stages and keeps live-patch identity separate from a
packaged HPM identity.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence


DELIVERY_STAGES = (
    "diagnosed",
    "patched",
    "component-built",
    "product-built",
    "packaged",
    "deployed",
    "runtime-verified",
    "rollback-verified",
)


def _completed(receipt: Mapping[str, object] | None) -> bool:
    return bool(receipt) and receipt.get("status") == "completed" and bool(
        receipt.get("evidence_ids")
    )


def _facts(receipt: Mapping[str, object] | None) -> Mapping[str, object]:
    value = receipt.get("facts", {}) if isinstance(receipt, Mapping) else {}
    return value if isinstance(value, Mapping) else {}


def _artifact(receipt: Mapping[str, object] | None) -> Mapping[str, object]:
    values = receipt.get("artifacts", []) if isinstance(receipt, Mapping) else []
    if isinstance(values, Sequence) and not isinstance(values, (str, bytes, bytearray)):
        for value in values:
            if isinstance(value, Mapping):
                return value
    return {}


def _identity(receipt: Mapping[str, object] | None) -> dict[str, str]:
    facts = _facts(receipt)
    artifact = _artifact(receipt)
    aliases = {
        "artifact_sha256": (
            facts.get("artifact_sha256"),
            artifact.get("sha256"),
            artifact.get("digest"),
        ),
        "product_version": (
            facts.get("product_version"),
            artifact.get("version"),
        ),
        "target_id": (facts.get("target_id"), artifact.get("target_id")),
        "target_address": (
            facts.get("target_address"),
            facts.get("address"),
            artifact.get("target_address"),
            artifact.get("target"),
        ),
    }
    result: dict[str, str] = {}
    for name, values in aliases.items():
        selected = next((str(value).strip() for value in values if str(value or "").strip()), "")
        if selected:
            result[name] = selected.removeprefix("sha256:") if name == "artifact_sha256" else selected
    return result


def _same_identity(
    expected: Mapping[str, str],
    observed: Mapping[str, str],
    *,
    required: Sequence[str],
) -> bool:
    return all(
        bool(expected.get(field))
        and bool(observed.get(field))
        and expected[field] == observed[field]
        for field in required
    )


def _release_gates_passed(facts: Mapping[str, object]) -> bool:
    release = facts.get("release_gates")
    return (
        isinstance(release, Mapping)
        and release.get("status") == "accepted"
        and not release.get("failed_gates")
    )


def _service_gate_passed(
    facts: Mapping[str, object],
    deployment_identity: Mapping[str, str],
) -> bool:
    gate = facts.get("service_start")
    if not isinstance(gate, Mapping) or gate.get("status") != "pass":
        return False
    checks = gate.get("checks")
    command = gate.get("command")
    if (
        not isinstance(checks, Sequence)
        or isinstance(checks, (str, bytes, bytearray))
        or not checks
        or any(not isinstance(item, Mapping) or item.get("active") is not True for item in checks)
        or not isinstance(command, Sequence)
        or isinstance(command, (str, bytes, bytearray))
        or not command
        or not str(gate.get("observed_at", "")).strip()
    ):
        return False
    bound = {
        "target_id": str(gate.get("target", "")).strip(),
        "target_address": str(gate.get("address", "")).strip(),
        "product_version": str(gate.get("version", "")).strip(),
    }
    return _same_identity(
        deployment_identity,
        bound,
        required=("target_id", "target_address", "product_version"),
    )


def _rollback_passed(receipt: Mapping[str, object] | None) -> bool:
    if not _completed(receipt):
        return False
    facts = _facts(receipt)
    recovery = facts.get("recovery_artifact")
    verification = facts.get("rollback_verification")
    if not isinstance(recovery, Mapping) or not isinstance(verification, Mapping):
        return False
    if recovery.get("established_before_mutation") is not True:
        return False
    if verification.get("status") not in {"pass", "verified"}:
        return False
    evidence_ids = verification.get("evidence_ids")
    if not isinstance(evidence_ids, list) or not evidence_ids:
        return False
    recovery_sha = str(recovery.get("sha256", "")).removeprefix("sha256:")
    verification_sha = str(verification.get("artifact_sha256", "")).removeprefix("sha256:")
    return (
        facts.get("rollback_verified") is True
        and bool(recovery_sha)
        and recovery_sha == verification_sha
        and str(recovery.get("version", "")).strip()
        == str(verification.get("version", "")).strip()
    )


def assess_delivery_stages(receipts: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Return the highest stage supported by explicit, identity-bound facts."""
    by_stage: dict[str, Mapping[str, object]] = {}
    for raw in receipts:
        if not isinstance(raw, Mapping):
            continue
        stage = str(raw.get("stage", ""))
        current = by_stage.get(stage)
        if current is None or _completed(raw):
            by_stage[stage] = raw

    support: dict[str, dict[str, object]] = {}
    diagnosis = by_stage.get("diagnosis")
    support["diagnosed"] = {
        "verified": _completed(diagnosis),
        "evidence_ids": list(diagnosis.get("evidence_ids", [])) if _completed(diagnosis) else [],
        "required": "completed diagnosis receipt with current evidence",
    }
    development = by_stage.get("development")
    development_facts = _facts(development)
    patched = _completed(development) and bool(
        development_facts.get("authored_files") or development_facts.get("patch_identity")
    )
    support["patched"] = {
        "verified": patched,
        "evidence_ids": list(development.get("evidence_ids", [])) if patched else [],
        "required": "completed development receipt with authored files or patch identity",
    }
    build = by_stage.get("build")
    build_facts = _facts(build)
    build_artifact = _artifact(build)
    build_identity = _identity(build)
    product = _completed(build) and (
        str(build_artifact.get("kind", "")).lower() in {"openubmc-hpm", "hpm", "product-image"}
        or str(build_facts.get("artifact_kind", "")).lower() in {"openubmc-hpm", "hpm", "product-image"}
    )
    component = _completed(build) and (
        product
        or bool(build_facts.get("component_versions"))
        or str(build_artifact.get("kind", "")).lower() in {"component-package", "conan-package"}
    )
    support["component-built"] = {
        "verified": component,
        "evidence_ids": list(build.get("evidence_ids", [])) if component else [],
        "required": "component artifact identity and build evidence",
    }
    support["product-built"] = {
        "verified": product,
        "evidence_ids": list(build.get("evidence_ids", [])) if product else [],
        "required": "product artifact identity and build evidence",
        "identity": build_identity if product else {},
    }
    package_binding = str(build_facts.get("package_binding", ""))
    packaged = (
        product
        and package_binding == "package_binding_verified"
        and _release_gates_passed(build_facts)
        and bool(build_identity.get("artifact_sha256"))
        and bool(build_identity.get("product_version"))
    )
    support["packaged"] = {
        "verified": packaged,
        "evidence_ids": list(build.get("evidence_ids", [])) if packaged else [],
        "required": "final package identity, containment, and release gates",
        "identity": build_identity if packaged else {},
    }
    deployment = by_stage.get("upgrade") or by_stage.get("live_patch")
    deployment_identity = _identity(deployment)
    deployed = _completed(deployment) and (
        str(deployment.get("stage", "")) == "live_patch"
        or _same_identity(
            build_identity,
            deployment_identity,
            required=("artifact_sha256", "product_version"),
        )
    ) and bool(deployment_identity.get("target_id")) and bool(
        deployment_identity.get("target_address")
    )
    support["deployed"] = {
        "verified": deployed,
        "evidence_ids": list(deployment.get("evidence_ids", [])) if deployed else [],
        "required": "deployment receipt bound to target and artifact identity",
        "identity": deployment_identity if deployed else {},
    }
    verification = by_stage.get("verification")
    verification_facts = _facts(verification)
    verification_identity = _identity(verification)
    runtime_verified = (
        _completed(verification)
        and (
            verification_facts.get("freshness") in {"fresh", "verified"}
            or verification_facts.get("verification_status") == "verified"
        )
        and _same_identity(
            deployment_identity,
            verification_identity,
            required=(
                "artifact_sha256",
                "product_version",
                "target_id",
                "target_address",
            ),
        )
        and _service_gate_passed(verification_facts, deployment_identity)
    )
    support["runtime-verified"] = {
        "verified": runtime_verified,
        "evidence_ids": list(verification.get("evidence_ids", [])) if runtime_verified else [],
        "required": "fresh target runtime and required-service verification for the deployed identity",
        "identity": verification_identity if runtime_verified else {},
    }
    rollback = any(_rollback_passed(item) for item in receipts if isinstance(item, Mapping))
    rollback_receipts = [
        item for item in receipts
        if isinstance(item, Mapping)
        and (_facts(item).get("rollback_verified") is True or str(item.get("stage", "")) == "rollback")
    ]
    support["rollback-verified"] = {
        "verified": rollback,
        "evidence_ids": [
            evidence_id
            for item in rollback_receipts
            for evidence_id in item.get("evidence_ids", [])
        ] if rollback else [],
        "required": "independent rollback receipt and post-rollback verification",
    }

    highest_index = -1
    for index, stage in enumerate(DELIVERY_STAGES):
        if support[stage]["verified"]:
            highest_index = index
        else:
            break
    highest = DELIVERY_STAGES[highest_index] if highest_index >= 0 else None
    next_stage = DELIVERY_STAGES[highest_index + 1] if highest_index + 1 < len(DELIVERY_STAGES) else None
    return {
        "schema": "openubmc.delivery-stage/v1",
        "highest": highest,
        "next": next_stage,
        "stages": support,
    }


def identity_split(
    receipts: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Expose package and live-patch identities independently."""
    packaged: dict[str, object] = {}
    live_patch: dict[str, object] = {}
    for receipt in receipts:
        if not isinstance(receipt, Mapping):
            continue
        destination = live_patch if receipt.get("stage") == "live_patch" else packaged
        for key in ("artifact_sha256", "artifact_path", "product_version", "source_revision"):
            value = _facts(receipt).get(key)
            if value and key not in destination:
                destination[key] = value
        artifact = _artifact(receipt)
        for key in ("sha256", "path", "version", "source_revision"):
            if artifact.get(key) and key not in destination:
                destination[{"sha256": "artifact_sha256", "path": "artifact_path", "version": "product_version"}.get(key, key)] = artifact[key]
    result: dict[str, object] = {"packaged": packaged, "live_patch": live_patch}
    if packaged and live_patch and packaged != live_patch:
        result["diverged"] = True
    else:
        result["diverged"] = False
    return result
