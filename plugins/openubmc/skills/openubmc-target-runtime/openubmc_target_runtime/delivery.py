"""Immutable source-to-target delivery identity contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import re

from .contracts import RUNTIME_API_VERSION


DELIVERY_RECORD_SCHEMA = f"{RUNTIME_API_VERSION}/delivery-record-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _fingerprint(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class ArtifactIdentity:
    source_revision: str
    path: str
    sha256: str
    product_version: str

    def __post_init__(self) -> None:
        if not self.source_revision.strip():
            raise ValueError("artifact identity requires source_revision")
        if not self.path.strip():
            raise ValueError("artifact identity requires path")
        if _SHA256.fullmatch(self.sha256.lower()) is None:
            raise ValueError("artifact identity requires a SHA-256 digest")
        if not self.product_version.strip():
            raise ValueError("artifact identity requires product_version")

    def to_public_dict(self) -> dict[str, object]:
        return {
            "source_revision": self.source_revision,
            "path": self.path,
            "sha256": self.sha256.lower(),
            "product_version": self.product_version,
        }


@dataclass(frozen=True)
class DeploymentIdentity:
    operation_id: str
    target_id: str
    requested_version: str
    active_version: str
    target_epoch: int | None
    status: str
    mutation_journal_id: str = ""
    rollback_identity: str = ""

    def __post_init__(self) -> None:
        if not self.operation_id.strip():
            raise ValueError("deployment identity requires operation_id")
        if not self.target_id.strip():
            raise ValueError("deployment identity requires target_id")
        if self.target_epoch is not None and self.target_epoch < 0:
            raise ValueError("deployment target_epoch must be non-negative")

    def to_public_dict(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "target_id": self.target_id,
            "requested_version": self.requested_version,
            "active_version": self.active_version,
            "target_epoch": self.target_epoch,
            "status": self.status,
            "mutation_journal_id": self.mutation_journal_id,
            "rollback_identity": self.rollback_identity,
        }


@dataclass(frozen=True)
class DeliveryOutcome:
    deployment_integrity: str
    active_identity: str
    business_validation: str
    overall: str

    def to_public_dict(self) -> dict[str, object]:
        return {
            "deployment_integrity": self.deployment_integrity,
            "active_identity": self.active_identity,
            "business_validation": self.business_validation,
            "overall": self.overall,
        }


@dataclass(frozen=True)
class DeliveryRecord:
    record_id: str
    case_id: str
    strategy: str
    artifact: ArtifactIdentity
    deployment: DeploymentIdentity
    outcome: DeliveryOutcome
    evidence_ids: tuple[str, ...]
    rollback_of: str = ""

    @classmethod
    def create(
        cls,
        *,
        case_id: str,
        strategy: str,
        artifact: ArtifactIdentity,
        deployment: DeploymentIdentity,
        outcome: DeliveryOutcome,
        evidence_ids: Sequence[str],
        rollback_of: str = "",
    ) -> "DeliveryRecord":
        identity = {
            "schema": DELIVERY_RECORD_SCHEMA,
            "case_id": case_id,
            "strategy": strategy,
            "artifact": artifact.to_public_dict(),
            "deployment": deployment.to_public_dict(),
            "outcome": outcome.to_public_dict(),
            "evidence_ids": list(dict.fromkeys(evidence_ids)),
            "rollback_of": rollback_of,
        }
        return cls(
            record_id="delivery-" + _fingerprint(identity),
            case_id=case_id,
            strategy=strategy,
            artifact=artifact,
            deployment=deployment,
            outcome=outcome,
            evidence_ids=tuple(identity["evidence_ids"]),
            rollback_of=rollback_of,
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": DELIVERY_RECORD_SCHEMA,
            "record_id": self.record_id,
            "case_id": self.case_id,
            "strategy": self.strategy,
            "artifact": self.artifact.to_public_dict(),
            "deployment": self.deployment.to_public_dict(),
            "outcome": self.outcome.to_public_dict(),
            "evidence_ids": list(self.evidence_ids),
            "rollback_of": self.rollback_of,
        }

    @classmethod
    def from_public_dict(cls, value: Mapping[str, object]) -> "DeliveryRecord":
        artifact = value.get("artifact")
        deployment = value.get("deployment")
        outcome = value.get("outcome")
        if not all(isinstance(item, Mapping) for item in (artifact, deployment, outcome)):
            raise ValueError("delivery record nested identities are required")
        record = cls.create(
            case_id=str(value.get("case_id", "")),
            strategy=str(value.get("strategy", "")),
            artifact=ArtifactIdentity(
                source_revision=str(artifact.get("source_revision", "")),
                path=str(artifact.get("path", "")),
                sha256=str(artifact.get("sha256", "")),
                product_version=str(artifact.get("product_version", "")),
            ),
            deployment=DeploymentIdentity(
                operation_id=str(deployment.get("operation_id", "")),
                target_id=str(deployment.get("target_id", "")),
                requested_version=str(deployment.get("requested_version", "")),
                active_version=str(deployment.get("active_version", "")),
                target_epoch=deployment.get("target_epoch"),
                status=str(deployment.get("status", "")),
                mutation_journal_id=str(deployment.get("mutation_journal_id", "")),
                rollback_identity=str(deployment.get("rollback_identity", "")),
            ),
            outcome=DeliveryOutcome(
                deployment_integrity=str(outcome.get("deployment_integrity", "")),
                active_identity=str(outcome.get("active_identity", "")),
                business_validation=str(outcome.get("business_validation", "")),
                overall=str(outcome.get("overall", "")),
            ),
            evidence_ids=[
                str(item)
                for item in value.get("evidence_ids", [])
                if isinstance(item, str)
            ],
            rollback_of=str(value.get("rollback_of", "")),
        )
        if str(value.get("record_id", "")) != record.record_id:
            raise ValueError("delivery record fingerprint mismatch")
        return record
