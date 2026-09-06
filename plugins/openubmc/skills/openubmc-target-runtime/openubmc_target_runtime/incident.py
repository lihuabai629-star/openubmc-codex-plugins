"""Incident recovery policy and Operator lifecycle metrics."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import time
from typing import Protocol

INCIDENT_METRICS_SCHEMA = "openubmc.semantic-runtime/incident-metrics-v1"


@dataclass(frozen=True)
class IncidentRecoveryPolicy:
    code: str
    recovery_path: str
    allowed_commands: tuple[str, ...]
    operator_action: str
    recoverable: bool = True

    def to_public_dict(self) -> dict[str, object]:
        return {
            "recovery_path": self.recovery_path,
            "allowed_commands": list(self.allowed_commands),
            "operator_action": self.operator_action,
            "recoverable": self.recoverable,
        }


INCIDENT_RECOVERY_POLICIES = {
    policy.code: policy
    for policy in (
        IncidentRecoveryPolicy(
            code="mutation_outcome_unknown",
            recovery_path="reconcile",
            allowed_commands=("reconcile", "cancel"),
            operator_action=(
                "restore the durable Effect intent or journal, then reconcile "
                "the same Effect identity"
            ),
        ),
        IncidentRecoveryPolicy(
            code="artifact_reference_invalid",
            recovery_path="correction_then_resume",
            allowed_commands=("resume", "cancel"),
            operator_action=(
                "restore the digest-bound artifact content, then resume the Run"
            ),
        ),
        IncidentRecoveryPolicy(
            code="effect_deadline_exceeded",
            recovery_path="inspect_existing_effect",
            allowed_commands=("resume", "cancel"),
            operator_action=(
                "resume to inspect the existing Effect result; retain its MutationJournal "
                "and do not admit a replacement mutation"
            ),
        ),
        IncidentRecoveryPolicy(
            code="domain_execution_failed",
            recovery_path="retry_resume",
            allowed_commands=("resume", "cancel"),
            operator_action=(
                "correct the transient domain preparation failure, then resume"
            ),
        ),
        IncidentRecoveryPolicy(
            code="invalid_run_continuation",
            recovery_path="cancel_terminal",
            allowed_commands=("cancel",),
            operator_action="cancel the Run and inspect the persisted Run ledger",
            recoverable=False,
        ),
        IncidentRecoveryPolicy(
            code="internal_step_limit",
            recovery_path="cancel_terminal",
            allowed_commands=("cancel",),
            operator_action="cancel the Run and inspect the workflow definition",
            recoverable=False,
        ),
    )
}

UNKNOWN_INCIDENT_POLICY = IncidentRecoveryPolicy(
    code="unknown",
    recovery_path="operator_required",
    allowed_commands=("cancel",),
    operator_action="inspect the Run ledger and cancel if no safe recovery exists",
    recoverable=False,
)


def incident_recovery_policy(code: str) -> IncidentRecoveryPolicy:
    return INCIDENT_RECOVERY_POLICIES.get(code, UNKNOWN_INCIDENT_POLICY)


class IncidentRepository(Protocol):
    def metadata(self) -> tuple[dict[str, object], ...]: ...

    def load(self, case_id: str) -> Mapping[str, object] | None: ...


class IncidentMetrics:
    """Project anonymous Incident lifecycle metrics from the durable Run ledger."""

    def __init__(
        self,
        repository: IncidentRepository,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.repository = repository
        self.clock = clock

    def status(self) -> dict[str, object]:
        incidents: dict[tuple[str, str], dict[str, object]] = {}
        duplicate_raises = 0
        runs = self.repository.metadata()
        for metadata in runs:
            run_id = str(metadata.get("case_id", ""))
            if not run_id:
                continue
            projection = self.repository.load(run_id)
            if not isinstance(projection, Mapping):
                continue
            raw_incidents = projection.get("incidents", [])
            if not isinstance(raw_incidents, list):
                continue
            for raw_incident in raw_incidents:
                if not isinstance(raw_incident, Mapping):
                    continue
                incident_id = str(raw_incident.get("incident_id", ""))
                if not incident_id:
                    continue
                identity = (run_id, incident_id)
                lifecycle = {
                    "code": str(raw_incident.get("code", "")),
                    "status": str(raw_incident.get("status", "open")),
                    "raised_at": float(
                        raw_incident.get("raised_at", 0.0) or 0.0
                    ),
                    "resolved_at": float(
                        raw_incident.get("resolved_at", 0.0) or 0.0
                    ),
                    "resolution": str(raw_incident.get("resolution", "")),
                }
                if identity in incidents:
                    duplicate_raises += 1
                    first_raised_at = float(
                        incidents[identity].get("raised_at", 0.0) or 0.0
                    )
                    duplicate_raised_at = float(lifecycle["raised_at"])
                    lifecycle["raised_at"] = (
                        min(first_raised_at, duplicate_raised_at)
                        if first_raised_at > 0 and duplicate_raised_at > 0
                        else first_raised_at or duplicate_raised_at
                    )
                    incidents[identity] = lifecycle
                    continue
                incidents[identity] = lifecycle

        by_code: dict[str, dict[str, object]] = {}
        recovery_paths: Counter[str] = Counter()
        resolutions: Counter[str] = Counter()
        unknown_codes: set[str] = set()
        now = self.clock()
        for incident in incidents.values():
            code = str(incident["code"])
            policy = incident_recovery_policy(code)
            if code not in INCIDENT_RECOVERY_POLICIES:
                unknown_codes.add(code)
            recovery_paths[policy.recovery_path] += 1
            metrics = by_code.setdefault(
                code,
                {
                    "total": 0,
                    "open": 0,
                    "resolved": 0,
                    "cancelled": 0,
                    "recovery_path": policy.recovery_path,
                    "allowed_commands": list(policy.allowed_commands),
                    "max_open_age_seconds": 0.0,
                    "average_resolution_seconds": 0.0,
                    "_resolution_seconds": [],
                },
            )
            metrics["total"] += 1
            status = str(incident["status"])
            metrics[status] += 1
            raised_at = float(incident["raised_at"])
            resolved_at = float(incident["resolved_at"])
            if status == "open" and raised_at > 0:
                metrics["max_open_age_seconds"] = max(
                    float(metrics["max_open_age_seconds"]),
                    max(0.0, now - raised_at),
                )
            if status != "open" and resolved_at >= raised_at > 0:
                metrics["_resolution_seconds"].append(resolved_at - raised_at)
                resolutions[str(incident["resolution"])] += 1
        for metrics in by_code.values():
            durations = metrics.pop("_resolution_seconds")
            if durations:
                metrics["average_resolution_seconds"] = round(
                    sum(durations) / len(durations),
                    3,
                )

        status_counts = Counter(str(item["status"]) for item in incidents.values())
        return {
            "schema": INCIDENT_METRICS_SCHEMA,
            "runs_scanned": len(runs),
            "total": len(incidents),
            "open": status_counts["open"],
            "resolved": status_counts["resolved"],
            "cancelled": status_counts["cancelled"],
            "duplicate_raises": duplicate_raises,
            "by_code": dict(sorted(by_code.items())),
            "recovery_path_counts": dict(sorted(recovery_paths.items())),
            "resolution_counts": dict(sorted(resolutions.items())),
            "unknown_policy_codes": sorted(unknown_codes),
        }
