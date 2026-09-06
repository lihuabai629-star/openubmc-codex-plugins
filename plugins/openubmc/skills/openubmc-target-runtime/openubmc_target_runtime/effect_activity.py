"""Bounded activity projections; these never write Effect or Run state."""
from __future__ import annotations

from collections.abc import Mapping
import math

from .redaction import redact_text


def active_operation(projection: Mapping[str, object]) -> Mapping[str, object]:
    operations = projection.get("operations", [])
    if not isinstance(operations, list):
        return {}
    return next(
        (
            operation for operation in reversed(operations)
            if isinstance(operation, Mapping)
            and str(operation.get("status", "")) in {
                "accepted", "running", "blocked", "mutation_outcome_unknown",
            }
        ),
        {},
    )


def operation_activity(projection: Mapping[str, object]) -> dict[str, object]:
    """Project only scheduling facts, never raw arguments or credentials."""
    operation = active_operation(projection)
    if (
        not operation or projection.get("run_outcome")
        or projection.get("status") == "cancelled"
    ):
        return {}
    result: dict[str, object] = {
        "status": "blocked" if operation.get("status") == "blocked" else "running",
        "effect_id": redact_text(operation.get("operation_id", ""))[:128],
        "operation": redact_text(operation.get("operation", ""))[:128],
        "owner": redact_text(operation.get("owner", ""))[:128],
        "phase": redact_text(operation.get("phase", operation.get("workflow_step_id", "")))[:128],
        "next_action": "reattach",
    }
    for name, source in (
        ("retry_generation", "evidence_retry_generation"),
        ("reconcile_count", "reconcile_count"),
    ):
        value = operation.get(source)
        if type(value) is int and 0 <= value < 2**63:
            result[name] = value
    for name in (
        "started_at", "last_progress_at", "deadline_at", "retry_requested_at",
        "reconcile_requested_at", "reconciled_at", "settled_at",
    ):
        value = operation.get(name)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
            result[name] = value
    unknown = projection.get("mutation_outcome_unknown_operations", {})
    if isinstance(unknown, Mapping) and result["effect_id"] in unknown:
        result["status"] = "unknown"
        result["next_action"] = "reconcile"
    error = operation.get("canonical_error")
    if isinstance(error, Mapping) and error.get("code"):
        result["reason"] = redact_text(error["code"])[:128]
    incident = projection.get("current_incident")
    if (
        isinstance(incident, Mapping)
        and incident.get("code") == "effect_deadline_exceeded"
        and incident.get("effect_id") == result["effect_id"]
    ):
        result["status"] = "deadline_exceeded"
        result["next_action"] = "inspect_existing_effect"
        result["reason"] = "effect_deadline_exceeded"
    return result
