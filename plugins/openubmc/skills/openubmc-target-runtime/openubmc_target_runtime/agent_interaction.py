"""Pure classification of exceptional Agent Interface interactions."""

from __future__ import annotations

from collections.abc import Mapping


def interaction_telemetry(
    document: Mapping[str, object],
    *,
    preflight_failure: bool = False,
) -> dict[str, object] | None:
    progress = document.get("progress")
    no_progress_retry = (
        isinstance(progress, Mapping) and progress.get("status") == "no_progress"
    )
    incident_present = document.get("state") == "incident"
    operator_attention_required = incident_present
    projection_target_exceeded = (
        document.get("projection_target_exceeded") is True
        or document.get("gate_projection_target_exceeded") is True
    )
    budget_blocker = document.get("budget_blocker") is True
    if preflight_failure:
        classification = "preflight_failure"
    elif no_progress_retry:
        classification = "no_progress_retry"
    elif incident_present:
        classification = "incident"
    elif budget_blocker:
        classification = "budget_blocker"
    elif projection_target_exceeded:
        classification = "projection_target_exceeded"
    else:
        return None
    return {
        "classification": classification,
        "preflight_failure": preflight_failure,
        "no_progress_retry": no_progress_retry,
        "incident_present": incident_present,
        "operator_attention_required": operator_attention_required,
        "projection_target_exceeded": projection_target_exceeded,
        "budget_blocker": budget_blocker,
    }
