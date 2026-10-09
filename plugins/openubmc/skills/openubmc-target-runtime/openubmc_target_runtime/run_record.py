"""Pure projections of Runtime facts; no collector, ledger, or execution authority."""

from collections.abc import Iterable, Mapping

from .workspace_context import WorkspaceSnapshot


def unavailable_usage() -> dict[str, object]:
    return {"status": "unavailable", "input_tokens": None, "output_tokens": None,
            "cached_tokens": None, "source_ref": None}


def project_run_record(task_id: str, run_id: str, projection: Mapping[str, object] | None,
                       *, runtime_state: str | None = None) -> dict[str, object]:
    """Use only this fresh projection, never Host notes or the current selection."""
    from .semantic_runtime import fingerprint

    record = {"schema_version": 1, "run_id": run_id, "task_ref": task_id,
        "runtime_availability": "unavailable", "workspace_binding": {"status": "unavailable", "snapshot": None},
        "workflow_definition_ref": None, "runtime_state": None, "outcome_ref": None,
        "usage": unavailable_usage()}
    if not isinstance(projection, Mapping):
        return record
    record["runtime_availability"] = "available"
    record["runtime_state"] = runtime_state
    start_input = projection.get("start_input")
    if isinstance(start_input, Mapping) and "workspace_context" in start_input:
        snapshot = WorkspaceSnapshot(start_input["workspace_context"])
        record["workspace_binding"] = {"status": "bound", "snapshot": snapshot.to_public_dict()}
    definition = projection.get("workflow_definition")
    if isinstance(definition, Mapping) and definition:
        record["workflow_definition_ref"] = {key: definition[key] for key in
            ("schema", "definition_id", "version", "fingerprint") if key in definition}
    outcome = projection.get("run_outcome")
    if isinstance(outcome, Mapping) and outcome:
        record["outcome_ref"] = "sha256:" + fingerprint(outcome)
    return record


def project_task_aggregate(
    task_id: str, records: Iterable[Mapping[str, object]],
) -> dict[str, object]:
    """Count bookmarked Run identities without inventing usage or Task outcomes."""
    run_refs = sorted({record["run_id"] for record in records})
    return {"schema_version": 1, "task_ref": task_id, "run_refs": run_refs,
            "unique_run_count": len(run_refs), "usage_totals": unavailable_usage()}
