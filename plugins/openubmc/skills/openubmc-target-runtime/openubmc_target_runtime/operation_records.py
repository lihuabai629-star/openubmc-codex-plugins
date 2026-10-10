"""Exact clean-source receipts produced with terminal Runtime facts."""
from collections.abc import Mapping
import hashlib
import json

from .redaction import redact_effect_output
from .source_check import check_source


def _digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def operation_receipts(intent, projection, *, terminal_status, outcome, checker, evidence_kind):
    operation = next((item for item in projection.get("operations", [])
                      if item.get("operation_id") == intent.effect_id), {})
    if (operation.get("source_check_status") != "matched"
            or check_source(projection, checker).status != "matched"):
        return []
    if terminal_status in {"completed", "verified", "succeeded"}:
        status = "passed"
    elif terminal_status == "failed":
        status = "failed"
    else:
        return []
    command_digest = _digest(redact_effect_output({"operation": intent.operation,
                                                   "arguments": dict(intent.arguments)}))
    log_digest = _digest(redact_effect_output(outcome))
    repositories = projection["start_input"]["workspace_context"]["repositories"]
    return [{"event_ref": "operation:" + hashlib.sha256((intent.effect_id + ":" + repo["repo_ref"] + ":" + log_digest).encode()).hexdigest(),
        "run_ref": intent.run_id, "repo_ref": repo["repo_ref"], "source_commit": repo["commit"],
        "command_ref": "operation:" + intent.operation, "command_digest": command_digest,
        "kind": "operation", "status": status, "execution_status": "executed",
        "evidence_ref": "receipt:" + log_digest.removeprefix("sha256:"), "log_digest": log_digest,
        "evidence_kind": evidence_kind}
        for repo in repositories if repo["commit"] is not None and repo["dirty"] is False]


class RuntimeOperationReader:
    def __init__(self, read_run, *, extra_reader=None):
        self.read_run = read_run
        self.extra_reader = extra_reader

    def __call__(self, task_id, run_refs):
        entries, kinds = [], set()
        for run_id in run_refs:
            projection = self.read_run(run_id)
            if not isinstance(projection, Mapping):
                raise ValueError("Runtime records unavailable")
            for operation in projection.get("operations", []):
                for receipt in operation.get("record_receipts", []):
                    row = dict(receipt)
                    kinds.add(row.pop("evidence_kind"))
                    if row["run_ref"] != run_id:
                        raise ValueError("Runtime receipt binding mismatch")
                    entries.append(row)
        if self.extra_reader is not None:
            for receipt in self.extra_reader(task_id, run_refs):
                row = dict(receipt)
                kinds.add(row.pop("evidence_kind"))
                entries.append(row)
        if not entries:
            return None
        if len(entries) > 256 or len(kinds) != 1:
            raise ValueError("Runtime receipt inventory unavailable")
        entries.sort(key=lambda row: row["event_ref"])
        body = {"schema_version": 1, "task_ref": task_id,
                "evidence_kind": kinds.pop(), "entries": entries}
        return {**body, "source_ref": _digest(body)}
