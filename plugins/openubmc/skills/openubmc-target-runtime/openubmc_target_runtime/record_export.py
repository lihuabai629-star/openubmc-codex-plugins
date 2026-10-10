"""Deterministic, bounded record exports; no execution or raw-evidence storage."""

from collections.abc import Mapping
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile

from .measurements import JsonMeasurementReader
from .redaction import require_secret_free
from .semantic_runtime import bounded_request
from .workspace_context import WorkspaceSnapshot


SCHEMA = "openubmc.task-record-export/v1"
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_STATUS = {"available", "partial", "unavailable"}
_RECORD = {"schema_version", "task_ref", "run_id", "runtime_availability", "workspace_binding",
           "workflow_definition_ref", "runtime_state", "outcome_ref", "usage"}
_METRICS = {"measurement_source", "timing", "interventions"}
_EVIDENCE = {"schema_version", "task_ref", "source_ref", "evidence_kind", "entries"}
_ENTRY = {"event_ref", "run_ref", "repo_ref", "source_commit", "command_ref", "command_digest",
          "kind", "status", "execution_status", "evidence_ref", "log_digest"}


class RecordExportError(ValueError):
    def __init__(self):
        super().__init__("Task record export is invalid")


def _shape(value, fields):
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise RecordExportError()


def _text(value, pattern=_REF, *, nullable=False):
    if value is None and nullable:
        return
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise RecordExportError()
    require_secret_free(value, boundary="record export reference")


def _number(value, *, integer=True):
    if value is None:
        return
    if type(value) not in ((int,) if integer else (int, float)) or value < 0:
        raise RecordExportError()
    if not integer and not math.isfinite(value):
        raise RecordExportError()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def _seal(body):
    return {**body, "content_digest": "sha256:" + hashlib.sha256(_canonical(body)).hexdigest()}


def _usage(value, version, *, task=False):
    fields = {"status", "input_tokens", "output_tokens", "cached_tokens", "source_ref"}
    if version == 2:
        fields.add("invocation_count")
        if task:
            fields.add("unattributed_invocation_count")
    _shape(value, fields)
    if value["status"] not in _STATUS:
        raise RecordExportError()
    _text(value["source_ref"], _DIGEST, nullable=True)
    for name in fields - {"status", "source_ref"}:
        _number(value[name])
    numbers = tuple(value[name] for name in fields - {"status", "source_ref"})
    expected = "unavailable" if all(number is None for number in numbers) else (
        "available" if all(number is not None for number in numbers) else "partial")
    if value["status"] != expected:
        raise RecordExportError()
    if version == 1 and (expected != "unavailable" or value["source_ref"] is not None):
        raise RecordExportError()
    if version == 2 and expected != "unavailable" and value["source_ref"] is None:
        raise RecordExportError()
    if value["input_tokens"] is not None and value["cached_tokens"] is not None and value["cached_tokens"] > value["input_tokens"]:
        raise RecordExportError()


def _metrics(value):
    source = value["measurement_source"]
    _shape(source, {"status", "source_ref", "evidence_kind"})
    if source["status"] not in {"available", "unavailable"} or source["evidence_kind"] not in {"observed", "synthetic", None}:
        raise RecordExportError()
    _text(source["source_ref"], _DIGEST, nullable=True)
    if source["status"] == "available" and (source["source_ref"] is None or source["evidence_kind"] is None):
        raise RecordExportError()
    if source["status"] == "unavailable" and (source["source_ref"] is not None or source["evidence_kind"] is not None):
        raise RecordExportError()
    timing = value["timing"]
    _shape(timing, {"status", "started_at", "ended_at", "wall_seconds", "active_seconds", "source_ref"})
    if timing["status"] not in _STATUS:
        raise RecordExportError()
    from .measurements import _timestamp
    for key in ("started_at", "ended_at"):
        _timestamp(timing[key])
    for key in ("wall_seconds", "active_seconds"):
        _number(timing[key], integer=False)
    if timing["wall_seconds"] is not None:
        start, end = _timestamp(timing["started_at"]), _timestamp(timing["ended_at"])
        if start is None or end is None or (end - start).total_seconds() != timing["wall_seconds"]:
            raise RecordExportError()
    _text(timing["source_ref"], _DIGEST, nullable=True)
    events = value["interventions"]
    _shape(events, {"status", "count", "counts_by_kind", "source_ref"})
    if events["status"] not in _STATUS:
        raise RecordExportError()
    _number(events["count"])
    _shape(events["counts_by_kind"], {"approval", "decision", "repair"})
    for number in events["counts_by_kind"].values():
        _number(number)
    _text(events["source_ref"], _DIGEST, nullable=True)
    for name in ("timing", "interventions"):
        if value[name]["source_ref"] != source["source_ref"]:
            raise RecordExportError()
    usage = value.get("usage", value.get("usage_totals"))
    if usage["source_ref"] != source["source_ref"]:
        raise RecordExportError()
    expected_timing = "unavailable" if timing["wall_seconds"] is None and timing["active_seconds"] is None else (
        "available" if timing["wall_seconds"] is not None and timing["active_seconds"] is not None else "partial")
    if timing["status"] != expected_timing:
        raise RecordExportError()
    counts = tuple(events["counts_by_kind"].values())
    if events["count"] is None:
        if events["status"] != "unavailable" or any(count is not None for count in counts):
            raise RecordExportError()
    elif events["status"] != "available" or any(count is None for count in counts) or sum(counts) != events["count"]:
        raise RecordExportError()
    if source["status"] == "unavailable" and any(item is not None for item in (
            *[usage[key] for key in usage if key not in {"status", "source_ref"}],
            timing["started_at"], timing["ended_at"], timing["wall_seconds"], timing["active_seconds"], events["count"])):
        raise RecordExportError()


def _record(value, task_id):
    version = value.get("schema_version") if isinstance(value, Mapping) else None
    if type(version) is not int or version not in (1, 2):
        raise RecordExportError()
    _shape(value, _RECORD | (_METRICS if version == 2 else set()))
    if value["task_ref"] != task_id or value["runtime_availability"] not in {"available", "unavailable"}:
        raise RecordExportError()
    _text(value["run_id"])
    _text(value["runtime_state"], nullable=True)
    _text(value["outcome_ref"], _DIGEST, nullable=True)
    binding = value["workspace_binding"]
    _shape(binding, {"status", "snapshot"})
    if binding["status"] == "bound":
        WorkspaceSnapshot(binding["snapshot"])
    elif binding != {"status": "unavailable", "snapshot": None}:
        raise RecordExportError()
    definition = value["workflow_definition_ref"]
    if definition is not None:
        if not isinstance(definition, Mapping) or set(definition) - {"schema", "definition_id", "version", "fingerprint"}:
            raise RecordExportError()
        for key, item in definition.items():
            if key == "version":
                if type(item) is not int or item < 1:
                    raise RecordExportError()
            else:
                if key == "schema":
                    from .contracts import RUNTIME_API_VERSION
                    if item != RUNTIME_API_VERSION + "/workflow-definition-v1":
                        raise RecordExportError()
                else:
                    _text(item, re.compile(r"[0-9a-f]{64}") if key == "fingerprint" else _REF)
    if value["runtime_availability"] == "unavailable" and any(value[key] is not None for key in ("runtime_state", "outcome_ref", "workflow_definition_ref")):
        raise RecordExportError()
    if value["runtime_availability"] == "unavailable" and binding["status"] != "unavailable":
        raise RecordExportError()
    _usage(value["usage"], version)
    if version == 2:
        _metrics(value)
    return json.loads(_canonical(value))


def _evidence(snapshot, task_id, records):
    if snapshot is None:
        return {"status": "unavailable", "snapshot": None}
    bounded_request(snapshot)
    _shape(snapshot, _EVIDENCE)
    if type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1 or snapshot["task_ref"] != task_id:
        raise RecordExportError()
    if snapshot["evidence_kind"] not in {"observed", "synthetic"}:
        raise RecordExportError()
    _text(snapshot["source_ref"], _DIGEST)
    body = {key: item for key, item in snapshot.items() if key != "source_ref"}
    if snapshot["source_ref"] != "sha256:" + hashlib.sha256(_canonical(body)).hexdigest():
        raise RecordExportError()
    entries = snapshot["entries"]
    if not isinstance(entries, list) or len(entries) > 256:
        raise RecordExportError()
    by_run = {row["run_id"]: row for row in records}
    seen = {}
    for row in entries:
        _shape(row, _ENTRY)
        for key in ("event_ref", "run_ref", "repo_ref", "command_ref"):
            _text(row[key])
        for key in ("command_digest", "log_digest"):
            _text(row[key], _DIGEST, nullable=key == "log_digest")
        _text(row["evidence_ref"], nullable=True)
        _text(row["source_commit"], _COMMIT)
        if row["kind"] not in {"operation", "test"} or row["status"] not in {"passed", "failed", "skipped", "not_run", "unavailable"}:
            raise RecordExportError()
        if row["execution_status"] not in {"executed", "not_executed", "unknown"}:
            raise RecordExportError()
        if row["status"] in {"passed", "failed"} and (row["execution_status"] != "executed" or row["evidence_ref"] is None or row["log_digest"] is None):
            raise RecordExportError()
        if row["status"] in {"skipped", "not_run"} and row["execution_status"] != "not_executed":
            raise RecordExportError()
        run = by_run.get(row["run_ref"], {})
        binding = run.get("workspace_binding", {}).get("snapshot") or {}
        repo = next((repo for repo in binding.get("repositories", []) if repo["repo_ref"] == row["repo_ref"]), {})
        if repo.get("commit") != row["source_commit"] or repo.get("dirty") is not False:
            raise RecordExportError()
        if row["event_ref"] in seen and seen[row["event_ref"]] != row:
            raise RecordExportError()
        seen[row["event_ref"]] = row
    # Retain the original sealed producer snapshot; its duplicate observations
    # remain verifiable. Consumers use unique event_ref for counting.
    return {"status": "available", "snapshot": json.loads(_canonical(snapshot))}


def export_task_records(handoff, *, producer_commit, evidence_snapshot=None):
    """Export allowed fresh records, excluding notes, answers and raw evidence."""
    try:
        bounded_request(handoff)
        _text(producer_commit, _COMMIT)
        task_id = handoff["task_id"]
        _text(task_id)
        rows = handoff["runs"]
        if not isinstance(rows, list) or len(rows) > 128:
            raise RecordExportError()
        for row in rows:
            if not isinstance(row, Mapping) or row.get("run_id") != row.get("run_record", {}).get("run_id"):
                raise RecordExportError()
        records = sorted((_record(row["run_record"], task_id) for row in rows), key=lambda row: row["run_id"])
        refs = [row["run_id"] for row in records]
        if len(set(refs)) != len(refs):
            raise RecordExportError()
        aggregate = handoff["task_aggregate"]
        version = aggregate["schema_version"]
        if type(version) is not int or version not in (1, 2) or any(row["schema_version"] != version for row in records):
            raise RecordExportError()
        _shape(aggregate, {"schema_version", "task_ref", "run_refs", "unique_run_count", "usage_totals"} | (_METRICS if version == 2 else set()))
        if aggregate["task_ref"] != task_id or aggregate["run_refs"] != refs or type(aggregate["unique_run_count"]) is not int or aggregate["unique_run_count"] != len(refs):
            raise RecordExportError()
        _usage(aggregate["usage_totals"], version, task=True)
        if version == 2:
            _metrics(aggregate)
            if any(row["measurement_source"] != aggregate["measurement_source"] for row in records):
                raise RecordExportError()
        try:
            evidence = _evidence(evidence_snapshot, task_id, records)
        except Exception:
            evidence = {"status": "unavailable", "snapshot": None}
        body = {"schema": SCHEMA, "task_ref": task_id, "producer_commit": producer_commit,
                "run_records": records, "task_aggregate": aggregate, "operation_evidence": evidence}
        bounded_request(body)
        return _seal(json.loads(_canonical(body)))
    except Exception as exc:
        raise RecordExportError() from exc


def verify_export(document):
    try:
        _shape(document, {"schema", "task_ref", "producer_commit", "run_records", "task_aggregate", "operation_evidence", "content_digest"})
        if document["schema"] != SCHEMA:
            raise RecordExportError()
        _text(document["content_digest"], _DIGEST)
        evidence = document["operation_evidence"]
        _shape(evidence, {"status", "snapshot"})
        handoff = {"task_id": document["task_ref"], "runs": [{"run_id": row["run_id"], "run_record": row} for row in document["run_records"]], "task_aggregate": document["task_aggregate"]}
        rebuilt = export_task_records(handoff, producer_commit=document["producer_commit"], evidence_snapshot=evidence["snapshot"])
        if rebuilt != document:
            raise RecordExportError()
        return document["content_digest"]
    except Exception as exc:
        raise RecordExportError() from exc


class RecordExportStore:
    """Explicit private, content-addressed exports; originals remain producer-owned."""

    def __init__(self, root):
        self.root = Path(root).absolute()

    def _private_root(self):
        if os.name == "nt":
            from .windows_private import verify_private_path
            if self.root.exists():
                verify_private_path(self.root)
            return
        if any(path.is_symlink() for path in (self.root, *self.root.parents)):
            raise RecordExportError()
        if self.root.exists():
            info = self.root.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise RecordExportError()

    def write(self, document):
        digest = verify_export(document)
        self._private_root()
        if os.name == "nt":
            from .windows_private import ensure_private_directory
            ensure_private_directory(self.root)
        else:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._private_root()
        destination = self.root / (digest.removeprefix("sha256:") + ".json")
        encoded = _canonical(document) + b"\n"
        if destination.exists() or destination.is_symlink():
            if not self._private_file(destination) or destination.read_bytes() != encoded:
                raise RecordExportError()
            return destination
        descriptor, name = tempfile.mkstemp(prefix=".export-", dir=self.root)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                if os.name == "nt":
                    from .windows_private import harden_new_file
                    harden_new_file(Path(name))
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(name, destination)
        except FileExistsError:
            if not self._private_file(destination) or destination.read_bytes() != encoded:
                raise RecordExportError()
        finally:
            Path(name).unlink(missing_ok=True)
        return destination

    def _private_file(self, path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.is_symlink():
            return False
        if os.name == "nt":
            from .windows_private import verify_private_path
            verify_private_path(path)
            return True
        return info.st_uid == os.getuid() and not info.st_mode & 0o077

    def prune(self, *, before_timestamp, dry_run=True):
        if type(before_timestamp) not in (int, float) or not math.isfinite(before_timestamp) or type(dry_run) is not bool or self.root.is_symlink():
            raise RecordExportError()
        self._private_root()
        selected = []
        if not self.root.exists():
            return selected
        for path in sorted(self.root.iterdir()):
            if re.fullmatch(r"[0-9a-f]{64}\.json", path.name) is None:
                continue
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mtime >= before_timestamp:
                continue
            try:
                if not self._private_file(path):
                    continue
                document = JsonMeasurementReader(path)(None, ())
                digest = verify_export(document)
            except Exception:
                continue
            if digest != "sha256:" + path.stem:
                continue
            selected.append(path.name)
            if not dry_run:
                path.unlink()
        return selected
