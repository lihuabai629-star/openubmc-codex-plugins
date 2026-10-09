"""Bounded Host measurement facts and pure projections; no collector or ledger."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re

from .redaction import require_secret_free


_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_FIELDS = frozenset({"schema_version", "task_ref", "source_ref", "evidence_kind",
    "task_coverage", "run_coverage", "invocations", "timing_segments", "wall_intervals", "intervention_events"})
_COVERAGE = frozenset({"usage", "timing", "interventions"})
_INVOCATION = frozenset({"provider_ref", "invocation_ref", "run_ref", "model_ref", "reasoning_ref",
    "input_tokens", "output_tokens", "cached_tokens", "source_ref"})
_TOKENS = ("input_tokens", "output_tokens", "cached_tokens")
_SEGMENT = frozenset({"segment_ref", "run_ref", "clock_ref", "elapsed_seconds", "source_ref"})
_INTERVAL = frozenset({"interval_ref", "run_ref", "clock_ref", "started_at", "ended_at", "source_ref"})
_INTERVENTION = frozenset({"event_ref", "run_ref", "actor_kind", "kind", "gate_ref", "source_ref"})
_KINDS = ("approval", "decision", "repair")
_UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)")


class MeasurementError(ValueError):
    def __init__(self):
        super().__init__("Host measurement snapshot is invalid")


def _shape(raw, fields):
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise MeasurementError()


def _reference(value, *, optional=False):
    if value is None and optional:
        return
    if not isinstance(value, str) or _REFERENCE.fullmatch(value) is None:
        raise MeasurementError()
    require_secret_free(value, boundary="Host measurement reference")


def _coverage(raw):
    _shape(raw, _COVERAGE)
    if any(not isinstance(v, str) or v not in {"complete", "partial", "unavailable"} for v in raw.values()):
        raise MeasurementError()


def _unique(rows, keys):
    found = {}
    for row in rows:
        identity = tuple(row[key] for key in keys)
        if identity in found and found[identity] != row:
            raise MeasurementError()
        found[identity] = row
    return list(found.values())


def _status(values):
    values = tuple(values)
    if all(value is None for value in values):
        return "unavailable"
    return "available" if all(value is not None for value in values) else "partial"


def _token_total(rows, name, *, complete):
    if not complete or any(row[name] is None for row in rows):
        return None
    total = sum(row[name] for row in rows)
    try:
        # Individually valid JSON integers may exceed the encoder's digit limit
        # after summation. Keep other independently known measurements usable.
        json.dumps(total)
    except (ValueError, OverflowError):
        return None
    return total


def _timestamp(value):
    if value is None:
        return None
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        raise MeasurementError()
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _timing(data, run_ref, *, complete):
    interval = next((row for row in data["wall_intervals"] if row["run_ref"] == run_ref), {})
    start, end = interval.get("started_at"), interval.get("ended_at")
    segments = [row for row in _unique(data["timing_segments"], ("segment_ref",)) if row["run_ref"] == run_ref]
    wall = None
    if complete and start is not None and end is not None and interval.get("clock_ref") is not None:
        elapsed = (_timestamp(end) - _timestamp(start)).total_seconds()
        if elapsed >= 0:
            wall = elapsed
    active = None
    if complete:
        try:
            active = math.fsum(row["elapsed_seconds"] for row in segments)
        except OverflowError:
            pass
    return {"status": _status((wall, active)), "started_at": start, "ended_at": end,
            "wall_seconds": wall, "active_seconds": active, "source_ref": data["source_ref"]}


def _interventions(data, run_ref, *, complete):
    events = _unique(data["intervention_events"], ("event_ref",))
    if run_ref is not None:
        events = [row for row in events if row["run_ref"] == run_ref]
    return {"status": "available" if complete else "unavailable",
            "count": len(events) if complete else None,
            "counts_by_kind": {kind: sum(row["kind"] == kind for row in events) if complete else None for kind in _KINDS},
            "source_ref": data["source_ref"]}


@dataclass(frozen=True, init=False)
class MeasurementSnapshot:
    _canonical_json: str = field(repr=False)

    def __init__(self, raw, *, task_id, run_refs):
        from .semantic_runtime import bounded_request

        bounded_request(raw)
        _shape(raw, _FIELDS)
        # JSON copies every nested value and rejects non-finite/non-JSON data.
        data = json.loads(json.dumps(dict(raw), ensure_ascii=False, allow_nan=False))
        if (type(data["schema_version"]) is not int or data["schema_version"] != 1
                or data["task_ref"] != task_id or data["evidence_kind"] not in ("observed", "synthetic")):
            raise MeasurementError()
        _coverage(data["task_coverage"])
        for name, limit in (("run_coverage", 128), ("invocations", 256), ("timing_segments", 256),
                            ("wall_intervals", 129), ("intervention_events", 256)):
            if not isinstance(data[name], list) or len(data[name]) > limit:
                raise MeasurementError()
        seen = set()
        for row in data["run_coverage"]:
            _shape(row, _COVERAGE | {"run_ref"})
            if not isinstance(row["run_ref"], str) or row["run_ref"] not in run_refs or row["run_ref"] in seen:
                raise MeasurementError()
            seen.add(row["run_ref"])
            _coverage({key: row[key] for key in _COVERAGE})
        for row in data["invocations"]:
            _shape(row, _INVOCATION)
            for name in ("provider_ref", "invocation_ref", "source_ref"):
                _reference(row[name])
            for name in ("model_ref", "reasoning_ref"):
                _reference(row[name], optional=True)
            if row["run_ref"] is not None and row["run_ref"] not in run_refs:
                raise MeasurementError()
            for name in _TOKENS:
                value = row[name]
                if value is not None and (type(value) is not int or value < 0):
                    raise MeasurementError()
            if (row["input_tokens"] is not None and row["cached_tokens"] is not None
                    and row["cached_tokens"] > row["input_tokens"]):
                raise MeasurementError()
        _unique(data["invocations"], ("provider_ref", "invocation_ref"))
        for row in data["timing_segments"]:
            _shape(row, _SEGMENT)
            for key in ("segment_ref", "clock_ref", "source_ref"):
                _reference(row[key])
            if row["run_ref"] is not None and row["run_ref"] not in run_refs:
                raise MeasurementError()
            elapsed = row["elapsed_seconds"]
            if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
                raise MeasurementError()
        _unique(data["timing_segments"], ("segment_ref",))
        scopes = set()
        for row in data["wall_intervals"]:
            _shape(row, _INTERVAL)
            for key in ("interval_ref", "source_ref"):
                _reference(row[key])
            _reference(row["clock_ref"], optional=True)
            if row["run_ref"] is not None and row["run_ref"] not in run_refs:
                raise MeasurementError()
            if row["run_ref"] in scopes:
                raise MeasurementError()
            scopes.add(row["run_ref"])
            _timestamp(row["started_at"])
            _timestamp(row["ended_at"])
        for row in data["intervention_events"]:
            _shape(row, _INTERVENTION)
            for key in ("event_ref", "source_ref"):
                _reference(row[key])
            _reference(row["gate_ref"], optional=True)
            if (row["run_ref"] is not None and row["run_ref"] not in run_refs
                    or row["actor_kind"] != "human" or row["kind"] not in _KINDS):
                raise MeasurementError()
        _unique(data["intervention_events"], ("event_ref",))
        body = {key: value for key, value in data.items() if key != "source_ref"}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        if data["source_ref"] != "sha256:" + hashlib.sha256(canonical.encode()).hexdigest():
            raise MeasurementError()
        object.__setattr__(self, "_canonical_json", json.dumps(data, sort_keys=True, ensure_ascii=False))

    def project(self, run_ref=None):
        data = json.loads(self._canonical_json)
        selected = data["task_coverage"] if run_ref is None else next(
            (row for row in data["run_coverage"] if row["run_ref"] == run_ref), {})
        rows = _unique(data["invocations"], ("provider_ref", "invocation_ref"))
        if run_ref is not None:
            rows = [row for row in rows if row["run_ref"] == run_ref]
        complete = selected.get("usage") == "complete"
        usage = {name: _token_total(rows, name, complete=complete) for name in _TOKENS}
        usage["invocation_count"] = len(rows) if complete else None
        if run_ref is None:
            usage["unattributed_invocation_count"] = sum(row["run_ref"] is None for row in rows) if complete else None
        usage.update(status=_status(usage.values()), source_ref=data["source_ref"])
        result = unavailable_measurements(task=run_ref is None)
        result["usage"] = usage
        result["timing"] = _timing(data, run_ref, complete=selected.get("timing") == "complete")
        result["interventions"] = _interventions(data, run_ref, complete=selected.get("interventions") == "complete")
        result["measurement_source"] = {"status": "available", "source_ref": data["source_ref"],
                                         "evidence_kind": data["evidence_kind"]}
        return result


def unavailable_measurements(*, task=False):
    usage = {"status": "unavailable", **dict.fromkeys((*_TOKENS, "invocation_count", "source_ref"))}
    if task:
        usage["unattributed_invocation_count"] = None
    return {"measurement_source": {"status": "unavailable", "source_ref": None, "evidence_kind": None},
            "usage": usage,
            "timing": {"status": "unavailable", **dict.fromkeys(("started_at", "ended_at", "wall_seconds", "active_seconds", "source_ref"))},
            "interventions": {"status": "unavailable", "count": None,
                "counts_by_kind": dict.fromkeys(_KINDS), "source_ref": None}}


class JsonMeasurementReader:
    """Read one existing producer-owned snapshot; never cache or create its file."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def __call__(self, task_id, run_refs):
        with self.path.open("rb") as stream:
            encoded = stream.read(512 * 1024 + 1)
        if len(encoded) > 512 * 1024:
            raise MeasurementError()
        def unique_fields(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise MeasurementError()
                value[key] = item
            return value

        return json.loads(encoded, object_pairs_hook=unique_fields)


class ProviderReportReader:
    """Adapt saved provider_requests, retaining only identity-bound observations.

    The Host binds the report to a Task/provider and declares inventory coverage.
    Old reports without physical invocation identities never acquire synthetic IDs.
    """

    def __init__(self, path: Path, *, task_id, provider_ref, evidence_kind, inventory_complete=False):
        _reference(task_id)
        _reference(provider_ref)
        if evidence_kind not in ("observed", "synthetic") or type(inventory_complete) is not bool:
            raise MeasurementError()
        self.reader = JsonMeasurementReader(path)
        self.task_id = task_id
        self.provider_ref = provider_ref
        self.evidence_kind = evidence_kind
        self.inventory_complete = inventory_complete

    def __call__(self, task_id, run_refs):
        if task_id != self.task_id:
            raise MeasurementError()
        report = self.reader(task_id, run_refs)
        if not isinstance(report, Mapping):
            raise MeasurementError()
        for key, expected in (("task_ref", task_id), ("provider_ref", self.provider_ref)):
            if key in report and report[key] != expected:
                raise MeasurementError()
        requests = report.get("provider_requests")
        if not isinstance(requests, list) or len(requests) > 256:
            raise MeasurementError()
        complete = self.inventory_complete
        attributed = True
        invocations = []
        for row in requests:
            if not isinstance(row, Mapping):
                raise MeasurementError()
            for key, expected in (("task_ref", task_id), ("provider_ref", self.provider_ref)):
                if key in row and row[key] != expected:
                    raise MeasurementError()
            identity = row.get("invocation_ref")
            if identity is None:
                complete = False
                continue
            _reference(identity)
            attributed = attributed and "run_ref" in row
            usage = row.get("usage")
            usage = usage if isinstance(usage, Mapping) else {}
            details = usage.get("input_tokens_details")
            details = details if isinstance(details, Mapping) else {}
            cached = usage.get("cached_tokens")
            if cached is None:
                cached = details.get("cached_tokens")
            if (usage.get("cached_tokens") is not None and details.get("cached_tokens") is not None
                    and usage["cached_tokens"] != details["cached_tokens"]):
                raise MeasurementError()
            model = row.get("response_model")
            model = model if isinstance(model, str) and _REFERENCE.fullmatch(model) else None
            invocations.append({"provider_ref": self.provider_ref, "invocation_ref": identity,
                "run_ref": row.get("run_ref"), "model_ref": model, "reasoning_ref": row.get("reasoning_ref"),
                "input_tokens": usage.get("input_tokens"), "output_tokens": usage.get("output_tokens"),
                "cached_tokens": cached, "source_ref": identity})
        coverage = {"usage": "complete" if complete else "partial", "timing": "unavailable", "interventions": "unavailable"}
        run_coverage = {**coverage, "usage": "complete" if complete and attributed else "partial"}
        body = {"schema_version": 1, "task_ref": task_id, "evidence_kind": self.evidence_kind,
            "task_coverage": coverage, "run_coverage": [{"run_ref": ref, **run_coverage} for ref in run_refs],
            "invocations": invocations, "timing_segments": [], "wall_intervals": [], "intervention_events": []}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        return {**body, "source_ref": "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()}
