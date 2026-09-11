#!/usr/bin/env python3
"""Derive bounded Drive diagnostic suggestions from captured read-only evidence."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
from collections.abc import Mapping
from datetime import datetime, timezone


REQUEST_SCHEMA = "openubmc-debug.diagnostic-advice-request.v1"
ADVICE_SCHEMA = "openubmc-debug.diagnostic-advice.v1"
STAGES = ("hardware_discovery", "mdb", "northbound")
MAX_INPUT_BYTES = 1024 * 1024
MAX_ADVICE_BYTES = 16 * 1024
OBSERVATION_SOURCE_SCHEMA = "openubmc.target-runtime.v1/observation-source-v1"
HYPOTHESES = (
    ("hardware_not_discovered", "The Drive was not discovered by hardware enumeration", (False, False, False)),
    ("mdb_not_created", "The discovered Drive has no MDB object", (True, False, False)),
    ("northbound_not_published", "The MDB Drive has no northbound representation", (True, True, False)),
)


def source_digest(value):
    """Identify the exact captured JSON, using the comparison source convention."""
    return "sha256:" + hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()).hexdigest()


def _pointer(document, pointer):
    if (not isinstance(pointer, str) or not pointer.startswith("/") or len(pointer) > 512
            or pointer.count("/") > 16 or re.search(r"~(?![01])", pointer)):
        raise ValueError("evidence reference must be a bounded JSON pointer")
    value = document
    for segment in pointer[1:].split("/"):
        segment = segment.replace("~1", "/").replace("~0", "~")
        try:
            if isinstance(value, list):
                if not re.fullmatch(r"0|[1-9][0-9]*", segment):
                    raise ValueError("array reference requires a canonical JSON pointer index")
                value = value[int(segment)]
            else:
                value = value[segment]
        except (KeyError, IndexError, TypeError, ValueError) as error:
            raise ValueError("evidence reference does not resolve") from error
    return value


def _source_target(source):
    return source.get("ip") or source.get("scope", {}).get("target")


def _source_body(source):
    return source.get("raw", {}) if source.get("schema") == OBSERVATION_SOURCE_SCHEMA else source


def _source_observed_at(source):
    body = _source_body(source)
    freshness = body.get("result", {}).get("freshness", body.get("freshness", {}))
    return source.get("observed_at") or freshness.get("observed_at")


def _source_epoch(source):
    if "target_epoch" in source:
        return source["target_epoch"]
    value = source
    for name in ("result", "runtime", "status"):
        value = value.get(name, {}) if isinstance(value, Mapping) else {}
    targets = value.get("targets", []) if isinstance(value, Mapping) else []
    if not isinstance(targets, list):
        return None
    matched = [item for item in targets if isinstance(item, Mapping)
               and isinstance(item.get("target"), Mapping) and item["target"].get("host") == _source_target(source)]
    if len(matched) != 1 or not isinstance(matched[0].get("epochs"), Mapping):
        return None
    return matched[0]["epochs"].get("target_epoch")


def _text(value):
    return isinstance(value, str) and bool(value.strip()) and len(value.encode()) <= 128


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.astimezone(timezone.utc) if result.tzinfo is not None else None
    except ValueError:
        return None


def _epoch(value):
    return type(value) is int and 0 <= value <= 2**63 - 1


def _validate_request(request):
    if not isinstance(request, Mapping) or request.get("schema") != REQUEST_SCHEMA:
        raise ValueError("unsupported diagnostic advice request")
    if set(request) - {"schema", "target", "device", "sources", "facts", "queries", "snapshot_at",
                       "max_age_seconds", "target_epochs", "observation_refs", "include_fault_chain",
                       "reference_target", "comparison_receipt"}:
        raise ValueError("undeclared diagnostic advice request fields")
    if "include_fault_chain" in request and type(request["include_fault_chain"]) is not bool:
        raise ValueError("include_fault_chain must be boolean")
    if len(json.dumps(request, allow_nan=False).encode()) > MAX_INPUT_BYTES:
        raise ValueError("diagnostic advice input exceeds the byte budget")
    if "snapshot_at" in request and _timestamp(request["snapshot_at"]) is None:
        raise ValueError("snapshot_at requires an ISO 8601 timestamp with timezone")
    max_age = request.get("max_age_seconds", 30)
    if type(max_age) is not int or not 1 <= max_age <= 900:
        raise ValueError("max_age_seconds must be between 1 and 900")
    epochs = request.get("target_epochs", {})
    if (not isinstance(epochs, Mapping) or len(epochs) > 8
            or not all(_text(target) and _epoch(epoch) for target, epoch in epochs.items())):
        raise ValueError("target_epochs requires bounded target identities and nonnegative integer epochs")
    device = request.get("device")
    if (not isinstance(device, Mapping) or set(device) - {"Name", "Protocol", "ResourceId"}
            or not _text(device.get("Protocol"))
            or not any(_text(device.get(key)) for key in ("Name", "ResourceId"))
            or not all(_text(value) for value in device.values()) or not _text(request.get("target"))):
        raise ValueError("a bounded Drive identity, protocol and target are required")
    sources = request.get("sources")
    if not isinstance(sources, Mapping) or not 1 <= len(sources) <= 8:
        raise ValueError("select one to eight captured sources")
    for source_id, source in sources.items():
        if not _text(source_id) or not isinstance(source, Mapping):
            raise ValueError("captured source identity is invalid")
        if not isinstance(source.get("result", {}), Mapping) or not isinstance(source.get("scope", {}), Mapping):
            raise ValueError("captured source structure is invalid")
        body = _source_body(source)
        if not isinstance(body, Mapping) or not isinstance(body.get("result", {}), Mapping):
            raise ValueError("captured observation body is invalid")
        if not isinstance(body.get("result", {}).get("freshness", body.get("freshness", {})), Mapping):
            raise ValueError("captured source freshness is invalid")
        if not _text(_source_target(source)):
            raise ValueError("captured source target is missing")
    observation_refs = request.get("observation_refs", {})
    if not isinstance(observation_refs, Mapping) or set(observation_refs) - set(sources):
        raise ValueError("observation references must name a captured source")
    if observation_refs:
        from _target_runtime_adapter import _load_runtime_module
        reference_type = _load_runtime_module().ObservationRef
        for source_id, value in observation_refs.items():
            if not isinstance(value, Mapping):
                raise ValueError("observation reference must be an object")
            reference = reference_type.from_public_dict(value)
            source = sources[source_id]
            if (source.get("schema") != OBSERVATION_SOURCE_SCHEMA
                    or reference.to_public_dict() != value
                    or "sha256:" + reference.digest != source_digest(source)
                    or reference.handle != "blob://" + reference.digest
                    or reference.size != len(json.dumps(source, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())
                    or reference.target != _source_target(source)
                    or reference.scope_digest != source.get("scope_digest")
                    or reference.observed_at != source.get("observed_at")
                    or reference.target_epoch != source.get("target_epoch")
                    or reference.target_fingerprint != source.get("target_fingerprint")):
                raise ValueError("observation reference does not match the captured document")
    facts = request.get("facts")
    if not isinstance(facts, list) or len(facts) > 24:
        raise ValueError("at most 24 captured facts are allowed")
    seen = set()
    for fact in facts:
        if (not isinstance(fact, Mapping) or fact.get("stage") not in STAGES
                or fact.get("source_id") not in sources):
            raise ValueError("fact stage or source reference is invalid")
        key = (_source_target(sources[fact["source_id"]]), fact["stage"])
        if key in seen:
            raise ValueError("ambiguous duplicate target/stage observation")
        seen.add(key)
    queries = request.get("queries", {})
    if not isinstance(queries, Mapping) or set(queries) - set(STAGES):
        raise ValueError("observation queries must name a supported stage")
    if queries:
        from _target_runtime_adapter import _load_runtime_module
        query_type = _load_runtime_module().ObservationQuery
        for query in queries.values():
            if not isinstance(query, Mapping) or query.get("target") != request["target"]:
                raise ValueError("suggested observation targets another device scope")
            query_type.from_query(query)


def _known_source(source, request, snapshot_at):
    body = _source_body(source)
    freshness = body.get("result", {}).get("freshness", body.get("freshness", {}))
    observed_at = _timestamp(_source_observed_at(source))
    valid_until = _timestamp(freshness.get("valid_until"))
    expected_epoch = request.get("target_epochs", {}).get(_source_target(source))
    actual_epoch = _source_epoch(source)
    return (
        (body.get("ok") is True or body.get("status") == "complete")
        and freshness.get("status") in {"fresh", "live", "complete"}
        and freshness.get("complete", True) is True
        and not any(freshness.get(name) for name in ("stale_evidence", "lost_dimensions", "unavailable_dimensions"))
        and observed_at is not None
        and 0 <= (snapshot_at - observed_at).total_seconds() <= request.get("max_age_seconds", 30)
        and ("valid_until" not in freshness or valid_until is not None and snapshot_at < valid_until)
        and _epoch(expected_epoch) and _epoch(actual_epoch) and actual_epoch == expected_epoch
        and (source.get("schema") != OBSERVATION_SOURCE_SCHEMA or (
            source.get("reusable") is True and type(source.get("fresh_until")) in {int, float}
            and snapshot_at.timestamp() < source["fresh_until"]
        ))
        and not source.get("truncated", False)
        and source.get("content_complete", True) is True
    )


def _complete_path(source, pointer):
    containers = [source]
    tokens = pointer[1:].split("/")
    containers.extend(_pointer(source, "/" + "/".join(tokens[:length])) for length in range(1, len(tokens)))
    return all(
        not isinstance(value, Mapping) or (
            value.get("content_complete", True) is True
            and value.get("ok", True) is True
            and value.get("status") not in {"partial", "stale", "unavailable", "not_checked", "failed", "unknown"}
            and not any(item is not False for key, item in value.items() if key.endswith("truncated"))
        )
        for value in containers
    )


def _fault_chain(request, facts):
    receipt = request.get("comparison_receipt", {})
    if not isinstance(receipt, Mapping):
        raise ValueError("fault chain requires a ComparisonReceipt object")
    if (not isinstance(receipt.get("freshness", {}), Mapping)
            or any(not isinstance(receipt.get(field, []), list) for field in ("sources", "differences", "incomparable_reasons"))
            or any(not isinstance(item, Mapping) for field in ("sources", "differences") for item in receipt.get(field, []))):
        raise ValueError("fault chain requires a well-formed ComparisonReceipt")
    reference = request.get("reference_target")
    if not _text(reference) or reference == request["target"]:
        raise ValueError("fault chain requires two distinct target identities")
    reasons = []
    if (receipt.get("schema") != "openubmc.target-runtime.v1/comparison-receipt-v1"
            or receipt.get("status") != "complete"
            or receipt.get("conclusion") not in {"same", "different"}
            or receipt.get("incomparable_reasons")
            or receipt.get("freshness", {}).get("status") != "fresh"):
        reasons.append("comparison_inconclusive")
    for target in (reference, request["target"]):
        bound = [source for source in receipt.get("sources", []) if source.get("address") == target]
        documents = [source for source in request["sources"].values() if _source_target(source) == target]
        if (len(bound) != 1 or not documents or bound[0].get("status") != "complete"
                or any(source_digest(source) != bound[0].get("source_digest") for source in documents)):
            reasons.append("comparison_source_mismatch:" + target)
    indexed = {(fact["target"], fact["stage"]): fact for fact in facts}
    stages = []
    for stage in STAGES:
        pair = [indexed.get((target, stage)) for target in (reference, request["target"])]
        known = all(fact and fact["status"] == "observed" for fact in pair)
        if not known:
            reasons.append("stage_unknown:" + stage)
        stages.append({
            "stage": stage,
            "status": "unknown" if not known else "same" if pair[0]["present"] == pair[1]["present"] else "different",
            "reference_present": pair[0]["present"] if pair[0] else None,
            "candidate_present": pair[1]["present"] if pair[1] else None,
            "evidence_refs": [fact["evidence_ref"] for fact in pair if fact],
        })
    first = next((stage["stage"] for stage in stages if stage["status"] == "different"), None)
    return {
        "status": "inconclusive" if reasons else "different" if first else "same",
        "reference_target": reference, "candidate_target": request["target"],
        "first_observed_divergence": None if reasons else first,
        "stages": stages, "inconclusive_reasons": reasons,
        "comparison_receipt_id": receipt.get("receipt_id"),
        "comparison_sources": copy.deepcopy(receipt.get("sources", [])),
        "differences": copy.deepcopy(receipt.get("differences", [])),
    }


def build_diagnostic_advice(request: Mapping[str, object]) -> dict[str, object]:
    """Return suggestions without executing queries or accepting any diagnosis."""
    _validate_request(request)
    snapshot_at = _timestamp(request.get("snapshot_at")) or datetime.now(timezone.utc)
    device = request["device"]
    target = request["target"]
    sources = request["sources"]
    facts = []
    for binding in request["facts"]:
        source_id = binding["source_id"]
        source = sources[source_id]
        identity = _pointer(source, binding["device_pointer"])
        value = _pointer(source, binding["value_pointer"])
        if not binding["value_pointer"].startswith(binding["device_pointer"] + "/"):
            raise ValueError("evidence value does not belong to the selected device")
        known = (
            _known_source(source, request, snapshot_at) and type(value) is bool
            and _complete_path(source, binding["device_pointer"] + "/_")
            and _complete_path(source, binding["value_pointer"])
            and isinstance(identity, Mapping)
            and all(identity.get(key) == expected for key, expected in device.items())
        )
        facts.append({
            "stage": binding["stage"], "target": _source_target(source),
            "status": "observed" if known else "unknown", "present": value if known else None,
            "evidence_ref": {
                "source_id": source_id, "source_digest": source_digest(source),
                "device_pointer": binding["device_pointer"], "value_pointer": binding["value_pointer"],
                "observed_at": _source_observed_at(source), "target_epoch": _source_epoch(source),
                **({"observation_ref": copy.deepcopy(request["observation_refs"][source_id])}
                   if source_id in request.get("observation_refs", {}) else {}),
            },
        })
    selected = {fact["stage"]: fact for fact in facts if fact["target"] == target}
    hypotheses = []
    for identifier, description, expectations in HYPOTHESES:
        supporting, contradicting = [], []
        for stage, expected in zip(STAGES, expectations):
            fact = selected.get(stage, {})
            if fact.get("status") == "observed":
                refs = supporting if fact["present"] is expected else contradicting
                refs.append(fact["evidence_ref"])
        hypotheses.append({
            "id": identifier, "description": description,
            "status": "contradicted" if contradicting else "fulfilled" if len(supporting) == len(STAGES) else "unknown",
            "supporting_refs": supporting, "contradicting_refs": contradicting,
        })
    remaining = {item["id"] for item in hypotheses if item["status"] != "contradicted"}
    next_observations = []
    for index, stage in enumerate(STAGES):
        if selected.get(stage, {}).get("status") == "observed":
            continue
        expected = {
            "present": [identifier for identifier, _description, values in HYPOTHESES if identifier in remaining and values[index]],
            "absent": [identifier for identifier, _description, values in HYPOTHESES if identifier in remaining and not values[index]],
        }
        query = request.get("queries", {}).get(stage)
        if query and all(expected.values()):
            next_observations.append({"stage": stage, "query": copy.deepcopy(query), "expected_outcomes": expected})
            break
    advice = {
        "schema": ADVICE_SCHEMA, "rule_version": 1, "status": "advisory",
        "target": target, "device": copy.deepcopy(device),
        "snapshot": {
            "at": snapshot_at.isoformat(), "max_age_seconds": request.get("max_age_seconds", 30),
            "target_epochs": copy.deepcopy(request.get("target_epochs", {})),
            "scope": "captured_snapshot",
        },
        "facts": facts, "hypotheses": hypotheses, "next_observations": next_observations,
    }
    if request.get("include_fault_chain") is True:
        advice["fault_chain"] = _fault_chain(request, facts)
    if len(json.dumps(advice, ensure_ascii=False).encode()) > MAX_ADVICE_BYTES:
        raise ValueError("diagnostic advice exceeds the output byte budget")
    return advice


def attach_diagnostic_advice(capture: Mapping[str, object], request: Mapping[str, object]) -> dict[str, object]:
    """Attach advice only when every source is the capture or one comparison target."""
    if not isinstance(capture, Mapping) or "diagnostic_advice" in capture:
        raise ValueError("an unannotated capture is required")
    advice = build_diagnostic_advice(request)
    candidates = [("", capture)]
    for prefix, container in (("", capture), ("/result", capture.get("result", {}))):
        if isinstance(container, Mapping) and isinstance(container.get("targets"), list):
            candidates.extend(
                (f"{prefix}/targets/{index}/result", entry["result"])
                for index, entry in enumerate(container["targets"])
                if isinstance(entry, Mapping) and isinstance(entry.get("result"), Mapping)
            )
    bindings = []
    for source_id, source in request["sources"].items():
        digest = source_digest(source)
        matches = [pointer for pointer, value in candidates if source_digest(value) == digest]
        if len(matches) != 1:
            raise ValueError("advice source is not uniquely bound to the attached capture")
        bindings.append({"source_id": source_id, "source_pointer": matches[0], "source_digest": digest})
    advice["source_bindings"] = bindings
    if len(json.dumps(advice, ensure_ascii=False).encode()) > MAX_ADVICE_BYTES:
        raise ValueError("attached diagnostic advice exceeds the output byte budget")
    return {**copy.deepcopy(capture), "diagnostic_advice": advice}


def _read_json(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("diagnostic advice input exceeds the byte budget")
    return json.loads(raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--attach-to", type=Path, help="emit the source capture with bound advisory metadata")
    args = parser.parse_args(argv)
    try:
        request = _read_json(args.input)
        advice = (attach_diagnostic_advice(_read_json(args.attach_to), request)
                  if args.attach_to else build_diagnostic_advice(request))
    except (ValueError, KeyError, TypeError, OSError, RecursionError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(advice, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
