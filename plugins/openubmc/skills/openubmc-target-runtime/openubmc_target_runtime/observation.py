"""Runtime-owned qualification of one bounded Observation attempt."""

from __future__ import annotations

from collections.abc import Mapping
import copy
from datetime import datetime

from .capabilities import CAPABILITY_ALIASES
from .semantic_runtime import ObservationQuery, ObservationSelector
from dataclasses import replace


OBSERVATION_TIMING_FIELD = "observation_timing"
OBSERVATION_MAX_SELECTOR_SKEW_SECONDS = 5.0
_SELECTOR_STATUSES = frozenset({"observed", "missing", "stale"})
def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _text(value: object) -> str:
    return str(value).strip() if value is not None else ""


def _instant(value: object) -> datetime | None:
    text = _text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def _target_scope_fact(raw: Mapping[str, object]) -> dict[str, object] | None:
    result = _mapping(raw.get("result"))
    runtime = _mapping(result.get("runtime"))
    status = _mapping(runtime.get("status"))
    targets = status.get("targets", [])
    if not isinstance(targets, list) or len(targets) != 1:
        return None
    detail = _mapping(targets[0])
    target = _mapping(detail.get("target"))
    identity = {
        key: value for key, value in _mapping(detail.get("identity")).items()
        if key not in {"schema", "target_clock"}
    }
    epochs = _mapping(detail.get("epochs"))
    if not target and not identity and "target_epoch" not in epochs:
        return None
    return {
        "target": copy.deepcopy(dict(target)),
        "identity": copy.deepcopy(dict(identity)),
        "target_epoch": copy.deepcopy(epochs.get("target_epoch")),
    }


def observation_target_scope_matches(
    baseline: Mapping[str, object],
    candidate: Mapping[str, object],
) -> bool:
    """Return whether an assured partition stayed on its fast target scope."""

    return _target_scope_fact(baseline) == _target_scope_fact(candidate)


def observation_target_scope_known(raw: Mapping[str, object]) -> bool:
    """Automatic reuse needs a positive target identity and an explicit epoch."""
    fact = _target_scope_fact(raw)
    if fact is None:
        return False
    epoch = fact.get("target_epoch")
    return (
        bool(_text(_mapping(fact.get("target")).get("fingerprint")))
        and any(isinstance(value, str) and value.strip() for value in _mapping(fact.get("identity")).values())
        and isinstance(epoch, int) and not isinstance(epoch, bool) and epoch >= 0
    )


def observation_completion_window_matches(*observations: Mapping[str, object]) -> bool:
    completions = [
        _instant(_mapping(item).get("completed_at"))
        for raw in observations
        for item in _mapping(raw.get(OBSERVATION_TIMING_FIELD)).get("selectors", [])
    ]
    if not completions or any(value is None for value in completions):
        return False
    return (max(completions) - min(completions)).total_seconds() <= OBSERVATION_MAX_SELECTOR_SKEW_SECONDS


def reusable_selector_fragments(
    query: ObservationQuery,
    prior_query: ObservationQuery,
    prior: Mapping[str, object],
) -> tuple[tuple[tuple[ObservationQuery, Mapping[str, object]], ...], tuple[ObservationSelector, ...]]:
    """Partition an evidence plan into exact reusable values and missing values."""
    # A systemd selector owns one boot/invocation window. Value-by-value cache
    # reconstruction cannot retain that window, so recollect the whole query.
    if any(item.kind == "systemd" for item in query.selectors):
        return (), query.selectors
    prior_selectors = {(item.selector_id, item.kind): item for item in prior_query.selectors}
    lanes = _mapping(_mapping(_mapping(prior.get("result")).get("lanes")).get("ssh"))
    prior_mdb = {}
    index = 0
    for selector in prior_query.selectors:
        for value in selector.mdb_queries:
            name = "mdbctl" if index == 0 else f"mdbctl_{index + 1}"
            prior_mdb[(selector.selector_id, value)] = lanes.get(name)
            index += 1
    fragments: list[tuple[ObservationQuery, Mapping[str, object]]] = []
    missing: list[ObservationSelector] = []
    for selector in query.selectors:
        old = prior_selectors.get((selector.selector_id, selector.kind))
        values = tuple(value for value in selector.values if old is not None and value in old.values)
        absent = tuple(value for value in selector.values if value not in values)
        if absent:
            missing.append(selector.with_values(absent))
        if not values:
            continue
        narrowed = selector.with_values(values)
        fragment_query = replace(query, selectors=(narrowed,))
        fragment = copy.deepcopy(dict(prior))
        result = dict(_mapping(fragment.get("result")))
        if selector.kind == "mdb":
            ssh = {
                ("mdbctl" if i == 0 else f"mdbctl_{i + 1}"): copy.deepcopy(prior_mdb[(selector.selector_id, value)])
                for i, value in enumerate(values)
            }
            result["lanes"] = {"ssh": ssh}
            result["capabilities"] = {}
        else:
            capabilities = _mapping(result.get("capabilities"))
            result["capabilities"] = {CAPABILITY_ALIASES[name]: capabilities[CAPABILITY_ALIASES[name]] for name in values if CAPABILITY_ALIASES[name] in capabilities}
            result["lanes"] = {"ssh": {}}
        result.pop("collection_partitions", None)
        fragment["result"] = result
        timing = dict(_mapping(fragment.get(OBSERVATION_TIMING_FIELD)))
        timing["selectors"] = [
            copy.deepcopy(item) for item in timing.get("selectors", [])
            if _mapping(item).get("selector_id") == selector.selector_id
        ]
        fragment[OBSERVATION_TIMING_FIELD] = timing
        fragments.append((fragment_query, fragment))
    return tuple(fragments), tuple(missing)


def capability_selector_complete(
    capabilities: Mapping[str, object],
    names: tuple[str, ...] | list[str],
) -> bool:
    return all(
        CAPABILITY_ALIASES.get(name) in capabilities
        and (
            name != "alarms"
            or capabilities.get(CAPABILITY_ALIASES[name]) is True
        )
        for name in names
    )


def selected_scope_complete(
    raw: Mapping[str, object], query: ObservationQuery
) -> bool:
    result = _mapping(raw.get("result"))
    capabilities = _mapping(result.get("capabilities"))
    lanes = _mapping(result.get("lanes"))
    ssh = _mapping(lanes.get("ssh"))
    mdb_index = 0
    for selector in query.selectors:
        if selector.kind == "systemd":
            child = _mapping(_mapping(result.get("systemd")).get(selector.selector_id))
            if child.get("complete") is not True or child.get("requested") != list(selector.names):
                return False
            continue
        if selector.kind == "capability":
            if not capability_selector_complete(capabilities, selector.names):
                return False
            continue
        for _query in selector.queries:
            name = "mdbctl" if mdb_index == 0 else f"mdbctl_{mdb_index + 1}"
            mdb_index += 1
            child = _mapping(ssh.get(name))
            if not child or child.get("ok") is not True:
                return False
    return True


def _partition_record(
    query: ObservationQuery,
    raw: Mapping[str, object],
    result: Mapping[str, object],
) -> dict[str, object]:
    record = copy.deepcopy(dict(raw))
    recorded_result = copy.deepcopy(dict(result))
    recorded_lanes = copy.deepcopy(dict(_mapping(recorded_result.get("lanes"))))
    recorded_lanes.pop("ssh", None)
    if recorded_lanes:
        recorded_result["lanes"] = recorded_lanes
    else:
        recorded_result.pop("lanes", None)
    record["result"] = recorded_result
    record["scope"] = query.to_public_dict()
    return record


def _merge_mdb_lanes(
    query: ObservationQuery,
    ssh: Mapping[str, object],
    merged: dict[str, object],
    global_index: int,
) -> int:
    local_index = 0
    for selector in query.selectors:
        for _query in selector.mdb_queries:
            local_name = (
                "mdbctl" if local_index == 0 else f"mdbctl_{local_index + 1}"
            )
            global_name = (
                "mdbctl" if global_index == 0 else f"mdbctl_{global_index + 1}"
            )
            if local_name in ssh:
                merged[global_name] = copy.deepcopy(ssh[local_name])
            local_index += 1
            global_index += 1
    return global_index


def _target_scope_changed(
    facts: list[dict[str, object] | None],
) -> bool:
    known = [fact for fact in facts if fact is not None]
    return bool(known) and (
        len(known) != len(facts)
        or any(fact != known[0] for fact in known[1:])
    )


def _merged_selector_timing(
    query: ObservationQuery,
    fragments_by_selector: Mapping[
        tuple[str, str], list[Mapping[str, object]]
    ],
    *,
    target_scope_changed: bool,
    invalid_partition_timing: set[tuple[str, str]],
) -> dict[str, object]:
    selector_facts: list[dict[str, object]] = []
    for selector in query.selectors:
        fragments = fragments_by_selector.get(
            (selector.selector_id, selector.kind), []
        )
        starts = [
            (_instant(fact.get("started_at")), _text(fact.get("started_at")))
            for fact in fragments
        ]
        completions = [
            (
                _instant(fact.get("completed_at")),
                _text(fact.get("completed_at")),
            )
            for fact in fragments
        ]
        valid_starts = [item for item in starts if item[0] is not None]
        valid_completions = [item for item in completions if item[0] is not None]
        statuses = {_text(fact.get("status")) for fact in fragments}
        status = (
            "observed"
            if fragments and statuses == {"observed"}
            else "stale"
            if "stale" in statuses
            else "missing"
        )
        if target_scope_changed or (
            selector.selector_id,
            selector.kind,
        ) in invalid_partition_timing:
            status = "stale"
        selector_facts.append(
            {
                "selector_id": selector.selector_id,
                "kind": selector.kind,
                "started_at": (
                    min(valid_starts, key=lambda item: item[0])[1]
                    if valid_starts
                    else ""
                ),
                "completed_at": (
                    max(valid_completions, key=lambda item: item[0])[1]
                    if valid_completions
                    else ""
                ),
                "status": status,
            }
        )
    attempt_starts = [
        (_instant(item["started_at"]), str(item["started_at"]))
        for item in selector_facts
        if _instant(item["started_at"]) is not None
    ]
    attempt_completions = [
        (_instant(item["completed_at"]), str(item["completed_at"]))
        for item in selector_facts
        if _instant(item["completed_at"]) is not None
    ]
    return {
        "started_at": (
            min(attempt_starts, key=lambda item: item[0])[1]
            if attempt_starts
            else ""
        ),
        "completed_at": (
            max(attempt_completions, key=lambda item: item[0])[1]
            if attempt_completions
            else ""
        ),
        "selectors": selector_facts,
    }


def aggregate_observation_partitions(
    query: ObservationQuery,
    partitions: tuple[tuple[ObservationQuery, Mapping[str, object]], ...],
) -> dict[str, object]:
    """Aggregate Runtime-enforced collection partitions into one source result."""

    if not partitions:
        raise ValueError("observation collection requires at least one partition")
    if len(partitions) == 1:
        return dict(partitions[0][1])

    aggregate = copy.deepcopy(dict(partitions[0][1]))
    first_result = _mapping(aggregate.get("result"))
    merged_result = copy.deepcopy(dict(first_result))
    merged_capabilities: dict[str, object] = {}
    selected_capabilities: dict[str, object] = {}
    merged_lanes: dict[str, object] = {}
    merged_ssh: dict[str, object] = {}
    merged_systemd: dict[str, object] = {}
    partition_records: list[dict[str, object]] = []
    timing_fragments: dict[
        tuple[str, str], list[Mapping[str, object]]
    ] = {}
    invalid_partition_timing: set[tuple[str, str]] = set()
    selected_capability_keys = {
        CAPABILITY_ALIASES[name]
        for selector in query.selectors
        if selector.kind == "capability"
        for name in selector.names
    }
    missing_selected_capability_facts: set[str] = set()
    raw_gaps: list[object] = []
    observed_at_values: list[str] = []
    target_scope_facts: list[dict[str, object] | None] = []
    global_mdb_index = 0
    all_ok = True

    for partition_query, raw_value in partitions:
        raw = _mapping(raw_value)
        all_ok = all_ok and raw.get("ok") is True
        observed_at = _text(raw.get("observed_at"))
        if observed_at:
            observed_at_values.append(observed_at)
        target_scope_facts.append(_target_scope_fact(raw))
        gaps = raw.get("gaps", [])
        if isinstance(gaps, list):
            raw_gaps.extend(gaps)
        result = _mapping(raw.get("result"))
        partition_records.append(_partition_record(partition_query, raw, result))
        merged_systemd.update(copy.deepcopy(dict(_mapping(result.get("systemd")))))
        capabilities = _mapping(result.get("capabilities"))
        partition_selected_capability_keys = {
            CAPABILITY_ALIASES[name]
            for selector in partition_query.selectors
            if selector.kind == "capability"
            for name in selector.names
        }
        for name, value in capabilities.items():
            normalized_name = str(name)
            if normalized_name in partition_selected_capability_keys:
                selected_capabilities[normalized_name] = copy.deepcopy(value)
            elif normalized_name in selected_capability_keys:
                continue
            elif normalized_name not in merged_capabilities:
                merged_capabilities[normalized_name] = copy.deepcopy(value)
        missing_selected_capability_facts.update(
            partition_selected_capability_keys.difference(capabilities)
        )
        lanes = _mapping(result.get("lanes"))
        for lane_name, lane_value in lanes.items():
            if lane_name != "ssh":
                merged_lanes[str(lane_name)] = copy.deepcopy(lane_value)
        ssh = _mapping(lanes.get("ssh"))
        global_mdb_index = _merge_mdb_lanes(
            partition_query, ssh, merged_ssh, global_mdb_index
        )
        timing = _mapping(raw.get(OBSERVATION_TIMING_FIELD))
        selector_facts = timing.get("selectors", [])
        expected_timing = [
            (selector.selector_id, selector.kind)
            for selector in partition_query.selectors
        ]
        actual_timing = (
            [
                (
                    _text(_mapping(item).get("selector_id")),
                    _text(_mapping(item).get("kind")),
                )
                for item in selector_facts
            ]
            if isinstance(selector_facts, list)
            else []
        )
        if actual_timing == expected_timing:
            for item in selector_facts:
                fact = _mapping(item)
                key = (_text(fact.get("selector_id")), _text(fact.get("kind")))
                timing_fragments.setdefault(key, []).append(fact)
        else:
            invalid_partition_timing.update(expected_timing)
        for key, value in result.items():
            if key in {"capabilities", "lanes", "preflight_start", "runtime"}:
                continue
            merged_result[str(key)] = copy.deepcopy(value)
        for key, value in raw.items():
            if key not in {
                "result",
                "ok",
                "observed_at",
                "gaps",
                OBSERVATION_TIMING_FIELD,
            }:
                aggregate[str(key)] = copy.deepcopy(value)

    merged_lanes["ssh"] = merged_ssh
    for capability_key in missing_selected_capability_facts:
        selected_capabilities.pop(capability_key, None)
    merged_capabilities.update(selected_capabilities)
    merged_result["capabilities"] = merged_capabilities
    merged_result["lanes"] = merged_lanes
    if merged_systemd:
        merged_result["systemd"] = merged_systemd
    merged_result["collection_partitions"] = partition_records
    aggregate["result"] = merged_result
    aggregate["ok"] = all_ok
    valid_observed = [
        (instant, value)
        for value in observed_at_values
        if (instant := _instant(value)) is not None
    ]
    if valid_observed:
        aggregate["observed_at"] = max(
            valid_observed, key=lambda item: item[0]
        )[1]
    elif observed_at_values:
        aggregate["observed_at"] = max(observed_at_values)
    target_scope_changed = _target_scope_changed(target_scope_facts)
    if target_scope_changed:
        raw_gaps.append(
            "target identity or epoch changed across observation partitions"
        )
    if invalid_partition_timing:
        raw_gaps.append(
            "one or more observation partitions omitted or reordered partition selector timing"
        )
    if missing_selected_capability_facts:
        raw_gaps.append(
            "one or more selected capability facts were omitted by their observation partition"
        )
    normalized_gaps = [_text(gap) for gap in raw_gaps if _text(gap)]
    if normalized_gaps:
        aggregate["gaps"] = list(dict.fromkeys(normalized_gaps))[:16]

    aggregate[OBSERVATION_TIMING_FIELD] = _merged_selector_timing(
        query,
        timing_fragments,
        target_scope_changed=target_scope_changed,
        invalid_partition_timing=invalid_partition_timing,
    )
    return aggregate


def qualify_observation(
    raw: Mapping[str, object],
    query: ObservationQuery,
    *,
    scope_complete: bool,
) -> dict[str, object]:
    """Return a copy with authoritative selector timing and consistency facts."""

    qualified = dict(raw)
    supplied = _mapping(raw.get(OBSERVATION_TIMING_FIELD))
    raw_selectors = supplied.get("selectors")
    expected = [(selector.selector_id, selector.kind) for selector in query.selectors]
    selector_facts: list[dict[str, object]] = []
    if isinstance(raw_selectors, list):
        actual = [
            (_text(_mapping(item).get("selector_id")), _text(_mapping(item).get("kind")))
            for item in raw_selectors
        ]
        if actual != expected:
            raise ValueError(
                "observation selector timing must match the declared selector order"
            )
        for item in raw_selectors:
            fact = _mapping(item)
            status = _text(fact.get("status"))
            if status not in _SELECTOR_STATUSES:
                status = "missing"
            selector_facts.append(
                {
                    "selector_id": _text(fact.get("selector_id")),
                    "kind": _text(fact.get("kind")),
                    "started_at": _text(fact.get("started_at")),
                    "completed_at": _text(fact.get("completed_at")),
                    "status": status,
                }
            )
    else:
        selector_facts = [
            {
                "selector_id": selector.selector_id,
                "kind": selector.kind,
                "started_at": "",
                "completed_at": "",
                "status": "missing",
            }
            for selector in query.selectors
        ]

    selector_starts = [_instant(fact["started_at"]) for fact in selector_facts]
    selector_completions = [_instant(fact["completed_at"]) for fact in selector_facts]
    valid_starts = [value for value in selector_starts if value is not None]
    valid_completions = [value for value in selector_completions if value is not None]
    supplied_start_text = _text(supplied.get("started_at"))
    supplied_complete_text = _text(supplied.get("completed_at"))
    attempt_start = _instant(supplied_start_text)
    attempt_complete = _instant(supplied_complete_text)
    if attempt_start is None and valid_starts:
        attempt_start = min(valid_starts)
        supplied_start_text = min(
            (fact["started_at"] for fact in selector_facts if _instant(fact["started_at"])),
            key=lambda value: _instant(value),
        )
    if attempt_complete is None and valid_completions:
        attempt_complete = max(valid_completions)
        supplied_complete_text = max(
            (
                fact["completed_at"]
                for fact in selector_facts
                if _instant(fact["completed_at"])
            ),
            key=lambda value: _instant(value),
        )

    gaps: list[str] = []
    for index, fact in enumerate(selector_facts):
        started = selector_starts[index]
        completed = selector_completions[index]
        if fact["status"] == "observed" and (
            started is None or completed is None or completed < started
        ):
            fact["status"] = "missing"
        if fact["status"] == "observed" and (
            attempt_start is None
            or attempt_complete is None
            or started < attempt_start
            or completed > attempt_complete
        ):
            fact["status"] = "stale"
        if fact["status"] != "observed":
            gaps.append(
                f"selector {fact['selector_id']} timing is {fact['status']}"
            )

    observed_completions = [
        _instant(fact["completed_at"])
        for fact in selector_facts
        if fact["status"] == "observed"
    ]
    observed_completions = [
        value for value in observed_completions if value is not None
    ]
    skew_seconds = (
        (max(observed_completions) - min(observed_completions)).total_seconds()
        if len(observed_completions) > 1
        else 0.0
    )
    over_skew = skew_seconds > OBSERVATION_MAX_SELECTOR_SKEW_SECONDS
    if over_skew:
        gaps.append(
            "selector completion skew exceeds the Runtime consistency window"
        )
    if not scope_complete:
        gaps.append("one or more selected facts were not observed")
    if attempt_start is None or attempt_complete is None or attempt_complete < attempt_start:
        gaps.append("observation attempt window is incomplete")

    if over_skew:
        classification = "inconsistent"
    elif gaps:
        classification = "partial"
    else:
        classification = "coherent"
    consistency = {
        "started_at": supplied_start_text,
        "completed_at": supplied_complete_text,
        "selectors": selector_facts,
        "classification": classification,
        "max_skew_seconds": OBSERVATION_MAX_SELECTOR_SKEW_SECONDS,
        "observed_skew_seconds": skew_seconds,
        "reusable": classification == "coherent",
        "gaps": list(dict.fromkeys(gaps))[:16],
    }
    qualified[OBSERVATION_TIMING_FIELD] = consistency
    return qualified


def observation_reusable(raw: Mapping[str, object]) -> bool:
    timing = _mapping(raw.get(OBSERVATION_TIMING_FIELD))
    return timing.get("classification") == "coherent" and timing.get("reusable") is True


def observation_consistency(raw: Mapping[str, object]) -> dict[str, object]:
    timing = _mapping(raw.get(OBSERVATION_TIMING_FIELD))
    return dict(timing)


def observation_improves(
    candidate: Mapping[str, object],
    baseline: Mapping[str, object],
) -> bool:
    candidate_timing = _mapping(candidate.get(OBSERVATION_TIMING_FIELD))
    baseline_timing = _mapping(baseline.get(OBSERVATION_TIMING_FIELD))
    ranks = {"inconsistent": 0, "partial": 1, "coherent": 2}
    candidate_selectors = candidate_timing.get("selectors", [])
    baseline_selectors = baseline_timing.get("selectors", [])
    candidate_observed = sum(
        _mapping(item).get("status") == "observed"
        for item in (
            candidate_selectors if isinstance(candidate_selectors, list) else []
        )
    )
    baseline_observed = sum(
        _mapping(item).get("status") == "observed"
        for item in (
            baseline_selectors if isinstance(baseline_selectors, list) else []
        )
    )
    candidate_rank = ranks.get(
        _text(candidate_timing.get("classification")), 0
    )
    baseline_rank = ranks.get(
        _text(baseline_timing.get("classification")), 0
    )
    return candidate_rank > baseline_rank or (
        candidate_rank == baseline_rank
        and candidate_observed > baseline_observed
    )
