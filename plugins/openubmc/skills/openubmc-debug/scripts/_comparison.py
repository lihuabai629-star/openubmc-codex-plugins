#!/usr/bin/env python3
"""Structured dual-target comparison for compatible Debug v1 results."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import statistics
from typing import Callable, Mapping


COMPARE_SCHEMA_VERSION = "openubmc-debug.compare.v1"
SINGLE_SCHEMA_VERSION = "openubmc-debug.v1"
_MISSING = object()
_COMPACT_VALUE_LIMIT_BYTES = 256
_COMPACT_WARNING = "comparison_values_compacted"
_VOLATILE_KEYS = {
    "completed_at",
    "duration",
    "duration_ms",
    "elapsed",
    "elapsed_ms",
    "evidence_id",
    "observed_at",
    "queue_delay_ms",
    "started_at",
    "target_clock",
    "timestamp",
    "uptime",
}
_OPERATIONAL_KEYS = {
    "bytes_captured",
    "bytes_read",
    "bytes_returned",
    "command",
    "dbus_session_bus_address",
    "deadline",
    "ip",
    "output_dir",
    "recommended_command",
    "request",
    "runtime",
    "transport",
    "written_files",
    "xdg_runtime_dir",
}
_VOLATILE_SECOND_KEYS = {
    "after_seconds",
    "before_seconds",
    "bmc_elapsed_seconds",
    "elapsed_seconds",
    "expected_after_seconds",
    "observation_elapsed_lower_bound_seconds",
    "observation_elapsed_seconds",
    "observation_elapsed_upper_bound_seconds",
    "remaining_seconds",
    "uptime_gap_seconds",
}
_IGNORED_DIFF_PATHS = {
    "$.result.correlation.evidence_pool",
    "$.result.correlation.records",
    "$.result.freshness.active_alarms_end",
    "$.result.freshness.bmc_time_delta",
    "$.result.freshness.preflight_end",
    "$.result.freshness.uptime_end",
    "$.result.freshness.version_end",
    "$.result.preflight_start",
}
_STABLE_IDENTITY_KEYS = (
    "target_id",
    "object_id",
    "id",
    "object_path",
    "path",
    "dn",
    "name",
)
_QUALITY_TOKENS = {
    "partial": "partial",
    "stale": "stale",
    "truncat": "truncated",
    "unsupported": "unsupported",
    "not_observed": "not_observed",
    "collection_failed": "collection_failed",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("observation timestamps must include a timezone offset")
    return parsed


def _normalized_key(key: object) -> str:
    return str(key).strip().lower().replace("-", "_")


def _normalize_for_diff(
    value: object,
    *,
    key: str = "",
    path: str = "$",
    incomparable_paths: set[str] | None = None,
) -> object:
    normalized_key = _normalized_key(key)
    if (
        path in _IGNORED_DIFF_PATHS
        or normalized_key in _VOLATILE_KEYS
        or normalized_key in _OPERATIONAL_KEYS
        or normalized_key in _VOLATILE_SECOND_KEYS
        or normalized_key.endswith("_at")
    ):
        return "<volatile>"
    if isinstance(value, dict):
        return {
            str(item_key): _normalize_for_diff(
                item,
                key=str(item_key),
                path=f"{path}.{item_key}",
                incomparable_paths=incomparable_paths,
            )
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        identity = _stable_list_identity(value)
        if identity is not None:
            identity_key, identified = identity
            return {
                f"{identity_key}={identity_value}": _normalize_for_diff(
                    item,
                    path=f"{path}[{identity_key}={identity_value}]",
                    incomparable_paths=incomparable_paths,
                )
                for identity_value, item in identified.items()
            }
        if value and incomparable_paths is not None:
            incomparable_paths.add(path)
            return {
                "<unidentified-list>": {
                    "status": "incomparable",
                    "item_count": len(value),
                }
            }
        return [
            _normalize_for_diff(
                item,
                path=f"{path}[]",
                incomparable_paths=incomparable_paths,
            )
            for item in value
        ]
    return value


def _stable_list_identity(
    value: list[object],
) -> tuple[str, dict[str, Mapping[str, object]]] | None:
    if not value or not all(isinstance(item, Mapping) for item in value):
        return None
    for identity_key in _STABLE_IDENTITY_KEYS:
        identified: dict[str, Mapping[str, object]] = {}
        valid = True
        for raw_item in value:
            item = raw_item if isinstance(raw_item, Mapping) else {}
            identity = item.get(identity_key)
            if not isinstance(identity, (str, int)) or isinstance(identity, bool):
                valid = False
                break
            cooked = str(identity).strip()
            if not cooked or cooked in identified:
                valid = False
                break
            identified[cooked] = item
        if valid:
            return identity_key, identified
    return None


def _quality_flags(result: Mapping[str, object] | None) -> list[str]:
    if result is None:
        return ["collection_failed"]
    candidates: list[str] = [
        str(result.get("code", "")),
        str(result.get("normalized_code", "")),
        str(result.get("error", "")),
    ]
    warnings = result.get("warnings")
    if isinstance(warnings, list):
        candidates.extend(str(item) for item in warnings)
    combined = " ".join(candidates).lower()
    return sorted(
        {
            label
            for token, label in _QUALITY_TOKENS.items()
            if token in combined
        }
    )


def _scope_signature(result: Mapping[str, object] | None) -> str | None:
    if result is None:
        return None
    explicit = result.get("evidence_scope")
    if explicit is not None:
        return hashlib.sha256(
            json.dumps(explicit, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
    request = result.get("request")
    if not isinstance(request, Mapping):
        return None
    scope = {
        key: request[key]
        for key in (
            "profile",
            "mdb_only",
            "mdb_queries",
            "mdb_expand_classes",
            "files",
            "include_rotated",
            "skip_telnet",
        )
        if key in request
    }
    if not scope:
        return None
    return hashlib.sha256(
        json.dumps(scope, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _freshness_signature(result: Mapping[str, object] | None) -> str | None:
    if result is None:
        return None
    explicit = result.get("freshness_boundary")
    if explicit is None:
        return None
    return hashlib.sha256(
        json.dumps(explicit, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _diff_card(
    *,
    mode: str,
    differences: list[dict[str, object]],
    incomparable_paths: set[str],
    quality_by_target: Mapping[str, list[str]],
    scope_equal: bool | None,
    freshness_equal: bool | None,
    failures: list[dict[str, object]],
) -> dict[str, object]:
    quality_partial = any(quality_by_target.values())
    inconclusive = bool(incomparable_paths) or scope_equal is False or freshness_equal is False
    status = "partial" if failures or quality_partial else "complete"
    comparability = "inconclusive" if inconclusive else "comparable"
    quality_statuses = sorted(
        {
            flag
            for flags in quality_by_target.values()
            for flag in flags
        }
    )
    if status != "complete" or comparability == "inconclusive":
        conclusion = "inconclusive"
    else:
        conclusion = "different" if differences else "same"
    return {
        "schema_version": "openubmc-debug.diff-card.v1",
        "mode": mode,
        "status": status,
        "comparability": comparability,
        "quality_statuses": quality_statuses,
        "conclusion": conclusion,
        "difference_count": len(differences),
        "important_changes": [
            {"path": item.get("path", ""), "kind": item.get("kind", "changed")}
            for item in differences[:16]
        ],
        "incomparable_paths": sorted(incomparable_paths),
        "quality_flags": {key: list(value) for key, value in quality_by_target.items()},
        "scope_equal": scope_equal,
        "freshness_equal": freshness_equal,
    }


def _normalized_volatile_fields() -> list[str]:
    return sorted(
        _VOLATILE_KEYS
        | _OPERATIONAL_KEYS
        | _VOLATILE_SECOND_KEYS
        | _IGNORED_DIFF_PATHS
    )


def _diff_values(
    left: object,
    right: object,
    *,
    path: str,
    left_role: str,
    right_role: str,
) -> list[dict[str, object]]:
    if isinstance(left, dict) and isinstance(right, dict):
        differences: list[dict[str, object]] = []
        for key in sorted(set(left) | set(right), key=str):
            next_path = f"{path}.{key}"
            left_value = left.get(key, _MISSING)
            right_value = right.get(key, _MISSING)
            if left_value is _MISSING:
                differences.append(
                    {
                        "path": next_path,
                        "kind": f"only-on-{right_role}",
                        "left": None,
                        "right": right_value,
                    }
                )
            elif right_value is _MISSING:
                differences.append(
                    {
                        "path": next_path,
                        "kind": f"only-on-{left_role}",
                        "left": left_value,
                        "right": None,
                    }
                )
            else:
                differences.extend(
                    _diff_values(
                        left_value,
                        right_value,
                        path=next_path,
                        left_role=left_role,
                        right_role=right_role,
                    )
                )
        return differences
    if left == right:
        return []
    return [
        {
            "path": path,
            "kind": "changed",
            "left": left,
            "right": right,
        }
    ]


def _compact_value(value: object) -> tuple[object, bool]:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    ).encode("utf-8")
    if len(encoded) <= _COMPACT_VALUE_LIMIT_BYTES:
        return value, False
    summary: dict[str, object] = {
        "compacted": True,
        "type": type(value).__name__,
        "size_bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }
    if isinstance(value, (dict, list)):
        summary["item_count"] = len(value)
    return summary, True


def compact_comparison_values(payload: dict[str, object]) -> dict[str, object]:
    """Deduplicate large diff values while preserving target evidence."""

    compacted = copy.deepcopy(payload)
    comparison = compacted.get("comparison")
    if not isinstance(comparison, dict):
        return compacted
    changed = False

    def compact_differences(value: object) -> None:
        nonlocal changed
        if not isinstance(value, list):
            return
        for difference in value:
            if not isinstance(difference, dict):
                continue
            for name in ("left", "right"):
                if name not in difference:
                    continue
                replacement, replaced = _compact_value(difference[name])
                if replaced:
                    difference[name] = replacement
                    changed = True

    compact_differences(comparison.get("differences"))
    candidate_comparisons = comparison.get("candidate_comparisons")
    if isinstance(candidate_comparisons, list):
        for candidate in candidate_comparisons:
            if isinstance(candidate, dict):
                compact_differences(candidate.get("differences"))
    value_groups = comparison.get("value_groups")
    if isinstance(value_groups, list):
        for path_groups in value_groups:
            if not isinstance(path_groups, dict):
                continue
            groups = path_groups.get("groups")
            if not isinstance(groups, list):
                continue
            for group in groups:
                if not isinstance(group, dict) or "value" not in group:
                    continue
                replacement, replaced = _compact_value(group["value"])
                if replaced:
                    group["value"] = replacement
                    changed = True
    if changed:
        warnings = compacted.get("warnings")
        if not isinstance(warnings, list):
            warnings = []
            compacted["warnings"] = warnings
        if _COMPACT_WARNING not in warnings:
            warnings.append(_COMPACT_WARNING)
    return compacted


def _capabilities(result: Mapping[str, object] | None) -> dict[str, object]:
    if result is None:
        return {}
    body = result.get("result")
    capabilities = body.get("capabilities") if isinstance(body, Mapping) else None
    if not isinstance(capabilities, Mapping):
        return {}
    return {str(key): value for key, value in capabilities.items()}


def _phase_starts(result: Mapping[str, object] | None) -> dict[str, str]:
    starts: dict[str, str] = {}

    def visit(value: object) -> None:
        if isinstance(value, Mapping):
            name = value.get("name")
            started_at = value.get("started_at")
            if isinstance(name, str) and isinstance(started_at, str):
                starts.setdefault(name, started_at)
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(result)
    return starts


@dataclass(frozen=True)
class TargetObservation:
    role: str
    target_id: str
    started_at: str
    completed_at: str
    result: dict[str, object] | None
    error_code: str = ""
    error: str = ""
    queue_delay_ms: float = 0.0

    @classmethod
    def success(
        cls,
        *,
        role: str,
        target_id: str,
        started_at: str,
        completed_at: str,
        result: dict[str, object],
        queue_delay_ms: float = 0.0,
    ) -> "TargetObservation":
        if result.get("schema_version") != SINGLE_SCHEMA_VERSION:
            raise ValueError("dual comparison requires openubmc-debug.v1 results")
        return cls(
            role,
            target_id,
            started_at,
            completed_at,
            result,
            queue_delay_ms=queue_delay_ms,
        )

    @classmethod
    def failure(
        cls,
        *,
        role: str,
        target_id: str,
        started_at: str,
        completed_at: str,
        error_code: str,
        error: str,
        queue_delay_ms: float = 0.0,
    ) -> "TargetObservation":
        return cls(
            role,
            target_id,
            started_at,
            completed_at,
            None,
            error_code=error_code,
            error=error,
            queue_delay_ms=queue_delay_ms,
        )

    @property
    def status(self) -> str:
        if self.result is None or not bool(self.result.get("ok")):
            return "failed"
        return "ok"

    def to_public_dict(self) -> dict[str, object]:
        error_code = self.error_code
        error = self.error
        if self.result is not None and self.status == "failed":
            error_code = str(self.result.get("code", "target_local_failure"))
            error = str(self.result.get("error", ""))
        return {
            "role": self.role,
            "target_id": self.target_id,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "queue_delay_ms": self.queue_delay_ms,
            "duration_ms": max(
                0.0,
                (
                    _parse_time(self.completed_at) - _parse_time(self.started_at)
                ).total_seconds()
                * 1000,
            ),
            "error_code": error_code,
            "error": error,
            "result": self.result,
        }


def build_dual_comparison(
    *,
    observations: list[TargetObservation],
    scheduler_metrics: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if len(observations) != 2:
        raise ValueError("dual comparison requires exactly two observations")
    roles = [observation.role for observation in observations]
    mode = (
        "reference-candidate"
        if set(roles) == {"reference", "candidate"}
        else "symmetric"
    )
    if mode == "symmetric" and roles != ["target-a", "target-b"]:
        raise ValueError(
            "roles must be reference/candidate or the symmetric target-a/target-b pair"
        )
    ordered = (
        sorted(observations, key=lambda item: roles.index(item.role))
        if mode == "symmetric"
        else sorted(observations, key=lambda item: item.role != "reference")
    )
    starts = [_parse_time(item.started_at) for item in ordered]
    completions = [_parse_time(item.completed_at) for item in ordered]
    start_skew_ms = abs((starts[1] - starts[0]).total_seconds()) * 1000
    target_entries = [item.to_public_dict() for item in ordered]
    failures = [
        {
            "role": entry["role"],
            "target_id": entry["target_id"],
            "code": entry["error_code"] or "target_local_failure",
            "error": entry["error"],
        }
        for entry in target_entries
        if entry["status"] == "failed"
    ]

    left_result = ordered[0].result
    right_result = ordered[1].result
    differences: list[dict[str, object]] = []
    incomparable_paths: set[str] = set()
    if left_result is not None and right_result is not None:
        differences = _diff_values(
            _normalize_for_diff(
                left_result,
                incomparable_paths=incomparable_paths,
            ),
            _normalize_for_diff(
                right_result,
                incomparable_paths=incomparable_paths,
            ),
            path="$",
            left_role=ordered[0].role,
            right_role=ordered[1].role,
        )
    quality_by_target = {
        item.target_id: _quality_flags(item.result) for item in ordered
    }
    scope_signatures = [_scope_signature(item.result) for item in ordered]
    scope_equal = (
        scope_signatures[0] == scope_signatures[1]
        if all(signature is not None for signature in scope_signatures)
        else None
    )
    freshness_signatures = [_freshness_signature(item.result) for item in ordered]
    freshness_equal = (
        freshness_signatures[0] == freshness_signatures[1]
        if all(signature is not None for signature in freshness_signatures)
        else None
    )

    left_capabilities = _capabilities(left_result)
    right_capabilities = _capabilities(right_result)
    capability_names = sorted(set(left_capabilities) | set(right_capabilities))
    capability_asymmetry = [
        f"$.result.capabilities.{name}"
        for name in capability_names
        if left_capabilities.get(name, _MISSING)
        != right_capabilities.get(name, _MISSING)
    ]
    unsupported = {
        ordered[0].role: [
            f"$.result.capabilities.{name}"
            for name, value in sorted(left_capabilities.items())
            if value is False or value is None
        ],
        ordered[1].role: [
            f"$.result.capabilities.{name}"
            for name, value in sorted(right_capabilities.items())
            if value is False or value is None
        ],
    }
    left_phases = _phase_starts(left_result)
    right_phases = _phase_starts(right_result)
    phases: dict[str, object] = {}
    for name in sorted(set(left_phases) & set(right_phases)):
        left_start = _parse_time(left_phases[name])
        right_start = _parse_time(right_phases[name])
        phases[name] = {
            ordered[0].role: left_phases[name],
            ordered[1].role: right_phases[name],
            "start_skew_ms": abs(
                (right_start - left_start).total_seconds()
            )
            * 1000,
        }

    card = _diff_card(
        mode=mode,
        differences=differences,
        incomparable_paths=incomparable_paths,
        quality_by_target=quality_by_target,
        scope_equal=scope_equal,
        freshness_equal=freshness_equal,
        failures=failures,
    )
    complete = card["status"] == "complete"
    if scheduler_metrics is None:
        scheduler = {
            "requested_policy": "unbounded",
            "actual_concurrency_budget": 2,
            "target_count": 2,
            "completed_count": 2 - len(failures),
            "failed_count": len(failures),
            "max_queue_delay_ms": max(
                observation.queue_delay_ms for observation in ordered
            ),
            "target_duration_p75_ms": statistics.quantiles(
                [entry["duration_ms"] for entry in target_entries],
                n=4,
                method="inclusive",
            )[2],
            "first_result_ms": min(
                entry["duration_ms"] for entry in target_entries
            ),
            "total_duration_ms": (
                max(completions) - min(starts)
            ).total_seconds()
            * 1000,
            "completion_order": [0, 1],
        }
    else:
        scheduler = dict(scheduler_metrics)
        scheduler["completed_count"] = 2 - len(failures)
        scheduler["failed_count"] = len(failures)
        completion_order = scheduler.get("completion_order")
        if isinstance(completion_order, list) and all(
            isinstance(index, int) and 0 <= index < len(observations)
            for index in completion_order
        ):
            output_index_by_input = {
                input_index: ordered.index(observation)
                for input_index, observation in enumerate(observations)
            }
            scheduler["completion_order"] = [
                output_index_by_input[index]
                for index in completion_order
            ]
    return {
        "schema_version": COMPARE_SCHEMA_VERSION,
        "tool": "compare_remote",
        "observed_at": _utc_now(),
        "ok": complete,
        "code": "ok" if complete else "partial_comparison",
        "normalized_code": "ok" if complete else "partial_comparison",
        "returncode": 0 if complete else 1,
        "warnings": [],
        "error": "" if complete else "one or more targets did not complete cleanly",
        "mode": mode,
        "observation": {
            "window_start": min(starts).isoformat(),
            "window_end": max(completions).isoformat(),
            "start_skew_ms": start_skew_ms,
            "phases": phases,
        },
        "targets": target_entries,
        "scheduler": scheduler,
        "completeness": {
            "requested": 2,
            "completed": 2 - len(failures),
            "failed": len(failures),
        },
        "comparison": {
            "status": card["status"],
            "differences": differences,
            "diff_card": card,
            "capability_asymmetry": capability_asymmetry,
            "unsupported": unsupported,
            "target_local_failures": failures,
            "normalized_volatile_fields": _normalized_volatile_fields(),
            "candidate_comparisons": [],
            "value_groups": [],
        },
    }


def _pair_comparison(
    reference: TargetObservation,
    candidate: TargetObservation,
) -> dict[str, object]:
    differences: list[dict[str, object]] = []
    incomparable_paths: set[str] = set()
    if reference.result is not None and candidate.result is not None:
        differences = _diff_values(
            _normalize_for_diff(
                reference.result,
                incomparable_paths=incomparable_paths,
            ),
            _normalize_for_diff(
                candidate.result,
                incomparable_paths=incomparable_paths,
            ),
            path="$",
            left_role="reference",
            right_role="candidate",
        )
    reference_capabilities = _capabilities(reference.result)
    candidate_capabilities = _capabilities(candidate.result)
    names = sorted(set(reference_capabilities) | set(candidate_capabilities))
    quality_by_target = {
        reference.target_id: _quality_flags(reference.result),
        candidate.target_id: _quality_flags(candidate.result),
    }
    scope_signatures = (
        _scope_signature(reference.result),
        _scope_signature(candidate.result),
    )
    freshness_signatures = (
        _freshness_signature(reference.result),
        _freshness_signature(candidate.result),
    )
    card = _diff_card(
        mode="reference-candidate",
        differences=differences,
        incomparable_paths=incomparable_paths,
        quality_by_target=quality_by_target,
        scope_equal=(
            scope_signatures[0] == scope_signatures[1]
            if all(item is not None for item in scope_signatures)
            else None
        ),
        freshness_equal=(
            freshness_signatures[0] == freshness_signatures[1]
            if all(item is not None for item in freshness_signatures)
            else None
        ),
        failures=(
            []
            if reference.status == "ok" and candidate.status == "ok"
            else [{"code": "target_local_failure"}]
        ),
    )
    return {
        "reference_target_id": reference.target_id,
        "candidate_target_id": candidate.target_id,
        "status": card["status"],
        "differences": differences,
        "diff_card": card,
        "capability_asymmetry": [
            f"$.result.capabilities.{name}"
            for name in names
            if reference_capabilities.get(name, _MISSING)
            != candidate_capabilities.get(name, _MISSING)
        ],
        "unsupported": {
            "reference": [
                f"$.result.capabilities.{name}"
                for name, value in sorted(reference_capabilities.items())
                if value is False or value is None
            ],
            "candidate": [
                f"$.result.capabilities.{name}"
                for name, value in sorted(candidate_capabilities.items())
                if value is False or value is None
            ],
        },
    }


def _flatten_values(value: object, path: str = "$") -> dict[str, object]:
    if isinstance(value, dict):
        flattened: dict[str, object] = {}
        for key, item in value.items():
            flattened.update(_flatten_values(item, f"{path}.{key}"))
        return flattened
    if isinstance(value, list):
        identity = _stable_list_identity(value)
        if identity is None:
            return {
                path: {
                    "status": "incomparable",
                    "reason": "unidentified_list",
                    "item_count": len(value),
                }
            }
        identity_key, identified = identity
        flattened: dict[str, object] = {}
        for identity_value, item in identified.items():
            flattened.update(
                _flatten_values(
                    item,
                    f"{path}[{identity_key}={identity_value}]",
                )
            )
        return flattened
    return {path: value}


def _symmetric_value_groups(
    observations: list[TargetObservation],
    *,
    max_paths: int = 512,
) -> list[dict[str, object]]:
    flattened = {
        observation.target_id: _flatten_values(
            _normalize_for_diff(observation.result)
        )
        for observation in observations
        if observation.result is not None
    }
    paths = sorted(
        {
            path
            for target_values in flattened.values()
            for path in target_values
        }
    )
    groups: list[dict[str, object]] = []
    for path in paths[:max_paths]:
        by_value: dict[str, dict[str, object]] = {}
        for target_id, target_values in flattened.items():
            value = target_values.get(path, "<missing>")
            key = json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            )
            bucket = by_value.setdefault(
                key,
                {"value": value, "target_ids": []},
            )
            bucket["target_ids"].append(target_id)  # type: ignore[union-attr]
        if len(by_value) > 1:
            groups.append(
                {
                    "path": path,
                    "groups": list(by_value.values()),
                }
            )
    return groups


def build_multi_comparison(
    *,
    observations: list[TargetObservation],
    scheduler_metrics: Mapping[str, object],
) -> dict[str, object]:
    if len(observations) < 2:
        raise ValueError("multi-target comparison requires at least two observations")
    references = [item for item in observations if item.role == "reference"]
    mode = "reference-candidate" if references else "symmetric"
    if len(references) > 1:
        raise ValueError("multi-target comparison supports one reference target")
    starts = [_parse_time(item.started_at) for item in observations]
    completions = [_parse_time(item.completed_at) for item in observations]
    target_entries = [item.to_public_dict() for item in observations]
    failures = [
        {
            "role": entry["role"],
            "target_id": entry["target_id"],
            "code": entry["error_code"] or "target_local_failure",
            "error": entry["error"],
        }
        for entry in target_entries
        if entry["status"] == "failed"
    ]
    candidate_comparisons: list[dict[str, object]] = []
    value_groups: list[dict[str, object]] = []
    if references:
        reference = references[0]
        candidate_comparisons = [
            _pair_comparison(reference, candidate)
            for candidate in observations
            if candidate is not reference
        ]
    else:
        value_groups = _symmetric_value_groups(observations)

    card_differences: list[dict[str, object]] = []
    incomparable_paths: set[str] = set()
    if references:
        for comparison in candidate_comparisons:
            differences = comparison.get("differences")
            if isinstance(differences, list):
                card_differences.extend(
                    item for item in differences if isinstance(item, dict)
                )
            pair_card = comparison.get("diff_card")
            if isinstance(pair_card, Mapping):
                paths = pair_card.get("incomparable_paths", [])
                if isinstance(paths, list):
                    incomparable_paths.update(str(path) for path in paths)
    else:
        card_differences = [
            {"path": group.get("path", ""), "kind": "value-groups"}
            for group in value_groups
        ]
        for observation in observations:
            _normalize_for_diff(
                observation.result,
                incomparable_paths=incomparable_paths,
            )

    capability_values: dict[str, set[str]] = {}
    unsupported: dict[str, list[str]] = {}
    role_counts = {
        role: sum(item.role == role for item in observations)
        for role in {item.role for item in observations}
    }
    for observation in observations:
        label = (
            observation.role
            if role_counts[observation.role] == 1
            else observation.target_id
        )
        capabilities = _capabilities(observation.result)
        unsupported[label] = [
            f"$.result.capabilities.{name}"
            for name, value in sorted(capabilities.items())
            if value is False or value is None
        ]
        for name, value in capabilities.items():
            capability_values.setdefault(name, set()).add(
                json.dumps(value, sort_keys=True, default=str)
            )
    capability_asymmetry = [
        f"$.result.capabilities.{name}"
        for name, values in sorted(capability_values.items())
        if len(values) > 1
    ]

    common_phase_names: set[str] | None = None
    per_target_phases: dict[str, dict[str, str]] = {}
    for observation in observations:
        phases = _phase_starts(observation.result)
        per_target_phases[observation.target_id] = phases
        names = set(phases)
        common_phase_names = (
            names if common_phase_names is None else common_phase_names & names
        )
    phase_windows: dict[str, object] = {}
    for name in sorted(common_phase_names or set()):
        phase_starts = {
            observation.target_id: per_target_phases[observation.target_id][name]
            for observation in observations
        }
        parsed = [_parse_time(value) for value in phase_starts.values()]
        phase_windows[name] = {
            "starts": phase_starts,
            "start_skew_ms": (
                max(parsed) - min(parsed)
            ).total_seconds()
            * 1000,
        }

    quality_by_target = {
        observation.target_id: _quality_flags(observation.result)
        for observation in observations
    }
    scope_signatures = [_scope_signature(item.result) for item in observations]
    non_null_scopes = [item for item in scope_signatures if item is not None]
    scope_equal = (
        len(set(non_null_scopes)) == 1
        if len(non_null_scopes) == len(observations)
        else None
    )
    freshness_signatures = [
        _freshness_signature(item.result) for item in observations
    ]
    non_null_freshness = [
        item for item in freshness_signatures if item is not None
    ]
    freshness_equal = (
        len(set(non_null_freshness)) == 1
        if len(non_null_freshness) == len(observations)
        else None
    )
    card = _diff_card(
        mode=mode,
        differences=card_differences,
        incomparable_paths=incomparable_paths,
        quality_by_target=quality_by_target,
        scope_equal=scope_equal,
        freshness_equal=freshness_equal,
        failures=failures,
    )
    complete = card["status"] == "complete"
    scheduler = dict(scheduler_metrics)
    scheduler["completed_count"] = len(observations) - len(failures)
    scheduler["failed_count"] = len(failures)
    return {
        "schema_version": COMPARE_SCHEMA_VERSION,
        "tool": "compare_remote",
        "observed_at": _utc_now(),
        "ok": complete,
        "code": "ok" if complete else "partial_comparison",
        "normalized_code": "ok" if complete else "partial_comparison",
        "returncode": 0 if complete else 1,
        "warnings": [],
        "error": "" if complete else "one or more targets did not complete cleanly",
        "mode": mode,
        "observation": {
            "window_start": min(starts).isoformat(),
            "window_end": max(completions).isoformat(),
            "start_skew_ms": (
                max(starts) - min(starts)
            ).total_seconds()
            * 1000,
            "phases": phase_windows,
        },
        "targets": target_entries,
        "scheduler": scheduler,
        "completeness": {
            "requested": len(observations),
            "completed": len(observations) - len(failures),
            "failed": len(failures),
        },
        "comparison": {
            "status": card["status"],
            "differences": [],
            "diff_card": card,
            "capability_asymmetry": capability_asymmetry,
            "unsupported": unsupported,
            "target_local_failures": failures,
            "normalized_volatile_fields": _normalized_volatile_fields(),
            "candidate_comparisons": candidate_comparisons,
            "value_groups": value_groups,
        },
    }


def _run_scheduled_targets(
    *,
    requests: list[dict[str, object]],
    roles: list[str],
    target_ids: list[str],
    run_target: Callable[[Mapping[str, object], object], dict[str, object]],
    context: object,
    concurrency: str | int,
) -> tuple[list[TargetObservation], dict[str, object]]:
    from _target_runtime_adapter import _load_runtime_module

    runtime = _load_runtime_module()
    scheduled = runtime.FairTargetScheduler(concurrency=concurrency).run(
        requests,
        run_target,
        context=context,
    )
    observations: list[TargetObservation] = []
    for index, scheduled_result in enumerate(scheduled.results):
        if scheduled_result.ok:
            if not isinstance(scheduled_result.value, dict):
                observations.append(
                    TargetObservation.failure(
                        role=roles[index],
                        target_id=target_ids[index],
                        started_at=scheduled_result.started_at,
                        completed_at=scheduled_result.completed_at,
                        error_code="InvalidTargetResult",
                        error="target callback did not return a Debug v1 object",
                        queue_delay_ms=scheduled_result.queue_delay_ms,
                    )
                )
            else:
                try:
                    observation = TargetObservation.success(
                        role=roles[index],
                        target_id=target_ids[index],
                        started_at=scheduled_result.started_at,
                        completed_at=scheduled_result.completed_at,
                        result=scheduled_result.value,
                        queue_delay_ms=scheduled_result.queue_delay_ms,
                    )
                except Exception as exc:
                    observation = TargetObservation.failure(
                        role=roles[index],
                        target_id=target_ids[index],
                        started_at=scheduled_result.started_at,
                        completed_at=scheduled_result.completed_at,
                        error_code=type(exc).__name__,
                        error=str(exc),
                        queue_delay_ms=scheduled_result.queue_delay_ms,
                    )
                observations.append(observation)
        else:
            observations.append(
                TargetObservation.failure(
                    role=roles[index],
                    target_id=target_ids[index],
                    started_at=scheduled_result.started_at,
                    completed_at=scheduled_result.completed_at,
                    error_code=scheduled_result.error_code,
                    error=scheduled_result.error,
                    queue_delay_ms=scheduled_result.queue_delay_ms,
                )
            )
    return observations, dict(scheduled.metrics)


def run_multi_target_comparison(
    *,
    targets: list[Mapping[str, object]],
    run_target: Callable[[Mapping[str, object], object], dict[str, object]],
    context: object,
    concurrency: str | int = "auto",
) -> dict[str, object]:
    if len(targets) < 2:
        raise ValueError("multi-target comparison requires at least two targets")
    from _target_runtime_adapter import _load_runtime_module

    identities = _load_runtime_module().comparison_target_identities(targets)
    roles = [role for role, _target_id in identities]

    requests: list[dict[str, object]] = []
    target_ids: list[str] = []
    for index, target in enumerate(targets):
        request = dict(target)
        request.pop("role", None)
        request.pop("target_id", None)
        target_ids.append(identities[index][1])
        requests.append(request)

    observations, scheduler_metrics = _run_scheduled_targets(
        requests=requests,
        roles=roles,
        target_ids=target_ids,
        run_target=run_target,
        context=context,
        concurrency=concurrency,
    )
    return build_multi_comparison(
        observations=observations,
        scheduler_metrics=scheduler_metrics,
    )


def run_dual_target_comparison(
    *,
    targets: list[Mapping[str, object]],
    run_target: Callable[[Mapping[str, object], object], dict[str, object]],
    context: object,
    concurrency: str | int = "auto",
) -> dict[str, object]:
    if len(targets) != 2:
        raise ValueError("dual comparison requires exactly two targets")
    from _target_runtime_adapter import _load_runtime_module

    identities = _load_runtime_module().comparison_target_identities(targets)
    roles = [role for role, _target_id in identities]
    requests: list[dict[str, object]] = []
    target_ids: list[str] = []
    for index, target in enumerate(targets):
        request = dict(target)
        request.pop("role", None)
        request.pop("target_id", None)
        target_ids.append(identities[index][1])
        requests.append(request)
    observations, scheduler_metrics = _run_scheduled_targets(
        requests=requests,
        roles=roles,
        target_ids=target_ids,
        run_target=run_target,
        context=context,
        concurrency=concurrency,
    )
    return build_dual_comparison(
        observations=observations,
        scheduler_metrics=scheduler_metrics,
    )
