"""Finite Agent MCP input compatibility and current-Turn identity binding.

This Adapter never chooses an Action, target, intent, response, or authorization.
The Runtime decoder remains the final authority for every normalized request.
"""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
import json
import math
import re
import threading


_ALIASES = {
    "observe": {
        "target_ip": "target",
        "bmc_ip": "target",
        "selector": "selectors",
    },
    "execute": {
        "action_type": "kind",
        "actionKind": "kind",
        "runId": "run_id",
        "gateId": "gate_id",
        "gateVersion": "gate_version",
        "schemaDigest": "schema_digest",
        "submissionId": "submission_id",
        "target_ip": "target",
        "bmc_ip": "target",
        "deliveryStrategy": "delivery_strategy",
        "entryOperation": "entry_operation",
        "entryArguments": "entry_arguments",
    },
}
_JSON_ARRAY_FIELDS = frozenset({"selectors", "targets"})
_JSON_OBJECT_FIELDS = frozenset({"freshness", "response", "entry_arguments"})
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z", re.ASCII)
_INTEGER = re.compile(r"(?:0|[1-9][0-9]*)\Z", re.ASCII)
_MAX_TURN_BINDINGS = 64


def _unique_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _finite_json_float(value: str) -> float:
    selected = float(value)
    if not math.isfinite(selected):
        raise ValueError("non-finite JSON number")
    return selected


def _typed_json(value: object, expected: type) -> object:
    if not isinstance(value, str):
        return value
    try:
        parsed = json.loads(
            value,
            object_pairs_hook=_unique_json_pairs,
            parse_constant=_reject_json_constant,
            parse_float=_finite_json_float,
        )
    except (ValueError, TypeError, RecursionError, OverflowError):
        return value
    return parsed if isinstance(parsed, expected) else value


def _canonical_value(field: str, value: object, *, alias: str = "") -> object:
    if field == "selectors" and alias == "selector":
        selected = _typed_json(value, dict)
        return [selected] if isinstance(selected, Mapping) else value
    if field in _JSON_ARRAY_FIELDS:
        return _typed_json(value, list)
    if field in _JSON_OBJECT_FIELDS:
        return _typed_json(value, dict)
    if field in {"deadline", "gate_version", "max_age_seconds"}:
        if not isinstance(value, str) or len(value) > 32:
            return value
        selected = value.strip()
        pattern = _DECIMAL if field == "deadline" else _INTEGER
        if pattern.fullmatch(selected) is None:
            return value
        return (
            float(selected) if "." in selected else int(selected)
        )
    if field == "kind" and isinstance(value, str):
        selected = value.strip().lower()
        return selected if selected in {"start", "respond", "resume", "control"} else value
    return value


def _same_typed_value(left: object, right: object) -> bool:
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return left.keys() == right.keys() and all(
            _same_typed_value(left[key], right[key]) for key in left
        )
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _same_typed_value(first, second)
            for first, second in zip(left, right, strict=True)
        )
    return type(left) is type(right) and left == right


def normalize_agent_arguments(
    operation: str, arguments: Mapping[str, object]
) -> dict[str, object]:
    """Canonicalize only documented aliases and syntax, preserving all scope."""

    aliases = _ALIASES.get(operation, {})
    canonical: dict[str, object] = {}
    for source, value in arguments.items():
        destination = aliases.get(source, source)
        selected = _canonical_value(destination, value, alias=source)
        if destination in canonical:
            if not _same_typed_value(canonical[destination], selected):
                raise ValueError(
                    f"conflicting values for {destination}: {source} disagrees"
                )
            continue
        canonical[destination] = selected
    if operation == "observe" and isinstance(canonical.get("freshness"), Mapping):
        freshness = dict(canonical["freshness"])
        if "max_age_seconds" in freshness:
            freshness["max_age_seconds"] = _canonical_value(
                "max_age_seconds", freshness["max_age_seconds"]
            )
        canonical["freshness"] = freshness
    return canonical


@dataclass(frozen=True)
class _TurnBinding:
    run_id: str
    state: str
    gate_id: str = ""
    gate_version: int = 0
    schema_digest: str = ""


class AgentInputAdapter:
    """Keep the last active Turn binding per task, never a second Run authority."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._turns: OrderedDict[str, _TurnBinding] = OrderedDict()

    def normalize(
        self,
        operation: str,
        arguments: Mapping[str, object],
        *,
        task_id: str,
    ) -> dict[str, object]:
        canonical = normalize_agent_arguments(operation, arguments)
        if operation != "execute" or canonical.get("kind") == "start":
            return canonical
        with self._lock:
            binding = self._turns.get(task_id)
        if binding is None or canonical.get("kind") not in {"respond", "resume", "control"}:
            return canonical
        if "run_id" not in canonical:
            canonical["run_id"] = binding.run_id
        if (
            canonical.get("kind") != "respond"
            or canonical.get("run_id") != binding.run_id
            or binding.state != "waiting_response"
            or not all((binding.gate_id, binding.gate_version, binding.schema_digest))
        ):
            return canonical
        gate = {
            "gate_id": binding.gate_id,
            "gate_version": binding.gate_version,
            "schema_digest": binding.schema_digest,
        }
        # Bind the Gate as a unit. A partially supplied binding stays a strict
        # decoder error, even when each supplied field matches the current Turn.
        if any(field in canonical for field in gate):
            return canonical
        for field, value in gate.items():
            canonical.setdefault(field, value)
        return canonical

    def remember(self, task_id: str, result: Mapping[str, object]) -> None:
        state = result.get("state")
        run_id = result.get("run_id")
        binding = None
        if isinstance(run_id, str) and run_id and state in {
            "waiting_response", "running", "incident"
        }:
            gate = result.get("gate")
            phase_gate = gate if isinstance(gate, Mapping) and gate.get("kind") == "phase" else {}
            gate_id = phase_gate.get("gate_id")
            gate_version = phase_gate.get("gate_version")
            schema_digest = phase_gate.get("schema_digest")
            binding = _TurnBinding(
                run_id=run_id,
                state=str(state),
                gate_id=gate_id if isinstance(gate_id, str) else "",
                gate_version=(
                    gate_version
                    if isinstance(gate_version, int) and not isinstance(gate_version, bool)
                    else 0
                ),
                schema_digest=schema_digest if isinstance(schema_digest, str) else "",
            )
        with self._lock:
            self._turns.pop(task_id, None)
            if binding is not None:
                self._turns[task_id] = binding
                while len(self._turns) > _MAX_TURN_BINDINGS:
                    self._turns.popitem(last=False)

    def forget(self, task_id: str) -> None:
        with self._lock:
            self._turns.pop(task_id, None)

    def clear(self) -> None:
        with self._lock:
            self._turns.clear()
