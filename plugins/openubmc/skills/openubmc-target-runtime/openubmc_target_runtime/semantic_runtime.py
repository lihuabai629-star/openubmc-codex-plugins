"""Typed semantic contracts shared by the Agent Gateway and Runtime Core."""

from __future__ import annotations

from .effect_activity import operation_activity

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
import hashlib
import json
import math
import re
from typing import Protocol, TypeAlias

from .capabilities import CAPABILITY_ALIASES
from .contracts import RUNTIME_API_VERSION
from .comparison_targets import comparison_target_identities
from .diagnostic_receipt import (
    DIAGNOSTIC_RECEIPT_MAX_STORED_RESULTS,
    DiagnosticReceipt,
    latest_diagnostic_receipt,
)
from .diagnostic_request import DiagnosticRequestPlan
from .diagnosis_record import DiagnosisRecord, accepted_diagnosis_record
from .incident import incident_recovery_policy
from .mdb_query import MDB_QUERY_CORRECTION, is_read_only_mdb_query


SEMANTIC_RUNTIME_SCHEMA = f"{RUNTIME_API_VERSION}/semantic-runtime-v1"
OBSERVATION_REF_SCHEMA = f"{SEMANTIC_RUNTIME_SCHEMA}/observation-ref"
ARTIFACT_REF_SCHEMA = f"{SEMANTIC_RUNTIME_SCHEMA}/artifact-ref"
AGENT_REQUEST_MAX_BYTES = 256 * 1024
AGENT_REQUEST_MAX_DEPTH = 32
AGENT_REQUEST_MAX_CONTAINER_ITEMS = 1024
AGENT_REQUEST_MAX_NODES = 8192
AGENT_REQUEST_MAX_STRING_BYTES = 128 * 1024
AGENT_REQUEST_MAX_KEY_BYTES = 256
GATE_SCHEMA_PROJECTION_TARGET_BYTES = 4 * 1024
# Compatibility name for consumers that still report the historical target.
# Gate schemas may exceed this value; it is not a Runtime control-flow maximum.
GATE_SCHEMA_MAX_BYTES = GATE_SCHEMA_PROJECTION_TARGET_BYTES
# Internal collection partitions target this size. It is not an Agent request or
# workflow-completion limit; individually valid selectors remain accepted.
OBSERVATION_PARTITION_TARGET_BYTES = 2 * 1024
# Compatibility name retained for Operator telemetry and older imports.
OBSERVATION_SCOPE_MAX_BYTES = OBSERVATION_PARTITION_TARGET_BYTES
TARGET_MAX_BYTES = 512
SELECTOR_ID_MAX_BYTES = 64
SELECTOR_MAX_ITEMS = 16
CAPABILITY_NAME_MAX_BYTES = 64
CAPABILITY_MAX_ITEMS = 16
MDB_QUERY_MAX_BYTES = 1024
MDB_QUERY_MAX_ITEMS = 32

_CAPABILITY_ALIASES = frozenset(CAPABILITY_ALIASES)
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RUNTIME_OWNED_ENTRY_ARGUMENTS = frozenset(
    {
        "ip",
        "target",
        "targets",
        "target_id",
        "target_role",
        "role",
        "intent",
        "entry_domain",
        "entry_operation",
        "final_purpose",
        "purpose",
        "delivery_strategy",
        "workflow",
        "case_id",
        "authorized_exceptions",
        "allow_insecure_tls",
        "observation_ref",
        "observation_receipt",
        "change_boundary",
        "include_closeout_bundle",
        "max_steps",
        "deadline",
        "expected_revision",
        "idempotency_key",
        "command_id",
        "input_digest",
        "run_id",
        "gate_id",
        "gate_version",
        "schema_digest",
        "submission_id",
        "incident_id",
        "operation_id",
        "effect_id",
        "target_epoch",
        "minimum_target_epoch",
        "authorization",
        "authorization_policy",
        "workflow_definition",
        "workflow_revision",
        "recovery_mode",
        "recovery_decision",
        "actor",
        "submitted_at",
    }
)


def is_safe_runtime_id(value: object) -> bool:
    return _SAFE_ID.fullmatch(_text(value)) is not None


def is_sha256_digest(value: object) -> bool:
    selected = _text(value).removeprefix("sha256:").lower()
    return _SHA256.fullmatch(selected) is not None

EXECUTE_ACTION_FIELD_TYPES = {
    "start": {
        "kind": "string",
        "target": "string",
        "targets": "array",
        "intent": "string",
        "entry_operation": "string",
        "entry_arguments": "object",
        "purpose": "string",
        "delivery_strategy": "string",
        "observation_ref": "object",
        "deadline": "number",
    },
    "respond": {
        "kind": "string",
        "run_id": "string",
        "gate_id": "string",
        "gate_version": "integer",
        "schema_digest": "string",
        "submission_id": "string",
        "response": "object",
        "deadline": "number",
    },
    "resume": {
        "kind": "string",
        "run_id": "string",
        "deadline": "number",
    },
    "control": {
        "kind": "string",
        "run_id": "string",
        "command": "string",
        "incident_id": "string",
        "gate_id": "string",
        "gate_version": "integer",
        "schema_digest": "string",
        "submission_id": "string",
        "deadline": "number",
    },
}
EXECUTE_ACTION_FIELDS = {
    kind: frozenset(fields) for kind, fields in EXECUTE_ACTION_FIELD_TYPES.items()
}
EXECUTE_ACTION_REQUIRED_FIELDS = {
    "start": frozenset({"kind", "intent"}),
    "respond": frozenset(
        {
            "kind",
            "run_id",
            "gate_id",
            "gate_version",
            "schema_digest",
            "response",
        }
    ),
    "resume": frozenset({"kind", "run_id"}),
    "control": frozenset({"kind", "run_id", "command"}),
}
_RUNTIME_OWNED_ACTION_FIELDS = frozenset(
    {
        "authorization",
        "authorization_policy",
        "case_id",
        "command_id",
        "effect_id",
        "expected_revision",
        "input_digest",
        "operation_id",
        "recovery_decision",
        "recovery_mode",
        "target_epoch",
        "workflow",
        "workflow_definition",
        "workflow_revision",
    }
)


class SemanticRuntimeError(ValueError):
    """Base error for the typed semantic Runtime interface."""


class AgentGatewayError(SemanticRuntimeError):
    """Raised when an Agent request cannot be decoded safely."""


class AgentBudgetError(AgentGatewayError):
    """Raised when an Agent request exceeds a hard transport input budget."""


class ScopeViolation(AgentGatewayError):
    """Raised when an observation requests an undeclared evidence surface."""


class PreflightReason(str, Enum):
    """Typed reason used by AgentGateway to project actionable guidance."""

    UNDECLARED_FIELD = "undeclared_field"
    REQUIRED_VALUE = "required_value"
    WRONG_TYPE = "wrong_type"
    VALUE_TOO_LONG = "value_too_long"
    TOO_MANY_ITEMS = "too_many_items"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    UNSUPPORTED_SELECTOR_KIND = "unsupported_selector_kind"
    MDB_GRAMMAR = "mdb_grammar"
    DUPLICATE_SELECTOR_ID = "duplicate_selector_id"
    FRESHNESS_MODE = "freshness_mode"
    LIVE_MAX_AGE = "live_max_age"
    DEADLINE = "deadline"
    RUNTIME_OWNED_FIELD = "runtime_owned_field"
    RUN_ID_REQUIRED = "run_id_required"
    RECONCILE_PRECONDITION = "reconcile_precondition"
    GATE_BINDING = "gate_binding"
    ARTIFACT_REQUIRED = "artifact_required"
    ARTIFACT_BINDING = "artifact_binding"


@dataclass(frozen=True)
class PreflightContext:
    """Typed facts needed to project a transport-neutral correction."""

    action_kind: str = ""
    run_id: str = ""
    target: str = ""
    targets: tuple[Mapping[str, object], ...] = ()
    intent: str = ""
    purpose: str = ""
    delivery_strategy: str = ""
    observation_ref: Mapping[str, object] = field(default_factory=dict)
    command: str = ""
    incident_id: str = ""
    entry_operation: str = ""
    entry_arguments: Mapping[str, object] = field(default_factory=dict)
    gate_id: str = ""
    gate_version: int = 0
    schema_digest: str = ""
    submission_id: str = ""
    response: Mapping[str, object] = field(default_factory=dict)
    artifact_kind: str = ""
    version_required: bool = False
    required_payload_fields: tuple[str, ...] = ()
    terminal: bool = False


@dataclass(frozen=True)
class PreflightDetail:
    """Runtime validation facts without Agent-facing prose or examples."""

    reason: PreflightReason
    field: str
    supported: tuple[str, ...] = ()
    limit: object | None = None
    context: PreflightContext = field(default_factory=PreflightContext)


class AgentPreflightError(ScopeViolation):
    """Actionable Agent-input rejection raised before target or Run work."""

    def __init__(
        self,
        message: str,
        *,
        reason: PreflightReason,
        field: str,
        supported: Sequence[str] = (),
        limit: object | None = None,
        context: PreflightContext | None = None,
    ) -> None:
        super().__init__(message)
        self.detail = PreflightDetail(
            reason=reason,
            field=field,
            supported=tuple(str(item) for item in supported),
            limit=limit,
            context=context or PreflightContext(),
        )


class ReferenceViolation(SemanticRuntimeError):
    """Raised when an ObservationRef or ArtifactRef is malformed."""


class GateConflict(SemanticRuntimeError):
    """Raised when a Gate submission targets stale or unrelated Gate state."""


class GatePreflightError(GateConflict, ReferenceViolation):
    """Actionable Gate-input rejection raised before transitions or Effects."""

    def __init__(
        self,
        message: str,
        *,
        reason: PreflightReason,
        field: str,
        limit: object | None = None,
        context: PreflightContext | None = None,
    ) -> None:
        super().__init__(message)
        self.detail = PreflightDetail(
            reason=reason,
            field=field,
            limit=limit,
            context=context or PreflightContext(),
        )


class CommandConflict(SemanticRuntimeError):
    """Raised when one durable submission identity is reused with new input."""


class AssuranceUnavailable(SemanticRuntimeError):
    """Raised when no scope-preserving assurance Adapter is available."""


def json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def fingerprint(value: object) -> str:
    return hashlib.sha256(json_bytes(value)).hexdigest()


def bounded_request(value: Mapping[str, object]) -> None:
    pending: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > AGENT_REQUEST_MAX_NODES:
            raise AgentBudgetError("Agent request exceeds the 8192-node input budget")
        if isinstance(current, str):
            if len(current.encode("utf-8")) > AGENT_REQUEST_MAX_STRING_BYTES:
                raise AgentBudgetError(
                    "Agent request string exceeds the 128 KiB input budget"
                )
            continue
        if isinstance(current, Mapping):
            if depth > AGENT_REQUEST_MAX_DEPTH:
                raise AgentBudgetError(
                    "Agent request exceeds the 32-level nesting budget"
                )
            if len(current) > AGENT_REQUEST_MAX_CONTAINER_ITEMS:
                raise AgentBudgetError(
                    "Agent request object exceeds the 1024-field input budget"
                )
            for key, item in current.items():
                if not isinstance(key, str):
                    raise AgentGatewayError("Agent request object keys must be strings")
                if len(key.encode("utf-8")) > AGENT_REQUEST_MAX_KEY_BYTES:
                    raise AgentBudgetError(
                        "Agent request object key exceeds the 256-byte input budget"
                    )
                pending.append((item, depth + 1))
            continue
        if isinstance(current, (list, tuple)):
            if depth > AGENT_REQUEST_MAX_DEPTH:
                raise AgentBudgetError(
                    "Agent request exceeds the 32-level nesting budget"
                )
            if len(current) > AGENT_REQUEST_MAX_CONTAINER_ITEMS:
                raise AgentBudgetError(
                    "Agent request array exceeds the 1024-item input budget"
                )
            pending.extend((item, depth + 1) for item in current)
    if len(json_bytes(value)) > AGENT_REQUEST_MAX_BYTES:
        raise AgentBudgetError("Agent request exceeds the 256 KiB input budget")


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _text(value: object) -> str:
    return str(value).strip() if value is not None else ""


@dataclass(frozen=True)
class ObservationSelector:
    selector_id: str
    kind: str
    names: tuple[str, ...] = ()
    queries: tuple[str, ...] = ()

    @classmethod
    def from_value(
        cls, value: Mapping[str, object], index: int
    ) -> "ObservationSelector":
        unexpected = set(value) - {"id", "kind", "names", "queries"}
        if unexpected:
            field = sorted(unexpected)[0]
            raise AgentPreflightError(
                f"selectors[{index - 1}].{field} is undeclared; selector contains "
                "undeclared fields: " + ", ".join(sorted(unexpected)),
                reason=PreflightReason.UNDECLARED_FIELD,
                field=f"selectors[{index - 1}].{field}",
                limit={"allowed_fields": ["id", "kind", "names", "queries"]},
            )
        raw_selector_id = value.get("id")
        if raw_selector_id is not None and not isinstance(raw_selector_id, str):
            raise AgentPreflightError(
                f"selectors[{index - 1}].id must be a string",
                reason=PreflightReason.WRONG_TYPE,
                field=f"selectors[{index - 1}].id",
                limit={"type": "string"},
            )
        raw_kind = value.get("kind")
        if not isinstance(raw_kind, str):
            raise AgentPreflightError(
                f"selectors[{index - 1}].kind must be a string",
                reason=PreflightReason.WRONG_TYPE,
                field=f"selectors[{index - 1}].kind",
                limit={"type": "string"},
            )
        kind = _text(value.get("kind")).lower()
        selector_id = _text(value.get("id")) or f"selector-{index}"
        if len(selector_id.encode("utf-8")) > SELECTOR_ID_MAX_BYTES:
            raise AgentPreflightError(
                f"selectors[{index - 1}].id exceeds the 64-byte UTF-8 limit",
                reason=PreflightReason.VALUE_TOO_LONG,
                field=f"selectors[{index - 1}].id",
                limit={"unit": "UTF-8 bytes", "maximum": SELECTOR_ID_MAX_BYTES},
            )
        if kind == "systemd":
            from .systemd_contract import validate_systemd_names
            try:
                if "queries" in value or not isinstance(value.get("names"), list):
                    raise ValueError('systemd requires names and cannot contain queries')
                validate_systemd_names(value.get("names"))
            except ValueError as error:
                raise AgentPreflightError(
                    str(error), field=f"selectors[{index - 1}].names",
                ) from None
            return cls(selector_id=selector_id, kind=kind, names=tuple(value["names"]))
        if kind == "capability":
            if "queries" in value:
                raise AgentPreflightError(
                    "capability selector cannot contain queries",
                    reason=PreflightReason.UNDECLARED_FIELD,
                    field=f"selectors[{index - 1}].queries",
                    limit={"allowed_fields": ["id", "kind", "names"]},
                )
            raw_names = value.get("names", [])
            if not isinstance(raw_names, list) or not raw_names:
                raise AgentPreflightError(
                    "capability selector requires a non-empty names array",
                    reason=PreflightReason.REQUIRED_VALUE,
                    field=f"selectors[{index - 1}].names",
                    limit={"minimum_items": 1, "maximum_items": CAPABILITY_MAX_ITEMS},
                )
            if len(raw_names) > CAPABILITY_MAX_ITEMS:
                raise AgentPreflightError(
                    "capability selector exceeds the 16-name limit",
                    reason=PreflightReason.TOO_MANY_ITEMS,
                    field=f"selectors[{index - 1}].names",
                    limit={"maximum_items": CAPABILITY_MAX_ITEMS},
                )
            if not all(isinstance(item, str) and item.strip() for item in raw_names):
                name_index = next(
                    item_index
                    for item_index, item in enumerate(raw_names)
                    if not isinstance(item, str) or not item.strip()
                )
                raise AgentPreflightError(
                    "capability names must be non-empty strings",
                    reason=PreflightReason.WRONG_TYPE,
                    field=f"selectors[{index - 1}].names[{name_index}]",
                    limit={"type": "non-empty string"},
                )
            if any(
                len(item.strip().encode("utf-8")) > CAPABILITY_NAME_MAX_BYTES
                for item in raw_names
            ):
                name_index = next(
                    item_index
                    for item_index, item in enumerate(raw_names)
                    if len(item.strip().encode("utf-8")) > CAPABILITY_NAME_MAX_BYTES
                )
                raise AgentPreflightError(
                    "capability name exceeds the 64-byte limit",
                    reason=PreflightReason.VALUE_TOO_LONG,
                    field=f"selectors[{index - 1}].names[{name_index}]",
                    limit={"unit": "UTF-8 bytes", "maximum": CAPABILITY_NAME_MAX_BYTES},
                )
            names = tuple(dict.fromkeys(_text(item).lower() for item in raw_names))
            unsupported = [
                (name_index, _text(item).lower())
                for name_index, item in enumerate(raw_names)
                if _text(item).lower() not in _CAPABILITY_ALIASES
            ]
            if unsupported:
                name_index, unsupported_name = unsupported[0]
                supported = tuple(sorted(_CAPABILITY_ALIASES))
                raise AgentPreflightError(
                    f"selectors[{index - 1}].names[{name_index}] has invalid capability "
                    f"{unsupported_name!r}; supported canonical names: "
                    + ", ".join(supported),
                    reason=PreflightReason.UNSUPPORTED_CAPABILITY,
                    field=f"selectors[{index - 1}].names[{name_index}]",
                    supported=supported,
                )
            return cls(selector_id=selector_id, kind=kind, names=names)
        if kind == "mdb":
            if "names" in value:
                raise AgentPreflightError(
                    "mdb selector cannot contain names",
                    reason=PreflightReason.UNDECLARED_FIELD,
                    field=f"selectors[{index - 1}].names",
                    limit={"allowed_fields": ["id", "kind", "queries"]},
                )
            raw_queries = value.get("queries", [])
            if not isinstance(raw_queries, list) or not raw_queries:
                raise AgentPreflightError(
                    "mdb selector requires a non-empty queries array",
                    reason=PreflightReason.REQUIRED_VALUE,
                    field=f"selectors[{index - 1}].queries",
                    limit={"minimum_items": 1, "maximum_items": MDB_QUERY_MAX_ITEMS},
                )
            if len(raw_queries) > MDB_QUERY_MAX_ITEMS:
                raise AgentPreflightError(
                    "mdb selector exceeds the 32-query limit",
                    reason=PreflightReason.TOO_MANY_ITEMS,
                    field=f"selectors[{index - 1}].queries",
                    limit={"maximum_items": MDB_QUERY_MAX_ITEMS},
                )
            if not all(isinstance(item, str) for item in raw_queries):
                query_index = next(
                    item_index
                    for item_index, item in enumerate(raw_queries)
                    if not isinstance(item, str)
                )
                raise AgentPreflightError(
                    "mdb queries must be strings",
                    reason=PreflightReason.WRONG_TYPE,
                    field=f"selectors[{index - 1}].queries[{query_index}]",
                    limit={"type": "string"},
                )
            queries = tuple(_text(item) for item in raw_queries)
            if any(not query for query in queries):
                query_index = next(
                    item_index for item_index, query in enumerate(queries) if not query
                )
                raise AgentPreflightError(
                    "mdb queries must not be empty",
                    reason=PreflightReason.REQUIRED_VALUE,
                    field=f"selectors[{index - 1}].queries[{query_index}]",
                    limit={"type": "non-empty string"},
                )
            if any(
                len(query.encode("utf-8")) > MDB_QUERY_MAX_BYTES
                for query in queries
            ):
                query_index = next(
                    item_index
                    for item_index, query in enumerate(queries)
                    if len(query.encode("utf-8")) > MDB_QUERY_MAX_BYTES
                )
                raise AgentPreflightError(
                    f"selectors[{index - 1}].queries[{query_index}] exceeds "
                    f"the {MDB_QUERY_MAX_BYTES}-byte UTF-8 limit",
                    reason=PreflightReason.VALUE_TOO_LONG,
                    field=f"selectors[{index - 1}].queries[{query_index}]",
                    limit={
                        "unit": "UTF-8 bytes",
                        "maximum": MDB_QUERY_MAX_BYTES,
                    },
                )
            for query_index, query in enumerate(queries, start=1):
                parts = query.split()
                if not is_read_only_mdb_query(parts):
                    raise AgentPreflightError(
                        f"invalid MDB query #{query_index} at "
                        f"selectors[{index - 1}].queries[{query_index - 1}] "
                        f"{query!r}; {MDB_QUERY_CORRECTION}",
                        reason=PreflightReason.MDB_GRAMMAR,
                        field=(
                            f"selectors[{index - 1}].queries[{query_index - 1}]"
                        ),
                        limit={
                            "grammar": "read-only mdbctl",
                            "maximum_queries": MDB_QUERY_MAX_ITEMS,
                        },
                    )
            return cls(selector_id=selector_id, kind=kind, queries=queries)
        supported = ("capability", "mdb", "systemd")
        raise AgentPreflightError(
            f"selectors[{index - 1}].kind has unsupported selector kind "
            f"{kind or '<empty>'!r}; supported kinds: " + ", ".join(supported),
            reason=PreflightReason.UNSUPPORTED_SELECTOR_KIND,
            field=f"selectors[{index - 1}].kind",
            supported=supported,
        )

    def to_public_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"id": self.selector_id, "kind": self.kind}
        if self.names:
            result["names"] = list(self.names)
        if self.queries:
            result["queries"] = list(self.queries)
        return result

    @property
    def values(self) -> tuple[str, ...]:
        """Return the exact selected values independent of selector kind."""

        return self.names or self.queries

    @property
    def mdb_queries(self) -> tuple[str, ...]:
        """Return MDB queries, or an empty tuple for another selector kind."""

        return self.queries

    def with_values(self, values: tuple[str, ...]) -> "ObservationSelector":
        """Return the same selector identity narrowed to the supplied values."""

        return ObservationSelector(
            selector_id=self.selector_id,
            kind=self.kind,
            names=values if self.names else (),
            queries=values if self.queries else (),
        )

    def has_same_identity(self, other: "ObservationSelector") -> bool:
        return self.selector_id == other.selector_id and self.kind == other.kind


@dataclass(frozen=True)
class ObservationQuery:
    """One immutable, exact, read-only observation scope."""

    target: str
    selectors: tuple[ObservationSelector, ...]
    freshness_mode: str = "live"
    max_age_seconds: int = 0
    deadline: float = 180.0

    @classmethod
    def from_query(cls, query: Mapping[str, object]) -> "ObservationQuery":
        bounded_request(query)
        unexpected = set(query) - {
            "target",
            "selectors",
            "freshness",
            "deadline",
        }
        if unexpected:
            field = sorted(unexpected)[0]
            raise AgentPreflightError(
                f"{field} is unexpected; query contains undeclared fields: "
                + ", ".join(sorted(unexpected)),
                reason=PreflightReason.UNDECLARED_FIELD,
                field=field,
                limit={"allowed_fields": ["target", "selectors", "freshness", "deadline"]},
            )
        raw_target = query.get("target")
        if not isinstance(raw_target, str):
            raise AgentPreflightError(
                "target must be a string",
                reason=PreflightReason.WRONG_TYPE,
                field="target",
                limit={"type": "non-empty string"},
            )
        target = _text(query.get("target"))
        if not target:
            raise AgentPreflightError(
                "target is required",
                reason=PreflightReason.REQUIRED_VALUE,
                field="target",
                limit={"type": "non-empty string"},
            )
        if len(target.encode("utf-8")) > TARGET_MAX_BYTES:
            raise AgentPreflightError(
                "target exceeds the 512-byte limit",
                reason=PreflightReason.VALUE_TOO_LONG,
                field="target",
                limit={"unit": "UTF-8 bytes", "maximum": TARGET_MAX_BYTES},
            )
        raw_selectors = query.get("selectors")
        if not isinstance(raw_selectors, list) or not raw_selectors:
            raise AgentPreflightError(
                "selectors must be a non-empty array",
                reason=PreflightReason.REQUIRED_VALUE,
                field="selectors",
                limit={"minimum_items": 1, "maximum_items": SELECTOR_MAX_ITEMS},
            )
        if len(raw_selectors) > SELECTOR_MAX_ITEMS:
            raise AgentPreflightError(
                "selectors exceed the 16-item limit",
                reason=PreflightReason.TOO_MANY_ITEMS,
                field="selectors",
                limit={"maximum_items": SELECTOR_MAX_ITEMS},
            )
        invalid_selector_index = next(
            (
                item_index
                for item_index, value in enumerate(raw_selectors)
                if not isinstance(value, Mapping)
            ),
            None,
        )
        if invalid_selector_index is not None:
            raise AgentPreflightError(
                f"selectors[{invalid_selector_index}] must be an object",
                reason=PreflightReason.WRONG_TYPE,
                field=f"selectors[{invalid_selector_index}]",
                limit={"type": "object"},
            )
        selectors = tuple(
            ObservationSelector.from_value(_mapping(value), index)
            for index, value in enumerate(raw_selectors, start=1)
        )
        if sum(selector.kind == "systemd" for selector in selectors) > 1:
            raise AgentPreflightError(
                "combine service IDs in one systemd selector per observation",
                reason=PreflightReason.TOO_MANY_ITEMS, field="selectors",
                limit={"maximum_systemd_selectors": 1},
            )
        selector_ids = [selector.selector_id for selector in selectors]
        if len(set(selector_ids)) != len(selector_ids):
            duplicate_index = next(
                item_index
                for item_index, selector_id in enumerate(selector_ids)
                if selector_id in selector_ids[:item_index]
            )
            raise AgentPreflightError(
                "selector ids must be unique",
                reason=PreflightReason.DUPLICATE_SELECTOR_ID,
                field=f"selectors[{duplicate_index}].id",
                limit={"constraint": "unique within the observe request"},
            )
        raw_freshness = query.get("freshness", {})
        if not isinstance(raw_freshness, Mapping):
            raise AgentPreflightError(
                "freshness must be an object",
                reason=PreflightReason.WRONG_TYPE,
                field="freshness",
                limit={"type": "object"},
            )
        freshness = _mapping(raw_freshness)
        if set(freshness) - {"mode", "max_age_seconds"}:
            field = sorted(set(freshness) - {"mode", "max_age_seconds"})[0]
            raise AgentPreflightError(
                "freshness contains undeclared fields",
                reason=PreflightReason.UNDECLARED_FIELD,
                field=f"freshness.{field}",
                limit={"allowed_fields": ["mode", "max_age_seconds"]},
            )
        raw_freshness_mode = freshness.get("mode", "live")
        if not isinstance(raw_freshness_mode, str):
            raise AgentPreflightError(
                "freshness.mode must be a string",
                reason=PreflightReason.WRONG_TYPE,
                field="freshness.mode",
                limit={"type": "string"},
            )
        freshness_mode = _text(raw_freshness_mode).lower()
        max_age = freshness.get("max_age_seconds", 0)
        if freshness_mode != "live":
            raise AgentPreflightError(
                "only live evidence is supported by the Agent interface",
                reason=PreflightReason.FRESHNESS_MODE,
                field="freshness.mode",
                supported=("live",),
                limit={"allowed": ["live"]},
            )
        if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age != 0:
            raise AgentPreflightError(
                "live evidence requires max_age_seconds=0",
                reason=PreflightReason.LIVE_MAX_AGE,
                field="freshness.max_age_seconds",
                limit={"allowed": [0]},
            )
        deadline = query.get("deadline", 180)
        if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
            raise AgentPreflightError(
                "deadline must be a positive number",
                reason=PreflightReason.DEADLINE,
                field="deadline",
                limit={"type": "positive number"},
            )
        try:
            numeric_deadline = float(deadline)
        except OverflowError:
            numeric_deadline = math.inf
        if not math.isfinite(numeric_deadline):
            raise AgentPreflightError(
                "deadline must be a positive finite number",
                reason=PreflightReason.DEADLINE,
                field="deadline",
                limit={"type": "positive finite number"},
            )
        if numeric_deadline <= 0:
            raise AgentPreflightError(
                "deadline must be a positive number",
                reason=PreflightReason.DEADLINE,
                field="deadline",
                limit={"exclusive_minimum": 0},
            )
        contract = cls(
            target=target,
            selectors=selectors,
            freshness_mode=freshness_mode,
            max_age_seconds=max_age,
            deadline=numeric_deadline,
        )
        return contract

    def collection_partitions(self) -> tuple["ObservationQuery", ...]:
        """Plan bounded internal collection batches without narrowing scope."""

        batches: list[list[ObservationSelector]] = []
        current: list[ObservationSelector] = []

        def document(selectors: list[ObservationSelector]) -> dict[str, object]:
            return {
                "target": self.target,
                "selectors": [selector.to_public_dict() for selector in selectors],
                "freshness": {
                    "mode": self.freshness_mode,
                    "max_age_seconds": self.max_age_seconds,
                },
            }

        for selector in self.selectors:
            if selector.kind == "systemd":
                if current:
                    batches.append(current)
                    current = []
                batches.append([selector])
                continue
            for value in selector.values:
                fragment = selector.with_values((value,))
                if (
                    current
                    and current[-1].has_same_identity(selector)
                ):
                    candidate = [
                        *current[:-1],
                        current[-1].with_values((*current[-1].values, value)),
                    ]
                else:
                    candidate = [*current, fragment]
                if (
                    current
                    and len(json_bytes(document(candidate)))
                    > OBSERVATION_PARTITION_TARGET_BYTES
                ):
                    batches.append(current)
                    current = [fragment]
                else:
                    current = candidate
        if current:
            batches.append(current)
        return tuple(
            ObservationQuery(
                target=self.target,
                selectors=tuple(batch),
                freshness_mode=self.freshness_mode,
                max_age_seconds=self.max_age_seconds,
                deadline=self.deadline,
            )
            for batch in batches
        )

    def runtime_arguments(self, *, assured: bool) -> dict[str, object]:
        queries = [
            query
            for selector in self.selectors
            if selector.kind == "mdb"
            for query in selector.queries
        ]
        return {
            "ip": self.target,
            "deadline": self.deadline,
            "mdb_queries": queries,
            "mdb_only": True,
            "_agent_capability_names": [
                name
                for selector in self.selectors
                if selector.kind == "capability"
                for name in selector.names
            ],
            "_agent_assured": assured,
            "_agent_selectors": [
                selector.to_public_dict() for selector in self.selectors
            ],
            "profile": "mdb",
        }

    def to_public_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "selectors": [selector.to_public_dict() for selector in self.selectors],
            "freshness": {
                "mode": self.freshness_mode,
                "max_age_seconds": self.max_age_seconds,
            },
        }


# Compatibility names remain importable while callers migrate to the domain language.
SelectorContract = ObservationSelector
ScopeContract = ObservationQuery


@dataclass(frozen=True)
class ObservationRef:
    handle: str
    digest: str
    size: int = 0
    provenance: str = "runtime-observation"
    retention_hint: str = "run-lifetime"
    kind: str = "observation"
    target: str = ""
    scope_digest: str = ""
    observed_at: str = ""
    target_fingerprint: str = ""
    target_epoch: int = 0

    def __post_init__(self) -> None:
        digest = self.digest.removeprefix("sha256:").lower()
        if not self.handle.strip():
            raise ReferenceViolation("ObservationRef handle is required")
        if _SHA256.fullmatch(digest) is None:
            raise ReferenceViolation("ObservationRef digest must be SHA-256")
        if isinstance(self.size, bool) or self.size < 0:
            raise ReferenceViolation("ObservationRef size must be non-negative")
        if self.kind != "observation":
            raise ReferenceViolation("ObservationRef kind must be observation")
        if self.provenance != "runtime-observation":
            raise ReferenceViolation(
                "ObservationRef provenance must be runtime-observation"
            )
        if not self.retention_hint.strip():
            raise ReferenceViolation("ObservationRef retention_hint is required")
        if not self.target.strip():
            raise ReferenceViolation("ObservationRef target is required")
        scope_digest = self.scope_digest.removeprefix("sha256:").lower()
        if _SHA256.fullmatch(scope_digest) is None:
            raise ReferenceViolation("ObservationRef scope_digest must be SHA-256")
        if not self.observed_at.strip():
            raise ReferenceViolation("ObservationRef observed_at is required")
        if isinstance(self.target_epoch, bool) or self.target_epoch < 0:
            raise ReferenceViolation("ObservationRef target_epoch must be non-negative")
        object.__setattr__(self, "digest", digest)
        object.__setattr__(self, "scope_digest", scope_digest)

    @classmethod
    def from_public_dict(cls, value: Mapping[str, object]) -> "ObservationRef":
        digest = _text(value.get("digest") or value.get("sha256"))
        handle = _text(value.get("handle") or value.get("uri"))
        raw_size = value.get("size", value.get("byte_count", 0))
        size = raw_size if isinstance(raw_size, int) and not isinstance(raw_size, bool) else 0
        return cls(
            handle=handle,
            digest=digest,
            size=size,
            provenance=_text(value.get("provenance")),
            retention_hint=_text(value.get("retention_hint")),
            kind=_text(value.get("kind")),
            target=_text(value.get("target")),
            scope_digest=_text(value.get("scope_digest")),
            observed_at=_text(value.get("observed_at")),
            target_fingerprint=_text(value.get("target_fingerprint")),
            target_epoch=(
                value.get("target_epoch", 0)
                if isinstance(value.get("target_epoch", 0), int)
                and not isinstance(value.get("target_epoch", 0), bool)
                else 0
            ),
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": OBSERVATION_REF_SCHEMA,
            "handle": self.handle,
            "digest": f"sha256:{self.digest}",
            "kind": self.kind,
            "size": self.size,
            "provenance": self.provenance,
            "retention_hint": self.retention_hint,
            "target": self.target,
            "scope_digest": (
                f"sha256:{self.scope_digest}" if self.scope_digest else ""
            ),
            "observed_at": self.observed_at,
            "target_fingerprint": self.target_fingerprint,
            "target_epoch": self.target_epoch,
        }

    def to_source_dict(self) -> dict[str, object]:
        return {
            "schema": f"{RUNTIME_API_VERSION}/observation-source-v1",
            "blob_id": self.digest,
            "sha256": self.digest,
            "uri": self.handle,
            "byte_count": self.size,
            "kind": self.kind,
            "provenance": self.provenance,
            "retention_hint": self.retention_hint,
            "target": self.target,
            "scope_digest": self.scope_digest,
            "observed_at": self.observed_at,
            "target_fingerprint": self.target_fingerprint,
            "target_epoch": self.target_epoch,
        }


@dataclass(frozen=True)
class ArtifactRef:
    handle: str
    digest: str
    kind: str
    size: int = 0
    provenance: str = "external-build"
    retention_hint: str = "run-lifetime"
    version: str = ""
    target: str = ""
    run_id: str = ""

    def __post_init__(self) -> None:
        digest = self.digest.removeprefix("sha256:").lower()
        if not self.handle.strip():
            raise ReferenceViolation("ArtifactRef handle is required")
        if _SHA256.fullmatch(digest) is None:
            raise ReferenceViolation("ArtifactRef digest must be SHA-256")
        if not self.kind.strip():
            raise ReferenceViolation("ArtifactRef kind is required")
        if isinstance(self.size, bool) or self.size < 0:
            raise ReferenceViolation("ArtifactRef size must be non-negative")
        if not self.provenance.strip():
            raise ReferenceViolation("ArtifactRef provenance is required")
        if not self.retention_hint.strip():
            raise ReferenceViolation("ArtifactRef retention_hint is required")
        if not self.target.strip():
            raise ReferenceViolation("ArtifactRef target is required")
        if not self.run_id.strip():
            raise ReferenceViolation("ArtifactRef run_id is required")
        object.__setattr__(self, "digest", digest)

    @classmethod
    def from_public_dict(cls, value: Mapping[str, object]) -> "ArtifactRef":
        raw_size = value.get("size", 0)
        size = raw_size if isinstance(raw_size, int) and not isinstance(raw_size, bool) else 0
        return cls(
            handle=_text(value.get("handle") or value.get("path")),
            digest=_text(value.get("digest") or value.get("sha256")),
            kind=_text(value.get("kind")),
            size=size,
            provenance=_text(value.get("provenance")),
            retention_hint=_text(value.get("retention_hint")),
            version=_text(value.get("version") or value.get("product_version")),
            target=_text(value.get("target")),
            run_id=_text(value.get("run_id")),
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": ARTIFACT_REF_SCHEMA,
            "handle": self.handle,
            "digest": f"sha256:{self.digest}",
            "kind": self.kind,
            "size": self.size,
            "provenance": self.provenance,
            "retention_hint": self.retention_hint,
            "version": self.version,
            "target": self.target,
            "run_id": self.run_id,
        }


@dataclass(frozen=True)
class RunTarget:
    """One normalized target in a typed multi-target Run scope."""

    ip: str
    role: str
    target_id: str

    def to_public_dict(self) -> dict[str, object]:
        target: dict[str, object] = {
            "ip": self.ip,
            "target_id": self.target_id,
        }
        if self.role:
            target["role"] = self.role
        return target


@dataclass(frozen=True)
class StartRun:
    target: str
    intent: str
    purpose: str
    delivery_strategy: str
    command_id: str
    input_digest: str
    entry_operation: str = ""
    entry_arguments: Mapping[str, object] | None = None
    targets: tuple[RunTarget, ...] = ()
    observation_ref: ObservationRef | None = None
    caller_deadline: float = 120.0


@dataclass(frozen=True)
class SubmitGate:
    run_id: str
    response: Mapping[str, object]
    gate_id: str
    gate_version: int
    schema_digest: str
    submission_id: str = ""
    command_id: str = ""
    input_digest: str = ""
    caller_deadline: float = 120.0


@dataclass(frozen=True)
class ResumeRun:
    run_id: str
    command_id: str = ""
    input_digest: str = ""
    caller_deadline: float = 120.0


@dataclass(frozen=True)
class CancelRun:
    run_id: str
    gate_id: str
    gate_version: int
    schema_digest: str
    submission_id: str = ""
    command_id: str = ""
    input_digest: str = ""
    caller_deadline: float = 120.0


@dataclass(frozen=True)
class CancelIncident:
    run_id: str
    incident_id: str
    command_id: str = ""
    input_digest: str = ""
    caller_deadline: float = 120.0


@dataclass(frozen=True)
class ReconcileRun:
    run_id: str
    effect_id: str = ""
    command_id: str = ""
    input_digest: str = ""
    caller_deadline: float = 120.0


RunCommand: TypeAlias = (
    StartRun | SubmitGate | ResumeRun | CancelRun | CancelIncident | ReconcileRun
)


def _normalized_gate_submission(
    response: Mapping[str, object],
) -> dict[str, object]:
    raw_payload = response.get("payload", {})
    payload: object = (
        dict(raw_payload) if isinstance(raw_payload, Mapping) else raw_payload
    )
    if isinstance(payload, dict):
        raw_artifact_ref = payload.get("artifact_ref")
        if isinstance(raw_artifact_ref, Mapping):
            artifact_ref = dict(raw_artifact_ref)
            if "handle" not in artifact_ref and "path" in artifact_ref:
                artifact_ref["handle"] = artifact_ref.pop("path")
            if "digest" not in artifact_ref and "sha256" in artifact_ref:
                artifact_ref["digest"] = artifact_ref.pop("sha256")
            raw_digest = artifact_ref.get("digest")
            if isinstance(raw_digest, str):
                digest = raw_digest.strip().removeprefix("sha256:").lower()
                artifact_ref["digest"] = f"sha256:{digest}"
            for name in (
                "handle",
                "kind",
                "provenance",
                "retention_hint",
                "version",
                "target",
                "run_id",
            ):
                value = artifact_ref.get(name)
                if isinstance(value, str):
                    artifact_ref[name] = value.strip()
            payload["artifact_ref"] = artifact_ref
    raw_status = response.get("status")
    raw_summary = response.get("summary")
    return {
        "status": (
            raw_status.strip().lower()
            if isinstance(raw_status, str)
            else raw_status
        ),
        "summary": (
            raw_summary.strip()
            if isinstance(raw_summary, str)
            else raw_summary
        ),
        "payload": payload,
    }


def _validate_gate_response_shape(response: Mapping[str, object]) -> None:
    required = {"status", "summary", "payload"}
    missing = sorted(required - set(response))
    if missing:
        raise AgentGatewayError(
            "response requires fields: " + ", ".join(missing)
        )
    unexpected = sorted(set(response) - required)
    if unexpected:
        raise AgentGatewayError(
            "response contains unsupported fields: " + ", ".join(unexpected)
        )
    raw_payload = response.get("payload", {})
    if not isinstance(raw_payload, Mapping):
        raise AgentGatewayError("response payload must be an object")
    raw_status = response.get("status")
    raw_summary = response.get("summary")
    status = raw_status.strip().lower() if isinstance(raw_status, str) else ""
    if status not in {"completed", "failed", "cancelled", "partial"}:
        raise AgentGatewayError(
            "response status must be completed, failed, cancelled, or partial"
        )
    if not isinstance(raw_summary, str) or not raw_summary.strip():
        raise AgentGatewayError("response summary must be a non-empty string")


def run_command_semantic_input(command: RunCommand) -> Mapping[str, object]:
    """Return the canonical semantic payload persisted and fingerprinted for a command."""
    if isinstance(command, SubmitGate):
        return {
            "schema": f"{SEMANTIC_RUNTIME_SCHEMA}/submit-gate-input-v1",
            "run_id": command.run_id,
            "gate_id": command.gate_id,
            "gate_version": command.gate_version,
            "schema_digest": command.schema_digest,
            "response": _normalized_gate_submission(command.response),
        }
    if isinstance(command, CancelIncident):
        return {
            "schema": f"{SEMANTIC_RUNTIME_SCHEMA}/cancel-incident-input-v1",
            "run_id": command.run_id,
            "incident_id": command.incident_id,
        }
    if isinstance(command, CancelRun):
        return {
            "schema": f"{SEMANTIC_RUNTIME_SCHEMA}/cancel-run-input-v1",
            "run_id": command.run_id,
            "gate_id": command.gate_id,
            "gate_version": command.gate_version,
            "schema_digest": command.schema_digest,
        }
    if isinstance(command, ReconcileRun):
        return {
            "schema": f"{SEMANTIC_RUNTIME_SCHEMA}/reconcile-run-input-v2",
            "run_id": command.run_id,
            "effect_id": command.effect_id,
        }
    if isinstance(command, ResumeRun):
        return {
            "schema": f"{SEMANTIC_RUNTIME_SCHEMA}/resume-run-input-v1",
            "run_id": command.run_id,
        }
    return {
        "schema": f"{SEMANTIC_RUNTIME_SCHEMA}/start-input-v1",
        "target": command.target,
        "targets": [target.to_public_dict() for target in command.targets],
        "intent": command.intent,
        "entry_operation": command.entry_operation,
        "entry_arguments": dict(command.entry_arguments or {}),
        "purpose": command.purpose,
        "delivery_strategy": command.delivery_strategy,
        "observation_ref": (
            command.observation_ref.to_public_dict()
            if command.observation_ref is not None
            else None
        ),
    }


def run_command_identity(
    command: RunCommand, *, operation_id: str
) -> tuple[str, str]:
    """Return the stable identity and canonical input digest for one command."""

    command_id = _text(getattr(command, "command_id", "")) or _text(operation_id)
    if _SAFE_ID.fullmatch(command_id) is None:
        raise AgentGatewayError(
            "Run command operation_id must be a safe 1-128 character identifier"
        )
    canonical_digest = fingerprint(run_command_semantic_input(command))
    persisted_digest = _text(getattr(command, "input_digest", ""))
    if persisted_digest:
        if _SHA256.fullmatch(persisted_digest) is None:
            raise AgentGatewayError("Run command input_digest must be SHA-256")
        if persisted_digest != canonical_digest:
            raise AgentGatewayError(
                "Run command input_digest does not match normalized input"
            )
    return command_id, canonical_digest


def run_id_for_command(command: RunCommand, *, command_id: str) -> str:
    if not isinstance(command, StartRun):
        return command.run_id
    return "run-" + fingerprint(
        {
            "schema": "openubmc.semantic-runtime/start-command-identity-v1",
            "command_id": command_id,
        }
    )[:32]


def _gate_version(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise AgentGatewayError("gate_version must be a positive integer")
    return value


def _gate_id(value: object) -> str:
    selected = _text(value)
    if _SAFE_ID.fullmatch(selected) is None:
        raise AgentGatewayError("gate_id must be a safe 1-128 character identifier")
    return selected


def _incident_id(value: object) -> str:
    selected = _text(value)
    if _SAFE_ID.fullmatch(selected) is None:
        raise AgentGatewayError("incident_id must be a safe 1-128 character identifier")
    return selected


def _schema_digest(value: object) -> str:
    selected = _text(value).removeprefix("sha256:").lower()
    if _SHA256.fullmatch(selected) is None:
        raise AgentGatewayError("schema_digest must be SHA-256")
    return selected


def gate_submission_id(binding: Mapping[str, object]) -> str:
    """Derive the stable default identity for one persisted Gate binding."""

    return "gate-submit-" + fingerprint(binding)[:32]


def _submission_id(value: object, *, binding: Mapping[str, object]) -> str:
    selected = _text(value) or gate_submission_id(binding)
    if _SAFE_ID.fullmatch(selected) is None:
        raise AgentGatewayError("submission_id must be a safe 1-128 character identifier")
    return selected


def _action_preflight_context(action: Mapping[str, object]) -> PreflightContext:
    raw_gate_version = action.get("gate_version", 0)
    gate_version = (
        raw_gate_version
        if isinstance(raw_gate_version, int) and not isinstance(raw_gate_version, bool)
        else 0
    )
    return PreflightContext(
        action_kind=_text(action.get("kind")) or "resume",
        run_id=_text(action.get("run_id")),
        target=_text(action.get("target")),
        targets=tuple(
            dict(item)
            for item in (
                action.get("targets", [])
                if isinstance(action.get("targets"), list)
                else []
            )
            if isinstance(item, Mapping)
        ),
        intent=_text(action.get("intent")),
        purpose=_text(action.get("purpose")),
        delivery_strategy=_text(action.get("delivery_strategy")),
        observation_ref=dict(_mapping(action.get("observation_ref"))),
        command=_text(action.get("command")).lower(),
        incident_id=_text(action.get("incident_id")),
        entry_operation=_text(action.get("entry_operation")),
        entry_arguments=dict(_mapping(action.get("entry_arguments"))),
        gate_id=_text(action.get("gate_id")),
        gate_version=gate_version,
        schema_digest=_text(action.get("schema_digest")),
        submission_id=_text(action.get("submission_id")),
        response=dict(_mapping(action.get("response"))),
    )


def _gate_binding_preflight_error(
    action: Mapping[str, object],
    *,
    field: str,
    message: str,
) -> AgentPreflightError:
    context = _action_preflight_context(action)
    replacement: dict[str, object] = {
        "gate_id": "",
        "gate_version": 0,
        "schema_digest": "",
        "submission_id": "",
    }
    return AgentPreflightError(
        message,
        reason=PreflightReason.GATE_BINDING,
        field=field,
        limit={"binding": "current Gate"},
        context=replace(context, **{field: replacement[field]}),
    )


def _decode_gate_binding(
    action: Mapping[str, object],
    *,
    run_id: str,
) -> tuple[str, int, str, str]:
    decoders = (
        ("gate_id", _gate_id),
        ("gate_version", _gate_version),
        ("schema_digest", _schema_digest),
    )
    decoded: dict[str, object] = {}
    for field_name, decoder in decoders:
        try:
            decoded[field_name] = decoder(action.get(field_name))
        except AgentGatewayError as exc:
            raise _gate_binding_preflight_error(
                action,
                field=field_name,
                message=str(exc),
            ) from exc
    binding = {
        "run_id": run_id,
        "gate_id": decoded["gate_id"],
        "gate_version": decoded["gate_version"],
        "schema_digest": decoded["schema_digest"],
    }
    try:
        submission_id = _submission_id(
            action.get("submission_id"),
            binding=binding,
        )
    except AgentGatewayError as exc:
        raise _gate_binding_preflight_error(
            action,
            field="submission_id",
            message=str(exc),
        ) from exc
    return (
        str(decoded["gate_id"]),
        int(decoded["gate_version"]),
        str(decoded["schema_digest"]),
        submission_id,
    )


def _execute_deadline_error(action: Mapping[str, object]) -> AgentPreflightError:
    return AgentPreflightError(
        "execute deadline must be greater than 0 and at most 120 seconds",
        reason=PreflightReason.DEADLINE,
        field="deadline",
        limit={"exclusive_minimum": 0, "maximum_seconds": 120},
        context=_action_preflight_context(action),
    )


def _validate_action_shape(action: Mapping[str, object]) -> str:
    raw_kind = action.get("kind")
    if not isinstance(raw_kind, str) or raw_kind not in EXECUTE_ACTION_FIELDS:
        raise AgentGatewayError(
            "execute kind must be start, respond, resume, or control"
        )
    kind = raw_kind
    runtime_owned = sorted(set(action) & _RUNTIME_OWNED_ACTION_FIELDS)
    if runtime_owned:
        field = runtime_owned[0]
        raise AgentPreflightError(
            "execute Action cannot supply Runtime-owned fields: "
            + ", ".join(runtime_owned),
            reason=PreflightReason.RUNTIME_OWNED_FIELD,
            field=field,
            limit={"ownership": "Runtime"},
            context=_action_preflight_context(action),
        )
    unexpected = sorted(set(action) - EXECUTE_ACTION_FIELDS[kind])
    if unexpected:
        raise AgentGatewayError(
            f"{kind} Action contains fields from another Action kind or unsupported fields: "
            + ", ".join(unexpected)
        )
    missing = sorted(EXECUTE_ACTION_REQUIRED_FIELDS[kind] - set(action))
    if missing:
        if "run_id" in missing and kind in {"respond", "resume", "control"}:
            raise AgentPreflightError(
                f"{kind} Action requires fields: " + ", ".join(missing),
                reason=PreflightReason.RUN_ID_REQUIRED,
                field="run_id",
                limit={"required": True},
                context=_action_preflight_context(action),
            )
        raise AgentGatewayError(
            f"{kind} Action requires fields: " + ", ".join(missing)
        )
    for name, expected in EXECUTE_ACTION_FIELD_TYPES[kind].items():
        if name not in action:
            continue
        value = action[name]
        valid = (
            isinstance(value, str)
            if expected == "string"
            else isinstance(value, Mapping)
            if expected == "object"
            else isinstance(value, list)
            if expected == "array"
            else isinstance(value, int) and not isinstance(value, bool)
            if expected == "integer"
            else isinstance(value, (int, float)) and not isinstance(value, bool)
        )
        if not valid:
            if name == "deadline":
                raise _execute_deadline_error(action)
            article = "an" if expected in {"array", "integer", "object"} else "a"
            raise AgentGatewayError(f"{name} must be {article} {expected}")
    if kind != "control":
        return kind
    command = _text(action.get("command")).lower()
    gate_fields = {"gate_id", "gate_version", "schema_digest", "submission_id"}
    if command == "reconcile":
        invalid = sorted((gate_fields | {"incident_id"}) & set(action))
        if invalid:
            raise AgentGatewayError(
                "control reconcile accepts only kind, run_id, command, and deadline"
            )
        return kind
    if command != "cancel":
        raise AgentGatewayError(
            "control command must be one of: reconcile, cancel"
        )
    if "incident_id" in action:
        invalid = sorted(gate_fields & set(action))
        if invalid:
            raise AgentGatewayError(
                "incident cancel cannot include Gate binding fields: "
                + ", ".join(invalid)
            )
        return kind
    missing_gate = sorted(
        {"gate_id", "gate_version", "schema_digest"} - set(action)
    )
    if missing_gate:
        raise AgentGatewayError(
            "control cancel requires a Gate binding or incident_id; missing: "
            + ", ".join(missing_gate)
        )
    return kind


def _caller_deadline(action: Mapping[str, object]) -> float:
    value = action.get("deadline", 120)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _execute_deadline_error(action)
    try:
        deadline = float(value)
    except OverflowError:
        raise _execute_deadline_error(action) from None
    if not math.isfinite(deadline) or deadline <= 0 or deadline > 120:
        raise _execute_deadline_error(action)
    return deadline


def _bounded_diagnostic_scope(
    *,
    intent: str,
    arguments: Mapping[str, object],
    target_count: int,
) -> None:
    if intent not in {"diagnosis-only", "diagnose-and-fix"}:
        return
    requested = DiagnosticRequestPlan.from_mapping(arguments).total_result_count(
        target_count=target_count
    )
    if requested > DIAGNOSTIC_RECEIPT_MAX_STORED_RESULTS:
        raise AgentGatewayError(
            f"diagnostic scope requests {requested} items; maximum is "
            f"{DIAGNOSTIC_RECEIPT_MAX_STORED_RESULTS}"
        )


def decode_run_command(
    action: Mapping[str, object], *, operation_id: str
) -> RunCommand:
    bounded_request(action)
    if "observation_receipt" in action:
        raise AgentGatewayError(
            "observation_receipt is retired and unexpected; use observation_ref"
        )
    kind = _validate_action_shape(action)
    caller_deadline = _caller_deadline(action)
    if kind == "start":
        command_id = _text(operation_id)
        if _SAFE_ID.fullmatch(command_id) is None:
            raise AgentGatewayError(
                "StartRun operation_id must be a safe 1-128 character identifier"
            )
        if isinstance(action.get("workflow"), Mapping):
            raise AgentGatewayError(
                "dynamic workflow objects are not supported; choose intent and delivery_strategy"
            )
        raw_targets = action.get("targets")
        targets: tuple[RunTarget, ...] = ()
        if raw_targets is not None:
            if (
                not isinstance(raw_targets, list)
                or len(raw_targets) < 2
                or len(raw_targets) > 16
                or not all(isinstance(item, Mapping) for item in raw_targets)
            ):
                raise AgentGatewayError(
                    "start targets must contain 2-16 target objects"
                )
            normalized_targets: list[dict[str, object]] = []
            for item in raw_targets:
                unexpected_fields = sorted(
                    str(name)
                    for name in item
                    if name not in {"ip", "role", "target_id"}
                )
                if unexpected_fields:
                    raise AgentGatewayError(
                        "start target fields contain unexpected field "
                        + ", ".join(unexpected_fields)
                        + "; unexpected fields are forbidden"
                    )
                ip = _text(item.get("ip"))
                if not ip:
                    raise AgentGatewayError("each start target requires ip")
                if len(ip.encode("utf-8")) > TARGET_MAX_BYTES:
                    raise AgentGatewayError("start target ip exceeds 512 bytes")
                target_item: dict[str, object] = {"ip": ip}
                role = _text(item.get("role"))
                target_id = _text(item.get("target_id"))
                if role:
                    target_item["role"] = role
                if target_id:
                    target_item["target_id"] = target_id
                normalized_targets.append(target_item)
            try:
                identities = comparison_target_identities(normalized_targets)
            except ValueError as exc:
                raise AgentGatewayError(str(exc)) from exc
            for target_item, (role, target_id) in zip(
                normalized_targets, identities, strict=True
            ):
                target_item["target_id"] = target_id
                if role in {"reference", "candidate"}:
                    target_item["role"] = role
                else:
                    target_item.pop("role", None)
            targets = tuple(
                RunTarget(
                    ip=_text(target_item.get("ip")),
                    role=_text(target_item.get("role")),
                    target_id=_text(target_item.get("target_id")),
                )
                for target_item in normalized_targets
            )
        target = _text(action.get("target"))
        if targets:
            primary_target = targets[0].ip
            if target and target != primary_target:
                raise AgentGatewayError(
                    "start target must match the first targets entry"
                )
            target = primary_target
        if not target:
            raise AgentGatewayError("start requires target or targets")
        intent = _text(action.get("intent")).lower()
        if not intent:
            raise AgentGatewayError("start requires a non-empty intent")
        entry_operation = _text(action.get("entry_operation"))
        if entry_operation and _SAFE_ID.fullmatch(entry_operation) is None:
            raise AgentGatewayError(
                "entry_operation must be a safe 1-128 character identifier"
            )
        raw_entry_arguments = action.get("entry_arguments", {})
        if not isinstance(raw_entry_arguments, Mapping):
            raise AgentGatewayError("entry_arguments must be an object")
        entry_arguments = dict(raw_entry_arguments)
        runtime_owned_entry_fields = sorted(
            name
            for name in entry_arguments
            if name in _RUNTIME_OWNED_ENTRY_ARGUMENTS or name.startswith("_")
        )
        if runtime_owned_entry_fields:
            field = runtime_owned_entry_fields[0]
            raise AgentPreflightError(
                "entry_arguments cannot override Runtime-owned fields: "
                + ", ".join(runtime_owned_entry_fields),
                reason=PreflightReason.RUNTIME_OWNED_FIELD,
                field=f"entry_arguments.{field}",
                limit={"ownership": "Runtime"},
                context=replace(
                    _action_preflight_context(action),
                    target=target,
                    intent=intent,
                    entry_operation=entry_operation,
                    entry_arguments={
                        name: value
                        for name, value in entry_arguments.items()
                        if name not in runtime_owned_entry_fields
                    },
                ),
            )
        if entry_arguments and not entry_operation:
            raise AgentGatewayError(
                "entry_arguments requires entry_operation"
            )
        _bounded_diagnostic_scope(
            intent=intent,
            arguments=entry_arguments,
            target_count=len(targets) or 1,
        )
        raw_delivery = _text(action.get("delivery_strategy")).lower()
        delivery = raw_delivery or (
            "source-only" if intent == "diagnose-and-fix" else ""
        )
        if delivery and delivery not in {
            "source-only",
            "live-patch",
            "build-upgrade",
        }:
            raise AgentGatewayError("unsupported delivery_strategy")
        observation_ref = None
        raw_ref = action.get("observation_ref")
        if raw_ref is not None and not isinstance(raw_ref, Mapping):
            raise AgentGatewayError("observation_ref must be an object")
        if isinstance(raw_ref, Mapping):
            if targets:
                raise AgentGatewayError(
                    "multi-target start does not accept a single-target observation_ref"
                )
            observation_ref = ObservationRef.from_public_dict(raw_ref)
        purpose = _text(action.get("purpose") or "complete the requested workflow")
        command = StartRun(
            target=target,
            intent=intent,
            purpose=purpose,
            delivery_strategy=delivery,
            command_id=command_id,
            input_digest="",
            entry_operation=entry_operation,
            entry_arguments=entry_arguments,
            targets=targets,
            observation_ref=observation_ref,
            caller_deadline=caller_deadline,
        )
        _identity, digest = run_command_identity(
            command,
            operation_id=operation_id,
        )
        return replace(command, input_digest=digest)
    run_id = _text(action.get("run_id"))
    if not run_id:
        raise AgentGatewayError(f"{kind or 'execute'} requires run_id")
    if kind == "respond":
        response = action.get("response")
        if not isinstance(response, Mapping):
            raise AgentGatewayError("respond requires a response object")
        _validate_gate_response_shape(response)
        gate_id, gate_version, schema_digest, submission_id = (
            _decode_gate_binding(action, run_id=run_id)
        )
        command = SubmitGate(
            run_id=run_id,
            response=_normalized_gate_submission(response),
            gate_id=gate_id,
            gate_version=gate_version,
            schema_digest=schema_digest,
            submission_id=submission_id,
            command_id=submission_id,
            input_digest="",
            caller_deadline=caller_deadline,
        )
        _identity, digest = run_command_identity(
            command,
            operation_id=operation_id,
        )
        return replace(command, input_digest=digest)
    if kind == "resume":
        command_id = _text(operation_id)
        command = ResumeRun(
            run_id,
            command_id=command_id,
            caller_deadline=caller_deadline,
        )
        identity, digest = run_command_identity(command, operation_id=operation_id)
        return ResumeRun(
            run_id,
            command_id=identity,
            input_digest=digest,
            caller_deadline=caller_deadline,
        )
    if kind == "control":
        command = _text(action.get("command")).lower()
        if command == "cancel":
            raw_incident_id = _text(action.get("incident_id"))
            if raw_incident_id:
                incident_id = _incident_id(raw_incident_id)
                command_id = "incident-cancel-" + fingerprint(
                    {"run_id": run_id, "incident_id": incident_id}
                )[:32]
                command = CancelIncident(
                    run_id=run_id,
                    incident_id=incident_id,
                    command_id=command_id,
                    caller_deadline=caller_deadline,
                )
                identity, digest = run_command_identity(
                    command, operation_id=operation_id
                )
                return CancelIncident(
                    run_id=run_id,
                    incident_id=incident_id,
                    command_id=identity,
                    input_digest=digest,
                    caller_deadline=caller_deadline,
                )
            else:
                gate_id, gate_version, schema_digest, submission_id = (
                    _decode_gate_binding(action, run_id=run_id)
                )
            command = CancelRun(
                run_id=run_id,
                gate_id=gate_id,
                gate_version=gate_version,
                schema_digest=schema_digest,
                submission_id=submission_id,
                command_id=submission_id,
                caller_deadline=caller_deadline,
            )
            identity, digest = run_command_identity(
                command, operation_id=operation_id
            )
            return CancelRun(
                run_id=run_id,
                gate_id=gate_id,
                gate_version=gate_version,
                schema_digest=schema_digest,
                submission_id=submission_id,
                command_id=identity,
                input_digest=digest,
                caller_deadline=caller_deadline,
            )
        if command == "reconcile":
            reconcile = ReconcileRun(
                run_id,
                command_id=_text(operation_id),
                caller_deadline=caller_deadline,
            )
            identity, digest = run_command_identity(
                reconcile,
                operation_id=operation_id,
            )
            return replace(
                reconcile,
                command_id=identity,
                input_digest=digest,
            )
        raise AgentGatewayError(
            "control command must be one of: reconcile, cancel"
        )
    raise AgentGatewayError("execute kind must be start, respond, resume, or control")


@dataclass(frozen=True)
class Gate:
    gate_id: str
    version: int
    name: str
    owner: str
    input_schema: Mapping[str, object]
    schema_digest: str
    kind: str = "phase"

    @classmethod
    def from_public_dict(cls, value: Mapping[str, object]) -> "Gate":
        raw_version = value.get("gate_version", value.get("version", 0))
        if isinstance(raw_version, bool) or not isinstance(raw_version, int):
            raise GateConflict("persisted Gate version is invalid")
        schema = value.get("input_schema")
        if not isinstance(schema, Mapping):
            raise GateConflict("persisted Gate schema is invalid")
        schema_digest = _schema_digest(value.get("schema_digest"))
        if fingerprint(schema) != schema_digest:
            raise GateConflict("persisted Gate schema digest is invalid")
        return cls(
            gate_id=_gate_id(value.get("gate_id")),
            version=_gate_version(raw_version),
            name=_text(value.get("name")),
            owner=_text(value.get("owner")),
            input_schema=dict(schema),
            schema_digest=schema_digest,
            kind=_text(value.get("kind") or "phase"),
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "gate_id": self.gate_id,
            "gate_version": self.version,
            "schema_digest": f"sha256:{self.schema_digest}",
            "name": self.name,
            "owner": self.owner,
            "input_schema": dict(self.input_schema),
        }


@dataclass(frozen=True)
class Incident:
    incident_id: str
    code: str
    message: str
    effect_id: str = ""
    recoverable: bool = True

    @property
    def recovery_path(self) -> str:
        return incident_recovery_policy(self.code).recovery_path

    @property
    def allowed_commands(self) -> tuple[str, ...]:
        return incident_recovery_policy(self.code).allowed_commands

    @property
    def operator_action(self) -> str:
        return incident_recovery_policy(self.code).operator_action

    @classmethod
    def from_public_dict(cls, value: Mapping[str, object]) -> "Incident":
        code = _text(value.get("code"))
        policy = incident_recovery_policy(code)
        return cls(
            incident_id=_text(value.get("incident_id")),
            code=code,
            message=_text(value.get("message")),
            effect_id=_text(value.get("effect_id")),
            recoverable=policy.recoverable,
        )

    def to_public_dict(self) -> dict[str, object]:
        policy = incident_recovery_policy(self.code)
        return {
            "incident_id": self.incident_id,
            "code": self.code,
            "message": self.message,
            "effect_id": self.effect_id,
            **policy.to_public_dict(),
        }


@dataclass(frozen=True)
class Outcome:
    status: str
    summary: str
    acceptance: object = field(default_factory=list)

    def to_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "summary": self.summary,
            "acceptance": self.acceptance,
        }


@dataclass(frozen=True)
class RunTurn:
    run_id: str
    state: str
    gate: Gate | Mapping[str, object] | None = None
    incident: Incident | None = None
    facts: tuple[Mapping[str, object], ...] = ()
    gaps: tuple[object, ...] = ()
    outcome: Outcome | None = None
    next_action: str = ""
    observation_ref: ObservationRef | None = None
    outcome_recorded: bool = False
    diagnostic_receipt: DiagnosticReceipt | None = None
    diagnosis_record: DiagnosisRecord | None = None
    response_required: bool = False
    progress: Mapping[str, object] = field(default_factory=dict)

    @classmethod
    def from_public_dict(cls, value: Mapping[str, object]) -> "RunTurn":
        raw_gate = value.get("gate")
        gate = (
            Gate.from_public_dict(raw_gate)
            if isinstance(raw_gate, Mapping) and raw_gate
            else None
        )
        raw_incident = value.get("incident")
        incident = (
            Incident.from_public_dict(raw_incident)
            if isinstance(raw_incident, Mapping) and raw_incident
            else None
        )
        raw_outcome = value.get("outcome")
        outcome = (
            Outcome(
                status=_text(raw_outcome.get("status")),
                summary=_text(raw_outcome.get("summary")),
                acceptance=raw_outcome.get("acceptance", []),
            )
            if isinstance(raw_outcome, Mapping) and raw_outcome
            else None
        )
        raw_facts = value.get("facts", [])
        facts = tuple(
            dict(item)
            for item in raw_facts
            if isinstance(item, Mapping)
        ) if isinstance(raw_facts, list) else ()
        raw_gaps = value.get("gaps", [])
        gaps = tuple(raw_gaps) if isinstance(raw_gaps, list) else ()
        raw_observation_ref = value.get("observation_ref")
        observation_ref = (
            ObservationRef.from_public_dict(raw_observation_ref)
            if isinstance(raw_observation_ref, Mapping) and raw_observation_ref
            else None
        )
        raw_diagnostic_receipt = value.get("diagnostic_receipt")
        return cls(
            run_id=_text(value.get("run_id")),
            state=_text(value.get("state")),
            gate=gate,
            incident=incident,
            facts=facts,
            gaps=gaps,
            outcome=outcome,
            next_action=_text(value.get("next")),
            observation_ref=observation_ref,
            outcome_recorded=bool(value.get("outcome_recorded", False)),
            diagnostic_receipt=(
                DiagnosticReceipt.from_public_dict(raw_diagnostic_receipt)
                if isinstance(raw_diagnostic_receipt, Mapping)
                else None
            ),
            diagnosis_record=(
                DiagnosisRecord.from_mapping(value["diagnosis_record"])
                if isinstance(value.get("diagnosis_record"), Mapping)
                else None
            ),
            response_required=bool(value.get("response_required", False)),
            progress=(
                dict(value.get("progress", {}))
                if isinstance(value.get("progress"), Mapping)
                else {}
            ),
        )

    def to_public_dict(self) -> dict[str, object]:
        gate = (
            self.gate.to_public_dict()
            if isinstance(self.gate, Gate)
            else dict(self.gate)
            if isinstance(self.gate, Mapping)
            else None
        )
        result: dict[str, object] = {
            "run_id": self.run_id,
            "state": self.state,
            "gate": gate,
            "incident": (
                self.incident.to_public_dict() if self.incident is not None else None
            ),
            "facts": [dict(item) for item in self.facts],
            "gaps": list(self.gaps),
            "outcome": (
                self.outcome.to_public_dict() if self.outcome is not None else None
            ),
            "next": self.next_action,
        }
        if self.observation_ref is not None:
            result["observation_ref"] = self.observation_ref.to_public_dict()
        if self.outcome_recorded:
            result["outcome_recorded"] = True
        if self.diagnostic_receipt is not None:
            result["diagnostic_receipt"] = (
                self.diagnostic_receipt.to_public_dict()
            )
        if self.diagnosis_record is not None:
            result["diagnosis_record"] = self.diagnosis_record.to_public_dict()
        if self.response_required:
            result["response_required"] = True
        if self.progress:
            result["progress"] = dict(self.progress)
        return result


def project_run_turn(
    projection: Mapping[str, object],
    *,
    run_id: str,
    gate: Gate | Mapping[str, object] | None = None,
    use_current_gate: bool = False,
    state: str = "",
    next_action: str = "",
    use_projected_next_action: bool = False,
    observation_ref: ObservationRef | None = None,
    base_turn: RunTurn | None = None,
    facts: tuple[Mapping[str, object], ...] | None = None,
) -> RunTurn:
    """Build the current semantic Turn from one authoritative Run projection."""

    selected_gate = gate
    if use_current_gate:
        raw_gate = projection.get("current_gate")
        selected_gate = (
            Gate.from_public_dict(raw_gate)
            if isinstance(raw_gate, Mapping) and raw_gate
            else None
        )
    raw_incident = projection.get("current_incident")
    incident = (
        Incident.from_public_dict(raw_incident)
        if isinstance(raw_incident, Mapping) and raw_incident
        else None
    )
    raw_outcome = projection.get("run_outcome")
    outcome = (
        Outcome(
            status=_text(raw_outcome.get("status")),
            summary=_text(raw_outcome.get("summary")),
            acceptance=raw_outcome.get("acceptance", []),
        )
        if isinstance(raw_outcome, Mapping) and raw_outcome
        else None
    )
    projection_status = _text(projection.get("status"))
    selected_state = state or (
        outcome.status
        if outcome is not None
        else "incident"
        if incident is not None
        else "waiting_response"
        if selected_gate is not None
        else "running"
        if projection_status in {"open", "waiting_phase_record"}
        else projection_status
        or (base_turn.state if base_turn is not None else "running")
    )
    selected_next_action = next_action
    if use_projected_next_action and not selected_next_action:
        raw_next_actions = projection.get("next_actions", [])
        if isinstance(raw_next_actions, list) and raw_next_actions:
            selected_next_action = _text(raw_next_actions[0])
        elif base_turn is not None and selected_state == base_turn.state:
            selected_next_action = base_turn.next_action
    if incident is not None and not selected_next_action:
        selected_next_action = incident.operator_action
    if outcome is not None or selected_state in {
        "cancelled",
        "completed",
        "failed",
    }:
        selected_next_action = ""
    gaps = base_turn.gaps if base_turn is not None else ()
    validation_gaps = tuple(
        str(gap)
        for phase in projection.get("phase_records", [])
        if isinstance(phase, Mapping)
        for gap in (
            phase.get("validation_gaps", [])
            if isinstance(phase.get("validation_gaps"), list)
            else []
        )
        if str(gap).strip()
    )
    if validation_gaps:
        gaps = tuple(dict.fromkeys((*gaps, *validation_gaps)))
    recovery_gap = _text(projection.get("closeout_recovery_gap"))
    if recovery_gap and recovery_gap not in gaps:
        gaps = (*gaps, recovery_gap)
    diagnostic_receipt = (
        base_turn.diagnostic_receipt if base_turn is not None else None
    )
    persisted_diagnostic_receipt = latest_diagnostic_receipt(projection)
    if persisted_diagnostic_receipt is not None:
        diagnostic_receipt = persisted_diagnostic_receipt
    persisted_observation_ref = None
    start_input = projection.get("start_input")
    if isinstance(start_input, Mapping):
        raw_start_ref = start_input.get("observation_ref")
        if isinstance(raw_start_ref, Mapping) and raw_start_ref:
            persisted_observation_ref = ObservationRef.from_public_dict(raw_start_ref)
    return RunTurn(
        run_id=run_id,
        state=selected_state,
        gate=selected_gate,
        incident=incident,
        facts=(
            facts
            if facts is not None
            else base_turn.facts
            if base_turn is not None
            else ()
        ),
        gaps=gaps,
        outcome=outcome,
        next_action=selected_next_action,
        observation_ref=(
            observation_ref
            if observation_ref is not None
            else persisted_observation_ref
            if persisted_observation_ref is not None
            else base_turn.observation_ref
            if base_turn is not None
            else None
        ),
        outcome_recorded=(
            outcome is not None
            or (base_turn.outcome_recorded if base_turn is not None else False)
        ),
        diagnostic_receipt=diagnostic_receipt,
        diagnosis_record=accepted_diagnosis_record(projection),
        progress=operation_activity(projection),
    )


@dataclass(frozen=True)
class ObservationResult:
    query: ObservationQuery
    raw: Mapping[str, object]
    assurance: str
    observation_ref: ObservationRef | None
    source: Mapping[str, object] = field(default_factory=dict)


class SemanticRuntimePort(Protocol):
    """The complete Runtime seam used by the Agent Gateway."""

    def observe(
        self,
        query: ObservationQuery,
        *,
        task_id: str,
        operation_id: str,
    ) -> ObservationResult: ...

    def execute(
        self,
        command: RunCommand,
        *,
        task_id: str,
        operation_id: str,
    ) -> RunTurn: ...
