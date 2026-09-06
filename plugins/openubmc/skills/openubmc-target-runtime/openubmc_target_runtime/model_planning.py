"""Runtime-internal model planning Effect and bounded Plan IR prototype."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import threading
import time
from typing import Protocol

from .contracts import RUNTIME_API_VERSION


MODEL_INVOCATION_SCHEMA = f"{RUNTIME_API_VERSION}/model-invocation-v1"
PLAN_PROPOSAL_SCHEMA = f"{RUNTIME_API_VERSION}/plan-proposal-v1"
PLAN_REVISION_SCHEMA = f"{RUNTIME_API_VERSION}/plan-revision-v1"
PLANNING_INPUT_SCHEMA = f"{RUNTIME_API_VERSION}/planning-input-v1"
BOUNDED_PLAN_IR_VERSION = "bounded-plan-ir/v1"
MAX_MODEL_ERROR_MESSAGE_BYTES = 4096

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SHA256_REF = re.compile(r"sha256:[0-9a-f]{64}")
class PlanNodeKind(str, Enum):
    ACTION = "action"
    SEQUENCE = "sequence"
    CHOICE = "choice"
    PARALLEL = "parallel"
    REPEAT = "repeat"
    TIMER = "timer"
    GATE = "gate"
    SUBFLOW = "subflow"


class PlanProposalStatus(str, Enum):
    PROPOSED = "proposed"


class ModelInvocationStatus(str, Enum):
    RUNNING = "running"
    UNKNOWN = "unknown"
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    FAILED = "failed"


class PlanRevisionStatus(str, Enum):
    PINNED = "pinned"


class ModelAdapterStatus(str, Enum):
    SUCCEEDED = "succeeded"
    UNKNOWN = "unknown"
    FAILED = "failed"


class PlanningDecisionStatus(str, Enum):
    ACCEPTED = "accepted"
    UNKNOWN = "unknown"
    REJECTED = "rejected"
    FAILED = "failed"


_TERMINAL_INVOCATION_STATUSES = frozenset(
    {
        ModelInvocationStatus.SUCCEEDED,
        ModelInvocationStatus.REJECTED,
        ModelInvocationStatus.FAILED,
    }
)


class ModelPlanningError(ValueError):
    """Base error for the model-planning Module."""


class ModelInvocationConflict(ModelPlanningError):
    """Raised when a stable model invocation identity is rebound."""


class PlanProposalRejected(ModelPlanningError):
    """Raised when model output exceeds the deliberately bounded IR."""


def _json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ModelPlanningError("value must be strict JSON") from exc


def _fingerprint(value: object) -> str:
    return "sha256:" + hashlib.sha256(_json_bytes(value)).hexdigest()


def _required_id(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ModelPlanningError(f"{name} must be a string")
    selected = value.strip()
    if _SAFE_ID.fullmatch(selected) is None:
        raise ModelPlanningError(f"{name} must be a safe identifier")
    return selected


def _required_text(value: object, name: str, *, max_bytes: int = 4096) -> str:
    if not isinstance(value, str):
        raise ModelPlanningError(f"{name} must be a string")
    selected = value.strip()
    if not selected:
        raise ModelPlanningError(f"{name} is required")
    if len(selected.encode("utf-8")) > max_bytes:
        raise ModelPlanningError(f"{name} exceeds its byte budget")
    return selected


def _bounded_error_message(value: object, default: str) -> str:
    selected = str(value).strip() or default
    encoded = selected.encode("utf-8")
    if len(encoded) <= MAX_MODEL_ERROR_MESSAGE_BYTES:
        return selected
    return encoded[:MAX_MODEL_ERROR_MESSAGE_BYTES].decode(
        "utf-8",
        errors="ignore",
    )


def _record_string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ModelPlanningError(f"{name} must be a string")
    return value


def _record_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelPlanningError(f"{name} must be an integer")
    return value


def _record_number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ModelPlanningError(f"{name} must be a number")
    selected = float(value)
    if not math.isfinite(selected):
        raise ModelPlanningError(f"{name} must be finite")
    return selected


def _strict_json_object(document: object, name: str) -> Mapping[str, object]:
    if not isinstance(document, str):
        raise ModelPlanningError(f"{name} must be strict JSON")

    def reject_constant(value: str) -> object:
        raise ModelPlanningError(
            f"{name} must be strict JSON; unsupported constant {value}"
        )

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        selected: dict[str, object] = {}
        for key, value in pairs:
            if key in selected:
                raise ModelPlanningError(
                    f"{name} must be strict JSON; duplicate key {key}"
                )
            selected[key] = value
        return selected

    try:
        decoded = json.loads(
            document,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except ModelPlanningError:
        raise
    except (TypeError, ValueError) as exc:
        raise ModelPlanningError(f"{name} must be strict JSON") from exc
    if not isinstance(decoded, Mapping):
        raise ModelPlanningError(f"{name} must be a JSON object")
    return dict(decoded)


def _json_string(value: object, name: str, *, default: str = "") -> str:
    if value is None:
        return default
    if not isinstance(value, str):
        raise PlanProposalRejected(f"{name} must be a string")
    return value


def _json_integer(value: object, name: str, *, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise PlanProposalRejected(f"{name} must be an integer")
    return value


def _json_boolean(value: object, name: str, *, default: bool = False) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise PlanProposalRejected(f"{name} must be a boolean")
    return value


def _planning_invocation_id(run_id: str, slot_id: str, generation: int) -> str:
    identity = _fingerprint(
        {
            "run_id": run_id,
            "slot_id": slot_id,
            "generation": generation,
        }
    )
    return "model-plan:" + identity.removeprefix("sha256:")[:48]


@dataclass(frozen=True)
class ModelConfiguration:
    provider: str
    model: str
    parameters_json: str
    timeout_seconds: float
    adapter_version: str = "1"
    model_revision: str = "pinned"
    template_id: str = "bounded-plan"
    template_version: int = 1
    max_output_bytes: int = 32 * 1024
    version: int = 1

    def __post_init__(self) -> None:
        _required_id(self.provider, "model provider")
        _required_id(self.model, "model name")
        _required_id(self.adapter_version, "model Adapter version")
        _required_id(self.model_revision, "model revision")
        _required_id(self.template_id, "model template id")
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise ModelPlanningError("model configuration version must be an integer")
        if self.version != 1:
            raise ModelPlanningError("unsupported model configuration version")
        if (
            isinstance(self.template_version, bool)
            or not isinstance(self.template_version, int)
            or self.template_version < 1
        ):
            raise ModelPlanningError("model template version must be positive")
        if (
            isinstance(self.max_output_bytes, bool)
            or not isinstance(self.max_output_bytes, int)
            or self.max_output_bytes < 1
            or self.max_output_bytes > 1024 * 1024
        ):
            raise ModelPlanningError("model output byte budget is invalid")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
            or self.timeout_seconds > 300
        ):
            raise ModelPlanningError("model timeout must be in (0, 300] seconds")
        decoded = _strict_json_object(self.parameters_json, "model parameters")
        _json_bytes(dict(decoded))

    @classmethod
    def freeze(
        cls,
        *,
        provider: str,
        model: str,
        parameters: Mapping[str, object] | None = None,
        timeout_seconds: float = 30.0,
        adapter_version: str = "1",
        model_revision: str = "pinned",
        template_id: str = "bounded-plan",
        template_version: int = 1,
        max_output_bytes: int = 32 * 1024,
    ) -> "ModelConfiguration":
        return cls(
            provider=_required_id(provider, "model provider"),
            model=_required_id(model, "model name"),
            parameters_json=_json_bytes(dict(parameters or {})).decode("ascii"),
            timeout_seconds=timeout_seconds,
            adapter_version=adapter_version,
            model_revision=model_revision,
            template_id=template_id,
            template_version=template_version,
            max_output_bytes=max_output_bytes,
        )

    @property
    def parameters(self) -> Mapping[str, object]:
        return _strict_json_object(self.parameters_json, "model parameters")

    @property
    def digest(self) -> str:
        return _fingerprint(self.to_public_dict())

    def to_public_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "provider": self.provider,
            "model": self.model,
            "adapter_version": self.adapter_version,
            "model_revision": self.model_revision,
            "template_id": self.template_id,
            "template_version": self.template_version,
            "parameters": dict(self.parameters),
            "timeout_seconds": self.timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
        }


@dataclass(frozen=True)
class PlanningInput:
    objective: str
    context_digests: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()
    version: int = 1

    def __post_init__(self) -> None:
        _required_text(self.objective, "planning objective", max_bytes=8192)
        if self.version != 1:
            raise ModelPlanningError("unsupported PlanningInput version")
        if len(self.context_digests) > 32:
            raise ModelPlanningError("PlanningInput has too many context digests")
        if len(self.constraints) > 32:
            raise ModelPlanningError("PlanningInput has too many constraints")
        for digest in self.context_digests:
            if _SHA256_REF.fullmatch(digest) is None:
                raise ModelPlanningError("PlanningInput context digest must be SHA-256")
        for constraint in self.constraints:
            _required_text(constraint, "planning constraint", max_bytes=1024)

    @property
    def digest(self) -> str:
        return _fingerprint(self.to_public_dict())

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": PLANNING_INPUT_SCHEMA,
            "version": self.version,
            "objective": self.objective,
            "context_digests": list(self.context_digests),
            "constraints": list(self.constraints),
        }


@dataclass(frozen=True)
class PlanningRequest:
    run_id: str
    planning_input: PlanningInput
    slot_id: str = "primary"
    generation: int = 1
    version: int = 1

    def __post_init__(self) -> None:
        _required_id(self.run_id, "model planning run_id")
        _required_id(self.slot_id, "model planning slot_id")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 1
        ):
            raise ModelPlanningError("model planning generation must be positive")
        if self.version != 1:
            raise ModelPlanningError("unsupported PlanningRequest version")

    @property
    def invocation_id(self) -> str:
        return _planning_invocation_id(
            self.run_id,
            self.slot_id,
            self.generation,
        )


@dataclass(frozen=True)
class PlanningBinding:
    """The stable Run, invocation, input, Provider, and policy identity clump."""

    run_id: str
    slot_id: str
    generation: int
    invocation_id: str
    input_digest: str
    provider_config_digest: str
    policy_digest: str

    def __post_init__(self) -> None:
        _required_id(self.run_id, "PlanningBinding run_id")
        _required_id(self.slot_id, "PlanningBinding slot_id")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 1
        ):
            raise ModelPlanningError("PlanningBinding generation must be positive")
        expected = _planning_invocation_id(
            self.run_id,
            self.slot_id,
            self.generation,
        )
        if self.invocation_id != expected:
            raise ModelPlanningError("PlanningBinding invocation_id is inconsistent")
        for name, value in (
            ("input_digest", self.input_digest),
            ("provider_config_digest", self.provider_config_digest),
            ("policy_digest", self.policy_digest),
        ):
            if _SHA256_REF.fullmatch(value) is None:
                raise ModelPlanningError(f"PlanningBinding {name} must be SHA-256")

    @classmethod
    def freeze(
        cls,
        request: PlanningRequest,
        *,
        input_digest: str,
        provider_config_digest: str,
        policy_digest: str,
    ) -> "PlanningBinding":
        return cls(
            run_id=request.run_id,
            slot_id=request.slot_id,
            generation=request.generation,
            invocation_id=request.invocation_id,
            input_digest=input_digest,
            provider_config_digest=provider_config_digest,
            policy_digest=policy_digest,
        )

    @property
    def digest(self) -> str:
        return _fingerprint(self.to_public_dict())

    def to_public_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "slot_id": self.slot_id,
            "generation": self.generation,
            "invocation_id": self.invocation_id,
            "input_digest": self.input_digest,
            "provider_config_digest": self.provider_config_digest,
            "policy_digest": self.policy_digest,
        }

    @classmethod
    def from_public_dict(cls, value: Mapping[str, object]) -> "PlanningBinding":
        generation = value.get("generation")
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise ModelPlanningError("PlanningBinding generation must be an integer")
        return cls(
            run_id=_record_string(value.get("run_id"), "PlanningBinding run_id"),
            slot_id=_record_string(value.get("slot_id"), "PlanningBinding slot_id"),
            generation=generation,
            invocation_id=_record_string(
                value.get("invocation_id"),
                "PlanningBinding invocation_id",
            ),
            input_digest=_record_string(
                value.get("input_digest"),
                "PlanningBinding input_digest",
            ),
            provider_config_digest=_record_string(
                value.get("provider_config_digest"),
                "PlanningBinding provider_config_digest",
            ),
            policy_digest=_record_string(
                value.get("policy_digest"),
                "PlanningBinding policy_digest",
            ),
        )


@dataclass(frozen=True)
class PlanNode:
    node_id: str
    kind: PlanNodeKind
    children: tuple[str, ...] = ()
    branches: tuple[str, ...] = ()
    body: str = ""
    action: str = ""
    repeat_max: int = 0
    timer_seconds: int = 0
    gate_schema: str = ""
    subflow: str = ""
    subflow_version: str = ""
    compensation: str = ""
    compensation_only: bool = False

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "PlanNode":
        allowed = {
            "node_id",
            "kind",
            "children",
            "branches",
            "body",
            "action",
            "repeat_max",
            "timer_seconds",
            "gate_schema",
            "subflow",
            "subflow_version",
            "compensation",
            "compensation_only",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise PlanProposalRejected(
                "Plan node contains unknown fields: " + ", ".join(unknown)
            )
        raw_children = value.get("children", [])
        raw_branches = value.get("branches", [])
        if not isinstance(raw_children, list) or not all(
            isinstance(item, str) for item in raw_children
        ):
            raise PlanProposalRejected("Plan node children must be a string array")
        if not isinstance(raw_branches, list) or not all(
            isinstance(item, str) for item in raw_branches
        ):
            raise PlanProposalRejected("Plan node branches must be a string array")
        raw_kind = _json_string(value.get("kind"), "Plan node kind")
        try:
            kind = PlanNodeKind(raw_kind)
        except ValueError as exc:
            raise PlanProposalRejected(
                f"unsupported Plan node kind: {raw_kind}"
            ) from exc
        return cls(
            node_id=_required_id(
                _json_string(value.get("node_id"), "Plan node_id"),
                "Plan node_id",
            ),
            kind=kind,
            children=tuple(raw_children),
            branches=tuple(raw_branches),
            body=_json_string(value.get("body"), "Plan node body"),
            action=_json_string(value.get("action"), "Plan node action"),
            repeat_max=_json_integer(
                value.get("repeat_max"),
                "Plan node repeat_max",
            ),
            timer_seconds=_json_integer(
                value.get("timer_seconds"),
                "Plan node timer_seconds",
            ),
            gate_schema=_json_string(
                value.get("gate_schema"),
                "Plan node gate_schema",
            ),
            subflow=_json_string(value.get("subflow"), "Plan node subflow"),
            subflow_version=_json_string(
                value.get("subflow_version"),
                "Plan node subflow_version",
            ),
            compensation=_json_string(
                value.get("compensation"),
                "Plan node compensation",
            ),
            compensation_only=_json_boolean(
                value.get("compensation_only"),
                "Plan node compensation_only",
            ),
        )

    def to_public_dict(self) -> dict[str, object]:
        value: dict[str, object] = {
            "node_id": self.node_id,
            "kind": self.kind.value,
        }
        for name, selected in (
            ("children", list(self.children)),
            ("branches", list(self.branches)),
            ("body", self.body),
            ("action", self.action),
            ("repeat_max", self.repeat_max),
            ("timer_seconds", self.timer_seconds),
            ("gate_schema", self.gate_schema),
            ("subflow", self.subflow),
            ("subflow_version", self.subflow_version),
            ("compensation", self.compensation),
            ("compensation_only", self.compensation_only),
        ):
            if selected not in ("", 0, False, []):
                value[name] = selected
        return value


@dataclass(frozen=True)
class PlanProposal:
    run_id: str
    root_node_id: str
    nodes: tuple[PlanNode, ...]
    invocation_id: str = ""
    input_digest: str = ""
    provider_config_json: str = "{}"
    provider_config_digest: str = ""
    status: PlanProposalStatus = PlanProposalStatus.PROPOSED
    error_code: str = ""
    error_message: str = ""
    version: int = 1

    def __post_init__(self) -> None:
        _required_id(self.run_id, "PlanProposal run_id")
        _required_id(self.root_node_id, "PlanProposal root_node_id")
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise PlanProposalRejected("PlanProposal version must be an integer")
        if self.version != 1:
            raise PlanProposalRejected("unsupported PlanProposal version")
        if not self.nodes:
            raise PlanProposalRejected("PlanProposal requires nodes")
        try:
            object.__setattr__(self, "status", PlanProposalStatus(self.status))
        except ValueError as exc:
            raise PlanProposalRejected(
                "PlanProposal status must be proposed"
            ) from exc
        if self.status is not PlanProposalStatus.PROPOSED:
            raise PlanProposalRejected("PlanProposal status must be proposed")
        if self.error_code or self.error_message:
            raise PlanProposalRejected(
                "proposed PlanProposal cannot contain error evidence"
            )

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "PlanProposal":
        allowed = {
            "schema",
            "version",
            "run_id",
            "invocation_id",
            "input_digest",
            "provider_config",
            "provider_config_digest",
            "status",
            "error_code",
            "error_message",
            "root_node_id",
            "nodes",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise PlanProposalRejected(
                "PlanProposal contains unknown fields: " + ", ".join(unknown)
            )
        if value.get("schema") != PLAN_PROPOSAL_SCHEMA:
            raise PlanProposalRejected("unsupported PlanProposal schema")
        version = value.get("version")
        if isinstance(version, bool) or not isinstance(version, int):
            raise PlanProposalRejected("PlanProposal version must be an integer")
        raw_nodes = value.get("nodes")
        if not isinstance(raw_nodes, list) or not all(
            isinstance(item, Mapping) for item in raw_nodes
        ):
            raise PlanProposalRejected("PlanProposal nodes must be an object array")
        raw_provider_config = value.get("provider_config", {})
        if not isinstance(raw_provider_config, Mapping):
            raise PlanProposalRejected("PlanProposal provider_config must be an object")
        return cls(
            run_id=_json_string(value.get("run_id"), "PlanProposal run_id"),
            root_node_id=_json_string(
                value.get("root_node_id"),
                "PlanProposal root_node_id",
            ),
            nodes=tuple(PlanNode.from_mapping(item) for item in raw_nodes),
            invocation_id=_json_string(
                value.get("invocation_id"),
                "PlanProposal invocation_id",
            ),
            input_digest=_json_string(
                value.get("input_digest"),
                "PlanProposal input_digest",
            ),
            provider_config_json=_json_bytes(dict(raw_provider_config)).decode("ascii"),
            provider_config_digest=_json_string(
                value.get("provider_config_digest"),
                "PlanProposal provider_config_digest",
            ),
            status=_json_string(
                value.get("status"),
                "PlanProposal status",
                default="proposed",
            ),
            error_code=_json_string(
                value.get("error_code"),
                "PlanProposal error_code",
            ),
            error_message=_json_string(
                value.get("error_message"),
                "PlanProposal error_message",
            ),
            version=version,
        )

    @property
    def provider_config(self) -> Mapping[str, object]:
        return _strict_json_object(
            self.provider_config_json,
            "PlanProposal provider_config",
        )

    def bind(self, record: "ModelInvocationRecord") -> "PlanProposal":
        for name, current, expected in (
            ("run_id", self.run_id, record.run_id),
            ("invocation_id", self.invocation_id, record.invocation_id),
            ("input_digest", self.input_digest, record.input_digest),
            (
                "provider_config_digest",
                self.provider_config_digest,
                record.provider_config_digest,
            ),
        ):
            if current and current != expected:
                raise PlanProposalRejected(
                    f"PlanProposal {name} does not match its invocation"
                )
        if (
            self.provider_config_digest
            or self.provider_config != {}
        ) and self.provider_config != record.provider_config:
            raise PlanProposalRejected(
                "PlanProposal provider_config does not match its invocation"
            )
        return replace(
            self,
            run_id=record.run_id,
            invocation_id=record.invocation_id,
            input_digest=record.input_digest,
            provider_config_json=record.provider_config_json,
            provider_config_digest=record.provider_config_digest,
            status=PlanProposalStatus.PROPOSED,
            error_code="",
            error_message="",
        )

    @property
    def digest(self) -> str:
        return _fingerprint(self.to_public_dict())

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": PLAN_PROPOSAL_SCHEMA,
            "version": self.version,
            "run_id": self.run_id,
            "invocation_id": self.invocation_id,
            "input_digest": self.input_digest,
            "provider_config": dict(self.provider_config),
            "provider_config_digest": self.provider_config_digest,
            "status": self.status.value,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "root_node_id": self.root_node_id,
            "nodes": [node.to_public_dict() for node in self.nodes],
        }


@dataclass(frozen=True)
class PlanPolicy:
    allowed_actions: frozenset[str]
    allowed_gate_schemas: frozenset[str]
    allowed_subflows: tuple[tuple[str, tuple[str, ...]], ...]
    max_serialized_bytes: int = 32 * 1024
    max_nodes: int = 32
    max_depth: int = 8
    max_parallel_width: int = 4
    max_repeat: int = 3
    max_timer_seconds: int = 300
    max_expanded_steps: int = 64
    version: int = 1

    @classmethod
    def freeze(
        cls,
        *,
        allowed_actions: set[str] | frozenset[str],
        allowed_gate_schemas: set[str] | frozenset[str],
        allowed_subflows: Mapping[str, set[str] | frozenset[str]],
        max_serialized_bytes: int = 32 * 1024,
        max_nodes: int = 32,
        max_depth: int = 8,
        max_parallel_width: int = 4,
        max_repeat: int = 3,
        max_timer_seconds: int = 300,
        max_expanded_steps: int = 64,
    ) -> "PlanPolicy":
        return cls(
            allowed_actions=frozenset(allowed_actions),
            allowed_gate_schemas=frozenset(allowed_gate_schemas),
            allowed_subflows=tuple(
                sorted((name, tuple(sorted(versions))) for name, versions in allowed_subflows.items())
            ),
            max_serialized_bytes=int(max_serialized_bytes),
            max_nodes=int(max_nodes),
            max_depth=int(max_depth),
            max_parallel_width=int(max_parallel_width),
            max_repeat=int(max_repeat),
            max_timer_seconds=int(max_timer_seconds),
            max_expanded_steps=int(max_expanded_steps),
        )

    def __post_init__(self) -> None:
        if self.version != 1:
            raise ModelPlanningError("unsupported PlanPolicy version")
        for name, value in (
            ("max_serialized_bytes", self.max_serialized_bytes),
            ("max_nodes", self.max_nodes),
            ("max_depth", self.max_depth),
            ("max_parallel_width", self.max_parallel_width),
            ("max_repeat", self.max_repeat),
            ("max_timer_seconds", self.max_timer_seconds),
            ("max_expanded_steps", self.max_expanded_steps),
        ):
            if value <= 0:
                raise ModelPlanningError(f"PlanPolicy {name} must be positive")

    @property
    def subflows(self) -> Mapping[str, frozenset[str]]:
        return {name: frozenset(versions) for name, versions in self.allowed_subflows}

    @property
    def digest(self) -> str:
        return _fingerprint(self.to_public_dict())

    def to_public_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "allowed_actions": sorted(self.allowed_actions),
            "allowed_gate_schemas": sorted(self.allowed_gate_schemas),
            "allowed_subflows": {
                name: list(versions) for name, versions in self.allowed_subflows
            },
            "limits": {
                "max_serialized_bytes": self.max_serialized_bytes,
                "max_nodes": self.max_nodes,
                "max_depth": self.max_depth,
                "max_parallel_width": self.max_parallel_width,
                "max_repeat": self.max_repeat,
                "max_timer_seconds": self.max_timer_seconds,
                "max_expanded_steps": self.max_expanded_steps,
            },
        }


@dataclass(frozen=True)
class ModelInvocationRecord:
    binding: PlanningBinding
    provider: str
    model: str
    provider_config_json: str
    status: ModelInvocationStatus
    effect_kind: str
    result_digest: str
    plan_revision_id: str
    error_code: str
    error_message: str
    started_at: float
    updated_at: float
    version: int = 1

    def __post_init__(self) -> None:
        _required_id(self.provider, "ModelInvocationRecord provider")
        _required_id(self.model, "ModelInvocationRecord model")
        provider_config = _strict_json_object(
            self.provider_config_json,
            "ModelInvocationRecord provider_config",
        )
        if _fingerprint(provider_config) != self.provider_config_digest:
            raise ModelPlanningError(
                "ModelInvocationRecord provider_config digest mismatch"
            )
        if provider_config.get("provider") != self.provider:
            raise ModelPlanningError(
                "ModelInvocationRecord provider contradicts provider_config"
            )
        if provider_config.get("model") != self.model:
            raise ModelPlanningError(
                "ModelInvocationRecord model contradicts provider_config"
            )
        try:
            object.__setattr__(self, "status", ModelInvocationStatus(self.status))
        except ValueError as exc:
            raise ModelPlanningError(
                "unsupported ModelInvocationRecord status"
            ) from exc
        if self.effect_kind != "non_deterministic":
            raise ModelPlanningError(
                "ModelInvocationRecord effect_kind must be non_deterministic"
            )
        if self.result_digest and _SHA256_REF.fullmatch(self.result_digest) is None:
            raise ModelPlanningError("ModelInvocationRecord result_digest must be SHA-256")
        if self.status is ModelInvocationStatus.SUCCEEDED:
            if not self.result_digest or not self.plan_revision_id:
                raise ModelPlanningError(
                    "succeeded ModelInvocationRecord requires result and revision identity"
                )
            if self.error_code or self.error_message:
                raise ModelPlanningError(
                    "succeeded ModelInvocationRecord cannot contain an error"
                )
        else:
            if self.result_digest or self.plan_revision_id:
                raise ModelPlanningError(
                    "non-success ModelInvocationRecord cannot contain result evidence"
                )
            if self.status is ModelInvocationStatus.RUNNING:
                if self.error_code or self.error_message:
                    raise ModelPlanningError(
                        "running ModelInvocationRecord cannot contain an error"
                    )
            elif not self.error_code:
                raise ModelPlanningError(
                    "settled non-success ModelInvocationRecord requires an error code"
                )
            else:
                _required_id(
                    self.error_code,
                    "ModelInvocationRecord error_code",
                )
                _required_text(
                    self.error_message,
                    "ModelInvocationRecord error_message",
                    max_bytes=MAX_MODEL_ERROR_MESSAGE_BYTES,
                )
        if self.updated_at < self.started_at:
            raise ModelPlanningError(
                "ModelInvocationRecord updated_at precedes started_at"
            )
        _record_number(self.started_at, "ModelInvocationRecord started_at")
        _record_number(self.updated_at, "ModelInvocationRecord updated_at")
        _record_integer(self.version, "ModelInvocationRecord version")
        if self.version != 1:
            raise ModelPlanningError("unsupported ModelInvocationRecord version")

    @property
    def binding_digest(self) -> str:
        return self.binding.digest

    @property
    def invocation_id(self) -> str:
        return self.binding.invocation_id

    @property
    def run_id(self) -> str:
        return self.binding.run_id

    @property
    def slot_id(self) -> str:
        return self.binding.slot_id

    @property
    def generation(self) -> int:
        return self.binding.generation

    @property
    def input_digest(self) -> str:
        return self.binding.input_digest

    @property
    def provider_config_digest(self) -> str:
        return self.binding.provider_config_digest

    @property
    def policy_digest(self) -> str:
        return self.binding.policy_digest

    @property
    def provider_config(self) -> Mapping[str, object]:
        return _strict_json_object(
            self.provider_config_json,
            "ModelInvocationRecord provider_config",
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": MODEL_INVOCATION_SCHEMA,
            "version": self.version,
            **self.binding.to_public_dict(),
            "provider": self.provider,
            "model": self.model,
            "provider_config": dict(self.provider_config),
            "status": self.status.value,
            "effect_kind": self.effect_kind,
            "result_digest": self.result_digest,
            "plan_revision_id": self.plan_revision_id,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_public_dict(
        cls,
        value: Mapping[str, object],
    ) -> "ModelInvocationRecord":
        if value.get("schema") != MODEL_INVOCATION_SCHEMA:
            raise ModelPlanningError("unsupported ModelInvocationRecord schema")
        provider_config = value.get("provider_config")
        if not isinstance(provider_config, Mapping):
            raise ModelPlanningError(
                "ModelInvocationRecord provider_config must be an object"
            )
        return cls(
            binding=PlanningBinding.from_public_dict(value),
            provider=_record_string(
                value.get("provider"),
                "ModelInvocationRecord provider",
            ),
            model=_record_string(
                value.get("model"),
                "ModelInvocationRecord model",
            ),
            provider_config_json=_json_bytes(dict(provider_config)).decode("ascii"),
            status=_record_string(
                value.get("status"),
                "ModelInvocationRecord status",
            ),
            effect_kind=_record_string(
                value.get("effect_kind"),
                "ModelInvocationRecord effect_kind",
            ),
            result_digest=_record_string(
                value.get("result_digest"),
                "ModelInvocationRecord result_digest",
            ),
            plan_revision_id=_record_string(
                value.get("plan_revision_id"),
                "ModelInvocationRecord plan_revision_id",
            ),
            error_code=_record_string(
                value.get("error_code"),
                "ModelInvocationRecord error_code",
            ),
            error_message=_record_string(
                value.get("error_message"),
                "ModelInvocationRecord error_message",
            ),
            started_at=_record_number(
                value.get("started_at"),
                "ModelInvocationRecord started_at",
            ),
            updated_at=_record_number(
                value.get("updated_at"),
                "ModelInvocationRecord updated_at",
            ),
            version=_record_integer(
                value.get("version"),
                "ModelInvocationRecord version",
            ),
        )


@dataclass(frozen=True)
class PlanRevision:
    revision_id: str
    binding: PlanningBinding
    proposal_digest: str
    proposal: PlanProposal
    status: PlanRevisionStatus
    ir_version: str
    error_code: str
    error_message: str
    created_at: float
    version: int = 1

    def __post_init__(self) -> None:
        _required_id(self.revision_id, "PlanRevision revision_id")
        if _SHA256_REF.fullmatch(self.proposal_digest) is None:
            raise ModelPlanningError("PlanRevision proposal_digest must be SHA-256")
        expected_revision_id = (
            "plan-revision:"
            + self.proposal_digest.removeprefix("sha256:")[:48]
        )
        if self.revision_id != expected_revision_id:
            raise ModelPlanningError(
                "PlanRevision revision_id is inconsistent with proposal_digest"
            )
        try:
            object.__setattr__(self, "status", PlanRevisionStatus(self.status))
        except ValueError as exc:
            raise ModelPlanningError("PlanRevision status must be pinned") from exc
        if self.status is not PlanRevisionStatus.PINNED:
            raise ModelPlanningError("PlanRevision status must be pinned")
        if self.ir_version != BOUNDED_PLAN_IR_VERSION:
            raise ModelPlanningError("unsupported PlanRevision IR version")
        if self.error_code or self.error_message:
            raise ModelPlanningError("pinned PlanRevision cannot contain an error")
        if self.proposal.run_id != self.run_id:
            raise ModelPlanningError("PlanRevision proposal belongs to another Run")
        for name, selected, expected in (
            (
                "invocation_id",
                self.proposal.invocation_id,
                self.invocation_id,
            ),
            ("input_digest", self.proposal.input_digest, self.input_digest),
            (
                "provider_config_digest",
                self.proposal.provider_config_digest,
                self.provider_config_digest,
            ),
        ):
            if selected != expected:
                raise ModelPlanningError(
                    f"PlanRevision proposal {name} does not match its binding"
                )
        if _fingerprint(self.proposal.provider_config) != self.provider_config_digest:
            raise ModelPlanningError(
                "PlanRevision proposal provider_config digest mismatch"
            )
        if self.proposal.digest != self.proposal_digest:
            raise ModelPlanningError("PlanRevision proposal digest mismatch")
        _record_number(self.created_at, "PlanRevision created_at")
        _record_integer(self.version, "PlanRevision version")
        if self.version != 1:
            raise ModelPlanningError("unsupported PlanRevision version")

    @property
    def run_id(self) -> str:
        return self.binding.run_id

    @property
    def slot_id(self) -> str:
        return self.binding.slot_id

    @property
    def generation(self) -> int:
        return self.binding.generation

    @property
    def invocation_id(self) -> str:
        return self.binding.invocation_id

    @property
    def input_digest(self) -> str:
        return self.binding.input_digest

    @property
    def provider_config_digest(self) -> str:
        return self.binding.provider_config_digest

    @property
    def policy_digest(self) -> str:
        return self.binding.policy_digest

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": PLAN_REVISION_SCHEMA,
            "version": self.version,
            "revision_id": self.revision_id,
            **self.binding.to_public_dict(),
            "proposal_digest": self.proposal_digest,
            "proposal": self.proposal.to_public_dict(),
            "status": self.status.value,
            "ir_version": self.ir_version,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "created_at": self.created_at,
        }

    @classmethod
    def from_public_dict(cls, value: Mapping[str, object]) -> "PlanRevision":
        if value.get("schema") != PLAN_REVISION_SCHEMA:
            raise ModelPlanningError("unsupported PlanRevision schema")
        raw_proposal = value.get("proposal")
        if not isinstance(raw_proposal, Mapping):
            raise ModelPlanningError("PlanRevision proposal must be an object")
        return cls(
            revision_id=_record_string(
                value.get("revision_id"),
                "PlanRevision revision_id",
            ),
            binding=PlanningBinding.from_public_dict(value),
            proposal_digest=_record_string(
                value.get("proposal_digest"),
                "PlanRevision proposal_digest",
            ),
            proposal=PlanProposal.from_mapping(raw_proposal),
            status=_record_string(value.get("status"), "PlanRevision status"),
            ir_version=_record_string(
                value.get("ir_version"),
                "PlanRevision ir_version",
            ),
            error_code=_record_string(
                value.get("error_code"),
                "PlanRevision error_code",
            ),
            error_message=_record_string(
                value.get("error_message"),
                "PlanRevision error_message",
            ),
            created_at=_record_number(
                value.get("created_at"),
                "PlanRevision created_at",
            ),
            version=_record_integer(
                value.get("version"),
                "PlanRevision version",
            ),
        )


@dataclass(frozen=True)
class ModelAdapterResult:
    status: ModelAdapterStatus
    proposal: Mapping[str, object] | None = None
    error_code: str = ""
    error_message: str = ""

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "status", ModelAdapterStatus(self.status))
        except ValueError as exc:
            raise ModelPlanningError(
                "unsupported model Adapter result status"
            ) from exc
        if self.status is ModelAdapterStatus.SUCCEEDED and not isinstance(
            self.proposal,
            Mapping,
        ):
            raise ModelPlanningError(
                "succeeded model Adapter result requires a proposal object"
            )
        if (
            self.status is not ModelAdapterStatus.SUCCEEDED
            and self.proposal is not None
        ):
            raise ModelPlanningError(
                "non-success model Adapter result cannot contain a proposal"
            )
        if self.status in {
            ModelAdapterStatus.UNKNOWN,
            ModelAdapterStatus.FAILED,
        } and not self.error_code:
            raise ModelPlanningError(
                "non-success model Adapter result requires an error code"
            )
        if self.status is not ModelAdapterStatus.SUCCEEDED:
            _required_id(self.error_code, "model Adapter error_code")
            _required_text(
                self.error_message,
                "model Adapter error_message",
                max_bytes=MAX_MODEL_ERROR_MESSAGE_BYTES,
            )

    @classmethod
    def succeeded(
        cls,
        proposal: PlanProposal | Mapping[str, object],
    ) -> "ModelAdapterResult":
        return cls(
            status=ModelAdapterStatus.SUCCEEDED,
            proposal=(
                proposal.to_public_dict()
                if isinstance(proposal, PlanProposal)
                else dict(proposal)
            ),
        )

    @classmethod
    def unknown(
        cls,
        message: str = "model invocation outcome is unknown",
    ) -> "ModelAdapterResult":
        return cls(
            status=ModelAdapterStatus.UNKNOWN,
            error_code="model_outcome_unknown",
            error_message=_bounded_error_message(
                message,
                "model invocation outcome is unknown",
            ),
        )

    @classmethod
    def failed(cls, code: str, message: str) -> "ModelAdapterResult":
        return cls(
            status=ModelAdapterStatus.FAILED,
            error_code=code,
            error_message=_bounded_error_message(
                message,
                "model invocation failed",
            ),
        )


class ModelAdapter(Protocol):
    configuration: ModelConfiguration

    def invoke(self, request: PlanningRequest) -> ModelAdapterResult: ...

    def reconcile(self, record: ModelInvocationRecord) -> ModelAdapterResult: ...


class DeterministicFakeModelAdapter:
    """Script model outcomes for hermetic CI without credentials or network."""

    def __init__(
        self,
        *,
        invoke_results: tuple[ModelAdapterResult, ...],
        reconcile_results: tuple[ModelAdapterResult, ...] = (),
        configuration: ModelConfiguration | None = None,
    ) -> None:
        if not invoke_results:
            raise ModelPlanningError(
                "deterministic fake requires at least one invoke result"
            )
        self.configuration = configuration or ModelConfiguration.freeze(
            provider="deterministic-fake",
            model="bounded-planner-v1",
            parameters={"temperature": 0, "seed": 1},
            timeout_seconds=1.0,
        )
        self._invoke_results = invoke_results
        self._reconcile_results = reconcile_results or invoke_results
        self.invoke_calls = 0
        self.reconcile_calls = 0

    @staticmethod
    def _select(
        results: tuple[ModelAdapterResult, ...],
        index: int,
    ) -> ModelAdapterResult:
        return results[min(index, len(results) - 1)]

    def invoke(self, request: PlanningRequest) -> ModelAdapterResult:
        result = self._select(self._invoke_results, self.invoke_calls)
        self.invoke_calls += 1
        return result

    def reconcile(self, record: ModelInvocationRecord) -> ModelAdapterResult:
        result = self._select(self._reconcile_results, self.reconcile_calls)
        self.reconcile_calls += 1
        return result


@dataclass(frozen=True)
class ModelPlanningClaim:
    record: ModelInvocationRecord
    created: bool


@dataclass(frozen=True)
class ModelPlanningSettlement:
    record: ModelInvocationRecord
    revision: PlanRevision | None
    applied: bool

    def __post_init__(self) -> None:
        if self.record.status is ModelInvocationStatus.SUCCEEDED:
            if self.revision is None:
                raise ModelPlanningError("pinned PlanRevision is unavailable")
            for name, selected, expected in (
                (
                    "revision_id",
                    self.revision.revision_id,
                    self.record.plan_revision_id,
                ),
                (
                    "binding",
                    self.revision.binding.digest,
                    self.record.binding_digest,
                ),
                (
                    "result_digest",
                    self.revision.proposal_digest,
                    self.record.result_digest,
                ),
            ):
                if selected != expected:
                    raise ModelInvocationConflict(
                        f"model planning settlement {name} mismatch"
                    )
        elif self.revision is not None:
            raise ModelInvocationConflict(
                "non-success model planning settlement cannot contain a revision"
            )


def _terminal_settlement(
    record: ModelInvocationRecord,
    load_revision: Callable[[str], PlanRevision | None],
) -> ModelPlanningSettlement | None:
    if record.status not in _TERMINAL_INVOCATION_STATUSES:
        return None
    revision = (
        load_revision(record.plan_revision_id)
        if record.status is ModelInvocationStatus.SUCCEEDED
        else None
    )
    return ModelPlanningSettlement(record, revision, applied=False)


def _select_settlement(
    current: ModelInvocationRecord,
    incoming: ModelInvocationRecord,
    revision: PlanRevision | None,
    load_revision: Callable[[str], PlanRevision | None],
) -> ModelPlanningSettlement:
    if current.binding_digest != incoming.binding_digest:
        raise ModelInvocationConflict(
            "model invocation settlement has a different binding"
        )
    terminal = _terminal_settlement(current, load_revision)
    if terminal is not None:
        return terminal
    return ModelPlanningSettlement(incoming, revision, applied=True)


class ModelPlanningRepository(Protocol):
    def claim(self, record: ModelInvocationRecord) -> ModelPlanningClaim: ...

    def load_invocation(self, invocation_id: str) -> ModelInvocationRecord | None: ...

    def load_revision(self, revision_id: str) -> PlanRevision | None: ...

    def list_revisions(self) -> tuple[PlanRevision, ...]: ...

    def settle(
        self,
        record: ModelInvocationRecord,
        revision: PlanRevision | None,
    ) -> ModelPlanningSettlement: ...


class InMemoryModelPlanningRepository:
    def __init__(self) -> None:
        self._invocations: dict[str, ModelInvocationRecord] = {}
        self._revisions: dict[str, PlanRevision] = {}
        self._lock = threading.RLock()

    def claim(self, record: ModelInvocationRecord) -> ModelPlanningClaim:
        with self._lock:
            current = self._invocations.get(record.invocation_id)
            if current is not None:
                return ModelPlanningClaim(current, created=False)
            self._invocations[record.invocation_id] = record
            return ModelPlanningClaim(record, created=True)

    def load_invocation(self, invocation_id: str) -> ModelInvocationRecord | None:
        with self._lock:
            return self._invocations.get(invocation_id)

    def load_revision(self, revision_id: str) -> PlanRevision | None:
        with self._lock:
            return self._revisions.get(revision_id)

    def list_revisions(self) -> tuple[PlanRevision, ...]:
        with self._lock:
            return tuple(
                self._revisions[key] for key in sorted(self._revisions)
            )

    def settle(
        self,
        record: ModelInvocationRecord,
        revision: PlanRevision | None,
    ) -> ModelPlanningSettlement:
        with self._lock:
            current = self._invocations.get(record.invocation_id)
            if current is None:
                raise ModelPlanningError(
                    "model invocation must be claimed before settlement"
                )
            settlement = _select_settlement(
                current,
                record,
                revision,
                self._revisions.get,
            )
            if not settlement.applied:
                return settlement
            if revision is not None:
                existing = self._revisions.get(revision.revision_id)
                if existing is not None and existing != revision:
                    raise ModelInvocationConflict(
                        "PlanRevision identity is already bound to different content"
                    )
            if revision is not None:
                self._revisions.setdefault(revision.revision_id, revision)
            self._invocations[record.invocation_id] = record
            return settlement


class SQLiteModelPlanningRepository:
    """Persist model invocation and immutable PlanRevision records locally."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            connection.close()
            raise
        return connection

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS model_planning_invocations ("
                "invocation_id TEXT PRIMARY KEY, document_json TEXT NOT NULL, "
                "updated_at REAL NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS model_planning_revisions ("
                "revision_id TEXT PRIMARY KEY, document_json TEXT NOT NULL, "
                "created_at REAL NOT NULL)"
            )

    @staticmethod
    def _record(row: sqlite3.Row | None) -> ModelInvocationRecord | None:
        if row is None:
            return None
        value = _strict_json_object(
            str(row["document_json"]),
            "persisted ModelInvocationRecord",
        )
        return ModelInvocationRecord.from_public_dict(value)

    @staticmethod
    def _revision(row: sqlite3.Row | None) -> PlanRevision | None:
        if row is None:
            return None
        value = _strict_json_object(
            str(row["document_json"]),
            "persisted PlanRevision",
        )
        return PlanRevision.from_public_dict(value)

    def claim(self, record: ModelInvocationRecord) -> ModelPlanningClaim:
        document = _json_bytes(record.to_public_dict()).decode("ascii")
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO model_planning_invocations "
                "(invocation_id, document_json, updated_at) VALUES (?, ?, ?)",
                (record.invocation_id, document, record.updated_at),
            )
            row = connection.execute(
                "SELECT document_json FROM model_planning_invocations "
                "WHERE invocation_id = ?",
                (record.invocation_id,),
            ).fetchone()
        selected = self._record(row)
        if selected is None:
            raise ModelPlanningError("model invocation claim was not persisted")
        return ModelPlanningClaim(selected, created=cursor.rowcount == 1)

    def load_invocation(self, invocation_id: str) -> ModelInvocationRecord | None:
        with self._lock, self._connection() as connection:
            row = connection.execute(
                "SELECT document_json FROM model_planning_invocations "
                "WHERE invocation_id = ?",
                (invocation_id,),
            ).fetchone()
        return self._record(row)

    def load_revision(self, revision_id: str) -> PlanRevision | None:
        with self._lock, self._connection() as connection:
            row = connection.execute(
                "SELECT document_json FROM model_planning_revisions "
                "WHERE revision_id = ?",
                (revision_id,),
            ).fetchone()
        return self._revision(row)

    def list_revisions(self) -> tuple[PlanRevision, ...]:
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                "SELECT document_json FROM model_planning_revisions "
                "ORDER BY revision_id"
            ).fetchall()
        return tuple(
            revision
            for revision in (self._revision(row) for row in rows)
            if revision is not None
        )

    def settle(
        self,
        record: ModelInvocationRecord,
        revision: PlanRevision | None,
    ) -> ModelPlanningSettlement:
        record_document = _json_bytes(record.to_public_dict()).decode("ascii")
        revision_document = (
            _json_bytes(revision.to_public_dict()).decode("ascii")
            if revision is not None
            else ""
        )
        with self._lock, self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT document_json FROM model_planning_invocations "
                "WHERE invocation_id = ?",
                (record.invocation_id,),
            ).fetchone()
            if current is None:
                raise ModelPlanningError(
                    "model invocation must be claimed before settlement"
                )
            selected = self._record(current)
            if selected is None:
                raise ModelPlanningError("persisted ModelInvocationRecord is invalid")
            settlement = _select_settlement(
                selected,
                record,
                revision,
                lambda revision_id: self._revision(
                    connection.execute(
                        "SELECT document_json FROM model_planning_revisions "
                        "WHERE revision_id = ?",
                        (revision_id,),
                    ).fetchone()
                ),
            )
            if not settlement.applied:
                return settlement
            if revision is not None:
                existing = connection.execute(
                    "SELECT document_json FROM model_planning_revisions "
                    "WHERE revision_id = ?",
                    (revision.revision_id,),
                ).fetchone()
                if (
                    existing is not None
                    and str(existing["document_json"]) != revision_document
                ):
                    raise ModelInvocationConflict(
                        "PlanRevision identity is already bound to different content"
                    )
                connection.execute(
                    "INSERT OR IGNORE INTO model_planning_revisions "
                    "(revision_id, document_json, created_at) VALUES (?, ?, ?)",
                    (revision.revision_id, revision_document, revision.created_at),
                )
            connection.execute(
                "UPDATE model_planning_invocations SET document_json = ?, updated_at = ? "
                "WHERE invocation_id = ?",
                (record_document, record.updated_at, record.invocation_id),
            )
        return settlement


@dataclass(frozen=True)
class PlanningDecision:
    status: PlanningDecisionStatus
    record: ModelInvocationRecord
    revision: PlanRevision | None
    reused: bool = False
    reconciled: bool = False

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "status", PlanningDecisionStatus(self.status))
        except ValueError as exc:
            raise ModelPlanningError(
                "unsupported model planning decision status"
            ) from exc


class PlanResolver:
    """Record, reconcile, validate, and pin one model planning Effect."""

    def __init__(
        self,
        repository: ModelPlanningRepository,
        adapter: ModelAdapter,
        *,
        policy: PlanPolicy,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.repository = repository
        self.adapter = adapter
        self.policy = policy
        self._clock = clock
        self._lock = threading.RLock()

    def resolve(self, request: PlanningRequest) -> PlanningDecision:
        with self._lock:
            now = float(self._clock())
            configuration = self.adapter.configuration
            input_digest = _fingerprint(
                {
                    "planning_input": request.planning_input.to_public_dict(),
                    "provider_config_digest": configuration.digest,
                    "policy_digest": self.policy.digest,
                    "ir_version": BOUNDED_PLAN_IR_VERSION,
                }
            )
            binding = PlanningBinding.freeze(
                request,
                input_digest=input_digest,
                provider_config_digest=configuration.digest,
                policy_digest=self.policy.digest,
            )
            candidate = ModelInvocationRecord(
                binding=binding,
                provider=configuration.provider,
                model=configuration.model,
                provider_config_json=_json_bytes(
                    configuration.to_public_dict()
                ).decode("ascii"),
                status=ModelInvocationStatus.RUNNING,
                effect_kind="non_deterministic",
                result_digest="",
                plan_revision_id="",
                error_code="",
                error_message="",
                started_at=now,
                updated_at=now,
            )
            claim = self.repository.claim(candidate)
            record = claim.record
            if record.binding_digest != candidate.binding_digest:
                raise ModelInvocationConflict(
                    "model invocation identity is already bound to different input or configuration"
                )
            if record.status is ModelInvocationStatus.SUCCEEDED:
                revision = self.repository.load_revision(record.plan_revision_id)
                return self._decision(
                    ModelPlanningSettlement(record, revision, applied=False),
                    reconciled=False,
                )
            if record.status in {
                ModelInvocationStatus.FAILED,
                ModelInvocationStatus.REJECTED,
            }:
                return PlanningDecision(
                    record.status,
                    record,
                    None,
                    reused=True,
                )
            if claim.created:
                try:
                    result = self.adapter.invoke(request)
                except Exception as exc:
                    result = ModelAdapterResult.unknown(str(exc))
                return self._settle(record, result, reconciled=False)
            try:
                result = self.adapter.reconcile(record)
            except Exception as exc:
                result = ModelAdapterResult.unknown(str(exc))
            return self._settle(record, result, reconciled=True)

    def _decision(
        self,
        settlement: ModelPlanningSettlement,
        *,
        reconciled: bool,
    ) -> PlanningDecision:
        if settlement.record.status is ModelInvocationStatus.SUCCEEDED:
            if settlement.revision is None:
                raise ModelPlanningError("pinned PlanRevision is unavailable")
            self._validate_proposal(
                settlement.revision.proposal,
                run_id=settlement.record.run_id,
            )
            return PlanningDecision(
                PlanningDecisionStatus.ACCEPTED,
                settlement.record,
                settlement.revision,
                reused=not settlement.applied,
                reconciled=reconciled,
            )
        return PlanningDecision(
            settlement.record.status,
            settlement.record,
            None,
            reused=not settlement.applied,
            reconciled=reconciled,
        )

    def _reject(
        self,
        record: ModelInvocationRecord,
        message: str,
        *,
        reconciled: bool,
    ) -> PlanningDecision:
        selected = replace(
            record,
            status=ModelInvocationStatus.REJECTED,
            error_code="plan_proposal_rejected",
            error_message=_bounded_error_message(
                message,
                "PlanProposal was rejected",
            ),
            updated_at=float(self._clock()),
        )
        settlement = self.repository.settle(selected, None)
        return self._decision(
            settlement,
            reconciled=reconciled,
        )

    def _settle(
        self,
        record: ModelInvocationRecord,
        result: ModelAdapterResult,
        *,
        reconciled: bool,
    ) -> PlanningDecision:
        now = float(self._clock())
        if (
            result.status is not ModelAdapterStatus.SUCCEEDED
            or result.proposal is None
        ):
            selected = replace(
                record,
                status=result.status,
                error_code=result.error_code,
                error_message=result.error_message,
                updated_at=now,
            )
            settlement = self.repository.settle(selected, None)
            return self._decision(
                settlement,
                reconciled=reconciled,
            )
        try:
            raw_proposal_bytes = len(_json_bytes(result.proposal))
            if raw_proposal_bytes > min(
                self.policy.max_serialized_bytes,
                self.adapter.configuration.max_output_bytes,
            ):
                raise PlanProposalRejected(
                    "PlanProposal exceeds the serialized byte budget"
                )
            proposal = PlanProposal.from_mapping(result.proposal).bind(record)
            self._validate_proposal(proposal, run_id=record.run_id)
        except (ModelPlanningError, TypeError, ValueError) as exc:
            return self._reject(
                record,
                str(exc),
                reconciled=reconciled,
            )
        proposal_digest = proposal.digest
        revision_id = "plan-revision:" + proposal_digest.removeprefix("sha256:")[:48]
        revision = PlanRevision(
            revision_id=revision_id,
            binding=record.binding,
            proposal_digest=proposal_digest,
            proposal=proposal,
            status=PlanRevisionStatus.PINNED,
            ir_version=BOUNDED_PLAN_IR_VERSION,
            error_code="",
            error_message="",
            created_at=now,
        )
        selected = replace(
            record,
            status=ModelInvocationStatus.SUCCEEDED,
            result_digest=proposal_digest,
            plan_revision_id=revision_id,
            error_code="",
            error_message="",
            updated_at=now,
        )
        settlement = self.repository.settle(selected, revision)
        return self._decision(
            settlement,
            reconciled=reconciled,
        )

    def _expand_action(
        self,
        node: PlanNode,
        depth: int,
        *,
        walk: Callable[..., int],
        require: Callable[[str, str], PlanNode],
    ) -> int:
        if node.action not in self.policy.allowed_actions:
            raise PlanProposalRejected(f"unknown Plan action: {node.action}")
        if not node.compensation:
            return 0
        compensation = require(node.compensation, node.node_id)
        if (
            compensation.kind is not PlanNodeKind.ACTION
            or not compensation.compensation_only
        ):
            raise PlanProposalRejected(
                "compensation must reference a compensation-only action"
            )
        return walk(
            compensation.node_id,
            depth + 1,
            compensation_path=True,
        )

    def _expand_sequence(
        self,
        node: PlanNode,
        depth: int,
        *,
        walk: Callable[..., int],
        require: Callable[[str, str], PlanNode],
    ) -> int:
        del require
        if not node.children:
            raise PlanProposalRejected("sequence requires child references")
        return sum(walk(child, depth + 1) for child in node.children)

    def _expand_choice(
        self,
        node: PlanNode,
        depth: int,
        *,
        walk: Callable[..., int],
        require: Callable[[str, str], PlanNode],
    ) -> int:
        del require
        if len(node.branches) < 2:
            raise PlanProposalRejected("choice requires at least two branches")
        return max(walk(branch, depth + 1) for branch in node.branches)

    def _expand_parallel(
        self,
        node: PlanNode,
        depth: int,
        *,
        walk: Callable[..., int],
        require: Callable[[str, str], PlanNode],
    ) -> int:
        del require
        if (
            not node.branches
            or len(node.branches) > self.policy.max_parallel_width
        ):
            raise PlanProposalRejected("parallel width exceeds its bound")
        return sum(walk(branch, depth + 1) for branch in node.branches)

    def _expand_repeat(
        self,
        node: PlanNode,
        depth: int,
        *,
        walk: Callable[..., int],
        require: Callable[[str, str], PlanNode],
    ) -> int:
        if not 1 <= node.repeat_max <= self.policy.max_repeat:
            raise PlanProposalRejected("repeat must have a bounded maximum")
        body = require(node.body, node.node_id)
        return node.repeat_max * walk(body.node_id, depth + 1)

    def _expand_timer(
        self,
        node: PlanNode,
        depth: int,
        *,
        walk: Callable[..., int],
        require: Callable[[str, str], PlanNode],
    ) -> int:
        del depth, walk, require
        if not 1 <= node.timer_seconds <= self.policy.max_timer_seconds:
            raise PlanProposalRejected("timer exceeds its bound")
        return 0

    def _expand_gate(
        self,
        node: PlanNode,
        depth: int,
        *,
        walk: Callable[..., int],
        require: Callable[[str, str], PlanNode],
    ) -> int:
        del depth, walk, require
        if node.gate_schema not in self.policy.allowed_gate_schemas:
            raise PlanProposalRejected(f"unknown Gate schema: {node.gate_schema}")
        return 0

    def _expand_subflow(
        self,
        node: PlanNode,
        depth: int,
        *,
        walk: Callable[..., int],
        require: Callable[[str, str], PlanNode],
    ) -> int:
        del depth, walk, require
        versions = self.policy.subflows.get(node.subflow, frozenset())
        if node.subflow_version not in versions:
            raise PlanProposalRejected(
                "subflow reference is unknown or not version-pinned"
            )
        return 0

    def _validate_proposal(self, proposal: PlanProposal, *, run_id: str) -> None:
        if proposal.run_id != run_id:
            raise PlanProposalRejected("PlanProposal belongs to another Run")
        if len(_json_bytes(proposal.to_public_dict())) > self.policy.max_serialized_bytes:
            raise PlanProposalRejected("PlanProposal exceeds the serialized byte budget")
        if len(proposal.nodes) > self.policy.max_nodes:
            raise PlanProposalRejected("PlanProposal exceeds the node budget")
        node_specs: Mapping[
            PlanNodeKind,
            tuple[frozenset[str], Callable[..., int]],
        ] = {
            PlanNodeKind.ACTION: (
                frozenset({"action", "compensation", "compensation_only"}),
                self._expand_action,
            ),
            PlanNodeKind.SEQUENCE: (
                frozenset({"children"}),
                self._expand_sequence,
            ),
            PlanNodeKind.CHOICE: (
                frozenset({"branches"}),
                self._expand_choice,
            ),
            PlanNodeKind.PARALLEL: (
                frozenset({"branches"}),
                self._expand_parallel,
            ),
            PlanNodeKind.REPEAT: (
                frozenset({"body", "repeat_max"}),
                self._expand_repeat,
            ),
            PlanNodeKind.TIMER: (
                frozenset({"timer_seconds"}),
                self._expand_timer,
            ),
            PlanNodeKind.GATE: (
                frozenset({"gate_schema"}),
                self._expand_gate,
            ),
            PlanNodeKind.SUBFLOW: (
                frozenset({"subflow", "subflow_version"}),
                self._expand_subflow,
            ),
        }
        nodes: dict[str, PlanNode] = {}
        for node in proposal.nodes:
            if node.node_id in nodes:
                raise PlanProposalRejected(f"duplicate Plan node: {node.node_id}")
            selected_fields = {
                "children": bool(node.children),
                "branches": bool(node.branches),
                "body": bool(node.body),
                "action": bool(node.action),
                "repeat_max": bool(node.repeat_max),
                "timer_seconds": bool(node.timer_seconds),
                "gate_schema": bool(node.gate_schema),
                "subflow": bool(node.subflow),
                "subflow_version": bool(node.subflow_version),
                "compensation": bool(node.compensation),
                "compensation_only": node.compensation_only,
            }
            allowed_fields, _ = node_specs[node.kind]
            invalid_fields = sorted(
                name
                for name, present in selected_fields.items()
                if present and name not in allowed_fields
            )
            if invalid_fields:
                raise PlanProposalRejected(
                    f"Plan node {node.node_id} has fields invalid for {node.kind.value}: "
                    + ", ".join(invalid_fields)
                )
            nodes[node.node_id] = node
        if proposal.root_node_id not in nodes:
            raise PlanProposalRejected("PlanProposal root reference is invalid")

        visiting: set[str] = set()
        visited: set[str] = set()
        def require(reference: str, owner: str) -> PlanNode:
            selected = nodes.get(reference)
            if selected is None:
                raise PlanProposalRejected(
                    f"Plan node {owner} references unknown node {reference}"
                )
            return selected

        def walk(node_id: str, depth: int, *, compensation_path: bool = False) -> int:
            if depth > self.policy.max_depth:
                raise PlanProposalRejected("PlanProposal exceeds the depth budget")
            if node_id in visiting:
                raise PlanProposalRejected("PlanProposal contains a cycle")
            node = require(node_id, node_id)
            if node.compensation_only and not compensation_path:
                raise PlanProposalRejected(
                    "compensation-only action is reachable from normal execution"
                )
            visiting.add(node_id)
            _, expander = node_specs[node.kind]
            expanded = 1 + expander(
                node,
                depth,
                walk=walk,
                require=require,
            )
            visiting.remove(node_id)
            visited.add(node_id)
            if expanded > self.policy.max_expanded_steps:
                raise PlanProposalRejected("PlanProposal exceeds the expanded-step budget")
            return expanded

        walk(proposal.root_node_id, 1)
        if visited != set(nodes):
            unreachable = ", ".join(sorted(set(nodes) - visited))
            raise PlanProposalRejected(f"PlanProposal has unreachable nodes: {unreachable}")
