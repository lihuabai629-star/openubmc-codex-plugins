"""Persistent bounded context for openUBMC MCP operations.

The module deliberately keeps transport and domain execution outside.  It owns
case history, idempotency receipts, evidence blobs, compact agent envelopes,
and lifecycle policy while existing Target Runtime objects keep owning remote
connections, target identity, epochs, and mutation journals.
"""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
import gzip
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
from typing import Protocol
import uuid

from .catalog import OperationCatalog, OperationDescriptor
from .closeout import (
    AcceptancePlan,
    aggregate_case_closeout,
    build_closeout_bundle,
    case_terminal_status,
    render_markdown,
)
from .contracts import RUNTIME_API_VERSION
from .diagnostic_receipt import (
    DiagnosticStatus,
    build_diagnostic_receipt,
    latest_diagnostic_receipt,
)
from .diagnosis_record import accepted_diagnosis_record
from .effect_runner import EffectIntent, EffectSettlementMode, PreparedEffect
from .evidence_store import EvidenceQuery
from .mutation import (
    MutationAuthorizationDenied,
    MutationOperationConflict,
    UnfinishedMutationExists,
    TaskAuthorizationPolicy,
    mutation_journal_operation_status,
)
from .operation_contracts import DEFAULT_OPERATION_CONTRACTS
from .redaction import is_secret_key, redact_text
from .run_store import (
    RunEvent,
    upcast_run_events,
)
from .semantic_runtime import GateConflict
from .observation import observation_consistency, observation_reusable
from .orchestration import enforce_fresh_verification
from .workflow import (
    DEFAULT_PHASE_REGISTRY,
    DEFAULT_WORKFLOW_DEFINITIONS,
    WorkflowDefinitions,
    WorkflowStepDefinition,
)


CONTEXT_RUNTIME_SCHEMA = f"{RUNTIME_API_VERSION}/context-runtime"
OBSERVATION_SOURCE_SCHEMA = f"{RUNTIME_API_VERSION}/observation-source-v1"
CONTEXT_RUNTIME_STORAGE_VERSION = 1
AGENT_ENVELOPE_SCHEMA = f"{RUNTIME_API_VERSION}/agent-envelope"
AGENT_ENVELOPE_MAX_BYTES = 24_576
DEFAULT_CASE_RETENTION_SECONDS = 7 * 24 * 60 * 60
DEFAULT_STORAGE_SOFT_LIMIT_BYTES = 1024 * 1024 * 1024
DEFAULT_EVIDENCE_READ_BYTES = 64 * 1024
MAX_EVIDENCE_READ_BYTES = 1024 * 1024
DEFAULT_PROJECTION_CACHE_BYTES = 8 * 1024 * 1024
MAX_PROJECTED_OPERATIONS = 128
MAX_PROJECTED_PHASE_RECORDS = 32
MAX_PROJECTED_EVIDENCE_REFS = 256
MAX_OPERATOR_PROJECTED_RUNS = 16
MAX_OBSERVATION_SOURCE_BYTES = 8 * 1024 * 1024
MAX_AUTOMATIC_OBSERVATION_SCAN_BLOBS = 256
MAX_AUTOMATIC_OBSERVATION_SCAN_BYTES = 32 * 1024 * 1024
OBSERVATION_REUSE_MAX_AGE_SECONDS = 15 * 60
AUTOMATIC_OBSERVATION_REUSE_MAX_AGE_SECONDS = 30


def _diagnostic_receipt_event_fields(
    operation: str,
    value: Mapping[str, object],
    arguments: Mapping[str, object],
    evidence_refs: Iterable[Mapping[str, object]],
    *,
    closeout_stage: str,
) -> dict[str, object]:
    receipt = build_diagnostic_receipt(
        operation,
        value,
        arguments,
        tuple(evidence_refs),
        closeout_stage=closeout_stage,
    )
    return (
        {"diagnostic_receipt": receipt.to_public_dict()}
        if receipt is not None
        else {}
    )


def _operation_closeout_stage(
    operation: str,
    overrides: Mapping[str, str],
) -> str:
    if operation in overrides:
        return str(overrides[operation])
    try:
        return DEFAULT_OPERATION_CONTRACTS.require(operation).closeout_stage
    except ValueError:
        return ""


CONTEXT_WORKFLOW_STEP_ARGUMENT = "_context_workflow_step"
_DELIVERY_STRATEGIES = {"source-only", "live-patch", "build-upgrade"}
_TASK_POLICY_FIELD = "author" + "ization"
_INTENT_ENTRY_DOMAINS = {
    "diagnose-and-fix": "debug",
    "bundle-and-diagnose": "log_analyzer",
    "live-patch": "live_patch",
    "rollback": "live_patch",
    "upgrade-and-verify": "upgrade",
}
_OPERATION_ENTRY_DOMAINS = DEFAULT_OPERATION_CONTRACTS.operation_domains()
_WORKFLOW_CONTROL_OPERATIONS = frozenset({"workflow.advance", "workflow.next"})
_WORKFLOW_SECTION_PROTECTED_ARGUMENTS = frozenset(
    {
        "case_id",
        "expected_revision",
        "idempotency_key",
        "intent",
        "final_purpose",
        "entry_domain",
        "delivery_strategy",
        "authorized_exceptions",
        "change_boundary",
        "include_closeout_bundle",
        "max_steps",
        "ip",
        "targets",
        "target_id",
        "target_role",
        "role",
        "ssh_port",
        "ssh_user",
        "ssh_user_env",
        "ssh_password_env",
        "ssh_identity_file",
        "ssh_host_key_policy",
        "ssh_known_hosts_file",
        "allow_insecure_host_key",
        "telnet_port",
        "telnet_user",
        "telnet_user_env",
        "telnet_password_env",
        "redfish_port",
        "redfish_user",
        "redfish_user_env",
        "redfish_password_env",
        "allow_insecure_tls",
    }
)
_CONTEXT_CONTROL_ARGUMENTS = frozenset(
    {
        "case_id",
        "expected_revision",
        "idempotency_key",
        "deadline",
        "max_steps",
        "include_closeout_bundle",
        "_workflow_cycle_id",
        "_workflow_step_id",
        "_workflow_step_kind",
        "_workflow_target_version",
        "_workflow_request_fingerprint",
        "_workflow_definition_id",
        "_workflow_definition_version",
        "_workflow_definition_fingerprint",
        "_workflow_execution_id",
        "_workflow_attempt",
        "_workflow_input_fingerprint",
        "_workflow_target_epoch",
        "_context_entry_operation",
    }
)
_TARGET_REPLACEMENT_RESET_ARGUMENTS = frozenset(
    {
        "ip",
        "targets",
        "target_id",
        "target_role",
        "role",
        "ssh_port",
        "telnet_port",
        "redfish_port",
    }
)
_TARGET_VERSION_ARGUMENTS = frozenset(
    {
        "ssh_port",
        "telnet_port",
        "redfish_port",
    }
)
_DEBUG_DOMAIN_ARGUMENTS = {
    "alarm_call_args",
    "alarm_call_signature",
    "alarm_discovery_path_limit",
    "alarm_discovery_service_limit",
    "alarm_limit",
    "alarm_path",
    "alarm_service",
    "allow_insecure_host_key",
    "compact_json",
    "concurrency",
    "correlate_alarm_limit",
    "correlation_time_window",
    "deadline",
    "files",
    "hardware_acceptance",
    "include_rotated",
    "ip",
    "keyword",
    "lines",
    "log_max_bytes",
    "logs",
    "mdb_concurrency",
    "mdb_expand_classes",
    "mdb_only",
    "mdb_queries",
    "no_freshness",
    "no_source_correlation",
    "profile",
    "reference_role",
    "rotated_limit",
    "skip_telnet",
    "source_max_matches",
    "source_root",
    "ssh_host_key_policy",
    "ssh_identity_file",
    "ssh_known_hosts_file",
    "ssh_password_env",
    "ssh_port",
    "ssh_user",
    "ssh_user_env",
    "target_id",
    "targets",
    "telnet_password_env",
    "telnet_port",
    "telnet_user",
    "telnet_user_env",
    "timeout",
    "tree_head",
    "tree_service",
    "_minimum_target_epoch",
    "intent",
    "final_purpose",
    "entry_domain",
    "delivery_strategy",
    "authorized_exceptions",
    CONTEXT_WORKFLOW_STEP_ARGUMENT,
}


def _process_start_marker(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ""
    closing = raw.rfind(")")
    fields = raw[closing + 2 :].split() if closing >= 0 else []
    return fields[19] if len(fields) > 19 else ""


def _process_owner_is_active(pid: int, started: str) -> bool:
    if pid <= 0:
        return False
    observed = _process_start_marker(pid)
    if observed:
        return not started or observed == started
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


class ContextRuntimeError(RuntimeError):
    """Base error with a stable external code."""

    code = "context_runtime_error"


class RevisionConflict(ContextRuntimeError):
    code = "revision_conflict"


class IdempotencyConflict(ContextRuntimeError):
    code = "idempotency_conflict"


class OperationAlreadyInProgress(ContextRuntimeError):
    code = "operation_in_progress"


class EvidenceUnavailable(ContextRuntimeError):
    code = "evidence_unavailable"


class CaseNotFound(ContextRuntimeError):
    code = "case_not_found"


class CaseClosed(ContextRuntimeError):
    code = "case_closed"


class CaseNotForgettable(ContextRuntimeError):
    code = "case_not_forgettable"


class MutationOutcomeUnknown(ContextRuntimeError):
    code = "mutation_outcome_unknown"


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def _fingerprint(value: object) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _safe_identifier(value: object, *, fallback: str) -> str:
    cooked = str(value or "").strip()
    if cooked and len(cooked) <= 128 and all(
        character.isalnum() or character in "._:-" for character in cooked
    ):
        return cooked
    return fallback


def _sanitize(value: object) -> object:
    if isinstance(value, Mapping):
        sanitized: dict[str, object] = {}
        for key, item in value.items():
            name = str(key)
            if is_secret_key(name):
                continue
            sanitized[name] = _sanitize(item)
        return sanitized
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_text(value)


def _sanitize_runtime_inputs(value: object) -> object:
    """Normalize reusable internal inputs without discarding connection values."""

    if isinstance(value, Mapping):
        return {
            str(key): _sanitize_runtime_inputs(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize_runtime_inputs(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _strict_bool(
    arguments: Mapping[str, object],
    name: str,
    *,
    default: bool = False,
) -> bool:
    value = arguments.get(name, default)
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a boolean")
    return value


def _inferred_entry_domain(intent: object) -> str:
    normalized = str(intent or "").strip().lower().replace("_", "-")
    return _INTENT_ENTRY_DOMAINS.get(normalized, "")


def _inferred_delivery_strategy(
    intent: object,
    arguments: Mapping[str, object],
    *,
    operation: str = "",
) -> str:
    normalized = str(intent or "").strip().lower().replace("_", "-")
    if normalized != "diagnose-and-fix":
        return {
            "live-patch": "live-patch",
            "rollback": "live-patch",
            "upgrade-and-verify": "build-upgrade",
        }.get(normalized, "")
    workflow = arguments.get("workflow", {})
    if isinstance(workflow, Mapping):
        has_build_upgrade = "build" in workflow or "upgrade" in workflow
        has_live_patch = "live_patch" in workflow
        if has_build_upgrade and has_live_patch:
            raise ValueError(
                "diagnose-and-fix workflow cannot mix live_patch with build/upgrade"
            )
        if has_build_upgrade:
            return "build-upgrade"
        if has_live_patch:
            return "live-patch"
        if "developer" in workflow:
            return "source-only"
    return {
        "live_patch_run": "live-patch",
        "upgrade_run": "build-upgrade",
    }.get(operation, "")


def _effective_case_intent(projection: Mapping[str, object]) -> str:
    intent = (
        str(projection.get("intent", "diagnosis-only"))
        .strip()
        .lower()
        .replace("_", "-")
        or "diagnosis-only"
    )
    if intent != "diagnosis-only":
        return intent
    operations = [
        item
        for item in projection.get("operations", [])
        if isinstance(item, Mapping)
    ]
    names = {str(item.get("operation", "")) for item in operations}
    if "upgrade_run" in names or "upgrade_batch" in names:
        return "upgrade-and-verify"
    if "live_patch_run" in names:
        rollback = any(
            isinstance(item.get("inputs"), Mapping)
            and str(item["inputs"].get("action", "")).strip().lower()
            == "rollback"
            for item in operations
            if item.get("operation") == "live_patch_run"
        )
        return "rollback" if rollback else "live-patch"
    if {"log_bundle_collect", "debug_run"}.issubset(names):
        return "bundle-and-diagnose"
    return intent


def _case_entry_domain(projection: Mapping[str, object]) -> str:
    entry_domain = projection.get("entry_domain")
    if isinstance(entry_domain, str) and entry_domain.strip():
        return entry_domain.strip()
    workflow_inputs = projection.get("workflow_inputs", {})
    if isinstance(workflow_inputs, Mapping):
        entry_domain = workflow_inputs.get("entry_domain")
        if isinstance(entry_domain, str) and entry_domain.strip():
            return entry_domain.strip()
    effective_intent = _effective_case_intent(projection)
    inferred = _inferred_entry_domain(effective_intent)
    if inferred:
        return inferred
    for operation in projection.get("operations", []):
        if not isinstance(operation, Mapping):
            continue
        domain = _OPERATION_ENTRY_DOMAINS.get(
            str(operation.get("operation", "")),
            "",
        )
        if domain:
            return domain
    return ""


def _operation_identity_inputs(arguments: Mapping[str, object]) -> dict[str, object]:
    """Persist only non-secret handoff identity needed for Case closeout."""

    allowed = {
        "action",
        "allow_insecure_tls",
        "artifact_ref",
        "artifact_path",
        "artifact_sha256",
        "force_path",
        "local_path",
        "no_backup",
        "no_remount",
        "product_version",
        "profile",
        "remote_path",
        "restart_scope",
        "ssh_host_key_policy",
        "target_id",
        "verification_checks",
        "_minimum_target_epoch",
    }
    sanitized = _sanitize(
        {key: value for key, value in arguments.items() if key in allowed}
    )
    return dict(sanitized) if isinstance(sanitized, Mapping) else {}


@dataclass(frozen=True)
class PendingCaseEvent:
    kind: str
    payload: Mapping[str, object]
    operation_id: str = ""


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    blob_id: str
    media_type: str
    byte_count: int
    target_id: str
    generation: str
    provenance: str
    observed_at: float
    case_id: str = ""
    producer: str = ""
    target_epoch: int | None = None
    workflow_definition_id: str = ""
    workflow_definition_version: int = 0
    workflow_definition_fingerprint: str = ""
    workflow_cycle_id: str = ""
    workflow_step_id: str = ""
    workflow_attempt: int = 0
    parent_evidence_ids: tuple[str, ...] = ()

    def to_public_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "blob_id": self.blob_id,
            "media_type": self.media_type,
            "byte_count": self.byte_count,
            "target_id": self.target_id,
            "generation": self.generation,
            "provenance": self.provenance,
            "observed_at": self.observed_at,
            "case_id": self.case_id,
            "producer": self.producer,
            "target_epoch": self.target_epoch,
            "workflow_definition_id": self.workflow_definition_id,
            "workflow_definition_version": self.workflow_definition_version,
            "workflow_definition_fingerprint": self.workflow_definition_fingerprint,
            "workflow_cycle_id": self.workflow_cycle_id,
            "workflow_step_id": self.workflow_step_id,
            "workflow_attempt": self.workflow_attempt,
            "parent_evidence_ids": list(self.parent_evidence_ids),
        }


class BlobRepository(Protocol):
    def put(self, body: bytes) -> str: ...

    def read(self, blob_id: str, *, offset: int, limit: int) -> bytes: ...

    def read_bounded(self, blob_id: str, *, max_bytes: int) -> bytes | None: ...

    def delete(self, blob_id: str) -> bool: ...

    def size_bytes(self) -> int: ...

    def blob_ids(self) -> tuple[str, ...]: ...


class InMemoryBlobRepository:
    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}
        self._lock = threading.RLock()

    def put(self, body: bytes) -> str:
        if not isinstance(body, bytes):
            raise TypeError("blob body must be bytes")
        blob_id = hashlib.sha256(body).hexdigest()
        with self._lock:
            self._blobs.setdefault(blob_id, body)
        return blob_id

    def read(self, blob_id: str, *, offset: int = 0, limit: int = -1) -> bytes:
        with self._lock:
            try:
                body = self._blobs[blob_id]
            except KeyError as exc:
                raise EvidenceUnavailable(f"blob {blob_id} is unavailable") from exc
        if hashlib.sha256(body).hexdigest() != blob_id:
            raise EvidenceUnavailable(f"blob {blob_id} failed hash verification")
        end = None if limit < 0 else offset + limit
        return body[offset:end]

    def read_bounded(self, blob_id: str, *, max_bytes: int) -> bytes | None:
        if type(max_bytes) is not int or max_bytes < 0:
            raise ValueError("max_bytes must be a non-negative integer")
        with self._lock:
            body = self._blobs.get(blob_id)
        if body is None:
            raise EvidenceUnavailable(f"blob {blob_id} is unavailable")
        if len(body) > max_bytes:
            return None
        if hashlib.sha256(body).hexdigest() != blob_id:
            raise EvidenceUnavailable(f"blob {blob_id} failed hash verification")
        return body

    def delete(self, blob_id: str) -> bool:
        with self._lock:
            return self._blobs.pop(blob_id, None) is not None

    def size_bytes(self) -> int:
        with self._lock:
            return sum(len(body) for body in self._blobs.values())

    def blob_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._blobs))


class FilesystemBlobRepository:
    """Content-addressed gzip blobs with atomic publication."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _path(self, blob_id: str) -> Path:
        if len(blob_id) != 64 or any(c not in "0123456789abcdef" for c in blob_id):
            raise EvidenceUnavailable("invalid blob identifier")
        return self.root / blob_id[:2] / f"{blob_id}.json.gz"

    def put(self, body: bytes) -> str:
        if not isinstance(body, bytes):
            raise TypeError("blob body must be bytes")
        blob_id = hashlib.sha256(body).hexdigest()
        destination = self._path(blob_id)
        with self._lock:
            if destination.is_file():
                return blob_id
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor, raw_path = tempfile.mkstemp(
                prefix=f".{blob_id}.",
                suffix=".tmp",
                dir=destination.parent,
            )
            try:
                with os.fdopen(descriptor, "wb") as raw_file:
                    with gzip.GzipFile(fileobj=raw_file, mode="wb", mtime=0) as archive:
                        archive.write(body)
                    raw_file.flush()
                    os.fsync(raw_file.fileno())
                os.replace(raw_path, destination)
            finally:
                try:
                    os.unlink(raw_path)
                except FileNotFoundError:
                    pass
        return blob_id

    def read(self, blob_id: str, *, offset: int = 0, limit: int = -1) -> bytes:
        path = self._path(blob_id)
        try:
            with gzip.open(path, "rb") as archive:
                body = archive.read()
        except (OSError, EOFError) as exc:
            raise EvidenceUnavailable(f"blob {blob_id} is unavailable") from exc
        if hashlib.sha256(body).hexdigest() != blob_id:
            raise EvidenceUnavailable(f"blob {blob_id} failed hash verification")
        end = None if limit < 0 else offset + limit
        return body[offset:end]

    def read_bounded(self, blob_id: str, *, max_bytes: int) -> bytes | None:
        if type(max_bytes) is not int or max_bytes < 0:
            raise ValueError("max_bytes must be a non-negative integer")
        path = self._path(blob_id)
        try:
            with gzip.open(path, "rb") as archive:
                body = archive.read(max_bytes + 1)
        except (OSError, EOFError) as exc:
            raise EvidenceUnavailable(f"blob {blob_id} is unavailable") from exc
        if len(body) > max_bytes:
            return None
        if hashlib.sha256(body).hexdigest() != blob_id:
            raise EvidenceUnavailable(f"blob {blob_id} failed hash verification")
        return body

    def delete(self, blob_id: str) -> bool:
        path = self._path(blob_id)
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        try:
            path.parent.rmdir()
        except OSError:
            pass
        return True

    def size_bytes(self) -> int:
        return sum(
            path.stat().st_size
            for path in self.root.glob("*/*.json.gz")
            if path.is_file()
        )

    def blob_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                path.name.removesuffix(".json.gz")
                for path in self.root.glob("*/*.json.gz")
                if path.is_file()
            )
        )


def _empty_projection(case_id: str) -> dict[str, object]:
    return {
        "schema": CONTEXT_RUNTIME_SCHEMA,
        "case_id": case_id,
        "revision": 0,
        "status": "open",
        "closed": False,
        "intent": "",
        "entry_domain": "",
        "entry_operation": "",
        "final_purpose": "",
        "change_boundary": "",
        "delivery_strategy": "",
        _TASK_POLICY_FIELD: {},
        "acceptance_plan": {},
        "acceptance_plan_history": [],
        "closeout": {},
        "closeout_markdown": "",
        "closeout_bundle": None,
        "closeout_history": [],
        "targets": [],
        "target_version": 1,
        "workflow_inputs": {},
        "workflow_definition": {},
        "workflow_cycle_id": "cycle-1",
        "workflow_cycle_number": 1,
        "workflow_step_states": {},
        "workflow_step_attempts": {},
        "workflow_phase_values": {},
        "mutation_outcome_unknown_operations": {},
        "operations": [],
        "completed_operation_counts": {},
        "operation_count": 0,
        "phase_records": [],
        "phase_record_count": 0,
        "run_gates": [],
        "current_gate": {},
        "gate_submissions": [],
        "incidents": [],
        "current_incident": {},
        "run_outcome": {},
        "run_decisions": [],
        "current_turn": {},
        "effect_intents": [],
        "start_command_id": "",
        "start_input_digest": "",
        "start_input": {},
        "evidence_refs": [],
        "evidence_ref_count": 0,
        "projection_truncated": False,
        "next_actions": [],
        "last_access": 0.0,
    }


def project_case(
    case_id: str,
    events: Iterable[Mapping[str, object]],
    *,
    last_access: float = 0.0,
) -> dict[str, object]:
    projection = _empty_projection(case_id)
    operations: OrderedDict[str, dict[str, object]] = OrderedDict()
    evidence_by_id: OrderedDict[str, dict[str, object]] = OrderedDict()
    phases: list[dict[str, object]] = []
    completed_counts: dict[str, int] = {}
    operation_count = 0
    phase_record_count = 0
    evidence_ref_count = 0
    workflow_step_states: dict[str, dict[str, object]] = {}
    workflow_step_attempts: dict[str, int] = {}
    workflow_phase_values: dict[str, dict[str, object]] = {}
    unknown_mutations: dict[str, dict[str, object]] = {}
    run_gates: list[dict[str, object]] = []
    gate_submissions: list[dict[str, object]] = []
    incidents: list[dict[str, object]] = []
    run_decisions: list[dict[str, object]] = []
    effect_intents: list[dict[str, object]] = []
    for event in (
        upcasted
        for persisted in events
        for upcasted in upcast_run_events(persisted)
    ):
        revision = int(event["revision"])
        projection["revision"] = revision
        kind = str(event["kind"])
        operation_id = str(event.get("operation_id", ""))
        created_at = float(event.get("created_at", 0.0) or 0.0)
        payload = event.get("payload", {})
        payload = dict(payload) if isinstance(payload, Mapping) else {}
        if kind == "CaseOpened":
            acceptance_plan = dict(payload.get("acceptance_plan", {}))
            workflow_inputs = dict(payload.get("workflow_inputs", {}))
            entry_domain = payload.get("entry_domain")
            if not isinstance(entry_domain, str) or not entry_domain.strip():
                entry_domain = workflow_inputs.get("entry_domain")
            if not isinstance(entry_domain, str) or not entry_domain.strip():
                entry_domain = _inferred_entry_domain(payload.get("intent"))
            projection.update(
                {
                    "intent": str(payload.get("intent", "")),
                    "entry_domain": str(entry_domain).strip(),
                    "entry_operation": str(payload.get("entry_operation", "")),
                    "final_purpose": str(payload.get("final_purpose", "")),
                    "change_boundary": str(payload.get("change_boundary", "")),
                    "delivery_strategy": str(payload.get("delivery_strategy", "")),
                    _TASK_POLICY_FIELD: dict(
                        payload.get(_TASK_POLICY_FIELD, {})
                    ),
                    "acceptance_plan": acceptance_plan,
                    "acceptance_plan_history": (
                        [acceptance_plan] if acceptance_plan else []
                    ),
                    "targets": list(payload.get("targets", [])),
                    "target_version": int(payload.get("target_version", 1)),
                    "workflow_inputs": workflow_inputs,
                    "workflow_definition": dict(
                        payload.get("workflow_definition", {})
                    ),
                    "start_command_id": str(payload.get("start_command_id", "")),
                    "start_input_digest": str(payload.get("start_input_digest", "")),
                    "start_input": dict(payload.get("start_input", {})),
                    "workflow_cycle_id": str(
                        payload.get("workflow_cycle_id", "cycle-1")
                    ),
                    "workflow_cycle_number": int(
                        payload.get("workflow_cycle_number", 1)
                    ),
                    "status": "open",
                }
            )
        elif kind == "DeliveryStrategySelected":
            previous_closeout = projection.get("closeout")
            if isinstance(previous_closeout, Mapping) and previous_closeout:
                projection.setdefault("closeout_history", []).append(
                    dict(previous_closeout)
                )
            projection["delivery_strategy"] = str(
                payload.get("delivery_strategy", projection["delivery_strategy"])
            )
            task_policy = payload.get(_TASK_POLICY_FIELD)
            if isinstance(task_policy, Mapping):
                projection[_TASK_POLICY_FIELD] = dict(task_policy)
            acceptance_plan = payload.get("acceptance_plan")
            if isinstance(acceptance_plan, Mapping):
                plan = dict(acceptance_plan)
                projection["acceptance_plan"] = plan
                projection.setdefault("acceptance_plan_history", []).append(plan)
            workflow_inputs = payload.get("workflow_inputs")
            if isinstance(workflow_inputs, Mapping):
                projection["workflow_inputs"] = {
                    **dict(projection.get("workflow_inputs", {})),
                    **dict(workflow_inputs),
                }
            workflow_definition = payload.get("workflow_definition")
            if isinstance(workflow_definition, Mapping):
                projection["workflow_definition"] = dict(workflow_definition)
            projection["closeout"] = {}
            projection["closeout_markdown"] = ""
            projection["closeout_bundle"] = None
            projection["status"] = "open"
        elif kind == "CaseUpdated":
            for name in (
                "intent",
                "final_purpose",
                "change_boundary",
                "delivery_strategy",
            ):
                if name in payload:
                    projection[name] = str(payload[name])
            if "targets" in payload:
                projection["targets"] = list(payload.get("targets", []))
            if "workflow_inputs" in payload:
                projection["workflow_inputs"] = dict(
                    payload.get("workflow_inputs", {})
                )
            workflow_definition = payload.get("workflow_definition")
            if isinstance(workflow_definition, Mapping):
                projection["workflow_definition"] = dict(workflow_definition)
            task_policy = payload.get(_TASK_POLICY_FIELD)
            if isinstance(task_policy, Mapping):
                projection[_TASK_POLICY_FIELD] = dict(task_policy)
            acceptance_plan = payload.get("acceptance_plan")
            if isinstance(acceptance_plan, Mapping):
                plan = dict(acceptance_plan)
                projection["acceptance_plan"] = plan
                projection.setdefault("acceptance_plan_history", []).append(plan)
            if payload.get("target_changed") is True:
                projection["target_version"] = int(
                    payload.get(
                        "target_version",
                        int(projection.get("target_version", 1)) + 1,
                    )
                )
                workflow_step_states = {
                    key: value
                    for key, value in workflow_step_states.items()
                    if value.get("kind") == "phase"
                }
                workflow_step_attempts = {
                    key: value
                    for key, value in workflow_step_attempts.items()
                    if ":phase:" in key
                }
                projection["current_gate"] = {}
                projection["current_incident"] = {}
            projection["status"] = "open"
        elif kind == "WorkflowCycleStarted":
            previous_closeout = projection.get("closeout")
            if isinstance(previous_closeout, Mapping) and previous_closeout:
                projection.setdefault("closeout_history", []).append(
                    dict(previous_closeout)
                )
            projection["workflow_cycle_number"] = int(
                payload.get(
                    "workflow_cycle_number",
                    int(projection.get("workflow_cycle_number", 1)) + 1,
                )
            )
            projection["workflow_cycle_id"] = str(
                payload.get(
                    "workflow_cycle_id",
                    f"cycle-{projection['workflow_cycle_number']}",
                )
            )
            workflow_step_states = {}
            workflow_step_attempts = {}
            workflow_phase_values = {}
            projection["current_gate"] = {}
            projection["current_incident"] = {}
            projection["closeout"] = {}
            projection["closeout_markdown"] = ""
            projection["closeout_bundle"] = None
            projection["status"] = "open"
            projection["next_actions"] = []
        elif kind == "WorkflowStepsInvalidated":
            previous_closeout = projection.get("closeout")
            if isinstance(previous_closeout, Mapping) and previous_closeout:
                projection.setdefault("closeout_history", []).append(
                    dict(previous_closeout)
                )
            retained_step_ids = payload.get("retained_step_ids")
            after_step_id = str(payload.get("after_step_id", ""))
            if isinstance(retained_step_ids, list):
                retained = {
                    str(step_id)
                    for step_id in retained_step_ids
                    if isinstance(step_id, str) and step_id
                }
                workflow_step_states = {
                    key: value
                    for key, value in workflow_step_states.items()
                    if key in retained
                }
            elif after_step_id:
                workflow_step_states = {
                    key: value
                    for key, value in workflow_step_states.items()
                    if key <= after_step_id
                }
            active_phase_names = {
                str(state.get("name", ""))
                for state in workflow_step_states.values()
                if isinstance(state, Mapping)
                and state.get("kind") == "phase"
                and str(state.get("name", ""))
            }
            workflow_phase_values = {
                phase_type: value
                for phase_type, value in workflow_phase_values.items()
                if phase_type in active_phase_names
            }
            projection["current_gate"] = {}
            projection["closeout"] = {}
            projection["closeout_markdown"] = ""
            projection["closeout_bundle"] = None
            projection["status"] = "open"
            projection["next_actions"] = []
        elif kind == "OperationAccepted":
            operation_count += 1
            operations[operation_id] = {
                "operation_id": operation_id,
                "operation": str(payload.get("operation", "")),
                "status": "accepted",
                "idempotency_key": str(payload.get("idempotency_key", "")),
                "request_fingerprint": str(
                    payload.get("request_fingerprint", "")
                ),
                "accepted_revision": revision,
            }
            inputs = payload.get("inputs")
            if isinstance(inputs, Mapping) and inputs:
                operations[operation_id]["inputs"] = dict(inputs)
            operation = operations[operation_id]
            for name in (
                "workflow_cycle_id",
                "workflow_step_id",
                "workflow_step_kind",
                "target_version",
                "target_id",
                "workflow_definition_id",
                "workflow_definition_version",
                "workflow_definition_fingerprint",
                "workflow_execution_id",
                "workflow_attempt",
                "workflow_input_fingerprint",
                "workflow_target_epoch",
            ):
                if name in payload:
                    operation[name] = payload[name]
            step_id = str(payload.get("workflow_step_id", ""))
            cycle_id = str(payload.get("workflow_cycle_id", ""))
            step_kind = str(payload.get("workflow_step_kind", ""))
            if step_id and cycle_id and step_kind:
                target_version = int(payload.get("target_version", 0))
                attempt_key = (
                    f"{cycle_id}:{step_kind}:{step_id}:target-{target_version}"
                    if step_kind == "operation"
                    else f"{cycle_id}:{step_kind}:{step_id}"
                )
                workflow_step_attempts[attempt_key] = (
                    workflow_step_attempts.get(attempt_key, 0) + 1
                )
                operation["workflow_attempt"] = workflow_step_attempts[attempt_key]
        elif kind == "OperationStarted":
            operation = operations.setdefault(
                operation_id,
                {"operation_id": operation_id, "operation": ""},
            )
            operation["status"] = "running"
            operation["started_revision"] = revision
            operation.setdefault("started_at", created_at)
            operation["last_progress_at"] = created_at
        elif kind == "EvidenceAttached":
            reference = payload.get("evidence")
            if isinstance(reference, Mapping):
                public = dict(reference)
                evidence_id = str(public.get("evidence_id", ""))
                if evidence_id:
                    if evidence_id not in evidence_by_id:
                        evidence_ref_count += 1
                    evidence_by_id[evidence_id] = public
                    operation = operations.get(operation_id)
                    if operation is not None:
                        operation.setdefault("evidence_ids", []).append(evidence_id)
                        operation["last_progress_at"] = created_at
        elif kind == "OperationProgressed":
            operation = operations.setdefault(
                operation_id,
                {"operation_id": operation_id, "operation": ""},
            )
            if "status" in payload:
                operation["status"] = str(payload["status"])
            for name in (
                "owner",
                "phase",
                "started_at",
                "retry_generation",
                "reconcile_attempt",
                "last_error",
                "deadline_at",
            ):
                if name in payload:
                    operation[name] = payload[name]
            if "evidence_retry_generation" in payload:
                operation["evidence_retry_generation"] = int(
                    payload["evidence_retry_generation"]
                )
                operation["retry_requested_at"] = created_at
            # `last_progress_at` is an event-derived timestamp. A payload may
            # describe domain progress, but it cannot spoof the event time or
            # a supervisor heartbeat into durable progress.
            operation["last_progress_at"] = created_at
            if "next_actions" in payload:
                projection["next_actions"] = list(payload["next_actions"])
            if "case_status" in payload:
                projection["status"] = str(payload["case_status"])
            phase = payload.get("legacy_phase_record")
            if not isinstance(phase, Mapping):
                phase = payload.get("phase_record")
            if isinstance(phase, Mapping):
                phase_public = dict(phase)
                phases.append(phase_public)
                phase_record_count += 1
                step_id = str(phase_public.get("workflow_step_id", ""))
                cycle_id = str(phase_public.get("workflow_cycle_id", ""))
                if step_id and cycle_id == str(
                    projection.get("workflow_cycle_id", "")
                ):
                    workflow_step_states[step_id] = {
                        "kind": "phase",
                        "name": str(phase_public.get("phase_type", "")),
                        "status": str(phase_public.get("status", "")),
                        "workflow_cycle_id": cycle_id,
                        "target_version": int(
                            phase_public.get(
                                "target_version", projection.get("target_version", 1)
                            )
                        ),
                        "target_id": "",
                        "operation_id": str(phase_public.get("operation_id", "")),
                        "workflow_execution_id": str(
                            phase_public.get("workflow_execution_id", "")
                        ),
                        "workflow_definition_id": str(
                            phase_public.get("workflow_definition_id", "")
                        ),
                        "workflow_definition_version": int(
                            phase_public.get("workflow_definition_version", 0)
                        ),
                        "workflow_input_fingerprint": str(
                            phase_public.get("workflow_input_fingerprint", "")
                        ),
                        "workflow_attempt": int(
                            phase_public.get(
                                "workflow_attempt",
                                phase_public.get("phase_attempt", 0),
                            )
                        ),
                        "target_epoch": int(
                            phase_public.get("workflow_target_epoch", 0)
                        ),
                    }
                    workflow_phase_values[
                        str(phase_public.get("phase_type", ""))
                    ] = phase_public
            else:
                step_id = str(operation.get("workflow_step_id", ""))
                cycle_id = str(operation.get("workflow_cycle_id", ""))
                if step_id and cycle_id == str(
                    projection.get("workflow_cycle_id", "")
                ):
                    workflow_step_states[step_id] = {
                        "kind": str(
                            operation.get("workflow_step_kind", "operation")
                        ),
                        "name": str(operation.get("operation", "")),
                        "status": str(operation.get("status", "running")),
                        "workflow_cycle_id": cycle_id,
                        "target_version": int(
                            operation.get("target_version", 0)
                        ),
                        "target_id": str(operation.get("target_id", "")),
                        "operation_id": operation_id,
                        "workflow_execution_id": str(
                            operation.get("workflow_execution_id", "")
                        ),
                        "workflow_definition_id": str(
                            operation.get("workflow_definition_id", "")
                        ),
                        "workflow_definition_version": int(
                            operation.get("workflow_definition_version", 0)
                        ),
                        "workflow_input_fingerprint": str(
                            operation.get("workflow_input_fingerprint", "")
                        ),
                        "workflow_attempt": int(
                            operation.get("workflow_attempt", 0)
                        ),
                        "target_epoch": int(
                            payload.get(
                                "target_epoch",
                                operation.get("workflow_target_epoch", 0),
                            )
                            or 0
                        ),
                    }
        elif kind == "OperationTerminal":
            operation = operations.setdefault(
                operation_id,
                {"operation_id": operation_id, "operation": ""},
            )
            operation["status"] = str(payload.get("status", "completed"))
            if operation["status"] in {"completed", "verified", "succeeded"}:
                name = str(operation.get("operation", ""))
                if name and name not in _WORKFLOW_CONTROL_OPERATIONS:
                    completed_counts[name] = completed_counts.get(name, 0) + 1
            operation["terminal_revision"] = revision
            operation["settled_at"] = created_at
            operation["last_progress_at"] = created_at
            operation["summary"] = str(payload.get("summary", ""))
            if isinstance(payload.get("diagnostic_receipt"), Mapping):
                operation["diagnostic_receipt"] = dict(
                    payload["diagnostic_receipt"]
                )
            if "target_epoch" in payload:
                operation["target_epoch"] = payload["target_epoch"]
            if isinstance(payload.get("target_epochs"), Mapping):
                operation["target_epochs"] = dict(payload["target_epochs"])
            if operation["status"] == "mutation_outcome_unknown":
                unknown_mutations[operation_id] = {
                    "operation_id": operation_id,
                    "operation": str(operation.get("operation", "")),
                    "status": operation["status"],
                }
            step_id = str(operation.get("workflow_step_id", ""))
            cycle_id = str(operation.get("workflow_cycle_id", ""))
            if step_id and cycle_id == str(
                projection.get("workflow_cycle_id", "")
            ):
                workflow_step_states[step_id] = {
                    "kind": str(operation.get("workflow_step_kind", "operation")),
                    "name": str(operation.get("operation", "")),
                    "status": str(operation.get("status", "")),
                    "workflow_cycle_id": cycle_id,
                    "target_version": int(operation.get("target_version", 0)),
                    "target_id": str(operation.get("target_id", "")),
                    "operation_id": operation_id,
                    "workflow_execution_id": str(
                        operation.get("workflow_execution_id", "")
                    ),
                    "workflow_definition_id": str(
                        operation.get("workflow_definition_id", "")
                    ),
                    "workflow_definition_version": int(
                        operation.get("workflow_definition_version", 0)
                    ),
                    "workflow_input_fingerprint": str(
                        operation.get("workflow_input_fingerprint", "")
                    ),
                    "workflow_attempt": int(
                        operation.get("workflow_attempt", 0)
                    ),
                }
                if "target_epoch" in operation:
                    workflow_step_states[step_id]["target_epoch"] = operation[
                        "target_epoch"
                    ]
            if payload.get("canonical_error") is not None:
                operation["canonical_error"] = payload.get("canonical_error")
            if "next_actions" in payload:
                projection["next_actions"] = list(payload["next_actions"])
            projection["status"] = str(payload.get("case_status", "open"))
        elif kind == "RunGateOpened":
            raw_gate = payload.get("gate")
            if isinstance(raw_gate, Mapping):
                gate = dict(raw_gate)
                gate["status"] = "open"
                run_gates.append(gate)
                projection["current_gate"] = gate
                projection["status"] = "waiting_phase_record"
        elif kind == "RunGateSubmitted":
            gate_id = str(payload.get("gate_id", ""))
            gate_version = int(payload.get("gate_version", 0))
            for gate in reversed(run_gates):
                if (
                    str(gate.get("gate_id", "")) == gate_id
                    and int(gate.get("gate_version", 0)) == gate_version
                ):
                    gate["status"] = "submitted"
                    gate["submission_id"] = str(payload.get("submission_id", ""))
                    break
            gate_submissions.append(
                {
                    key: value
                    for key, value in payload.items()
                    if key != "phase"
                }
            )
            raw_phase = payload.get("phase")
            if isinstance(raw_phase, Mapping):
                phase_public = dict(raw_phase)
                phases.append(phase_public)
                phase_record_count += 1
                step_id = str(phase_public.get("workflow_step_id", ""))
                cycle_id = str(phase_public.get("workflow_cycle_id", ""))
                if step_id and cycle_id == str(
                    projection.get("workflow_cycle_id", "")
                ):
                    workflow_step_states[step_id] = {
                        "kind": "phase",
                        "name": str(phase_public.get("phase_type", "")),
                        "status": str(phase_public.get("status", "")),
                        "workflow_cycle_id": cycle_id,
                        "target_version": int(
                            phase_public.get(
                                "target_version",
                                projection.get("target_version", 1),
                            )
                        ),
                        "target_id": "",
                        "operation_id": str(
                            phase_public.get("operation_id", operation_id)
                        ),
                        "workflow_execution_id": str(
                            phase_public.get("workflow_execution_id", "")
                        ),
                        "workflow_definition_id": str(
                            phase_public.get("workflow_definition_id", "")
                        ),
                        "workflow_definition_version": int(
                            phase_public.get("workflow_definition_version", 0)
                        ),
                        "workflow_input_fingerprint": str(
                            phase_public.get("workflow_input_fingerprint", "")
                        ),
                        "workflow_attempt": int(
                            phase_public.get(
                                "workflow_attempt",
                                phase_public.get("phase_attempt", 0),
                            )
                        ),
                        "target_epoch": int(
                            phase_public.get("workflow_target_epoch", 0)
                        ),
                    }
                    workflow_phase_values[
                        str(phase_public.get("phase_type", ""))
                    ] = phase_public
            current_gate = projection.get("current_gate")
            if (
                isinstance(current_gate, Mapping)
                and str(current_gate.get("gate_id", "")) == gate_id
                and int(current_gate.get("gate_version", 0)) == gate_version
            ):
                projection["current_gate"] = {}
        elif kind == "RunCancelled":
            gate_id = str(payload.get("gate_id", ""))
            gate_version = int(payload.get("gate_version", 0))
            if gate_id:
                for gate in reversed(run_gates):
                    if (
                        str(gate.get("gate_id", "")) == gate_id
                        and int(gate.get("gate_version", 0)) == gate_version
                    ):
                        gate["status"] = "cancelled"
                        gate["submission_id"] = str(
                            payload.get("submission_id", "")
                        )
                        break
                gate_submissions.append(dict(payload))
            projection["current_gate"] = {}
            projection["current_incident"] = {}
            projection["status"] = "cancelled"
            projection["next_actions"] = []
        elif kind == "RunIncidentRaised":
            raw_incident = payload.get("incident")
            if isinstance(raw_incident, Mapping):
                incident = dict(raw_incident)
                incident["status"] = "open"
                incident["raised_at"] = created_at
                incident["resolved_at"] = 0.0
                incidents.append(incident)
                projection["current_incident"] = incident
                projection["status"] = "incident"
        elif kind == "RunIncidentResolved":
            incident_id = str(payload.get("incident_id", ""))
            resolution = str(payload.get("resolution", "resolved")) or "resolved"
            for incident in reversed(incidents):
                if str(incident.get("incident_id", "")) == incident_id:
                    incident["status"] = (
                        "cancelled" if resolution == "cancelled" else "resolved"
                    )
                    incident["resolution"] = resolution
                    incident["resolved_at"] = created_at
                    break
            current_incident = projection.get("current_incident")
            if (
                isinstance(current_incident, Mapping)
                and str(current_incident.get("incident_id", "")) == incident_id
            ):
                projection["current_incident"] = {}
                projection["status"] = "open"
        elif kind == "RunOutcomeRecorded":
            raw_outcome = payload.get("outcome")
            if isinstance(raw_outcome, Mapping):
                projection["run_outcome"] = dict(raw_outcome)
                projection["current_gate"] = {}
                projection["current_incident"] = {}
                projection["status"] = "terminal"
                projection["next_actions"] = []
        elif kind == "RunDecisionCommitted":
            decision = {
                key: value
                for key, value in payload.items()
                if key not in {"_run_event_schema", "_run_event_version"}
            }
            run_decisions.append(decision)
            raw_turn = decision.get("turn")
            if isinstance(raw_turn, Mapping):
                projection["current_turn"] = dict(raw_turn)
            raw_effect_intent = decision.get("effect_intent")
            if isinstance(raw_effect_intent, Mapping) and raw_effect_intent:
                effect_intents.append(dict(raw_effect_intent))
                if str(decision.get("command_id", "")).startswith("recover-"):
                    operation = operations.get(str(raw_effect_intent.get("effect_id", "")))
                    if operation is not None:
                        operation["reconcile_requested_at"] = created_at
        elif kind == "RunVerificationDeferred":
            step_id = str(payload.get("workflow_step_id", ""))
            state = workflow_step_states.get(step_id)
            if isinstance(state, Mapping):
                workflow_step_states[step_id] = {
                    **dict(state),
                    "status": "pending_retry",
                }
            projection["status"] = "running"
            projection["next_actions"] = [
                str(
                    payload.get(
                        "next_action",
                        "resume the Run to retry fresh verification",
                    )
                )
            ]
        elif kind == "OperationReconciled":
            operation = operations.setdefault(
                operation_id,
                {"operation_id": operation_id, "operation": ""},
            )
            operation["status"] = str(payload.get("status", "completed"))
            if operation["status"] in {"completed", "verified", "succeeded"}:
                name = str(operation.get("operation", ""))
                if name and name not in _WORKFLOW_CONTROL_OPERATIONS:
                    completed_counts[name] = completed_counts.get(name, 0) + 1
            operation["reconciled_revision"] = revision
            operation["reconciled_at"] = created_at
            operation["last_progress_at"] = created_at
            operation["reconcile_count"] = operation.get("reconcile_count", 0) + 1
            operation["summary"] = str(payload.get("summary", ""))
            if isinstance(payload.get("diagnostic_receipt"), Mapping):
                operation["diagnostic_receipt"] = dict(
                    payload["diagnostic_receipt"]
                )
            if "target_epoch" in payload:
                operation["target_epoch"] = payload["target_epoch"]
            if isinstance(payload.get("target_epochs"), Mapping):
                operation["target_epochs"] = dict(payload["target_epochs"])
            if operation["status"] == "mutation_outcome_unknown":
                unknown_mutations[operation_id] = {
                    "operation_id": operation_id,
                    "operation": str(operation.get("operation", "")),
                    "status": operation["status"],
                }
            else:
                unknown_mutations.pop(operation_id, None)
            step_id = str(operation.get("workflow_step_id", ""))
            cycle_id = str(operation.get("workflow_cycle_id", ""))
            if step_id and cycle_id == str(
                projection.get("workflow_cycle_id", "")
            ):
                workflow_step_states[step_id] = {
                    "kind": str(operation.get("workflow_step_kind", "operation")),
                    "name": str(operation.get("operation", "")),
                    "status": str(operation.get("status", "")),
                    "workflow_cycle_id": cycle_id,
                    "target_version": int(operation.get("target_version", 0)),
                    "target_id": str(operation.get("target_id", "")),
                    "operation_id": operation_id,
                }
                if "target_epoch" in operation:
                    workflow_step_states[step_id]["target_epoch"] = operation[
                        "target_epoch"
                    ]
            operation.pop("canonical_error", None)
            if payload.get("canonical_error") is not None:
                operation["canonical_error"] = payload.get("canonical_error")
            if "next_actions" in payload:
                projection["next_actions"] = list(payload["next_actions"])
            projection["status"] = str(payload.get("case_status", "open"))
        elif kind == "CloseoutRecorded":
            closeout = payload.get("closeout")
            if isinstance(closeout, Mapping):
                previous_closeout = projection.get("closeout")
                if (
                    isinstance(previous_closeout, Mapping)
                    and previous_closeout
                    and previous_closeout.get("fingerprint")
                    != closeout.get("fingerprint")
                ):
                    projection.setdefault("closeout_history", []).append(
                        dict(previous_closeout)
                    )
                projection["closeout"] = dict(closeout)
            projection["closeout_markdown"] = str(
                payload.get("closeout_markdown", "")
            )
            bundle = payload.get("closeout_bundle")
            projection["closeout_bundle"] = (
                dict(bundle) if isinstance(bundle, Mapping) else None
            )
        elif kind == "CaseClosed":
            projection["closed"] = True
            projection["status"] = "closed"
    active_statuses = {
        "accepted",
        "running",
        "waiting_external",
        "waiting_phase_record",
        "mutation_outcome_unknown",
    }
    while len(operations) > MAX_PROJECTED_OPERATIONS:
        removable = next(
            (
                candidate_id
                for candidate_id, operation in operations.items()
                if str(operation.get("status", "")) not in active_statuses
            ),
            next(iter(operations)),
        )
        operations.pop(removable, None)
    while len(evidence_by_id) > MAX_PROJECTED_EVIDENCE_REFS:
        evidence_by_id.popitem(last=False)
    if len(phases) > MAX_PROJECTED_PHASE_RECORDS:
        phases = phases[-MAX_PROJECTED_PHASE_RECORDS:]
    projection["operations"] = list(operations.values())
    projection["completed_operation_counts"] = completed_counts
    projection["workflow_step_states"] = workflow_step_states
    projection["workflow_step_attempts"] = workflow_step_attempts
    projection["workflow_phase_values"] = workflow_phase_values
    projection["mutation_outcome_unknown_operations"] = unknown_mutations
    projection["operation_count"] = operation_count
    projection["phase_records"] = phases
    projection["phase_record_count"] = phase_record_count
    projection["run_gates"] = run_gates
    projection["gate_submissions"] = gate_submissions
    projection["incidents"] = incidents
    projection["run_decisions"] = run_decisions
    projection["effect_intents"] = effect_intents
    projection["evidence_refs"] = list(evidence_by_id.values())
    projection["evidence_ref_count"] = evidence_ref_count
    projection["projection_truncated"] = bool(
        operation_count > len(operations)
        or phase_record_count > len(phases)
        or evidence_ref_count > len(evidence_by_id)
    )
    if not str(projection.get("entry_domain", "")).strip():
        projection["entry_domain"] = _case_entry_domain(projection)
    projection["last_access"] = last_access
    return projection


def _walk_projection_values(
    value: object,
    *,
    field_name: str = "",
) -> Iterable[tuple[str, object]]:
    yield field_name, value
    if isinstance(value, Mapping):
        for name, nested in value.items():
            yield from _walk_projection_values(nested, field_name=str(name))
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_projection_values(nested)


def _operator_artifact_refs(
    projection: Mapping[str, object],
    *,
    limit: int = 16,
) -> list[dict[str, object]]:
    references: list[dict[str, object]] = []
    seen: set[str] = set()

    def visit(value: object) -> None:
        if len(references) >= limit:
            return
        for field_name, candidate_value in _walk_projection_values(value):
            if len(references) >= limit:
                return
            if not isinstance(candidate_value, Mapping):
                continue
            candidate = dict(candidate_value)
            is_reference = field_name == "artifact_ref" or all(
                name in candidate
                for name in ("handle", "digest", "kind", "size", "run_id")
            )
            if is_reference:
                identity = json.dumps(
                    candidate,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                if identity not in seen:
                    seen.add(identity)
                    references.append(candidate)

    visit(projection.get("operations", []))
    visit(projection.get("workflow_phase_values", {}))
    visit(projection.get("evidence_refs", []))
    visit(projection.get("run_outcome", {}))
    return references


def _operator_target_epoch(projection: Mapping[str, object]) -> int:
    epochs: list[int] = []

    for value in (
        projection.get("targets", []),
        projection.get("operations", []),
        projection.get("workflow_step_states", {}),
        projection.get("current_turn", {}),
        projection.get("run_outcome", {}),
    ):
        epochs.extend(
            nested
            for name, nested in _walk_projection_values(value)
            if name == "target_epoch"
            and isinstance(nested, int)
            and not isinstance(nested, bool)
            and nested >= 0
        )
    return max(epochs, default=0)


def operator_run_projection(projection: Mapping[str, object]) -> dict[str, object]:
    """Derive one bounded Operator view from authoritative Run facts."""

    current_turn = projection.get("current_turn")
    turn = dict(current_turn) if isinstance(current_turn, Mapping) else {}
    current_gate = projection.get("current_gate")
    gate = dict(current_gate) if isinstance(current_gate, Mapping) else {}
    current_incident = projection.get("current_incident")
    incident = (
        dict(current_incident)
        if isinstance(current_incident, Mapping)
        else {}
    )
    raw_outcome = projection.get("run_outcome")
    outcome = dict(raw_outcome) if isinstance(raw_outcome, Mapping) else {}
    run_state = str(projection.get("status", "open"))
    turn_state = str(turn.get("state", "")).strip()
    if not turn_state:
        turn_state = (
            "incident"
            if incident
            else "waiting_response"
            if gate
            else str(outcome.get("status", "terminal"))
            if outcome
            else run_state
        )
    workflow_attempts = projection.get("workflow_step_attempts", {})
    retry_count = (
        sum(
            max(0, int(value) - 1)
            for value in workflow_attempts.values()
            if isinstance(value, int) and not isinstance(value, bool)
        )
        if isinstance(workflow_attempts, Mapping)
        else 0
    )
    if incident or turn_state == "incident":
        interaction_classification = "incident"
    elif gate or turn_state == "waiting_response":
        interaction_classification = "gate_response_required"
    elif outcome or run_state in {"terminal", "closed", "cancelled"}:
        interaction_classification = "terminal_outcome"
    elif retry_count:
        interaction_classification = "retrying"
    else:
        interaction_classification = turn_state or "running"
    unknown = projection.get("mutation_outcome_unknown_operations", {})
    unknown_effects = (
        [dict(value) for value in unknown.values() if isinstance(value, Mapping)]
        if isinstance(unknown, Mapping)
        else []
    )
    return {
        "run_id": str(projection.get("case_id", "")),
        "revision": int(projection.get("revision", 0)),
        "run_state": run_state,
        "turn_state": turn_state,
        "current_turn": turn or None,
        "interaction_classification": interaction_classification,
        "retry_count": retry_count,
        "recovery": {
            "required": bool(incident or unknown_effects),
            "incident_id": str(incident.get("incident_id", "")),
            "code": str(incident.get("code", "")),
            "effect_id": str(incident.get("effect_id", "")),
            "recovery_path": str(incident.get("recovery_path", "")),
            "unknown_effects": unknown_effects[:8],
        },
        "target_epoch": _operator_target_epoch(projection),
        "current_gate": gate or None,
        "current_incident": incident or None,
        "artifact_outcome_linkage": {
            "artifact_refs": _operator_artifact_refs(projection),
            "outcome": outcome or None,
        },
    }


class RuntimeRepository(Protocol):
    def load(self, case_id: str) -> dict[str, object] | None: ...

    def events(self, case_id: str) -> tuple[dict[str, object], ...]: ...

    def current_revision(self, case_id: str) -> int | None: ...

    def commit(
        self,
        case_id: str,
        *,
        expected_revision: int,
        events: Iterable[PendingCaseEvent],
    ) -> dict[str, object]: ...

    def claim_idempotency(
        self, case_id: str, key: str, fingerprint: str
    ) -> Mapping[str, object] | None: ...

    def complete_idempotency(
        self, case_id: str, key: str, receipt: Mapping[str, object]
    ) -> None: ...

    def abandon_idempotency(self, case_id: str, key: str) -> None: ...

    def bind_task(self, task_id: str, case_id: str) -> None: ...

    def case_for_task(self, task_id: str) -> str | None: ...

    def is_case_bound(self, case_id: str) -> bool: ...

    def unbind_task(self, task_id: str) -> None: ...

    def touch(self, case_id: str, *, at: float) -> None: ...

    def evidence_reference(
        self, case_id: str, evidence_id: str
    ) -> dict[str, object] | None: ...

    def evidence_references(
        self, case_id: str
    ) -> tuple[dict[str, object], ...]: ...

    def evidence_query_candidates(
        self,
        query: EvidenceQuery,
        *,
        limit: int,
    ) -> tuple[dict[str, object], ...]: ...

    def delete_case(self, case_id: str) -> tuple[dict[str, object], ...]: ...

    def metadata(self) -> tuple[dict[str, object], ...]: ...

    def blob_reference_count(self, blob_id: str) -> int: ...

    def size_bytes(self) -> int: ...

    def status(self) -> dict[str, object]: ...


@dataclass
class _BufferedRunState:
    run_id: str
    base_revision: int
    base_events: tuple[dict[str, object], ...]
    last_access: float
    recorded_at: float
    events: list[PendingCaseEvent] = field(default_factory=list)
    idempotency_claims: dict[tuple[str, str], str] = field(default_factory=dict)
    idempotency_receipts: dict[
        tuple[str, str], Mapping[str, object]
    ] = field(default_factory=dict)
    bindings: dict[str, str] = field(default_factory=dict)
    unbound_tasks: set[str] = field(default_factory=set)
    effect_intent: Mapping[str, object] | None = None


class BufferedRunCommand:
    def __init__(
        self,
        repository: "BufferedRuntimeRepository",
        state: _BufferedRunState,
        token: Token,
    ) -> None:
        self.repository = repository
        self.state = state
        self.token = token
        self.committed = False

    @property
    def expected_revision(self) -> int:
        return self.state.base_revision

    @property
    def events(self) -> tuple[RunEvent, ...]:
        persisted_receipts = tuple(
            RunEvent(
                kind="RunCommandReceiptRecorded",
                payload={
                    "case_id": identity[0],
                    "key": identity[1],
                    "fingerprint": self.state.idempotency_claims.get(identity, ""),
                    "receipt": dict(receipt),
                },
                operation_id=identity[1],
            )
            for identity, receipt in self.state.idempotency_receipts.items()
        )
        return (
            *tuple(
                RunEvent(
                    kind=event.kind,
                    payload=event.payload,
                    operation_id=event.operation_id,
                )
                for event in self.state.events
            ),
            *persisted_receipts,
        )

    @property
    def effect_intent(self) -> Mapping[str, object] | None:
        return self.state.effect_intent

    def stage(
        self,
        *,
        events: tuple[RunEvent, ...],
        effect_intent: Mapping[str, object] | None = None,
    ) -> None:
        self.repository.stage(
            self.state.run_id,
            events=events,
            effect_intent=effect_intent,
        )

    def accept(self) -> None:
        self.committed = True

    def __enter__(self) -> "BufferedRunCommand":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        del exc_type, exc, traceback
        self.repository.finish(
            self.state,
            self.token,
            committed=self.committed,
        )


class BufferedRuntimeRepository:
    """Provide one command-local projection while deferring Run event commits."""

    def __init__(
        self,
        base_repository: RuntimeRepository,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.base_repository = base_repository
        self.clock = clock
        self._state: ContextVar[_BufferedRunState | None] = ContextVar(
            f"openubmc_run_buffer_{id(self)}",
            default=None,
        )

    def begin(self, run_id: str) -> BufferedRunCommand:
        if self._state.get() is not None:
            raise ContextRuntimeError("a Run command transaction is already active")
        base_projection = self.base_repository.load(run_id)
        base_events = (
            self.base_repository.events(run_id)
            if base_projection is not None
            else ()
        )
        base_revision = len(base_events)
        state = _BufferedRunState(
            run_id=run_id,
            base_revision=base_revision,
            base_events=base_events,
            last_access=float(
                base_projection.get("last_access", 0.0)
                if isinstance(base_projection, Mapping)
                else 0.0
            ),
            recorded_at=self.clock(),
        )
        return BufferedRunCommand(self, state, self._state.set(state))

    def transaction_active(self, run_id: str) -> bool:
        state = self._state.get()
        return state is not None and state.run_id == run_id

    def stage(
        self,
        run_id: str,
        *,
        events: tuple[RunEvent, ...],
        effect_intent: Mapping[str, object] | None = None,
    ) -> None:
        """Stage the complete RunEngine transition in the command-local draft."""

        state = self._active(run_id)
        if state is None:
            raise ContextRuntimeError(
                "Run transition staging requires an active Run command transaction"
            )
        if effect_intent is not None and state.effect_intent is not None:
            raise ContextRuntimeError(
                "one RunDecision cannot schedule multiple Effects"
            )
        state.events.extend(
            PendingCaseEvent(
                kind=event.kind,
                payload=dict(event.payload),
                operation_id=event.operation_id,
            )
            for event in events
        )
        if effect_intent is not None:
            state.effect_intent = dict(effect_intent)

    def reattach(self, run_id: str, task_id: str) -> None:
        if self.base_repository.load(run_id) is None:
            raise CaseNotFound(run_id)
        for event in self.base_repository.events(run_id):
            if event.get("kind") != "RunCommandReceiptRecorded":
                continue
            payload = event.get("payload", {})
            if not isinstance(payload, Mapping):
                continue
            case_id = str(payload.get("case_id", ""))
            key = str(payload.get("key", ""))
            fingerprint = str(payload.get("fingerprint", ""))
            receipt = payload.get("receipt")
            if (
                case_id != run_id
                or not key
                or not fingerprint
                or not isinstance(receipt, Mapping)
            ):
                continue
            try:
                replay = self.base_repository.claim_idempotency(
                    case_id,
                    key,
                    fingerprint,
                )
            except OperationAlreadyInProgress:
                replay = None
            if replay is None:
                self.base_repository.complete_idempotency(
                    case_id,
                    key,
                    receipt,
                )
        self.base_repository.bind_task(task_id, run_id)

    def _active(self, case_id: str) -> _BufferedRunState | None:
        state = self._state.get()
        if state is None:
            return None
        if state.run_id != case_id:
            raise ContextRuntimeError(
                "one Run command cannot mutate a second Case"
            )
        return state

    @staticmethod
    def _public_event(
        event: PendingCaseEvent,
        *,
        revision: int,
        created_at: float,
    ) -> dict[str, object]:
        return {
            "revision": revision,
            "kind": event.kind,
            "operation_id": event.operation_id,
            "payload": dict(event.payload),
            "created_at": created_at,
        }

    def _events_for(self, state: _BufferedRunState) -> tuple[dict[str, object], ...]:
        return (
            *state.base_events,
            *(
                self._public_event(
                    event,
                    revision=state.base_revision + offset,
                    created_at=state.recorded_at,
                )
                for offset, event in enumerate(state.events, start=1)
            ),
        )

    def load(self, case_id: str) -> dict[str, object] | None:
        state = self._active(case_id) if self._state.get() is not None else None
        if state is None:
            return self.base_repository.load(case_id)
        events = self._events_for(state)
        if not events:
            return None
        return project_case(case_id, events, last_access=state.last_access)

    def events(self, case_id: str) -> tuple[dict[str, object], ...]:
        state = self._active(case_id) if self._state.get() is not None else None
        if state is None:
            return self.base_repository.events(case_id)
        events = self._events_for(state)
        if not events:
            raise CaseNotFound(case_id)
        return events

    def current_revision(self, case_id: str) -> int | None:
        state = self._active(case_id) if self._state.get() is not None else None
        if state is None:
            return self.base_repository.current_revision(case_id)
        if not state.base_events and not state.events:
            return None
        return state.base_revision + len(state.events)

    def commit(
        self,
        case_id: str,
        *,
        expected_revision: int,
        events: Iterable[PendingCaseEvent],
    ) -> dict[str, object]:
        state = self._active(case_id) if self._state.get() is not None else None
        if state is None:
            return self.base_repository.commit(
                case_id,
                expected_revision=expected_revision,
                events=events,
            )
        current_revision = state.base_revision + len(state.events)
        if expected_revision != current_revision:
            raise RevisionConflict(
                f"case {case_id} revision is {current_revision}, "
                f"expected {expected_revision}"
            )
        state.events.extend(
            PendingCaseEvent(
                kind=event.kind,
                payload=dict(event.payload),
                operation_id=event.operation_id,
            )
            for event in events
        )
        projection = self.load(case_id)
        if projection is None:
            raise CaseNotFound(case_id)
        return projection

    def claim_idempotency(
        self, case_id: str, key: str, fingerprint: str
    ) -> Mapping[str, object] | None:
        state = self._active(case_id) if self._state.get() is not None else None
        replay = self.base_repository.claim_idempotency(
            case_id, key, fingerprint
        )
        if state is not None and replay is None:
            state.idempotency_claims[(case_id, key)] = fingerprint
        return replay

    def complete_idempotency(
        self, case_id: str, key: str, receipt: Mapping[str, object]
    ) -> None:
        state = self._active(case_id) if self._state.get() is not None else None
        if state is None:
            self.base_repository.complete_idempotency(case_id, key, receipt)
            return
        state.idempotency_receipts[(case_id, key)] = dict(receipt)

    def abandon_idempotency(self, case_id: str, key: str) -> None:
        state = self._active(case_id) if self._state.get() is not None else None
        if state is not None:
            state.idempotency_claims.pop((case_id, key), None)
            state.idempotency_receipts.pop((case_id, key), None)
        self.base_repository.abandon_idempotency(case_id, key)

    def bind_task(self, task_id: str, case_id: str) -> None:
        state = self._active(case_id) if self._state.get() is not None else None
        if state is None:
            self.base_repository.bind_task(task_id, case_id)
            return
        state.bindings[task_id] = case_id
        state.unbound_tasks.discard(task_id)

    def case_for_task(self, task_id: str) -> str | None:
        state = self._state.get()
        if state is not None:
            if task_id in state.unbound_tasks:
                return None
            if task_id in state.bindings:
                return state.bindings[task_id]
        return self.base_repository.case_for_task(task_id)

    def is_case_bound(self, case_id: str) -> bool:
        state = self._state.get()
        if state is not None and case_id in state.bindings.values():
            return True
        return self.base_repository.is_case_bound(case_id)

    def unbind_task(self, task_id: str) -> None:
        state = self._state.get()
        if state is None:
            self.base_repository.unbind_task(task_id)
            return
        state.bindings.pop(task_id, None)
        state.unbound_tasks.add(task_id)

    def touch(self, case_id: str, *, at: float) -> None:
        state = self._active(case_id) if self._state.get() is not None else None
        if state is None:
            self.base_repository.touch(case_id, at=at)
            return
        state.last_access = at

    def evidence_reference(
        self, case_id: str, evidence_id: str
    ) -> dict[str, object] | None:
        state = self._active(case_id) if self._state.get() is not None else None
        if state is not None:
            for event in reversed(state.events):
                if event.kind != "EvidenceAttached":
                    continue
                reference = event.payload.get("evidence")
                if (
                    isinstance(reference, Mapping)
                    and str(reference.get("evidence_id", "")) == evidence_id
                ):
                    return dict(reference)
        return self.base_repository.evidence_reference(case_id, evidence_id)

    def evidence_references(
        self, case_id: str
    ) -> tuple[dict[str, object], ...]:
        projection = self.load(case_id)
        if not isinstance(projection, Mapping):
            return ()
        return tuple(
            dict(item)
            for item in projection.get("evidence_refs", [])
            if isinstance(item, Mapping)
        )

    def evidence_query_candidates(
        self, query: EvidenceQuery, *, limit: int
    ) -> tuple[dict[str, object], ...]:
        return self.base_repository.evidence_query_candidates(query, limit=limit)

    def blob_reference_count(self, blob_id: str) -> int:
        count = self.base_repository.blob_reference_count(blob_id)
        state = self._state.get()
        if state is None:
            return count
        return count + sum(
            1
            for event in state.events
            if event.kind == "EvidenceAttached"
            and isinstance(event.payload.get("evidence"), Mapping)
            and str(event.payload["evidence"].get("blob_id", "")) == blob_id
        )

    def finish(
        self,
        state: _BufferedRunState,
        token: Token,
        *,
        committed: bool,
    ) -> None:
        try:
            if committed:
                for task_id in state.unbound_tasks:
                    self.base_repository.unbind_task(task_id)
                for task_id, case_id in state.bindings.items():
                    self.base_repository.bind_task(task_id, case_id)
                for identity, receipt in state.idempotency_receipts.items():
                    self.base_repository.complete_idempotency(
                        identity[0], identity[1], receipt
                    )
                for case_id, key in (
                    set(state.idempotency_claims) - set(state.idempotency_receipts)
                ):
                    self.base_repository.abandon_idempotency(case_id, key)
            else:
                for case_id, key in state.idempotency_claims:
                    self.base_repository.abandon_idempotency(case_id, key)
        finally:
            self._state.reset(token)

    def __getattr__(self, name: str):
        return getattr(self.base_repository, name)


class InMemoryRuntimeRepository:
    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._events: dict[str, list[dict[str, object]]] = {}
        self._evidence_index: dict[tuple[str, str], dict[str, object]] = {}
        self._idempotency: dict[tuple[str, str], dict[str, object]] = {}
        self._bindings: dict[str, str] = {}
        self._meta: dict[str, dict[str, object]] = {}
        self._clock = clock
        self._lock = threading.RLock()

    def _load_locked(self, case_id: str) -> dict[str, object] | None:
        events = self._events.get(case_id)
        if events is None:
            return None
        meta = self._meta.get(case_id, {})
        return project_case(
            case_id,
            events,
            last_access=float(meta.get("last_access", 0.0)),
        )

    def load(self, case_id: str) -> dict[str, object] | None:
        with self._lock:
            projection = self._load_locked(case_id)
            return json.loads(json.dumps(projection)) if projection is not None else None

    def events(self, case_id: str) -> tuple[dict[str, object], ...]:
        with self._lock:
            if case_id not in self._events:
                raise CaseNotFound(case_id)
            return tuple(json.loads(json.dumps(self._events[case_id])))

    def current_revision(self, case_id: str) -> int | None:
        with self._lock:
            events = self._events.get(case_id)
            return len(events) if events is not None else None

    def commit(
        self,
        case_id: str,
        *,
        expected_revision: int,
        events: Iterable[PendingCaseEvent],
    ) -> dict[str, object]:
        pending = tuple(events)
        if not pending:
            projection = self.load(case_id)
            if projection is None:
                raise CaseNotFound(case_id)
            return projection
        with self._lock:
            existing = self._events.setdefault(case_id, [])
            current = len(existing)
            if current != expected_revision:
                raise RevisionConflict(
                    f"case {case_id} revision is {current}, expected {expected_revision}"
                )
            now = self._clock()
            for item in pending:
                revision = len(existing) + 1
                existing.append(
                    {
                        "revision": revision,
                        "kind": item.kind,
                        "operation_id": item.operation_id,
                        "payload": dict(item.payload),
                        "created_at": now,
                    }
                )
                if item.kind == "EvidenceAttached":
                    reference = item.payload.get("evidence")
                    if isinstance(reference, Mapping):
                        evidence_id = str(reference.get("evidence_id", ""))
                        if evidence_id:
                            indexed = dict(reference)
                            indexed.setdefault("case_id", case_id)
                            self._evidence_index[(case_id, evidence_id)] = indexed
            projection = self._load_locked(case_id)
            assert projection is not None
            self._meta[case_id] = {
                "last_access": now,
                "status": projection["status"],
                "created_at": self._meta.get(case_id, {}).get("created_at", now),
            }
            return json.loads(json.dumps(projection))

    def claim_idempotency(
        self, case_id: str, key: str, fingerprint: str
    ) -> Mapping[str, object] | None:
        identity = (case_id, key)
        with self._lock:
            existing = self._idempotency.get(identity)
            if existing is None:
                self._idempotency[identity] = {
                    "fingerprint": fingerprint,
                    "status": "pending",
                    "receipt": None,
                }
                return None
            if existing["fingerprint"] != fingerprint:
                raise IdempotencyConflict(
                    f"idempotency key {key} is already bound to different input"
                )
            receipt = existing.get("receipt")
            if isinstance(receipt, Mapping):
                return json.loads(json.dumps(receipt))
            raise OperationAlreadyInProgress(
                f"idempotency key {key} is already in progress"
            )

    def complete_idempotency(
        self, case_id: str, key: str, receipt: Mapping[str, object]
    ) -> None:
        with self._lock:
            self._idempotency[(case_id, key)]["status"] = "completed"
            self._idempotency[(case_id, key)]["receipt"] = dict(receipt)

    def abandon_idempotency(self, case_id: str, key: str) -> None:
        with self._lock:
            identity = (case_id, key)
            existing = self._idempotency.get(identity)
            if existing is not None and existing.get("status") == "pending":
                self._idempotency.pop(identity, None)

    def bind_task(self, task_id: str, case_id: str) -> None:
        with self._lock:
            self._bindings[task_id] = case_id

    def case_for_task(self, task_id: str) -> str | None:
        with self._lock:
            return self._bindings.get(task_id)

    def is_case_bound(self, case_id: str) -> bool:
        with self._lock:
            return any(bound == case_id for bound in self._bindings.values())

    def unbind_task(self, task_id: str) -> None:
        with self._lock:
            self._bindings.pop(task_id, None)

    def touch(self, case_id: str, *, at: float) -> None:
        with self._lock:
            if case_id not in self._events:
                raise CaseNotFound(case_id)
            self._meta.setdefault(case_id, {})["last_access"] = at

    def evidence_reference(
        self, case_id: str, evidence_id: str
    ) -> dict[str, object] | None:
        with self._lock:
            reference = self._evidence_index.get((case_id, evidence_id))
            return (
                json.loads(json.dumps(reference))
                if reference is not None
                else None
            )

    def evidence_references(
        self, case_id: str
    ) -> tuple[dict[str, object], ...]:
        with self._lock:
            if case_id not in self._events:
                raise CaseNotFound(case_id)
            references = [
                reference
                for (indexed_case_id, _evidence_id), reference in self._evidence_index.items()
                if indexed_case_id == case_id
            ]
            references.sort(
                key=lambda item: (
                    float(item.get("observed_at", 0.0)),
                    str(item.get("evidence_id", "")),
                )
            )
            return tuple(json.loads(json.dumps(references)))

    def evidence_query_candidates(
        self,
        query: EvidenceQuery,
        *,
        limit: int,
    ) -> tuple[dict[str, object], ...]:
        with self._lock:
            references = [
                reference
                for reference in self._evidence_index.values()
                if (
                    not query.case_id
                    or str(reference.get("case_id", "")) == query.case_id
                )
                and (
                    not query.target_id
                    or str(reference.get("target_id", "")) == query.target_id
                )
                and (
                    not query.producer
                    or str(reference.get("producer", "")) == query.producer
                )
                and (
                    not query.workflow_definition_id
                    or str(reference.get("workflow_definition_id", ""))
                    == query.workflow_definition_id
                )
                and (
                    query.observed_after is None
                    or float(reference.get("observed_at", 0.0))
                    >= query.observed_after
                )
                and (
                    query.observed_before is None
                    or float(reference.get("observed_at", 0.0))
                    <= query.observed_before
                )
            ]
            references.sort(
                key=lambda item: (
                    float(item.get("observed_at", 0.0)),
                    str(item.get("case_id", "")),
                    str(item.get("evidence_id", "")),
                ),
                reverse=True,
            )
            return tuple(json.loads(json.dumps(references[:limit])))

    def delete_case(self, case_id: str) -> tuple[dict[str, object], ...]:
        with self._lock:
            if case_id not in self._events:
                return ()
            refs = tuple(
                dict(reference)
                for (indexed_case_id, _evidence_id), reference in self._evidence_index.items()
                if indexed_case_id == case_id
            )
            self._evidence_index = {
                identity: reference
                for identity, reference in self._evidence_index.items()
                if identity[0] != case_id
            }
            self._events.pop(case_id, None)
            self._meta.pop(case_id, None)
            self._idempotency = {
                identity: value
                for identity, value in self._idempotency.items()
                if identity[0] != case_id
            }
            self._bindings = {
                task: bound
                for task, bound in self._bindings.items()
                if bound != case_id
            }
            return refs

    def metadata(self) -> tuple[dict[str, object], ...]:
        with self._lock:
            return tuple(
                {
                    "case_id": case_id,
                    "last_access": float(meta.get("last_access", 0.0)),
                    "status": str(meta.get("status", "open")),
                }
                for case_id, meta in self._meta.items()
            )

    def blob_reference_count(self, blob_id: str) -> int:
        with self._lock:
            return sum(
                1
                for reference in self._evidence_index.values()
                if reference.get("blob_id") == blob_id
            )

    def size_bytes(self) -> int:
        with self._lock:
            return len(
                _json_bytes(
                    {
                        "events": self._events,
                        "evidence_index": {
                            f"{case_id}:{evidence_id}": reference
                            for (case_id, evidence_id), reference in self._evidence_index.items()
                        },
                        "idempotency": {
                            f"{case_id}:{key}": value
                            for (case_id, key), value in self._idempotency.items()
                        },
                        "bindings": self._bindings,
                        "meta": self._meta,
                    }
                )
            )

    def status(self) -> dict[str, object]:
        with self._lock:
            return {
                "adapter": "memory",
                "case_count": len(self._events),
                "idempotency_count": len(self._idempotency),
                "task_binding_count": len(self._bindings),
                "evidence_index_count": len(self._evidence_index),
            }


class SQLiteRuntimeRepository:
    """SQLite WAL append-only case and idempotency repository."""

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], float] = time.time,
        owner_is_active: Callable[[int, str], bool] = _process_owner_is_active,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._clock = clock
        self._owner_pid = os.getpid()
        self._owner_started = _process_start_marker(self._owner_pid)
        self._owner_token = uuid.uuid4().hex
        self._owner_is_active = owner_is_active
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS case_events (
                    case_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (case_id, revision)
                );
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL,
                    last_access REAL NOT NULL,
                    status TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS idempotency (
                    case_id TEXT NOT NULL,
                    key TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    status TEXT NOT NULL,
                    receipt_json TEXT,
                    updated_at REAL NOT NULL,
                    owner_pid INTEGER NOT NULL DEFAULT 0,
                    owner_started TEXT NOT NULL DEFAULT '',
                    owner_token TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (case_id, key)
                );
                CREATE TABLE IF NOT EXISTS task_bindings (
                    task_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    owner_pid INTEGER NOT NULL DEFAULT 0,
                    owner_started TEXT NOT NULL DEFAULT '',
                    owner_token TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS runtime_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence_index (
                    case_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    blob_id TEXT NOT NULL,
                    reference_json TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    PRIMARY KEY (case_id, evidence_id)
                );
                CREATE INDEX IF NOT EXISTS evidence_index_blob
                    ON evidence_index(blob_id);
                """
            )
            indexed = {
                (str(row["case_id"]), str(row["evidence_id"]))
                for row in connection.execute(
                    "SELECT case_id, evidence_id FROM evidence_index"
                )
            }
            for event_row in connection.execute(
                "SELECT case_id, payload_json, created_at FROM case_events "
                "WHERE kind = 'EvidenceAttached' ORDER BY case_id, revision"
            ):
                payload = json.loads(event_row["payload_json"])
                reference = (
                    payload.get("evidence") if isinstance(payload, Mapping) else None
                )
                if not isinstance(reference, Mapping):
                    continue
                evidence_id = str(reference.get("evidence_id", ""))
                identity = (str(event_row["case_id"]), evidence_id)
                if not evidence_id or identity in indexed:
                    continue
                public = dict(reference)
                public.setdefault("case_id", identity[0])
                connection.execute(
                    "INSERT INTO evidence_index "
                    "(case_id, evidence_id, blob_id, reference_json, observed_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        identity[0],
                        evidence_id,
                        str(public.get("blob_id", "")),
                        _json_bytes(public).decode("utf-8"),
                        float(public.get("observed_at", event_row["created_at"])),
                    ),
                )
                indexed.add(identity)
            idempotency_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(idempotency)")
            }
            for name, declaration in (
                ("owner_pid", "INTEGER NOT NULL DEFAULT 0"),
                ("owner_started", "TEXT NOT NULL DEFAULT ''"),
                ("owner_token", "TEXT NOT NULL DEFAULT ''"),
            ):
                if name not in idempotency_columns:
                    connection.execute(
                        f"ALTER TABLE idempotency ADD COLUMN {name} {declaration}"
                    )
            binding_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(task_bindings)")
            }
            for name, declaration in (
                ("owner_pid", "INTEGER NOT NULL DEFAULT 0"),
                ("owner_started", "TEXT NOT NULL DEFAULT ''"),
                ("owner_token", "TEXT NOT NULL DEFAULT ''"),
            ):
                if name not in binding_columns:
                    connection.execute(
                        f"ALTER TABLE task_bindings ADD COLUMN {name} {declaration}"
                    )
            row = connection.execute(
                "SELECT value FROM runtime_meta WHERE key = 'storage_version'"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO runtime_meta (key, value) VALUES ('storage_version', ?)",
                    (str(CONTEXT_RUNTIME_STORAGE_VERSION),),
                )
            elif str(row["value"]) != str(CONTEXT_RUNTIME_STORAGE_VERSION):
                raise ContextRuntimeError(
                    "unsupported Context Runtime storage version: "
                    + str(row["value"])
                )

    @staticmethod
    def _load_from_connection(
        connection: sqlite3.Connection, case_id: str
    ) -> dict[str, object] | None:
        rows = connection.execute(
            "SELECT revision, kind, operation_id, payload_json, created_at "
            "FROM case_events WHERE case_id = ? ORDER BY revision",
            (case_id,),
        ).fetchall()
        if not rows:
            return None
        meta = connection.execute(
            "SELECT last_access FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        events = [
            {
                "revision": row["revision"],
                "kind": row["kind"],
                "operation_id": row["operation_id"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]
        return project_case(
            case_id,
            events,
            last_access=float(meta["last_access"]) if meta is not None else 0.0,
        )

    def load(self, case_id: str) -> dict[str, object] | None:
        with self._lock, self._connect() as connection:
            return self._load_from_connection(connection, case_id)

    def events(self, case_id: str) -> tuple[dict[str, object], ...]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT revision, kind, operation_id, payload_json, created_at "
                "FROM case_events WHERE case_id = ? ORDER BY revision",
                (case_id,),
            ).fetchall()
            if not rows:
                raise CaseNotFound(case_id)
            return tuple(
                {
                    "revision": int(row["revision"]),
                    "kind": str(row["kind"]),
                    "operation_id": str(row["operation_id"]),
                    "payload": json.loads(row["payload_json"]),
                    "created_at": float(row["created_at"]),
                }
                for row in rows
            )

    def current_revision(self, case_id: str) -> int | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT MAX(revision) AS revision FROM case_events WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            revision = row["revision"] if row is not None else None
            return int(revision) if revision is not None else None

    def commit(
        self,
        case_id: str,
        *,
        expected_revision: int,
        events: Iterable[PendingCaseEvent],
    ) -> dict[str, object]:
        pending = tuple(events)
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT COALESCE(MAX(revision), 0) AS revision "
                "FROM case_events WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            current = int(row["revision"])
            if current != expected_revision:
                raise RevisionConflict(
                    f"case {case_id} revision is {current}, expected {expected_revision}"
                )
            now = self._clock()
            for offset, item in enumerate(pending, start=1):
                connection.execute(
                    "INSERT INTO case_events "
                    "(case_id, revision, kind, operation_id, payload_json, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        case_id,
                        current + offset,
                        item.kind,
                        item.operation_id,
                        _json_bytes(dict(item.payload)).decode("utf-8"),
                        now,
                    ),
                )
                if item.kind == "EvidenceAttached":
                    reference = item.payload.get("evidence")
                    if isinstance(reference, Mapping):
                        evidence_id = str(reference.get("evidence_id", ""))
                        if evidence_id:
                            public = dict(reference)
                            public.setdefault("case_id", case_id)
                            connection.execute(
                                "INSERT INTO evidence_index "
                                "(case_id, evidence_id, blob_id, reference_json, observed_at) "
                                "VALUES (?, ?, ?, ?, ?) "
                                "ON CONFLICT(case_id, evidence_id) DO UPDATE SET "
                                "blob_id = excluded.blob_id, "
                                "reference_json = excluded.reference_json, "
                                "observed_at = excluded.observed_at",
                                (
                                    case_id,
                                    evidence_id,
                                    str(public.get("blob_id", "")),
                                    _json_bytes(public).decode("utf-8"),
                                    float(public.get("observed_at", now)),
                                ),
                            )
            projection = self._load_from_connection(connection, case_id)
            if projection is None:
                raise CaseNotFound(case_id)
            connection.execute(
                "INSERT INTO cases (case_id, created_at, last_access, status) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(case_id) DO UPDATE SET "
                "last_access = excluded.last_access, status = excluded.status",
                (case_id, now, now, projection["status"]),
            )
            connection.commit()
            projection["last_access"] = now
            return projection

    def claim_idempotency(
        self, case_id: str, key: str, fingerprint: str
    ) -> Mapping[str, object] | None:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT fingerprint, status, receipt_json, owner_pid, "
                "owner_started, owner_token FROM idempotency "
                "WHERE case_id = ? AND key = ?",
                (case_id, key),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO idempotency "
                    "(case_id, key, fingerprint, status, receipt_json, updated_at, "
                    "owner_pid, owner_started, owner_token) "
                    "VALUES (?, ?, ?, 'pending', NULL, ?, ?, ?, ?)",
                    (
                        case_id,
                        key,
                        fingerprint,
                        self._clock(),
                        self._owner_pid,
                        self._owner_started,
                        self._owner_token,
                    ),
                )
                connection.commit()
                return None
            if row["fingerprint"] != fingerprint:
                raise IdempotencyConflict(
                    f"idempotency key {key} is already bound to different input"
                )
            if row["status"] == "completed" and row["receipt_json"]:
                return json.loads(row["receipt_json"])
            owner_pid = int(row["owner_pid"] or 0)
            owner_started = str(row["owner_started"] or "")
            owner_token = str(row["owner_token"] or "")
            if owner_token != self._owner_token and not self._owner_is_active(
                owner_pid, owner_started
            ):
                connection.execute(
                    "UPDATE idempotency SET status = 'pending', receipt_json = NULL, "
                    "updated_at = ?, owner_pid = ?, owner_started = ?, owner_token = ? "
                    "WHERE case_id = ? AND key = ?",
                    (
                        self._clock(),
                        self._owner_pid,
                        self._owner_started,
                        self._owner_token,
                        case_id,
                        key,
                    ),
                )
                connection.commit()
                return None
            raise OperationAlreadyInProgress(
                f"idempotency key {key} is already in progress"
            )

    def complete_idempotency(
        self, case_id: str, key: str, receipt: Mapping[str, object]
    ) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "UPDATE idempotency SET status = 'completed', receipt_json = ?, "
                "updated_at = ? WHERE case_id = ? AND key = ?",
                (
                    _json_bytes(dict(receipt)).decode("utf-8"),
                    self._clock(),
                    case_id,
                    key,
                ),
            )

    def abandon_idempotency(self, case_id: str, key: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "DELETE FROM idempotency WHERE case_id = ? AND key = ? "
                "AND status = 'pending'",
                (case_id, key),
            )

    def bind_task(self, task_id: str, case_id: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO task_bindings "
                "(task_id, case_id, updated_at, owner_pid, owner_started, owner_token) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(task_id) DO UPDATE SET "
                "case_id = excluded.case_id, updated_at = excluded.updated_at, "
                "owner_pid = excluded.owner_pid, "
                "owner_started = excluded.owner_started, "
                "owner_token = excluded.owner_token",
                (
                    task_id,
                    case_id,
                    self._clock(),
                    self._owner_pid,
                    self._owner_started,
                    self._owner_token,
                ),
            )

    def case_for_task(self, task_id: str) -> str | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT case_id FROM task_bindings WHERE task_id = ?", (task_id,)
            ).fetchone()
            return str(row["case_id"]) if row is not None else None

    def is_case_bound(self, case_id: str) -> bool:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT task_id, owner_pid, owner_started, owner_token "
                "FROM task_bindings WHERE case_id = ?",
                (case_id,),
            ).fetchall()
            active = False
            stale_task_ids: list[str] = []
            for row in rows:
                owner_token = str(row["owner_token"] or "")
                if owner_token == self._owner_token or self._owner_is_active(
                    int(row["owner_pid"] or 0),
                    str(row["owner_started"] or ""),
                ):
                    active = True
                else:
                    stale_task_ids.append(str(row["task_id"]))
            if stale_task_ids:
                connection.executemany(
                    "DELETE FROM task_bindings WHERE task_id = ?",
                    ((task_id,) for task_id in stale_task_ids),
                )
            return active

    def unbind_task(self, task_id: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM task_bindings WHERE task_id = ?", (task_id,))

    def touch(self, case_id: str, *, at: float) -> None:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "UPDATE cases SET last_access = ? WHERE case_id = ?", (at, case_id)
            )
            if cursor.rowcount == 0:
                raise CaseNotFound(case_id)

    def evidence_reference(
        self, case_id: str, evidence_id: str
    ) -> dict[str, object] | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT reference_json FROM evidence_index "
                "WHERE case_id = ? AND evidence_id = ?",
                (case_id, evidence_id),
            ).fetchone()
            return json.loads(row["reference_json"]) if row is not None else None

    def evidence_references(
        self, case_id: str
    ) -> tuple[dict[str, object], ...]:
        with self._lock, self._connect() as connection:
            exists = connection.execute(
                "SELECT 1 FROM case_events WHERE case_id = ? LIMIT 1",
                (case_id,),
            ).fetchone()
            if exists is None:
                raise CaseNotFound(case_id)
            rows = connection.execute(
                "SELECT reference_json FROM evidence_index WHERE case_id = ? "
                "ORDER BY observed_at, evidence_id",
                (case_id,),
            ).fetchall()
            return tuple(json.loads(row["reference_json"]) for row in rows)

    def evidence_query_candidates(
        self,
        query: EvidenceQuery,
        *,
        limit: int,
    ) -> tuple[dict[str, object], ...]:
        clauses: list[str] = []
        parameters: list[object] = []
        for column, value in (("case_id", query.case_id),):
            if value:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        for path, value in (
            ("$.target_id", query.target_id),
            ("$.producer", query.producer),
            ("$.workflow_definition_id", query.workflow_definition_id),
        ):
            if value:
                clauses.append("json_extract(reference_json, ?) = ?")
                parameters.extend((path, value))
        if query.observed_after is not None:
            clauses.append("observed_at >= ?")
            parameters.append(query.observed_after)
        if query.observed_before is not None:
            clauses.append("observed_at <= ?")
            parameters.append(query.observed_before)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(limit)
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT reference_json FROM evidence_index"
                + where
                + " ORDER BY observed_at DESC, case_id DESC, evidence_id DESC LIMIT ?",
                parameters,
            ).fetchall()
            return tuple(json.loads(row["reference_json"]) for row in rows)

    def delete_case(self, case_id: str) -> tuple[dict[str, object], ...]:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            exists = connection.execute(
                "SELECT 1 FROM case_events WHERE case_id = ? LIMIT 1", (case_id,)
            ).fetchone()
            if exists is None:
                connection.rollback()
                return ()
            refs = tuple(
                json.loads(row["reference_json"])
                for row in connection.execute(
                    "SELECT reference_json FROM evidence_index WHERE case_id = ?",
                    (case_id,),
                )
            )
            connection.execute(
                "DELETE FROM evidence_index WHERE case_id = ?", (case_id,)
            )
            connection.execute("DELETE FROM case_events WHERE case_id = ?", (case_id,))
            connection.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
            connection.execute("DELETE FROM idempotency WHERE case_id = ?", (case_id,))
            connection.execute("DELETE FROM task_bindings WHERE case_id = ?", (case_id,))
            connection.commit()
            return refs

    def metadata(self) -> tuple[dict[str, object], ...]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT case_id, last_access, status FROM cases ORDER BY last_access"
            ).fetchall()
            return tuple(dict(row) for row in rows)

    def blob_reference_count(self, blob_id: str) -> int:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM evidence_index WHERE blob_id = ?",
                (blob_id,),
            ).fetchone()
            return int(row["count"])

    def size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self.path) + suffix)
            if path.is_file():
                total += path.stat().st_size
        return total

    def status(self) -> dict[str, object]:
        with self._lock, self._connect() as connection:
            case_count = connection.execute(
                "SELECT COUNT(*) AS count FROM cases"
            ).fetchone()["count"]
            idempotency_count = connection.execute(
                "SELECT COUNT(*) AS count FROM idempotency"
            ).fetchone()["count"]
            binding_count = connection.execute(
                "SELECT COUNT(*) AS count FROM task_bindings"
            ).fetchone()["count"]
            evidence_index_count = connection.execute(
                "SELECT COUNT(*) AS count FROM evidence_index"
            ).fetchone()["count"]
        return {
            "adapter": "sqlite",
            "case_count": int(case_count),
            "idempotency_count": int(idempotency_count),
            "task_binding_count": int(binding_count),
            "evidence_index_count": int(evidence_index_count),
            "database_bytes": self.size_bytes(),
        }


class ContextToolResult(dict[str, object]):
    """Legacy mapping for Python callers plus compact MCP envelope."""

    def __init__(
        self,
        legacy: Mapping[str, object],
        envelope: Mapping[str, object],
    ) -> None:
        super().__init__(legacy)
        self.envelope = dict(envelope)


def _summary_for(operation: str, value: Mapping[str, object]) -> str:
    for key in ("summary", "message", "next_action", "next_step"):
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    if "completed" in value:
        if value.get("completed"):
            return f"{operation} completed"
        if value.get("partial"):
            return f"{operation} partially completed"
    if value.get("ok") is False:
        return f"{operation} completed with partial or failed evidence"
    return f"{operation} completed"


def _facts_for(value: Mapping[str, object], *, max_facts: int = 32) -> list[dict[str, object]]:
    priority = (
        "ok",
        "schema",
        "normalized_code",
        "code",
        "completed",
        "partial",
        "profile",
        "task",
        "ip",
        "target_id",
        "product_version",
    )
    facts: list[dict[str, object]] = []
    for key in priority:
        item = value.get(key)
        if isinstance(item, (str, int, float, bool)) or item is None:
            if key in value:
                facts.append({"key": key, "value": item})
        if len(facts) >= max_facts:
            break
    targets = value.get("targets")
    if isinstance(targets, list) and len(facts) < max_facts:
        facts.append({"key": "target_count", "value": len(targets)})
    journal = value.get("journal")
    if isinstance(journal, Mapping) and len(facts) < max_facts:
        stage = journal.get("stage")
        if isinstance(stage, str):
            facts.append({"key": "mutation_stage", "value": stage})
    return facts


def _next_actions(value: Mapping[str, object]) -> list[str]:
    actions: list[str] = []
    for key in ("next_action", "next_step"):
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate.strip():
            actions.append(candidate.strip())
    return actions[:8]


def bounded_envelope(value: Mapping[str, object], *, max_bytes: int) -> dict[str, object]:
    envelope = dict(value)
    if len(_json_bytes(envelope)) <= max_bytes:
        return envelope
    envelope["content_compacted"] = True
    facts = envelope.get("facts")
    if isinstance(facts, list):
        while facts and len(_json_bytes(envelope)) > max_bytes:
            facts.pop()
    evidence = envelope.get("evidence_refs")
    if isinstance(evidence, list):
        while len(evidence) > 8 and len(_json_bytes(envelope)) > max_bytes:
            evidence.pop()
    summary = envelope.get("summary")
    if isinstance(summary, str) and len(_json_bytes(envelope)) > max_bytes:
        envelope["summary"] = summary[:1024]
    error = envelope.get("canonical_error")
    if isinstance(error, Mapping) and len(_json_bytes(envelope)) > max_bytes:
        envelope["canonical_error"] = {
            "code": str(error.get("code", "internal_error")),
            "message": str(error.get("message", ""))[:512],
        }
    if len(_json_bytes(envelope)) > max_bytes:
        envelope = {
            "schema": envelope.get("schema", AGENT_ENVELOPE_SCHEMA),
            "case_id": envelope.get("case_id", ""),
            "revision": envelope.get("revision", 0),
            "operation": envelope.get("operation", {}),
            "status": envelope.get("status", "failed"),
            "code": envelope.get("code", ""),
            "summary": str(envelope.get("summary", ""))[:512],
            "evidence_refs": list(envelope.get("evidence_refs", []))[:2],
            "gaps": ["content_compacted"],
            "next_actions": list(envelope.get("next_actions", []))[:2],
            "next_action": str(envelope.get("next_action", ""))[:512],
            "canonical_error": envelope.get("canonical_error"),
            "content_compacted": True,
        }
    if len(_json_bytes(envelope)) > max_bytes:
        raise ValueError("agent envelope cannot be compacted below byte limit")
    return envelope


class ContextRuntime:
    """Case lifecycle and bounded response coordinator."""

    def __init__(
        self,
        catalog: OperationCatalog,
        *,
        repository: RuntimeRepository | None = None,
        blob_repository: BlobRepository | None = None,
        envelope_max_bytes: int = AGENT_ENVELOPE_MAX_BYTES,
        max_cached_projections: int = 64,
        max_cached_projection_bytes: int = DEFAULT_PROJECTION_CACHE_BYTES,
        retention_seconds: float = DEFAULT_CASE_RETENTION_SECONDS,
        storage_soft_limit_bytes: int = DEFAULT_STORAGE_SOFT_LIMIT_BYTES,
        clock: Callable[[], float] = time.time,
        workflow_definitions: WorkflowDefinitions = DEFAULT_WORKFLOW_DEFINITIONS,
        operation_stages: Mapping[str, str] | None = None,
    ) -> None:
        if envelope_max_bytes <= 1024:
            raise ValueError("agent envelope byte limit is too small")
        if max_cached_projections <= 0:
            raise ValueError("projection cache size must be positive")
        if max_cached_projection_bytes <= 0:
            raise ValueError("projection cache byte limit must be positive")
        self.catalog = catalog
        base_repository = repository or InMemoryRuntimeRepository(clock=clock)
        self.repository = (
            base_repository
            if isinstance(base_repository, BufferedRuntimeRepository)
            else BufferedRuntimeRepository(base_repository, clock=clock)
        )
        self.blob_repository = blob_repository or InMemoryBlobRepository()
        self.envelope_max_bytes = envelope_max_bytes
        self.max_cached_projections = max_cached_projections
        self.max_cached_projection_bytes = int(max_cached_projection_bytes)
        self.retention_seconds = float(retention_seconds)
        self.storage_soft_limit_bytes = int(storage_soft_limit_bytes)
        self.clock = clock
        self.workflow_definitions = workflow_definitions
        self.operation_stages = dict(operation_stages or {})
        self._projection_cache: OrderedDict[str, dict[str, object]] = OrderedDict()
        self._projection_cache_sizes: dict[str, int] = {}
        self._projection_cache_bytes = 0
        self._capsule_cache: OrderedDict[str, dict[str, object]] = OrderedDict()
        self._metrics = {
            "invocations": 0,
            "idempotent_replays": 0,
            "idempotency_receipt_repairs": 0,
            "warm_continuations": 0,
            "projection_cache_hits": 0,
            "projection_evictions": 0,
            "projection_rebuilds": 0,
            "capsule_cache_hits": 0,
            "capsule_rebuilds": 0,
            "capsule_evictions": 0,
            "evidence_reads": 0,
            "evidence_bytes_read": 0,
            "evidence_bytes_written": 0,
            "envelope_bytes": 0,
            "peak_envelope_bytes": 0,
            "shadow_writes": 0,
            "shadow_write_failures": 0,
            "shadow_parity_mismatches": 0,
            "maintenance_evictions": 0,
        }
        self._lock = threading.RLock()

    def _cache(self, projection: Mapping[str, object]) -> dict[str, object]:
        public = json.loads(json.dumps(projection))
        case_id = str(public["case_id"])
        if self.repository.transaction_active(case_id):
            return public
        public_bytes = len(_json_bytes(public))
        with self._lock:
            if self._projection_cache.pop(case_id, None) is not None:
                self._projection_cache_bytes -= self._projection_cache_sizes.pop(
                    case_id, 0
                )
            cached_capsule = self._capsule_cache.get(case_id)
            if (
                cached_capsule is not None
                and int(cached_capsule.get("case_revision", -1)) != int(public["revision"])
            ):
                self._capsule_cache.pop(case_id, None)
            if public_bytes <= self.max_cached_projection_bytes:
                self._projection_cache[case_id] = public
                self._projection_cache_sizes[case_id] = public_bytes
                self._projection_cache_bytes += public_bytes
            while (
                len(self._projection_cache) > self.max_cached_projections
                or self._projection_cache_bytes > self.max_cached_projection_bytes
            ):
                evicted_case_id, _projection = self._projection_cache.popitem(
                    last=False
                )
                self._projection_cache_bytes -= self._projection_cache_sizes.pop(
                    evicted_case_id, 0
                )
                self._metrics["projection_evictions"] += 1
        return json.loads(json.dumps(public))

    def _load(self, case_id: str, *, touch: bool = False) -> dict[str, object] | None:
        with self._lock:
            cached = self._projection_cache.get(case_id)
            cached_revision = (
                int(cached.get("revision", -1)) if cached is not None else None
            )
        if cached is not None:
            repository_revision = self.repository.current_revision(case_id)
            if repository_revision == cached_revision:
                with self._lock:
                    cached = self._projection_cache.get(case_id)
                    if cached is not None:
                        self._projection_cache.move_to_end(case_id)
                        self._metrics["projection_cache_hits"] += 1
                        projection = json.loads(json.dumps(cached))
                    else:
                        projection = None
            else:
                with self._lock:
                    removed = self._projection_cache.pop(case_id, None)
                    if removed is not None:
                        self._projection_cache_bytes -= self._projection_cache_sizes.pop(
                            case_id, 0
                        )
                    self._capsule_cache.pop(case_id, None)
                    self._metrics.setdefault("projection_cache_stale", 0)
                    self._metrics["projection_cache_stale"] += 1
                projection = None
        else:
            projection = None
        if projection is None:
            projection = self.repository.load(case_id)
            if projection is None:
                return None
            self._metrics["projection_rebuilds"] += 1
            projection = self._cache(projection)
        if touch:
            now = self.clock()
            self.repository.touch(case_id, at=now)
            projection["last_access"] = now
            self._cache(projection)
        return projection

    def _capsule(self, projection: Mapping[str, object]) -> dict[str, object]:
        """Build the bounded, revision-bound model input projection."""

        case_id = str(projection["case_id"])
        revision = int(projection["revision"])
        with self._lock:
            cached = self._capsule_cache.get(case_id)
            if cached is not None and int(cached.get("case_revision", -1)) == revision:
                self._capsule_cache.move_to_end(case_id)
                self._metrics["capsule_cache_hits"] += 1
                return json.loads(json.dumps(cached))
        phase_records = [
            dict(item)
            for item in projection.get("phase_records", [])
            if isinstance(item, Mapping)
        ]
        evidence_refs = [
            dict(item)
            for item in projection.get("evidence_refs", [])
            if isinstance(item, Mapping)
        ]
        workflow_definition = DEFAULT_WORKFLOW_DEFINITIONS.definition_for(projection)
        capsule = {
            "schema": f"{CONTEXT_RUNTIME_SCHEMA}/capsule",
            "case_id": case_id,
            "case_revision": revision,
            "status": projection.get("status", "open"),
            "intent": projection.get("intent", ""),
            "entry_domain": projection.get("entry_domain", ""),
            "entry_operation": projection.get("entry_operation", ""),
            "final_purpose": projection.get("final_purpose", ""),
            "change_boundary": projection.get("change_boundary", ""),
            "delivery_strategy": projection.get("delivery_strategy", ""),
            _TASK_POLICY_FIELD: _sanitize(
                projection.get(_TASK_POLICY_FIELD, {})
            ),
            "targets": list(projection.get("targets", [])),
            "target_version": int(projection.get("target_version", 1)),
            "target_epoch_floor": self._target_epoch_floor(
                projection,
                target_id=self._selected_target_id(projection),
            ),
            "target_epoch_floors": self._target_epoch_floors(projection),
            "workflow_cycle_id": str(
                projection.get("workflow_cycle_id", "cycle-1")
            ),
            "workflow_cycle_number": int(
                projection.get("workflow_cycle_number", 1)
            ),
            "workflow_definition": workflow_definition.to_public_dict(),
            "workflow_plan": [
                step.to_public_dict() for step in workflow_definition.steps
            ],
            "target_generations": sorted(
                {
                    f"{item.get('target_id', '')}:{item.get('generation', '')}"
                    for item in evidence_refs
                }
            ),
            "source_revisions": sorted(
                {
                    str(item.get("source_revision", ""))
                    for item in phase_records
                    if item.get("source_revision")
                }
            ),
            "artifact_revisions": sorted(
                {
                    str(item.get("artifact_sha256", ""))
                    for item in phase_records
                    if item.get("artifact_sha256")
                }
            ),
            "evidence_ids": [
                str(item.get("evidence_id", "")) for item in evidence_refs[-32:]
            ],
            "next_actions": list(projection.get("next_actions", []))[:8],
        }
        capsule = bounded_envelope(capsule, max_bytes=self.envelope_max_bytes)
        with self._lock:
            self._capsule_cache.pop(case_id, None)
            self._capsule_cache[case_id] = capsule
            self._metrics["capsule_rebuilds"] += 1
            while len(self._capsule_cache) > self.max_cached_projections:
                self._capsule_cache.popitem(last=False)
                self._metrics["capsule_evictions"] += 1
        return json.loads(json.dumps(capsule))

    def _case_id(
        self,
        task_id: str,
        arguments: Mapping[str, object],
        *,
        bind: bool = True,
    ) -> str:
        explicit = arguments.get("case_id")
        if isinstance(explicit, str) and explicit.strip():
            case_id = _safe_identifier(explicit, fallback="")
            if not case_id:
                raise ValueError("case_id must be a safe 1-128 character identifier")
        else:
            case_id = self.repository.case_for_task(task_id) or (
                "case-" + hashlib.sha256(task_id.encode("utf-8")).hexdigest()[:24]
            )
        if bind:
            self.repository.bind_task(task_id, case_id)
        return case_id

    def _validate_expected_before_case_update(
        self,
        case_id: str,
        arguments: Mapping[str, object],
    ) -> dict[str, object] | None:
        existing = self._load(case_id)
        expected = arguments.get("expected_revision")
        if expected is None:
            return existing
        if isinstance(expected, bool) or not isinstance(expected, int):
            raise TypeError("expected_revision must be an integer")
        observed = int(existing["revision"]) if existing is not None else 0
        if expected != observed:
            raise RevisionConflict(
                f"case {case_id} revision is {observed}, expected {expected}"
            )
        return existing

    def _existing_case(
        self,
        task_id: str,
        arguments: Mapping[str, object],
    ) -> tuple[str, dict[str, object]]:
        if "case_id" in arguments:
            explicit = arguments.get("case_id")
            if not isinstance(explicit, str):
                raise TypeError("case_id must be a string")
            if not explicit.strip():
                raise ValueError("case_id must not be empty")
            case_id = _safe_identifier(explicit, fallback="")
            if not case_id:
                raise ValueError("case_id must be a safe 1-128 character identifier")
        else:
            case_id = self.repository.case_for_task(task_id) or ""
            if not case_id:
                raise CaseNotFound(f"no Case is bound to task {task_id}")
        projection = self._load(case_id)
        if projection is None:
            raise CaseNotFound(case_id)
        return case_id, projection

    @staticmethod
    def _targets(arguments: Mapping[str, object]) -> list[dict[str, object]]:
        raw_targets = arguments.get("targets")
        if isinstance(raw_targets, list):
            return [
                {
                    "target_id": str(item.get("target_id", f"target-{index}")),
                    "role": str(item.get("role", "symmetric")),
                    "address": str(item.get("ip", "")),
                }
                for index, item in enumerate(raw_targets, start=1)
                if isinstance(item, Mapping)
            ]
        address = arguments.get("ip")
        if isinstance(address, str) and address.strip():
            return [
                {
                    "target_id": str(arguments.get("target_id", "target-1")),
                    "role": str(arguments.get("target_role", "candidate")),
                    "address": address.strip(),
                }
            ]
        return []

    def _select_delivery_strategy(
        self,
        projection: Mapping[str, object],
        requested: object,
        *,
        reason: str,
        selection_arguments: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        selected = str(requested or "").strip().lower().replace("_", "-")
        if not selected:
            return dict(projection)
        if selected not in _DELIVERY_STRATEGIES:
            raise ValueError(f"unsupported delivery strategy: {requested}")
        raw_plan = projection.get("acceptance_plan")
        plan = AcceptancePlan.from_public_dict(raw_plan) if isinstance(raw_plan, Mapping) else None
        current = (
            str(projection.get("delivery_strategy", ""))
            .strip()
            .lower()
            .replace("_", "-")
        )
        effective_current = current or (
            plan.delivery_strategy if plan is not None else "source-only"
        )
        if selected == effective_current:
            return dict(projection)
        if projection.get("closed"):
            raise CaseClosed(f"case {projection.get('case_id', '')} is closed")
        intent = str(projection.get("intent", ""))
        if intent != "diagnose-and-fix":
            compatible = (
                intent in {"live-patch", "rollback"} and selected == "live-patch"
            ) or (
                intent == "upgrade-and-verify" and selected == "build-upgrade"
            )
            if compatible:
                return dict(projection)
            raise ValueError(
                "delivery strategy can change only for a diagnose-and-fix Case"
            )
        if effective_current != "source-only" or selected == "source-only":
            raise ValueError(
                "delivery strategy may only be promoted once from source-only"
            )
        revised_plan = AcceptancePlan.freeze(
            {
                "intent": projection.get("intent", "diagnose-and-fix"),
                "delivery_strategy": selected,
                "final_purpose": projection.get("final_purpose", ""),
            },
            frozen_at=self.clock(),
        )
        revised_workflow = self.workflow_definitions.registry.resolve(
            intent=intent,
            entry_domain=_case_entry_domain(projection),
            entry_operation=str(projection.get("entry_operation", "")),
            delivery_strategy=selected,
        )
        current_policy_raw = projection.get(_TASK_POLICY_FIELD)
        if isinstance(current_policy_raw, Mapping) and current_policy_raw:
            current_policy = TaskAuthorizationPolicy.from_public_dict(
                current_policy_raw
            )
        else:
            workflow_inputs = projection.get("workflow_inputs", {})
            workflow_inputs = (
                workflow_inputs if isinstance(workflow_inputs, Mapping) else {}
            )
            current_policy = TaskAuthorizationPolicy.from_task_intent(
                intent,
                delivery_strategy=effective_current,
                authorized_exceptions=workflow_inputs.get(
                    "authorized_exceptions"
                ),
                allow_insecure_tls=_strict_bool(
                    workflow_inputs,
                    "allow_insecure_tls",
                    default=True,
                ),
            )
        selection = selection_arguments or {}
        selected_exceptions = selection.get(
            "authorized_exceptions",
            current_policy.authorized_exceptions.to_public_dict(),
        )
        selected_tls = selection.get(
            "allow_insecure_tls",
            current_policy.allow_insecure_tls,
        )
        if not isinstance(selected_tls, bool):
            raise TypeError("allow_insecure_tls must be a boolean")
        revised_policy = TaskAuthorizationPolicy.from_task_intent(
            intent,
            delivery_strategy=selected,
            authorized_exceptions=selected_exceptions,
            allow_insecure_tls=selected_tls,
        )
        updated = self.repository.commit(
            str(projection["case_id"]),
            expected_revision=int(projection["revision"]),
            events=(
                PendingCaseEvent(
                    "DeliveryStrategySelected",
                    {
                        "previous_delivery_strategy": effective_current,
                        "delivery_strategy": selected,
                        _TASK_POLICY_FIELD: revised_policy.to_public_dict(),
                        "previous_plan_id": plan.plan_id if plan is not None else "",
                        "acceptance_plan": revised_plan.to_public_dict(),
                        "workflow_definition": revised_workflow.to_public_dict(),
                        "reason": _safe_identifier(
                            reason,
                            fallback="explicit-task-selection",
                        ),
                        "workflow_inputs": _sanitize_runtime_inputs(
                            {
                                key: value
                                for key, value in (selection_arguments or {}).items()
                                if key
                                not in {
                                    "case_id",
                                    "expected_revision",
                                    "idempotency_key",
                                    "deadline",
                                    "max_steps",
                                }
                            }
                        ),
                    },
                ),
            ),
        )
        return self._cache(updated)

    def _open_case(
        self,
        case_id: str,
        arguments: Mapping[str, object],
        *,
        require_existing: bool = False,
        create_only: bool = False,
    ) -> dict[str, object]:
        if "include_closeout_bundle" in arguments:
            _strict_bool(
                arguments,
                "include_closeout_bundle",
                default=True,
            )
        existing = self._load(case_id)
        if existing is not None:
            if create_only:
                raise RevisionConflict(f"case {case_id} already exists")
            if arguments.get(CONTEXT_WORKFLOW_STEP_ARGUMENT) is True:
                return existing
            supplied = {
                key: value
                for key, value in arguments.items()
                if key not in _CONTEXT_CONTROL_ARGUMENTS and not key.startswith("_")
            }
            previous_inputs = existing.get("workflow_inputs", {})
            previous_input_map = (
                dict(previous_inputs) if isinstance(previous_inputs, Mapping) else {}
            )
            workflow_inputs = dict(previous_input_map)
            replaces_target = "targets" in supplied or (
                isinstance(supplied.get("ip"), str)
                and bool(str(supplied.get("ip", "")).strip())
            )
            if replaces_target:
                for name in _TARGET_REPLACEMENT_RESET_ARGUMENTS:
                    workflow_inputs.pop(name, None)
            workflow_inputs.update(_sanitize_runtime_inputs(supplied))
            payload: dict[str, object] = {}
            for name in (
                "intent",
                "final_purpose",
                "change_boundary",
                "delivery_strategy",
            ):
                if name in supplied and str(supplied[name]) != str(
                    existing.get(name, "")
                ):
                    payload[name] = str(supplied[name])
            updated_targets = self._targets(arguments) if replaces_target else []
            if replaces_target and updated_targets != existing.get("targets", []):
                payload["targets"] = updated_targets
            if workflow_inputs != previous_input_map:
                payload["workflow_inputs"] = workflow_inputs
            changed_input_keys = {
                name
                for name in set(previous_input_map) | set(workflow_inputs)
                if previous_input_map.get(name) != workflow_inputs.get(name)
            }
            binding_changed = bool(
                replaces_target and updated_targets != existing.get("targets", [])
            )
            if not binding_changed:
                for name in _TARGET_VERSION_ARGUMENTS:
                    if workflow_inputs.get(name) != previous_input_map.get(name):
                        binding_changed = True
                        break
            if binding_changed:
                payload["target_changed"] = True
                payload["target_version"] = int(existing.get("target_version", 1)) + 1
            intent_changed = "intent" in payload
            delivery_changed = "delivery_strategy" in payload
            if intent_changed:
                revised_arguments = {
                    **workflow_inputs,
                    "intent": payload.get("intent", existing.get("intent", "")),
                    "delivery_strategy": payload.get(
                        "delivery_strategy",
                        existing.get("delivery_strategy", ""),
                    ),
                    "final_purpose": payload.get(
                        "final_purpose",
                        existing.get("final_purpose", ""),
                    ),
                }
                payload["acceptance_plan"] = AcceptancePlan.freeze(
                    revised_arguments,
                    frozen_at=self.clock(),
                ).to_public_dict()
                payload["workflow_definition"] = (
                    self.workflow_definitions.registry.resolve(
                        intent=str(revised_arguments["intent"]),
                        entry_domain=str(
                            payload.get(
                                "entry_domain",
                                existing.get("entry_domain", ""),
                            )
                        ),
                        entry_operation=str(
                            existing.get("entry_operation", "")
                        ),
                        delivery_strategy=str(
                            revised_arguments.get("delivery_strategy", "")
                        ),
                    ).to_public_dict()
                )
                payload[_TASK_POLICY_FIELD] = (
                    TaskAuthorizationPolicy.from_task_intent(
                        str(revised_arguments["intent"]),
                        delivery_strategy=str(
                            revised_arguments.get("delivery_strategy", "")
                        ),
                        authorized_exceptions=workflow_inputs.get(
                            "authorized_exceptions"
                        ),
                        allow_insecure_tls=_strict_bool(
                            workflow_inputs,
                            "allow_insecure_tls",
                            default=True,
                        ),
                    ).to_public_dict()
                )
            workflow_input_changed = any(
                name in previous_input_map
                and name
                not in (
                    _TARGET_REPLACEMENT_RESET_ARGUMENTS
                    | _TARGET_VERSION_ARGUMENTS
                )
                for name in changed_input_keys
            )
            workflow_cycle_required = intent_changed or workflow_input_changed
            if payload and (intent_changed or binding_changed or workflow_cycle_required):
                events: list[PendingCaseEvent] = [
                    PendingCaseEvent("CaseUpdated", payload)
                ]
                if workflow_cycle_required:
                    next_cycle_number = int(
                        existing.get("workflow_cycle_number", 1)
                    ) + 1
                    events.append(
                        PendingCaseEvent(
                            "WorkflowCycleStarted",
                            {
                                "workflow_cycle_number": next_cycle_number,
                                "workflow_cycle_id": f"cycle-{next_cycle_number}",
                                "reason": (
                                    "workflow definition changed"
                                    if intent_changed or delivery_changed
                                    else "workflow inputs changed"
                                ),
                                "changed_input_keys": sorted(changed_input_keys),
                            },
                        )
                    )
                updated = self.repository.commit(
                    case_id,
                    expected_revision=int(existing["revision"]),
                    events=events,
                )
                cached = self._cache(updated)
                cached["_update_base_revision"] = int(existing["revision"])
                return cached
            if "delivery_strategy" in arguments:
                expected = arguments.get("expected_revision")
                if expected is not None:
                    if isinstance(expected, bool) or not isinstance(expected, int):
                        raise TypeError("expected_revision must be an integer")
                    if expected != existing["revision"]:
                        raise RevisionConflict(
                            f"case {case_id} revision is {existing['revision']}, "
                            f"expected {expected}"
                        )
                selected = self._select_delivery_strategy(
                    existing,
                    arguments.get("delivery_strategy"),
                    reason="explicit-task-selection",
                    selection_arguments=arguments,
                )
                if selected.get("revision") != existing.get("revision"):
                    selected["_selection_base_revision"] = int(existing["revision"])
                return selected
            if payload:
                updated = self.repository.commit(
                    case_id,
                    expected_revision=int(existing["revision"]),
                    events=(PendingCaseEvent("CaseUpdated", payload),),
                )
                return self._cache(updated)
            return existing
        if require_existing:
            raise CaseNotFound(case_id)
        opened_arguments = dict(arguments)
        if not str(opened_arguments.get("delivery_strategy", "")).strip():
            inferred_delivery = _inferred_delivery_strategy(
                opened_arguments.get("intent"),
                opened_arguments,
            )
            if inferred_delivery:
                opened_arguments["delivery_strategy"] = inferred_delivery
        entry_domain = opened_arguments.get("entry_domain")
        if entry_domain is not None and not isinstance(entry_domain, str):
            raise TypeError("entry_domain must be a string")
        if not isinstance(entry_domain, str) or not entry_domain.strip():
            inferred_entry_domain = _inferred_entry_domain(
                opened_arguments.get("intent")
            )
            if inferred_entry_domain:
                opened_arguments["entry_domain"] = inferred_entry_domain
        allow_insecure_tls = opened_arguments.get("allow_insecure_tls", True)
        if not isinstance(allow_insecure_tls, bool):
            raise TypeError("allow_insecure_tls must be a boolean")
        opened_arguments["allow_insecure_tls"] = allow_insecure_tls
        task_policy = TaskAuthorizationPolicy.from_task_intent(
            str(opened_arguments.get("intent", "diagnosis-only")),
            delivery_strategy=str(
                opened_arguments.get("delivery_strategy", "")
            ),
            authorized_exceptions=opened_arguments.get("authorized_exceptions"),
            allow_insecure_tls=allow_insecure_tls,
        )
        workflow_definition = self.workflow_definitions.registry.resolve(
            intent=str(opened_arguments.get("intent", "diagnosis-only")),
            entry_domain=str(opened_arguments.get("entry_domain", "")),
            entry_operation=str(
                opened_arguments.get("_context_entry_operation", "")
            ),
            delivery_strategy=str(
                opened_arguments.get("delivery_strategy", "")
            ),
        )
        workflow_definition = self.workflow_definitions.bind_target_scope(
            workflow_definition, self._targets(opened_arguments)
        )
        # Resolve the entry domain before the first Effect fingerprint is made.
        # Inferring it only after OperationAccepted changes resume identity.
        selected_entry_domain = workflow_definition.entry_domain or next(
            (_OPERATION_ENTRY_DOMAINS.get(step.name, "") for step in workflow_definition.steps if step.kind == "operation"),
            "",
        )
        if selected_entry_domain:
            opened_arguments["entry_domain"] = selected_entry_domain
        event = PendingCaseEvent(
            "CaseOpened",
            {
                "intent": str(opened_arguments.get("intent", "diagnosis-only")),
                "entry_domain": str(opened_arguments.get("entry_domain", "")),
                "entry_operation": str(
                    opened_arguments.get("_context_entry_operation", "")
                ),
                "final_purpose": str(
                    opened_arguments.get(
                        "final_purpose",
                        opened_arguments.get("problem", ""),
                    )
                ),
                "change_boundary": str(
                    opened_arguments.get("change_boundary", "")
                ),
                "delivery_strategy": str(
                    opened_arguments.get("delivery_strategy", "")
                ),
                _TASK_POLICY_FIELD: task_policy.to_public_dict(),
                "acceptance_plan": AcceptancePlan.freeze(
                    opened_arguments,
                    frozen_at=self.clock(),
                ).to_public_dict(),
                "targets": self._targets(opened_arguments),
                "target_version": 1,
                "workflow_cycle_id": "cycle-1",
                "workflow_cycle_number": 1,
                "workflow_definition": workflow_definition.to_public_dict(),
                "workflow_inputs": _sanitize_runtime_inputs(
                    {
                        key: value
                        for key, value in opened_arguments.items()
                        if key
                        not in {
                            "case_id",
                            "expected_revision",
                            "idempotency_key",
                            "deadline",
                        }
                        and not str(key).startswith("_")
                    }
                ),
                "start_command_id": str(
                    opened_arguments.get("_start_command_id", "")
                ),
                "start_input_digest": str(
                    opened_arguments.get("_start_input_digest", "")
                ),
                "start_input": _sanitize_runtime_inputs(
                    opened_arguments.get("_start_input", {})
                ),
            },
            str(opened_arguments.get("_start_command_id", "")),
        )
        return self._cache(
            self.repository.commit(case_id, expected_revision=0, events=(event,))
        )

    def _put_evidence(
        self,
        value: Mapping[str, object],
        *,
        case_id: str,
        operation_id: str,
        descriptor: OperationDescriptor,
        arguments: Mapping[str, object],
    ) -> EvidenceRef:
        body = _json_bytes(_sanitize(value))
        blob_id = self.blob_repository.put(body)
        self._metrics["evidence_bytes_written"] += len(body)
        targets = self._targets(arguments)
        target_id = str(arguments.get("target_id", ""))
        if not target_id and len(targets) == 1:
            target_id = str(targets[0].get("target_id", "target-1"))
        generation = str(
            value.get(
                "target_epoch",
                value.get("generation", arguments.get("target_epoch", "unknown")),
            )
        )
        provenance = f"{descriptor.name}:{operation_id}"
        projection = self._load(case_id) or {}
        definition = projection.get("workflow_definition", {})
        definition = definition if isinstance(definition, Mapping) else {}
        operation = next(
            (
                item
                for item in reversed(list(projection.get("operations", [])))
                if isinstance(item, Mapping)
                and str(item.get("operation_id", "")) == operation_id
            ),
            {},
        )
        operation = operation if isinstance(operation, Mapping) else {}
        raw_parents = value.get(
            "parent_evidence_ids", arguments.get("parent_evidence_ids", [])
        )
        parent_evidence_ids = (
            tuple(
                dict.fromkeys(
                    str(item)
                    for item in raw_parents
                    if isinstance(item, str) and item
                )
            )
            if isinstance(raw_parents, list)
            else ()
        )
        target_epoch_value = value.get(
            "target_epoch", value.get("epoch_after", value.get("generation"))
        )
        target_epoch = (
            int(target_epoch_value)
            if isinstance(target_epoch_value, int)
            and not isinstance(target_epoch_value, bool)
            and target_epoch_value >= 0
            else None
        )
        evidence_id = _fingerprint(
            {
                "blob_id": blob_id,
                "case_id": case_id,
                "target_id": target_id,
                "generation": generation,
                "provenance": provenance,
            }
        )
        return EvidenceRef(
            evidence_id=evidence_id,
            blob_id=blob_id,
            media_type="application/json",
            byte_count=len(body),
            target_id=target_id,
            generation=generation,
            provenance=provenance,
            observed_at=self.clock(),
            case_id=case_id,
            producer=str(value.get("producer_identity", descriptor.name)),
            target_epoch=target_epoch,
            workflow_definition_id=str(
                value.get(
                    "workflow_definition_id",
                    operation.get(
                        "workflow_definition_id",
                        definition.get("definition_id", ""),
                    ),
                )
            ),
            workflow_definition_version=int(
                value.get(
                    "workflow_definition_version",
                    operation.get(
                        "workflow_definition_version", definition.get("version", 0)
                    ),
                )
            ),
            workflow_definition_fingerprint=str(
                value.get(
                    "workflow_definition_fingerprint",
                    operation.get(
                        "workflow_definition_fingerprint",
                        definition.get("fingerprint", ""),
                    ),
                )
            ),
            workflow_cycle_id=str(
                value.get(
                    "workflow_cycle_id",
                    operation.get(
                        "workflow_cycle_id",
                        projection.get("workflow_cycle_id", ""),
                    ),
                )
            ),
            workflow_step_id=str(
                value.get(
                    "workflow_step_id", operation.get("workflow_step_id", "")
                )
            ),
            workflow_attempt=int(
                value.get(
                    "workflow_attempt",
                    value.get(
                        "phase_attempt", operation.get("workflow_attempt", 0)
                    ),
                )
            ),
            parent_evidence_ids=parent_evidence_ids,
        )

    def _envelope(
        self,
        *,
        case_id: str,
        revision: int,
        operation_id: str,
        operation: str,
        status: str,
        value: Mapping[str, object],
        evidence_refs: Iterable[Mapping[str, object]] = (),
        gaps: Iterable[str] = (),
        canonical_error: Mapping[str, object] | None = None,
        continuation: Mapping[str, object] | None = None,
        capsule: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        next_actions = _sanitize(_next_actions(value))
        envelope = {
            "schema": AGENT_ENVELOPE_SCHEMA,
            "case_id": case_id,
            "revision": revision,
            "operation": {
                "operation_id": operation_id,
                "name": operation,
                "status": status,
            },
            "status": status,
            "summary": redact_text(_summary_for(operation, value)),
            "facts": _sanitize(_facts_for(value)),
            "evidence_refs": [dict(item) for item in evidence_refs],
            "gaps": _sanitize(list(gaps)),
            "next_actions": next_actions,
            "canonical_error": (
                _sanitize(dict(canonical_error))
                if canonical_error is not None
                else None
            ),
        }
        if canonical_error is not None:
            envelope["code"] = str(
                canonical_error.get("code", "internal_error")
            )
        if isinstance(next_actions, list) and next_actions:
            envelope["next_action"] = str(next_actions[0])
        if continuation is not None:
            envelope["continuation"] = dict(continuation)
        if capsule is not None:
            envelope["capsule"] = dict(capsule)
        comparison = value.get("comparison")
        diff_card = (
            comparison.get("diff_card")
            if isinstance(comparison, Mapping)
            else value.get("diff_card")
        )
        if isinstance(diff_card, Mapping):
            envelope["diff_card"] = dict(diff_card)
        closeout = value.get("closeout")
        if isinstance(closeout, Mapping):
            envelope["closeout_summary"] = {
                name: closeout.get(name)
                for name in (
                    "closure_status",
                    "claim_level",
                    "business_acceptance",
                    "identity_status",
                    "freshness_status",
                    "source_delivery",
                    "summary",
                    "fingerprint",
                )
                if name in closeout
            }
            bundle = value.get("closeout_bundle")
            if isinstance(bundle, Mapping):
                envelope["document_refs"] = list(bundle.get("documents", []))
        bounded = bounded_envelope(envelope, max_bytes=self.envelope_max_bytes)
        encoded_bytes = len(_json_bytes(bounded))
        self._metrics["envelope_bytes"] += encoded_bytes
        self._metrics["peak_envelope_bytes"] = max(
            self._metrics["peak_envelope_bytes"], encoded_bytes
        )
        return bounded

    def _result_from_receipt(
        self,
        receipt: Mapping[str, object],
        *,
        mutation: bool = False,
        refresh_from_case: bool = True,
    ) -> ContextToolResult:
        envelope = receipt.get("envelope")
        reference = receipt.get("legacy_result_ref")
        inline = receipt.get("legacy_value")
        if not isinstance(envelope, Mapping):
            raise EvidenceUnavailable("idempotency receipt is incomplete")
        if isinstance(reference, Mapping):
            raw = self.blob_repository.read(
                str(reference["blob_id"]), offset=0, limit=-1
            )
            value = json.loads(raw.decode("utf-8"))
        elif isinstance(inline, Mapping):
            value = dict(inline)
        else:
            raise EvidenceUnavailable("idempotency receipt has no readable result")
        if not isinstance(value, Mapping):
            raise EvidenceUnavailable("legacy result evidence is not an object")
        self._metrics["idempotent_replays"] += 1
        self._metrics["warm_continuations"] += 1
        public = dict(value)
        case_id = str(envelope.get("case_id", ""))
        projection = self._load(case_id) if case_id else None
        if isinstance(projection, Mapping) and projection.get("status") == "terminal":
            try:
                projection = self._recover_terminal_closeout(projection)
            except Exception:
                # Replaying the domain result remains safe even if optional
                # Closeout repair cannot be persisted at this moment.
                pass
        if isinstance(projection, Mapping) and projection.get("closeout"):
            public["closeout"] = dict(projection["closeout"])
            public["closeout_markdown"] = str(
                projection.get("closeout_markdown", "")
            )
            bundle = projection.get("closeout_bundle")
            if isinstance(bundle, Mapping):
                public["closeout_bundle"] = dict(bundle)
        if mutation:
            public["idempotent_replay"] = True
        if refresh_from_case and isinstance(projection, Mapping):
            operation = envelope.get("operation", {})
            operation = operation if isinstance(operation, Mapping) else {}
            refreshed = self._envelope(
                case_id=str(projection.get("case_id", case_id)),
                revision=int(projection.get("revision", envelope.get("revision", 0))),
                operation_id=str(operation.get("operation_id", "")),
                operation=str(operation.get("name", "operation")),
                status=str(operation.get("status", envelope.get("status", "completed"))),
                value=public,
                evidence_refs=(
                    item
                    for item in envelope.get("evidence_refs", [])
                    if isinstance(item, Mapping)
                ),
                gaps=(
                    str(item)
                    for item in envelope.get("gaps", [])
                    if str(item)
                ),
                canonical_error=(
                    envelope.get("canonical_error")
                    if isinstance(envelope.get("canonical_error"), Mapping)
                    else None
                ),
            )
            envelope = refreshed
        return ContextToolResult(public, envelope)

    def _recover_pending_idempotency(
        self,
        *,
        case_id: str,
        key: str,
        fingerprint: str,
        descriptor: OperationDescriptor,
    ) -> Mapping[str, object] | None:
        """Repair a pending receipt after its terminal Case facts were committed."""

        projection = self.repository.load(case_id)
        if projection is None:
            return None
        operation = next(
            (
                item
                for item in reversed(projection.get("operations", []))
                if isinstance(item, Mapping)
                and item.get("operation") == descriptor.name
                and item.get("idempotency_key") == key
                and item.get("request_fingerprint") == fingerprint
                and (
                    "terminal_revision" in item
                    or "reconciled_revision" in item
                )
            ),
            None,
        )
        if not isinstance(operation, Mapping):
            return None
        references = {
            str(item.get("evidence_id", "")): item
            for item in projection.get("evidence_refs", [])
            if isinstance(item, Mapping) and item.get("evidence_id")
        }
        reference: Mapping[str, object] | None = None
        value: Mapping[str, object] | None = None
        evidence_ids = operation.get("evidence_ids", [])
        latest_evidence_id = (
            evidence_ids[-1]
            if isinstance(evidence_ids, list)
            and evidence_ids
            and isinstance(evidence_ids[-1], str)
            else ""
        )
        candidate = references.get(latest_evidence_id)
        if isinstance(candidate, Mapping):
            try:
                raw = self.blob_repository.read(
                    str(candidate.get("blob_id", "")),
                    offset=0,
                    limit=-1,
                )
                loaded = json.loads(raw.decode("utf-8"))
            except Exception:
                loaded = None
            if isinstance(loaded, Mapping):
                reference = candidate
                value = loaded
        if value is None or reference is None:
            return None
        if projection.get("status") == "terminal":
            projection = self._recover_terminal_closeout(projection)
        public = dict(value)
        if projection.get("closeout"):
            public["closeout"] = dict(projection["closeout"])
            public["closeout_markdown"] = str(
                projection.get("closeout_markdown", "")
            )
            bundle = projection.get("closeout_bundle")
            if isinstance(bundle, Mapping):
                public["closeout_bundle"] = dict(bundle)
        status = str(operation.get("status", "completed"))
        envelope = self._envelope(
            case_id=case_id,
            revision=int(projection["revision"]),
            operation_id=str(operation.get("operation_id", "")),
            operation=descriptor.name,
            status=status,
            value=public,
            evidence_refs=(reference,),
        )
        receipt = {
            "envelope": envelope,
            "legacy_result_ref": dict(reference),
        }
        self.repository.complete_idempotency(case_id, key, receipt)
        self._metrics["idempotency_receipt_repairs"] += 1
        return receipt

    def _claim_idempotency(
        self,
        *,
        case_id: str,
        key: str,
        fingerprint: str,
        descriptor: OperationDescriptor,
    ) -> Mapping[str, object] | None:
        try:
            return self.repository.claim_idempotency(case_id, key, fingerprint)
        except OperationAlreadyInProgress:
            recovered = self._recover_pending_idempotency(
                case_id=case_id,
                key=key,
                fingerprint=fingerprint,
                descriptor=descriptor,
            )
            if recovered is not None:
                return recovered
            raise

    @staticmethod
    def _domain_operation_status(
        descriptor: OperationDescriptor,
        value: Mapping[str, object],
    ) -> str:
        if descriptor.mutation:
            journal = value.get("journal")
            if isinstance(journal, Mapping):
                classified = mutation_journal_operation_status(
                    journal,
                    action=str(value.get("action", "")),
                )
                if classified:
                    return classified
        raw_status = str(value.get("status", "")).strip().lower()
        if raw_status in {"failed", "cancelled", "blocked"}:
            return raw_status
        if value.get("ok") is False:
            return "failed"
        return "completed"

    @staticmethod
    def _mutation_exception_status(exc: BaseException) -> str:
        recovery_status = getattr(exc, "recovery_status", None)
        if isinstance(recovery_status, Mapping):
            classified = mutation_journal_operation_status(recovery_status)
            if classified:
                return classified
        outcome = str(getattr(exc, "mutation_outcome", "")).strip().lower()
        stage = str(getattr(exc, "mutation_journal_stage", "")).strip().lower()
        effects_started = bool(
            getattr(exc, "mutation_effects_started", False)
        )
        if stage:
            classified = mutation_journal_operation_status(
                {
                    "stage": stage,
                    "effects_started": effects_started,
                }
            )
            if classified:
                return classified
        if outcome == "unknown":
            return "mutation_outcome_unknown"
        if outcome == "applied":
            return "blocked"
        if outcome in {"not_started", "rejected"}:
            return "failed"
        if isinstance(
            exc,
            (
                MutationAuthorizationDenied,
                MutationOperationConflict,
                UnfinishedMutationExists,
                TypeError,
                ValueError,
            ),
        ):
            return "failed"
        return "mutation_outcome_unknown"

    def _derive_closeout(
        self,
        projection: Mapping[str, object],
        *,
        terminal_status: str,
        include_bundle: bool,
    ) -> tuple[dict[str, object], str, dict[str, object] | None]:
        def read_closeout_evidence(
            reference: Mapping[str, object],
        ) -> Mapping[str, object] | None:
            resolved = reference
            if not str(reference.get("blob_id", "")):
                evidence_id = str(reference.get("evidence_id", ""))
                indexed = self.repository.evidence_reference(
                    str(projection.get("case_id", "")), evidence_id
                )
                if not isinstance(indexed, Mapping):
                    return None
                resolved = indexed
            raw = self.blob_repository.read(
                str(resolved.get("blob_id", "")),
                offset=0,
                limit=-1,
            )
            loaded = json.loads(raw.decode("utf-8"))
            return loaded if isinstance(loaded, Mapping) else None

        closeout = aggregate_case_closeout(
            projection,
            read_closeout_evidence,
            terminal_status=terminal_status,
            operation_stages=self.operation_stages,
        )
        payload = closeout.to_public_dict()
        markdown = render_markdown(closeout)
        bundle = build_closeout_bundle(closeout, markdown) if include_bundle else None
        return payload, markdown, bundle

    @staticmethod
    def _closeout_bundle_enabled(
        projection: Mapping[str, object],
        arguments: Mapping[str, object] | None = None,
    ) -> bool:
        if arguments is not None and "include_closeout_bundle" in arguments:
            return _strict_bool(
                arguments,
                "include_closeout_bundle",
                default=True,
            )
        workflow_inputs = projection.get("workflow_inputs", {})
        if (
            isinstance(workflow_inputs, Mapping)
            and "include_closeout_bundle" in workflow_inputs
        ):
            return _strict_bool(
                workflow_inputs,
                "include_closeout_bundle",
                default=True,
            )
        return True

    def _record_closeout(
        self,
        projection: Mapping[str, object],
        *,
        terminal_status: str,
        include_bundle: bool,
        operation_id: str,
    ) -> tuple[
        dict[str, object],
        dict[str, object],
        str,
        dict[str, object] | None,
    ]:
        closeout_payload, closeout_markdown, closeout_bundle = self._derive_closeout(
            projection,
            terminal_status=terminal_status,
            include_bundle=include_bundle,
        )
        existing_closeout = projection.get("closeout")
        existing_bundle = projection.get("closeout_bundle")
        if (
            isinstance(existing_closeout, Mapping)
            and existing_closeout.get("fingerprint")
            == closeout_payload.get("fingerprint")
            and (
                not include_bundle
                or isinstance(existing_bundle, Mapping)
            )
        ):
            return (
                dict(projection),
                dict(existing_closeout),
                str(projection.get("closeout_markdown", closeout_markdown)),
                dict(existing_bundle) if isinstance(existing_bundle, Mapping) else None,
            )
        try:
            updated = self.repository.commit(
                str(projection["case_id"]),
                expected_revision=int(projection["revision"]),
                events=(
                    PendingCaseEvent(
                        "CloseoutRecorded",
                        {
                            "closeout": closeout_payload,
                            "closeout_markdown": closeout_markdown,
                            "closeout_bundle": closeout_bundle,
                        },
                        operation_id,
                    ),
                ),
            )
        except RevisionConflict:
            current = self.repository.load(str(projection["case_id"]))
            current_closeout = (
                current.get("closeout") if isinstance(current, Mapping) else None
            )
            if (
                isinstance(current, Mapping)
                and isinstance(current_closeout, Mapping)
                and current_closeout.get("fingerprint")
                == closeout_payload.get("fingerprint")
            ):
                updated = dict(current)
                closeout_payload = dict(current_closeout)
                closeout_markdown = str(
                    current.get("closeout_markdown", closeout_markdown)
                )
                current_bundle = current.get("closeout_bundle")
                closeout_bundle = (
                    dict(current_bundle)
                    if isinstance(current_bundle, Mapping)
                    else None
                )
            else:
                raise
        return (
            self._cache(updated),
            closeout_payload,
            closeout_markdown,
            closeout_bundle,
        )

    def _recover_terminal_closeout(
        self,
        projection: Mapping[str, object],
    ) -> dict[str, object]:
        if str(projection.get("status", "")) != "terminal":
            return dict(projection)
        raw_outcome = projection.get("run_outcome")
        existing_closeout = projection.get("closeout")
        if (
            isinstance(raw_outcome, Mapping)
            and isinstance(existing_closeout, Mapping)
            and existing_closeout
            and str(raw_outcome.get("closeout_fingerprint", ""))
            == str(existing_closeout.get("fingerprint", ""))
        ):
            return dict(projection)
        outcome_status = (
            str(raw_outcome.get("status", ""))
            if isinstance(raw_outcome, Mapping)
            else ""
        )
        updated, _payload, _markdown, _bundle = self._record_closeout(
            projection,
            terminal_status=(
                outcome_status
                if outcome_status == "cancelled"
                else case_terminal_status(projection)
            ),
            include_bundle=self._closeout_bundle_enabled(projection),
            operation_id="case-closeout-recovery",
        )
        return updated

    def _bounded_legacy_value(self, value: Mapping[str, object]) -> dict[str, object]:
        sanitized = _sanitize(value)
        if isinstance(sanitized, Mapping) and len(_json_bytes(sanitized)) <= self.envelope_max_bytes:
            return dict(sanitized)
        return {
            "ok": value.get("ok"),
            "summary": _summary_for("operation", value),
            "result_compacted": True,
            "next_action": (_next_actions(value) or [""])[0],
        }

    @classmethod
    def _case_status_after_domain(
        cls,
        projection: Mapping[str, object],
        descriptor: OperationDescriptor,
        value: Mapping[str, object],
        *,
        operation_id: str = "",
        reconciled: bool = False,
        target_id: str = "",
    ) -> str:
        metadata = cls._compatible_workflow_operation(
            projection,
            descriptor.name,
            execution_target_id=target_id,
        )
        step_id = str(metadata.get("workflow_step_id", ""))
        if not step_id:
            return "open"
        simulated = json.loads(json.dumps(projection))
        states = simulated.get("workflow_step_states", {})
        states = dict(states) if isinstance(states, Mapping) else {}
        states[step_id] = {
            "kind": str(metadata.get("workflow_step_kind", "operation")),
            "name": descriptor.name,
            "status": "completed",
            "workflow_cycle_id": str(
                metadata.get(
                    "workflow_cycle_id",
                    projection.get("workflow_cycle_id", "cycle-1"),
                )
            ),
            "target_version": int(
                metadata.get("target_version", projection.get("target_version", 1))
            ),
            "target_id": target_id,
            "operation_id": operation_id,
        }
        epoch = cls._observed_target_epoch(value, target_id=target_id)
        if epoch is not None:
            states[step_id]["target_epoch"] = epoch
        simulated["workflow_step_states"] = states
        return (
            "terminal"
            if cls._continuation_for(simulated)["workflow_complete"]
            else "open"
        )

    def invoke_domain(
        self,
        descriptor: OperationDescriptor,
        arguments: Mapping[str, object],
        *,
        task_id: str,
        operation_id: str,
        executor: Callable[[], Mapping[str, object]],
    ) -> ContextToolResult:
        self._metrics["invocations"] += 1
        case_arguments = dict(arguments)
        case_arguments.setdefault("_context_entry_operation", descriptor.name)
        case_id = self._case_id(task_id, case_arguments)
        existing = self._load(case_id)
        if (
            descriptor.mutation
            and existing is None
            and not self._targets(case_arguments)
        ):
            raise ValueError(
                "the first mutation domain call must provide ip or targets"
            )
        infer_domain_defaults = existing is None or descriptor.mutation
        if (
            infer_domain_defaults
            and not str(case_arguments.get("intent", "")).strip()
        ):
            inferred_intent = {
                "debug_run": "diagnosis-only",
                "debug_collect": "diagnosis-only",
                "live_patch_run": (
                    "rollback"
                    if str(case_arguments.get("action", "")).strip().lower()
                    == "rollback"
                    else "live-patch"
                ),
                "upgrade_run": "upgrade-and-verify",
                "upgrade_batch": "upgrade-and-verify",
                "log_bundle_collect": "bundle-and-diagnose",
            }.get(descriptor.name, "diagnosis-only")
            case_arguments["intent"] = inferred_intent
        if (
            infer_domain_defaults
            and
            not str(case_arguments.get("delivery_strategy", "")).strip()
            and case_arguments.get(CONTEXT_WORKFLOW_STEP_ARGUMENT) is not True
        ):
            inferred_delivery = _inferred_delivery_strategy(
                case_arguments.get("intent"),
                case_arguments,
                operation=descriptor.name,
            )
            if inferred_delivery:
                case_arguments["delivery_strategy"] = inferred_delivery
        if existing is None and not str(
            case_arguments.get("entry_domain", "")
        ).strip():
            entry_domain = _OPERATION_ENTRY_DOMAINS.get(descriptor.name, "")
            if entry_domain:
                case_arguments["entry_domain"] = entry_domain
        idempotency_key = _safe_identifier(
            arguments.get("idempotency_key", operation_id),
            fallback=operation_id,
        )
        resumed_fingerprint = arguments.get("_workflow_request_fingerprint")
        if resumed_fingerprint is not None and (
            not isinstance(resumed_fingerprint, str)
            or len(resumed_fingerprint) != 64
            or any(
                character not in "0123456789abcdef"
                for character in resumed_fingerprint
            )
        ):
            raise ValueError("invalid resumed workflow request fingerprint")
        request_fingerprint = resumed_fingerprint or _fingerprint(
            {
                "operation": descriptor.name,
                "arguments": _sanitize(
                    {
                        key: value
                        for key, value in arguments.items()
                        if key
                        not in {
                            "case_id",
                            "expected_revision",
                            "idempotency_key",
                        }
                    }
                ),
            }
        )
        try:
            replay = self._claim_idempotency(
                case_id=case_id,
                key=idempotency_key,
                fingerprint=request_fingerprint,
                descriptor=descriptor,
            )
        except IdempotencyConflict:
            if descriptor.mutation:
                # MutationJournal owns mutation identity conflicts. Invoke the
                # domain only far enough for its durable journal to reject the
                # conflicting operation before any new remote effect.
                executor()
            raise
        if replay is not None:
            return self._result_from_receipt(replay, mutation=descriptor.mutation)
        try:
            self._validate_expected_before_case_update(
                case_id, case_arguments
            )
            projection = self._open_case(case_id, case_arguments)
            if projection.get("closed"):
                raise CaseClosed(f"case {case_id} is closed")
            expected = arguments.get("expected_revision")
            if expected is not None:
                if isinstance(expected, bool) or not isinstance(expected, int):
                    raise TypeError("expected_revision must be an integer")
                if expected not in {
                    int(projection["revision"]),
                    int(projection.get("_selection_base_revision", -1)),
                    int(projection.get("_update_base_revision", -1)),
                }:
                    raise RevisionConflict(
                        f"case {case_id} revision is {projection['revision']}, "
                        f"expected {expected}"
                    )
        except Exception:
            self.repository.abandon_idempotency(case_id, idempotency_key)
            raise
        execution_target_id = (
            "" if descriptor.name == "upgrade_batch" else
            self._preferred_target_id(projection, arguments)
            if descriptor.mutation or descriptor.name == "debug_collect"
            else self._selected_target_id(projection, arguments)
        )
        reconciling = any(
            isinstance(item, Mapping)
            and item.get("operation_id") == operation_id
            and item.get("status")
            in {"accepted", "running", "mutation_outcome_unknown"}
            for item in projection.get("operations", [])
        )
        revision = int(projection["revision"])
        if not reconciling:
            workflow_metadata = {
                "workflow_cycle_id": str(arguments.get("_workflow_cycle_id", "")),
                "workflow_step_id": str(arguments.get("_workflow_step_id", "")),
                "workflow_step_kind": str(arguments.get("_workflow_step_kind", "")),
                "target_version": int(
                    arguments.get(
                        "_workflow_target_version",
                        projection.get("target_version", 1),
                    )
                ),
                "target_id": execution_target_id,
                "workflow_definition_id": str(
                    arguments.get("_workflow_definition_id", "")
                ),
                "workflow_definition_version": int(
                    arguments.get("_workflow_definition_version", 0)
                ),
                "workflow_definition_fingerprint": str(
                    arguments.get("_workflow_definition_fingerprint", "")
                ),
                "workflow_execution_id": str(
                    arguments.get("_workflow_execution_id", "")
                ),
                "workflow_attempt": int(
                    arguments.get("_workflow_attempt", 0)
                ),
                "workflow_input_fingerprint": str(
                    arguments.get("_workflow_input_fingerprint", "")
                ),
                "workflow_target_epoch": int(
                    arguments.get("_workflow_target_epoch", 0)
                ),
            }
            if not workflow_metadata["workflow_step_id"]:
                workflow_metadata.update(
                    self._compatible_workflow_operation(
                        projection,
                        descriptor.name,
                        execution_target_id=execution_target_id,
                    )
                )
            workflow_step_id = str(workflow_metadata["workflow_step_id"])
            if workflow_step_id and not workflow_metadata["workflow_execution_id"]:
                definition = DEFAULT_WORKFLOW_DEFINITIONS.definition_for(projection)
                step_definition = next(
                    (
                        step
                        for step in definition.steps
                        if step.step_id == workflow_step_id
                    ),
                    None,
                )
                if step_definition is not None:
                    attempt = self._workflow_attempt(
                        projection,
                        kind=str(
                            workflow_metadata.get(
                                "workflow_step_kind", step_definition.kind
                            )
                        ),
                        step_id=workflow_step_id,
                    ) + 1
                    target_epoch = self._target_epoch_floor(
                        projection,
                        target_id=execution_target_id,
                    )
                    workflow_input_fingerprint = (
                        self._workflow_operation_input_fingerprint(
                            projection,
                            descriptor.name,
                            target_id=execution_target_id,
                        )
                    )
                    identity = DEFAULT_WORKFLOW_DEFINITIONS.step_identity(
                        projection,
                        step=step_definition,
                        attempt=attempt,
                        input_fingerprint=workflow_input_fingerprint,
                        target_epoch=target_epoch,
                    )
                    workflow_metadata.update(
                        {
                            "workflow_definition_id": identity.workflow_definition_id,
                            "workflow_definition_version": identity.workflow_version,
                            "workflow_definition_fingerprint": identity.workflow_fingerprint,
                            "workflow_execution_id": identity.execution_id,
                            "workflow_attempt": identity.attempt,
                            "workflow_input_fingerprint": identity.input_fingerprint,
                            "workflow_target_epoch": identity.target_epoch,
                        }
                    )
            try:
                projection = self.repository.commit(
                    case_id,
                    expected_revision=revision,
                    events=(
                        PendingCaseEvent(
                            "OperationAccepted",
                            {
                                "operation": descriptor.name,
                                "idempotency_key": idempotency_key,
                                "request_fingerprint": request_fingerprint,
                                "inputs": _operation_identity_inputs(arguments),
                                **workflow_metadata,
                            },
                            operation_id,
                        ),
                        PendingCaseEvent("OperationStarted", {}, operation_id),
                    ),
                )
                self._cache(projection)
            except Exception:
                self.repository.abandon_idempotency(case_id, idempotency_key)
                raise
        try:
            raw_value = executor()
            if not isinstance(raw_value, Mapping):
                raise TypeError("domain operation must return an object")
            value = dict(raw_value)
            minimum_epoch = arguments.get("_minimum_target_epoch")
            if minimum_epoch is not None:
                observed_epoch = self._require_minimum_target_epoch(
                    value,
                    minimum_epoch=minimum_epoch,
                    target_id=execution_target_id,
                )
                value.setdefault("target_epoch", observed_epoch)
            operation_status = self._domain_result_status(descriptor, value)
        except Exception as exc:
            current = self.repository.load(case_id)
            terminal_projection: Mapping[str, object] | None = None
            error = {
                "code": getattr(exc, "code", type(exc).__name__),
                "message": redact_text(exc),
            }
            if current is not None:
                terminal_status = (
                    self._mutation_exception_status(exc)
                    if descriptor.mutation
                    else "failed"
                )
                next_action = (
                    "reconcile the mutation journal before retrying"
                    if terminal_status == "mutation_outcome_unknown"
                    else (
                        "provide the missing recovery authorization and retry "
                        "the same durable operation"
                        if terminal_status == "blocked"
                        else "resolve the error and retry with the same case"
                    )
                )
                try:
                    event = (
                        PendingCaseEvent(
                            "OperationProgressed",
                            {
                                "status": terminal_status,
                                "next_actions": [next_action],
                            },
                            operation_id,
                        )
                        if reconciling
                        else PendingCaseEvent(
                            "OperationTerminal",
                            {
                                "status": terminal_status,
                                "summary": redact_text(exc),
                                "canonical_error": error,
                                "next_actions": [next_action],
                                "case_status": "open",
                            },
                            operation_id,
                        )
                    )
                    terminal_projection = self.repository.commit(
                        case_id,
                        expected_revision=int(current["revision"]),
                        events=(event,),
                    )
                    self._cache(terminal_projection)
                except Exception:
                    terminal_projection = None
            if descriptor.mutation or terminal_projection is None:
                self.repository.abandon_idempotency(case_id, idempotency_key)
                raise
            value = {
                "ok": False,
                "status": "failed",
                "error": str(exc),
                "canonical_error": error,
            }
            envelope = self._envelope(
                case_id=case_id,
                revision=int(terminal_projection["revision"]),
                operation_id=operation_id,
                operation=descriptor.name,
                status="failed",
                value=value,
                evidence_refs=(),
                canonical_error=error,
                continuation=self._continuation_for(terminal_projection),
                capsule=self._capsule(terminal_projection),
            )
            self.repository.complete_idempotency(
                case_id,
                idempotency_key,
                {
                    "envelope": envelope,
                    "legacy_value": self._bounded_legacy_value(value),
                },
            )
            return ContextToolResult(value, envelope)
        gaps: list[str] = []
        evidence: EvidenceRef | None = None
        try:
            evidence_arguments = dict(arguments)
            if execution_target_id:
                evidence_arguments.setdefault("target_id", execution_target_id)
            evidence = self._put_evidence(
                value,
                case_id=case_id,
                operation_id=operation_id,
                descriptor=descriptor,
                arguments=evidence_arguments,
            )
        except Exception as exc:
            gaps.append(
                redact_text(
                    f"evidence_not_persisted: {type(exc).__name__}: {exc}"
                )
            )
            if descriptor.mutation:
                current = self.repository.load(case_id)
                message = redact_text(
                    f"cannot persist mutation evidence: {exc}"
                )
                if current is not None:
                    event_kind = "OperationReconciled" if reconciling else "OperationTerminal"
                    terminal = self.repository.commit(
                        case_id,
                        expected_revision=int(current["revision"]),
                        events=(
                            PendingCaseEvent(
                                event_kind,
                                {
                                    "status": "mutation_outcome_unknown",
                                    "summary": message,
                                    "canonical_error": {
                                        "code": "mutation_outcome_unknown",
                                        "message": message,
                                    },
                                    "next_actions": [
                                        "reconcile the mutation journal before retrying"
                                    ],
                                    "case_status": "open",
                                },
                                operation_id,
                            ),
                        ),
                    )
                    self._cache(terminal)
                self.repository.abandon_idempotency(case_id, idempotency_key)
                raise MutationOutcomeUnknown(message) from exc
        current = self.repository.load(case_id)
        if current is None:
            self.repository.abandon_idempotency(case_id, idempotency_key)
            raise CaseNotFound(case_id)
        pending: list[PendingCaseEvent] = []
        if evidence is not None:
            pending.append(
                PendingCaseEvent(
                    "EvidenceAttached",
                    {"evidence": evidence.to_public_dict()},
                    operation_id,
                )
            )
        workflow_case_status = (
            self._case_status_after_domain(
                current,
                descriptor,
                value,
                operation_id=operation_id,
                reconciled=reconciling,
                target_id=execution_target_id,
            )
            if operation_status == "completed"
            else "open"
        )
        direct_terminal = (
            arguments.get(CONTEXT_WORKFLOW_STEP_ARGUMENT) is not True
            and operation_status
            in {"completed", "failed", "cancelled", "blocked"}
            and (
                operation_status in {"failed", "cancelled", "blocked"}
                or
                workflow_case_status == "terminal"
                or (
                    arguments.get("_context_defaults_inferred") is not True
                    and
                    bool(str(arguments.get("intent", "")).strip())
                    and bool(
                        str(arguments.get("delivery_strategy", "")).strip()
                    )
                    and _effective_case_intent(current) != "diagnose-and-fix"
                )
                or (
                    bool(str(arguments.get("final_purpose", "")).strip())
                    and _effective_case_intent(current) != "diagnose-and-fix"
                )
            )
        )
        if (
            descriptor.name == "log_bundle_collect"
            and workflow_case_status != "terminal"
        ):
            direct_terminal = False
        case_status = (
            "terminal"
            if direct_terminal
            else workflow_case_status
        )
        pending.append(
            PendingCaseEvent(
                (
                    "OperationProgressed"
                    if operation_status == "running"
                    else "OperationReconciled"
                    if reconciling
                    else "OperationTerminal"
                ),
                {
                    "status": operation_status,
                    "summary": redact_text(
                        _summary_for(descriptor.name, value)
                    ),
                    "next_actions": _next_actions(value),
                    "case_status": (
                        "running" if operation_status == "running" else case_status
                    ),
                    "target_epoch": self._observed_target_epoch(
                        value,
                        target_id=execution_target_id,
                    ),
                    **self._batch_target_epoch_fields(descriptor.name, value),
                    **_diagnostic_receipt_event_fields(
                        descriptor.name,
                        value,
                        arguments,
                        (
                            (evidence.to_public_dict(),)
                            if evidence is not None
                            else ()
                        ),
                        closeout_stage=_operation_closeout_stage(
                            descriptor.name,
                            self.operation_stages,
                        ),
                    ),
                },
                operation_id,
            )
        )
        try:
            projection = self.repository.commit(
                case_id,
                expected_revision=int(current["revision"]),
                events=pending,
            )
        except Exception as exc:
            if descriptor.mutation:
                raise MutationOutcomeUnknown(
                    "mutation returned but its Case terminal receipt could not be committed"
                ) from exc
            raise
        self._cache(projection)
        if case_status == "terminal":
            try:
                closeout_status = (
                    operation_status
                    if operation_status
                    in {"completed", "failed", "cancelled", "blocked"}
                    else "failed"
                )
                (
                    projection,
                    closeout_payload,
                    closeout_markdown,
                    closeout_bundle,
                ) = self._record_closeout(
                    projection,
                    terminal_status=closeout_status,
                    include_bundle=self._closeout_bundle_enabled(
                        projection,
                        arguments,
                    ),
                    operation_id=operation_id,
                )
                value["closeout"] = closeout_payload
                value["closeout_markdown"] = closeout_markdown
                if closeout_bundle is not None:
                    value["closeout_bundle"] = closeout_bundle
            except Exception as exc:
                gaps.append(
                    redact_text(
                        f"closeout_not_persisted: {type(exc).__name__}: {exc}"
                    )
                )
        public_evidence = [evidence.to_public_dict()] if evidence is not None else []
        envelope = self._envelope(
            case_id=case_id,
            revision=int(projection["revision"]),
            operation_id=operation_id,
            operation=descriptor.name,
            status=operation_status,
            value=value,
            evidence_refs=public_evidence,
            gaps=gaps,
            continuation=self._continuation_for(projection),
            capsule=self._capsule(projection),
        )
        receipt = {
            "envelope": envelope,
            "legacy_result_ref": (
                evidence.to_public_dict() if evidence is not None else None
            ),
        }
        if evidence is None:
            receipt["legacy_value"] = self._bounded_legacy_value(value)
        if (
            operation_status == "mutation_outcome_unknown"
            and descriptor.name != "upgrade_batch"
        ):
            self.repository.abandon_idempotency(case_id, idempotency_key)
            raise MutationOutcomeUnknown(
                "mutation returned without a terminal journal stage"
            )
        if operation_status == "running":
            self.repository.abandon_idempotency(case_id, idempotency_key)
            return ContextToolResult(value, envelope)
        self.repository.complete_idempotency(case_id, idempotency_key, receipt)
        return ContextToolResult(value, envelope)

    def wrap_status(
        self,
        value: Mapping[str, object],
        *,
        task_id: str,
        operation_id: str,
    ) -> ContextToolResult:
        case_id = self.repository.case_for_task(task_id) or ""
        projection = self._load(case_id) if case_id else None
        envelope = self._envelope(
            case_id=case_id,
            revision=int(projection["revision"]) if projection else 0,
            operation_id=operation_id,
            operation="runtime_status",
            status="completed",
            value=value,
        )
        envelope["api_version"] = value.get("api_version", RUNTIME_API_VERSION)
        envelope = bounded_envelope(envelope, max_bytes=self.envelope_max_bytes)
        return ContextToolResult(value, envelope)

    def wrap_read(
        self,
        value: Mapping[str, object],
        *,
        operation: str,
        operation_id: str,
        case_id: str,
        status: str = "completed",
    ) -> ContextToolResult:
        return self.wrap_operator_result(
            value,
            operation=operation,
            operation_id=operation_id,
            case_id=case_id,
            status=status,
        )

    def wrap_operator_result(
        self,
        value: Mapping[str, object],
        *,
        operation: str,
        operation_id: str,
        case_id: str,
        status: str = "completed",
    ) -> ContextToolResult:
        """Wrap one Operator / CI Plane result regardless of read/write semantics."""

        projection = self._load(case_id) if case_id else None
        continuation = (
            self._continuation_for(value) if operation == "case_read" else None
        )
        capsule = value.get("capsule") if operation == "case_read" else None
        envelope = self._envelope(
            case_id=case_id,
            revision=int(projection["revision"]) if projection else 0,
            operation_id=operation_id,
            operation=operation,
            status=status,
            value=value,
            evidence_refs=(
                value.get("evidence_refs", [])
                if isinstance(value.get("evidence_refs"), list)
                else ()
            ),
            continuation=continuation,
            capsule=capsule if isinstance(capsule, Mapping) else None,
        )
        return ContextToolResult(value, envelope)

    def error_result(
        self,
        exc: Exception,
        *,
        operation: str,
        arguments: Mapping[str, object],
        task_id: str,
        operation_id: str,
    ) -> ContextToolResult:
        explicit_case = arguments.get("case_id")
        case_id = (
            str(explicit_case).strip()
            if isinstance(explicit_case, str) and explicit_case.strip()
            else (self.repository.case_for_task(task_id) or "")
        )
        projection = self._load(case_id) if case_id else None
        descriptor = (
            self.catalog.require(operation)
            if operation in self.catalog.names()
            else None
        )
        status = (
            self._mutation_exception_status(exc)
            if descriptor is not None and descriptor.mutation
            else "failed"
        )
        raw_code = str(getattr(exc, "code", type(exc).__name__))
        code = (
            status
            if status in {"mutation_outcome_unknown", "blocked"}
            else raw_code
        )
        message = redact_text(exc)
        next_action = (
            "reconcile the durable mutation journal before retrying"
            if status == "mutation_outcome_unknown"
            else (
                "provide the missing recovery authorization and continue the same journal"
                if status == "blocked"
                else "resolve the error and retry with the same case"
            )
        )
        canonical = {"code": code, "message": message[:2048]}
        legacy = {
            "ok": False,
            "error": type(exc).__name__,
            "code": code,
            "message": message,
            "next_action": next_action,
        }
        envelope = self._envelope(
            case_id=case_id,
            revision=int(projection["revision"]) if projection else 0,
            operation_id=operation_id,
            operation=operation,
            status=status,
            value=legacy,
            canonical_error=canonical,
        )
        return ContextToolResult(legacy, envelope)

    def shadow_domain(
        self,
        descriptor: OperationDescriptor,
        arguments: Mapping[str, object],
        *,
        task_id: str,
        operation_id: str,
        value: Mapping[str, object],
    ) -> dict[str, object]:
        """Best-effort migration write that never changes the legacy result."""

        public = dict(value)
        try:
            recorded = self.invoke_domain(
                descriptor,
                arguments,
                task_id=task_id,
                operation_id=operation_id,
                executor=lambda: public,
            )
            self._metrics["shadow_writes"] += 1
            if _fingerprint(_sanitize(recorded)) != _fingerprint(_sanitize(public)):
                self._metrics["shadow_parity_mismatches"] += 1
                public["context_shadow_warning"] = "legacy/context result mismatch"
        except Exception as exc:
            self._metrics["shadow_write_failures"] += 1
            public["context_shadow_warning"] = redact_text(
                f"context shadow write failed: {type(exc).__name__}: {exc}"
            )
        return public



    @staticmethod
    def _batch_target_epoch_fields(
        operation: str,
        value: Mapping[str, object],
    ) -> dict[str, object]:
        epochs = value.get("target_epochs")
        if operation != "upgrade_batch" or not isinstance(epochs, Mapping):
            return {}
        return {"target_epochs": dict(epochs)}

    @staticmethod
    def _observed_target_epoch(
        value: Mapping[str, object],
        *,
        target_id: str = "",
    ) -> int | None:
        direct = value.get(
            "target_epoch",
            value.get("epoch_after", value.get("generation")),
        )
        if isinstance(direct, int) and not isinstance(direct, bool) and direct >= 0:
            return direct
        observed = value.get("observed_target_epochs")
        if isinstance(observed, Mapping):
            selected = observed.get(target_id) if target_id else None
            if selected is None and not target_id and len(observed) == 1:
                selected = next(iter(observed.values()))
            if (
                isinstance(selected, int)
                and not isinstance(selected, bool)
                and selected >= 0
            ):
                return selected
        containers: list[Mapping[str, object]] = [value]
        result = value.get("result")
        if isinstance(result, Mapping):
            containers.append(result)
        for container in containers:
            runtime = container.get("runtime")
            status = runtime.get("status") if isinstance(runtime, Mapping) else None
            targets = status.get("targets") if isinstance(status, Mapping) else None
            if not isinstance(targets, list):
                continue
            candidates: list[tuple[str, int]] = []
            for target in targets:
                if not isinstance(target, Mapping):
                    continue
                epochs = target.get("epochs")
                epoch = epochs.get("target_epoch") if isinstance(epochs, Mapping) else None
                if (
                    isinstance(epoch, int)
                    and not isinstance(epoch, bool)
                    and epoch >= 0
                ):
                    nested_target = target.get("target")
                    nested_target_id = (
                        nested_target.get("target_id")
                        if isinstance(nested_target, Mapping)
                        else None
                    )
                    candidate_target_id = str(
                        target.get("target_id", nested_target_id or "")
                    ).strip()
                    candidates.append((candidate_target_id, epoch))
            if target_id:
                for candidate_target_id, epoch in candidates:
                    if candidate_target_id == target_id:
                        return epoch
                if len(candidates) == 1 and not candidates[0][0]:
                    return candidates[0][1]
            elif len(candidates) == 1:
                return candidates[0][1]
        return None

    @classmethod
    def _require_minimum_target_epoch(
        cls,
        value: Mapping[str, object],
        *,
        minimum_epoch: object,
        target_id: str,
    ) -> int:
        if (
            isinstance(minimum_epoch, bool)
            or not isinstance(minimum_epoch, int)
            or minimum_epoch < 0
        ):
            raise TypeError("_minimum_target_epoch must be a non-negative integer")
        observed_epoch = cls._observed_target_epoch(value, target_id=target_id)
        if observed_epoch is None:
            raise ValueError(
                "fresh verification did not report the required target epoch"
            )
        if observed_epoch < minimum_epoch:
            raise ValueError(
                "fresh verification did not report the required target epoch: "
                f"observed {observed_epoch}, required {minimum_epoch}"
            )
        return observed_epoch

    @staticmethod
    def _selected_target_id(
        projection: Mapping[str, object],
        arguments: Mapping[str, object] | None = None,
    ) -> str:
        supplied = arguments or {}
        target_id = str(supplied.get("target_id", "")).strip()
        if target_id:
            return target_id
        supplied_targets = ContextRuntime._targets(supplied)
        if len(supplied_targets) == 1:
            return str(supplied_targets[0].get("target_id", "")).strip()
        workflow_inputs = projection.get("workflow_inputs", {})
        if isinstance(workflow_inputs, Mapping):
            target_id = str(workflow_inputs.get("target_id", "")).strip()
            if target_id:
                return target_id
        targets = projection.get("targets", [])
        if isinstance(targets, list) and len(targets) == 1:
            target = targets[0]
            if isinstance(target, Mapping):
                return str(target.get("target_id", "")).strip()
        return ""

    @classmethod
    def _preferred_target_id(
        cls,
        projection: Mapping[str, object],
        arguments: Mapping[str, object] | None = None,
    ) -> str:
        selected = cls._selected_target_id(projection, arguments)
        if selected:
            return selected
        supplied = arguments or {}
        targets = cls._targets(supplied)
        if not targets:
            raw_targets = projection.get("targets", [])
            if isinstance(raw_targets, list):
                targets = [
                    dict(target)
                    for target in raw_targets
                    if isinstance(target, Mapping)
                ]
        candidates = [
            target
            for target in targets
            if str(target.get("role", "")).strip().lower() == "candidate"
        ]
        if len(candidates) == 1:
            return str(candidates[0].get("target_id", "")).strip()
        return ""

    @classmethod
    def _target_epoch_floors(
        cls,
        projection: Mapping[str, object],
    ) -> dict[str, int]:
        target_version = int(projection.get("target_version", 1))
        targets = projection.get("targets", [])
        default_target_id = ""
        if isinstance(targets, list) and len(targets) == 1:
            target = targets[0]
            if isinstance(target, Mapping):
                default_target_id = str(target.get("target_id", "")).strip()
        floors: dict[str, int] = {}

        def retain_epoch(raw_target_id: object, raw_epoch: object) -> None:
            if (
                not isinstance(raw_epoch, int)
                or isinstance(raw_epoch, bool)
                or raw_epoch < 0
            ):
                return
            target_id = str(raw_target_id or "").strip() or default_target_id
            if not target_id:
                return
            floors[target_id] = max(floors.get(target_id, 0), raw_epoch)

        states = projection.get("workflow_step_states", {})
        for state in states.values() if isinstance(states, Mapping) else ():
            if not isinstance(state, Mapping):
                continue
            epoch = state.get("target_epoch")
            state_target_version = int(state.get("target_version", 0))
            if (
                isinstance(epoch, int)
                and not isinstance(epoch, bool)
                and epoch >= 0
                and state_target_version == target_version
            ):
                retain_epoch(state.get("target_id"), epoch)
        for operation in projection.get("operations", []):
            if not isinstance(operation, Mapping):
                continue
            epoch = operation.get("target_epoch")
            operation_target_version = int(operation.get("target_version", 0))
            epochs = operation.get("target_epochs")
            if (
                operation.get("operation") == "upgrade_batch"
                and isinstance(epochs, Mapping)
                and operation_target_version == target_version
            ):
                for target_id, target_epoch in epochs.items():
                    retain_epoch(target_id, target_epoch)
            if (
                isinstance(epoch, int)
                and not isinstance(epoch, bool)
                and epoch >= 0
                and (
                    operation_target_version == target_version
                    or (target_version == 1 and operation_target_version == 0)
                )
            ):
                retain_epoch(operation.get("target_id"), epoch)
        return dict(sorted(floors.items()))

    @classmethod
    def _target_epoch_floor(
        cls,
        projection: Mapping[str, object],
        *,
        target_id: str = "",
    ) -> int:
        floors = cls._target_epoch_floors(projection)
        selected = target_id.strip() or cls._selected_target_id(projection)
        if selected:
            return floors.get(selected, 0)
        if len(floors) == 1:
            return next(iter(floors.values()))
        return 0

    def minimum_target_epoch(
        self,
        task_id: str,
        arguments: Mapping[str, object],
    ) -> int:
        case_id = self._case_id(task_id, arguments, bind=False)
        projection = self._load(case_id)
        if projection is None:
            return 0
        supplied_targets = self._targets(arguments)
        if supplied_targets and supplied_targets != projection.get("targets", []):
            return 0
        return self._target_epoch_floor(
            projection,
            target_id=self._preferred_target_id(projection, arguments),
        )

    def persist_observation(
        self,
        raw: Mapping[str, object],
        *,
        scope: Mapping[str, object],
        assurance: str,
        task_id: str = "",
    ) -> dict[str, object]:
        """Persist redacted observation evidence without opening a Case."""

        result = raw.get("result")
        result = result if isinstance(result, Mapping) else {}
        runtime = result.get("runtime")
        runtime = runtime if isinstance(runtime, Mapping) else {}
        runtime_status = runtime.get("status")
        runtime_status = runtime_status if isinstance(runtime_status, Mapping) else {}
        raw_targets = runtime_status.get("targets", [])
        first_target = (
            raw_targets[0]
            if isinstance(raw_targets, list)
            and raw_targets
            and isinstance(raw_targets[0], Mapping)
            else {}
        )
        target_detail = first_target.get("target")
        target_detail = target_detail if isinstance(target_detail, Mapping) else {}
        epochs = first_target.get("epochs")
        epochs = epochs if isinstance(epochs, Mapping) else {}
        identity = first_target.get("identity")
        identity = identity if isinstance(identity, Mapping) else {}
        observed_at = str(
            raw.get("observed_at")
            or result.get("completed_at")
            or result.get("started_at")
            or ""
        ).strip()
        persisted_at = self.clock()
        scope_digest = _fingerprint(_sanitize(scope))
        consistency = observation_consistency(raw)
        reusable = observation_reusable(raw)
        document = {
            "schema": OBSERVATION_SOURCE_SCHEMA,
            "scope": _sanitize(scope),
            "task_id": str(task_id),
            "scope_digest": scope_digest,
            "assurance": str(assurance),
            "target": str(scope.get("target", "")),
            "observed_at": observed_at,
            "observation_timing": _sanitize(consistency),
            "reusable": reusable,
            "persisted_at": persisted_at,
            "fresh_until": (
                persisted_at + OBSERVATION_REUSE_MAX_AGE_SECONDS
                if reusable
                else persisted_at
            ),
            "target_fingerprint": str(target_detail.get("fingerprint", "")),
            "target_epoch": int(epochs.get("target_epoch", 0) or 0),
            "target_identity": _sanitize(identity),
            "raw": _sanitize(raw),
        }
        body = _json_bytes(document)
        if len(body) > MAX_OBSERVATION_SOURCE_BYTES:
            raise ValueError("observation source exceeds the 8 MiB persistence limit")
        blob_id = self.blob_repository.put(body)
        return {
            "schema": OBSERVATION_SOURCE_SCHEMA,
            "blob_id": blob_id,
            "sha256": blob_id,
            "uri": f"blob://{blob_id}",
            "byte_count": len(body),
            "kind": "observation",
            "provenance": "runtime-observation",
            "retention_hint": "run-lifetime",
            "target": document["target"],
            "scope_digest": scope_digest,
            "observed_at": observed_at,
            "fresh_until": document["fresh_until"],
            "target_fingerprint": document["target_fingerprint"],
            "target_epoch": document["target_epoch"],
            "reusable": reusable,
        }

    def find_reusable_observation(
        self, *, task_id: str, target: str
    ) -> dict[str, object] | None:
        """Rebuild the bounded observation index from durable content-addressed blobs."""
        if not task_id or not target:
            return None
        read_bounded = getattr(self.blob_repository, "read_bounded", None)
        if not callable(read_bounded):
            return None
        candidates: list[dict[str, object]] = []
        blob_ids = self.blob_repository.blob_ids()
        # Selection is valid only after inspecting the full candidate set.
        # An incomplete scan must not hide another possible source.
        if len(blob_ids) > MAX_AUTOMATIC_OBSERVATION_SCAN_BLOBS:
            return None
        remaining_bytes = MAX_AUTOMATIC_OBSERVATION_SCAN_BYTES
        for blob_id in blob_ids:
            try:
                source = {
                    "blob_id": blob_id,
                    "sha256": blob_id,
                    "uri": f"blob://{blob_id}",
                    "kind": "observation",
                    "provenance": "runtime-observation",
                    "retention_hint": "run-lifetime",
                }
                if remaining_bytes <= 0:
                    return None
                max_bytes = min(MAX_OBSERVATION_SOURCE_BYTES, remaining_bytes - 1)
                request_bytes = max_bytes + 1
                remaining_bytes -= request_bytes
                body = read_bounded(blob_id, max_bytes=max_bytes)
                if body is None:
                    return None
                remaining_bytes += request_bytes - (len(body) + 1)
                value = json.loads(body.decode("utf-8"))
                if not isinstance(value, Mapping) or value.get("schema") != OBSERVATION_SOURCE_SCHEMA:
                    continue
                if value.get("task_id") != task_id or value.get("target") != target:
                    continue
                if value.get("reusable") is not True:
                    continue
                persisted_at = value.get("persisted_at")
                if (
                    isinstance(persisted_at, bool) or not isinstance(persisted_at, (int, float))
                    or not 0 <= self.clock() - persisted_at <= AUTOMATIC_OBSERVATION_REUSE_MAX_AGE_SECONDS
                ):
                    continue
                fresh_until = value.get("fresh_until", 0)
                if isinstance(fresh_until, bool) or not isinstance(fresh_until, (int, float)) or fresh_until < self.clock():
                    continue
                scope = value.get("scope")
                raw = value.get("raw")
                if not isinstance(scope, Mapping) or not isinstance(raw, Mapping):
                    continue
                source.update({
                    "byte_count": len(body),
                    "target": value.get("target", ""),
                    "scope_digest": value.get("scope_digest", ""),
                    "observed_at": value.get("observed_at", ""),
                    "target_fingerprint": value.get("target_fingerprint", ""),
                    "target_epoch": value.get("target_epoch", 0),
                })
                if not source["target_fingerprint"]:
                    continue
                source["fresh_until"] = fresh_until
                source["reusable"] = True
                candidates.append(source)
            except (EvidenceUnavailable, OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
        if len(candidates) != 1:
            return None
        return candidates[0]

    def load_observation(
        self,
        source: Mapping[str, object],
    ) -> dict[str, object]:
        """Load and verify one content-addressed observation source."""

        blob_id = str(source.get("blob_id", "")).strip()
        if (
            len(blob_id) != 64
            or any(character not in "0123456789abcdef" for character in blob_id)
            or source.get("sha256") != blob_id
            or source.get("uri") != f"blob://{blob_id}"
            or source.get("kind") != "observation"
            or source.get("provenance") != "runtime-observation"
        ):
            raise EvidenceUnavailable("invalid observation source reference")
        body = self.blob_repository.read(blob_id, offset=0, limit=-1)
        if len(body) > MAX_OBSERVATION_SOURCE_BYTES:
            raise EvidenceUnavailable("observation source exceeds the persistence limit")
        byte_count = source.get("byte_count")
        if (
            isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or byte_count != len(body)
        ):
            raise EvidenceUnavailable("observation source size is invalid")
        value = json.loads(body.decode("utf-8"))
        if not isinstance(value, Mapping) or value.get("schema") != OBSERVATION_SOURCE_SCHEMA:
            raise EvidenceUnavailable("observation source schema is invalid")
        scope = value.get("scope")
        raw = value.get("raw")
        if not isinstance(scope, Mapping) or not isinstance(raw, Mapping):
            raise EvidenceUnavailable("observation source is incomplete")
        expected_metadata = {
            "target": str(value.get("target", "")),
            "scope_digest": str(value.get("scope_digest", "")),
            "observed_at": str(value.get("observed_at", "")),
            "target_fingerprint": str(value.get("target_fingerprint", "")),
            "target_epoch": int(value.get("target_epoch", 0) or 0),
        }
        if expected_metadata["scope_digest"] != _fingerprint(_sanitize(scope)):
            raise EvidenceUnavailable("observation source scope digest is invalid")
        for name, expected in expected_metadata.items():
            supplied = source.get(name, "" if isinstance(expected, str) else 0)
            if supplied != expected:
                raise EvidenceUnavailable(
                    f"observation source {name} does not match persisted metadata"
                )
        return dict(value)

    def restore_domain_arguments(
        self,
        task_id: str,
        operation: str,
        arguments: Mapping[str, object],
        *,
        force: bool = False,
    ) -> dict[str, object]:
        """Recover Case-owned domain inputs before a new task opens its backend."""

        restored = dict(arguments)
        supplied_ip = restored.get("ip")
        if (
            isinstance(supplied_ip, str)
            and supplied_ip.strip()
        ) or "targets" in restored:
            return restored
        if self.repository.case_for_task(task_id) and not force:
            return restored
        case_id = self._case_id(task_id, restored, bind=False)
        projection = self._load(case_id)
        if projection is None:
            return restored
        recovered = self._domain_arguments(
            projection,
            operation,
            self._completed_phases(projection),
        )
        recovered.pop(CONTEXT_WORKFLOW_STEP_ARGUMENT, None)
        recovered.update(restored)
        return recovered

    @staticmethod
    def _context_workflow_plan(
        projection: Mapping[str, object]
    ) -> list[tuple[str, str, str]]:
        return [
            (step.kind, step.name, step.step_id)
            for step in DEFAULT_WORKFLOW_DEFINITIONS.definition_for(projection).steps
        ]

    @classmethod
    def _workflow_step_target_id(
        cls,
        projection: Mapping[str, object],
        *,
        kind: str,
        name: str,
        step_id: str,
    ) -> str:
        if kind != "operation":
            return ""
        definition = DEFAULT_WORKFLOW_DEFINITIONS.definition_for(projection)
        for step in definition.steps:
            if step.step_id == step_id and getattr(step, "target_id", ""):
                return step.target_id
        states = projection.get("workflow_step_states", {})
        state = states.get(step_id) if isinstance(states, Mapping) else None
        if (
            isinstance(state, Mapping)
            and state.get("status") in {"completed", "verified", "succeeded"}
            and int(state.get("target_version", 0))
            == int(projection.get("target_version", 1))
        ):
            return str(state.get("target_id", ""))
        if name == "debug_collect":
            preceding: list[tuple[str, str, str]] = []
            for prior_kind, prior_name, prior_step_id in cls._context_workflow_plan(
                projection
            ):
                if prior_step_id == step_id:
                    break
                preceding.append((prior_kind, prior_name, prior_step_id))
            for prior_kind, prior_name, prior_step_id in reversed(preceding):
                if prior_kind != "operation" or prior_name not in {
                    "live_patch_run",
                    "upgrade_run",
                    "upgrade_batch",
                }:
                    continue
                prior_state = (
                    states.get(prior_step_id) if isinstance(states, Mapping) else None
                )
                if (
                    isinstance(prior_state, Mapping)
                    and prior_state.get("status")
                    in {"completed", "verified", "succeeded"}
                    and int(prior_state.get("target_version", 0))
                    == int(projection.get("target_version", 1))
                ):
                    return str(prior_state.get("target_id", ""))
        if name == "upgrade_batch":
            return ""
        if name in {"live_patch_run", "upgrade_run", "debug_collect"}:
            return cls._preferred_target_id(projection)
        return cls._selected_target_id(projection)

    @classmethod
    def _workflow_step_completed(
        cls,
        projection: Mapping[str, object],
        *,
        kind: str,
        name: str,
        step_id: str,
        target_id: str | None = None,
    ) -> bool:
        if kind == "phase" and name == "diagnosis.acceptance":
            return accepted_diagnosis_record(projection) is not None
        states = projection.get("workflow_step_states", {})
        state = states.get(step_id) if isinstance(states, Mapping) else None
        if not isinstance(state, Mapping):
            if kind == "phase":
                current = projection.get("workflow_phase_values", {})
                record = current.get(name) if isinstance(current, Mapping) else None
                if isinstance(record, Mapping):
                    return str(record.get("status", "")) == "completed"
                return False
            expected_target_id = (
                cls._workflow_step_target_id(
                    projection,
                    kind=kind,
                    name=name,
                    step_id=step_id,
                )
                if target_id is None
                else target_id
            )
            occurrence = 0
            for plan_kind, plan_name, plan_step_id in cls._context_workflow_plan(
                projection
            ):
                if plan_kind == kind and plan_name == name:
                    occurrence += 1
                if plan_step_id == step_id:
                    break
            legacy_completed = [
                item
                for item in projection.get("operations", [])
                if isinstance(item, Mapping)
                and str(item.get("operation", "")) == name
                and str(item.get("status", ""))
                in {"completed", "verified", "succeeded"}
                and not str(item.get("workflow_step_id", ""))
                and (
                    not str(item.get("target_id", ""))
                    or str(item.get("target_id", "")) == expected_target_id
                )
            ]
            return len(legacy_completed) >= max(occurrence, 1)
        if state.get("status") not in {"completed", "verified", "succeeded"}:
            return False
        if kind == "operation":
            expected_target_id = (
                cls._workflow_step_target_id(
                    projection,
                    kind=kind,
                    name=name,
                    step_id=step_id,
                )
                if target_id is None
                else target_id
            )
            return (
                int(state.get("target_version", 0))
                == int(projection.get("target_version", 1))
                and str(state.get("target_id", "")) == expected_target_id
            )
        return True

    @staticmethod
    def _workflow_attempt(
        projection: Mapping[str, object],
        *,
        kind: str,
        step_id: str,
    ) -> int:
        cycle_id = str(projection.get("workflow_cycle_id", "cycle-1"))
        key = (
            f"{cycle_id}:{kind}:{step_id}:target-"
            f"{int(projection.get('target_version', 1))}"
            if kind == "operation"
            else f"{cycle_id}:{kind}:{step_id}"
        )
        attempts = projection.get("workflow_step_attempts", {})
        value = attempts.get(key, 0) if isinstance(attempts, Mapping) else 0
        return (
            int(value)
            if isinstance(value, int) and not isinstance(value, bool)
            else 0
        )

    @classmethod
    def _continuation_for(
        cls,
        projection: Mapping[str, object],
    ) -> dict[str, object]:
        required_kind = ""
        required_name = ""
        required_step_id = ""
        for kind, name, step_id in cls._context_workflow_plan(projection):
            if cls._workflow_step_completed(
                projection,
                kind=kind,
                name=name,
                step_id=step_id,
            ):
                continue
            required_kind = kind
            required_name = name
            required_step_id = step_id
            break
        blocked_operation = next(
            (
                item
                for item in reversed(list(projection.get("operations", [])))
                if isinstance(item, Mapping)
                and str(item.get("status", ""))
                in {"failed", "mutation_outcome_unknown"}
            ),
            None,
        )
        next_actions = projection.get("next_actions", [])
        next_action = (
            str(next_actions[0])
            if isinstance(next_actions, list) and next_actions
            else ""
        )
        if not next_action and required_name:
            next_action = (
                f"submit phase_record for {required_name}"
                if required_kind == "phase"
                else f"run {required_name}"
            )
        continuation = {
            "intent": str(projection.get("intent", "")),
            "delivery_strategy": str(projection.get("delivery_strategy", "")),
            "targets": [
                dict(target)
                for target in projection.get("targets", [])
                if isinstance(target, Mapping)
            ],
            "target_version": int(projection.get("target_version", 1)),
            "target_epoch_floor": cls._target_epoch_floor(
                projection,
                target_id=cls._selected_target_id(projection),
            ),
            "target_epoch_floors": cls._target_epoch_floors(projection),
            "workflow_cycle_id": str(
                projection.get("workflow_cycle_id", "cycle-1")
            ),
            "workflow_cycle_number": int(
                projection.get("workflow_cycle_number", 1)
            ),
            "workflow_complete": not bool(required_name),
            "current_phase": required_name,
            "required_phase_type": required_name if required_kind == "phase" else "",
            "required_operation": required_name if required_kind == "operation" else "",
            "required_workflow_step_id": required_step_id,
            "blocked_operation_id": (
                str(blocked_operation.get("operation_id", ""))
                if isinstance(blocked_operation, Mapping)
                else ""
            ),
            "status": str(projection.get("status", "open")),
            "next_action": next_action,
        }
        if required_kind == "phase":
            continuation.update(
                cls._phase_handoff(
                    projection,
                    phase_type=required_name,
                    workflow_step_id=required_step_id,
                )
            )
        return continuation

    @classmethod
    def _phase_handoff(
        cls,
        projection: Mapping[str, object],
        *,
        phase_type: str,
        workflow_step_id: str,
    ) -> dict[str, object]:
        try:
            phase_descriptor = DEFAULT_PHASE_REGISTRY.require(phase_type)
        except ValueError:
            return {}
        required_skill = phase_descriptor.owner
        workflow_inputs = projection.get("workflow_inputs", {})
        completed_phases = cls._completed_phases(projection)
        cycle_id = str(projection.get("workflow_cycle_id", "cycle-1"))
        arguments = {
            "case_id": str(projection.get("case_id", "")),
            "intent": str(projection.get("intent", "")),
            "final_purpose": str(projection.get("final_purpose", "")),
            "change_boundary": str(projection.get("change_boundary", "")),
            "delivery_strategy": str(projection.get("delivery_strategy", "")),
            "targets": projection.get("targets", []),
            "workflow_inputs": workflow_inputs if isinstance(workflow_inputs, Mapping) else {},
            "completed_phases": completed_phases,
            "phase_record_contract": {
                "receipt_schema": phase_descriptor.receipt_schema,
                "case_id": str(projection.get("case_id", "")),
                "expected_revision": int(projection.get("revision", 0)),
                "idempotency_key": f"{cycle_id}:{workflow_step_id}:result",
                "phase_type": phase_type,
                "producer_identity": required_skill,
            },
        }
        return {
            "required_skill": required_skill,
            "handoff_arguments": _sanitize(arguments),
        }

    @classmethod
    def _compatible_workflow_operation(
        cls,
        projection: Mapping[str, object],
        operation: str,
        *,
        execution_target_id: str = "",
    ) -> dict[str, object]:
        for kind, name, step_id in cls._context_workflow_plan(projection):
            if cls._workflow_step_completed(
                projection,
                kind=kind,
                name=name,
                step_id=step_id,
                target_id=(
                    execution_target_id
                    if kind == "operation" and name == operation
                    else None
                ),
            ):
                continue
            if kind == "operation" and name == operation:
                expected_target_id = cls._workflow_step_target_id(
                    projection,
                    kind=kind,
                    name=name,
                    step_id=step_id,
                )
                if operation in {"live_patch_run", "upgrade_run", "upgrade_batch"}:
                    expected_target_id = execution_target_id or expected_target_id
                if expected_target_id and execution_target_id != expected_target_id:
                    return {}
                return {
                    "workflow_cycle_id": str(
                        projection.get("workflow_cycle_id", "cycle-1")
                    ),
                    "workflow_step_id": step_id,
                    "workflow_step_kind": kind,
                    "target_version": int(projection.get("target_version", 1)),
                }
            break
        return {}

    @staticmethod
    def _domain_result_status(
        descriptor: OperationDescriptor,
        value: Mapping[str, object],
    ) -> str:
        if (
            descriptor.name == "upgrade_batch"
            and value.get("outcome_status") == "mutation_outcome_unknown"
        ):
            return "mutation_outcome_unknown"
        if descriptor.mutation:
            classified = ContextRuntime._domain_operation_status(
                descriptor, value
            )
            if classified != "completed":
                return classified
        explicit = str(value.get("status", "")).strip().lower()
        if explicit in {
            "running",
            "partial",
            "failed",
            "cancelled",
            "blocked",
            "mutation_outcome_unknown",
        }:
            return explicit
        if value.get("ok") is False:
            code = str(value.get("normalized_code", value.get("code", ""))).lower()
            if value.get("partial") is True or "partial" in code:
                return "partial"
            return "failed"
        return "completed"

    @staticmethod
    def _workflow_plan(projection: Mapping[str, object]) -> list[tuple[str, str]]:
        return [
            (step.kind, step.name)
            for step in DEFAULT_WORKFLOW_DEFINITIONS.definition_for(projection).steps
        ]

    @staticmethod
    def _operation_records(
        projection: Mapping[str, object],
    ) -> dict[str, list[Mapping[str, object]]]:
        records: dict[str, list[Mapping[str, object]]] = {}
        for operation in projection.get("operations", []):
            if not isinstance(operation, Mapping):
                continue
            name = str(operation.get("operation", ""))
            if not name or name in _WORKFLOW_CONTROL_OPERATIONS:
                continue
            records.setdefault(name, []).append(operation)
        return records

    @staticmethod
    def _latest_phase_records(
        projection: Mapping[str, object],
    ) -> dict[str, Mapping[str, object]]:
        current = projection.get("workflow_phase_values", {})
        if not isinstance(current, Mapping):
            return {}
        return {
            str(phase_type): record
            for phase_type, record in current.items()
            if isinstance(phase_type, str) and isinstance(record, Mapping)
        }

    @classmethod
    def _completed_phases(
        cls, projection: Mapping[str, object]
    ) -> dict[str, Mapping[str, object]]:
        return {
            phase_type: record
            for phase_type, record in cls._latest_phase_records(projection).items()
            if record.get("status") == "completed"
        }

    @classmethod
    def _workflow_semantic_cursor(
        cls,
        projection: Mapping[str, object],
    ) -> str:
        """Fingerprint only plan facts that can change the next business gate."""

        operation_records = cls._operation_records(projection)
        latest_phases = cls._latest_phase_records(projection)
        operation_counts: dict[str, int] = {}
        nodes: list[dict[str, object]] = []
        for kind, name in cls._workflow_plan(projection):
            if kind == "phase":
                phase = latest_phases.get(name)
                nodes.append(
                    {
                        "kind": kind,
                        "name": name,
                        "record": (
                            _sanitize(dict(phase))
                            if isinstance(phase, Mapping)
                            else None
                        ),
                    }
                )
                continue
            occurrence = operation_counts.get(name, 0)
            operation_counts[name] = occurrence + 1
            records = operation_records.get(name, [])
            operation = records[occurrence] if len(records) > occurrence else None
            selected: dict[str, object] | None = None
            if isinstance(operation, Mapping):
                selected = {
                    key: operation[key]
                    for key in (
                        "operation_id",
                        "operation",
                        "status",
                        "accepted_revision",
                        "started_revision",
                        "terminal_revision",
                        "reconciled_revision",
                    )
                    if key in operation
                }
            nodes.append(
                {
                    "kind": kind,
                    "name": name,
                    "occurrence": occurrence,
                    "record": selected,
                }
            )
        raw_plan = projection.get("acceptance_plan", {})
        plan = raw_plan if isinstance(raw_plan, Mapping) else {}
        return DEFAULT_WORKFLOW_DEFINITIONS.semantic_cursor(
            projection,
            nodes=nodes,
            acceptance_plan_id=str(plan.get("plan_id", "")),
            context_facts={
                "case_id": str(projection.get("case_id", "")),
                _TASK_POLICY_FIELD: _sanitize(
                    projection.get(_TASK_POLICY_FIELD, {})
                ),
                "targets": _sanitize(projection.get("targets", [])),
            },
        )


    @staticmethod
    def _domain_arguments(
        projection: Mapping[str, object],
        operation: str,
        completed_phases: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        raw = projection.get("workflow_inputs", {})
        arguments = dict(raw) if isinstance(raw, Mapping) else {}
        raw_entry_arguments = arguments.pop("entry_arguments", {})
        entry_operation = str(projection.get("entry_operation", ""))
        if (
            (
                operation == entry_operation
                or (
                    operation == "debug_collect"
                    and entry_operation in {"debug_run", "debug_collect"}
                )
            )
            and isinstance(raw_entry_arguments, Mapping)
        ):
            arguments.update(raw_entry_arguments)
        projected_intent = (
            str(projection.get("intent", "diagnosis-only"))
            .strip()
            .lower()
            .replace("_", "-")
            or "diagnosis-only"
        )
        effective_intent = _effective_case_intent(projection)
        recovered_legacy_intent = (
            projected_intent == "diagnosis-only"
            and effective_intent != projected_intent
        )
        raw_policy = projection.get(_TASK_POLICY_FIELD)
        if isinstance(raw_policy, Mapping) and raw_policy:
            task_policy = TaskAuthorizationPolicy.from_public_dict(raw_policy)
            if recovered_legacy_intent:
                task_policy = TaskAuthorizationPolicy.from_task_intent(
                    effective_intent,
                    authorized_exceptions=(
                        task_policy.authorized_exceptions.to_public_dict()
                    ),
                    allow_insecure_tls=task_policy.allow_insecure_tls,
                )
        else:
            task_policy = TaskAuthorizationPolicy.from_task_intent(
                effective_intent,
                delivery_strategy=(
                    ""
                    if recovered_legacy_intent
                    else str(projection.get("delivery_strategy", ""))
                ),
                authorized_exceptions=(
                    raw.get("authorized_exceptions")
                    if isinstance(raw, Mapping)
                    else None
                ),
                allow_insecure_tls=(
                    _strict_bool(
                        raw,
                        "allow_insecure_tls",
                        default=True,
                    )
                    if isinstance(raw, Mapping)
                    else True
                ),
            )
        frozen_arguments: dict[str, object] = {
            "intent": task_policy.original_intent,
            "authorized_exceptions": task_policy.authorized_exceptions.to_public_dict(),
            "allow_insecure_tls": task_policy.allow_insecure_tls,
        }
        final_purpose = str(projection.get("final_purpose", "")).strip()
        if final_purpose:
            frozen_arguments["final_purpose"] = final_purpose
        if not recovered_legacy_intent and task_policy.delivery_strategy:
            frozen_arguments["delivery_strategy"] = task_policy.delivery_strategy
        entry_domain = _case_entry_domain(projection)
        if entry_domain:
            frozen_arguments["entry_domain"] = entry_domain
        if isinstance(raw, Mapping):
            for name in _WORKFLOW_SECTION_PROTECTED_ARGUMENTS:
                if name in raw and name not in frozen_arguments:
                    frozen_arguments[name] = raw[name]
        workflow = arguments.pop("workflow", {})
        domain = {
            "debug_run": "debug",
            "debug_collect": "debug",
            "log_bundle_collect": "log_analyzer",
            "live_patch_run": "live_patch",
            "upgrade_run": "upgrade",
            "upgrade_batch": "upgrade",
        }.get(operation, "")
        if isinstance(workflow, Mapping):
            section = (
                workflow.get("verification")
                if operation == "debug_collect"
                else workflow.get(domain)
            )
            if not isinstance(section, Mapping) and operation == "debug_collect":
                section = workflow.get(domain)
            if isinstance(section, Mapping):
                arguments.update(
                    {
                        name: value
                        for name, value in section.items()
                        if name not in _WORKFLOW_SECTION_PROTECTED_ARGUMENTS
                        and not str(name).startswith("_")
                    }
                )
        for name in (
            "target_role",
            "max_steps",
            "include_closeout_bundle",
            "change_boundary",
        ):
            arguments.pop(name, None)
        arguments["case_id"] = projection["case_id"]
        arguments[CONTEXT_WORKFLOW_STEP_ARGUMENT] = True
        arguments.update(frozen_arguments)
        targets = projection.get("targets", [])
        if operation == "upgrade_batch":
            arguments["targets"] = [
                {"target_id": str(target.get("target_id", "")), "ip": str(target.get("address", ""))}
                for target in targets if isinstance(target, Mapping)
            ]
            arguments.pop("ip", None)
            arguments.pop("target_id", None)
        if "ip" not in arguments and isinstance(targets, list) and targets:
            first = targets[0]
            if operation != "upgrade_batch" and isinstance(first, Mapping) and first.get("address"):
                arguments["ip"] = first["address"]
        if operation in {"debug_run", "debug_collect"}:
            arguments = {
                name: value
                for name, value in arguments.items()
                if name in _DEBUG_DOMAIN_ARGUMENTS or name == "case_id"
            }
            raw_targets = arguments.get("targets")
            multi_target_debug = (
                operation == "debug_run"
                and isinstance(raw_targets, list)
                and len(raw_targets) >= 2
            )
            if not multi_target_debug:
                for name in ("concurrency", "reference_role", "targets"):
                    arguments.pop(name, None)
        if operation == "debug_collect":
            arguments.setdefault("profile", "standard")
            arguments = enforce_fresh_verification(arguments)
        if operation == "live_patch_run":
            developer = completed_phases.get("developer.change", {})
            artifact_ref = developer.get("artifact_ref")
            if isinstance(artifact_ref, Mapping) and artifact_ref:
                arguments["artifact_ref"] = dict(artifact_ref)
            for source, destination in (
                ("artifact_path", "local_path"),
                ("artifact_sha256", "artifact_sha256"),
                ("remote_path", "remote_path"),
                ("restart_scope", "restart_scope"),
                ("verification_plan", "verification_checks"),
            ):
                if (
                    source in developer
                    and destination not in arguments
                    and not (
                        source in {"artifact_path", "artifact_sha256"}
                        and "artifact_ref" in arguments
                    )
                ):
                    value = developer[source]
                    if source == "artifact_sha256" and not str(value).strip():
                        continue
                    arguments[destination] = value
        if operation in {"upgrade_run", "upgrade_batch"}:
            build = completed_phases.get("build.artifact", {})
            artifact_ref = build.get("artifact_ref")
            if isinstance(artifact_ref, Mapping) and artifact_ref:
                arguments["artifact_ref"] = dict(artifact_ref)
            for name in ("artifact_path", "artifact_sha256", "product_version"):
                if name in build and "artifact_ref" not in arguments:
                    arguments[name] = build[name]
            for name in ("package_binding", "upgrade_eligible", "evidence_ids"):
                if name in build:
                    arguments[name] = build[name]
        return arguments

    @classmethod
    def _workflow_operation_input_fingerprint(
        cls,
        projection: Mapping[str, object],
        operation: str,
        *,
        target_id: str,
    ) -> str:
        arguments = cls._domain_arguments(
            projection,
            operation,
            cls._completed_phases(projection),
        )
        if target_id:
            arguments["target_id"] = target_id
            for target in projection.get("targets", []):
                if (
                    isinstance(target, Mapping)
                    and str(target.get("target_id", "")) == target_id
                    and str(target.get("address", "")).strip()
                ):
                    arguments["ip"] = str(target["address"])
                    break
        normalized = {
            key: value for key, value in arguments.items()
            if key not in {"case_id", "expected_revision", "idempotency_key"}
            and not str(key).startswith("_")
        }
        def digest(values: Mapping[str, object]) -> str:
            return _fingerprint({"operation": operation, "arguments": _sanitize(values)})
        current_fingerprint = digest(normalized)
        # Before entry-domain pinning, a default diagnosis Run omitted that
        # field from its first Effect. Match the exact historical argument set;
        # no other changed input may reuse the old Effect identity.
        workflow_inputs = projection.get("workflow_inputs", {})
        if isinstance(workflow_inputs, Mapping) and not str(workflow_inputs.get("entry_domain", "")).strip():
            legacy_arguments = {key: value for key, value in normalized.items() if key != "entry_domain"}
            legacy_fingerprint = digest(legacy_arguments)
            if any(
                isinstance(item, Mapping)
                and item.get("operation") == operation
                and item.get("workflow_cycle_id") == projection.get("workflow_cycle_id", "cycle-1")
                and item.get("target_id") == target_id
                and item.get("target_version") == projection.get("target_version", 1)
                and item.get("status") in {"accepted", "running"}
                and item.get("workflow_input_fingerprint") == legacy_fingerprint
                for item in projection.get("operations", [])
            ):
                return legacy_fingerprint
        return current_fingerprint


    def prepare_semantic_run_operation(
        self,
        projection: Mapping[str, object],
        *,
        operation: str,
        workflow_step_id: str,
    ) -> tuple[dict[str, object], str]:
        """Prepare one exact operation selected by RunEngine, without advancing."""

        continuation = self._continuation_for(projection)
        if str(continuation.get("required_operation", "")) != operation:
            raise ValueError("operation is not the current Run continuation")
        if str(continuation.get("required_workflow_step_id", "")) != workflow_step_id:
            raise ValueError("workflow step is not the current Run continuation")
        completed_phases = self._completed_phases(projection)
        domain_arguments = self._domain_arguments(
            projection, operation, completed_phases
        )
        required_target_id = self._workflow_step_target_id(
            projection,
            kind="operation",
            name=operation,
            step_id=workflow_step_id,
        )
        definition = self.workflow_definitions.definition_for(projection)
        operation_is_mutation = self.catalog.require(operation).mutation
        step_index = next(
            index
            for index, step in enumerate(definition.steps)
            if step.step_id == workflow_step_id
        )
        preceding_operation = next(
            (
                step
                for step in reversed(definition.steps[:step_index])
                if step.kind == "operation"
            ),
            None,
        )
        preceding_mutation = (
            preceding_operation
            if preceding_operation is not None
            and self.catalog.require(preceding_operation.name).mutation
            else None
        )
        if operation == "debug_collect" and definition.steps[step_index].target_id:
            preceding_mutation = next(
                (
                    step for step in reversed(definition.steps[:step_index])
                    if step.kind == "operation" and self.catalog.require(step.name).mutation
                ),
                None,
            )
        if not operation_is_mutation and preceding_mutation is not None:
            raw_states = projection.get("workflow_step_states", {})
            prior_state = (
                raw_states.get(preceding_mutation.step_id)
                if isinstance(raw_states, Mapping)
                else None
            )
            if (
                isinstance(prior_state, Mapping)
                and not definition.steps[step_index].target_id
                and str(prior_state.get("status", ""))
                in {"completed", "verified", "succeeded"}
                and str(prior_state.get("target_id", "")).strip()
            ):
                required_target_id = str(prior_state["target_id"])
        if required_target_id:
            domain_arguments["target_id"] = required_target_id
            for target in projection.get("targets", []):
                if (
                    isinstance(target, Mapping)
                    and str(target.get("target_id", "")) == required_target_id
                    and str(target.get("address", "")).strip()
                ):
                    domain_arguments["ip"] = str(target["address"])
                    break
        verification_after_mutation = (
            not operation_is_mutation and preceding_mutation is not None
        )
        target_epoch_floor = self._target_epoch_floor(
            projection,
            target_id=(
                self._preferred_target_id(projection, domain_arguments)
                if operation_is_mutation or verification_after_mutation
                else self._selected_target_id(projection, domain_arguments)
            ),
        )
        if operation_is_mutation:
            domain_arguments["_minimum_target_epoch"] = target_epoch_floor
            if operation == "upgrade_batch":
                domain_arguments["_minimum_target_epochs"] = self._target_epoch_floors(projection)
        if verification_after_mutation and target_epoch_floor:
            domain_arguments["_minimum_target_epoch"] = target_epoch_floor
        cycle_id = str(projection.get("workflow_cycle_id", "cycle-1"))
        target_version = int(projection.get("target_version", 1))
        workflow_definition = self.workflow_definitions.definition_for(projection)
        step_definition = next(
            step
            for step in workflow_definition.steps
            if step.step_id == workflow_step_id
        )
        workflow_input_fingerprint = self._workflow_operation_input_fingerprint(
            projection,
            operation,
            target_id=required_target_id,
        )
        resumable_operation = next(
            (
                item
                for item in reversed(list(projection.get("operations", [])))
                if isinstance(item, Mapping)
                and str(item.get("operation", "")) == operation
                and str(item.get("workflow_cycle_id", "")) == cycle_id
                and str(item.get("workflow_step_id", "")) == workflow_step_id
                and int(item.get("target_version", 0)) == target_version
                and str(item.get("target_id", "")) == required_target_id
                and str(item.get("workflow_definition_fingerprint", ""))
                == workflow_definition.fingerprint
                and str(item.get("workflow_input_fingerprint", ""))
                == workflow_input_fingerprint
                and str(item.get("status", "")) in {"accepted", "running"}
            ),
            None,
        )
        if isinstance(resumable_operation, Mapping):
            derived_operation_id = str(
                resumable_operation.get("operation_id", "")
            )
            resumed_request_fingerprint = str(
                resumable_operation.get("request_fingerprint", "")
            )
            if resumed_request_fingerprint:
                domain_arguments["_workflow_request_fingerprint"] = (
                    resumed_request_fingerprint
                )
            attempt = int(
                resumable_operation.get(
                    "workflow_attempt",
                    self._workflow_attempt(
                        projection,
                        kind="operation",
                        step_id=workflow_step_id,
                    ),
                )
            )
        else:
            attempt = self._workflow_attempt(
                projection,
                kind="operation",
                step_id=workflow_step_id,
            ) + 1
        step_identity = DEFAULT_WORKFLOW_DEFINITIONS.step_identity(
            projection,
            step=step_definition,
            attempt=attempt,
            input_fingerprint=workflow_input_fingerprint,
            target_epoch=target_epoch_floor,
        )
        if not isinstance(resumable_operation, Mapping):
            derived_operation_id = (
                "op-run-"
                + _fingerprint(
                    {
                        "run_id": str(projection.get("case_id", "")),
                        "workflow_execution_id": step_identity.execution_id,
                    }
                )[:24]
            )
        domain_arguments["idempotency_key"] = derived_operation_id
        domain_arguments["_workflow_cycle_id"] = cycle_id
        domain_arguments["_workflow_step_id"] = workflow_step_id
        domain_arguments["_workflow_step_kind"] = "operation"
        domain_arguments["_workflow_target_version"] = target_version
        domain_arguments["_workflow_definition_id"] = (
            step_identity.workflow_definition_id
        )
        domain_arguments["_workflow_definition_version"] = (
            step_identity.workflow_version
        )
        domain_arguments["_workflow_definition_fingerprint"] = (
            step_identity.workflow_fingerprint
        )
        domain_arguments["_workflow_execution_id"] = step_identity.execution_id
        domain_arguments["_workflow_attempt"] = attempt
        domain_arguments["_workflow_input_fingerprint"] = (
            workflow_input_fingerprint
        )
        domain_arguments["_workflow_target_epoch"] = target_epoch_floor
        if "_workflow_request_fingerprint" not in domain_arguments:
            domain_arguments["_workflow_request_fingerprint"] = _fingerprint(
                {
                    "operation": operation,
                    "arguments": _sanitize(
                        {
                            key: value
                            for key, value in domain_arguments.items()
                            if key
                            not in {
                                "case_id",
                                "expected_revision",
                                "idempotency_key",
                                "_workflow_request_fingerprint",
                            }
                        }
                    ),
                }
            )
        return domain_arguments, derived_operation_id

    def prepare_semantic_run_effect(
        self,
        run_id: str,
        *,
        operation: str,
        arguments: Mapping[str, object],
        operation_id: str,
        effect_class: object,
    ) -> PreparedEffect | None:
        """Prepare one Effect fact set for RunEngine to persist."""

        projection = self.read_case(run_id)
        request_fingerprint = str(
            arguments.get("_workflow_request_fingerprint", "")
        )
        if len(request_fingerprint) != 64:
            raise ValueError(
                "semantic Effect request fingerprint is unavailable"
            )
        existing = next(
            (
                item
                for item in reversed(list(projection.get("operations", [])))
                if isinstance(item, Mapping)
                and str(item.get("operation_id", "")) == operation_id
            ),
            None,
        )
        if isinstance(existing, Mapping):
            if str(existing.get("operation", "")) != operation:
                raise IdempotencyConflict(
                    "Effect identity is already bound to another operation"
                )
            persisted_fingerprint = str(
                existing.get("request_fingerprint", "")
            )
            if (
                persisted_fingerprint
                and persisted_fingerprint != request_fingerprint
            ):
                raise IdempotencyConflict(
                    "Effect identity is already bound to different input"
                )
            return None
        workflow_metadata = {
            "workflow_cycle_id": str(arguments.get("_workflow_cycle_id", "")),
            "workflow_step_id": str(arguments.get("_workflow_step_id", "")),
            "workflow_step_kind": str(arguments.get("_workflow_step_kind", "")),
            "target_version": int(
                arguments.get(
                    "_workflow_target_version",
                    projection.get("target_version", 1),
                )
            ),
            "target_id": str(arguments.get("target_id", "")),
            "workflow_definition_id": str(
                arguments.get("_workflow_definition_id", "")
            ),
            "workflow_definition_version": int(
                arguments.get("_workflow_definition_version", 0)
            ),
            "workflow_definition_fingerprint": str(
                arguments.get("_workflow_definition_fingerprint", "")
            ),
            "workflow_execution_id": str(
                arguments.get("_workflow_execution_id", "")
            ),
            "workflow_attempt": int(arguments.get("_workflow_attempt", 0)),
            "workflow_input_fingerprint": str(
                arguments.get("_workflow_input_fingerprint", "")
            ),
            "workflow_target_epoch": int(
                arguments.get("_workflow_target_epoch", 0)
            ),
        }
        intent_arguments = dict(_sanitize_runtime_inputs(arguments))
        if isinstance(intent_arguments.get("artifact_ref"), Mapping):
            for path_field in ("local_path", "artifact_path"):
                intent_arguments.pop(path_field, None)
        intent = EffectIntent(
            run_id=run_id,
            effect_id=operation_id,
            operation=operation,
            effect_class=effect_class,
            request_fingerprint=request_fingerprint,
            arguments=intent_arguments,
        )
        return PreparedEffect(
            intent=intent,
            accepted_payload={
                "operation": operation,
                "idempotency_key": operation_id,
                "request_fingerprint": request_fingerprint,
                "inputs": _operation_identity_inputs(arguments),
                **workflow_metadata,
            },
        )

    def prepare_effect_transition(
        self,
        intent: EffectIntent,
        *,
        result: Mapping[str, object] | None,
        error: BaseException | None,
        settlement_mode: EffectSettlementMode,
    ) -> tuple[RunEvent, ...]:
        """Prepare settled Effect facts without committing Run state."""

        if (result is None) == (error is None):
            raise ValueError("Effect transition requires exactly one result or error")
        if not isinstance(settlement_mode, EffectSettlementMode):
            raise TypeError("Effect transition requires an EffectSettlementMode")
        terminal_event_kind = (
            "OperationReconciled"
            if settlement_mode is EffectSettlementMode.RECONCILE
            else "OperationTerminal"
        )
        descriptor = self.catalog.require(intent.operation)
        projection = self.read_case(intent.run_id)
        operation = next(
            (
                item
                for item in reversed(list(projection.get("operations", [])))
                if isinstance(item, Mapping)
                and str(item.get("operation_id", "")) == intent.effect_id
            ),
            None,
        )
        if not isinstance(operation, Mapping):
            raise ValueError("settled Effect is missing from its Run")
        if str(operation.get("operation", "")) != intent.operation:
            raise ValueError("settled Effect identity belongs to another operation")

        arguments = dict(intent.arguments)
        target_id = (
            "" if intent.operation == "upgrade_batch" else
            self._preferred_target_id(projection, arguments)
            if descriptor.mutation or intent.operation == "debug_collect"
            else self._selected_target_id(projection, arguments)
        )
        value = dict(result) if result is not None else None
        if value is not None:
            minimum_epoch = arguments.get("_minimum_target_epoch")
            if minimum_epoch is not None:
                try:
                    observed_epoch = self._require_minimum_target_epoch(
                        value,
                        minimum_epoch=minimum_epoch,
                        target_id=target_id,
                    )
                    value.setdefault("target_epoch", observed_epoch)
                except (TypeError, ValueError) as exc:
                    error = exc
                    value = None

        if error is not None:
            status = (
                self._mutation_exception_status(error)
                if descriptor.mutation
                else "failed"
            )
            next_action = (
                "reconcile the mutation journal before retrying"
                if status == "mutation_outcome_unknown"
                else (
                    "provide the missing recovery authorization and retry "
                    "the same durable operation"
                    if status == "blocked"
                    else "resolve the error and retry with the same Run"
                )
            )
            return (
                RunEvent(
                    terminal_event_kind,
                    {
                        "status": status,
                        "summary": redact_text(error),
                        "canonical_error": {
                            "code": str(
                                getattr(error, "code", type(error).__name__)
                            ),
                            "message": redact_text(error),
                        },
                        "next_actions": [next_action],
                        "case_status": "open",
                    },
                    intent.effect_id,
                ),
            )

        assert value is not None
        status = self._domain_result_status(descriptor, value)
        events: list[RunEvent] = []
        try:
            evidence = self._put_evidence(
                value,
                case_id=intent.run_id,
                operation_id=intent.effect_id,
                descriptor=descriptor,
                arguments=arguments,
            )
        except Exception as exc:
            if descriptor.mutation:
                return (
                    RunEvent(
                        terminal_event_kind,
                        {
                            "status": "mutation_outcome_unknown",
                            "summary": redact_text(
                                "cannot persist mutation evidence: "
                                f"{exc}"
                            ),
                            "canonical_error": {
                                "code": "mutation_outcome_unknown",
                                "message": redact_text(exc),
                            },
                            "next_actions": [
                                "reconcile the mutation journal before retrying"
                            ],
                            "case_status": "open",
                        },
                        intent.effect_id,
                    ),
                )
            retry_generation = int(
                operation.get("evidence_retry_generation", 0)
            ) + 1
            return (
                RunEvent(
                    "OperationProgressed",
                    {
                        "status": "running",
                        "summary": redact_text(
                            "cannot persist read-only evidence: "
                            f"{exc}"
                        ),
                        "canonical_error": {
                            "code": "evidence_not_persisted",
                            "message": redact_text(exc),
                        },
                        "next_actions": [
                            "retry the same read-only Effect after restoring "
                            "evidence storage"
                        ],
                        "evidence_retry_generation": retry_generation,
                        "case_status": "running",
                    },
                    intent.effect_id,
                ),
            )
        else:
            events.append(
                RunEvent(
                    "EvidenceAttached",
                    {"evidence": evidence.to_public_dict()},
                    intent.effect_id,
                )
            )
        events.append(
            RunEvent(
                (
                    "OperationProgressed"
                    if status == "running"
                    else terminal_event_kind
                ),
                {
                    "status": status,
                    "summary": redact_text(
                        _summary_for(intent.operation, value)
                    ),
                    "next_actions": _next_actions(value),
                    "case_status": "running" if status == "running" else "open",
                    "target_epoch": self._observed_target_epoch(
                        value,
                        target_id=target_id,
                    ),
                    **self._batch_target_epoch_fields(intent.operation, value),
                    **_diagnostic_receipt_event_fields(
                        intent.operation,
                        value,
                        arguments,
                        (evidence.to_public_dict(),),
                        closeout_stage=_operation_closeout_stage(
                            intent.operation,
                            self.operation_stages,
                        ),
                    ),
                },
                intent.effect_id,
            )
        )
        return tuple(events)



    def open_semantic_run(
        self,
        arguments: Mapping[str, object],
        *,
        task_id: str,
        run_id: str,
        start_command_id: str,
        start_input_digest: str,
        start_input: Mapping[str, object],
    ) -> dict[str, object]:
        """Open a pinned Run without executing or selecting any workflow step."""

        existing = self.reattach_semantic_run(
            run_id,
            task_id=task_id,
            start_command_id=start_command_id,
            start_input_digest=start_input_digest,
        )
        if existing is not None:
            return existing
        opened_arguments = {
            **dict(arguments),
            "case_id": run_id,
            "_start_command_id": start_command_id,
            "_start_input_digest": start_input_digest,
            "_start_input": dict(start_input),
        }
        try:
            projection = self._open_case(
                run_id,
                opened_arguments,
                create_only=True,
            )
        except RevisionConflict:
            concurrent = self.reattach_semantic_run(
                run_id,
                task_id=task_id,
                start_command_id=start_command_id,
                start_input_digest=start_input_digest,
            )
            if concurrent is None:
                raise
            return concurrent
        self.repository.bind_task(task_id, run_id)
        return self._cache(projection)

    def reattach_semantic_run(
        self,
        run_id: str,
        *,
        task_id: str,
        start_command_id: str,
        start_input_digest: str,
    ) -> dict[str, object] | None:
        projection = self._load(run_id)
        if projection is None:
            return None
        if (
            str(projection.get("start_command_id", "")) != start_command_id
            or str(projection.get("start_input_digest", "")) != start_input_digest
        ):
            raise IdempotencyConflict(
                "StartRun command identity is already bound to different input"
            )
        self.repository.bind_task(task_id, run_id)
        return self._cache(projection)

    def derive_run_closeout(
        self,
        run_id: str,
        *,
        terminal_status: str,
        include_bundle: bool = False,
    ) -> dict[str, object]:
        """Project closeout content without committing a Run transition."""

        projection = self._load(run_id)
        if projection is None:
            raise CaseNotFound(run_id)
        closeout, markdown, bundle = self._derive_closeout(
            projection,
            terminal_status=terminal_status,
            include_bundle=include_bundle,
        )
        return {
            "closeout": closeout,
            "closeout_markdown": markdown,
            "closeout_bundle": bundle,
        }

    def read_case(self, case_id: str) -> dict[str, object]:
        projection = self._load(case_id, touch=True)
        if projection is None:
            raise CaseNotFound(case_id)
        if projection.get("status") == "terminal":
            try:
                projection = self._recover_terminal_closeout(projection)
            except Exception as exc:
                # Case reads remain available even when the optional Closeout
                # repair cannot be persisted; the event facts are still intact.
                projection["closeout_recovery_gap"] = redact_text(
                    f"{type(exc).__name__}: {exc}"
                )
        projection["capsule"] = self._capsule(projection)
        return projection

    def continuation_for(
        self, projection: Mapping[str, object]
    ) -> dict[str, object]:
        """Return the semantic continuation without exposing event mechanics."""

        return self._continuation_for(projection)

    def read_evidence(
        self,
        case_id: str,
        evidence_id: str,
        *,
        offset: int = 0,
        limit: int = DEFAULT_EVIDENCE_READ_BYTES,
        target_id: str = "",
        generation: str = "",
    ) -> dict[str, object]:
        if offset < 0:
            raise ValueError("evidence offset must be non-negative")
        if limit <= 0 or limit > MAX_EVIDENCE_READ_BYTES:
            raise ValueError(
                f"evidence limit must be between 1 and {MAX_EVIDENCE_READ_BYTES}"
            )
        projection = self._load(case_id, touch=True)
        if projection is None:
            raise CaseNotFound(case_id)
        reference = self.repository.evidence_reference(case_id, evidence_id)
        if not isinstance(reference, Mapping):
            raise EvidenceUnavailable(
                f"evidence {evidence_id} does not belong to case {case_id}"
            )
        if target_id and str(reference.get("target_id", "")) != target_id:
            raise EvidenceUnavailable(
                f"evidence {evidence_id} target does not match {target_id}"
            )
        if generation and str(reference.get("generation", "")) != generation:
            raise EvidenceUnavailable(
                f"evidence {evidence_id} generation does not match {generation}"
            )
        body = self.blob_repository.read(
            str(reference["blob_id"]), offset=offset, limit=limit
        )
        self._metrics["evidence_reads"] += 1
        self._metrics["evidence_bytes_read"] += len(body)
        return {
            "schema": f"{CONTEXT_RUNTIME_SCHEMA}/evidence-read",
            "case_id": case_id,
            "evidence": dict(reference),
            "offset": offset,
            "returned_bytes": len(body),
            "truncated": offset + len(body) < int(reference["byte_count"]),
            "body": body.decode("utf-8", errors="replace"),
        }

    @staticmethod
    def _accepts_operator_evidence(projection: Mapping[str, object]) -> bool:
        return not (
            projection.get("status") in {"terminal", "cancelled"}
            or isinstance(projection.get("run_outcome"), Mapping)
            and bool(projection.get("run_outcome"))
        )

    def _operator_evidence_context(
        self, run_id: str, *, target: str, require_open: bool = True
    ) -> tuple[dict[str, object], dict[str, object], str]:
        projection = self._load(run_id)
        if projection is None:
            raise CaseNotFound(run_id)
        if require_open and not self._accepts_operator_evidence(projection):
            raise CaseClosed(f"run {run_id} no longer accepts evidence")
        targets = [
            dict(item)
            for item in projection.get("targets", [])
            if isinstance(item, Mapping)
            and target
            in {
                str(item.get("target_id", "")).strip(),
                str(item.get("address", "")).strip(),
            }
        ]
        if len(targets) != 1:
            raise ValueError("target must select exactly one Runtime Run target")
        selected_target = targets[0]
        target_id = str(
            selected_target.get("target_id") or selected_target.get("address")
        ).strip()
        return projection, selected_target, target_id

    def operator_evidence_target(
        self,
        run_id: str,
        *,
        target: str,
        require_open: bool = False,
    ) -> str:
        """Resolve one Run target to its canonical ArtifactRef binding."""

        _projection, selected_target, target_id = self._operator_evidence_context(
            run_id, target=target, require_open=require_open
        )
        return str(selected_target.get("address") or target_id).strip()

    def prepare_file_evidence(
        self,
        run_id: str,
        *,
        target: str,
        path: str,
        expected_sha256: str,
        evidence_type: str,
        operation_id: str,
    ) -> dict[str, object]:
        """Validate and persist exact Operator/CI bytes without writing Run facts."""

        projection, selected_target, target_id = self._operator_evidence_context(
            run_id, target=target, require_open=False
        )
        source_path = Path(path).expanduser()
        if not source_path.is_absolute():
            raise ValueError("evidence path must be absolute")
        source_path = source_path.absolute()
        normalized_sha256 = expected_sha256.removeprefix("sha256:")
        if len(normalized_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in normalized_sha256
        ):
            raise ValueError("evidence sha256 must be 64 lowercase hex characters")
        if not evidence_type or _safe_identifier(
            evidence_type, fallback=""
        ) != evidence_type:
            raise ValueError("evidence_type must be a safe identifier")
        evidence_id = "evidence-" + _fingerprint(
            {
                "run_id": run_id,
                "target_id": target_id,
                "evidence_type": evidence_type,
                "blob_id": normalized_sha256,
            }
        )[:32]
        existing = self.repository.evidence_reference(run_id, evidence_id)
        if isinstance(existing, Mapping):
            return {
                "run_id": run_id,
                "evidence_type": evidence_type,
                "evidence": dict(existing),
                "already_attached": True,
            }
        if not self._accepts_operator_evidence(projection):
            raise CaseClosed(f"run {run_id} no longer accepts evidence")
        if not source_path.is_file():
            raise EvidenceUnavailable(f"evidence file is unavailable: {source_path}")
        body = source_path.read_bytes()
        actual_sha256 = hashlib.sha256(body).hexdigest()
        if actual_sha256 != normalized_sha256:
            raise ValueError(
                "evidence digest mismatch: "
                f"expected {normalized_sha256}, actual {actual_sha256}"
            )
        blob_id = self.blob_repository.put(body)
        if blob_id != actual_sha256:
            raise EvidenceUnavailable("evidence blob identity does not match source bytes")
        self._metrics["evidence_bytes_written"] += len(body)
        definition = projection.get("workflow_definition", {})
        definition = definition if isinstance(definition, Mapping) else {}
        epochs = selected_target.get("epochs", {})
        epochs = epochs if isinstance(epochs, Mapping) else {}
        target_epoch_value = epochs.get("target_epoch")
        target_epoch = (
            int(target_epoch_value)
            if isinstance(target_epoch_value, int)
            and not isinstance(target_epoch_value, bool)
            and target_epoch_value >= 0
            else None
        )
        reference = {
            "evidence_id": evidence_id,
            "blob_id": blob_id,
            "media_type": "application/octet-stream",
            "byte_count": len(body),
            "target_id": target_id,
            "generation": str(target_epoch if target_epoch is not None else "operator"),
            "provenance": f"operator-evidence-attach:{evidence_type}",
            "observed_at": self.clock(),
            "case_id": run_id,
            "producer": "operator-evidence-attach",
            "evidence_type": evidence_type,
            "target_epoch": target_epoch,
            "workflow_definition_id": str(definition.get("definition_id", "")),
            "workflow_definition_version": int(definition.get("version", 0) or 0),
            "workflow_definition_fingerprint": str(
                definition.get("fingerprint", "")
            ),
            "workflow_cycle_id": str(projection.get("workflow_cycle_id", "")),
            "workflow_step_id": "",
            "workflow_attempt": 0,
            "parent_evidence_ids": [],
        }
        return {
            "run_id": run_id,
            "evidence_type": evidence_type,
            "evidence": reference,
            "already_attached": False,
        }

    def prepare_artifact_evidence(
        self,
        run_id: str,
        *,
        target: str,
        artifact_ref: Mapping[str, object],
        evidence_type: str,
    ) -> dict[str, object]:
        """Bind one ArtifactStore-owned package to an open Run Evidence fact."""

        projection, selected_target, target_id = self._operator_evidence_context(
            run_id, target=target, require_open=False
        )
        if evidence_type != "firmware-recovery-artifact":
            raise ValueError("Artifact evidence type is unsupported")
        target_bindings = {
            target_id,
            str(selected_target.get("address", "")).strip(),
        }
        target_bindings.discard("")
        reference_value = dict(artifact_ref)
        digest = str(reference_value.get("digest", "")).removeprefix("sha256:")
        size = reference_value.get("size")
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or str(reference_value.get("kind", "")) != "openubmc-hpm"
            or str(reference_value.get("run_id", "")) != run_id
            or str(reference_value.get("target", "")) not in target_bindings
        ):
            raise ValueError("recovery ArtifactRef is not bound to the selected Run target")
        evidence_id = "evidence-" + _fingerprint(
            {
                "run_id": run_id,
                "target_id": target_id,
                "evidence_type": evidence_type,
                "artifact_digest": digest,
            }
        )[:32]
        existing = self.repository.evidence_reference(run_id, evidence_id)
        if isinstance(existing, Mapping):
            return {
                "run_id": run_id,
                "evidence_type": evidence_type,
                "evidence": dict(existing),
                "already_attached": True,
            }
        if not self._accepts_operator_evidence(projection):
            raise CaseClosed(f"run {run_id} no longer accepts evidence")
        definition = projection.get("workflow_definition", {})
        definition = definition if isinstance(definition, Mapping) else {}
        epochs = selected_target.get("epochs", {})
        epochs = epochs if isinstance(epochs, Mapping) else {}
        target_epoch_value = epochs.get("target_epoch")
        target_epoch = (
            int(target_epoch_value)
            if isinstance(target_epoch_value, int)
            and not isinstance(target_epoch_value, bool)
            and target_epoch_value >= 0
            else None
        )
        descriptor = _json_bytes(
            {
                "schema": f"{CONTEXT_RUNTIME_SCHEMA}/artifact-evidence-v1",
                "artifact_ref": reference_value,
            }
        )
        descriptor_blob_id = self.blob_repository.put(descriptor)
        self._metrics["evidence_bytes_written"] += len(descriptor)
        reference = {
            "evidence_id": evidence_id,
            "blob_id": descriptor_blob_id,
            "media_type": "application/vnd.openubmc.artifact-ref+json",
            "byte_count": len(descriptor),
            "target_id": target_id,
            "generation": str(target_epoch if target_epoch is not None else "operator"),
            "provenance": f"operator-evidence-attach:{evidence_type}",
            "observed_at": self.clock(),
            "case_id": run_id,
            "producer": "operator-evidence-attach",
            "evidence_type": evidence_type,
            "artifact_ref": reference_value,
            "target_epoch": target_epoch,
            "workflow_definition_id": str(definition.get("definition_id", "")),
            "workflow_definition_version": int(definition.get("version", 0) or 0),
            "workflow_definition_fingerprint": str(
                definition.get("fingerprint", "")
            ),
            "workflow_cycle_id": str(projection.get("workflow_cycle_id", "")),
            "workflow_step_id": "",
            "workflow_attempt": 0,
            "parent_evidence_ids": [],
        }
        return {
            "run_id": run_id,
            "evidence_type": evidence_type,
            "evidence": reference,
            "already_attached": False,
        }

    def close_case(self, case_id: str, *, expected_revision: int) -> dict[str, object]:
        projection = self._load(case_id)
        if projection is None:
            raise CaseNotFound(case_id)
        if projection.get("closed"):
            return projection
        if expected_revision != projection["revision"]:
            raise RevisionConflict(
                f"case {case_id} revision is {projection['revision']}, expected {expected_revision}"
            )
        if projection.get("status") in {
            "open",
            "running",
            "waiting_external",
            "waiting_phase_record",
            "mutation_outcome_unknown",
        }:
            raise CaseNotForgettable(f"case {case_id} is not terminal")
        if not self._continuation_for(projection)["workflow_complete"]:
            raise CaseNotForgettable(f"case {case_id} workflow is not complete")
        closed = self.repository.commit(
            case_id,
            expected_revision=expected_revision,
            events=(PendingCaseEvent("CaseClosed", {}),),
        )
        return self._cache(closed)

    def forget_case(self, case_id: str) -> dict[str, object]:
        projection = self._load(case_id)
        if projection is None:
            return {"case_id": case_id, "forgotten": False}
        if projection.get("status") in {
            "open",
            "running",
            "waiting_external",
            "waiting_phase_record",
            "mutation_outcome_unknown",
        }:
            raise CaseNotForgettable(f"case {case_id} is not terminal")
        if not self._continuation_for(projection)["workflow_complete"]:
            raise CaseNotForgettable(f"case {case_id} workflow is not complete")
        references = self.repository.delete_case(case_id)
        candidate_blob_ids = tuple(
            dict.fromkeys(
                str(reference.get("blob_id", ""))
                for reference in references
                if str(reference.get("blob_id", ""))
            )
        )
        gc_result = self.garbage_collect_evidence(blob_ids=candidate_blob_ids)
        with self._lock:
            if self._projection_cache.pop(case_id, None) is not None:
                self._projection_cache_bytes -= self._projection_cache_sizes.pop(
                    case_id, 0
                )
            self._capsule_cache.pop(case_id, None)
        return {
            "case_id": case_id,
            "forgotten": True,
            "deleted_blobs": gc_result["deleted"],
            "evidence_gc": gc_result,
        }

    def garbage_collect_evidence(
        self,
        *,
        blob_ids: Iterable[str] | None = None,
    ) -> dict[str, object]:
        candidates = tuple(
            dict.fromkeys(
                str(blob_id)
                for blob_id in (
                    self.blob_repository.blob_ids()
                    if blob_ids is None
                    else blob_ids
                )
                if str(blob_id)
            )
        )
        retained: list[str] = []
        deleted: list[str] = []
        failed: list[dict[str, str]] = []
        for blob_id in candidates:
            try:
                if self.repository.blob_reference_count(blob_id) > 0:
                    retained.append(blob_id)
                    continue
                # Standalone observations have no Case yet. Keep their durable
                # index source until the advertised explicit-reference window ends.
                try:
                    body = self.blob_repository.read(blob_id, offset=0, limit=-1)
                    document = json.loads(body.decode("utf-8")) if len(body) <= MAX_OBSERVATION_SOURCE_BYTES else None
                except (EvidenceUnavailable, ValueError, UnicodeError):
                    document = None
                if isinstance(document, Mapping) and document.get("schema") == OBSERVATION_SOURCE_SCHEMA:
                    fresh_until = document.get("fresh_until", 0)
                    if isinstance(fresh_until, (int, float)) and not isinstance(fresh_until, bool) and fresh_until >= self.clock():
                        retained.append(blob_id)
                        continue
                if self.blob_repository.delete(blob_id):
                    deleted.append(blob_id)
            except Exception as exc:
                failed.append(
                    {
                        "blob_id": blob_id,
                        "error": redact_text(f"{type(exc).__name__}: {exc}"),
                    }
                )
        return {
            "scanned": len(candidates),
            "retained": len(retained),
            "deleted": len(deleted),
            "failed": len(failed),
            "retained_blob_ids": retained,
            "deleted_blob_ids": deleted,
            "failures": failed,
        }

    def maintain(self) -> dict[str, object]:
        now = self.clock()
        evicted_cases = 0
        for meta in self.repository.metadata():
            status = str(meta.get("status", "open"))
            last_access = float(meta.get("last_access", 0.0))
            projection = self._load(str(meta["case_id"]))
            workflow_complete = (
                projection is not None
                and self._continuation_for(projection)["workflow_complete"]
            )
            if (
                status in {"terminal", "closed"}
                and workflow_complete
                and now - last_access >= self.retention_seconds
            ):
                self.forget_case(str(meta["case_id"]))
                evicted_cases += 1
        if (
            self.blob_repository.size_bytes() + self.repository.size_bytes()
            > self.storage_soft_limit_bytes
        ):
            for meta in sorted(
                self.repository.metadata(), key=lambda item: float(item["last_access"])
            ):
                if (
                    self.blob_repository.size_bytes() + self.repository.size_bytes()
                    <= self.storage_soft_limit_bytes
                ):
                    break
                if str(meta.get("status")) not in {"terminal", "closed"}:
                    continue
                projection = self._load(str(meta["case_id"]))
                if projection is None or not self._continuation_for(
                    projection
                )["workflow_complete"]:
                    continue
                self.forget_case(str(meta["case_id"]))
                evicted_cases += 1
        gc_result = self.garbage_collect_evidence()
        self._metrics["maintenance_evictions"] += evicted_cases
        return {"evicted_cases": evicted_cases, "evidence_gc": gc_result}

    def status(self) -> dict[str, object]:
        with self._lock:
            cache_count = len(self._projection_cache)
            cache_bytes = self._projection_cache_bytes
            capsule_count = len(self._capsule_cache)
            metrics = dict(self._metrics)
        return {
            "schema": CONTEXT_RUNTIME_SCHEMA,
            "repository": self.repository.status(),
            "blob_bytes": self.blob_repository.size_bytes(),
            "repository_bytes": self.repository.size_bytes(),
            "storage_bytes": (
                self.blob_repository.size_bytes() + self.repository.size_bytes()
            ),
            "projection_cache_count": cache_count,
            "projection_cache_limit": self.max_cached_projections,
            "projection_cache_bytes": cache_bytes,
            "projection_cache_byte_limit": self.max_cached_projection_bytes,
            "capsule_cache_count": capsule_count,
            "capsule_cache_limit": self.max_cached_projections,
            "envelope_max_bytes": self.envelope_max_bytes,
            "retention_seconds": self.retention_seconds,
            "storage_soft_limit_bytes": self.storage_soft_limit_bytes,
            "metrics": metrics,
        }

    def operator_projection(
        self,
        *,
        task_id: str = "",
        limit: int = MAX_OPERATOR_PROJECTED_RUNS,
    ) -> dict[str, object]:
        """Read a bounded Run/Turn view without persisting projection state."""

        selected_limit = max(1, min(int(limit), MAX_OPERATOR_PROJECTED_RUNS))
        metadata = sorted(
            self.repository.metadata(),
            key=lambda item: (
                float(item.get("last_access", 0.0)),
                str(item.get("case_id", "")),
            ),
            reverse=True,
        )
        bound_run_id = self.repository.case_for_task(task_id) if task_id else None
        runs: list[dict[str, object]] = []
        if bound_run_id is not None:
            bound_projection = self._load(bound_run_id)
            if bound_projection is not None:
                runs.append(operator_run_projection(bound_projection))
        for item in metadata:
            run_id = str(item.get("case_id", ""))
            if run_id == bound_run_id:
                continue
            projection = self._load(run_id)
            if projection is None:
                continue
            runs.append(operator_run_projection(projection))
            if len(runs) >= selected_limit:
                break
        current_run = next(
            (run for run in runs if run.get("run_id") == bound_run_id),
            None,
        )
        return {
            "schema": f"{CONTEXT_RUNTIME_SCHEMA}/operator-projection-v1",
            "source": "runtime-ledger",
            "state_store": False,
            "limit": selected_limit,
            "run_count": len(runs),
            "current_run": current_run,
            "runs": runs,
        }
