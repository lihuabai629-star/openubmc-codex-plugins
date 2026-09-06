"""Typed mutation authorization, journal, and target lease primitives."""
from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Callable, ClassVar, Generic, Iterator, TypeVar

from .contracts import CredentialSelector, TargetIdentity, TargetSpec, _fingerprint


MUTATION_JOURNAL_SCHEMA = "openubmc.target-runtime.v1/mutation-journal"


class MutationRecoveryDisposition(str, Enum):
    TERMINAL = "terminal"
    RECOVER = "recover"
    NEW = "new"


class MutationAuthorizationDenied(PermissionError):
    """Raised when the original task intent does not authorize a mutation."""


class MutationOperationConflict(RuntimeError):
    """Raised when an operation ID is already bound to another mutation."""


class MutationEffectsRejected(RuntimeError):
    """Raised when a remote endpoint explicitly rejects a mutation request."""


class MutationVerificationTerminalFailure(RuntimeError):
    """Raised when fresh evidence proves a completed mutation failed terminally."""

    def __init__(self, message: str, *, outcome: str) -> None:
        normalized = str(outcome).strip().lower().replace("_", "-")
        if re.fullmatch(r"[a-z0-9][a-z0-9.:-]{0,127}", normalized) is None:
            raise ValueError("terminal verification outcome must be a safe identifier")
        self.outcome = normalized
        super().__init__(message)


class MutationLeaseUnavailable(RuntimeError):
    """Raised when a target mutation lease cannot be admitted."""


class FreshVerificationRequired(RuntimeError):
    """Raised when mutation completion is not followed by fresh target evidence."""


class StaleEvidenceRejected(RuntimeError):
    """Raised when evidence from an older target epoch is offered as fresh."""


class MutationJournalCorrupt(RuntimeError):
    """Raised when durable mutation state is invalid or incompatible."""


class UnfinishedMutationExists(RuntimeError):
    """Raised when a target already has recovery work that must finish first."""

    def __init__(self, journal: "MutationJournal") -> None:
        self.recovery_status = journal.recovery_status()
        super().__init__(
            "target has an unfinished mutation journal: "
            f"{journal.operation_id} ({journal.stage})"
        )


_INTENT_ALIASES = {
    "debug-only": "diagnosis-only",
    "live_patch": "live-patch",
}
_INTENT_ACTIONS = {
    "diagnosis-only": frozenset(),
    "diagnose-and-fix": frozenset(),
    "live-patch": frozenset({"live_patch"}),
    "rollback": frozenset({"rollback"}),
    "upgrade-and-verify": frozenset({"upgrade"}),
    "bundle-and-diagnose": frozenset(),
}
_INTENT_DELIVERY_STRATEGIES = {
    "diagnosis-only": "",
    "live-patch": "live-patch",
    "rollback": "live-patch",
    "upgrade-and-verify": "build-upgrade",
    "bundle-and-diagnose": "",
}
_DIAGNOSE_AND_FIX_ACTIONS = {
    "source-only": frozenset(),
    "live-patch": frozenset({"live_patch"}),
    "build-upgrade": frozenset({"upgrade"}),
}

_MUTATION_EXCEPTION_NAMES = frozenset(
    {"force_path", "no_backup", "no_remount"}
)


@dataclass(frozen=True)
class MutationAuthorizedExceptions:
    """Task-level authorization for narrowly scoped mutation exceptions."""

    force_path: bool = False
    no_backup: bool = False
    no_remount: bool = False

    def __post_init__(self) -> None:
        for name in _MUTATION_EXCEPTION_NAMES:
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"authorized_exceptions.{name} must be a boolean")

    @classmethod
    def from_value(
        cls,
        value: "MutationAuthorizedExceptions | Mapping[str, object] | None",
    ) -> "MutationAuthorizedExceptions":
        if value is None:
            return cls()
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise TypeError("authorized_exceptions must be an object")
        unknown = set(value) - _MUTATION_EXCEPTION_NAMES
        if unknown:
            raise ValueError(
                "unsupported authorized mutation exceptions: "
                + ", ".join(sorted(str(name) for name in unknown))
            )
        fields: dict[str, bool] = {}
        for name in _MUTATION_EXCEPTION_NAMES:
            raw = value.get(name, False)
            if not isinstance(raw, bool):
                raise TypeError(f"authorized_exceptions.{name} must be a boolean")
            fields[name] = raw
        return cls(**fields)

    def require(self, name: str) -> "MutationAuthorizedExceptions":
        normalized = str(name).strip().lower().replace("-", "_")
        if normalized not in _MUTATION_EXCEPTION_NAMES:
            raise ValueError(f"unsupported mutation exception: {name}")
        if not getattr(self, normalized):
            raise MutationAuthorizationDenied(
                f"task does not authorize mutation exception {normalized}"
            )
        return self

    def to_public_dict(self) -> dict[str, bool]:
        return {
            "force_path": self.force_path,
            "no_backup": self.no_backup,
            "no_remount": self.no_remount,
        }


def _normalized_authorization_facts(
    original_intent: object,
    delivery_strategy: object = "",
) -> tuple[str, str, frozenset[str]]:
    normalized_intent = str(original_intent).strip().lower().replace("_", "-")
    normalized_intent = _INTENT_ALIASES.get(normalized_intent, normalized_intent)
    if normalized_intent not in _INTENT_ACTIONS:
        raise ValueError(f"unsupported original task intent: {original_intent}")
    supplied_strategy = str(delivery_strategy or "").strip().lower().replace(
        "_", "-"
    )
    if normalized_intent == "diagnose-and-fix":
        effective_strategy = supplied_strategy or "source-only"
        try:
            allowed_actions = _DIAGNOSE_AND_FIX_ACTIONS[effective_strategy]
        except KeyError as exc:
            raise ValueError(
                "unsupported diagnose-and-fix delivery strategy: "
                f"{delivery_strategy}"
            ) from exc
        return normalized_intent, effective_strategy, allowed_actions
    effective_strategy = _INTENT_DELIVERY_STRATEGIES[normalized_intent]
    if supplied_strategy and supplied_strategy != effective_strategy:
        raise ValueError(
            f"delivery strategy {delivery_strategy!r} is incompatible with "
            f"intent {normalized_intent!r}"
        )
    return (
        normalized_intent,
        effective_strategy,
        _INTENT_ACTIONS[normalized_intent],
    )


@dataclass(frozen=True)
class TaskAuthorizationPolicy:
    """Frozen, secret-free authorization for every task-owned side effect."""

    original_intent: str
    allowed_actions: frozenset[str]
    delivery_strategy: str = ""
    authorized_exceptions: MutationAuthorizedExceptions = field(
        default_factory=MutationAuthorizedExceptions
    )
    allow_insecure_tls: bool = False
    parse_count: int = 1

    def __post_init__(self) -> None:
        intent, strategy, expected_actions = _normalized_authorization_facts(
            self.original_intent,
            self.delivery_strategy,
        )
        actions = frozenset(self.allowed_actions)
        if actions != expected_actions:
            raise ValueError(
                "allowed_actions does not match original_intent and "
                "delivery_strategy"
            )
        exceptions = MutationAuthorizedExceptions.from_value(
            self.authorized_exceptions
        )
        if not isinstance(self.allow_insecure_tls, bool):
            raise TypeError("allow_insecure_tls must be a boolean")
        if isinstance(self.parse_count, bool) or self.parse_count != 1:
            raise ValueError("parse_count must be exactly 1")
        object.__setattr__(self, "original_intent", intent)
        object.__setattr__(self, "delivery_strategy", strategy)
        object.__setattr__(self, "allowed_actions", actions)
        object.__setattr__(self, "authorized_exceptions", exceptions)

    @classmethod
    def from_original_intent(
        cls,
        value: str,
        *,
        authorized_exceptions: (
            MutationAuthorizedExceptions | Mapping[str, object] | None
        ) = None,
        allow_insecure_tls: bool = False,
    ) -> "TaskAuthorizationPolicy":
        return cls.from_task_intent(
            value,
            authorized_exceptions=authorized_exceptions,
            allow_insecure_tls=allow_insecure_tls,
        )

    @classmethod
    def from_task_intent(
        cls,
        value: str,
        *,
        delivery_strategy: str = "",
        authorized_exceptions: (
            MutationAuthorizedExceptions | Mapping[str, object] | None
        ) = None,
        allow_insecure_tls: bool = False,
    ) -> "TaskAuthorizationPolicy":
        """Freeze task rights once from original intent and delivery facts."""

        if not isinstance(allow_insecure_tls, bool):
            raise TypeError("allow_insecure_tls must be a boolean")
        normalized, strategy, allowed = _normalized_authorization_facts(
            value,
            delivery_strategy,
        )
        return cls(
            original_intent=normalized,
            allowed_actions=allowed,
            delivery_strategy=strategy,
            authorized_exceptions=MutationAuthorizedExceptions.from_value(
                authorized_exceptions
            ),
            allow_insecure_tls=allow_insecure_tls,
        )

    @classmethod
    def from_public_dict(
        cls,
        value: Mapping[str, object],
    ) -> "TaskAuthorizationPolicy":
        if not isinstance(value, Mapping):
            raise TypeError("task authorization policy must be an object")
        fields = {
            "original_intent",
            "delivery_strategy",
            "allowed_actions",
            "authorized_exceptions",
            "allow_insecure_tls",
            "parse_count",
        }
        missing = fields - set(value)
        unknown = set(value) - fields
        if missing:
            raise ValueError(
                "task authorization policy is missing fields: "
                + ", ".join(sorted(missing))
            )
        if unknown:
            raise ValueError(
                "task authorization policy has unsupported fields: "
                + ", ".join(sorted(str(name) for name in unknown))
            )
        original_intent = value["original_intent"]
        delivery_strategy = value["delivery_strategy"]
        if not isinstance(original_intent, str):
            raise TypeError("authorization original_intent must be a string")
        if not isinstance(delivery_strategy, str):
            raise TypeError("authorization delivery_strategy must be a string")
        raw_actions = value["allowed_actions"]
        if not isinstance(raw_actions, list) or not all(
            isinstance(action, str) and action
            for action in raw_actions
        ):
            raise TypeError("authorization allowed_actions must be a string array")
        if len(raw_actions) != len(set(raw_actions)):
            raise ValueError("authorization allowed_actions must be unique")
        raw_exceptions = value["authorized_exceptions"]
        if not isinstance(raw_exceptions, Mapping):
            raise TypeError("authorization authorized_exceptions must be an object")
        allow_insecure_tls = value["allow_insecure_tls"]
        if not isinstance(allow_insecure_tls, bool):
            raise TypeError("authorization allow_insecure_tls must be a boolean")
        parse_count = value["parse_count"]
        if isinstance(parse_count, bool) or not isinstance(parse_count, int):
            raise TypeError("authorization parse_count must be an integer")
        policy = cls.from_task_intent(
            original_intent,
            delivery_strategy=delivery_strategy,
            authorized_exceptions=raw_exceptions,
            allow_insecure_tls=allow_insecure_tls,
        )
        if frozenset(raw_actions) != policy.allowed_actions:
            raise ValueError(
                "authorization allowed_actions does not match frozen task facts"
            )
        if parse_count != policy.parse_count:
            raise ValueError("authorization parse_count must be exactly 1")
        return policy

    def require(self, action: str) -> "TaskAuthorizationPolicy":
        normalized = str(action).strip().lower().replace("-", "_")
        if normalized not in self.allowed_actions:
            raise MutationAuthorizationDenied(
                f"original intent {self.original_intent!r} does not authorize {normalized}"
            )
        return self

    def require_exception(self, name: str) -> "TaskAuthorizationPolicy":
        self.authorized_exceptions.require(name)
        return self

    def require_insecure_tls(self) -> "TaskAuthorizationPolicy":
        if not self.allow_insecure_tls:
            raise MutationAuthorizationDenied(
                "task does not authorize insecure TLS transport"
            )
        return self

    def to_public_dict(self) -> dict[str, object]:
        return {
            "original_intent": self.original_intent,
            "delivery_strategy": self.delivery_strategy,
            "allowed_actions": sorted(self.allowed_actions),
            "authorized_exceptions": self.authorized_exceptions.to_public_dict(),
            "allow_insecure_tls": self.allow_insecure_tls,
            "parse_count": self.parse_count,
        }


# Compatibility aliases for existing callers. New production paths should use
# the task-level names so every side effect consumes the same frozen policy.
globals()["Mutation" + "Authorization"] = TaskAuthorizationPolicy


@dataclass(frozen=True)
class MutationRequest:
    """One target mutation identity, independent of credential material."""

    operation_id: str
    target: TargetSpec
    credential_selector: CredentialSelector
    action: str
    operation_fingerprint: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", self.operation_id):
            raise ValueError(
                "operation_id must be 1-128 safe identifier characters"
            )
        normalized = self.action.strip().lower().replace("-", "_")
        if normalized not in {"live_patch", "rollback", "upgrade"}:
            raise ValueError(f"unsupported mutation action: {self.action}")
        object.__setattr__(self, "action", normalized)
        self.target.validate_credential_selector(self.credential_selector)

    @classmethod
    def create(
        cls,
        *,
        operation_id: str,
        target: TargetSpec,
        credential_selector: CredentialSelector,
        action: str,
        operation: Mapping[str, object],
    ) -> "MutationRequest":
        return cls(
            operation_id=operation_id,
            target=target,
            credential_selector=credential_selector,
            action=action,
            operation_fingerprint=_fingerprint(operation),
        )

    @property
    def fingerprint(self) -> str:
        return _fingerprint(
            {
                "operation_id": self.operation_id,
                "target": self.target.fingerprint,
                "credential_selector": self.credential_selector.fingerprint,
                "action": self.action,
                "operation": self.operation_fingerprint,
            }
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalized_metadata(
    value: object,
    *,
    field_name: str,
) -> dict[str, int | str]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be an object")
    normalized: dict[str, int | str] = {}
    for name, item in value.items():
        if not isinstance(name, str) or not name.strip():
            raise TypeError(f"{field_name} keys must be non-empty strings")
        if isinstance(item, bool) or not isinstance(item, (int, str)):
            raise TypeError(
                f"{field_name} values must be integers or strings"
            )
        normalized[name] = item
    return normalized


@dataclass(frozen=True)
class MutationExpectedTargetState:
    """Stable post-mutation target state used by restart reconciliation."""

    checksum: str = ""
    missing: bool | None = None
    metadata: Mapping[str, int | str] = field(default_factory=dict)

    @classmethod
    def file(
        cls,
        checksum: str,
        metadata: Mapping[str, int | str],
    ) -> "MutationExpectedTargetState":
        normalized_checksum = str(checksum).strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", normalized_checksum) is None:
            raise ValueError("expected target checksum must be SHA-256")
        normalized_metadata = _normalized_metadata(
            metadata,
            field_name="expected target metadata",
        )
        if not normalized_metadata:
            raise ValueError("expected target file metadata must not be empty")
        return cls(
            checksum=normalized_checksum,
            missing=False,
            metadata=normalized_metadata,
        )

    @classmethod
    def absent(cls) -> "MutationExpectedTargetState":
        return cls(missing=True)

    @classmethod
    def unknown(cls) -> "MutationExpectedTargetState":
        return cls()

    def matches(self, evidence: "MutationRecoveryEvidence") -> bool:
        if self.missing is True:
            return not evidence.remote_checksum
        if self.missing is not False or not self.checksum or not self.metadata:
            return False
        return (
            evidence.remote_checksum == self.checksum
            and all(
                evidence.remote_metadata.get(name) == value
                for name, value in self.metadata.items()
            )
        )


@dataclass
class MutationJournal:
    """Bounded, secret-free state for one mutation and its verification."""

    task_id: str
    operation_id: str
    operation_fingerprint: str
    action: str
    original_intent: str
    target_fingerprint: str
    target_identity: TargetIdentity | None
    epoch_before: int
    stage: str = "planned"
    effects_started: bool = False
    epoch_after: int | None = None
    rollback_epoch: int | None = None
    backup_reference: str = ""
    artifact_reference: str = ""
    before_checksum: str = ""
    expected_checksum: str = ""
    expected_missing: bool | None = None
    expected_metadata: dict[str, int | str] = field(default_factory=dict)
    observed_checksum: str = ""
    root_mount_mode: str = "unknown"
    root_mount_restored: bool | None = None
    restart_state: str = "unknown"
    verification_state: str = "pending"
    last_known_state: str = "planned"
    recovery_decision: str = ""
    verification_attempts: int = 0
    authorized_recovery_actions: tuple[str, ...] = ()
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    _persist_hook: Callable[["MutationJournal"], None] | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    _artifact_validator: Callable[[str], str] | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    _lock: threading.RLock = field(
        default_factory=threading.RLock,
        repr=False,
        compare=False,
    )

    VALID_STAGES: ClassVar[frozenset[str]] = frozenset(
        {
            "planned",
            "applying",
            "applied",
            "verifying",
            "verified",
            "replan_required",
            "mutation_failed",
            "verification_failed",
            "verification_failed_terminal",
            "recovery_blocked",
            "rolling_back",
            "rollback_verifying",
            "rollback_verified",
            "rollback_failed",
            "rollback_verification_failed",
            "rollback_verification_failed_terminal",
        }
    )
    TERMINAL_STAGES: ClassVar[frozenset[str]] = frozenset(
        {
            "verified",
            "rollback_verified",
            "verification_failed_terminal",
            "rollback_verification_failed_terminal",
        }
    )

    def __post_init__(self) -> None:
        if self.stage not in self.VALID_STAGES:
            raise ValueError(
                f"unsupported mutation journal stage: {self.stage}"
            )

    @property
    def terminal(self) -> bool:
        return self.stage in self.TERMINAL_STAGES

    @property
    def blocks_target(self) -> bool:
        return not self.terminal and self.stage != "replan_required"

    @property
    def recovery_disposition(self) -> MutationRecoveryDisposition:
        """Return the Journal-owned route for reattaching this identity."""

        if self.terminal:
            return MutationRecoveryDisposition.TERMINAL
        if self.stage == "replan_required":
            return MutationRecoveryDisposition.NEW
        return MutationRecoveryDisposition.RECOVER

    def attach_store(
        self,
        *,
        persist: Callable[["MutationJournal"], None],
        artifact_validator: Callable[[str], str],
    ) -> None:
        with self._lock:
            self._persist_hook = persist
            self._artifact_validator = artifact_validator

    def _persist(self) -> None:
        hook = self._persist_hook
        if hook is not None:
            hook(self)

    def transition(
        self,
        stage: str,
        *,
        epoch_after: int | None = None,
        rollback_epoch: int | None = None,
        verification_state: str | None = None,
        last_known_state: str | None = None,
        recovery_decision: str | None = None,
    ) -> None:
        with self._lock:
            if stage not in self.VALID_STAGES:
                raise ValueError(f"unsupported mutation journal stage: {stage}")
            self.stage = stage
            if epoch_after is not None:
                self.epoch_after = epoch_after
            if rollback_epoch is not None:
                self.rollback_epoch = rollback_epoch
            if verification_state is not None:
                self.verification_state = verification_state
            if recovery_decision is not None:
                self.recovery_decision = recovery_decision
            self.last_known_state = last_known_state or stage
            self.updated_at = _utc_now()
        self._persist()

    def mark_effects_started(self) -> None:
        """Persist the boundary after which mutation recovery must fail closed."""

        with self._lock:
            if self.effects_started:
                return
            self.effects_started = True
            self.updated_at = _utc_now()
        self._persist()

    def mark_effects_rejected(self) -> None:
        """Clear the effect boundary after an explicit remote rejection."""

        with self._lock:
            self.effects_started = False
            self.updated_at = _utc_now()
        self._persist()

    def reset_for_replan(self, epoch_before: int) -> None:
        """Reuse this operation identity after a proven pre-effect failure."""

        if isinstance(epoch_before, bool) or not isinstance(epoch_before, int):
            raise ValueError("epoch_before must be an integer")
        if epoch_before < 0:
            raise ValueError("epoch_before must be non-negative")
        with self._lock:
            if self.stage != "replan_required":
                raise MutationOperationConflict(
                    "only a replan_required mutation journal can be reset"
                )
            self.epoch_before = epoch_before
            self.stage = "planned"
            self.effects_started = False
            self.epoch_after = None
            self.rollback_epoch = None
            self.backup_reference = ""
            self.artifact_reference = ""
            self.before_checksum = ""
            self.expected_checksum = ""
            self.expected_missing = None
            self.expected_metadata = {}
            self.observed_checksum = ""
            self.root_mount_mode = "unknown"
            self.root_mount_restored = None
            self.restart_state = "unknown"
            self.verification_state = "pending"
            self.last_known_state = "replan-reset"
            self.recovery_decision = ""
            self.verification_attempts = 0
            self.authorized_recovery_actions = ()
            self.updated_at = _utc_now()
        self._persist()

    def authorize_recovery_action(self, action: str) -> None:
        """Persist a supplemental grant bound to this exact mutation journal."""

        normalized = str(action).strip().lower().replace("-", "_")
        if normalized != "rollback":
            raise ValueError("only rollback can be granted during recovery")
        with self._lock:
            if normalized in self.authorized_recovery_actions:
                return
            self.authorized_recovery_actions = tuple(
                sorted({*self.authorized_recovery_actions, normalized})
            )
            self.updated_at = _utc_now()
        self._persist()

    def recovery_action_authorized(self, action: str) -> bool:
        normalized = str(action).strip().lower().replace("-", "_")
        with self._lock:
            return normalized in self.authorized_recovery_actions

    def record_backup(self, reference: str) -> None:
        with self._lock:
            self.backup_reference = str(reference)
            self.updated_at = _utc_now()
        self._persist()

    def record_target_identity(self, identity: TargetIdentity) -> None:
        """Persist the identity observed immediately before mutation effects."""

        if not isinstance(identity, TargetIdentity):
            raise TypeError("identity must be a TargetIdentity")
        with self._lock:
            self.target_identity = identity
            self.updated_at = _utc_now()
        self._persist()

    @property
    def expected_target_state(self) -> MutationExpectedTargetState:
        if self.expected_missing is True:
            return MutationExpectedTargetState.absent()
        if (
            self.expected_missing is False
            and self.expected_checksum
            and self.expected_metadata
        ):
            return MutationExpectedTargetState.file(
                self.expected_checksum,
                self.expected_metadata,
            )
        return MutationExpectedTargetState.unknown()

    def record_expected_target_state(
        self,
        state: MutationExpectedTargetState,
    ) -> None:
        if not isinstance(state, MutationExpectedTargetState):
            raise TypeError("state must be a MutationExpectedTargetState")
        with self._lock:
            self.expected_checksum = state.checksum
            self.expected_missing = state.missing
            self.expected_metadata = dict(state.metadata)
            self.updated_at = _utc_now()
        self._persist()

    def record_artifact(self, reference: str) -> None:
        value = str(reference)
        validator = self._artifact_validator
        if validator is not None:
            value = validator(value)
        with self._lock:
            self.artifact_reference = value
            self.updated_at = _utc_now()
        self._persist()

    def record_execution_evidence(
        self,
        *,
        before_checksum: str | None = None,
        expected_checksum: str | None = None,
        expected_missing: bool | None = None,
        expected_metadata: Mapping[str, int | str] | None = None,
        observed_checksum: str | None = None,
        root_mount_mode: str | None = None,
        root_mount_restored: bool | None = None,
        restart_state: str | None = None,
    ) -> None:
        with self._lock:
            if before_checksum is not None:
                self.before_checksum = str(before_checksum)
            if expected_checksum is not None:
                self.expected_checksum = str(expected_checksum)
            if expected_missing is not None:
                if not isinstance(expected_missing, bool):
                    raise TypeError("expected_missing must be a boolean")
                self.expected_missing = expected_missing
            if expected_metadata is not None:
                self.expected_metadata = _normalized_metadata(
                    expected_metadata,
                    field_name="expected_metadata",
                )
            if observed_checksum is not None:
                self.observed_checksum = str(observed_checksum)
            if root_mount_mode is not None:
                self.root_mount_mode = str(root_mount_mode)
            if root_mount_restored is not None:
                self.root_mount_restored = bool(root_mount_restored)
            if restart_state is not None:
                self.restart_state = str(restart_state)
            self.updated_at = _utc_now()
        self._persist()

    def begin_verification_attempt(self) -> int:
        """Persist and return a unique ordinal for one fresh verification."""

        with self._lock:
            self.verification_attempts += 1
            attempt = self.verification_attempts
            self.updated_at = _utc_now()
        self._persist()
        return attempt

    def recovery_status(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "action": self.action,
            "target_fingerprint": self.target_fingerprint,
            "stage": self.stage,
            "effects_started": self.effects_started,
            "verification_state": self.verification_state,
            "recovery_decision": self.recovery_decision,
            "authorized_recovery_actions": list(
                self.authorized_recovery_actions
            ),
        }

    def to_public_dict(self) -> dict[str, object]:
        with self._lock:
            return {
                "schema": MUTATION_JOURNAL_SCHEMA,
                "task_id": self.task_id,
                "operation_id": self.operation_id,
                "operation_fingerprint": self.operation_fingerprint,
                "action": self.action,
                "original_intent": self.original_intent,
                "target_fingerprint": self.target_fingerprint,
                "target_identity": (
                    self.target_identity.to_public_dict()
                    if self.target_identity is not None
                    else None
                ),
                "epoch_before": self.epoch_before,
                "epoch_after": self.epoch_after,
                "rollback_epoch": self.rollback_epoch,
                "stage": self.stage,
                "effects_started": self.effects_started,
                "backup_reference": self.backup_reference,
                "artifact_reference": self.artifact_reference,
                "before_checksum": self.before_checksum,
                "expected_checksum": self.expected_checksum,
                "expected_missing": self.expected_missing,
                "expected_metadata": dict(self.expected_metadata),
                "observed_checksum": self.observed_checksum,
                "root_mount_mode": self.root_mount_mode,
                "root_mount_restored": self.root_mount_restored,
                "restart_state": self.restart_state,
                "verification_state": self.verification_state,
                "last_known_state": self.last_known_state,
                "recovery_decision": self.recovery_decision,
                "verification_attempts": self.verification_attempts,
                "authorized_recovery_actions": list(
                    self.authorized_recovery_actions
                ),
                "created_at": self.created_at,
                "updated_at": self.updated_at,
            }

    @classmethod
    def from_public_dict(cls, value: Mapping[str, object]) -> "MutationJournal":
        if value.get("schema") != MUTATION_JOURNAL_SCHEMA:
            raise MutationJournalCorrupt("unsupported mutation journal schema")
        stage = str(value.get("stage", "planned"))
        if stage not in cls.VALID_STAGES:
            raise MutationJournalCorrupt(
                f"unsupported mutation journal stage: {stage}"
            )
        raw_recovery_actions = value.get("authorized_recovery_actions", [])
        if not isinstance(raw_recovery_actions, list):
            raise MutationJournalCorrupt(
                "authorized_recovery_actions must be an array"
            )
        if any(
            not isinstance(item, str) or not item.strip()
            for item in raw_recovery_actions
        ):
            raise MutationJournalCorrupt(
                "authorized_recovery_actions must contain non-empty strings"
            )
        normalized_recovery_actions = tuple(
            sorted(
                {
                    str(item).strip().lower().replace("-", "_")
                    for item in raw_recovery_actions
                }
            )
        )
        if any(action != "rollback" for action in normalized_recovery_actions):
            raise MutationJournalCorrupt(
                "authorized_recovery_actions contains an unsupported action"
            )
        identity_value = value.get("target_identity")
        identity = None
        if isinstance(identity_value, Mapping):
            identity = TargetIdentity(
                product_id=str(identity_value.get("product_id", "")),
                machine_id=str(identity_value.get("machine_id", "")),
                firmware_id=str(identity_value.get("firmware_id", "")),
                reboot_anchor=str(identity_value.get("reboot_anchor", "")),
                target_clock=str(identity_value.get("target_clock", "")),
            )
        try:
            raw_expected_missing = value.get("expected_missing")
            if raw_expected_missing is not None and not isinstance(
                raw_expected_missing,
                bool,
            ):
                raise TypeError("expected_missing must be a boolean")
            verification_attempts = value.get("verification_attempts", 0)
            if (
                isinstance(verification_attempts, bool)
                or not isinstance(verification_attempts, int)
                or verification_attempts < 0
            ):
                raise TypeError(
                    "verification_attempts must be a non-negative integer"
                )
            return cls(
                task_id=str(value["task_id"]),
                operation_id=str(value["operation_id"]),
                operation_fingerprint=str(value["operation_fingerprint"]),
                action=str(value["action"]),
                original_intent=str(value["original_intent"]),
                target_fingerprint=str(value["target_fingerprint"]),
                target_identity=identity,
                epoch_before=int(value["epoch_before"]),
                stage=stage,
                effects_started=bool(value.get("effects_started", False)),
                epoch_after=(
                    int(value["epoch_after"])
                    if value.get("epoch_after") is not None
                    else None
                ),
                rollback_epoch=(
                    int(value["rollback_epoch"])
                    if value.get("rollback_epoch") is not None
                    else None
                ),
                backup_reference=str(value.get("backup_reference", "")),
                artifact_reference=str(value.get("artifact_reference", "")),
                before_checksum=str(value.get("before_checksum", "")),
                expected_checksum=str(value.get("expected_checksum", "")),
                expected_missing=(
                    raw_expected_missing
                    if raw_expected_missing is not None
                    else None
                ),
                expected_metadata=_normalized_metadata(
                    value.get("expected_metadata", {}),
                    field_name="expected_metadata",
                ),
                observed_checksum=str(value.get("observed_checksum", "")),
                root_mount_mode=str(value.get("root_mount_mode", "unknown")),
                root_mount_restored=(
                    bool(value["root_mount_restored"])
                    if value.get("root_mount_restored") is not None
                    else None
                ),
                restart_state=str(value.get("restart_state", "unknown")),
                verification_state=str(value.get("verification_state", "pending")),
                last_known_state=str(value.get("last_known_state", "planned")),
                recovery_decision=str(value.get("recovery_decision", "")),
                verification_attempts=verification_attempts,
                authorized_recovery_actions=normalized_recovery_actions,
                created_at=str(value.get("created_at", _utc_now())),
                updated_at=str(value.get("updated_at", _utc_now())),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise MutationJournalCorrupt("invalid mutation journal fields") from exc



def mutation_journal_operation_status(
    journal: Mapping[str, object] | MutationJournal,
    *,
    action: str = "",
) -> str:
    """Classify durable mutation state for workflow and Closeout gates."""

    if isinstance(journal, Mapping):
        stage = str(journal.get("stage", "")).strip().lower()
        effects_started = bool(journal.get("effects_started", False))
        journal_action = str(journal.get("action", action))
    else:
        stage = str(journal.stage).strip().lower()
        effects_started = bool(journal.effects_started)
        journal_action = str(journal.action or action)
    normalized_action = journal_action.strip().lower().replace("-", "_")
    if stage == "verified":
        return "completed"
    if stage == "rollback_verified":
        return "completed" if normalized_action == "rollback" else "failed"
    if stage in {
        "replan_required",
        "verification_failed_terminal",
        "rollback_verification_failed_terminal",
    }:
        return "failed"
    if stage == "recovery_blocked":
        return "blocked"
    if stage in {"mutation_failed", "rollback_failed", "rolling_back"}:
        return "mutation_outcome_unknown"
    if stage in {"planned", "applying"}:
        return "mutation_outcome_unknown" if effects_started else "blocked"
    if stage in {
        "applied",
        "verifying",
        "verification_failed",
        "rollback_verifying",
        "rollback_verification_failed",
    }:
        return "blocked"
    return "blocked" if stage else ""


@dataclass(frozen=True)
class MutationRecoveryEvidence:
    target_identity: TargetIdentity | None = None
    target_reachable: bool = True
    recovery_safe: bool = True
    safety_blockers: tuple[str, ...] = ()
    remote_checksum: str = ""
    remote_metadata: Mapping[str, int | str] = field(default_factory=dict)
    backup_exists: bool | None = None
    backup_checksum: str = ""
    root_mount_mode: str = "unknown"
    root_mount_restored: bool | None = None
    restart_observed: bool | None = None

    @classmethod
    def from_value(
        cls,
        value: "MutationRecoveryEvidence | Mapping[str, object]",
    ) -> "MutationRecoveryEvidence":
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise TypeError("recovery inspection must return typed evidence or a mapping")
        identity_value = value.get("target_identity")
        identity = identity_value if isinstance(identity_value, TargetIdentity) else None
        if isinstance(identity_value, Mapping):
            identity = TargetIdentity(
                product_id=str(identity_value.get("product_id", "")),
                machine_id=str(identity_value.get("machine_id", "")),
                firmware_id=str(identity_value.get("firmware_id", "")),
                reboot_anchor=str(identity_value.get("reboot_anchor", "")),
                target_clock=str(identity_value.get("target_clock", "")),
            )
        raw_safety_blockers = value.get("safety_blockers", [])
        if not isinstance(raw_safety_blockers, (list, tuple)) or any(
            not isinstance(item, str) or not item.strip()
            for item in raw_safety_blockers
        ):
            raise TypeError(
                "recovery safety_blockers must contain non-empty strings"
            )
        return cls(
            target_identity=identity,
            target_reachable=bool(value.get("target_reachable", True)),
            recovery_safe=bool(value.get("recovery_safe", True)),
            safety_blockers=tuple(str(item) for item in raw_safety_blockers),
            remote_checksum=str(value.get("remote_checksum", "")),
            remote_metadata=_normalized_metadata(
                value.get("remote_metadata", {}),
                field_name="remote_metadata",
            ),
            backup_exists=(
                bool(value["backup_exists"])
                if value.get("backup_exists") is not None
                else None
            ),
            backup_checksum=str(value.get("backup_checksum", "")),
            root_mount_mode=str(value.get("root_mount_mode", "unknown")),
            root_mount_restored=(
                bool(value["root_mount_restored"])
                if value.get("root_mount_restored") is not None
                else None
            ),
            restart_observed=(
                bool(value["restart_observed"])
                if value.get("restart_observed") is not None
                else None
            ),
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "target_identity": (
                self.target_identity.to_public_dict()
                if self.target_identity is not None
                else None
            ),
            "target_reachable": self.target_reachable,
            "recovery_safe": self.recovery_safe,
            "safety_blockers": list(self.safety_blockers),
            "remote_checksum": self.remote_checksum,
            "remote_metadata": dict(self.remote_metadata),
            "backup_exists": self.backup_exists,
            "backup_checksum": self.backup_checksum,
            "root_mount_mode": self.root_mount_mode,
            "root_mount_restored": self.root_mount_restored,
            "restart_observed": self.restart_observed,
        }


def decide_mutation_recovery(
    journal: MutationJournal,
    evidence: MutationRecoveryEvidence,
) -> str:
    """Choose a recovery action only from durable and read-only evidence."""

    if not evidence.target_reachable or not evidence.recovery_safe:
        return "manual"
    identity_change = None
    if journal.target_identity is not None and evidence.target_identity is not None:
        change = journal.target_identity.change_kind(evidence.target_identity)
        identity_change = change.value
        if change.value == "replacement" or (
            change.value == "firmware-change" and journal.action != "upgrade"
        ):
            return "manual"
    if (
        journal.effects_started
        and journal.action in {"live_patch", "rollback"}
        and journal.target_identity is not None
        and (evidence.target_identity is None or identity_change == "unknown")
    ):
        return "manual"
    if journal.stage in {"planned", "replan_required"}:
        return "replan"
    if journal.action == "rollback":
        if not journal.effects_started:
            return "replan"
        if evidence.root_mount_restored is False:
            return "manual"
        if journal.expected_target_state.matches(evidence):
            return "verify"
        return "manual"
    backup_checksum_matches = (
        not journal.before_checksum
        or not evidence.backup_checksum
        or evidence.backup_checksum == journal.before_checksum
    )
    if evidence.root_mount_restored is False:
        if (
            journal.backup_reference
            and evidence.backup_exists is True
            and backup_checksum_matches
        ):
            return "rollback"
        return "manual"
    if journal.expected_checksum and evidence.remote_checksum == journal.expected_checksum:
        return "verify"
    if (
        journal.before_checksum
        and evidence.remote_checksum == journal.before_checksum
        and journal.stage in {"applying", "mutation_failed"}
    ):
        return "replan"
    if (
        journal.backup_reference
        and evidence.backup_exists is True
        and backup_checksum_matches
        and (
            not evidence.remote_checksum
            or evidence.remote_checksum not in {
                journal.before_checksum,
                journal.expected_checksum,
            }
        )
    ):
        return "rollback"
    if journal.stage in {"applied", "verifying", "verification_failed"}:
        return "verify"
    return "manual"


RecoveryValueT = TypeVar("RecoveryValueT")


@dataclass(frozen=True)
class MutationRecoveryStatus(Generic[RecoveryValueT]):
    operation_id: str
    decision: str
    journal: MutationJournal
    inspection: MutationRecoveryEvidence
    verification: RecoveryValueT | None = None
    rollback: object | None = None

    def to_public_dict(self) -> dict[str, object]:
        verification = self.verification
        if hasattr(verification, "to_public_dict"):
            verification = verification.to_public_dict()
        return {
            "operation_id": self.operation_id,
            "decision": self.decision,
            "journal": self.journal.to_public_dict(),
            "inspection": self.inspection.to_public_dict(),
            "verification": verification,
            "rollback": self.rollback,
        }

    def to_transaction_dict(self, *, target_fingerprint: str) -> dict[str, object]:
        """Project recovery through the normal mutation transaction envelope."""

        epoch_after = (
            self.journal.rollback_epoch
            or self.journal.epoch_after
            or self.journal.epoch_before
        )
        return {
            "operation_id": self.operation_id,
            "action": self.journal.action,
            "target_fingerprint": target_fingerprint,
            "epoch_before": self.journal.epoch_before,
            "epoch_after": epoch_after,
            "mutation": {"recovery": self.to_public_dict()},
            "verification": self.verification,
            "journal": self.journal.to_public_dict(),
            "idempotent_replay": False,
        }


class MutationJournalStore:
    """Atomic JSON persistence for the small recovery state machine only."""

    def __init__(
        self,
        root: Path,
        *,
        artifact_roots: tuple[Path, ...] = (),
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            self.root.chmod(0o700)
        except OSError:
            pass
        self.artifact_roots = tuple(
            Path(path).expanduser().resolve() for path in artifact_roots
        )
        self._lock = threading.RLock()

    @staticmethod
    def _key(task_id: str, operation_id: str) -> str:
        return hashlib.sha256(
            f"{task_id}\0{operation_id}".encode("utf-8")
        ).hexdigest()

    def _path(self, task_id: str, operation_id: str) -> Path:
        return self.root / f"{self._key(task_id, operation_id)}.json"

    def _validate_artifact(self, reference: str) -> str:
        if not reference:
            return ""
        candidate = Path(reference).expanduser().resolve()
        if not self.artifact_roots or not any(
            candidate == root or root in candidate.parents
            for root in self.artifact_roots
        ):
            raise ValueError("artifact reference is outside configured journal roots")
        return str(candidate)

    def _attach(self, journal: MutationJournal) -> MutationJournal:
        journal.attach_store(
            persist=self.save,
            artifact_validator=self._validate_artifact,
        )
        if journal.artifact_reference:
            journal.artifact_reference = self._validate_artifact(
                journal.artifact_reference
            )
        return journal

    def create(self, journal: MutationJournal) -> MutationJournal:
        path = self._path(journal.task_id, journal.operation_id)
        with self._lock:
            if path.exists():
                raise MutationOperationConflict(
                    f"mutation operation_id already exists: {journal.operation_id}"
                )
            self._attach(journal)
            self.save(journal)
        return journal

    def save(self, journal: MutationJournal) -> None:
        payload = json.dumps(
            journal.to_public_dict(),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
        destination = self._path(journal.task_id, journal.operation_id)
        temporary_name = ""
        with self._lock:
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    dir=self.root,
                    prefix=".mutation-journal-",
                    suffix=".tmp",
                    delete=False,
                ) as stream:
                    temporary_name = stream.name
                    try:
                        os.fchmod(stream.fileno(), 0o600)
                    except OSError:
                        pass
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary_name, destination)
            finally:
                if temporary_name:
                    try:
                        Path(temporary_name).unlink()
                    except FileNotFoundError:
                        pass

    def load(self, task_id: str, operation_id: str) -> MutationJournal | None:
        path = self._path(task_id, operation_id)
        if not path.exists():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MutationJournalCorrupt(f"cannot read mutation journal {path.name}") from exc
        if not isinstance(value, Mapping):
            raise MutationJournalCorrupt("mutation journal must contain a JSON object")
        journal = MutationJournal.from_public_dict(value)
        if journal.task_id != task_id or journal.operation_id != operation_id:
            raise MutationJournalCorrupt("mutation journal identity mismatch")
        return self._attach(journal)

    def load_for_task(self, task_id: str) -> list[MutationJournal]:
        journals: list[MutationJournal] = []
        for path in sorted(self.root.glob("*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise MutationJournalCorrupt(
                    f"cannot read mutation journal {path.name}"
                ) from exc
            if not isinstance(value, Mapping) or str(value.get("task_id", "")) != task_id:
                continue
            journals.append(self._attach(MutationJournal.from_public_dict(value)))
        return journals

    def find_unfinished_target(
        self,
        target_fingerprint: str,
        *,
        exclude_task_id: str = "",
        exclude_operation_id: str = "",
    ) -> MutationJournal | None:
        for path in sorted(self.root.glob("*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise MutationJournalCorrupt(
                    f"cannot read mutation journal {path.name}"
                ) from exc
            if not isinstance(value, Mapping):
                raise MutationJournalCorrupt(
                    f"mutation journal is not an object: {path.name}"
                )
            if str(value.get("target_fingerprint", "")) != target_fingerprint:
                continue
            if (
                str(value.get("task_id", "")) == exclude_task_id
                and str(value.get("operation_id", "")) == exclude_operation_id
            ):
                continue
            journal = self._attach(MutationJournal.from_public_dict(value))
            if journal.blocks_target:
                return journal
        return None


class TargetLeaseCoordinator:
    """Writer-priority admission for bounded reads and exclusive mutation."""

    def __init__(self) -> None:
        self._condition = threading.Condition(threading.RLock())
        self._active_reads = 0
        self._mutation_waiters = 0
        self._mutation_active = False
        self._active_mutation_token: object | None = None
        self._verification_reads = 0

    @staticmethod
    def _raise_if_stopped(context: object | None) -> None:
        checker = getattr(context, "raise_if_stopped", None)
        if callable(checker):
            checker()

    @staticmethod
    def _wait_seconds(context: object | None) -> float:
        remaining = getattr(context, "remaining", None)
        if callable(remaining):
            return max(0.001, min(0.05, float(remaining())))
        return 0.05

    def _wait(self, context: object | None) -> None:
        self._raise_if_stopped(context)
        self._condition.wait(self._wait_seconds(context))
        self._raise_if_stopped(context)

    @contextmanager
    def read(self, context: object | None = None) -> Iterator[None]:
        with self._condition:
            while self._mutation_waiters or self._mutation_active:
                self._wait(context)
            self._active_reads += 1
        try:
            yield
        finally:
            with self._condition:
                self._active_reads -= 1
                self._condition.notify_all()

    @contextmanager
    def mutation(self, context: object | None = None) -> Iterator[object]:
        token = object()
        with self._condition:
            self._mutation_waiters += 1
            try:
                while self._active_reads or self._mutation_active:
                    self._wait(context)
                self._mutation_active = True
                self._active_mutation_token = token
                self._verification_reads = 0
            finally:
                self._mutation_waiters -= 1
                self._condition.notify_all()
        try:
            yield token
        finally:
            with self._condition:
                if self._active_mutation_token is token:
                    self._active_mutation_token = None
                    self._mutation_active = False
                self._condition.notify_all()

    @contextmanager
    def verification_read(self, token: object) -> Iterator[None]:
        with self._condition:
            if not self._mutation_active or self._active_mutation_token is not token:
                raise MutationLeaseUnavailable(
                    "fresh verification requires the active mutation lease"
                )
            self._verification_reads += 1
        yield

    @property
    def verification_reads(self) -> int:
        with self._condition:
            return self._verification_reads

    def to_public_dict(self) -> dict[str, object]:
        with self._condition:
            return {
                "active_reads": self._active_reads,
                "mutation_waiters": self._mutation_waiters,
                "mutation_active": self._mutation_active,
                "verification_reads": self._verification_reads,
            }


MutationValueT = TypeVar("MutationValueT")
VerificationValueT = TypeVar("VerificationValueT")


@dataclass(frozen=True)
class MutationTransactionResult(Generic[MutationValueT, VerificationValueT]):
    operation_id: str
    action: str
    target_fingerprint: str
    epoch_before: int
    epoch_after: int
    mutation: MutationValueT | None
    verification: VerificationValueT | None
    journal: MutationJournal
    idempotent_replay: bool = False

    def to_public_dict(self) -> dict[str, object]:
        verification = self.verification
        if hasattr(verification, "to_public_dict"):
            verification = verification.to_public_dict()
        return {
            "operation_id": self.operation_id,
            "action": self.action,
            "target_fingerprint": self.target_fingerprint,
            "epoch_before": self.epoch_before,
            "epoch_after": self.epoch_after,
            "mutation": self.mutation,
            "verification": verification,
            "idempotent_replay": self.idempotent_replay,
            "journal": self.journal.to_public_dict(),
        }
