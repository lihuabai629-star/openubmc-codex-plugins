"""Task-scoped coordination and retry-safe read execution."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from collections import OrderedDict, deque
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
import threading
import time
from typing import Generic, Protocol, TypeVar
import uuid

from .contracts import (
    RUNTIME_API_VERSION,
    CredentialSelector,
    EpochState,
    LANES,
    TargetIdentity,
    TargetIdentityChange,
    TargetSpec,
    _fingerprint,
    _validate_port,
)
from .mutation import (
    FreshVerificationRequired,
    MutationAuthorization,
    MutationAuthorizationDenied,
    MutationEffectsRejected,
    MutationJournal,
    MutationJournalStore,
    MutationOperationConflict,
    MutationRecoveryEvidence,
    MutationRecoveryStatus,
    MutationRequest,
    MutationTransactionResult,
    MutationVerificationTerminalFailure,
    StaleEvidenceRejected,
    TargetLeaseCoordinator,
    UnfinishedMutationExists,
    decide_mutation_recovery,
    mutation_journal_operation_status,
)
from .orchestration import TaskIntent, TaskOrchestrationContext


T = TypeVar("T")
MasterT = TypeVar("MasterT")
ChannelResultT = TypeVar("ChannelResultT")
SessionT = TypeVar("SessionT")
TelnetResultT = TypeVar("TelnetResultT")
RedfishSessionT = TypeVar("RedfishSessionT")
RedfishResultT = TypeVar("RedfishResultT")
CredentialT = TypeVar("CredentialT")
MutationResultT = TypeVar("MutationResultT")
VerificationResultT = TypeVar("VerificationResultT")


def _annotate_mutation_exception(
    error: BaseException,
    *,
    outcome: str,
    journal: MutationJournal | None = None,
) -> None:
    """Expose a bounded mutation outcome hint to the owning Context Runtime."""

    try:
        setattr(error, "mutation_outcome", outcome)
        if journal is not None:
            setattr(error, "mutation_journal_stage", journal.stage)
            setattr(error, "mutation_effects_started", journal.effects_started)
    except (AttributeError, TypeError):
        pass


@contextmanager
def _annotated_recovery_mutation_lease(
    coordinator: "TargetCoordinator",
    operation_context: object | None,
    journal: MutationJournal,
):
    """Annotate every failure window while recovery holds mutation ownership."""

    try:
        with coordinator.lease_coordinator.mutation(operation_context) as token:
            yield token
    except BaseException as exc:
        if not hasattr(exc, "mutation_outcome"):
            status = mutation_journal_operation_status(journal)
            outcome = (
                "unknown"
                if status == "mutation_outcome_unknown"
                else ("applied" if journal.effects_started else "not_started")
            )
            _annotate_mutation_exception(
                exc,
                outcome=outcome,
                journal=journal,
            )
        raise


class RequestIdConflict(ValueError):
    """Raised when one request ID is reused for a different remote action."""


class RequestInProgress(RuntimeError):
    """Raised when a concurrent retry arrives before the first attempt completes."""


class DuplicateRequestSuppressed(RuntimeError):
    """Raised when retry safety suppresses replay after an uncertain failure."""


class RequestState(str, Enum):
    RUNNING = "running"
    FAILED = "failed"
    COMPLETED = "completed"


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    target_fingerprint: str
    collector: str
    observed_at: str
    target_epoch: int
    lane_epochs: Mapping[str, int]
    freshness: str
    status: str
    summary: str
    size_bytes: int = 0
    artifact_reference: str = ""

    def to_public_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "target_fingerprint": self.target_fingerprint,
            "collector": self.collector,
            "observed_at": self.observed_at,
            "target_epoch": self.target_epoch,
            "lane_epochs": dict(self.lane_epochs),
            "freshness": self.freshness,
            "status": self.status,
            "summary": self.summary,
            "size_bytes": self.size_bytes,
            "artifact_reference": self.artifact_reference,
        }


class EvidenceLedger:
    """Bounded evidence metadata; dynamic result bodies are never cached here."""

    def __init__(
        self,
        *,
        max_records: int = 128,
        max_summary_bytes: int = 2048,
    ) -> None:
        if max_records < 1:
            raise ValueError("max_records must be positive")
        if max_summary_bytes < 1:
            raise ValueError("max_summary_bytes must be positive")
        self.max_records = max_records
        self.max_summary_bytes = max_summary_bytes
        self._records: deque[EvidenceRecord] = deque(maxlen=max_records)
        self._lock = threading.RLock()

    def _bounded_summary(self, summary: str) -> str:
        encoded = str(summary).encode("utf-8", errors="replace")
        if len(encoded) <= self.max_summary_bytes:
            return str(summary)
        return encoded[: self.max_summary_bytes].decode("utf-8", errors="ignore")

    def append(
        self,
        *,
        target_fingerprint: str,
        collector: str,
        target_epoch: int,
        lane_epochs: Mapping[str, int],
        freshness: str,
        status: str,
        summary: str,
        size_bytes: int = 0,
        artifact_reference: str = "",
    ) -> EvidenceRecord:
        if not collector.strip():
            raise ValueError("collector must not be empty")
        if size_bytes < 0:
            raise ValueError("size_bytes must be non-negative")
        record = EvidenceRecord(
            evidence_id=f"evidence-{uuid.uuid4().hex}",
            target_fingerprint=target_fingerprint,
            collector=collector,
            observed_at=datetime.now(timezone.utc).isoformat(),
            target_epoch=target_epoch,
            lane_epochs=dict(lane_epochs),
            freshness=freshness,
            status=status,
            summary=self._bounded_summary(summary),
            size_bytes=size_bytes,
            artifact_reference=artifact_reference,
        )
        with self._lock:
            self._records.append(record)
        return record

    def to_public_dict(self) -> dict[str, object]:
        with self._lock:
            records = list(self._records)
        return {
            "max_records": self.max_records,
            "max_summary_bytes": self.max_summary_bytes,
            "record_count": len(records),
            "records": [record.to_public_dict() for record in records],
        }


@dataclass(frozen=True)
class ResolvedSshCredentials:
    """In-memory SSH credentials whose secret-bearing fields never appear in repr."""

    user: str
    password: str = field(default="", repr=False)
    port: int = 22
    identity_file: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        _validate_port("credential SSH port", self.port)

    @classmethod
    def from_mapping(
        cls,
        values: Mapping[str, str | int],
    ) -> "ResolvedSshCredentials":
        return cls(
            user=str(values.get("user", "")),
            password=str(values.get("password", "")),
            port=int(values.get("port", 22)),
            identity_file=str(values.get("identity_file", "")),
        )

    def to_ssh_mapping(self) -> dict[str, str | int]:
        return {
            "user": self.user,
            "password": self.password,
            "port": self.port,
            "identity_file": self.identity_file,
        }

    def to_public_dict(self) -> dict[str, object]:
        return {
            "transport": "ssh",
            "user_configured": bool(self.user),
            "password_configured": bool(self.password),
            "identity_file_configured": bool(self.identity_file),
            "port": self.port,
        }


@dataclass(frozen=True)
class ResolvedTelnetCredentials:
    """In-memory Telnet credentials whose password never appears in repr."""

    user: str
    password: str = field(default="", repr=False)
    port: int = 23

    def __post_init__(self) -> None:
        _validate_port("credential Telnet port", self.port)

    @classmethod
    def from_mapping(
        cls,
        values: Mapping[str, str | int],
    ) -> "ResolvedTelnetCredentials":
        return cls(
            user=str(values.get("user", "")),
            password=str(values.get("password", "")),
            port=int(values.get("port", 23)),
        )

    def to_telnet_mapping(self) -> dict[str, str | int]:
        return {
            "user": self.user,
            "password": self.password,
            "port": self.port,
        }

    def to_public_dict(self) -> dict[str, object]:
        return {
            "transport": "telnet",
            "user_configured": bool(self.user),
            "password_configured": bool(self.password),
            "port": self.port,
        }


@dataclass(frozen=True)
class ResolvedRedfishCredentials:
    """In-memory Redfish credentials whose password never appears in repr."""

    user: str
    password: str = field(default="", repr=False)
    port: int = 443

    def __post_init__(self) -> None:
        _validate_port("credential Redfish port", self.port)

    @property
    def username(self) -> str:
        """Compatibility spelling used by existing Upgrade helpers."""

        return self.user

    @classmethod
    def from_mapping(
        cls,
        values: Mapping[str, str | int],
    ) -> "ResolvedRedfishCredentials":
        return cls(
            user=str(values.get("user", "")),
            password=str(values.get("password", "")),
            port=int(values.get("port", 443)),
        )

    def to_redfish_mapping(self) -> dict[str, str | int]:
        return {
            "user": self.user,
            "password": self.password,
            "port": self.port,
        }

    def to_public_dict(self) -> dict[str, object]:
        return {
            "transport": "redfish",
            "user_configured": bool(self.user),
            "password_configured": bool(self.password),
            "port": self.port,
        }


@dataclass(frozen=True)
class CredentialResolution(Generic[CredentialT]):
    credentials: CredentialT
    cache_hit: bool


class CredentialResolver:
    """Resolve one credential source at most once for each task target."""

    def __init__(
        self,
        loader: Callable[[CredentialSelector], ResolvedSshCredentials] | None = None,
        *,
        ssh_loader: Callable[[CredentialSelector], ResolvedSshCredentials] | None = None,
        config_path: str | Path | None = None,
        environ: Mapping[str, str] | None = None,
        redfish_loader: Callable[
            [CredentialSelector], ResolvedRedfishCredentials
        ]
        | None = None,
    ) -> None:
        if loader is not None and ssh_loader is not None:
            raise ValueError("provide loader or ssh_loader, not both")
        selected_ssh_loader = ssh_loader or loader
        self._loaders: dict[str, Callable[[CredentialSelector], object]] = {}
        if selected_ssh_loader is not None:
            self._loaders["ssh"] = selected_ssh_loader
        if redfish_loader is not None:
            self._loaders["redfish"] = redfish_loader
        from .credentials import LocalCredentialSource
        self._local_source = LocalCredentialSource(config_path=config_path, environ=environ)
        self._local_cache: dict[tuple[str, str, str, str], object] = {}
        self._task_sources: dict[str, Path | None] = {}
        self._task_snapshots: dict[str, tuple[Path | None, str | None]] = {}
        self._task_source_environments: dict[str, dict[str, str]] = {}
        self._cache: dict[tuple[str, str, str], object] = {}
        self._lock = threading.RLock()

    def resolve_local(
        self, *, task_id: str, host: str, transport: str, purpose: str = "bmc", required: bool = True,
    ) -> CredentialResolution[object]:
        """Resolve one complete local record and bind its source for the task."""
        from .credentials import normalize_credential_host
        if not task_id.strip() or not host.strip() or purpose not in {"bmc", "os"} or transport not in {"ssh", "redfish"}:
            raise ValueError("Local credentials require a task, target, BMC/OS purpose and SSH/Redfish transport")
        key = (task_id, normalize_credential_host(host), purpose, transport)
        with self._lock:
            if key in self._local_cache:
                return CredentialResolution(self._local_cache[key], cache_hit=True)
            path, snapshot = self._selected_local_snapshot(task_id)
            values = self._local_source.resolve(snapshot[0], host=host, purpose=purpose, transport=transport, required=required)
            if values is None:
                return CredentialResolution(None, cache_hit=False)
            credential_type = ResolvedSshCredentials if transport == "ssh" else ResolvedRedfishCredentials
            resolved = credential_type.from_mapping(values)
            self._task_sources[task_id] = path
            self._remember_source_environment(task_id)
            self._task_snapshots[task_id] = snapshot
            self._local_cache[key] = resolved
            return CredentialResolution(resolved, cache_hit=False)

    def _selected_local_snapshot(self, task_id: str):
        """Called with the resolver lock held."""
        from .configuration import activated_source
        path = self._task_sources[task_id] if task_id in self._task_sources else self._local_source.select_path()
        snapshot = self._task_snapshots.get(task_id) or (activated_source(path) if path is not None else (None, None))
        return path, snapshot

    def _remember_source_environment(self, task_id: str) -> None:
        if task_id not in self._task_source_environments:
            self._task_source_environments[task_id] = {
                name: value for name, value in self._local_source.environ.items()
                if name in {"OPENUBMC_CREDENTIALS_CONFIG", "OPENUBMC_CREDENTIALS_FILE", "OPENUBMC_DEBUG_CREDENTIALS_FILE", "XDG_CONFIG_HOME", "HOME"}
            }

    def source_environment(self, task_id: str) -> dict[str, str]:
        """Keep source selectors stable while leaving named credential values local."""
        with self._lock:
            environment = dict(self._local_source.environ)
            if task_id in self._task_source_environments:
                for name in ("OPENUBMC_CREDENTIALS_CONFIG", "OPENUBMC_CREDENTIALS_FILE", "OPENUBMC_DEBUG_CREDENTIALS_FILE", "XDG_CONFIG_HOME", "HOME"):
                    environment.pop(name, None)
                environment.update(self._task_source_environments[task_id])
            return environment

    def resolve_legacy_values(self, *, task_id: str, loader: Callable[..., dict[str, str]]) -> dict[str, str]:
        """Read the compatibility file while binding the same task source as JSON."""
        with self._lock:
            path = self._task_sources[task_id] if task_id in self._task_sources else self._local_source.select_path()
            values = loader(environ=self.source_environment(task_id))
            self._task_sources[task_id] = path
            self._remember_source_environment(task_id)
            return values

    def refresh_local_revision(self, task_id: str) -> bool:
        """Switch snapshots only at a caller-owned request boundary."""
        from .configuration import activated_source
        from .credentials import LocalCredentialSource
        with self._lock:
            if task_id not in self._task_sources:
                return False
            path = self._task_sources[task_id]
            if path is None:
                path = LocalCredentialSource(environ=self.source_environment(task_id)).select_path()
            snapshot = activated_source(path) if path is not None else (None, None)
            previous = self._task_snapshots.get(task_id, (self._task_sources[task_id], None))
            if snapshot == previous:
                return False
            self._task_sources[task_id] = path
            self._task_snapshots[task_id] = snapshot
            self._local_cache = {key: value for key, value in self._local_cache.items() if key[0] != task_id}
            return True

    def configuration_revision(self, task_id: str) -> str | None:
        with self._lock:
            return self._task_snapshots.get(task_id, (None, None))[1]

    def uses_structured_source(self, task_id: str) -> bool:
        with self._lock:
            _path, snapshot = self._selected_local_snapshot(task_id)
            return self._local_source.is_structured(snapshot[0])

    def resolve_local_values(
        self, *, task_id: str, host: str, arguments: Mapping[str, object] | None = None,
        transports: tuple[str, ...] = ("ssh", "redfish"),
    ) -> dict[str, str]:
        """Project selected records only into local Domain Adapter input."""
        arguments = arguments or {}
        values = {"__runtime_selected__": "1"}
        for purpose, transport in (("bmc", "ssh"), ("bmc", "redfish"), ("os", "ssh")):
            if transport not in transports:
                continue
            prefix = ("os_" if purpose == "os" else "") + transport
            if any(arguments.get(prefix + suffix) for suffix in ("_user", "_user_env", "_password", "_password_env", "_identity_file")):
                continue
            selected_host = str(arguments.get("os_ip", "")) if purpose == "os" else host
            if not selected_host:
                continue
            record = self.resolve_local(task_id=task_id, host=selected_host, purpose=purpose, transport=transport,
                                        required=len(transports) == 1 or purpose == "os").credentials
            env_prefix = "OPENUBMC_" + prefix.upper()
            if record is None:
                values[env_prefix + "_USER"] = ""
                values[env_prefix + "_PASSWORD"] = ""
                if transport == "ssh":
                    values[env_prefix + "_IDENTITY_FILE"] = ""
                else:
                    values["REDFISH_USERNAME"] = ""
                    values["REDFISH_PASSWORD"] = ""
                continue
            values[env_prefix + "_USER"] = record.user
            values[env_prefix + "_PASSWORD"] = record.password
            if isinstance(record, ResolvedSshCredentials):
                values[env_prefix + "_IDENTITY_FILE"] = record.identity_file
            if transport == "redfish":
                values["REDFISH_USERNAME"] = record.user
                values["REDFISH_PASSWORD"] = record.password
        return values

    def resolve(
        self,
        *,
        task_id: str,
        target: TargetSpec,
        selector: CredentialSelector,
    ) -> ResolvedSshCredentials:
        resolution = self.resolve_with_status(
            task_id=task_id,
            target=target,
            selector=selector,
        )
        if not isinstance(resolution.credentials, ResolvedSshCredentials):
            raise TypeError("credential selector did not resolve SSH credentials")
        return resolution.credentials

    def resolve_redfish(
        self,
        *,
        task_id: str,
        target: TargetSpec,
        selector: CredentialSelector,
    ) -> ResolvedRedfishCredentials:
        resolution = self.resolve_with_status(
            task_id=task_id,
            target=target,
            selector=selector,
        )
        if not isinstance(resolution.credentials, ResolvedRedfishCredentials):
            raise TypeError("credential selector did not resolve Redfish credentials")
        return resolution.credentials

    def resolve_with_status(
        self,
        *,
        task_id: str,
        target: TargetSpec,
        selector: CredentialSelector,
    ) -> CredentialResolution[object]:
        target.validate_credential_selector(selector)
        key = (task_id, target.fingerprint, selector.fingerprint)
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                return CredentialResolution(cached, cache_hit=True)
            loader = self._loaders.get(selector.transport)
            if loader is None:
                raise RuntimeError(
                    f"{selector.transport} credential resolver is not configured"
                )
            resolved = loader(selector)
            expected_type = {
                "ssh": ResolvedSshCredentials,
                "redfish": ResolvedRedfishCredentials,
            }.get(selector.transport)
            if expected_type is None or not isinstance(resolved, expected_type):
                raise TypeError(
                    f"credential loader must return {expected_type.__name__ if expected_type else 'a supported credential type'}"
                )
            self._cache[key] = resolved
            return CredentialResolution(resolved, cache_hit=False)


@dataclass(frozen=True)
class RemoteReadRequest:
    request_id: str
    target: TargetSpec
    credential_selector: CredentialSelector
    collector_name: str
    operation_fingerprint: str

    def __post_init__(self) -> None:
        if not self.request_id.strip():
            raise ValueError("request_id must not be empty")
        if not self.collector_name.strip():
            raise ValueError("collector_name must not be empty")
        self.target.validate_credential_selector(self.credential_selector)

    @classmethod
    def create(
        cls,
        *,
        request_id: str,
        target: TargetSpec,
        credential_selector: CredentialSelector,
        collector_name: str,
        operation: Mapping[str, object],
    ) -> "RemoteReadRequest":
        return cls(
            request_id=request_id,
            target=target,
            credential_selector=credential_selector,
            collector_name=collector_name,
            operation_fingerprint=_fingerprint(operation),
        )

    @property
    def fingerprint(self) -> str:
        return _fingerprint(
            {
                "target": self.target.fingerprint,
                "credential_selector": self.credential_selector.fingerprint,
                "collector_name": self.collector_name,
                "operation": self.operation_fingerprint,
            }
        )


@dataclass(frozen=True)
class ReadContext:
    task_id: str
    request_id: str
    target: TargetSpec
    credentials: object
    epochs: EpochState


@dataclass(frozen=True)
class RuntimeReadResult(Generic[T]):
    api_version: str
    request_id: str
    collector_name: str
    target_fingerprint: str
    target_epoch: int
    lane_epochs: Mapping[str, int]
    value: T
    deduplicated: bool = False


@dataclass
class TargetCoordinator:
    target: TargetSpec
    epochs: EpochState = field(default_factory=EpochState)
    identity: TargetIdentity | None = None
    lease_coordinator: TargetLeaseCoordinator = field(
        default_factory=TargetLeaseCoordinator,
        repr=False,
    )
    ssh_leases: dict[str, "SshLane[object, object]"] = field(
        default_factory=dict,
        repr=False,
    )
    telnet_leases: dict[str, "TelnetLane[object, object]"] = field(
        default_factory=dict,
        repr=False,
    )
    redfish_leases: dict[str, "RedfishLane[object, object]"] = field(
        default_factory=dict,
        repr=False,
    )
    _lock: threading.RLock = field(
        default_factory=threading.RLock,
        repr=False,
    )

    def lane_state(self, lane: str):
        with self._lock:
            return getattr(self.epochs, lane)

    def connect_lane(self, lane: str) -> None:
        with self._lock:
            self.epochs = self.epochs.connect_lane(lane)

    def cache_lane_state(self, lane: str) -> None:
        with self._lock:
            self.epochs = self.epochs.cache_lane_state(lane)

    def invalidate_lane(self, lane: str, *, reason: str) -> None:
        with self._lock:
            self.epochs = self.epochs.invalidate_lane(lane, reason=reason)

    def advance_target_epoch(self, *, reason: str) -> EpochState:
        with self._lock:
            self.epochs = self.epochs.advance_target_epoch(reason=reason)
            self.identity = None
            return self.epochs

    def ensure_target_epoch(self, minimum: int, *, reason: str) -> EpochState:
        if minimum < 0:
            raise ValueError("minimum target epoch must be non-negative")
        with self._lock:
            while self.epochs.target_epoch < minimum:
                self.epochs = self.epochs.advance_target_epoch(reason=reason)
            self.identity = None
            return self.epochs

    def epochs_snapshot(self) -> EpochState:
        with self._lock:
            return self.epochs


class SshLaneTransport(Protocol[MasterT, ChannelResultT]):
    """Transport boundary used by the canonical task-scoped SSH lane."""

    def open_master(
        self,
        *,
        target: TargetSpec,
        credentials: ResolvedSshCredentials,
    ) -> MasterT: ...

    def check_master(self, master: MasterT) -> bool: ...

    def run_channel(
        self,
        master: MasterT,
        remote_command: str,
        **kwargs: object,
    ) -> ChannelResultT: ...

    def upload_file(
        self,
        master: MasterT,
        local_path: str,
        remote_path: str,
        **kwargs: object,
    ) -> ChannelResultT: ...

    def channel_lost_master(
        self,
        master: MasterT,
        result: ChannelResultT,
    ) -> bool: ...

    def close_master(self, master: MasterT) -> None: ...


class SshLane(Generic[MasterT, ChannelResultT]):
    """Reuse one SSH authentication while every collector opens a fresh channel."""

    _METRIC_NAMES = (
        "authentication_attempts",
        "authentications",
        "channel_requests",
        "reconnects",
        "master_failures",
        "replay_safe_retries",
        "cache_hits",
        "cache_misses",
    )

    def __init__(
        self,
        *,
        lease_name: str,
        coordinator: TargetCoordinator,
        credentials: ResolvedSshCredentials,
        transport: SshLaneTransport[MasterT, ChannelResultT],
        metric_recorder: Callable[[str], None],
    ) -> None:
        if not lease_name.strip():
            raise ValueError("SSH lease_name must not be empty")
        self.lease_name = lease_name
        self._coordinator = coordinator
        self._credentials = credentials
        self._transport = transport
        self._metric_recorder = metric_recorder
        self._master: MasterT | None = None
        self._master_epoch: int | None = None
        self._master_opens = 0
        self._cache: dict[str, object] = {}
        self._cache_epoch: int | None = None
        self._metrics = {name: 0 for name in self._METRIC_NAMES}
        self._lock = threading.RLock()

    @property
    def transport(self) -> SshLaneTransport[MasterT, ChannelResultT]:
        return self._transport

    @property
    def ssh_epoch(self) -> int:
        with self._lock:
            return self._coordinator.lane_state("ssh").epoch

    @property
    def cached_state_keys(self) -> tuple[str, ...]:
        with self._lock:
            self._sync_epoch_state()
            return tuple(sorted(self._cache))

    def _record(self, local_name: str, task_name: str) -> None:
        self._metrics[local_name] = self._metrics.get(local_name, 0) + 1
        self._metric_recorder(task_name)

    def _invalidate(
        self,
        *,
        reason: str,
        master_failure: bool,
    ) -> None:
        master = self._master
        self._master = None
        self._master_epoch = None
        self._cache.clear()
        self._cache_epoch = None
        if master is not None:
            try:
                self._transport.close_master(master)
            except Exception:
                pass
        self._coordinator.invalidate_lane(
            "ssh",
            reason=reason,
        )
        if master_failure:
            self._record("master_failures", "ssh_master_failures")

    def _open_master(self) -> MasterT:
        reconnecting = self._master_opens > 0
        self._record("authentication_attempts", "ssh_authentication_attempts")
        try:
            master = self._transport.open_master(
                target=self._coordinator.target,
                credentials=self._credentials,
            )
        except Exception:
            self._cache.clear()
            self._cache_epoch = None
            self._coordinator.invalidate_lane(
                "ssh",
                reason="authentication-failed",
            )
            raise
        self._master = master
        self._coordinator.connect_lane("ssh")
        self._master_epoch = self._coordinator.lane_state("ssh").epoch
        self._master_opens += 1
        self._record("authentications", "ssh_authentications")
        if reconnecting:
            self._record("reconnects", "ssh_reconnects")
        return master

    def _sync_epoch_state(self) -> None:
        state = self._coordinator.lane_state("ssh")
        if self._cache and (
            self._cache_epoch != state.epoch or state.status.value != "ready"
        ):
            self._cache.clear()
            self._cache_epoch = None
        if self._master is not None and (
            self._master_epoch != state.epoch or state.status.value != "ready"
        ):
            master = self._master
            self._master = None
            self._master_epoch = None
            try:
                self._transport.close_master(master)
            except Exception:
                pass

    def _ensure_master(self) -> MasterT:
        self._sync_epoch_state()
        master = self._master
        if master is not None:
            return master
        return self._open_master()

    def run_channel(
        self,
        remote_command: str,
        *,
        timeout: float,
        tty: bool = False,
        stdout_limit_bytes: int | None = None,
        stderr_limit_bytes: int | None = None,
        debug_dumper: object | None = None,
        debug_label: str = "ssh",
        replay_safe: bool = False,
    ) -> ChannelResultT:
        """Execute one channel and optionally recover one replay-safe read."""

        started = time.monotonic()
        attempts = 2 if replay_safe else 1
        result: ChannelResultT
        for attempt in range(attempts):
            remaining = max(0.0, float(timeout) - (time.monotonic() - started))
            if attempt > 0 and remaining <= 0:
                return result
            with self._lock:
                master = self._ensure_master()
            result = self._transport.run_channel(
                master,
                remote_command,
                timeout=remaining if attempt > 0 else timeout,
                tty=tty,
                stdout_limit_bytes=stdout_limit_bytes,
                stderr_limit_bytes=stderr_limit_bytes,
                debug_dumper=debug_dumper,
                debug_label=debug_label,
            )
            lost_master = self._transport.channel_lost_master(master, result)
            with self._lock:
                self._record("channel_requests", "ssh_channels")
                if lost_master and self._master is master:
                    self._invalidate(
                        reason="master-lost-during-channel",
                        master_failure=True,
                    )
            if not lost_master or attempt + 1 >= attempts:
                return result
            with self._lock:
                self._record("replay_safe_retries", "ssh_replay_safe_retries")
        return result

    def run_ssh(
        self,
        ip: str,
        user: str,
        password: str,
        remote_cmd: str,
        timeout: float,
        tty: bool = False,
        port: int = 22,
        identity_file: str = "",
        debug_dumper: object | None = None,
        debug_label: str = "ssh",
        host_key_policy: str = "",
        known_hosts_file: str = "",
        allow_insecure_host_key: bool = False,
        stdout_limit_bytes: int | None = None,
        stderr_limit_bytes: int | None = None,
        replay_safe: bool = False,
    ) -> ChannelResultT:
        """Compatibility callable for typed collectors that already accept run_ssh."""

        target = self._coordinator.target
        if ip.strip().lower() != target.host or int(port) != target.ssh_port:
            raise ValueError("collector attempted to use the SSH lane for a different target")
        if (
            user != self._credentials.user
            or password != self._credentials.password
            or identity_file != self._credentials.identity_file
        ):
            raise ValueError(
                "collector attempted to use credentials outside the bound SSH lane"
            )
        if host_key_policy or known_hosts_file or allow_insecure_host_key:
            validator = getattr(self._transport, "validate_channel_options", None)
            if validator is None:
                raise ValueError(
                    "SSH channel options cannot differ from the bound lease"
                )
            validator(
                target=target,
                host_key_policy=host_key_policy,
                known_hosts_file=known_hosts_file,
                allow_insecure_host_key=allow_insecure_host_key,
            )
        try:
            return self.run_channel(
                remote_cmd,
                timeout=timeout,
                tty=tty,
                stdout_limit_bytes=stdout_limit_bytes,
                stderr_limit_bytes=stderr_limit_bytes,
                debug_dumper=debug_dumper,
                debug_label=debug_label,
                replay_safe=replay_safe,
            )
        except Exception as exc:
            completed = getattr(exc, "completed", None)
            if completed is not None:
                return completed
            raise

    def download_file(
        self,
        remote_path: str,
        local_path: str,
        *,
        timeout: float,
    ) -> ChannelResultT:
        """Download one file through the bound master without replay."""

        with self._lock:
            master = self._ensure_master()
        downloader = getattr(self._transport, "download_file", None)
        if downloader is None:
            raise RuntimeError("SSH transport does not support file download")
        result = downloader(
            master,
            remote_path,
            local_path,
            timeout=timeout,
        )
        lost_master = self._transport.channel_lost_master(master, result)
        with self._lock:
            self._record("file_transfers", "ssh_file_transfers")
            if lost_master and self._master is master:
                self._invalidate(
                    reason="master-lost-during-file-transfer",
                    master_failure=True,
                )
        return result

    def upload_file(
        self,
        local_path: str,
        remote_path: str,
        *,
        timeout: float,
    ) -> ChannelResultT:
        """Upload one file through the bound master without replay."""

        with self._lock:
            master = self._ensure_master()
        uploader = getattr(self._transport, "upload_file", None)
        if uploader is None:
            raise RuntimeError("SSH transport does not support file upload")
        result = uploader(
            master,
            local_path,
            remote_path,
            timeout=timeout,
        )
        lost_master = self._transport.channel_lost_master(master, result)
        with self._lock:
            self._record("file_transfers", "ssh_file_transfers")
            if lost_master and self._master is master:
                self._invalidate(
                    reason="master-lost-during-file-transfer",
                    master_failure=True,
                )
        return result

    def _get_cached(self, key: str, loader: Callable[[], T]) -> T:
        with self._lock:
            if key in self._cache:
                self._record("cache_hits", "ssh_cache_hits")
                return self._cache[key]  # type: ignore[return-value]
            self._ensure_master()
            value = loader()
            self._cache[key] = value
            self._coordinator.cache_lane_state("ssh")
            self._cache_epoch = self._coordinator.lane_state("ssh").epoch
            self._record("cache_misses", "ssh_cache_misses")
            return value

    def get_dbus_environment(self, loader: Callable[[], T]) -> T:
        return self._get_cached("dbus-environment", loader)

    def get_alarm_endpoint(self, loader: Callable[[], T]) -> T:
        return self._get_cached("alarm-endpoint", loader)

    def invalidate_alarm_endpoint(self) -> bool:
        """Drop cached alarm metadata while preserving the live SSH master."""

        with self._lock:
            self._sync_epoch_state()
            return self._cache.pop("alarm-endpoint", None) is not None

    def cache_capability(self, name: str, value: T) -> T:
        if not name.strip():
            raise ValueError("capability name must not be empty")
        with self._lock:
            self._ensure_master()
            self._cache[f"capability:{name}"] = value
            self._coordinator.cache_lane_state("ssh")
            self._cache_epoch = self._coordinator.lane_state("ssh").epoch
            return value

    def close(self, *, reason: str = "lease-closed") -> None:
        with self._lock:
            self._invalidate(reason=reason, master_failure=False)

    def prune_dead_connection(self) -> int:
        """Drop a dead master so the next bounded request reconnects once."""

        with self._lock:
            self._sync_epoch_state()
            master = self._master
            if master is None:
                return 0
            try:
                healthy = bool(self._transport.check_master(master))
            except Exception:
                healthy = False
            if healthy:
                return 0
            self._invalidate(reason="dead-master-maintenance", master_failure=True)
            return 1

    def status(self) -> dict[str, object]:
        with self._lock:
            self._sync_epoch_state()
            return {
                "lease_name": self.lease_name,
                "connected": self._master is not None,
                "ssh_epoch": self._coordinator.lane_state("ssh").epoch,
                "cached_state": list(sorted(self._cache)),
                "metrics": dict(self._metrics),
            }


class TelnetLaneTransport(Protocol[SessionT, TelnetResultT]):
    """Transport boundary used by one domain-owned persistent Telnet session."""

    def open_session(
        self,
        *,
        target: TargetSpec,
        credentials: ResolvedTelnetCredentials,
    ) -> SessionT: ...

    def run_command(
        self,
        session: SessionT,
        command: str,
        **kwargs: object,
    ) -> TelnetResultT: ...

    def command_invalidates_session(
        self,
        session: SessionT,
        result: TelnetResultT,
    ) -> bool: ...

    def close_session(self, session: SessionT) -> None: ...


class TelnetLane(Generic[SessionT, TelnetResultT]):
    """Own and serialize one Telnet shell for a domain lease and lane epoch."""

    _METRIC_NAMES = (
        "login_attempts",
        "logins",
        "command_requests",
        "reconnects",
        "session_failures",
        "replay_safe_retries",
    )

    def __init__(
        self,
        *,
        lease_name: str,
        coordinator: TargetCoordinator,
        credentials: ResolvedTelnetCredentials,
        transport: TelnetLaneTransport[SessionT, TelnetResultT],
        metric_recorder: Callable[[str], None],
    ) -> None:
        if not lease_name.strip():
            raise ValueError("Telnet lease_name must not be empty")
        self.lease_name = lease_name
        self._coordinator = coordinator
        self._credentials = credentials
        self._transport = transport
        self._metric_recorder = metric_recorder
        self._session: SessionT | None = None
        self._session_epoch: int | None = None
        self._session_opens = 0
        self._metrics = {name: 0 for name in self._METRIC_NAMES}
        self._lock = threading.RLock()

    @property
    def transport(self) -> TelnetLaneTransport[SessionT, TelnetResultT]:
        return self._transport

    @property
    def telnet_epoch(self) -> int:
        with self._lock:
            return self._coordinator.lane_state("telnet").epoch

    @property
    def connected(self) -> bool:
        with self._lock:
            self._sync_epoch_state()
            return self._session is not None

    @property
    def session(self) -> SessionT | None:
        with self._lock:
            self._sync_epoch_state()
            return self._session

    def _record(self, local_name: str, task_name: str) -> None:
        self._metrics[local_name] += 1
        self._metric_recorder(task_name)

    def _close_local_session(self) -> None:
        session = self._session
        self._session = None
        self._session_epoch = None
        if session is not None:
            try:
                self._transport.close_session(session)
            except Exception:
                pass

    def _invalidate(self, *, reason: str, session_failure: bool) -> None:
        self._close_local_session()
        self._coordinator.invalidate_lane("telnet", reason=reason)
        if session_failure:
            self._record("session_failures", "telnet_session_failures")

    def _sync_epoch_state(self) -> None:
        state = self._coordinator.lane_state("telnet")
        if self._session is not None and (
            self._session_epoch != state.epoch or state.status.value != "ready"
        ):
            self._close_local_session()

    def _open_session(self) -> SessionT:
        reconnecting = self._session_opens > 0
        self._record("login_attempts", "telnet_login_attempts")
        try:
            session = self._transport.open_session(
                target=self._coordinator.target,
                credentials=self._credentials,
            )
        except Exception:
            self._coordinator.invalidate_lane(
                "telnet",
                reason="login-failed",
            )
            raise
        self._session = session
        self._coordinator.connect_lane("telnet")
        self._session_epoch = self._coordinator.lane_state("telnet").epoch
        self._session_opens += 1
        self._record("logins", "telnet_logins")
        if reconnecting:
            self._record("reconnects", "telnet_reconnects")
        return session

    def _ensure_session(self) -> SessionT:
        self._sync_epoch_state()
        if self._session is not None:
            return self._session
        return self._open_session()

    def ensure_connected(self) -> SessionT:
        with self._lock:
            return self._ensure_session()

    def run_command(
        self,
        command: str,
        **kwargs: object,
    ) -> TelnetResultT:
        """Run one framed command and optionally replay one read-only failure."""

        replay_safe = kwargs.pop("replay_safe", False)
        if not isinstance(replay_safe, bool):
            raise TypeError("replay_safe must be a boolean")
        attempts = 2 if replay_safe else 1
        started = time.monotonic()
        timeout_value = kwargs.get("timeout")
        timeout = (
            float(timeout_value)
            if isinstance(timeout_value, (int, float))
            and not isinstance(timeout_value, bool)
            else None
        )
        result: TelnetResultT
        for attempt in range(attempts):
            attempt_kwargs = dict(kwargs)
            if attempt > 0 and timeout is not None:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    return result
                attempt_kwargs["timeout"] = max(1.0, remaining)
            with self._lock:
                session = self._ensure_session()
                try:
                    result = self._transport.run_command(
                        session,
                        command,
                        **attempt_kwargs,
                    )
                except BaseException:
                    self._record("command_requests", "telnet_commands")
                    self._invalidate(
                        reason="command-exception",
                        session_failure=True,
                    )
                    raise
                self._record("command_requests", "telnet_commands")
                invalidated = self._transport.command_invalidates_session(
                    session,
                    result,
                )
                if invalidated:
                    self._invalidate(
                        reason="command-incomplete",
                        session_failure=True,
                    )
                if not invalidated or attempt + 1 >= attempts:
                    return result
                self._record(
                    "replay_safe_retries",
                    "telnet_replay_safe_retries",
                )
        return result

    def close(self) -> None:
        with self._lock:
            self._close_local_session()

    def prune_dead_connection(self) -> int:
        """Use an optional transport probe and rebuild lazily after failure."""

        with self._lock:
            self._sync_epoch_state()
            session = self._session
            checker = getattr(self._transport, "check_session", None)
            if session is None or checker is None:
                return 0
            try:
                healthy = bool(checker(session))
            except Exception:
                healthy = False
            if healthy:
                return 0
            self._invalidate(reason="dead-session-maintenance", session_failure=True)
            return 1

    def status(self) -> dict[str, object]:
        with self._lock:
            self._sync_epoch_state()
            return {
                "lease_name": self.lease_name,
                "connected": self._session is not None,
                "telnet_epoch": self._coordinator.lane_state("telnet").epoch,
                "metrics": dict(self._metrics),
            }


class RedfishLaneTransport(Protocol[RedfishSessionT, RedfishResultT]):
    """Transport boundary for one domain-owned Redfish Session."""

    def open_session(
        self,
        *,
        target: TargetSpec,
        credentials: ResolvedRedfishCredentials,
    ) -> RedfishSessionT: ...

    def request(
        self,
        session: RedfishSessionT,
        operation: str,
        **kwargs: object,
    ) -> RedfishResultT: ...

    def is_authentication_failure(self, error: BaseException) -> bool: ...

    def close_session(self, session: RedfishSessionT) -> None: ...


class RedfishLane(Generic[RedfishSessionT, RedfishResultT]):
    """Reuse one Redfish Session inside one domain lease and target epoch."""

    _METRIC_NAMES = (
        "session_attempts",
        "sessions",
        "requests",
        "reconnects",
        "authentication_failures",
    )

    def __init__(
        self,
        *,
        lease_name: str,
        coordinator: TargetCoordinator,
        credentials: ResolvedRedfishCredentials,
        transport: RedfishLaneTransport[RedfishSessionT, RedfishResultT],
        metric_recorder: Callable[[str], None],
    ) -> None:
        if not lease_name.strip():
            raise ValueError("Redfish lease_name must not be empty")
        if credentials.port != coordinator.target.redfish_port:
            raise ValueError("Redfish credentials port must match TargetSpec")
        self.lease_name = lease_name
        self._coordinator = coordinator
        self._credentials = credentials
        self._transport = transport
        self._metric_recorder = metric_recorder
        self._session: RedfishSessionT | None = None
        self._session_epoch: int | None = None
        self._session_opens = 0
        self._metrics = {name: 0 for name in self._METRIC_NAMES}
        self._lock = threading.RLock()

    @property
    def transport(self) -> RedfishLaneTransport[RedfishSessionT, RedfishResultT]:
        return self._transport

    @property
    def redfish_epoch(self) -> int:
        with self._lock:
            return self._coordinator.lane_state("redfish").epoch

    @property
    def session(self) -> RedfishSessionT | None:
        with self._lock:
            self._sync_epoch_state()
            return self._session

    def _record(self, local_name: str, task_name: str) -> None:
        self._metrics[local_name] += 1
        self._metric_recorder(task_name)

    def _close_local_session(self) -> None:
        session = self._session
        self._session = None
        self._session_epoch = None
        if session is not None:
            try:
                self._transport.close_session(session)
            except Exception:
                pass

    def _invalidate(self, *, reason: str, authentication_failure: bool) -> None:
        self._close_local_session()
        self._coordinator.invalidate_lane("redfish", reason=reason)
        if authentication_failure:
            self._record(
                "authentication_failures",
                "redfish_authentication_failures",
            )

    def _sync_epoch_state(self) -> None:
        state = self._coordinator.lane_state("redfish")
        if self._session is not None and (
            self._session_epoch != state.epoch or state.status.value != "ready"
        ):
            self._close_local_session()

    def _open_session(self) -> RedfishSessionT:
        reconnecting = self._session_opens > 0
        self._record("session_attempts", "redfish_session_attempts")
        try:
            session = self._transport.open_session(
                target=self._coordinator.target,
                credentials=self._credentials,
            )
        except Exception:
            self._coordinator.invalidate_lane("redfish", reason="authentication-failed")
            self._record(
                "authentication_failures",
                "redfish_authentication_failures",
            )
            raise
        self._session = session
        self._coordinator.connect_lane("redfish")
        self._session_epoch = self._coordinator.lane_state("redfish").epoch
        self._session_opens += 1
        self._record("sessions", "redfish_sessions")
        if reconnecting:
            self._record("reconnects", "redfish_reconnects")
        return session

    def _ensure_session(self) -> RedfishSessionT:
        self._sync_epoch_state()
        if self._session is not None:
            return self._session
        return self._open_session()

    def request(
        self,
        operation: str,
        *,
        replay_safe: bool,
        **kwargs: object,
    ) -> RedfishResultT:
        """Run one domain request; only explicitly replay-safe auth failures retry."""

        if not operation.strip():
            raise ValueError("Redfish operation must not be empty")
        attempts = 2 if replay_safe else 1
        for attempt in range(attempts):
            with self._lock:
                session = self._ensure_session()
            try:
                result = self._transport.request(session, operation, **kwargs)
            except BaseException as exc:
                with self._lock:
                    self._record("requests", "redfish_requests")
                    is_auth_failure = bool(
                        self._transport.is_authentication_failure(exc)
                    )
                    if is_auth_failure and self._session is session:
                        self._invalidate(
                            reason="authentication-failed",
                            authentication_failure=True,
                        )
                if is_auth_failure and replay_safe and attempt + 1 < attempts:
                    continue
                raise
            with self._lock:
                self._record("requests", "redfish_requests")
                invalidator = getattr(
                    self._transport,
                    "response_invalidates_session",
                    None,
                )
                if invalidator is not None and bool(invalidator(session, result)):
                    self._invalidate(
                        reason="response-invalidated-session",
                        authentication_failure=False,
                    )
            return result
        raise AssertionError("Redfish request loop exited without a result")

    def close(self, *, reason: str = "lease-closed") -> None:
        with self._lock:
            if self._session is None:
                return
            self._invalidate(
                reason=reason,
                authentication_failure=False,
            )

    def prune_dead_connection(self) -> int:
        with self._lock:
            self._sync_epoch_state()
            session = self._session
            checker = getattr(self._transport, "check_session", None)
            if session is None or checker is None:
                return 0
            try:
                healthy = bool(checker(session))
            except Exception:
                healthy = False
            if healthy:
                return 0
            self._invalidate(
                reason="dead-session-maintenance",
                authentication_failure=False,
            )
            return 1

    def status(self) -> dict[str, object]:
        with self._lock:
            self._sync_epoch_state()
            return {
                "lease_name": self.lease_name,
                "connected": self._session is not None,
                "redfish_epoch": self._coordinator.lane_state("redfish").epoch,
                "metrics": dict(self._metrics),
            }


@dataclass
class _RequestRecord(Generic[T]):
    fingerprint: str
    state: RequestState = RequestState.RUNNING
    result: RuntimeReadResult[T] | None = None


@dataclass(frozen=True)
class MutationContext:
    """Context supplied to one domain-owned mutation implementation."""

    task_id: str
    request: MutationRequest
    credentials: object
    journal: MutationJournal

    @property
    def target(self) -> TargetSpec:
        return self.request.target

    def record_backup(self, reference: str) -> None:
        self.journal.record_backup(reference)

    def record_artifact(self, reference: str) -> None:
        self.journal.record_artifact(reference)

    def record_target_identity(self, identity: TargetIdentity) -> None:
        self.journal.record_target_identity(identity)

    def mark_effects_started(self) -> None:
        self.journal.mark_effects_started()


@dataclass(frozen=True)
class MutationRecoveryInspectionContext:
    """Read-only context used before any restart recovery decision."""

    task_id: str
    request: MutationRequest
    credentials: object
    journal: MutationJournal

    @property
    def target(self) -> TargetSpec:
        return self.request.target


@dataclass(frozen=True)
class TargetIdentityObservation:
    change: str
    target_epoch: int


class FreshVerificationContext:
    """Admit only new-epoch reads while the mutation lease remains exclusive."""

    def __init__(
        self,
        *,
        task_run: "OpenUBMCTaskRun",
        coordinator: TargetCoordinator,
        target: TargetSpec,
        mutation_token: object,
        epoch_after: int,
        verification_attempt: int,
    ) -> None:
        if verification_attempt < 1:
            raise ValueError("verification_attempt must be positive")
        self.task_run = task_run
        self.coordinator = coordinator
        self.target = target
        self.mutation_token = mutation_token
        self.epoch_after = epoch_after
        self.verification_attempt = verification_attempt

    def run_read(
        self,
        request: RemoteReadRequest,
        collect: Callable[[ReadContext], T],
    ) -> RuntimeReadResult[T]:
        if request.target.fingerprint != self.target.fingerprint:
            raise ValueError("fresh verification must use the mutated target")
        with self.coordinator.lease_coordinator.verification_read(
            self.mutation_token
        ):
            return self.task_run._run_read_admitted(
                request,
                collect,
                coordinator=self.coordinator,
                minimum_target_epoch=self.epoch_after,
            )


class OpenUBMCTaskRun:
    """Own target coordinators, credential cache, request dedupe, and metrics."""

    def __init__(
        self,
        *,
        task_id: str,
        credential_resolver: CredentialResolver | None = None,
        evidence_ledger: EvidenceLedger | None = None,
        mutation_journal_store: MutationJournalStore | None = None,
        max_request_records: int = 256,
    ) -> None:
        if not task_id.strip():
            raise ValueError("task_id must not be empty")
        if max_request_records < 1:
            raise ValueError("max_request_records must be positive")
        self.task_id = task_id
        self.max_request_records = int(max_request_records)
        self._credential_resolver = credential_resolver
        self.evidence_ledger = evidence_ledger or EvidenceLedger()
        self._mutation_journal_store = mutation_journal_store
        self._coordinators: dict[str, TargetCoordinator] = {}
        self._requests: OrderedDict[str, _RequestRecord[object]] = OrderedDict()
        loaded_journals = (
            mutation_journal_store.load_for_task(task_id)
            if mutation_journal_store is not None
            else []
        )
        self._mutation_journals: dict[str, MutationJournal] = {
            journal.operation_id: journal for journal in loaded_journals
        }
        self._orchestration: TaskOrchestrationContext | None = None
        self._metrics = {
            "credential_resolutions": 0,
            "fresh_requests": 0,
            "remote_actions": 0,
            "retry_deduplications": 0,
        }
        self._request_evictions = 0
        self._peak_request_records = 0
        self._metrics_lock = threading.Lock()
        self._lock = threading.RLock()

    def bind_task_intent(self, intent: TaskIntent) -> TaskOrchestrationContext:
        """Bind original intent once and return the task-owned typed context."""

        if not isinstance(intent, TaskIntent):
            raise TypeError("intent must be a TaskIntent")
        with self._lock:
            if self._orchestration is None:
                self._orchestration = TaskOrchestrationContext(
                    task_id=self.task_id,
                    intent=intent,
                )
            elif self._orchestration.intent.fingerprint != intent.fingerprint:
                raise ValueError(
                    "task intent is already bound and cannot be replaced or re-parsed"
                )
            return self._orchestration

    def _ssh_credential_resolver(self) -> CredentialResolver:
        if self._credential_resolver is None:
            raise RuntimeError("SSH credential resolver is not configured")
        return self._credential_resolver

    def _record_metric(self, name: str) -> None:
        with self._metrics_lock:
            self._metrics[name] = self._metrics.get(name, 0) + 1

    def _metrics_snapshot(self) -> dict[str, int]:
        with self._metrics_lock:
            return dict(self._metrics)

    def _evict_request_records_locked(self, *, reserve: int = 0) -> None:
        while len(self._requests) + reserve > self.max_request_records:
            victim = next(
                (
                    request_id
                    for request_id, record in self._requests.items()
                    if record.state is not RequestState.RUNNING
                ),
                None,
            )
            if victim is None:
                break
            self._requests.pop(victim, None)
            self._request_evictions += 1

    def _coordinator(self, target: TargetSpec) -> TargetCoordinator:
        coordinator = self._coordinators.get(target.fingerprint)
        if coordinator is None:
            coordinator = TargetCoordinator(target=target)
            self._coordinators[target.fingerprint] = coordinator
        return coordinator

    def ssh_lane(
        self,
        *,
        target: TargetSpec,
        credential_selector: CredentialSelector,
        lease_name: str,
        transport: SshLaneTransport[MasterT, ChannelResultT],
    ) -> SshLane[MasterT, ChannelResultT]:
        """Return the task-owned SSH lane for one domain lease."""

        resolution = self._ssh_credential_resolver().resolve_with_status(
            task_id=self.task_id,
            target=target,
            selector=credential_selector,
        )
        if not resolution.cache_hit:
            self._record_metric("credential_resolutions")
        with self._lock:
            coordinator = self._coordinator(target)
            existing = coordinator.ssh_leases.get(lease_name)
            if existing is not None:
                if existing.transport is not transport:
                    raise ValueError(
                        "SSH lease is already bound to a different transport"
                    )
                return existing  # type: ignore[return-value]
            lane: SshLane[MasterT, ChannelResultT] = SshLane(
                lease_name=lease_name,
                coordinator=coordinator,
                credentials=resolution.credentials,
                transport=transport,
                metric_recorder=self._record_metric,
            )
            coordinator.ssh_leases[lease_name] = lane  # type: ignore[assignment]
            return lane

    def telnet_lane(
        self,
        *,
        target: TargetSpec,
        credentials: ResolvedTelnetCredentials,
        lease_name: str,
        transport: TelnetLaneTransport[SessionT, TelnetResultT],
    ) -> TelnetLane[SessionT, TelnetResultT]:
        """Return one domain-owned Telnet session for the target and task."""

        if credentials.port != target.telnet_port:
            raise ValueError("Telnet credentials port must match TargetSpec")
        with self._lock:
            coordinator = self._coordinator(target)
            existing = coordinator.telnet_leases.get(lease_name)
            if existing is not None:
                if existing.transport is not transport:
                    raise ValueError(
                        "Telnet lease is already bound to a different transport"
                    )
                return existing  # type: ignore[return-value]
            lane: TelnetLane[SessionT, TelnetResultT] = TelnetLane(
                lease_name=lease_name,
                coordinator=coordinator,
                credentials=credentials,
                transport=transport,
                metric_recorder=self._record_metric,
            )
            coordinator.telnet_leases[lease_name] = lane  # type: ignore[assignment]
            return lane

    def redfish_lane(
        self,
        *,
        target: TargetSpec,
        credential_selector: CredentialSelector,
        lease_name: str,
        transport: RedfishLaneTransport[RedfishSessionT, RedfishResultT],
    ) -> RedfishLane[RedfishSessionT, RedfishResultT]:
        """Return one domain-owned Redfish Session for the target and task."""

        resolution = self._ssh_credential_resolver().resolve_with_status(
            task_id=self.task_id,
            target=target,
            selector=credential_selector,
        )
        if not isinstance(resolution.credentials, ResolvedRedfishCredentials):
            raise TypeError("Redfish selector did not resolve Redfish credentials")
        if not resolution.cache_hit:
            self._record_metric("credential_resolutions")
        with self._lock:
            coordinator = self._coordinator(target)
            existing = coordinator.redfish_leases.get(lease_name)
            if existing is not None:
                if existing.transport is not transport:
                    raise ValueError(
                        "Redfish lease is already bound to a different transport"
                    )
                return existing  # type: ignore[return-value]
            lane: RedfishLane[RedfishSessionT, RedfishResultT] = RedfishLane(
                lease_name=lease_name,
                coordinator=coordinator,
                credentials=resolution.credentials,
                transport=transport,
                metric_recorder=self._record_metric,
            )
            coordinator.redfish_leases[lease_name] = lane  # type: ignore[assignment]
            return lane

    def observe_target_identity(
        self,
        target: TargetSpec,
        identity: TargetIdentity,
    ) -> TargetIdentityObservation:
        """Record live identity and invalidate all lanes when the target changed."""

        with self._lock:
            coordinator = self._coordinator(target)
            previous = coordinator.identity
            if previous is None:
                coordinator.identity = identity
                return TargetIdentityObservation(
                    change="initial",
                    target_epoch=coordinator.epochs_snapshot().target_epoch,
                )
            change = previous.change_kind(identity)
        if change in {
            TargetIdentityChange.REBOOT,
            TargetIdentityChange.FIRMWARE_CHANGE,
            TargetIdentityChange.REPLACEMENT,
        }:
            target_epoch = self._advance_target_epoch(
                coordinator,
                reason=f"identity-{change.value}",
            )
            with self._lock:
                coordinator.identity = identity
            return TargetIdentityObservation(
                change=change.value,
                target_epoch=target_epoch,
            )
        with self._lock:
            coordinator.identity = identity
            return TargetIdentityObservation(
                change=change.value,
                target_epoch=coordinator.epochs_snapshot().target_epoch,
            )

    def advance_target_epoch(self, target: TargetSpec, *, reason: str) -> int:
        """Explicitly invalidate every target lane after reboot/upgrade/mutation."""

        with self._lock:
            coordinator = self._coordinator(target)
        return self._advance_target_epoch(coordinator, reason=reason)

    def ensure_target_epoch(
        self,
        target: TargetSpec,
        minimum: int,
        *,
        reason: str,
    ) -> int:
        """Synchronize a domain-local coordinator to a shared task epoch."""

        if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 0:
            raise ValueError("minimum target epoch must be a non-negative integer")
        with self._lock:
            coordinator = self._coordinator(target)
            current = coordinator.epochs_snapshot().target_epoch
        if current >= minimum:
            return current
        return self._restore_target_epoch(
            coordinator,
            minimum=minimum,
            reason=reason,
        )

    def run_read(
        self,
        request: RemoteReadRequest,
        collect: Callable[[ReadContext], T],
        *,
        operation_context: object | None = None,
    ) -> RuntimeReadResult[T]:
        with self._lock:
            coordinator = self._coordinator(request.target)
        with coordinator.lease_coordinator.read(operation_context):
            return self._run_read_admitted(
                request,
                collect,
                coordinator=coordinator,
            )

    def _run_read_admitted(
        self,
        request: RemoteReadRequest,
        collect: Callable[[ReadContext], T],
        *,
        coordinator: TargetCoordinator,
        minimum_target_epoch: int | None = None,
    ) -> RuntimeReadResult[T]:
        with self._lock:
            current_epoch = coordinator.epochs_snapshot().target_epoch
            if minimum_target_epoch is not None and current_epoch < minimum_target_epoch:
                raise StaleEvidenceRejected(
                    "fresh verification target epoch has not advanced"
                )
            existing = self._requests.get(request.request_id)
            if existing is not None:
                self._requests.move_to_end(request.request_id)
                if existing.fingerprint != request.fingerprint:
                    raise RequestIdConflict(
                        "request_id is already bound to a different remote action"
                    )
                if existing.state is RequestState.RUNNING:
                    raise RequestInProgress(
                        "request is already executing; duplicate remote action suppressed"
                    )
                if existing.state is RequestState.FAILED:
                    raise DuplicateRequestSuppressed(
                        "previous request outcome is uncertain; remote action was not replayed"
                    )
                assert existing.result is not None
                if existing.result.target_epoch != current_epoch:
                    raise StaleEvidenceRejected(
                        "request result belongs to an older target epoch and cannot "
                        "satisfy fresh verification"
                    )
                self._record_metric("retry_deduplications")
                return replace(existing.result, deduplicated=True)  # type: ignore[arg-type]

            self._evict_request_records_locked(reserve=1)
            self._requests[request.request_id] = _RequestRecord(
                fingerprint=request.fingerprint
            )
            self._peak_request_records = max(
                self._peak_request_records, len(self._requests)
            )

        try:
            resolution = self._ssh_credential_resolver().resolve_with_status(
                task_id=self.task_id,
                target=request.target,
                selector=request.credential_selector,
            )
            with self._lock:
                if not resolution.cache_hit:
                    self._record_metric("credential_resolutions")
                self._record_metric("fresh_requests")
                self._record_metric("remote_actions")
                context_epochs = coordinator.epochs
            value = collect(
                ReadContext(
                    task_id=self.task_id,
                    request_id=request.request_id,
                    target=request.target,
                    credentials=resolution.credentials,
                    epochs=context_epochs,
                )
            )
            with self._lock:
                result_epochs = coordinator.epochs
            result = RuntimeReadResult(
                api_version=RUNTIME_API_VERSION,
                request_id=request.request_id,
                collector_name=request.collector_name,
                target_fingerprint=request.target.fingerprint,
                target_epoch=result_epochs.target_epoch,
                lane_epochs={
                    lane.value: getattr(result_epochs, lane.value).epoch
                    for lane in LANES
                },
                value=value,
            )
        except BaseException as exc:
            with self._lock:
                record = self._requests[request.request_id]
                record.state = RequestState.FAILED
                self._requests.move_to_end(request.request_id)
                self._evict_request_records_locked()
            raise

        with self._lock:
            record = self._requests[request.request_id]
            record.state = RequestState.COMPLETED
            record.result = result  # type: ignore[assignment]
            self._requests.move_to_end(request.request_id)
            self._evict_request_records_locked()
        return result

    @staticmethod
    def _record_mutation_artifacts(
        journal: MutationJournal,
        mutation_value: object,
        *,
        mutation_phase: bool = True,
    ) -> None:
        if not isinstance(mutation_value, Mapping):
            return
        backup = mutation_value.get("backup_reference", mutation_value.get("backup"))
        artifact = mutation_value.get(
            "artifact_reference",
            mutation_value.get("artifact"),
        )
        if isinstance(backup, str) and backup:
            journal.record_backup(backup)
        if isinstance(artifact, str) and artifact:
            journal.record_artifact(artifact)
        before_checksum = (
            mutation_value.get(
                "before_checksum",
                mutation_value.get("remote_before_sha256"),
            )
            if mutation_phase
            else None
        )
        expected_checksum = (
            mutation_value.get(
                "expected_checksum",
                mutation_value.get(
                    "remote_after_sha256",
                    mutation_value.get("local_sha256"),
                ),
            )
            if mutation_phase
            else None
        )
        expected_missing = (
            mutation_value.get("expected_missing")
            if mutation_phase
            else None
        )
        if expected_missing is None and mutation_phase:
            expected_missing = mutation_value.get("remote_removed")
        expected_metadata = (
            mutation_value.get(
                "expected_metadata",
                mutation_value.get("remote_after_metadata"),
            )
            if mutation_phase
            else None
        )
        observed_checksum = mutation_value.get(
            "observed_checksum",
            mutation_value.get("remote_after_sha256"),
        )
        mount_mode = mutation_value.get(
            "root_mount_mode",
            mutation_value.get("root_mount_before"),
        )
        if isinstance(mount_mode, (list, tuple)):
            mount_mode = ",".join(str(item) for item in mount_mode)
        restart_state = mutation_value.get("restart_state")
        if restart_state is None and "restart_scope" in mutation_value:
            restart_state = f"completed:{mutation_value.get('restart_scope')}"
        journal.record_execution_evidence(
            before_checksum=(
                str(before_checksum) if before_checksum is not None else None
            ),
            expected_checksum=(
                str(expected_checksum) if expected_checksum is not None else None
            ),
            expected_missing=(
                bool(expected_missing)
                if expected_missing is not None
                else None
            ),
            expected_metadata=(
                expected_metadata
                if isinstance(expected_metadata, Mapping)
                else None
            ),
            observed_checksum=(
                str(observed_checksum) if observed_checksum is not None else None
            ),
            root_mount_mode=(str(mount_mode) if mount_mode is not None else None),
            root_mount_restored=(
                bool(mutation_value["root_mount_restored"])
                if mutation_value.get("root_mount_restored") is not None
                else None
            ),
            restart_state=(
                str(restart_state) if restart_state is not None else None
            ),
        )

    def _advance_target_epoch(
        self,
        coordinator: TargetCoordinator,
        *,
        reason: str,
    ) -> int:
        with self._lock:
            lanes = {
                id(lane): lane
                for lane in (
                    *coordinator.ssh_leases.values(),
                    *coordinator.telnet_leases.values(),
                    *coordinator.redfish_leases.values(),
                )
            }
        for lane in lanes.values():
            if isinstance(lane, SshLane):
                lane.close(reason=f"target-{reason}")
            else:
                lane.close()
        epochs = coordinator.advance_target_epoch(reason=reason)
        self._record_metric("target_epoch_advances")
        return epochs.target_epoch

    def _restore_target_epoch(
        self,
        coordinator: TargetCoordinator,
        *,
        minimum: int,
        reason: str,
    ) -> int:
        with self._lock:
            lanes = {
                id(lane): lane
                for lane in (
                    *coordinator.ssh_leases.values(),
                    *coordinator.telnet_leases.values(),
                    *coordinator.redfish_leases.values(),
                )
            }
        for lane in lanes.values():
            if isinstance(lane, SshLane):
                lane.close(reason=f"target-{reason}")
            else:
                lane.close()
        return coordinator.ensure_target_epoch(minimum, reason=reason).target_epoch

    def run_mutation(
        self,
        request: MutationRequest,
        *,
        authorization: MutationAuthorization,
        apply: Callable[[MutationContext], MutationResultT],
        verify: Callable[[FreshVerificationContext], VerificationResultT],
        operation_context: object | None = None,
    ) -> MutationTransactionResult[MutationResultT, VerificationResultT]:
        """Run one authorized target mutation and mandatory fresh verification."""

        try:
            authorization.require(request.action)
        except BaseException as exc:
            _annotate_mutation_exception(exc, outcome="not_started")
            raise
        with self._lock:
            existing = self._mutation_journals.get(request.operation_id)
            if existing is not None:
                if existing.operation_fingerprint != request.fingerprint:
                    raise MutationOperationConflict(
                        "operation_id is already bound to a different mutation"
                    )
                if existing.terminal:
                    self._record_metric("mutation_idempotent_replays")
                    completed_epoch = (
                        existing.rollback_epoch
                        or existing.epoch_after
                        or existing.epoch_before
                    )
                    return MutationTransactionResult(
                        operation_id=request.operation_id,
                        action=request.action,
                        target_fingerprint=request.target.fingerprint,
                        epoch_before=existing.epoch_before,
                        epoch_after=completed_epoch,
                        mutation=None,
                        verification=None,
                        journal=existing,
                        idempotent_replay=True,
                    )
                if existing.stage != "replan_required":
                    raise UnfinishedMutationExists(existing)
            unfinished = next(
                (
                    journal
                    for journal in self._mutation_journals.values()
                    if journal.target_fingerprint == request.target.fingerprint
                    and journal.blocks_target
                ),
                None,
            )
            if unfinished is not None:
                raise UnfinishedMutationExists(unfinished)
            if self._mutation_journal_store is not None:
                durable_unfinished = (
                    self._mutation_journal_store.find_unfinished_target(
                        request.target.fingerprint,
                        exclude_task_id=self.task_id,
                        exclude_operation_id=request.operation_id,
                    )
                )
                if durable_unfinished is not None:
                    raise UnfinishedMutationExists(durable_unfinished)
            coordinator = self._coordinator(request.target)

        with coordinator.lease_coordinator.mutation(operation_context) as token:
            try:
                resolution = self._ssh_credential_resolver().resolve_with_status(
                    task_id=self.task_id,
                    target=request.target,
                    selector=request.credential_selector,
                )
            except BaseException as exc:
                _annotate_mutation_exception(exc, outcome="not_started")
                raise
            if not resolution.cache_hit:
                self._record_metric("credential_resolutions")
            epoch_before = coordinator.epochs_snapshot().target_epoch
            with self._lock:
                journal = self._mutation_journals.get(request.operation_id)
                if journal is not None:
                    if journal.operation_fingerprint != request.fingerprint:
                        raise MutationOperationConflict(
                            "operation_id is already bound to a different mutation"
                        )
                    if journal.terminal:
                        self._record_metric("mutation_idempotent_replays")
                        completed_epoch = (
                            journal.rollback_epoch
                            or journal.epoch_after
                            or journal.epoch_before
                        )
                        return MutationTransactionResult(
                            operation_id=request.operation_id,
                            action=request.action,
                            target_fingerprint=request.target.fingerprint,
                            epoch_before=journal.epoch_before,
                            epoch_after=completed_epoch,
                            mutation=None,
                            verification=None,
                            journal=journal,
                            idempotent_replay=True,
                        )
                    if journal.stage != "replan_required":
                        raise UnfinishedMutationExists(journal)
                    journal.reset_for_replan(epoch_before)
                    self._record_metric("mutation_replans")
                else:
                    journal = MutationJournal(
                        task_id=self.task_id,
                        operation_id=request.operation_id,
                        operation_fingerprint=request.fingerprint,
                        action=request.action,
                        original_intent=authorization.original_intent,
                        target_fingerprint=request.target.fingerprint,
                        target_identity=coordinator.identity,
                        epoch_before=epoch_before,
                    )
                    if self._mutation_journal_store is not None:
                        self._mutation_journal_store.create(journal)
                    self._mutation_journals[request.operation_id] = journal
            self._record_metric("mutation_operations")

            try:
                journal.transition("applying", last_known_state="mutation-started")
                mutation_value = apply(
                    MutationContext(
                        task_id=self.task_id,
                        request=request,
                        credentials=resolution.credentials,
                        journal=journal,
                    )
                )
                journal.mark_effects_started()
                self._record_mutation_artifacts(journal, mutation_value)
                journal.transition("applied", last_known_state="mutation-completed")
            except BaseException as exc:
                if isinstance(exc, MutationEffectsRejected):
                    journal.mark_effects_rejected()
                    journal.transition(
                        "replan_required",
                        verification_state="not_started",
                        last_known_state="mutation-explicitly-rejected",
                        recovery_decision="replan",
                    )
                    outcome = "not_started"
                elif journal.effects_started:
                    journal.transition(
                        "mutation_failed",
                        verification_state="not_started",
                        last_known_state="mutation-outcome-uncertain",
                    )
                    outcome = "unknown"
                else:
                    journal.transition(
                        "replan_required",
                        verification_state="not_started",
                        last_known_state="mutation-effects-not-started",
                        recovery_decision="replan",
                    )
                    outcome = "not_started"
                _annotate_mutation_exception(
                    exc,
                    outcome=outcome,
                    journal=journal,
                )
                raise

            try:
                epoch_after = self._advance_target_epoch(
                    coordinator,
                    reason=f"{request.action}-{request.operation_id}",
                )
            except BaseException as exc:
                _annotate_mutation_exception(
                    exc,
                    outcome="applied",
                    journal=journal,
                )
                raise
            journal.transition(
                "verifying",
                epoch_after=epoch_after,
                verification_state="running",
                last_known_state="mutation-completed-awaiting-verification",
            )
            verification_context = FreshVerificationContext(
                task_run=self,
                coordinator=coordinator,
                target=request.target,
                mutation_token=token,
                epoch_after=epoch_after,
                verification_attempt=journal.begin_verification_attempt(),
            )
            try:
                verification_value = verify(verification_context)
                if coordinator.lease_coordinator.verification_reads < 1:
                    raise FreshVerificationRequired(
                        "mutation verification did not collect new-epoch target evidence"
                    )
            except BaseException as exc:
                if isinstance(exc, MutationVerificationTerminalFailure):
                    journal.transition(
                        "verification_failed_terminal",
                        epoch_after=epoch_after,
                        verification_state="failed",
                        last_known_state=exc.outcome,
                        recovery_decision="none",
                    )
                else:
                    journal.transition(
                        "verification_failed",
                        epoch_after=epoch_after,
                        verification_state="failed",
                        last_known_state="mutation-completed-verification-failed",
                    )
                _annotate_mutation_exception(
                    exc,
                    outcome="applied",
                    journal=journal,
                )
                raise

            self._record_metric("fresh_verifications")
            journal.transition(
                "verified",
                epoch_after=epoch_after,
                verification_state="verified",
                last_known_state="verified",
            )
            return MutationTransactionResult(
                operation_id=request.operation_id,
                action=request.action,
                target_fingerprint=request.target.fingerprint,
                epoch_before=epoch_before,
                epoch_after=epoch_after,
                mutation=mutation_value,
                verification=verification_value,
                journal=journal,
            )

    def recover_mutation(
        self,
        request: MutationRequest,
        *,
        authorization: MutationAuthorization,
        inspect: Callable[
            [MutationRecoveryInspectionContext],
            MutationRecoveryEvidence | Mapping[str, object],
        ],
        verify: Callable[[FreshVerificationContext], VerificationResultT],
        rollback: Callable[
            [MutationContext, MutationRecoveryEvidence], object
        ] | None = None,
        operation_context: object | None = None,
    ) -> MutationRecoveryStatus[VerificationResultT]:
        """Recover one durable journal after read-only target inspection."""

        with self._lock:
            journal = self._mutation_journals.get(request.operation_id)
            if journal is None:
                raise KeyError(
                    f"mutation journal is unavailable: {request.operation_id}"
                )
            if journal.operation_fingerprint != request.fingerprint:
                raise MutationOperationConflict(
                    "recovery request does not match the durable operation"
                )
            supplemental_rollback = (
                authorization.original_intent != journal.original_intent
            )
            if supplemental_rollback:
                try:
                    authorization.require("rollback")
                except BaseException as exc:
                    _annotate_mutation_exception(
                        exc,
                        outcome="not_started",
                        journal=journal,
                    )
                    raise MutationOperationConflict(
                        "recovery authorization does not match the durable task intent"
                    ) from exc
                if not (
                    journal.stage == "recovery_blocked"
                    and journal.recovery_decision == "rollback"
                ):
                    error = MutationOperationConflict(
                        "supplemental rollback authorization requires the exact "
                        "recovery_blocked journal"
                    )
                    _annotate_mutation_exception(
                        error,
                        outcome="not_started",
                        journal=journal,
                    )
                    raise error
                journal.authorize_recovery_action("rollback")
            coordinator = self._coordinator(request.target)
        if journal.terminal:
            return MutationRecoveryStatus(
                operation_id=request.operation_id,
                decision="already_verified",
                journal=journal,
                inspection=MutationRecoveryEvidence(),
            )
        if journal.stage == "replan_required":
            self._record_metric("mutation_recoveries")
            return MutationRecoveryStatus(
                operation_id=request.operation_id,
                decision="replan",
                journal=journal,
                inspection=MutationRecoveryEvidence(),
            )

        try:
            resolution = self._ssh_credential_resolver().resolve_with_status(
                task_id=self.task_id,
                target=request.target,
                selector=request.credential_selector,
            )
        except BaseException as exc:
            _annotate_mutation_exception(
                exc,
                outcome="not_started",
                journal=journal,
            )
            raise
        if not resolution.cache_hit:
            self._record_metric("credential_resolutions")
        try:
            with coordinator.lease_coordinator.read(operation_context):
                evidence = MutationRecoveryEvidence.from_value(
                    inspect(
                        MutationRecoveryInspectionContext(
                            task_id=self.task_id,
                            request=request,
                            credentials=resolution.credentials,
                            journal=journal,
                        )
                    )
                )
        except BaseException as exc:
            _annotate_mutation_exception(
                exc,
                outcome="not_started",
                journal=journal,
            )
            raise
        journal.record_execution_evidence(
            observed_checksum=evidence.remote_checksum,
            root_mount_restored=evidence.root_mount_restored,
        )
        decision = decide_mutation_recovery(journal, evidence)
        self._record_metric("mutation_recoveries")
        if decision == "replan":
            journal.transition(
                "replan_required",
                verification_state="not_started",
                last_known_state="read-only-inspection-found-no-applied-mutation",
                recovery_decision=decision,
            )
            return MutationRecoveryStatus(
                operation_id=request.operation_id,
                decision=decision,
                journal=journal,
                inspection=evidence,
            )
        if decision == "manual":
            journal.transition(
                "recovery_blocked",
                verification_state="blocked",
                last_known_state="read-only-evidence-insufficient-for-safe-recovery",
                recovery_decision=decision,
            )
            return MutationRecoveryStatus(
                operation_id=request.operation_id,
                decision=decision,
                journal=journal,
                inspection=evidence,
            )

        if decision == "rollback":
            try:
                authorization.require("rollback")
            except MutationAuthorizationDenied as exc:
                if journal.recovery_action_authorized("rollback"):
                    pass
                else:
                    journal.transition(
                        "recovery_blocked",
                        verification_state="blocked",
                        last_known_state="rollback-requires-explicit-task-authorization",
                        recovery_decision=decision,
                    )
                    _annotate_mutation_exception(
                        exc,
                        outcome="not_started",
                        journal=journal,
                    )
                    raise
            else:
                journal.authorize_recovery_action("rollback")

        with _annotated_recovery_mutation_lease(
            coordinator,
            operation_context,
            journal,
        ) as token:
            post_mutation_epoch = journal.epoch_after or journal.epoch_before + 1
            post_mutation_epoch = self._restore_target_epoch(
                coordinator,
                minimum=post_mutation_epoch,
                reason=f"recover-{request.operation_id}",
            )
            rollback_value: object | None = None
            verification_epoch = post_mutation_epoch
            if decision == "rollback":
                self._record_metric("mutation_rollbacks")
                if rollback is None:
                    error = ValueError(
                        "rollback callback is required by recovery evidence"
                    )
                    journal.transition(
                        "recovery_blocked",
                        verification_state="blocked",
                        last_known_state="rollback-callback-is-unavailable",
                        recovery_decision=decision,
                    )
                    _annotate_mutation_exception(
                        error,
                        outcome="not_started",
                        journal=journal,
                    )
                    raise error
                journal.transition(
                    "rolling_back",
                    epoch_after=post_mutation_epoch,
                    verification_state="not_started",
                    last_known_state="evidence-authorized-rollback-started",
                    recovery_decision=decision,
                )
                try:
                    rollback_value = rollback(
                        MutationContext(
                            task_id=self.task_id,
                            request=request,
                            credentials=resolution.credentials,
                            journal=journal,
                        ),
                        evidence,
                    )
                    self._record_mutation_artifacts(
                        journal,
                        rollback_value,
                        mutation_phase=False,
                    )
                except BaseException as exc:
                    journal.transition(
                        "rollback_failed",
                        verification_state="not_started",
                        last_known_state="rollback-outcome-uncertain",
                        recovery_decision=decision,
                    )
                    _annotate_mutation_exception(
                        exc,
                        outcome="unknown",
                        journal=journal,
                    )
                    raise
                verification_epoch = self._advance_target_epoch(
                    coordinator,
                    reason=f"rollback-{request.operation_id}",
                )
                journal.transition(
                    "rollback_verifying",
                    epoch_after=post_mutation_epoch,
                    rollback_epoch=verification_epoch,
                    verification_state="running",
                    last_known_state="rollback-completed-awaiting-verification",
                    recovery_decision=decision,
                )
            else:
                journal.transition(
                    "verifying",
                    epoch_after=post_mutation_epoch,
                    verification_state="running",
                    last_known_state="recovered-mutation-awaiting-verification",
                    recovery_decision=decision,
                )

            verification_context = FreshVerificationContext(
                task_run=self,
                coordinator=coordinator,
                target=request.target,
                mutation_token=token,
                epoch_after=verification_epoch,
                verification_attempt=journal.begin_verification_attempt(),
            )
            try:
                verification_value = verify(verification_context)
                if coordinator.lease_coordinator.verification_reads < 1:
                    raise FreshVerificationRequired(
                        "recovery verification did not collect new-epoch evidence"
                    )
            except BaseException as exc:
                if isinstance(exc, MutationVerificationTerminalFailure):
                    journal.transition(
                        "rollback_verification_failed_terminal"
                        if decision == "rollback"
                        else "verification_failed_terminal",
                        epoch_after=post_mutation_epoch,
                        rollback_epoch=(
                            verification_epoch if decision == "rollback" else None
                        ),
                        verification_state="failed",
                        last_known_state=exc.outcome,
                        recovery_decision="none",
                    )
                else:
                    journal.transition(
                        "rollback_verification_failed"
                        if decision == "rollback"
                        else "verification_failed",
                        epoch_after=post_mutation_epoch,
                        rollback_epoch=(
                            verification_epoch if decision == "rollback" else None
                        ),
                        verification_state="failed",
                        last_known_state="recovery-verification-failed",
                        recovery_decision=decision,
                    )
                _annotate_mutation_exception(
                    exc,
                    outcome="applied",
                    journal=journal,
                )
                raise
            self._record_metric("fresh_verifications")
            journal.transition(
                "rollback_verified" if decision == "rollback" else "verified",
                epoch_after=post_mutation_epoch,
                rollback_epoch=(
                    verification_epoch if decision == "rollback" else None
                ),
                verification_state="verified",
                last_known_state="verified",
                recovery_decision=decision,
            )
            return MutationRecoveryStatus(
                operation_id=request.operation_id,
                decision=decision,
                journal=journal,
                inspection=evidence,
                verification=verification_value,
                rollback=rollback_value,
            )

    def runtime_status(self) -> dict[str, object]:
        with self._lock:
            return {
                "api_version": RUNTIME_API_VERSION,
                "task_id": self.task_id,
                "metrics": self._metrics_snapshot(),
                "evidence_ledger": self.evidence_ledger.to_public_dict(),
                "orchestration": (
                    self._orchestration.to_public_dict()
                    if self._orchestration is not None
                    else None
                ),
                "mutation_journals": [
                    journal.to_public_dict()
                    for journal in self._mutation_journals.values()
                ],
                "request_cache": {
                    "count": len(self._requests),
                    "limit": self.max_request_records,
                    "running": sum(
                        record.state is RequestState.RUNNING
                        for record in self._requests.values()
                    ),
                    "evictions": self._request_evictions,
                    "peak_count": self._peak_request_records,
                },
                "targets": [
                    {
                        "target": coordinator.target.to_public_dict(),
                        "identity": (
                            coordinator.identity.to_public_dict()
                            if coordinator.identity is not None
                            else None
                        ),
                        "epochs": coordinator.epochs.to_public_dict(),
                        "lease_admission": (
                            coordinator.lease_coordinator.to_public_dict()
                        ),
                        "ssh_leases": {
                            name: lane.status()
                            for name, lane in coordinator.ssh_leases.items()
                        },
                        "telnet_leases": {
                            name: lane.status()
                            for name, lane in coordinator.telnet_leases.items()
                        },
                        "redfish_leases": {
                            name: lane.status()
                            for name, lane in coordinator.redfish_leases.items()
                        },
                    }
                    for coordinator in self._coordinators.values()
                ],
            }

    def mutation_journals(self) -> tuple[MutationJournal, ...]:
        """Return task-owned journals for domain-specific read-only recovery routing."""

        with self._lock:
            return tuple(self._mutation_journals.values())

    def prune_dead_connections(self) -> int:
        """Release dead transport state without discarding task evidence metadata."""

        with self._lock:
            lanes = [
                lane
                for coordinator in self._coordinators.values()
                for lane in (
                    *coordinator.ssh_leases.values(),
                    *coordinator.telnet_leases.values(),
                    *coordinator.redfish_leases.values(),
                )
            ]
        return sum(lane.prune_dead_connection() for lane in lanes)

    def close(self) -> None:
        """Close every task-owned domain lane; repeated calls are harmless."""

        with self._lock:
            lanes = {
                id(lane): lane
                for coordinator in self._coordinators.values()
                for lane in (
                    *coordinator.ssh_leases.values(),
                    *coordinator.telnet_leases.values(),
                    *coordinator.redfish_leases.values(),
                )
            }
            self._requests.clear()
        for lane in lanes.values():
            lane.close()
