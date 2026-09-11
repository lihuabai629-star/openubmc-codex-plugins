"""Stable, secret-free data contracts for Target Runtime v1."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
import hashlib
import json
from collections.abc import Mapping
import os
from pathlib import Path


RUNTIME_API_VERSION = "openubmc.target-runtime.v1"
TARGET_SPEC_SCHEMA = f"{RUNTIME_API_VERSION}/target-spec"
CREDENTIAL_SELECTOR_SCHEMA = f"{RUNTIME_API_VERSION}/credential-selector"
TARGET_IDENTITY_SCHEMA = f"{RUNTIME_API_VERSION}/target-identity"
EPOCH_STATE_SCHEMA = f"{RUNTIME_API_VERSION}/epoch-state"

_CREDENTIAL_FILE_ENV_NAMES = (
    "OPENUBMC_CREDENTIALS_CONFIG",
    "OPENUBMC_CREDENTIALS_FILE",
    "OPENUBMC_DEBUG_CREDENTIALS_FILE",
)


def _fingerprint(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _selector_token(kind: str, value: str) -> str:
    return _fingerprint({"kind": kind, "value": value})


def _normalized_local_path(value: str) -> str:
    return os.path.abspath(os.fspath(Path(value).expanduser()))


@dataclass(frozen=True)
class CredentialSelector:
    """A non-secret description of where credentials will be resolved."""

    transport: str
    username_source: str
    password_source: str
    identity_source: str
    credentials_file_sources: tuple[str, ...] = ()
    username_source_fingerprint: str = ""
    password_source_fingerprint: str = ""
    identity_source_fingerprint: str = ""
    credentials_file_source_fingerprints: tuple[str, ...] = ()

    @classmethod
    def for_ssh(
        cls,
        *,
        user: str,
        user_env: str,
        password_env: str,
        identity_file: str,
        environ: Mapping[str, str],
    ) -> "CredentialSelector":
        file_sources = tuple(
            env_name for env_name in _CREDENTIAL_FILE_ENV_NAMES if env_name in environ
        )
        if user:
            username_kind = "argument"
            username_selector = user
        elif user_env:
            username_kind = "named-environment"
            username_selector = user_env
        else:
            username_kind = "default-environment"
            username_selector = "OPENUBMC_SSH_USER"
        password_kind = (
            "named-environment" if password_env else "default-environment"
        )
        password_selector = password_env or "OPENUBMC_SSH_PASSWORD"
        identity_kind = "identity-file" if identity_file else "none"
        identity_selector = (
            _normalized_local_path(identity_file) if identity_file else ""
        )
        return cls(
            transport="ssh",
            username_source=username_kind,
            password_source=password_kind,
            identity_source=identity_kind,
            credentials_file_sources=file_sources,
            username_source_fingerprint=_selector_token(
                username_kind,
                username_selector,
            ),
            password_source_fingerprint=_selector_token(
                password_kind,
                password_selector,
            ),
            identity_source_fingerprint=(
                _selector_token(identity_kind, identity_selector)
                if identity_selector
                else ""
            ),
            credentials_file_source_fingerprints=tuple(
                _selector_token(
                    env_name,
                    _normalized_local_path(environ[env_name]),
                )
                for env_name in file_sources
            ),
        )

    @classmethod
    def for_telnet(
        cls,
        *,
        user: str,
        user_env: str,
        password_env: str,
        environ: Mapping[str, str],
    ) -> "CredentialSelector":
        file_sources = tuple(
            env_name for env_name in _CREDENTIAL_FILE_ENV_NAMES if env_name in environ
        )
        if user:
            username_kind = "argument"
            username_selector = user
        elif user_env:
            username_kind = "named-environment"
            username_selector = user_env
        else:
            username_kind = "default-environment"
            username_selector = "OPENUBMC_TELNET_USER"
        password_kind = (
            "named-environment" if password_env else "default-environment"
        )
        password_selector = password_env or "OPENUBMC_TELNET_PASSWORD"
        return cls(
            transport="telnet",
            username_source=username_kind,
            password_source=password_kind,
            identity_source="none",
            credentials_file_sources=file_sources,
            username_source_fingerprint=_selector_token(
                username_kind,
                username_selector,
            ),
            password_source_fingerprint=_selector_token(
                password_kind,
                password_selector,
            ),
            credentials_file_source_fingerprints=tuple(
                _selector_token(
                    env_name,
                    _normalized_local_path(environ[env_name]),
                )
                for env_name in file_sources
            ),
        )

    @classmethod
    def for_redfish(
        cls,
        *,
        user: str,
        user_env: str,
        password_env: str,
        environ: Mapping[str, str],
    ) -> "CredentialSelector":
        file_sources = tuple(
            env_name for env_name in _CREDENTIAL_FILE_ENV_NAMES if env_name in environ
        )
        if user:
            username_kind = "argument"
            username_selector = user
        elif user_env:
            username_kind = "named-environment"
            username_selector = user_env
        else:
            username_kind = "default-environment"
            username_selector = "OPENUBMC_REDFISH_USER"
        password_kind = (
            "named-environment" if password_env else "default-environment"
        )
        password_selector = password_env or "OPENUBMC_REDFISH_PASSWORD"
        return cls(
            transport="redfish",
            username_source=username_kind,
            password_source=password_kind,
            identity_source="none",
            credentials_file_sources=file_sources,
            username_source_fingerprint=_selector_token(
                username_kind,
                username_selector,
            ),
            password_source_fingerprint=_selector_token(
                password_kind,
                password_selector,
            ),
            credentials_file_source_fingerprints=tuple(
                _selector_token(
                    env_name,
                    _normalized_local_path(environ[env_name]),
                )
                for env_name in file_sources
            ),
        )

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.to_public_dict(include_fingerprint=False))

    def to_public_dict(self, *, include_fingerprint: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema": CREDENTIAL_SELECTOR_SCHEMA,
            "transport": self.transport,
            "username_source": self.username_source,
            "password_source": self.password_source,
            "identity_source": self.identity_source,
            "credentials_file_sources": list(self.credentials_file_sources),
            "username_source_fingerprint": self.username_source_fingerprint,
            "password_source_fingerprint": self.password_source_fingerprint,
            "identity_source_fingerprint": self.identity_source_fingerprint,
            "credentials_file_source_fingerprints": list(
                self.credentials_file_source_fingerprints
            ),
        }
        if include_fingerprint:
            payload["fingerprint"] = self.fingerprint
        return payload


@dataclass(frozen=True)
class TargetPolicy:
    """Target-wide policy that can safely participate in target identity."""

    read_only: bool = True
    ssh_host_key_policy: str = "default"

    def to_public_dict(self) -> dict[str, object]:
        return {
            "read_only": self.read_only,
            "ssh_host_key_policy": self.ssh_host_key_policy,
        }


def _validate_port(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError(f"{name} must be an integer between 1 and 65535")


@dataclass(frozen=True)
class TargetSpec:
    """Normalized target coordinates without credential material or local paths."""

    host: str
    ssh_port: int = 22
    telnet_port: int = 23
    redfish_port: int = 443
    credential_selector_fingerprint: str = ""
    credential_selector_fingerprints: tuple[str, ...] = ()
    policy: TargetPolicy = field(default_factory=TargetPolicy)

    def __post_init__(self) -> None:
        normalized_host = self.host.strip().lower()
        if not normalized_host:
            raise ValueError("target host must not be empty")
        object.__setattr__(self, "host", normalized_host)
        _validate_port("ssh_port", self.ssh_port)
        _validate_port("telnet_port", self.telnet_port)
        _validate_port("redfish_port", self.redfish_port)
        fingerprint = self.credential_selector_fingerprint
        if len(fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in fingerprint
        ):
            raise ValueError(
                "credential_selector_fingerprint must be a lowercase SHA-256 digest"
            )
        normalized_fingerprints = tuple(
            sorted(set(self.credential_selector_fingerprints))
        )
        for member in normalized_fingerprints:
            if len(member) != 64 or any(
                character not in "0123456789abcdef" for character in member
            ):
                raise ValueError(
                    "credential_selector_fingerprints must contain lowercase SHA-256 digests"
                )
        if normalized_fingerprints:
            expected = _fingerprint(
                {"credential_selector_fingerprints": normalized_fingerprints}
            )
            if fingerprint != expected:
                raise ValueError(
                    "credential_selector_fingerprint must identify the declared selector set"
                )
        object.__setattr__(
            self,
            "credential_selector_fingerprints",
            normalized_fingerprints,
        )

    @classmethod
    def for_credential_selectors(
        cls,
        *,
        host: str,
        credential_selectors: tuple[CredentialSelector, ...],
        ssh_port: int = 22,
        telnet_port: int = 23,
        redfish_port: int = 443,
        policy: TargetPolicy | None = None,
    ) -> "TargetSpec":
        fingerprints = tuple(
            sorted({selector.fingerprint for selector in credential_selectors})
        )
        if not fingerprints:
            raise ValueError("at least one credential selector is required")
        return cls(
            host=host,
            ssh_port=ssh_port,
            telnet_port=telnet_port,
            redfish_port=redfish_port,
            credential_selector_fingerprint=_fingerprint(
                {"credential_selector_fingerprints": fingerprints}
            ),
            credential_selector_fingerprints=fingerprints,
            policy=policy or TargetPolicy(),
        )

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.to_public_dict(include_fingerprint=False))

    def to_public_dict(self, *, include_fingerprint: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema": TARGET_SPEC_SCHEMA,
            "host": self.host,
            "ports": {
                "ssh": self.ssh_port,
                "telnet": self.telnet_port,
                "redfish": self.redfish_port,
            },
            "credential_selector_fingerprint": self.credential_selector_fingerprint,
            "policy": self.policy.to_public_dict(),
        }
        if self.credential_selector_fingerprints:
            payload["credential_selector_fingerprints"] = list(
                self.credential_selector_fingerprints
            )
        if include_fingerprint:
            payload["fingerprint"] = self.fingerprint
        return payload

    def validate_credential_selector(self, selector: CredentialSelector) -> None:
        valid = (
            selector.fingerprint in self.credential_selector_fingerprints
            if self.credential_selector_fingerprints
            else self.credential_selector_fingerprint == selector.fingerprint
        )
        if not valid:
            raise ValueError(
                "TargetSpec credential selector fingerprint does not match the request"
            )


@dataclass(frozen=True)
class TargetIdentity:
    """Observed target identity fields used to detect target-wide changes."""

    product_id: str = ""
    machine_id: str = ""
    firmware_id: str = ""
    reboot_anchor: str = ""
    target_clock: str = ""

    def change_kind(self, current: "TargetIdentity") -> "TargetIdentityChange":
        for field_name in ("product_id", "machine_id"):
            previous_value = getattr(self, field_name)
            current_value = getattr(current, field_name)
            if previous_value and current_value and previous_value != current_value:
                return TargetIdentityChange.REPLACEMENT
        if (
            self.firmware_id
            and current.firmware_id
            and self.firmware_id != current.firmware_id
        ):
            return TargetIdentityChange.FIRMWARE_CHANGE
        if (
            self.reboot_anchor
            and current.reboot_anchor
            and self.reboot_anchor != current.reboot_anchor
        ):
            return TargetIdentityChange.REBOOT
        comparable_fields = (
            (self.product_id, current.product_id),
            (self.machine_id, current.machine_id),
            (self.firmware_id, current.firmware_id),
            (self.reboot_anchor, current.reboot_anchor),
        )
        if any(previous and observed for previous, observed in comparable_fields):
            return TargetIdentityChange.UNCHANGED
        return TargetIdentityChange.UNKNOWN

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": TARGET_IDENTITY_SCHEMA,
            "product_id": self.product_id,
            "machine_id": self.machine_id,
            "firmware_id": self.firmware_id,
            "reboot_anchor": self.reboot_anchor,
            "target_clock": self.target_clock,
        }


class TargetIdentityChange(str, Enum):
    UNCHANGED = "unchanged"
    REBOOT = "reboot"
    FIRMWARE_CHANGE = "firmware-change"
    REPLACEMENT = "replacement"
    UNKNOWN = "unknown"


class Lane(str, Enum):
    SSH = "ssh"
    TELNET = "telnet"
    REDFISH = "redfish"


class LaneStatus(str, Enum):
    DISCONNECTED = "disconnected"
    READY = "ready"
    INVALID = "invalid"


LANES = tuple(Lane)


@dataclass(frozen=True)
class LaneEpochState:
    status: LaneStatus = LaneStatus.DISCONNECTED
    epoch: int = 0
    opens: int = 0
    cache_valid: bool = False
    last_reason: str = "initial"

    def to_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "epoch": self.epoch,
            "opens": self.opens,
            "cache_valid": self.cache_valid,
            "last_reason": self.last_reason,
        }


@dataclass(frozen=True)
class EpochState:
    """Independent lane epochs plus the target-wide evidence epoch."""

    target_epoch: int = 0
    ssh: LaneEpochState = field(default_factory=LaneEpochState)
    telnet: LaneEpochState = field(default_factory=LaneEpochState)
    redfish: LaneEpochState = field(default_factory=LaneEpochState)
    last_reason: str = "initial"

    @staticmethod
    def _lane(lane: Lane | str) -> Lane:
        try:
            return lane if isinstance(lane, Lane) else Lane(lane)
        except ValueError:
            raise ValueError(f"unsupported lane: {lane}") from None

    def _replace_lane(
        self,
        lane: Lane | str,
        state: LaneEpochState,
        *,
        reason: str,
    ) -> "EpochState":
        lane_name = self._lane(lane)
        return replace(self, **{lane_name.value: state}, last_reason=reason)

    def connect_lane(self, lane: Lane | str) -> "EpochState":
        lane_name = self._lane(lane)
        current = getattr(self, lane_name.value)
        if current.status is LaneStatus.READY:
            return self
        connected = replace(
            current,
            status=LaneStatus.READY,
            epoch=current.epoch + int(current.opens > 0),
            opens=current.opens + 1,
            cache_valid=False,
            last_reason="connected" if current.opens == 0 else "reconnected",
        )
        return self._replace_lane(
            lane_name,
            connected,
            reason=f"{lane_name.value}-{connected.last_reason}",
        )

    def cache_lane_state(self, lane: Lane | str) -> "EpochState":
        lane_name = self._lane(lane)
        current = getattr(self, lane_name.value)
        if current.status is not LaneStatus.READY:
            raise ValueError(
                f"{lane_name.value} lane must be ready before caching state"
            )
        return self._replace_lane(
            lane_name,
            replace(current, cache_valid=True, last_reason="cache-refreshed"),
            reason=f"{lane_name.value}-cache-refreshed",
        )

    def invalidate_lane(self, lane: Lane | str, *, reason: str) -> "EpochState":
        lane_name = self._lane(lane)
        current = getattr(self, lane_name.value)
        return self._replace_lane(
            lane_name,
            replace(
                current,
                status=LaneStatus.INVALID,
                cache_valid=False,
                last_reason=reason,
            ),
            reason=f"{lane_name.value}-{reason}",
        )

    def advance_target_epoch(self, *, reason: str) -> "EpochState":
        def invalidated(lane: LaneEpochState) -> LaneEpochState:
            return replace(
                lane,
                status=LaneStatus.INVALID,
                cache_valid=False,
                last_reason=f"target-{reason}",
            )

        lanes = {
            lane.value: invalidated(getattr(self, lane.value)) for lane in LANES
        }
        return replace(
            self,
            target_epoch=self.target_epoch + 1,
            last_reason=reason,
            **lanes,
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": EPOCH_STATE_SCHEMA,
            "target_epoch": self.target_epoch,
            "lanes": {
                lane.value: getattr(self, lane.value).to_public_dict()
                for lane in LANES
            },
            "last_reason": self.last_reason,
        }
