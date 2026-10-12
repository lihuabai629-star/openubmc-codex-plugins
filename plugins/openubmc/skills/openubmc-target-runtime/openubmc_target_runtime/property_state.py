"""Versioned property plans and observations; no transport or authorization I/O."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields
import hashlib
import json
import re

from .contracts import TargetIdentity, TARGET_IDENTITY_SCHEMA
from .redaction import require_secret_free

PROPERTY_STATE_SCHEMA = "openubmc.target-runtime.v1/property-state-v1"
_TYPES = {"Boolean": ("b", None, None), "U8": ("y", 0, 255),
          "I16": ("n", -32768, 32767), "U16": ("q", 0, 65535),
          "I32": ("i", -(2**31), 2**31 - 1), "U32": ("u", 0, 2**32 - 1)}


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class PropertyValue:
    base_type: str
    value: int | bool

    def __post_init__(self) -> None:
        if self.base_type not in _TYPES:
            raise ValueError("unsupported scalar property type")
        _, low, high = _TYPES[self.base_type]
        if self.base_type == "Boolean":
            if type(self.value) is not bool:
                raise TypeError("Boolean property requires a boolean")
        elif type(self.value) is not int or not low <= self.value <= high:
            raise ValueError("property integer type or range is invalid")

    @property
    def signature(self) -> str:
        return _TYPES[self.base_type][0]

    def to_public_dict(self) -> dict[str, object]:
        return {"base_type": self.base_type, "value": self.value}

    @classmethod
    def from_value(cls, value: object) -> PropertyValue:
        if not isinstance(value, Mapping) or set(value) != {"base_type", "value"}:
            raise TypeError("property value requires exactly base_type and value")
        return cls(value["base_type"], value["value"])


@dataclass(frozen=True)
class PropertyContract:
    """Operator-owned allowlist entry, pinned to an owner and firmware contract.

    Proof properties must be implemented by the owner described in source_sha256.
    Neither an Agent request nor missing target metadata can assert these facts.
    """
    contract_id: str
    target: str
    service: str
    path: str
    interface: str
    property: str
    object: str
    base_type: str
    minimum: int
    maximum: int
    source_sha256: str
    firmware_id: str
    firmware_service: str
    firmware_path: str
    firmware_interface: str
    firmware_property: str
    generation_interface: str
    generation_property: str
    override_interface: str
    override_property: str
    allowed_ssh_users: tuple[str, ...]
    persistence: str
    setter_kind: str = "ordinary-assignment"
    object_lifetime: str = "owner-generation"

    def __post_init__(self) -> None:
        for name in ("contract_id", "property", "object", "firmware_property",
                     "generation_property", "override_property"):
            if not isinstance(getattr(self, name), str) or re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]{0,127}", getattr(self, name)
            ) is None:
                raise ValueError(f"invalid property contract {name}")
        for name in ("service", "interface", "firmware_service", "firmware_interface",
                     "generation_interface", "override_interface"):
            if not isinstance(getattr(self, name), str) or re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+", getattr(self, name)
            ) is None or len(getattr(self, name)) > 255:
                raise ValueError(f"invalid property contract {name}")
        for name in ("path", "firmware_path"):
            if not isinstance(getattr(self, name), str) or re.fullmatch(
                r"/(?:[A-Za-z0-9_]+/)*[A-Za-z0-9_]+", getattr(self, name)
            ) is None or len(getattr(self, name)) > 512:
                raise ValueError(f"invalid property contract {name}")
        if not isinstance(self.target, str) or not self.target or len(self.target) > 253:
            raise ValueError("property contract requires one target")
        if not isinstance(self.firmware_id, str) or not self.firmware_id or len(self.firmware_id) > 256:
            raise ValueError("property contract requires firmware identity")
        if re.fullmatch(r"[0-9a-f]{64}", self.source_sha256) is None:
            raise ValueError("property contract requires source SHA256")
        if not isinstance(self.allowed_ssh_users, tuple) or not self.allowed_ssh_users or any(not isinstance(x, str) or not x or
                len(x) > 64 for x in self.allowed_ssh_users):
            raise ValueError("property contract requires authorized SSH users")
        if self.setter_kind != "ordinary-assignment" or self.object_lifetime != "owner-generation":
            raise ValueError("first-version properties require ordinary setter and generation proof")
        if self.persistence not in {"runtime", "persistent"}:
            raise ValueError("property persistence contract is required")
        if type(self.minimum) is not int or type(self.maximum) is not int or self.minimum > self.maximum:
            raise ValueError("property contract range is invalid")
        if self.base_type not in _TYPES:
            raise ValueError("unsupported property contract type")
        if self.base_type == "Boolean":
            if (self.minimum, self.maximum) != (0, 1):
                raise ValueError("Boolean contract range must be 0..1")
        else:
            PropertyValue(self.base_type, self.minimum)
            PropertyValue(self.base_type, self.maximum)
        require_secret_free(self.to_public_dict(), boundary="PropertyContract")

    def validate_value(self, value: PropertyValue) -> None:
        if value.base_type != self.base_type or not self.minimum <= int(value.value) <= self.maximum:
            raise ValueError("property value does not match allowlisted type/range")

    def to_public_dict(self) -> dict[str, object]:
        return {**self.__dict__, "allowed_ssh_users": list(self.allowed_ssh_users)}

    @property
    def fingerprint(self) -> str:
        return digest(self.to_public_dict())

    @classmethod
    def from_value(cls, value: object) -> PropertyContract:
        if not isinstance(value, Mapping):
            raise TypeError("property contract must be an object")
        raw = dict(value)
        if set(raw) != {f.name for f in fields(cls)}:
            raise ValueError("property contract fields must be complete and exact")
        users = raw.get("allowed_ssh_users")
        if not isinstance(users, list):
            raise TypeError("allowed_ssh_users must be an array")
        raw["allowed_ssh_users"] = tuple(users)
        return cls(**raw)


@dataclass(frozen=True)
class PropertyObservation:
    target_identity: TargetIdentity
    contract_digest: str
    owner: str
    generation: str
    value: PropertyValue
    visible_value: PropertyValue
    override_active: bool
    writable: bool
    observed_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.target_identity, TargetIdentity):
            raise TypeError("property observation requires target identity")
        for name in (f.name for f in fields(TargetIdentity)):
            item = getattr(self.target_identity, name)
            if not isinstance(item, str) or len(item) > 512:
                raise TypeError("property identity fields must be bounded strings")
        if re.fullmatch(r"[0-9a-f]{64}", self.contract_digest) is None:
            raise ValueError("property observation requires contract digest")
        if not isinstance(self.owner, str) or re.fullmatch(r":[0-9]+\.[0-9]+", self.owner) is None:
            raise ValueError("property observation requires unique D-Bus owner")
        if not isinstance(self.generation, str) or not self.generation or len(self.generation) > 256:
            raise ValueError("property observation requires object generation")
        if type(self.override_active) is not bool or type(self.writable) is not bool:
            raise TypeError("property proof flags must be booleans")
        if not isinstance(self.value, PropertyValue) or not isinstance(self.visible_value, PropertyValue):
            raise TypeError("property observation requires typed values")
        if not isinstance(self.observed_at, str) or not self.observed_at or len(self.observed_at) > 128:
            raise ValueError("property observation requires collection timestamp")
        if not all((self.target_identity.machine_id, self.target_identity.firmware_id,
                    self.target_identity.reboot_anchor)):
            raise ValueError("property observation identity is incomplete")
        require_secret_free(self.to_public_dict(), boundary="PropertyObservation")

    def identity_dict(self) -> dict[str, object]:
        return {"machine_id": self.target_identity.machine_id,
                "firmware_id": self.target_identity.firmware_id,
                "reboot_anchor": self.target_identity.reboot_anchor,
                "contract_digest": self.contract_digest,
                "owner": self.owner, "generation": self.generation}

    @property
    def usable(self) -> bool:
        return self.writable and not self.override_active and self.value == self.visible_value

    def to_public_dict(self) -> dict[str, object]:
        return {**self.identity_dict(), "target_identity": self.target_identity.to_public_dict(),
                "value": self.value.to_public_dict(), "visible_value": self.visible_value.to_public_dict(),
                "override_active": self.override_active, "writable": self.writable,
                "observed_at": self.observed_at}

    @classmethod
    def from_value(cls, value: object) -> PropertyObservation:
        if not isinstance(value, Mapping):
            raise TypeError("property observation must be an object")
        if set(value) != {"machine_id", "firmware_id", "reboot_anchor", "contract_digest", "owner", "generation",
                          "target_identity", "value", "visible_value", "override_active", "writable", "observed_at"}:
            raise ValueError("property observation fields must be complete and exact")
        raw = value["target_identity"]
        if not isinstance(raw, Mapping):
            raise TypeError("property target identity must be an object")
        if set(raw) != {"schema", *(f.name for f in fields(TargetIdentity))} or raw.get("schema") != TARGET_IDENTITY_SCHEMA:
            raise ValueError("unsupported property target identity")
        identity = TargetIdentity(**{name: raw.get(name, "") for name in (
            "product_id", "machine_id", "firmware_id", "reboot_anchor", "target_clock",
            "target_clock_epoch", "target_uptime_seconds")})
        observation = cls(identity, value["contract_digest"], value["owner"],
                   value["generation"], PropertyValue.from_value(value["value"]),
                   PropertyValue.from_value(value["visible_value"]), value["override_active"],
                   value["writable"], value["observed_at"])
        if any(value[name] != item for name, item in observation.identity_dict().items()):
            raise ValueError("property observation identity fields disagree")
        return observation


@dataclass(frozen=True)
class PropertyMutationState:
    contract: PropertyContract
    expected: PropertyValue
    desired: PropertyValue
    before: PropertyObservation

    def __post_init__(self) -> None:
        self.contract.validate_value(self.expected)
        self.contract.validate_value(self.desired)
        if self.before.contract_digest != self.contract.fingerprint or not self.before.usable:
            raise ValueError("property plan requires matching usable observation")
        if self.before.value != self.expected:
            raise ValueError("property expected value is stale")
        if self.before.target_identity.firmware_id != self.contract.firmware_id:
            raise ValueError("property firmware contract mismatch")

    def matches(self, observation: PropertyObservation) -> bool:
        return (observation.usable and observation.identity_dict() == self.before.identity_dict()
                and observation.value == self.desired)

    def to_public_dict(self) -> dict[str, object]:
        return {"schema": PROPERTY_STATE_SCHEMA, "contract": self.contract.to_public_dict(),
                "expected": self.expected.to_public_dict(), "desired": self.desired.to_public_dict(),
                "before": self.before.to_public_dict(), "atomic_compare_and_set": False}

    @classmethod
    def from_value(cls, value: object) -> PropertyMutationState:
        if not isinstance(value, Mapping) or value.get("schema") != PROPERTY_STATE_SCHEMA:
            raise ValueError("unsupported property journal state")
        if set(value) != {"schema", "contract", "expected", "desired", "before", "atomic_compare_and_set"}:
            raise ValueError("property journal state fields must be complete and exact")
        if value.get("atomic_compare_and_set") is not False:
            raise ValueError("property state cannot claim atomic compare-and-set")
        return cls(PropertyContract.from_value(value["contract"]),
                   PropertyValue.from_value(value["expected"]), PropertyValue.from_value(value["desired"]),
                   PropertyObservation.from_value(value["before"]))
