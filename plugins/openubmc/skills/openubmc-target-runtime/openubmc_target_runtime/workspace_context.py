"""Validated, immutable Host selection metadata; it grants no execution authority."""

from collections.abc import Mapping
from dataclasses import dataclass, field
import hashlib
import json
import re

from .redaction import require_secret_free


_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_FIELDS = frozenset({"schema_version", "context_digest", "selection_ref", "project_ref",
    "requested_machine_ref", "requested_firmware_ref", "repositories"})
_REPO_FIELDS = frozenset({"repo_ref", "repo_class", "commit", "branch", "dirty",
    "identity_availability", "identity_source_ref"})


class WorkspaceContextError(ValueError):
    code = "invalid_workspace_context"


def _invalid():
    raise WorkspaceContextError("Host workspace snapshot is invalid")


def _reference(value, *, optional=False):
    if value is None and optional:
        return None
    if not isinstance(value, str) or _REFERENCE.fullmatch(value) is None:
        _invalid()
    return value


def _branch_is_representable(value):
    return (isinstance(value, str) and bool(value) and len(value.encode("utf-8")) <= 256
            and not value.startswith(("/", "\\")) and ":" not in value
            and all(ord(c) >= 33 for c in value))


def _repository(raw):
    if not isinstance(raw, Mapping) or set(raw) - _REPO_FIELDS:
        _invalid()
    commit, branch, dirty = raw.get("commit"), raw.get("branch"), raw.get("dirty")
    if commit is not None and (not isinstance(commit, str) or _COMMIT.fullmatch(commit) is None):
        _invalid()
    if branch is not None and not _branch_is_representable(branch):
        _invalid()
    if dirty is not None and type(dirty) is not bool:
        _invalid()
    availability = raw.get("identity_availability", "unavailable")
    if not isinstance(availability, str) or availability not in {"available", "partial", "unavailable"}:
        _invalid()
    if availability == "unavailable" and any(v is not None for v in (commit, branch, dirty)):
        _invalid()
    if availability == "available" and (commit is None or dirty is None):
        _invalid()
    repo_class = raw.get("repo_class", "unknown")
    if not isinstance(repo_class, str) or repo_class not in {"product", "internal", "community", "unknown"}:
        _invalid()
    return {"repo_ref": _reference(raw.get("repo_ref")), "repo_class": repo_class,
        "commit": commit, "branch": branch, "dirty": dirty,
        "identity_availability": availability,
        "identity_source_ref": _reference(raw.get("identity_source_ref"), optional=True)}


@dataclass(frozen=True, init=False)
class WorkspaceSnapshot:
    """A canonical value supplied only through a trusted Host composition seam."""

    _canonical_json: str = field(repr=False)

    def __init__(self, raw: Mapping[str, object]):
        # Import after semantic contracts initialize; reuse their existing input bound.
        from .semantic_runtime import bounded_request

        if not isinstance(raw, Mapping):
            _invalid()
        bounded_request(raw)
        require_secret_free(raw, boundary="Host workspace snapshot")
        if set(raw) - _FIELDS or type(raw.get("schema_version")) is not int or raw["schema_version"] != 1:
            _invalid()
        repositories = raw.get("repositories")
        if not isinstance(repositories, list) or len(repositories) > 32:
            _invalid()
        repositories = [_repository(item) for item in repositories]
        if len({item["repo_ref"] for item in repositories}) != len(repositories):
            _invalid()
        body = {"schema_version": 1, "selection_ref": _reference(raw.get("selection_ref")),
            "project_ref": _reference(raw.get("project_ref")),
            "requested_machine_ref": _reference(raw.get("requested_machine_ref"), optional=True),
            "requested_firmware_ref": _reference(raw.get("requested_firmware_ref"), optional=True),
            "repositories": repositories}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if raw.get("context_digest") != digest:
            _invalid()
        body["context_digest"] = digest
        object.__setattr__(self, "_canonical_json", json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False))

    def to_public_dict(self) -> dict[str, object]:
        return json.loads(self._canonical_json)
