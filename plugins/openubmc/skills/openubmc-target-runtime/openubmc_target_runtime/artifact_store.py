"""Persistent content-addressed lifecycle behind the Runtime ArtifactStore seam."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import threading
import time
from typing import Protocol
from urllib.parse import unquote, urlparse

from .contracts import RUNTIME_API_VERSION
from .redaction import is_secret_key, redact_text
from .semantic_runtime import ArtifactRef, ReferenceViolation


ARTIFACT_RECORD_SCHEMA = f"{RUNTIME_API_VERSION}/artifact-record-v1"
_RETENTION_HINTS = frozenset({"temporary", "run-lifetime", "audit"})


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True)
class ArtifactBindingIdentity:
    digest: str
    kind: str
    target: str
    run_id: str

    def __post_init__(self) -> None:
        if len(self.digest) != 64 or any(
            not str(value).strip() for value in (self.kind, self.target, self.run_id)
        ):
            raise ReferenceViolation("Artifact identity is incomplete")

    def values(self) -> tuple[str, str, str, str]:
        return (self.digest, self.kind, self.target, self.run_id)


@dataclass(frozen=True)
class ArtifactEffectBindingIdentity:
    created_by_effect: str
    kind: str
    target: str
    run_id: str

    def __post_init__(self) -> None:
        if any(
            not str(value).strip()
            for value in (
                self.created_by_effect,
                self.kind,
                self.target,
                self.run_id,
            )
        ):
            raise ReferenceViolation("Artifact Effect identity is incomplete")

    def values(self) -> tuple[str, str, str, str]:
        return (self.created_by_effect, self.kind, self.target, self.run_id)


@dataclass(frozen=True)
class ArtifactRecord:
    reference: ArtifactRef
    storage_path: str
    created_by_effect: str
    redacted: bool
    managed: bool
    created_at: float
    last_access: float
    expires_at: float = 0.0
    released: bool = False

    def __post_init__(self) -> None:
        if not self.storage_path.strip():
            raise ReferenceViolation("Artifact record storage path is required")
        if not self.created_by_effect.strip():
            raise ReferenceViolation("Artifact record Effect identity is required")
        if self.created_at < 0 or self.last_access < 0 or self.expires_at < 0:
            raise ReferenceViolation("Artifact record timestamps must be non-negative")

    @property
    def identity(self) -> ArtifactBindingIdentity:
        return ArtifactBindingIdentity(
            digest=self.reference.digest,
            kind=self.reference.kind,
            target=self.reference.target,
            run_id=self.reference.run_id,
        )

    @property
    def effect_identity(self) -> ArtifactEffectBindingIdentity:
        return ArtifactEffectBindingIdentity(
            created_by_effect=self.created_by_effect,
            kind=self.reference.kind,
            target=self.reference.target,
            run_id=self.reference.run_id,
        )

    def has_same_binding(self, other: "ArtifactRecord") -> bool:
        return (
            self.reference == other.reference
            and self.storage_path == other.storage_path
            and self.redacted == other.redacted
            and self.managed == other.managed
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": ARTIFACT_RECORD_SCHEMA,
            "artifact_ref": self.reference.to_public_dict(),
            "created_by_effect": self.created_by_effect,
            "redacted": self.redacted,
            "managed": self.managed,
            "created_at": self.created_at,
            "last_access": self.last_access,
            "expires_at": self.expires_at,
            "released": self.released,
        }


class ArtifactRepository(Protocol):
    def put(self, record: ArtifactRecord) -> ArtifactRecord: ...

    def load(self, reference: ArtifactRef) -> ArtifactRecord | None: ...

    def find(
        self,
        identity: ArtifactEffectBindingIdentity,
    ) -> ArtifactRecord | None: ...

    def touch(self, reference: ArtifactRef, *, at: float) -> None: ...

    def release_run(self, run_id: str, *, at: float) -> int: ...

    def records(self) -> tuple[ArtifactRecord, ...]: ...

    def delete(self, reference: ArtifactRef) -> bool: ...

    def digest_reference_count(self, digest: str) -> int: ...


class InMemoryArtifactRepository:
    def __init__(self) -> None:
        self._records: dict[ArtifactBindingIdentity, ArtifactRecord] = {}
        self._effects: dict[ArtifactEffectBindingIdentity, ArtifactBindingIdentity] = {}
        self._lock = threading.RLock()

    def put(self, record: ArtifactRecord) -> ArtifactRecord:
        with self._lock:
            existing_identity = self._effects.get(record.effect_identity)
            if existing_identity is not None:
                existing = self._records[existing_identity]
                if not existing.has_same_binding(record):
                    raise ReferenceViolation(
                        "Artifact Effect identity is already bound to different content"
                    )
                return existing
            existing = self._records.get(record.identity)
            if existing is not None:
                if (
                    existing.reference != record.reference
                    or existing.storage_path != record.storage_path
                    or existing.redacted != record.redacted
                    or existing.managed != record.managed
                ):
                    raise ReferenceViolation(
                        "Artifact identity is already bound to different metadata"
                    )
                self._effects[record.effect_identity] = record.identity
                return existing
            self._records[record.identity] = record
            self._effects[record.effect_identity] = record.identity
            return record

    def load(self, reference: ArtifactRef) -> ArtifactRecord | None:
        with self._lock:
            return self._records.get(
                ArtifactBindingIdentity(
                    digest=reference.digest,
                    kind=reference.kind,
                    target=reference.target,
                    run_id=reference.run_id,
                )
            )

    def find(
        self,
        identity: ArtifactEffectBindingIdentity,
    ) -> ArtifactRecord | None:
        with self._lock:
            bound = self._effects.get(identity)
            return self._records.get(bound) if bound is not None else None

    def touch(self, reference: ArtifactRef, *, at: float) -> None:
        with self._lock:
            identity = ArtifactBindingIdentity(
                digest=reference.digest,
                kind=reference.kind,
                target=reference.target,
                run_id=reference.run_id,
            )
            record = self._records.get(identity)
            if record is not None:
                self._records[identity] = replace(record, last_access=at)

    def release_run(self, run_id: str, *, at: float) -> int:
        released = 0
        with self._lock:
            for identity, record in tuple(self._records.items()):
                if (
                    record.reference.run_id == run_id
                    and record.reference.retention_hint == "run-lifetime"
                    and not record.released
                ):
                    self._records[identity] = replace(
                        record,
                        released=True,
                        expires_at=at,
                    )
                    released += 1
        return released

    def records(self) -> tuple[ArtifactRecord, ...]:
        with self._lock:
            return tuple(self._records.values())

    def delete(self, reference: ArtifactRef) -> bool:
        identity = ArtifactBindingIdentity(
            digest=reference.digest,
            kind=reference.kind,
            target=reference.target,
            run_id=reference.run_id,
        )
        with self._lock:
            record = self._records.pop(identity, None)
            if record is None:
                return False
            self._effects = {
                effect: bound
                for effect, bound in self._effects.items()
                if bound != identity
            }
            return True

    def digest_reference_count(self, digest: str) -> int:
        with self._lock:
            return sum(
                1 for record in self._records.values() if record.reference.digest == digest
            )


class SQLiteArtifactRepository:
    """Persistent Artifact metadata in a Runtime-owned SQLite database."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS artifact_records (
                    digest TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    target TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    reference_json TEXT NOT NULL,
                    storage_path TEXT NOT NULL,
                    created_by_effect TEXT NOT NULL,
                    redacted INTEGER NOT NULL,
                    managed INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    last_access REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    released INTEGER NOT NULL,
                    PRIMARY KEY (digest, kind, target, run_id)
                );
                CREATE TABLE IF NOT EXISTS artifact_effect_bindings (
                    created_by_effect TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    target TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    PRIMARY KEY (created_by_effect, kind, target, run_id)
                );
                CREATE INDEX IF NOT EXISTS artifact_records_digest
                    ON artifact_records(digest);
                CREATE INDEX IF NOT EXISTS artifact_records_run
                    ON artifact_records(run_id);
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO artifact_effect_bindings "
                "(created_by_effect, kind, target, run_id, digest) "
                "SELECT created_by_effect, kind, target, run_id, digest "
                "FROM artifact_records"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        return connection

    @staticmethod
    def _record(row: sqlite3.Row) -> ArtifactRecord:
        raw_reference = json.loads(str(row["reference_json"]))
        if not isinstance(raw_reference, Mapping):
            raise ReferenceViolation("Artifact repository contains invalid metadata")
        return ArtifactRecord(
            reference=ArtifactRef.from_public_dict(raw_reference),
            storage_path=str(row["storage_path"]),
            created_by_effect=str(row["created_by_effect"]),
            redacted=bool(row["redacted"]),
            managed=bool(row["managed"]),
            created_at=float(row["created_at"]),
            last_access=float(row["last_access"]),
            expires_at=float(row["expires_at"]),
            released=bool(row["released"]),
        )

    def put(self, record: ArtifactRecord) -> ArtifactRecord:
        with self._lock, self._connect() as connection:
            effect_row = connection.execute(
                "SELECT records.* FROM artifact_effect_bindings AS bindings "
                "JOIN artifact_records AS records ON "
                "records.digest = bindings.digest AND records.kind = bindings.kind "
                "AND records.target = bindings.target AND records.run_id = bindings.run_id "
                "WHERE bindings.created_by_effect = ? AND bindings.kind = ? "
                "AND bindings.target = ? AND bindings.run_id = ?",
                record.effect_identity.values(),
            ).fetchone()
            if effect_row is not None:
                existing = self._record(effect_row)
                if not existing.has_same_binding(record):
                    raise ReferenceViolation(
                        "Artifact Effect identity is already bound to different content"
                    )
                return existing
            identity_row = connection.execute(
                "SELECT * FROM artifact_records WHERE digest = ? AND kind = ? "
                "AND target = ? AND run_id = ?",
                record.identity.values(),
            ).fetchone()
            if identity_row is not None:
                existing = self._record(identity_row)
                if (
                    existing.reference != record.reference
                    or existing.storage_path != record.storage_path
                    or existing.redacted != record.redacted
                    or existing.managed != record.managed
                ):
                    raise ReferenceViolation(
                        "Artifact identity is already bound to different metadata"
                    )
                connection.execute(
                    "INSERT INTO artifact_effect_bindings "
                    "(created_by_effect, kind, target, run_id, digest) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (*record.effect_identity.values(), record.reference.digest),
                )
                return existing
            connection.execute(
                "INSERT INTO artifact_records "
                "(digest, kind, target, run_id, reference_json, storage_path, "
                "created_by_effect, redacted, managed, created_at, last_access, "
                "expires_at, released) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    *record.identity.values(),
                    _json_bytes(record.reference.to_public_dict()).decode("utf-8"),
                    record.storage_path,
                    record.created_by_effect,
                    int(record.redacted),
                    int(record.managed),
                    record.created_at,
                    record.last_access,
                    record.expires_at,
                    int(record.released),
                ),
            )
            connection.execute(
                "INSERT INTO artifact_effect_bindings "
                "(created_by_effect, kind, target, run_id, digest) "
                "VALUES (?, ?, ?, ?, ?)",
                (*record.effect_identity.values(), record.reference.digest),
            )
            return record

    def load(self, reference: ArtifactRef) -> ArtifactRecord | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM artifact_records WHERE digest = ? AND kind = ? "
                "AND target = ? AND run_id = ?",
                (reference.digest, reference.kind, reference.target, reference.run_id),
            ).fetchone()
            return self._record(row) if row is not None else None

    def find(
        self,
        identity: ArtifactEffectBindingIdentity,
    ) -> ArtifactRecord | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT records.* FROM artifact_effect_bindings AS bindings "
                "JOIN artifact_records AS records ON "
                "records.digest = bindings.digest AND records.kind = bindings.kind "
                "AND records.target = bindings.target AND records.run_id = bindings.run_id "
                "WHERE bindings.created_by_effect = ? AND bindings.kind = ? "
                "AND bindings.target = ? AND bindings.run_id = ?",
                identity.values(),
            ).fetchone()
            return self._record(row) if row is not None else None

    def touch(self, reference: ArtifactRef, *, at: float) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "UPDATE artifact_records SET last_access = ? WHERE digest = ? "
                "AND kind = ? AND target = ? AND run_id = ?",
                (at, reference.digest, reference.kind, reference.target, reference.run_id),
            )

    def release_run(self, run_id: str, *, at: float) -> int:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "UPDATE artifact_records SET released = 1, expires_at = ? "
                "WHERE run_id = ? AND released = 0 AND "
                "json_extract(reference_json, '$.retention_hint') = 'run-lifetime'",
                (at, run_id),
            )
            return int(cursor.rowcount)

    def records(self) -> tuple[ArtifactRecord, ...]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM artifact_records ORDER BY created_at, digest"
            ).fetchall()
            return tuple(self._record(row) for row in rows)

    def delete(self, reference: ArtifactRef) -> bool:
        with self._lock, self._connect() as connection:
            connection.execute(
                "DELETE FROM artifact_effect_bindings WHERE digest = ? AND kind = ? "
                "AND target = ? AND run_id = ?",
                (reference.digest, reference.kind, reference.target, reference.run_id),
            )
            cursor = connection.execute(
                "DELETE FROM artifact_records WHERE digest = ? AND kind = ? "
                "AND target = ? AND run_id = ?",
                (reference.digest, reference.kind, reference.target, reference.run_id),
            )
            return cursor.rowcount > 0

    def digest_reference_count(self, digest: str) -> int:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM artifact_records WHERE digest = ?",
                (digest,),
            ).fetchone()
            return int(row["count"])


class LocalArtifactStore:
    """Own content identity, access binding, redaction, retention, and GC."""

    def __init__(
        self,
        *,
        content_root: Path | None = None,
        repository: ArtifactRepository | None = None,
        clock: Callable[[], float] = time.time,
        temporary_retention_seconds: float = 24 * 60 * 60,
    ) -> None:
        if temporary_retention_seconds <= 0:
            raise ValueError("temporary Artifact retention must be positive")
        self.content_root = Path(
            content_root
            or Path(tempfile.gettempdir()) / "openubmc-target-runtime-artifacts"
        )
        self.content_root.mkdir(parents=True, exist_ok=True)
        self.repository = repository or InMemoryArtifactRepository()
        self.clock = clock
        self.temporary_retention_seconds = float(temporary_retention_seconds)
        self._lock = threading.RLock()

    @staticmethod
    def reference(value: ArtifactRef | Mapping[str, object]) -> ArtifactRef:
        return value if isinstance(value, ArtifactRef) else ArtifactRef.from_public_dict(value)

    @staticmethod
    def _path(handle: str) -> Path:
        parsed = urlparse(handle)
        if parsed.scheme not in {"", "file"}:
            raise ReferenceViolation(
                "ArtifactRef handle is not available from the local ArtifactStore"
            )
        if parsed.scheme == "file":
            if parsed.netloc not in {"", "localhost"}:
                raise ReferenceViolation("ArtifactRef file handle must be local")
            return Path(unquote(parsed.path))
        return Path(handle)

    def path_for(self, reference: ArtifactRef) -> Path:
        """Resolve handle syntax or a persisted content-addressed record."""

        record = self.repository.load(reference)
        return Path(record.storage_path) if record is not None else self._path(reference.handle)

    @staticmethod
    def _digest(path: Path) -> tuple[str, int]:
        digest = hashlib.sha256()
        size = 0
        try:
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
        except OSError as exc:
            raise ReferenceViolation("ArtifactRef content is unavailable") from exc
        return digest.hexdigest(), size

    @staticmethod
    def metadata_path(path: Path) -> Path:
        return Path(str(path) + ".metadata.json")

    @classmethod
    def _validate_version_metadata(
        cls,
        path: Path,
        reference: ArtifactRef,
        *,
        actual_digest: str,
        actual_size: int,
    ) -> None:
        if not reference.version:
            return
        metadata_path = cls.metadata_path(path)
        if not metadata_path.is_file():
            raise ReferenceViolation("versioned ArtifactRef requires build artifact metadata")
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ReferenceViolation("build artifact metadata is unreadable") from exc
        if not isinstance(metadata, dict) or metadata.get("schema") != (
            "openubmc-agent-workflow/artifact-metadata-v1"
        ):
            raise ReferenceViolation("build artifact metadata schema is unsupported")
        artifact = metadata.get("artifact")
        if not isinstance(artifact, dict):
            raise ReferenceViolation("build artifact metadata omits artifact identity")
        if str(artifact.get("sha256", "")).removeprefix("sha256:") != actual_digest:
            raise ReferenceViolation("build artifact metadata digest does not match stored content")
        size = artifact.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size != actual_size:
            raise ReferenceViolation("build artifact metadata size does not match stored content")
        if str(artifact.get("kind", "")) != reference.kind:
            raise ReferenceViolation("build artifact metadata kind does not match ArtifactRef")
        if str(metadata.get("product_version", "")) != reference.version:
            raise ReferenceViolation("ArtifactRef version does not match artifact metadata")
        if str(metadata.get("provenance", "")) != reference.provenance:
            raise ReferenceViolation("ArtifactRef provenance does not match artifact metadata")

    @staticmethod
    def _validate_retention(retention_hint: str) -> str:
        normalized = str(retention_hint).strip().lower()
        if normalized not in _RETENTION_HINTS:
            raise ReferenceViolation("ArtifactRef retention_hint is unsupported")
        return normalized

    def _managed_path(self, digest: str) -> Path:
        return self.content_root / digest[:2] / digest

    def _copy_content(self, source: Path, digest: str) -> Path:
        destination = self._managed_path(digest)
        with self._lock:
            if destination.is_file():
                actual_digest, _ = self._digest(destination)
                if actual_digest != digest:
                    raise ReferenceViolation("managed Artifact content failed hash verification")
                return destination
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor, raw_path = tempfile.mkstemp(
                prefix=f".{digest}.",
                suffix=".tmp",
                dir=destination.parent,
            )
            os.close(descriptor)
            try:
                shutil.copyfile(source, raw_path)
                actual_digest, _ = self._digest(Path(raw_path))
                if actual_digest != digest:
                    raise ReferenceViolation("Artifact content changed while being persisted")
                os.replace(raw_path, destination)
            finally:
                try:
                    os.unlink(raw_path)
                except FileNotFoundError:
                    pass
        return destination

    def _record(
        self,
        reference: ArtifactRef,
        *,
        storage_path: Path,
        created_by_effect: str,
        redacted: bool,
        managed: bool,
    ) -> ArtifactRef:
        now = float(self.clock())
        retention = self._validate_retention(reference.retention_hint)
        expires_at = (
            now + self.temporary_retention_seconds
            if retention == "temporary"
            else 0.0
        )
        record = ArtifactRecord(
            reference=reference,
            storage_path=str(storage_path),
            created_by_effect=created_by_effect,
            redacted=redacted,
            managed=managed,
            created_at=now,
            last_access=now,
            expires_at=expires_at,
        )
        return self.repository.put(record).reference

    def _put(
        self,
        path: Path,
        *,
        kind: str,
        provenance: str,
        retention_hint: str,
        target: str,
        run_id: str,
        created_by_effect: str,
        version: str = "",
        redacted: bool,
        expected_sha256: str = "",
    ) -> ArtifactRef:
        source = Path(path)
        if not source.is_file():
            raise ReferenceViolation("ArtifactRef content is unavailable")
        digest, size = self._digest(source)
        if expected_sha256 and digest != expected_sha256:
            raise ReferenceViolation(
                "Artifact content does not match the expected SHA-256"
            )
        reference = ArtifactRef(
            handle=f"artifact://sha256/{digest}",
            digest=digest,
            kind=kind,
            size=size,
            provenance=provenance,
            retention_hint=self._validate_retention(retention_hint),
            version=version,
            target=target,
            run_id=run_id,
        )
        existing = self.repository.find(
            ArtifactEffectBindingIdentity(
                created_by_effect=created_by_effect,
                kind=kind,
                target=target,
                run_id=run_id,
            )
        )
        if existing is not None:
            if existing.reference != reference:
                raise ReferenceViolation(
                    "Artifact Effect identity is already bound to different content"
                )
            return existing.reference
        managed_path = self._copy_content(source, digest)
        return self._record(
            reference,
            storage_path=managed_path,
            created_by_effect=created_by_effect,
            redacted=redacted,
            managed=True,
        )

    def put(
        self,
        path: Path,
        *,
        kind: str,
        provenance: str,
        retention_hint: str,
        target: str,
        run_id: str,
        created_by_effect: str,
        version: str = "",
        expected_sha256: str = "",
    ) -> ArtifactRef:
        """Persist raw content and return a content-addressed ArtifactRef."""

        if expected_sha256:
            normalized_expected = expected_sha256.removeprefix("sha256:").lower()
            if len(normalized_expected) != 64 or any(
                character not in "0123456789abcdef"
                for character in normalized_expected
            ):
                raise ReferenceViolation("expected Artifact SHA-256 is invalid")
        else:
            normalized_expected = ""

        return self._put(
            path,
            kind=kind,
            provenance=provenance,
            retention_hint=retention_hint,
            target=target,
            run_id=run_id,
            created_by_effect=created_by_effect,
            version=version,
            redacted=False,
            expected_sha256=normalized_expected,
        )

    def register(
        self,
        reference: ArtifactRef,
        *,
        created_by_effect: str,
    ) -> ArtifactRef:
        """Persist metadata for a verified external local ArtifactRef."""

        path = self._path(reference.handle).resolve()
        actual_digest, actual_size = self._digest(path)
        if actual_digest != reference.digest:
            raise ReferenceViolation("ArtifactRef digest does not match stored content")
        if actual_size != reference.size:
            raise ReferenceViolation("ArtifactRef size does not match stored content")
        self._validate_version_metadata(
            path,
            reference,
            actual_digest=actual_digest,
            actual_size=actual_size,
        )
        effect_identity = ArtifactEffectBindingIdentity(
            created_by_effect=created_by_effect,
            kind=reference.kind,
            target=reference.target,
            run_id=reference.run_id,
        )
        existing = self.repository.find(effect_identity)
        if existing is not None:
            candidate = ArtifactRecord(
                reference=reference,
                storage_path=str(path),
                created_by_effect=created_by_effect,
                redacted=False,
                managed=False,
                created_at=existing.created_at,
                last_access=existing.last_access,
                expires_at=existing.expires_at,
                released=existing.released,
            )
            if not existing.has_same_binding(candidate):
                raise ReferenceViolation(
                    "Artifact Effect identity is already bound to different content"
                )
            return existing.reference
        for record in self.repository.records():
            if record.managed:
                continue
            try:
                same_path = Path(record.storage_path).resolve() == path
            except OSError:
                same_path = record.storage_path == str(path)
            if same_path and (
                record.reference.target != reference.target
                or record.reference.run_id != reference.run_id
            ):
                raise ReferenceViolation(
                    "External ArtifactRef local handle is already bound to another scope"
                )
        return self._record(
            reference,
            storage_path=path,
            created_by_effect=created_by_effect,
            redacted=False,
            managed=False,
        )

    @staticmethod
    def _redact_value(value: object) -> object:
        if isinstance(value, Mapping):
            return {
                str(key): (
                    "<redacted>"
                    if is_secret_key(key)
                    else LocalArtifactStore._redact_value(member)
                )
                for key, member in value.items()
            }
        if isinstance(value, list):
            return [LocalArtifactStore._redact_value(member) for member in value]
        if isinstance(value, tuple):
            return [LocalArtifactStore._redact_value(member) for member in value]
        if isinstance(value, str):
            return redact_text(value)
        return value

    def redact(
        self,
        reference: ArtifactRef,
        *,
        kind: str,
        provenance: str,
        created_by_effect: str,
        retention_hint: str | None = None,
        max_bytes: int = 0,
    ) -> ArtifactRef:
        """Derive new redacted bytes; never mutate or relabel source content."""

        if max_bytes < 0:
            raise ValueError("redacted Artifact byte budget must be non-negative")

        source = self.resolve(reference)
        body = source.read_bytes()
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            redacted_body = redact_text(body.decode("utf-8", errors="replace")).encode(
                "utf-8"
            )
        else:
            redacted_body = _json_bytes(self._redact_value(decoded))
        if redacted_body == body:
            redacted_body += b"\n"
        if max_bytes and len(redacted_body) > max_bytes:
            raise ReferenceViolation("Redacted Artifact exceeds its byte budget")
        descriptor, raw_path = tempfile.mkstemp(
            prefix="artifact-redacted-",
            suffix=".json",
            dir=self.content_root,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(redacted_body)
                stream.flush()
                os.fsync(stream.fileno())
            return self._put(
                Path(raw_path),
                kind=kind,
                provenance=provenance,
                retention_hint=retention_hint or reference.retention_hint,
                target=reference.target,
                run_id=reference.run_id,
                created_by_effect=created_by_effect,
                redacted=True,
            )
        finally:
            try:
                os.unlink(raw_path)
            except FileNotFoundError:
                pass

    def find(
        self,
        *,
        kind: str,
        target: str,
        run_id: str,
        created_by_effect: str,
    ) -> ArtifactRef | None:
        record = self.repository.find(
            ArtifactEffectBindingIdentity(
                created_by_effect=created_by_effect,
                kind=kind,
                target=target,
                run_id=run_id,
            )
        )
        return record.reference if record is not None else None

    def resolve(
        self,
        reference: ArtifactRef,
        *,
        expected_kinds: Iterable[str] = (),
        expected_target: str = "",
        expected_run_id: str = "",
        require_redacted: bool = False,
    ) -> Path:
        allowed = frozenset(str(kind).strip() for kind in expected_kinds if str(kind).strip())
        if allowed and reference.kind not in allowed:
            raise ReferenceViolation("ArtifactRef kind does not match the current operation")
        if expected_target and reference.target != expected_target:
            raise ReferenceViolation("ArtifactRef target does not match the Run target")
        if expected_run_id and reference.run_id != expected_run_id:
            raise ReferenceViolation("ArtifactRef run_id does not match the current Run")
        record = self.repository.load(reference)
        if record is None:
            raise ReferenceViolation("ArtifactRef content is unavailable")
        if record is None or record.reference != reference:
            raise ReferenceViolation("ArtifactRef metadata does not match persisted content")
        now = float(self.clock())
        if record.expires_at and record.expires_at <= now:
            raise ReferenceViolation("ArtifactRef retention has expired")
        if require_redacted and not record.redacted:
            raise ReferenceViolation("ArtifactRef is not redacted")
        path = Path(record.storage_path)
        if not path.is_file():
            raise ReferenceViolation("ArtifactRef content is unavailable")
        actual_digest, actual_size = self._digest(path)
        if actual_digest != reference.digest:
            raise ReferenceViolation("ArtifactRef digest does not match stored content")
        if actual_size != reference.size:
            raise ReferenceViolation("ArtifactRef size does not match stored content")
        if not record.managed:
            self._validate_version_metadata(
                path,
                reference,
                actual_digest=actual_digest,
                actual_size=actual_size,
            )
        self.repository.touch(reference, at=now)
        return path

    def release_run(self, run_id: str) -> int:
        return self.repository.release_run(run_id, at=float(self.clock()))

    def garbage_collect(self) -> dict[str, int]:
        now = float(self.clock())
        deleted_records = 0
        deleted_content = 0
        for record in self.repository.records():
            if not record.expires_at or record.expires_at > now:
                continue
            if not self.repository.delete(record.reference):
                continue
            deleted_records += 1
            if record.managed and self.repository.digest_reference_count(
                record.reference.digest
            ) == 0:
                try:
                    Path(record.storage_path).unlink()
                except FileNotFoundError:
                    pass
                else:
                    deleted_content += 1
        return {
            "deleted_records": deleted_records,
            "deleted_content": deleted_content,
        }

    def status(self) -> dict[str, object]:
        records = self.repository.records()
        return {
            "record_count": len(records),
            "managed_record_count": sum(1 for record in records if record.managed),
            "redacted_record_count": sum(1 for record in records if record.redacted),
            "released_record_count": sum(1 for record in records if record.released),
            "retention_counts": {
                hint: sum(
                    1
                    for record in records
                    if record.reference.retention_hint == hint
                )
                for hint in sorted(_RETENTION_HINTS)
            },
        }
