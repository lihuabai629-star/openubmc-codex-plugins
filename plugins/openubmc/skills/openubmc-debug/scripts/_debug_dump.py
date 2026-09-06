#!/usr/bin/env python3
"""Helpers for writing ordered debug dump artifacts."""
from __future__ import annotations

import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _slug(value: str) -> str:
    cooked = SAFE_RE.sub("_", value.strip()).strip("._-")
    return cooked or "artifact"


class DebugDumper:
    def __init__(self, output_dir: str, secrets: Iterable[str] | None = None) -> None:
        self.root = Path(output_dir)
        if self.root.is_symlink():
            raise ValueError(f"debug dump directory must not be a symbolic link: {self.root}")
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        if not self.root.is_dir():
            raise ValueError(f"debug dump path is not a directory: {self.root}")
        self.root.chmod(0o700)
        self._counter = 0
        self._artifacts: list[dict[str, object]] = []
        self._lock = threading.Lock()
        # Keep the legacy argument for callers, but internal development mode
        # intentionally preserves dump content verbatim.
        del secrets
        self._summary_path = self.root / "summary.json"
        if self._summary_path.is_symlink():
            raise ValueError(f"debug dump summary must not be a symbolic link: {self._summary_path}")
        self._created_at = self._timestamp()

    def _timestamp(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _next_path(self, label: str, name: str, suffix: str) -> Path:
        path = self.root / f"{self._counter:03d}_{_slug(label)}_{_slug(name)}{suffix}"
        self._counter += 1
        return path

    def _write_summary(self) -> None:
        summary = {
            "created_at": self._created_at,
            "updated_at": self._timestamp(),
            "artifact_count": len(self._artifacts),
            "redacted_artifact_count": sum(1 for item in self._artifacts if item["redacted"]),
            "artifacts": self._artifacts,
        }
        temporary = self.root / f".summary-{uuid.uuid4().hex}.tmp"
        try:
            self._write_private_bytes(temporary, (json.dumps(summary, indent=2) + "\n").encode("utf-8"))
            os.replace(temporary, self._summary_path)
            self._summary_path.chmod(0o600)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _write_private_bytes(self, path: Path, content: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(content)
        finally:
            if fd >= 0:
                os.close(fd)
        path.chmod(0o600)

    def _record(
        self,
        path: Path,
        label: str,
        name: str,
        kind: str,
        metadata: dict[str, object] | None = None,
    ) -> None:
        artifact = {
            "index": len(self._artifacts),
            "filename": path.name,
            "label": label,
            "name": name,
            "kind": kind,
            "size_bytes": path.stat().st_size,
            "redacted": False,
            "timestamp": self._timestamp(),
        }
        if metadata:
            artifact["metadata"] = metadata
        self._artifacts.append(artifact)
        self._write_summary()

    def write_text(self, label: str, name: str, content: str, metadata: dict[str, object] | None = None) -> Path:
        with self._lock:
            path = self._next_path(label, name, ".txt")
            self._write_private_bytes(path, content.encode("utf-8"))
            self._record(
                path,
                label,
                name,
                "text",
                metadata=metadata,
            )
        return path

    def write_bytes(self, label: str, name: str, content: bytes, metadata: dict[str, object] | None = None) -> Path:
        with self._lock:
            path = self._next_path(label, name, ".bin")
            self._write_private_bytes(path, content)
            self._record(
                path,
                label,
                name,
                "bytes",
                metadata=metadata,
            )
        return path


def build_debug_dumper(output_dir: str, secrets: Iterable[str] | None = None):
    return DebugDumper(output_dir, secrets=secrets) if output_dir else None
