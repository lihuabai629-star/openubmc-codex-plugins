#!/usr/bin/env python3
"""Resolve an openUBMC source root without machine-specific defaults."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess


SOURCE_ROOT_ENV = "OPENUBMC_SOURCE_ROOT"
OPENUBMC_REMOTE_RE = re.compile(
    r"(?:^|[/:])openubmc(?:[/.]|$)", re.IGNORECASE
)


def _existing_directory(raw: str) -> Path | None:
    if not raw.strip():
        return None
    candidate = Path(raw).expanduser().resolve()
    return candidate if candidate.is_dir() else None


def discover_git_root(start: str | Path | None = None) -> Path | None:
    """Return the git root containing *start*, or None when it is not a repo."""
    base = Path(start or Path.cwd()).expanduser().resolve()
    if base.is_file():
        base = base.parent
    try:
        completed = subprocess.run(
            ["git", "-C", str(base), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return _existing_directory(completed.stdout.strip())


def is_verified_openubmc_repository(root: Path) -> bool:
    """Return whether a discovered Git root identifies an openUBMC remote.

    Explicit and environment-selected roots are user-authorized inputs.  The
    implicit cwd fallback is different: accepting an arbitrary containing Git
    repository can turn an unrelated zero-hit search into false source evidence.
    Keep that fallback conservative and never expose the remote URLs themselves.
    """

    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "remote", "-v"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if completed.returncode != 0:
        return False
    for raw_line in completed.stdout.splitlines():
        fields = raw_line.split()
        if len(fields) >= 2 and OPENUBMC_REMOTE_RE.search(fields[1]):
            return True
    return False


def resolve_source_root(
    explicit: str = "",
    *,
    cwd: str | Path | None = None,
) -> tuple[Path | None, str]:
    """Resolve source root from explicit input, environment, or repo discovery."""
    if explicit.strip():
        root = _existing_directory(explicit)
        return root, "explicit" if root else "invalid_explicit"

    configured = os.environ.get(SOURCE_ROOT_ENV, "")
    if configured.strip():
        root = _existing_directory(configured)
        return root, "environment" if root else "invalid_environment"

    root = discover_git_root(cwd)
    if root and is_verified_openubmc_repository(root):
        return root, "repository_discovery"
    if root:
        return None, "unverified_repository"
    return None, "unresolved"
