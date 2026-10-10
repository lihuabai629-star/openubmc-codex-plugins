"""Installed Host composition for workspace facts and producer-owned measurements.

Only a Host hook writes the selection. Runtime reads it at Start; neither Agent
arguments nor transport metadata can supply roots, snapshots or measurement data.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from .host_continuity import HostContinuity, _identity, read_runtime_projection
from .operation_records import RuntimeOperationReader
from .measurements import JsonMeasurementReader, ProviderReportReader
from .workspace_context import WorkspaceSnapshot, _branch_is_representable
from .source_check import SourceCheck
from .test_records import TestRecordRunner


def _ref(kind, value):
    return kind + ":" + hashlib.sha256(value.encode()).hexdigest()


def _git(root, *arguments):
    # Ignore inherited repository overrides. Disable filesystem-monitor helpers
    # and optional index writes: this observer must not run workspace programs.
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_TERMINAL_PROMPT="0")
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
                                 "-C", str(root), *arguments], env=environment,
                                stdout=output, stderr=subprocess.DEVNULL, timeout=5)
        if result.returncode:
            raise ValueError("Host Git observation unavailable")
        output.seek(0)
        return output.read(64 * 1024).decode("utf-8", errors="strict")


def _git_metadata(root):
    # One status observation contains HEAD, branch and worktree state.
    lines = _git(root, "status", "--porcelain=v2", "--branch", "--untracked-files=normal").splitlines()
    headers = dict(line[2:].split(" ", 1) for line in lines if line.startswith("# "))
    commit, branch = headers.get("branch.oid"), headers.get("branch.head")
    commit = commit if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit or "") else None
    return {"commit": commit,
            "branch": branch if branch != "(detached)" and _branch_is_representable(branch) else None,
            "dirty": any(not line.startswith("# ") for line in lines),
            "identity_availability": "available" if commit else "partial"}


class InstalledHostRecords:
    def __init__(self, state_dir, *, environment=None):
        self.state_dir = Path(state_dir)
        self.environment = dict(os.environ if environment is None else environment)
        self.continuity = HostContinuity(self.state_dir / "host-continuity",
            measurement_reader=self.read_measurements, record_schema_version=2,
            evidence_reader=RuntimeOperationReader(lambda run: read_runtime_projection(
                self.state_dir / "context-runtime.sqlite3", run),
                extra_reader=lambda task, refs: TestRecordRunner(self).read(task, refs)))

    def capture_selection(self, event):
        if event.get("hook_event_name") not in {"SessionStart", "UserPromptSubmit"}:
            return
        task_id = _identity(event.get("session_id"))
        raw = event.get("cwd")
        cwd, repository = None, None
        if (isinstance(raw, str) and len(raw.encode()) <= 4096
                and not any(ord(c) < 32 for c in raw) and Path(raw).is_absolute()):
            cwd = str(Path(raw).resolve())
            try:
                repository = _git(cwd, "rev-parse", "--show-toplevel").strip()
                if not Path(repository).is_absolute():
                    repository = None
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
        with self.continuity._database() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS workspace_selections "
                "(task_id TEXT PRIMARY KEY, cwd TEXT, repository TEXT)")
            if connection.execute("SELECT COUNT(*) FROM workspace_selections").fetchone()[0] >= 1024:
                if not connection.execute("SELECT 1 FROM workspace_selections WHERE task_id=?", (task_id,)).fetchone():
                    raise ValueError("Host selection capacity reached")
            # Missing/malformed cwd invalidates an old selection rather than
            # silently reusing a different project's source identity.
            connection.execute("INSERT INTO workspace_selections VALUES (?, ?, ?) "
                "ON CONFLICT(task_id) DO UPDATE SET cwd=excluded.cwd, repository=excluded.repository",
                (task_id, cwd, repository))
            connection.execute("CREATE TABLE IF NOT EXISTS source_locators "
                "(repo_ref TEXT PRIMARY KEY, root TEXT NOT NULL)")
            if repository:
                ref = _ref("repo", repository)
                known = connection.execute("SELECT 1 FROM source_locators WHERE repo_ref=?", (ref,)).fetchone()
                if known or connection.execute("SELECT COUNT(*) FROM source_locators").fetchone()[0] < 1024:
                    connection.execute("INSERT OR IGNORE INTO source_locators VALUES (?, ?)", (ref, repository))

    def workspace_context(self, task_id):
        _identity(task_id)
        if not (self.continuity.root / "bookmarks.sqlite3").is_file():
            return None
        with self.continuity._database() as connection:
            if not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                                      "AND name='workspace_selections'").fetchone():
                return None
            selected = connection.execute("SELECT cwd, repository FROM workspace_selections "
                                          "WHERE task_id=?", (task_id,)).fetchone()
        if not selected or not selected["cwd"]:
            return None
        repositories = []
        if selected["repository"]:
            root = selected["repository"]
            repo = {"repo_ref": _ref("repo", root), "repo_class": "unknown",
                    "commit": None, "branch": None, "dirty": None,
                    "identity_availability": "unavailable", "identity_source_ref": "host:git-status-v2"}
            try:
                repo.update(_git_metadata(root))
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
            repositories.append(repo)
        body = {"schema_version": 1, "selection_ref": _ref("selection", selected["cwd"]),
                "project_ref": _ref("project", selected["cwd"]),
                "requested_machine_ref": None, "requested_firmware_ref": None,
                "repositories": repositories}
        body["context_digest"] = hashlib.sha256(json.dumps(body, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        return WorkspaceSnapshot(body).to_public_dict()

    def read_measurements(self, task_id, run_refs):
        snapshot = self.environment.get("OPENUBMC_HOST_MEASUREMENTS_FILE")
        report = self.environment.get("OPENUBMC_HOST_PROVIDER_REPORT")
        # Registration is process composition, never an action/note/_meta field.
        if snapshot and report:
            raise ValueError("Ambiguous Host measurement registration")
        if snapshot:
            return JsonMeasurementReader(Path(snapshot))(task_id, run_refs)
        if report:
            return ProviderReportReader(Path(report), task_id=task_id,
                provider_ref=self.environment.get("OPENUBMC_HOST_PROVIDER_REF"),
                evidence_kind=self.environment.get("OPENUBMC_HOST_EVIDENCE_KIND", "observed"),
                producer_inventory=True)(task_id, run_refs)
        return None

    def check_source(self, snapshot):
        """Locate only repositories already registered by a trusted Host hook."""
        with self.continuity._database() as connection:
            if not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                                      "AND name='source_locators'").fetchone():
                return SourceCheck("unavailable", "repository_unavailable")
            for repo in snapshot["repositories"]:
                if repo["commit"] is None or repo["dirty"] is None:
                    return SourceCheck("unavailable", "identity_unavailable")
                locator = connection.execute("SELECT root FROM source_locators WHERE repo_ref=?",
                                             (repo["repo_ref"],)).fetchone()
                if not locator:
                    return SourceCheck("unavailable", "repository_unavailable")
                root = locator["root"]
                try:
                    if _git(root, "rev-parse", "--show-toplevel").strip() != root:
                        return SourceCheck("unavailable", "repository_unavailable")
                    current = _git_metadata(root)
                    if current["commit"] != repo["commit"]:
                        return SourceCheck("drift", "commit_changed")
                    if current["dirty"] != repo["dirty"]:
                        return SourceCheck("drift", "dirty_changed")
                except (OSError, ValueError, subprocess.SubprocessError):
                    return SourceCheck("unavailable", "repository_unavailable")
        return SourceCheck("matched", "metadata_matched")

    def repository_root(self, repo_ref):
        with self.continuity._database() as connection:
            row = connection.execute("SELECT root FROM source_locators WHERE repo_ref=?", (repo_ref,)).fetchone()
        if row is None:
            raise ValueError("Registered repository unavailable")
        return Path(row["root"])
