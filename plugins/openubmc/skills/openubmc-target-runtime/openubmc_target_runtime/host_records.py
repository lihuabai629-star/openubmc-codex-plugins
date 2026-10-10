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

from .host_continuity import HostContinuity, _identity
from .measurements import JsonMeasurementReader, ProviderReportReader
from .workspace_context import WorkspaceSnapshot


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


class InstalledHostRecords:
    def __init__(self, state_dir, *, environment=None):
        self.state_dir = Path(state_dir)
        self.environment = dict(os.environ if environment is None else environment)
        self.continuity = HostContinuity(self.state_dir / "host-continuity",
            measurement_reader=self.read_measurements, record_schema_version=2)

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
                # One status observation contains HEAD, branch and worktree state.
                lines = _git(root, "status", "--porcelain=v2", "--branch",
                             "--untracked-files=normal").splitlines()
                headers = dict(line[2:].split(" ", 1) for line in lines if line.startswith("# "))
                commit = headers.get("branch.oid")
                repo["commit"] = commit if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit or "") else None
                branch = headers.get("branch.head")
                repo["branch"] = None if branch == "(detached)" else branch
                repo["dirty"] = any(not line.startswith("# ") for line in lines)
                repo["identity_availability"] = "available" if repo["commit"] else "partial"
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
