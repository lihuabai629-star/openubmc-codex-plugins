"""Trusted local test execution producer; it cannot change Run state or Outcome."""
import hashlib
import json
import os
import signal
import subprocess
import threading
import time
import uuid

from .host_continuity import _identity, read_runtime_projection
from .operation_records import _digest
from .redaction import require_secret_free
from .source_check import check_source


MAX_TEST_OUTPUT = 16 * 1024 * 1024


class TestRecordRunner:
    def __init__(self, host, *, evidence_kind="observed"):
        if evidence_kind not in {"observed", "synthetic"}:
            raise ValueError("Invalid test evidence kind")
        self.host, self.evidence_kind = host, evidence_kind

    def run(self, task_id, run_id, repo_ref, command_ref, argv, *, timeout=600):
        for ref in (task_id, run_id, repo_ref, command_ref):
            _identity(ref)
        if (not isinstance(argv, list) or not argv or len(argv) > 128
                or any(not isinstance(arg, str) or len(arg.encode()) > 4096 or "\0" in arg for arg in argv)
                or type(timeout) not in {int, float} or not 0 < timeout <= 3600):
            raise ValueError("Invalid test command")
        require_secret_free(argv, boundary="test command")
        projection = read_runtime_projection(self.host.state_dir / "context-runtime.sqlite3", run_id)
        if projection is None or check_source(projection, self.host.check_source).status != "matched":
            raise ValueError("Original source metadata unavailable")
        repo = next((row for row in projection["start_input"]["workspace_context"]["repositories"]
                     if row["repo_ref"] == repo_ref), {})
        if repo.get("dirty") is not False or not repo.get("commit"):
            raise ValueError("Exact clean source is required for test provenance")
        root = self.host.repository_root(repo_ref)
        entry = {"event_ref": "test:" + uuid.uuid4().hex, "run_ref": run_id, "repo_ref": repo_ref,
            "source_commit": repo["commit"], "command_ref": command_ref, "command_digest": _digest(argv),
            "kind": "test", "status": "unavailable", "execution_status": "unknown",
            "evidence_ref": None, "log_digest": None, "evidence_kind": self.evidence_kind}
        with self.host.continuity._database() as connection:
            if not connection.execute("SELECT 1 FROM runs WHERE task_id=? AND run_id=?", (task_id, run_id)).fetchone():
                raise ValueError("Test Run is not bookmarked for this Task")
            connection.execute("CREATE TABLE IF NOT EXISTS test_receipts "
                "(event_ref TEXT PRIMARY KEY, task_id TEXT NOT NULL, body TEXT NOT NULL)")
            if connection.execute("SELECT COUNT(*) FROM test_receipts WHERE task_id=?", (task_id,)).fetchone()[0] >= 256:
                raise ValueError("Test receipt capacity reached")
            connection.execute("INSERT INTO test_receipts VALUES (?, ?, ?)",
                               (entry["event_ref"], task_id, json.dumps(entry)))
        # Persist physical invocation identity before starting. Crash/incomplete
        # execution stays unknown, never a successful or zero-work test.
        digest = hashlib.sha256()
        count, overflow = [0], [False]
        exit_code = None
        capture_interrupted = False
        deadline = time.monotonic() + timeout
        try:
            process = subprocess.Popen(argv, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       start_new_session=os.name != "nt")
            def stop():
                if os.name != "nt":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                elif process.poll() is None:
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                if process.poll() is None:
                    process.kill()
            def consume():
                while block := process.stdout.read(32768):
                    count[0] += len(block)
                    if count[0] > MAX_TEST_OUTPUT:
                        overflow[0] = True
                        stop()
                        break
                    digest.update(block)
            reader = threading.Thread(target=consume, daemon=True)
            reader.start()
            try:
                exit_code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                capture_interrupted = True
                stop()
                process.wait(timeout=5)
            reader.join(timeout=max(0, min(5, deadline - time.monotonic())))
            if reader.is_alive():
                capture_interrupted = True
                stop()
                reader.join(timeout=1)
            complete = not capture_interrupted and not reader.is_alive() and not overflow[0] and exit_code is not None
            if not reader.is_alive():
                process.stdout.close()
            # Closing a pipe while another thread is reading it may block on a
            # descendant's inherited handle. Incomplete capture remains unknown;
            # its daemon reader owns cleanup when that handle closes.
            if complete and check_source(projection, self.host.check_source).status == "matched":
                entry.update(status="passed" if exit_code == 0 else "failed", execution_status="executed",
                    log_digest="sha256:" + digest.hexdigest(), evidence_ref="test-log:" + digest.hexdigest())
        except OSError:
            entry["execution_status"] = "not_executed" if exit_code is None else "unknown"
        with self.host.continuity._database() as connection:
            connection.execute("UPDATE test_receipts SET body=? WHERE event_ref=?",
                               (json.dumps(entry), entry["event_ref"]))
        return {"event_ref": entry["event_ref"], "status": entry["status"], "exit_code": exit_code}

    def read(self, task_id, run_refs):
        with self.host.continuity._database() as connection:
            if not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='test_receipts'").fetchone():
                return []
            rows = connection.execute("SELECT body FROM test_receipts WHERE task_id=? ORDER BY event_ref LIMIT 257",
                                      (task_id,)).fetchall()
        entries = [json.loads(row["body"]) for row in rows]
        return [row for row in entries if row["run_ref"] in run_refs]
