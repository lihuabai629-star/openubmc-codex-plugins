"""Host selection -> real Start ledger -> fresh Task record/export acceptance."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from openubmc_target_runtime import JsonRpcMcpEndpoint, RuntimeMcpService, SQLiteRuntimeRepository
from openubmc_target_runtime.host_continuity import read_runtime_projection
from openubmc_target_runtime.host_records import InstalledHostRecords
from openubmc_target_runtime.record_export import export_task_records, verify_export
from test_mcp_contracts import FakeDebugBackend


class InstalledHostRecordTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.host = InstalledHostRecords(self.state, environment={})
        self.project = self.repository("a")

    def git(self, root, *arguments):
        return subprocess.check_output(["git", "-C", str(root), *arguments], stderr=subprocess.DEVNULL,
                                       text=True).strip()

    def repository(self, name):
        root = self.root / name
        root.mkdir()
        self.git(root, "init", "-q")
        (root / "source.txt").write_text(name)
        self.git(root, "add", ".")
        self.git(root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                 "commit", "-qm", "fixture")
        return root

    def select(self, root, task="task", name="SessionStart"):
        self.host.capture_selection({"hook_event_name": name, "session_id": task, "cwd": str(root)})

    def service(self):
        repository = SQLiteRuntimeRepository(self.state / "context-runtime.sqlite3")
        service = RuntimeMcpService(FakeDebugBackend(), context_repository=repository,
            host_continuity=self.host.continuity, host_context_provider=self.host.workspace_context)
        self.addCleanup(service.close)
        return service

    def start(self, service, operation, task="task", metadata=None):
        endpoint = JsonRpcMcpEndpoint(service, session_task_id=task, bind_session_task=True)
        result = endpoint.handle({"jsonrpc": "2.0", "id": operation, "method": "tools/call",
            "params": {"name": "execute", "arguments": {"kind": "start", "target": "192.0.2.1",
                "intent": "diagnosis-only"}, "_meta": metadata or {}}})["result"]
        self.assertFalse(result["isError"], result)
        return result["structuredContent"]["run_id"]

    def handoff(self, task="task"):
        return self.host.continuity.handoff(task, read_run=lambda run: read_runtime_projection(
            self.state / "context-runtime.sqlite3", run))

    def test_project_switch_and_process_restart_preserve_old_start_binding(self):
        self.select(self.project)
        service = self.service()
        first = self.start(service, "first")
        old = self.handoff()["runs"][0]["run_record"]["workspace_binding"]["snapshot"]
        second_project = self.repository("b")
        self.select(second_project, name="UserPromptSubmit")
        second = self.start(service, "second")
        service.close()
        self.host = InstalledHostRecords(self.state, environment={})
        handoff = self.handoff()
        records = {run["run_id"]: run["run_record"] for run in handoff["runs"]}
        self.assertEqual(records[first]["workspace_binding"]["snapshot"], old)
        self.assertNotEqual(old["project_ref"], records[second]["workspace_binding"]["snapshot"]["project_ref"])
        self.assertEqual(handoff["task_aggregate"]["unique_run_count"], 2)
        self.assertEqual(records[first]["schema_version"], 2)
        self.assertIsNone(handoff["task_aggregate"]["usage_totals"]["input_tokens"])
        document = export_task_records(handoff, producer_commit="a" * 40)
        self.assertEqual(verify_export(document), document["content_digest"])
        self.assertNotIn(str(self.root), json.dumps(document))

    def test_fresh_git_status_tracks_dirty_and_detached_head(self):
        self.select(self.project)
        first = self.host.workspace_context("task")["repositories"][0]
        self.assertFalse(first["dirty"])
        (self.project / "untracked").write_text("fixture")
        self.git(self.project, "checkout", "--detach", "-q")
        second = self.host.workspace_context("task")["repositories"][0]
        self.assertTrue(second["dirty"])
        self.assertIsNone(second["branch"])
        self.assertEqual(second["commit"], self.git(self.project, "rev-parse", "HEAD"))

    def test_inherited_git_repository_override_cannot_change_snapshot(self):
        other = self.repository("other")
        with patch.dict(os.environ, {"GIT_DIR": str(other / ".git"), "GIT_WORK_TREE": str(other)}):
            self.select(self.project)
            context = self.host.workspace_context("task")
        self.assertEqual(context["repositories"][0]["commit"], self.git(self.project, "rev-parse", "HEAD"))

    def test_valid_git_branch_outside_record_bound_does_not_block_start(self):
        for branch in ("a" * 150 + "/" + "b" * 151, "\u5206" * 44 + "/" + "\u540d" * 44):
            with self.subTest(branch_bytes=len(branch.encode("utf-8"))):
                self.git(self.project, "checkout", "-qb", branch)
                self.select(self.project)
                run = self.start(self.service(), "start-" + str(len(branch.encode("utf-8"))))
                record = next(row["run_record"] for row in self.handoff()["runs"] if row["run_id"] == run)
                observed = record["workspace_binding"]["snapshot"]["repositories"][0]
                self.assertIsNone(observed["branch"])
                self.assertEqual(observed["commit"], self.git(self.project, "rev-parse", "HEAD"))
                self.assertFalse(observed["dirty"])

    def test_fsmonitor_program_is_not_executed_by_observer(self):
        if os.name == "nt":
            self.skipTest("POSIX executable fixture")
        sentinel = self.root / "unexpected-execution"
        script = self.root / "fsmonitor"
        script.write_text("#!/bin/sh\ntouch '" + str(sentinel) + "'\n")
        script.chmod(0o700)
        self.git(self.project, "config", "core.fsmonitor", str(script))
        self.select(self.project)
        self.host.workspace_context("task")
        self.assertFalse(sentinel.exists())

    def test_missing_or_invalid_host_selection_never_uses_plugin_cwd_or_old_selection(self):
        self.assertIsNone(self.host.workspace_context("task"))
        self.select(self.project)
        self.host.capture_selection({"hook_event_name": "UserPromptSubmit", "session_id": "task"})
        self.assertIsNone(self.host.workspace_context("task"))
        self.assertIsNone(self.host.workspace_context("different-task"))

    def test_non_repository_project_has_bound_project_without_invented_repo(self):
        self.select(self.root)
        self.assertEqual(self.host.workspace_context("task")["repositories"], [])

    def test_explicit_host_task_cannot_be_rebound_by_transport_metadata(self):
        self.select(self.project)
        self.select(self.repository("other"), task="different-task")
        run = self.start(self.service(), "first", metadata={"threadId": "different-task",
            "workspace_context": {"project_ref": "spoofed"}, "usage": {"input_tokens": 999}})
        handoff = self.handoff()
        self.assertEqual(handoff["runs"][0]["run_id"], run)
        self.assertEqual(handoff["runs"][0]["run_record"]["workspace_binding"]["snapshot"],
                         self.host.workspace_context("task"))
        self.assertIsNone(handoff["task_aggregate"]["usage_totals"]["input_tokens"])
        self.assertEqual(self.handoff("different-task")["runs"], [])

    def report(self, **changes):
        report = {"schema": "openubmc.provider-requests/v1", "task_ref": "task", "provider_ref": "provider:fixture",
            "evidence_kind": "synthetic", "inventory_complete": True, "provider_requests": [
                {"invocation_ref": "invocation:one", "usage": {"input_tokens": 10, "output_tokens": 2,
                    "input_tokens_details": {"cached_tokens": 4}}},
                {"invocation_ref": "invocation:retry", "usage": {"input_tokens": 20, "output_tokens": 3,
                    "input_tokens_details": {"cached_tokens": 5}}}]}
        report.update(changes)
        path = self.root / "producer.json"
        path.write_text(json.dumps(report))
        self.host = InstalledHostRecords(self.state, environment={"OPENUBMC_HOST_PROVIDER_REPORT": str(path),
            "OPENUBMC_HOST_PROVIDER_REF": "provider:fixture", "OPENUBMC_HOST_EVIDENCE_KIND": "synthetic"})
        return report, path

    def test_registered_durable_producer_keeps_task_only_usage_and_deduplicates(self):
        self.select(self.project)
        self.start(self.service(), "first")
        report, path = self.report()
        report["provider_requests"].append(report["provider_requests"][0])
        path.write_text(json.dumps(report))
        handoff = self.handoff()
        usage = handoff["task_aggregate"]["usage_totals"]
        self.assertEqual((usage["input_tokens"], usage["output_tokens"], usage["cached_tokens"]), (30, 5, 9))
        self.assertEqual(usage["invocation_count"], 2)
        self.assertEqual(usage["unattributed_invocation_count"], 2)
        self.assertIsNone(handoff["runs"][0]["run_record"]["usage"]["input_tokens"])
        self.assertEqual(handoff["task_aggregate"]["measurement_source"]["evidence_kind"], "synthetic")
        path.unlink()
        self.assertIsNone(self.handoff()["task_aggregate"]["usage_totals"]["input_tokens"])

    def test_incomplete_inventory_and_wrong_task_remain_unknown(self):
        self.select(self.project)
        self.start(self.service(), "first")
        report, path = self.report(inventory_complete=False)
        self.assertIsNone(self.handoff()["task_aggregate"]["usage_totals"]["invocation_count"])
        report.update(inventory_complete=True, task_ref="other-task")
        path.write_text(json.dumps(report))
        self.assertEqual(self.handoff()["task_aggregate"]["measurement_source"]["status"], "unavailable")

    def test_explicit_null_run_attribution_keeps_each_run_usage_unknown(self):
        self.select(self.project)
        service = self.service()
        self.start(service, "first")
        self.start(service, "second")
        report, path = self.report()
        for row in report["provider_requests"]:
            row["run_ref"] = None
        path.write_text(json.dumps(report))
        handoff = self.handoff()
        self.assertEqual(handoff["task_aggregate"]["usage_totals"]["input_tokens"], 30)
        self.assertEqual(handoff["task_aggregate"]["usage_totals"]["unattributed_invocation_count"], 2)
        for row in handoff["runs"]:
            usage = row["run_record"]["usage"]
            self.assertEqual(usage["status"], "unavailable")
            for field in ("input_tokens", "output_tokens", "cached_tokens", "invocation_count"):
                self.assertIsNone(usage[field])

    def test_unknown_usage_is_not_zero_even_when_physical_inventory_is_complete(self):
        self.select(self.project)
        self.start(self.service(), "first")
        self.report(provider_requests=[{"invocation_ref": "invocation:failed", "usage": None}])
        usage = self.handoff()["task_aggregate"]["usage_totals"]
        self.assertEqual(usage["invocation_count"], 1)
        self.assertIsNone(usage["input_tokens"])
        self.assertIsNone(usage["cached_tokens"])


if __name__ == "__main__":
    unittest.main()
