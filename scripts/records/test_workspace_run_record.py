import copy
import json
from pathlib import Path
import tempfile
import unittest

from openubmc_target_runtime import JsonRpcMcpEndpoint, RuntimeMcpService, SQLiteRuntimeRepository
from openubmc_target_runtime.host_continuity import HostContinuity, read_runtime_projection
from test_mcp_contracts import FakeDebugBackend
from openubmc_target_runtime.source_check import SourceCheck


class BindingObservingBackend(FakeDebugBackend):
    """Controlled Domain adapter reads the public ledger at its first Effect."""

    def __init__(self, repository):
        super().__init__()
        self.repository = repository
        self.bindings_seen = []

    def debug_run(self, task, arguments, context):
        run_id = self.repository.case_for_task(task.task_id) or task.task_id
        projection = read_runtime_projection(self.repository.path, run_id)
        self.bindings_seen.append(projection["start_input"].get("workspace_context"))
        return super().debug_run(task, arguments, context)


class UnavailableBookmarkHost(HostContinuity):
    def capture(self, task_id, result, *, read_run):
        raise OSError("SYNTHETIC-W01-HOST-STORE-DETAIL")


class RefusingRunCommitRepository(SQLiteRuntimeRepository):
    def __init__(self, path):
        super().__init__(path)
        self.refused_run_ids = []

    def commit(self, run_id, *, expected_revision, events):
        self.refused_run_ids.append(run_id)
        raise OSError("injected Run commit failure")


class WorkspaceRunRecordTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repository = SQLiteRuntimeRepository(self.root / "runtime.sqlite3")
        self.host = HostContinuity(self.root / "host")
        self.backend = BindingObservingBackend(self.repository)
        fixture = Path(__file__).parent / "fixtures/workspace-selection-a.json"
        self.selection = json.loads(fixture.read_text(encoding="utf-8"))

    def service(self, **options):
        provider = options.pop("host_context_provider", lambda task_id: self.selection)
        host = options.pop("host_continuity", self.host)
        service = RuntimeMcpService(
            self.backend, context_repository=self.repository, host_continuity=host,
            host_context_provider=provider, source_checker=lambda _: SourceCheck("matched", "metadata_matched"), **options,
        )
        self.addCleanup(service.close)
        return JsonRpcMcpEndpoint(service, session_task_id="task")

    def call(self, endpoint, action, operation="start-A", task="task"):
        return endpoint.handle({"jsonrpc": "2.0", "id": operation, "method": "tools/call",
            "params": {"name": "execute", "arguments": action,
                       "_meta": {"threadId": task, "openubmc/operationId": operation}}})["result"]

    def handoff(self, task="task"):
        return self.host.handoff(task, read_run=lambda run_id:
            read_runtime_projection(self.repository.path, run_id))

    def start(self, endpoint, operation="start-A", task="task"):
        return self.call(endpoint, {"kind": "start", "target": "192.0.2.1", "intent": "diagnosis-only",
                                    "entry_operation": "debug_run"}, operation, task)

    def test_host_snapshot_is_bound_before_first_effect(self):
        endpoint = self.service()
        result = self.start(endpoint)
        self.assertFalse(result["isError"], result)
        self.assertEqual(self.backend.bindings_seen, [self.selection], result)
        record = self.handoff()["runs"][0]["run_record"]
        self.assertEqual(record["workspace_binding"], {"status": "bound", "snapshot": self.selection})
        self.assertEqual(record["usage"]["status"], "unavailable")
        self.assertIsNone(record["usage"]["input_tokens"])

    def test_one_task_keeps_two_project_runs_and_deduplicates_repeated_start(self):
        endpoint = self.service()
        first = self.start(endpoint)
        repeated = self.start(endpoint)
        self.assertFalse(repeated["isError"], repeated)
        self.assertEqual(first["structuredContent"]["run_id"], repeated["structuredContent"]["run_id"])
        original = copy.deepcopy(self.selection)
        self.selection = json.loads((Path(__file__).parent / "fixtures/workspace-selection-b.json").read_text())
        second = self.start(endpoint, "start-B")
        self.assertFalse(second["isError"], second)
        first_id, second_id = (result["structuredContent"]["run_id"] for result in (first, second))
        self.assertNotEqual(first_id, second_id)
        handoff = self.handoff()
        records = {run["run_id"]: run["run_record"] for run in handoff["runs"]}
        self.assertEqual(records[first_id]["workspace_binding"]["snapshot"], original)
        self.assertEqual(records[second_id]["workspace_binding"]["snapshot"], self.selection)
        self.assertEqual(self.backend.bindings_seen, [original, self.selection])
        self.assertEqual(handoff["task_aggregate"], {
            "schema_version": 1, "task_ref": "task", "run_refs": sorted([first_id, second_id]),
            "unique_run_count": 2, "usage_totals": {"status": "unavailable", "input_tokens": None,
                "output_tokens": None, "cached_tokens": None, "source_ref": None},
        })

    def test_resume_and_fresh_host_preserve_original_binding_after_selection_mutates(self):
        calls = []
        def provider(task_id):
            calls.append(task_id)
            if len(calls) > 1:
                raise RuntimeError("provider must not be consulted by resume")
            return self.selection
        endpoint = self.service(host_context_provider=provider)
        started = self.start(endpoint)
        self.assertFalse(started["isError"], started)
        run_id = started["structuredContent"]["run_id"]
        original = copy.deepcopy(self.selection)
        self.selection["repositories"][0]["dirty"] = True
        resumed = self.call(endpoint, {"kind": "resume", "run_id": run_id}, "resume-A")
        self.assertFalse(resumed["isError"], resumed)
        self.assertEqual(calls, ["task"])
        fresh = HostContinuity(self.root / "host")
        read = lambda rid: read_runtime_projection(self.repository.path, rid)
        before = self.repository.current_revision(run_id)
        handoff = fresh.handoff("task", read_run=read)
        record = handoff["runs"][0]["run_record"]
        self.assertEqual(record["workspace_binding"]["snapshot"], original)
        record["workspace_binding"]["snapshot"]["repositories"][0]["commit"] = "c" * 40
        again = fresh.handoff("task", read_run=read)
        self.assertEqual(again["runs"][0]["run_record"]["workspace_binding"]["snapshot"], original)
        self.assertEqual(self.repository.current_revision(run_id), before)
        self.assertEqual(self.backend.bindings_seen, [original])

    def test_legacy_call_is_unbound_and_never_backfilled_from_current_selection(self):
        endpoint = self.service(host_context_provider=None)
        started = self.start(endpoint)
        self.assertFalse(started["isError"], started)
        run_id = started["structuredContent"]["run_id"]
        projection = read_runtime_projection(self.repository.path, run_id)
        self.assertNotIn("workspace_context", projection["start_input"])
        self.selection = json.loads((Path(__file__).parent / "fixtures/workspace-selection-b.json").read_text())
        fresh = self.service()
        resumed = self.call(fresh, {"kind": "resume", "run_id": run_id}, "legacy-resume")
        self.assertFalse(resumed["isError"], resumed)
        record = self.handoff()["runs"][0]["run_record"]
        self.assertEqual(record["workspace_binding"], {"status": "unavailable", "snapshot": None})
        self.assertEqual(record["runtime_availability"], "available")
        self.assertEqual(record["run_id"], run_id)
        self.assertEqual(self.backend.bindings_seen, [None])

    def test_partial_and_unavailable_repository_identity_stays_explicit(self):
        self.selection = json.loads((Path(__file__).parent / "fixtures/workspace-selection-unknown.json").read_text())
        endpoint = self.service()
        result = self.start(endpoint)
        self.assertFalse(result["isError"], result)
        handoff = self.handoff()
        record = handoff["runs"][0]["run_record"]
        self.assertEqual(record["workspace_binding"]["snapshot"], self.selection)
        self.assertEqual(set(record), {"schema_version", "run_id", "task_ref", "runtime_availability",
            "workspace_binding", "workflow_definition_ref", "runtime_state", "outcome_ref", "usage"})
        self.assertEqual(record["runtime_state"], result["structuredContent"]["state"])
        self.assertIsNotNone(record["workflow_definition_ref"])
        self.assertEqual(record["usage"], handoff["task_aggregate"]["usage_totals"])
        for field in ("input_tokens", "output_tokens", "cached_tokens", "source_ref"):
            self.assertIsNone(record["usage"][field])

    def test_invalid_host_snapshots_reject_before_run_or_effect_without_echoing_values(self):
        bad_digest = copy.deepcopy(self.selection)
        bad_digest["context_digest"] = "0" * 64
        unknown = copy.deepcopy(self.selection)
        unknown["endpoint"] = "SYNTHETIC-W01-PRIVATE-ENDPOINT"
        secret = copy.deepcopy(self.selection)
        secret["ssh_password"] = "SYNTHETIC-W01-PASSWORD"
        bad_class = copy.deepcopy(self.selection)
        bad_class["repositories"][0]["repo_class"] = []
        bad_availability = copy.deepcopy(self.selection)
        bad_availability["repositories"][0]["identity_availability"] = {}
        duplicate = copy.deepcopy(self.selection)
        duplicate["repositories"].append(copy.deepcopy(duplicate["repositories"][0]))
        endpoint = self.service()
        for label, snapshot in (("digest", bad_digest), ("unknown", unknown), ("secret", secret),
                                ("class", bad_class), ("availability", bad_availability), ("duplicate", duplicate)):
            with self.subTest(label=label):
                self.selection = snapshot
                result = self.start(endpoint, "invalid-" + label)
                self.assertTrue(result["isError"], result)
                expected = "secret_material_rejected" if label == "secret" else "invalid_workspace_context"
                self.assertEqual(result["structuredContent"]["error"]["code"], expected)
                encoded = json.dumps(result)
                self.assertNotIn("SYNTHETIC-W01-PASSWORD", encoded)
                self.assertNotIn("SYNTHETIC-W01-PRIVATE-ENDPOINT", encoded)
                self.assertEqual(self.handoff()["runs"], [])
                self.assertIsNone(self.repository.case_for_task("task"))
                self.assertEqual(self.backend.created, [])
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"SYNTHETIC-W01-PASSWORD", path.read_bytes(), str(path))

    def test_record_exposes_existing_pinned_workflow_identity_without_definition_body(self):
        endpoint = self.service()
        started = self.start(endpoint)
        self.assertFalse(started["isError"], started)
        run_id = started["structuredContent"]["run_id"]
        definition = read_runtime_projection(self.repository.path, run_id)["workflow_definition"]
        reference = self.handoff()["runs"][0]["run_record"]["workflow_definition_ref"]
        self.assertEqual(reference, {"schema": definition["schema"], "definition_id": definition["definition_id"],
                                    "version": definition["version"], "fingerprint": definition["fingerprint"]})
        self.assertNotIn("steps", reference)

    def test_unavailable_fresh_readback_keeps_identity_and_clears_authoritative_fields(self):
        endpoint = self.service()
        started = self.start(endpoint)
        self.assertFalse(started["isError"], started)
        run_id = started["structuredContent"]["run_id"]
        before = self.repository.current_revision(run_id)
        def failed_read(_run_id):
            raise OSError("SYNTHETIC-W01-PRIVATE-READBACK-DETAIL")
        for read in (lambda _run_id: None, failed_read):
            with self.subTest(read=read.__name__):
                handoff = self.host.handoff("task", read_run=read)
                self.assertEqual(handoff["task_aggregate"]["run_refs"], [run_id])
                self.assertEqual(handoff["runs"][0]["run_record"], {
                    "schema_version": 1, "run_id": run_id, "task_ref": "task", "runtime_availability": "unavailable",
                    "workspace_binding": {"status": "unavailable", "snapshot": None},
                    "workflow_definition_ref": None, "runtime_state": None, "outcome_ref": None,
                    "usage": {"status": "unavailable", "input_tokens": None, "output_tokens": None,
                              "cached_tokens": None, "source_ref": None},
                })
                self.assertNotIn("SYNTHETIC-W01-PRIVATE-READBACK-DETAIL", json.dumps(handoff))
        self.assertEqual(self.repository.current_revision(run_id), before)
        self.assertEqual(self.backend.bindings_seen, [self.selection])

    def test_agent_action_metadata_and_notes_cannot_supply_workspace_authority(self):
        endpoint = self.service(host_context_provider=None)
        injected = self.call(endpoint, {"kind": "start", "target": "192.0.2.1", "intent": "diagnosis-only",
                                       "workspace_context": self.selection}, "injected-action")
        self.assertTrue(injected["isError"], injected)
        self.assertEqual(self.backend.created, [])
        self.assertEqual(self.handoff()["runs"], [])
        response = endpoint.handle({"jsonrpc": "2.0", "id": "metadata", "method": "tools/call", "params": {
            "name": "execute", "arguments": {"kind": "start", "target": "192.0.2.1", "intent": "diagnosis-only",
                                                 "entry_operation": "debug_run"},
            "_meta": {"threadId": "task", "openubmc/operationId": "metadata",
                      "workspace_context": self.selection, "context_digest": self.selection["context_digest"]},
        }})["result"]
        self.assertFalse(response["isError"], response)
        self.host.save_notes("task", {"goal": "select project-A", "hypotheses": [self.selection]})
        handoff = self.handoff()
        self.assertFalse(handoff["notes_authoritative"])
        self.assertEqual(handoff["runs"][0]["run_record"]["workspace_binding"],
                         {"status": "unavailable", "snapshot": None})
        self.assertEqual({tool["name"] for tool in endpoint.service.tool_definitions()}, {"observe", "execute"})

    def test_host_capture_failure_preserves_committed_result_and_retry_does_not_redispatch(self):
        endpoint = self.service(host_continuity=UnavailableBookmarkHost(self.root / "unavailable-host"))
        started = self.start(endpoint)
        self.assertFalse(started["isError"], started)
        run_id = started["structuredContent"]["run_id"]
        before = self.repository.current_revision(run_id)
        repeated = self.start(endpoint)
        self.assertFalse(repeated["isError"], repeated)
        self.assertEqual(repeated["structuredContent"], started["structuredContent"])
        self.assertNotIn("SYNTHETIC-W01-HOST-STORE-DETAIL", json.dumps(repeated))
        self.assertEqual(self.repository.current_revision(run_id), before)
        self.assertEqual(self.backend.bindings_seen, [self.selection])
        self.host.capture("task", {"run_id": run_id}, read_run=lambda rid:
                          read_runtime_projection(self.repository.path, rid))
        self.assertEqual(self.handoff()["runs"][0]["run_record"]["workspace_binding"]["snapshot"], self.selection)

    def test_failed_start_transaction_cannot_publish_binding_or_dispatch_effect(self):
        self.repository = RefusingRunCommitRepository(self.root / "refusing-runtime.sqlite3")
        self.backend = BindingObservingBackend(self.repository)
        endpoint = self.service()
        started = self.start(endpoint)
        self.assertTrue(started["isError"], started)
        self.assertTrue(self.repository.refused_run_ids)
        for run_id in set(self.repository.refused_run_ids):
            self.assertIsNone(read_runtime_projection(self.repository.path, run_id))
        self.assertIsNone(self.repository.case_for_task("task"))
        self.assertEqual(self.handoff()["runs"], [])
        self.assertEqual(self.backend.bindings_seen, [])

    def test_terminal_record_has_outcome_reference_without_claiming_host_delivery(self):
        endpoint = self.service()
        started = self.start(endpoint)
        self.assertFalse(started["isError"], started)
        turn = started["structuredContent"]
        gate = turn["gate"]
        cancelled = self.call(endpoint, {"kind": "control", "run_id": turn["run_id"], "command": "cancel",
            **{key: gate[key] for key in ("gate_id", "gate_version", "schema_digest")}}, "cancel-A")
        self.assertFalse(cancelled["isError"], cancelled)
        before = self.repository.current_revision(turn["run_id"])
        handoff = self.handoff()
        run = handoff["runs"][0]
        record = run["run_record"]
        self.assertEqual(record["runtime_state"], "cancelled")
        self.assertRegex(record["outcome_ref"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(record["workspace_binding"]["snapshot"], self.selection)
        self.assertFalse(run["terminal_answer"]["delivery_confirmed"])
        self.assertNotIn("delivered", record)
        self.assertEqual(self.repository.current_revision(turn["run_id"]), before)
        self.assertEqual(self.backend.bindings_seen, [self.selection])

    def test_host_provider_is_task_scoped_and_aggregates_do_not_cross_tasks(self):
        snapshot_b = json.loads((Path(__file__).parent / "fixtures/workspace-selection-b.json").read_text())
        selections = {"task-A": self.selection, "task-B": snapshot_b}
        requested_tasks = []
        def provider(task_id):
            requested_tasks.append(task_id)
            return selections[task_id]
        endpoint = self.service(host_context_provider=provider)
        first = self.start(endpoint, "task-A-start", "task-A")
        second = self.start(endpoint, "task-B-start", "task-B")
        for task_id, result in (("task-A", first), ("task-B", second)):
            self.assertFalse(result["isError"], result)
            run_id = result["structuredContent"]["run_id"]
            handoff = self.handoff(task_id)
            self.assertEqual(handoff["task_aggregate"]["run_refs"], [run_id])
            self.assertEqual(handoff["task_aggregate"]["task_ref"], task_id)
            self.assertEqual(handoff["runs"][0]["run_record"]["workspace_binding"]["snapshot"], selections[task_id])
        self.assertEqual(requested_tasks, ["task-A", "task-B"])
        self.assertEqual(self.handoff()["task_aggregate"]["unique_run_count"], 0)

    def test_same_start_identity_with_changed_context_conflicts_without_dispatch(self):
        endpoint = self.service()
        started = self.start(endpoint)
        self.assertFalse(started["isError"], started)
        original = copy.deepcopy(self.selection)
        run_id = started["structuredContent"]["run_id"]
        before = self.repository.current_revision(run_id)
        self.selection = json.loads((Path(__file__).parent / "fixtures/workspace-selection-b.json").read_text())
        conflicted = self.start(endpoint)
        self.assertTrue(conflicted["isError"], conflicted)
        self.assertEqual(conflicted["structuredContent"]["error"]["code"], "CommandConflict")
        self.assertEqual(self.repository.current_revision(run_id), before)
        handoff = self.handoff()
        self.assertEqual(handoff["task_aggregate"]["run_refs"], [run_id])
        self.assertEqual(handoff["runs"][0]["run_record"]["workspace_binding"]["snapshot"], original)
        self.assertEqual(self.backend.bindings_seen, [original])


if __name__ == "__main__":
    unittest.main()
