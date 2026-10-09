import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

from openubmc_target_runtime import JsonRpcMcpEndpoint, RuntimeMcpService, SQLiteRuntimeRepository
from openubmc_target_runtime.host_continuity import HostContinuity, read_runtime_projection
from test_mcp_contracts import FakeDebugBackend


def seal(body):
    result = copy.deepcopy(body)
    result.pop("source_ref", None)
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    result["source_ref"] = "sha256:" + hashlib.sha256(encoded.encode()).hexdigest()
    return result


def coverage(usage="complete", timing="unavailable", interventions="unavailable"):
    return {"usage": usage, "timing": timing, "interventions": interventions}


def invocation(run_id, identity="call-a", tokens=(100, 20, 40)):
    return {"provider_ref": "provider-a", "invocation_ref": identity, "run_ref": run_id,
            "model_ref": "model-a", "reasoning_ref": "low", "input_tokens": tokens[0],
            "output_tokens": tokens[1], "cached_tokens": tokens[2], "source_ref": "source-" + identity}


class RunMeasurementTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.repository = SQLiteRuntimeRepository(self.root / "runtime.sqlite3")
        self.backend = FakeDebugBackend()
        self.snapshot = None
        self.reads = []

    def reader(self, task, run_refs):
        self.reads.append((task, run_refs))
        return self.snapshot

    def host(self, **options):
        return HostContinuity(self.root / "host", measurement_reader=self.reader,
                              record_schema_version=2, **options)

    def endpoint(self, host, **options):
        service = RuntimeMcpService(self.backend, context_repository=self.repository, host_continuity=host, **options)
        self.addCleanup(service.close)
        return JsonRpcMcpEndpoint(service, session_task_id="task")

    def start(self, endpoint, identity="start-a"):
        result = endpoint.handle({"jsonrpc": "2.0", "id": identity, "method": "tools/call",
            "params": {"name": "execute", "arguments": {"kind": "start", "target": "192.0.2.1",
                        "intent": "diagnosis-only", "entry_operation": "debug_run"},
                       "_meta": {"threadId": "task", "openubmc/operationId": identity}}})["result"]
        self.assertFalse(result["isError"], result)
        return result["structuredContent"]["run_id"]

    def body(self, *run_ids):
        return {"schema_version": 1, "task_ref": "task", "evidence_kind": "synthetic",
                "task_coverage": coverage(),
                "run_coverage": [{"run_ref": run_id, **coverage()} for run_id in run_ids],
                "invocations": [], "timing_segments": [], "wall_intervals": [], "intervention_events": []}

    def handoff(self, host):
        return host.handoff("task", read_run=lambda rid: read_runtime_projection(self.repository.path, rid))

    def test_task_usage_deduplicates_invocations_and_keeps_unknown_cache_null(self):
        host = self.host()
        endpoint = self.endpoint(host)
        a = self.start(endpoint)
        self.assertEqual(a, self.start(endpoint))
        b = self.start(endpoint, "start-b")
        body = self.body(a, b)
        body["invocations"] = [invocation(a), invocation(a), invocation(b, "call-b", (50, 10, None))]
        self.snapshot = seal(body)
        result = self.handoff(host)
        total = result["task_aggregate"]
        self.assertEqual(total["schema_version"], 2)
        self.assertEqual(total["unique_run_count"], 2)
        self.assertEqual(total["usage_totals"], {"status": "partial", "input_tokens": 150,
            "output_tokens": 30, "cached_tokens": None, "invocation_count": 2,
            "unattributed_invocation_count": 0, "source_ref": self.snapshot["source_ref"]})
        records = {row["run_id"]: row["run_record"] for row in result["runs"]}
        self.assertEqual(records[a]["usage"]["input_tokens"], 100)
        self.assertEqual(records[a]["usage"]["status"], "available")
        self.assertEqual(records[a]["measurement_source"]["evidence_kind"], "synthetic")
        self.assertEqual(self.reads, [("task", tuple(sorted((a, b))))])

    def test_saved_measurements_are_read_fresh_after_host_restart(self):
        from openubmc_target_runtime.measurements import JsonMeasurementReader

        host = self.host()
        run_id = self.start(self.endpoint(host))
        body = self.body(run_id)
        body["invocations"] = [invocation(run_id)]
        source = self.root / "measurements.json"
        source.write_text(json.dumps(seal(body)))
        recovered = HostContinuity(self.root / "host", record_schema_version=2,
                                   measurement_reader=JsonMeasurementReader(source))
        self.assertEqual(self.handoff(recovered)["task_aggregate"]["usage_totals"]["input_tokens"], 100)
        body["invocations"].append(invocation(run_id, "retry-a", (30, 5, 0)))
        source.write_text(json.dumps(seal(body)))
        total = self.handoff(recovered)["task_aggregate"]["usage_totals"]
        self.assertEqual((total["input_tokens"], total["output_tokens"], total["invocation_count"]), (130, 25, 2))
        source.unlink()
        missing = self.handoff(recovered)
        self.assertIsNone(missing["task_aggregate"]["usage_totals"]["input_tokens"])
        self.assertEqual(missing["runs"][0]["run_record"]["runtime_availability"], "available")

    def test_restart_segments_and_waiting_are_distinct_from_task_wall_time(self):
        host = self.host()
        run_id = self.start(self.endpoint(host))
        body = self.body(run_id)
        body["task_coverage"]["timing"] = "complete"
        body["run_coverage"][0]["timing"] = "complete"
        body["wall_intervals"] = [{"interval_ref": "task-wall", "run_ref": None,
            "started_at": "2026-10-09T10:00:00Z", "ended_at": "2026-10-09T10:00:30Z",
            "clock_ref": "wall-clock-1", "source_ref": "wall-source"}]
        first = {"segment_ref": "task-segment-1", "run_ref": None, "clock_ref": "process-1",
                 "elapsed_seconds": 4, "source_ref": "timing-1"}
        body["timing_segments"] = [first, first, {"segment_ref": "task-segment-2", "run_ref": None,
            "clock_ref": "process-2", "elapsed_seconds": 6, "source_ref": "timing-2"}]
        self.snapshot = seal(body)
        timing = self.handoff(host)["task_aggregate"]["timing"]
        self.assertEqual((timing["wall_seconds"], timing["active_seconds"], timing["status"]), (30, 10, "available"))
        body["task_coverage"]["timing"] = "partial"
        self.snapshot = seal(body)
        partial = self.handoff(host)["task_aggregate"]["timing"]
        self.assertIsNone(partial["active_seconds"])
        self.assertIsNone(partial["wall_seconds"])

    def test_human_events_are_deduplicated_without_counting_runtime_gates(self):
        host = self.host()
        run_id = self.start(self.endpoint(host))
        unmeasured = self.handoff(host)["runs"][0]["run_record"]["interventions"]
        self.assertIsNone(unmeasured["count"])
        body = self.body(run_id)
        body["task_coverage"]["interventions"] = "complete"
        body["run_coverage"][0]["interventions"] = "complete"
        approval = {"event_ref": "human-1", "run_ref": run_id, "actor_kind": "human",
                    "kind": "approval", "gate_ref": "gate-1", "source_ref": "human-source-1"}
        body["intervention_events"] = [approval, approval,
            {**approval, "event_ref": "human-2", "kind": "decision", "source_ref": "human-source-2"},
            {**approval, "event_ref": "human-3", "run_ref": None, "kind": "decision", "source_ref": "human-source-3"}]
        self.snapshot = seal(body)
        result = self.handoff(host)
        self.assertEqual(result["task_aggregate"]["interventions"]["count"], 3)
        self.assertEqual(result["task_aggregate"]["interventions"]["counts_by_kind"],
                         {"approval": 1, "decision": 2, "repair": 0})
        self.assertEqual(result["runs"][0]["run_record"]["interventions"]["count"], 2)

    def test_unrepresentable_segment_total_cannot_break_runtime_handoff(self):
        host = self.host()
        run_id = self.start(self.endpoint(host))
        body = self.body(run_id)
        body["task_coverage"]["timing"] = "complete"
        body["timing_segments"] = [{"segment_ref": ref, "run_ref": None, "clock_ref": ref,
            "elapsed_seconds": 1e308, "source_ref": ref} for ref in ("segment-a", "segment-b")]
        self.snapshot = seal(body)
        result = self.handoff(host)
        self.assertIsNone(result["task_aggregate"]["timing"]["active_seconds"])
        self.assertEqual(result["task_aggregate"]["usage_totals"]["input_tokens"], 0)
        self.assertEqual(result["runs"][0]["run_record"]["runtime_availability"], "available")

    def test_existing_provider_report_requires_stable_invocation_identity(self):
        from openubmc_target_runtime.measurements import ProviderReportReader

        run_id = self.start(self.endpoint(self.host()))
        source = self.root / "provider-report.json"
        provider = {"invocation_ref": "request-1", "run_ref": run_id, "response_model": "model-a",
            "usage": {"input_tokens": 100, "output_tokens": 20, "input_tokens_details": {"cached_tokens": 40}}}
        source.write_text(json.dumps({"provider_requests": [provider, provider]}))
        reader = ProviderReportReader(source, task_id="task", provider_ref="provider-a",
                                      evidence_kind="synthetic", inventory_complete=True)
        host = HostContinuity(self.root / "host", measurement_reader=reader, record_schema_version=2)
        total = self.handoff(host)["task_aggregate"]["usage_totals"]
        self.assertEqual((total["input_tokens"], total["cached_tokens"], total["invocation_count"]), (100, 40, 1))
        del provider["invocation_ref"]
        source.write_text(json.dumps({"provider_requests": [provider]}))
        legacy = self.handoff(host)["task_aggregate"]["usage_totals"]
        self.assertEqual(legacy["status"], "unavailable")
        self.assertIsNone(legacy["invocation_count"])
        self.assertIsNone(legacy["input_tokens"])

    def test_observed_empty_inventory_is_zero_but_missing_usage_is_unknown(self):
        host = self.host()
        run_id = self.start(self.endpoint(host))
        missing = self.handoff(host)["task_aggregate"]["usage_totals"]
        self.assertIsNone(missing["input_tokens"])
        body = self.body(run_id)
        self.snapshot = seal(body)
        zero = self.handoff(host)["task_aggregate"]["usage_totals"]
        self.assertEqual((zero["input_tokens"], zero["cached_tokens"], zero["invocation_count"]), (0, 0, 0))
        self.assertEqual(zero["status"], "available")
        body["invocations"] = [invocation(run_id, tokens=(None, None, None))]
        self.snapshot = seal(body)
        unknown = self.handoff(host)["task_aggregate"]["usage_totals"]
        self.assertEqual(unknown["invocation_count"], 1)
        self.assertIsNone(unknown["input_tokens"])
        self.assertEqual(unknown["status"], "partial")

    def test_partial_inventory_does_not_publish_known_subset_as_total(self):
        host = self.host()
        run_id = self.start(self.endpoint(host))
        body = self.body(run_id)
        body["invocations"] = [invocation(run_id)]
        body["task_coverage"]["usage"] = "partial"
        self.snapshot = seal(body)
        result = self.handoff(host)
        self.assertIsNone(result["task_aggregate"]["usage_totals"]["input_tokens"])
        self.assertIsNone(result["task_aggregate"]["usage_totals"]["invocation_count"])
        self.assertEqual(result["runs"][0]["run_record"]["usage"]["input_tokens"], 100)
        body["run_coverage"] = []
        self.snapshot = seal(body)
        self.assertIsNone(self.handoff(host)["runs"][0]["run_record"]["usage"]["input_tokens"])

    def test_task_only_invocation_is_not_apportioned_to_runs(self):
        host = self.host()
        run_id = self.start(self.endpoint(host))
        body = self.body(run_id)
        body["invocations"] = [invocation(None, tokens=(7, 3, 0))] * 2
        self.snapshot = seal(body)
        result = self.handoff(host)
        total = result["task_aggregate"]["usage_totals"]
        self.assertEqual((total["input_tokens"], total["invocation_count"], total["unattributed_invocation_count"]), (7, 1, 1))
        self.assertEqual(result["runs"][0]["run_record"]["usage"]["input_tokens"], 0)

    def test_v1_default_never_consults_injected_measurement_reader(self):
        host = HostContinuity(self.root / "host", measurement_reader=self.reader)
        run_id = self.start(self.endpoint(host))
        self.snapshot = seal(self.body(run_id))
        result = self.handoff(host)
        self.assertEqual(result["task_aggregate"]["schema_version"], 1)
        self.assertEqual(result["runs"][0]["run_record"]["usage"],
            {"status": "unavailable", "input_tokens": None, "output_tokens": None, "cached_tokens": None, "source_ref": None})
        self.assertNotIn("measurement_source", result["runs"][0]["run_record"])
        self.assertEqual(self.reads, [])

    def test_unsupported_record_version_is_rejected_at_host_composition(self):
        for version in (True, 0, 3, "2"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                HostContinuity(self.root / "host", record_schema_version=version)

    def test_invalid_snapshots_are_isolated_from_committed_runtime_facts(self):
        host = self.host()
        run_id = self.start(self.endpoint(host))
        baseline = self.handoff(host)["runs"][0]["run_record"]
        revision = self.repository.current_revision(run_id)
        good = self.body(run_id)
        good["invocations"] = [invocation(run_id)]
        invalid = []
        for field, value in (("input_tokens", True), ("input_tokens", -1), ("cached_tokens", 101),
                             ("run_ref", "foreign-run"), ("model_ref", "password:SYNTHETIC-W02")):
            body = copy.deepcopy(good)
            body["invocations"][0][field] = value
            invalid.append(seal(body))
        for name, value in (("credential", "SYNTHETIC-W02"), ("task_ref", "foreign-task"),
                            ("schema_version", True), ("invocations", [invocation(run_id)] * 257)):
            invalid.append(seal({**good, name: value}))
        invalid.append({**seal(good), "source_ref": "sha256:" + "0" * 64})
        invalid.append(seal({**good, "invocations": [invocation(run_id), invocation(run_id, tokens=(101, 20, 40))]}))
        for snapshot in invalid:
            with self.subTest(snapshot_index=invalid.index(snapshot)):
                self.snapshot = snapshot
                result = self.handoff(host)
                record = result["runs"][0]["run_record"]
                self.assertEqual(record["measurement_source"]["status"], "unavailable")
                self.assertEqual(record["runtime_state"], baseline["runtime_state"])
                self.assertEqual(record["workspace_binding"], baseline["workspace_binding"])
                self.assertIsNone(record["usage"]["input_tokens"])
                self.assertNotIn("SYNTHETIC-W02", json.dumps(result))
        self.assertEqual(self.repository.current_revision(run_id), revision)

    def test_missing_end_backward_clock_and_unknown_epoch_never_invent_wall_duration(self):
        host = self.host()
        run_id = self.start(self.endpoint(host))
        body = self.body(run_id)
        body["task_coverage"]["timing"] = "complete"
        wall = {"interval_ref": "wall", "run_ref": None, "started_at": "2026-10-09T10:00:30Z",
                "ended_at": None, "clock_ref": "clock", "source_ref": "wall-source"}
        for end, clock in ((None, "clock"), ("2026-10-09T10:00:00Z", "clock"),
                           ("2026-10-09T10:01:00Z", None)):
            body["wall_intervals"] = [{**wall, "ended_at": end, "clock_ref": clock}]
            self.snapshot = seal(body)
            self.assertIsNone(self.handoff(host)["task_aggregate"]["timing"]["wall_seconds"])

    def test_parallel_runs_do_not_sum_into_task_timing(self):
        host = self.host()
        endpoint = self.endpoint(host)
        a, b = self.start(endpoint), self.start(endpoint, "start-b")
        body = self.body(a, b)
        for row in [body["task_coverage"], *body["run_coverage"]]:
            row["timing"] = "complete"
        body["wall_intervals"] = [{"interval_ref": name, "run_ref": scope,
            "started_at": "2026-10-09T10:00:00Z", "ended_at": end, "clock_ref": "clock", "source_ref": name}
            for scope, name, end in ((None, "task-wall", "2026-10-09T10:00:30Z"),
                                    (a, "a-wall", "2026-10-09T10:00:20Z"),
                                    (b, "b-wall", "2026-10-09T10:00:25Z"))]
        body["timing_segments"] = [{"segment_ref": name, "run_ref": scope, "clock_ref": name,
            "elapsed_seconds": elapsed, "source_ref": name}
            for scope, name, elapsed in ((None, "task-segment", 10), (a, "a-segment", 8), (b, "b-segment", 7))]
        self.snapshot = seal(body)
        result = self.handoff(host)
        self.assertEqual(result["task_aggregate"]["timing"]["wall_seconds"], 30)
        self.assertEqual(result["task_aggregate"]["timing"]["active_seconds"], 10)

    def test_measurement_failure_preserves_terminal_outcome_and_delivery(self):
        host = self.host()
        endpoint = self.endpoint(host)
        run_id = self.start(endpoint)
        gate = self.handoff(host)["runs"][0]["turn"]["gate"]
        cancelled = endpoint.handle({"jsonrpc": "2.0", "id": "cancel", "method": "tools/call",
            "params": {"name": "execute", "arguments": {"kind": "control", "run_id": run_id,
                "command": "cancel", **{key: gate[key] for key in ("gate_id", "gate_version", "schema_digest")}},
                "_meta": {"threadId": "task", "openubmc/operationId": "cancel"}}})["result"]
        self.assertFalse(cancelled["isError"], cancelled)
        baseline = self.handoff(host)["runs"][0]["run_record"]
        revision = self.repository.current_revision(run_id)
        def fail_reader(*_):
            raise RuntimeError("SYNTHETIC-W02-SOURCE-DETAIL")
        recovered = HostContinuity(self.root / "host", measurement_reader=fail_reader, record_schema_version=2)
        for _ in range(2):
            result = self.handoff(recovered)
            run = result["runs"][0]
            self.assertEqual(run["run_record"]["outcome_ref"], baseline["outcome_ref"])
            self.assertEqual(run["run_record"]["runtime_state"], "cancelled")
            self.assertFalse(run["terminal_answer"]["delivery_confirmed"])
            self.assertNotIn("SYNTHETIC-W02-SOURCE-DETAIL", json.dumps(result))
        self.assertEqual(self.repository.current_revision(run_id), revision)

    def test_runtime_unavailable_keeps_independent_measurements_without_runtime_claim(self):
        host = self.host()
        run_id = self.start(self.endpoint(host))
        body = self.body(run_id)
        body["invocations"] = [invocation(run_id)]
        self.snapshot = seal(body)
        result = host.handoff("task", read_run=lambda _: None)
        record = result["runs"][0]["run_record"]
        self.assertEqual(record["runtime_availability"], "unavailable")
        self.assertIsNone(record["runtime_state"])
        self.assertIsNone(record["outcome_ref"])
        self.assertEqual(record["usage"]["input_tokens"], 100)

    def test_provider_report_cannot_override_explicit_task_or_provider_binding(self):
        from openubmc_target_runtime.measurements import ProviderReportReader

        run_id = self.start(self.endpoint(self.host()))
        source = self.root / "provider-report.json"
        reader = ProviderReportReader(source, task_id="task", provider_ref="provider-a",
                                      evidence_kind="observed", inventory_complete=True)
        host = HostContinuity(self.root / "host", measurement_reader=reader, record_schema_version=2)
        row = {"invocation_ref": "request-1", "run_ref": run_id, "usage": {"input_tokens": 100, "output_tokens": 20}}
        for field, value in (("task_ref", "foreign-task"), ("provider_ref", "foreign-provider")):
            source.write_text(json.dumps({"provider_requests": [{**row, field: value}]}))
            self.assertIsNone(self.handoff(host)["task_aggregate"]["usage_totals"]["input_tokens"])

    def test_saved_source_rejects_ambiguous_json_keys(self):
        from openubmc_target_runtime.measurements import JsonMeasurementReader

        run_id = self.start(self.endpoint(self.host()))
        body = self.body(run_id)
        body["invocations"] = [invocation(run_id)]
        encoded = json.dumps(seal(body))
        source = self.root / "measurements.json"
        source.write_text('{"task_ref":"foreign-task",' + encoded[1:])
        host = HostContinuity(self.root / "host", record_schema_version=2,
                              measurement_reader=JsonMeasurementReader(source))
        self.assertIsNone(self.handoff(host)["task_aggregate"]["usage_totals"]["input_tokens"])

    def test_invalid_time_and_human_facts_do_not_escape_into_runtime_result(self):
        host = self.host()
        run_id = self.start(self.endpoint(host))
        base = self.body(run_id)
        segment = {"segment_ref": "segment", "run_ref": None, "clock_ref": "clock",
                   "elapsed_seconds": 2, "source_ref": "timing-source"}
        event = {"event_ref": "event", "run_ref": run_id, "actor_kind": "human",
                 "kind": "repair", "gate_ref": None, "source_ref": "human-source"}
        invalid = [
            {**base, "timing_segments": [{**segment, "elapsed_seconds": -1}]},
            {**base, "timing_segments": [{**segment, "elapsed_seconds": True}]},
            {**base, "timing_segments": [segment, {**segment, "elapsed_seconds": 3}]},
            {**base, "intervention_events": [{**event, "actor_kind": "agent"}]},
            {**base, "intervention_events": [{**event, "kind": "automatic-retry"}]},
            {**base, "intervention_events": [event, {**event, "kind": "decision"}]},
            {**base, "intervention_events": [{**event, "run_ref": "foreign-run"}]},
            {**base, "wall_intervals": [{"interval_ref": "wall", "run_ref": None,
                "clock_ref": "clock", "source_ref": "clock-source", "started_at": "2026-10-09T10:00:00",
                "ended_at": "2026-10-09T10:00:30Z"}]},
        ]
        for index, body in enumerate(invalid):
            with self.subTest(index=index):
                self.snapshot = seal(body)
                record = self.handoff(host)["runs"][0]["run_record"]
                self.assertEqual(record["measurement_source"]["status"], "unavailable")
                self.assertEqual(record["runtime_availability"], "available")

    def test_provider_task_only_observation_does_not_claim_run_coverage(self):
        from openubmc_target_runtime.measurements import ProviderReportReader

        run_id = self.start(self.endpoint(self.host()))
        source = self.root / "provider-report.json"
        source.write_text(json.dumps({"provider_requests": [{"invocation_ref": "request-1",
            "usage": {"input_tokens": 100, "output_tokens": 20}}]}))
        host = HostContinuity(self.root / "host", record_schema_version=2,
            measurement_reader=ProviderReportReader(source, task_id="task", provider_ref="provider-a",
                                                    evidence_kind="observed", inventory_complete=True))
        result = self.handoff(host)
        self.assertEqual(result["task_aggregate"]["usage_totals"]["input_tokens"], 100)
        self.assertIsNone(result["runs"][0]["run_record"]["usage"]["input_tokens"])

    def test_oversized_or_non_finite_source_does_not_become_zero_usage(self):
        from openubmc_target_runtime.measurements import JsonMeasurementReader

        run_id = self.start(self.endpoint(self.host()))
        source = self.root / "measurements.json"
        source.write_bytes(b" " * (512 * 1024 + 1))
        host = HostContinuity(self.root / "host", record_schema_version=2,
                              measurement_reader=JsonMeasurementReader(source))
        self.assertIsNone(self.handoff(host)["task_aggregate"]["usage_totals"]["input_tokens"])
        body = self.body(run_id)
        body["timing_segments"] = [{"segment_ref": "segment", "run_ref": None, "clock_ref": "clock",
                                   "elapsed_seconds": float("inf"), "source_ref": "source"}]
        self.snapshot = {**body, "source_ref": "sha256:" + "0" * 64}
        self.assertEqual(self.handoff(self.host())["task_aggregate"]["measurement_source"]["status"], "unavailable")

    def test_v2_measurements_preserve_workspace_bindings_across_switch_and_restart(self):
        host = self.host()
        fixtures = Path(__file__).parent / "fixtures"
        selected = json.loads((fixtures / "workspace-selection-a.json").read_text())
        original = copy.deepcopy(selected)
        endpoint = self.endpoint(host, host_context_provider=lambda _: selected)
        a = self.start(endpoint)
        selected = json.loads((fixtures / "workspace-selection-b.json").read_text())
        b = self.start(endpoint, "start-b")
        body = self.body(a, b)
        body["invocations"] = [invocation(a), invocation(b, "call-b", (50, 10, None))]
        self.snapshot = seal(body)
        recovered = self.host()
        result = self.handoff(recovered)
        records = {row["run_id"]: row["run_record"] for row in result["runs"]}
        self.assertEqual(records[a]["workspace_binding"]["snapshot"], original)
        self.assertEqual(records[b]["workspace_binding"]["snapshot"], selected)
        self.assertEqual(records[a]["usage"]["input_tokens"], 100)
        self.assertEqual(records[b]["usage"]["input_tokens"], 50)

    def test_model_arguments_and_metadata_cannot_supply_measurement_authority(self):
        host = self.host()
        endpoint = self.endpoint(host)
        run_id = self.start(endpoint)
        body = self.body(run_id)
        body["invocations"] = [invocation(run_id)]
        self.snapshot = seal(body)
        request = {"jsonrpc": "2.0", "id": "resume", "method": "tools/call",
            "params": {"name": "execute", "arguments": {"kind": "resume", "run_id": run_id},
                "_meta": {"threadId": "task", "openubmc/operationId": "resume",
                          "measurement_snapshot": {"input_tokens": 999}}}}
        result = endpoint.handle(request)["result"]
        self.assertFalse(result["isError"], result)
        request["params"]["arguments"]["measurement_snapshot"] = {"input_tokens": 999}
        rejected = endpoint.handle(request)["result"]
        self.assertTrue(rejected["isError"], rejected)
        self.assertEqual(self.handoff(host)["task_aggregate"]["usage_totals"]["input_tokens"], 100)

    def test_provider_cache_aliases_preserve_known_values_and_reject_conflicts(self):
        from openubmc_target_runtime.measurements import ProviderReportReader

        run_id = self.start(self.endpoint(self.host()))
        source = self.root / "provider-report.json"
        host = HostContinuity(self.root / "host", record_schema_version=2,
            measurement_reader=ProviderReportReader(source, task_id="task", provider_ref="provider-a",
                                                    evidence_kind="observed", inventory_complete=True))
        for flat, nested, expected in ((None, 40, 40), (40, None, 40), (40, 40, 40),
                                       (None, None, None), (0, None, 0), (39, 40, None)):
            with self.subTest(flat=flat, nested=nested):
                source.write_text(json.dumps({"provider_requests": [{"invocation_ref": "request-1",
                    "run_ref": run_id, "usage": {"input_tokens": 100, "output_tokens": 20,
                        "cached_tokens": flat, "input_tokens_details": {"cached_tokens": nested}}}]}))
                result = self.handoff(host)
                for usage in (result["task_aggregate"]["usage_totals"], result["runs"][0]["run_record"]["usage"]):
                    self.assertEqual(usage["cached_tokens"], expected)
                    if flat == 39:
                        self.assertEqual(usage["status"], "unavailable")
                    else:
                        self.assertEqual(usage["input_tokens"], 100)
                        self.assertEqual(usage["status"], "available" if expected is not None else "partial")

    def test_unserializable_token_total_cannot_break_terminal_handoff(self):
        host = self.host()
        endpoint = self.endpoint(host)
        run_id = self.start(endpoint)
        gate = self.handoff(host)["runs"][0]["turn"]["gate"]
        cancelled = endpoint.handle({"jsonrpc": "2.0", "id": "cancel", "method": "tools/call",
            "params": {"name": "execute", "arguments": {"kind": "control", "run_id": run_id,
                "command": "cancel", **{key: gate[key] for key in ("gate_id", "gate_version", "schema_digest")}},
                "_meta": {"threadId": "task", "openubmc/operationId": "cancel"}}})["result"]
        self.assertFalse(cancelled["isError"], cancelled)
        baseline = self.handoff(host)["runs"][0]
        revision = self.repository.current_revision(run_id)
        digit_limit = getattr(sys, "get_int_max_str_digits", lambda: 0)()
        digits = min(digit_limit or 4300, 8000)
        value = 10 ** (digits - 1)
        expected = None if digit_limit and digit_limit <= digits else value * 10
        for scope in (run_id, None):
            with self.subTest(scope=scope):
                body = self.body(run_id)
                body["invocations"] = [invocation(scope, "call-" + str(index), (value, 20, 40)) for index in range(10)]
                self.snapshot = seal(body)
                result = self.handoff(host)
                json.dumps(result, allow_nan=False)
                total = result["task_aggregate"]["usage_totals"]
                self.assertEqual(total["input_tokens"], expected)
                self.assertEqual((total["output_tokens"], total["cached_tokens"], total["invocation_count"]), (200, 400, 10))
                self.assertEqual(total["status"], "partial" if expected is None else "available")
                run = result["runs"][0]
                self.assertEqual(run["run_record"]["usage"]["input_tokens"], expected if scope is not None else 0)
                self.assertEqual(run["run_record"]["measurement_source"]["status"], "available")
                self.assertEqual(run["run_record"]["outcome_ref"], baseline["run_record"]["outcome_ref"])
                self.assertEqual(run["run_record"]["runtime_state"], "cancelled")
                self.assertEqual(run["terminal_answer"], baseline["terminal_answer"])
        self.assertEqual(self.repository.current_revision(run_id), revision)
