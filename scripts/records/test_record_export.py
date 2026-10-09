import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from openubmc_target_runtime.host_continuity import read_runtime_projection
from openubmc_target_runtime.record_export import RecordExportError, RecordExportStore, export_task_records, verify_export
import test_run_measurements as measurements


PRODUCER = "b" * 40


def evidence_seal(body):
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return {**body, "source_ref": "sha256:" + hashlib.sha256(encoded).hexdigest()}


class RecordExportTests(unittest.TestCase):
    setUp = measurements.RunMeasurementTests.setUp
    reader = measurements.RunMeasurementTests.reader
    host = measurements.RunMeasurementTests.host
    endpoint = measurements.RunMeasurementTests.endpoint
    start = measurements.RunMeasurementTests.start
    handoff = measurements.RunMeasurementTests.handoff
    body = measurements.RunMeasurementTests.body

    def bound(self, host):
        selected = json.loads((Path(__file__).parent / "fixtures/workspace-selection-a.json").read_text())
        return self.start(self.endpoint(host, host_context_provider=lambda _: selected))

    def evidence(self, run):
        row = {"event_ref": "test-1", "run_ref": run, "repo_ref": "repo-A", "source_commit": "a" * 40,
            "command_ref": "command-unit-test", "command_digest": "sha256:" + "c" * 64,
            "kind": "test", "status": "passed", "execution_status": "executed",
            "evidence_ref": "evidence-test-1", "log_digest": "sha256:" + "d" * 64}
        return evidence_seal({"schema_version": 1, "task_ref": "task", "evidence_kind": "synthetic", "entries": [row]})

    def export(self, host, **options):
        return host.export_records("task", read_run=lambda rid: read_runtime_projection(self.repository.path, rid),
                                   producer_commit=PRODUCER, **options)

    def test_real_public_start_handoff_exports_only_allowed_records(self):
        host = self.host()
        run = self.bound(host)
        body = self.body(run)
        body["invocations"] = [measurements.invocation(run)]
        self.snapshot = measurements.seal(body)
        handoff = self.handoff(host)
        handoff["notes"] = {"password": "SYNTHETIC-PRIVATE-NOTE"}
        handoff["runs"][0]["terminal_answer"] = {"text": "SYNTHETIC-PRIVATE-ANSWER"}
        doc = export_task_records(handoff, producer_commit=PRODUCER)
        encoded = json.dumps(doc)
        self.assertNotIn("SYNTHETIC-PRIVATE", encoded)
        self.assertEqual(doc["run_records"][0]["usage"]["input_tokens"], 100)
        self.assertEqual(doc["run_records"][0]["workspace_binding"]["snapshot"]["project_ref"], "project-A")
        self.assertEqual(verify_export(doc), doc["content_digest"])

    def test_restart_exports_same_snapshot_without_new_effect(self):
        host = self.host()
        run = self.bound(host)
        revision = self.repository.current_revision(run)
        first = self.export(host)
        second = self.export(self.host())
        self.assertEqual(first, second)
        self.assertEqual(self.repository.current_revision(run), revision)

    def test_trusted_evidence_binds_run_repo_commit_command_and_log(self):
        host = self.host()
        run = self.bound(host)
        reads = []
        def read(task, refs):
            reads.append((task, refs))
            return self.evidence(run)
        doc = self.export(host, evidence_reader=read)
        self.assertEqual(reads, [("task", (run,))])
        self.assertEqual(doc["operation_evidence"]["status"], "available")
        self.assertEqual(doc["operation_evidence"]["snapshot"]["evidence_kind"], "synthetic")
        self.assertEqual(verify_export(doc), doc["content_digest"])

    def test_bad_provenance_downgrades_evidence_without_changing_records(self):
        host = self.host()
        run = self.bound(host)
        baseline = self.export(host)
        good = self.evidence(run)
        for key, value in (("run_ref", "foreign"), ("repo_ref", "foreign"), ("source_commit", "b" * 40),
                           ("execution_status", "not_executed"), ("log_digest", None),
                           ("command_ref", "password:SYNTHETIC-SECRET"), ("prompt", "SYNTHETIC-SECRET")):
            with self.subTest(key=key):
                body = {k: copy.deepcopy(v) for k, v in good.items() if k != "source_ref"}
                body["entries"][0][key] = value
                doc = self.export(host, evidence_reader=lambda *_: evidence_seal(body))
                self.assertEqual(doc["operation_evidence"]["status"], "unavailable")
                self.assertEqual(doc["run_records"], baseline["run_records"])
                self.assertNotIn("SYNTHETIC-SECRET", json.dumps(doc))

    def test_reader_failure_preserves_runtime_and_unknown_metrics(self):
        host = self.host()
        self.bound(host)
        def fail(*_):
            raise OSError("SYNTHETIC-SECRET")
        doc = self.export(host, evidence_reader=fail)
        self.assertEqual(doc["operation_evidence"], {"status": "unavailable", "snapshot": None})
        self.assertIsNone(doc["task_aggregate"]["usage_totals"]["input_tokens"])
        self.assertEqual(doc["run_records"][0]["runtime_availability"], "available")

    def test_statuses_do_not_promote_unexecuted_test_to_pass(self):
        host = self.host()
        run = self.bound(host)
        for status, execution, expected in (("passed", "executed", "available"), ("failed", "executed", "available"),
            ("skipped", "not_executed", "available"), ("not_run", "not_executed", "available"),
            ("passed", "not_executed", "unavailable"), ("skipped", "executed", "unavailable")):
            with self.subTest(status=status, execution=execution):
                raw = {k: v for k, v in self.evidence(run).items() if k != "source_ref"}
                raw["entries"][0].update(status=status, execution_status=execution)
                doc = self.export(host, evidence_reader=lambda *_: evidence_seal(raw))
                self.assertEqual(doc["operation_evidence"]["status"], expected)

    def test_conflicting_evidence_identity_rejected_but_identical_observations_preserved(self):
        host = self.host()
        run = self.bound(host)
        raw = {k: v for k, v in self.evidence(run).items() if k != "source_ref"}
        raw["entries"].append(copy.deepcopy(raw["entries"][0]))
        doc = self.export(host, evidence_reader=lambda *_: evidence_seal(raw))
        self.assertEqual(doc["operation_evidence"]["status"], "available")
        raw["entries"][1]["status"] = "failed"
        self.assertEqual(self.export(host, evidence_reader=lambda *_: evidence_seal(raw))["operation_evidence"]["status"], "unavailable")

    def test_tampering_unknown_version_and_fields_fail_verification(self):
        host = self.host()
        self.bound(host)
        good = self.export(host)
        for key, value in (("schema", "future/v3"), ("producer_commit", "c" * 40),
                           ("content_digest", "sha256:" + "0" * 64), ("notes", "SYNTHETIC")):
            with self.subTest(key=key), self.assertRaises(RecordExportError):
                verify_export({**good, key: value})

    def test_v1_and_runtime_unavailable_remain_explicit(self):
        from openubmc_target_runtime.host_continuity import HostContinuity
        host = HostContinuity(self.root / "host")
        self.bound(host)
        doc = host.export_records("task", read_run=lambda _: None, producer_commit=PRODUCER)
        self.assertEqual(doc["run_records"][0]["schema_version"], 1)
        self.assertIsNone(doc["run_records"][0]["runtime_state"])
        self.assertIsNone(doc["run_records"][0]["usage"]["input_tokens"])
        self.assertEqual(verify_export(doc), doc["content_digest"])

    def test_private_store_is_idempotent_and_does_not_extend_retention(self):
        host = self.host()
        self.bound(host)
        doc = self.export(host)
        store = RecordExportStore(self.root / "exports")
        path = store.write(doc)
        os.utime(path, (100, 100))
        self.assertEqual(store.write(doc), path)
        self.assertEqual(path.stat().st_mtime, 100)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_prune_preview_and_apply_only_valid_owned_exports(self):
        host = self.host()
        self.bound(host)
        store = RecordExportStore(self.root / "exports")
        path = store.write(self.export(host))
        os.utime(path, (100, 100))
        unrelated = store.root / "raw-evidence.log"
        unrelated.write_text("preserve")
        invalid = store.root / ("0" * 64 + ".json")
        invalid.write_text("{}")
        os.utime(invalid, (100, 100))
        self.assertEqual(store.prune(before_timestamp=200), [path.name])
        self.assertTrue(path.exists())
        self.assertEqual(store.prune(before_timestamp=200, dry_run=False), [path.name])
        self.assertFalse(path.exists())
        self.assertTrue(unrelated.exists() and invalid.exists())

    def test_symlink_destinations_are_refused(self):
        host = self.host()
        self.bound(host)
        doc = self.export(host)
        store = RecordExportStore(self.root / "exports")
        path = store.write(doc)
        path.unlink()
        path.symlink_to(self.repository.path)
        with self.assertRaises(RecordExportError):
            store.write(doc)
        self.assertEqual(store.prune(before_timestamp=1e20, dry_run=False), [])

    def test_shared_or_symlinked_export_directory_is_refused(self):
        host = self.host()
        self.bound(host)
        doc = self.export(host)
        shared = self.root / "shared"
        shared.mkdir(mode=0o755)
        with self.assertRaises(RecordExportError):
            RecordExportStore(shared).write(doc)
        alias = self.root / "alias"
        alias.symlink_to(shared, target_is_directory=True)
        with self.assertRaises(RecordExportError):
            RecordExportStore(alias / "exports").write(doc)

    def test_unknown_record_fields_and_schema_versions_fail_closed(self):
        host = self.host()
        self.bound(host)
        handoff = self.handoff(host)
        for key, value in (("schema_version", 3), ("credential", "SYNTHETIC-SECRET")):
            with self.subTest(key=key), self.assertRaises(RecordExportError):
                bad = copy.deepcopy(handoff)
                bad["runs"][0]["run_record"][key] = value
                export_task_records(bad, producer_commit=PRODUCER)

    def test_workflow_references_cannot_export_endpoints_or_private_paths(self):
        host = self.host()
        self.bound(host)
        good = self.handoff(host)
        for field in ("schema", "definition_id"):
            with self.subTest(field=field), self.assertRaises(RecordExportError):
                bad = copy.deepcopy(good)
                bad["runs"][0]["run_record"]["workflow_definition_ref"][field] = "https://private.example/internal/path"
                export_task_records(bad, producer_commit=PRODUCER)

    def test_unavailable_records_and_v1_usage_cannot_acquire_fabricated_authority(self):
        from openubmc_target_runtime.host_continuity import HostContinuity
        host = HostContinuity(self.root / "host")
        self.bound(host)
        good = self.handoff(host)
        bad = copy.deepcopy(good)
        bad["runs"][0]["run_record"]["usage"].update(status="available", input_tokens=100, output_tokens=20, cached_tokens=40)
        with self.assertRaises(RecordExportError):
            export_task_records(bad, producer_commit=PRODUCER)
        bad = copy.deepcopy(good)
        bad["runs"][0]["run_record"].update(runtime_availability="unavailable", runtime_state=None, outcome_ref=None, workflow_definition_ref=None)
        with self.assertRaises(RecordExportError):
            export_task_records(bad, producer_commit=PRODUCER)

    def test_outer_bookmark_identity_must_match_record_and_evidence(self):
        host = self.host()
        run = self.bound(host)
        handoff = self.handoff(host)
        handoff["runs"][0]["run_id"] = "foreign-bookmark"
        with self.assertRaises(RecordExportError):
            export_task_records(handoff, producer_commit=PRODUCER, evidence_snapshot=self.evidence(run))

    def test_hardlinked_export_is_neither_reused_nor_pruned(self):
        host = self.host()
        self.bound(host)
        doc = self.export(host)
        store = RecordExportStore(self.root / "exports")
        path = store.write(doc)
        os.utime(path, (100, 100))
        owner = self.root / "producer-owned.json"
        os.link(path, owner)
        with self.assertRaises(RecordExportError):
            store.write(doc)
        self.assertEqual(store.prune(before_timestamp=200), [])
        self.assertEqual(store.prune(before_timestamp=200, dry_run=False), [])
        self.assertTrue(path.exists() and owner.exists())

    def test_v2_export_requires_one_source_and_observed_wall_endpoints(self):
        host = self.host()
        run = self.bound(host)
        body = self.body(run)
        body["invocations"] = [measurements.invocation(run)]
        self.snapshot = measurements.seal(body)
        good = self.handoff(host)
        bad = copy.deepcopy(good)
        source = "sha256:" + "f" * 64
        total = bad["task_aggregate"]
        total["measurement_source"]["source_ref"] = source
        for key in ("usage_totals", "timing", "interventions"):
            total[key]["source_ref"] = source
        with self.assertRaises(RecordExportError):
            export_task_records(bad, producer_commit=PRODUCER)
        bad = copy.deepcopy(good)
        bad["runs"][0]["run_record"]["timing"].update(status="available", wall_seconds=30, active_seconds=10)
        with self.assertRaises(RecordExportError):
            export_task_records(bad, producer_commit=PRODUCER)

    def test_cli_export_verify_and_dry_run_prune(self):
        host = self.host()
        self.bound(host)
        input_path = self.root / "handoff.json"
        input_path.write_text(json.dumps(self.handoff(host)))
        cli = Path(__file__).resolve().parents[2] / "plugins/openubmc/skills/openubmc-target-runtime/tools/record_export.py"
        result = subprocess.run([sys.executable, "-I", str(cli), "export", "--handoff", str(input_path),
            "--producer-commit", PRODUCER, "--output-directory", str(self.root / "exports")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        path = json.loads(result.stdout)["path"]
        verified = subprocess.run([sys.executable, "-I", str(cli), "verify", path], capture_output=True, text=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        preview = subprocess.run([sys.executable, "-I", str(cli), "prune", "--output-directory", str(self.root / "exports"),
            "--before-timestamp", "9999999999"], capture_output=True, text=True)
        self.assertTrue(json.loads(preview.stdout)["dry_run"])
        self.assertTrue(Path(path).exists())
