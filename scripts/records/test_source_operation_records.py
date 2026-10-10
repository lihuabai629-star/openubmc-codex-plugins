"""Source drift and receipt acceptance through the installed Host and MCP seam."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from openubmc_target_runtime import RuntimeMcpService, SQLiteRuntimeRepository
from openubmc_target_runtime.host_continuity import read_runtime_projection
from openubmc_target_runtime.host_records import InstalledHostRecords
from openubmc_target_runtime.record_export import verify_export
from openubmc_target_runtime.test_records import TestRecordRunner
from test_mcp_contracts import FakeDebugBackend


class SourceOperationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'
        self.host = InstalledHostRecords(self.state, environment={})
        self.project = self.root / 'project'
        self.project.mkdir()
        self.git('init', '-q')
        (self.project / 'source').write_text('initial')
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '-qm', 'initial')
        self.select(self.project)
        self.bound = self.host.workspace_context('task')
        self.repository = SQLiteRuntimeRepository(self.state / 'context-runtime.sqlite3')
        self.backend = FakeDebugBackend()

    def git(self, *arguments):
        return subprocess.check_output(['git', '-C', str(self.project), *arguments],
                                       text=True, stderr=subprocess.DEVNULL).strip()

    def select(self, project):
        self.host.capture_selection({'hook_event_name': 'SessionStart', 'session_id': 'task', 'cwd': str(project)})

    def service(self, *, provider=None, checker=None, backend=None):
        service = RuntimeMcpService(backend or self.backend, context_repository=self.repository,
            host_continuity=self.host.continuity, host_context_provider=provider or (lambda _: self.bound),
            source_checker=checker or self.host.check_source, operation_evidence_kind='synthetic')
        self.addCleanup(service.close)
        return service

    def call(self, service, action, operation='start'):
        return service.call_exposed_tool('execute', action, task_id='task', operation_id=operation)

    def start(self, service):
        return self.call(service, {'kind': 'start', 'target': '192.0.2.1', 'intent': 'diagnosis-only'})

    def retry(self, service, turn, operation='retry', **changes):
        gate = turn['gate']
        action = {'kind': 'respond', 'run_id': turn['run_id'],
                  **{k: gate[k] for k in ('gate_id', 'gate_version', 'schema_digest')},
                  'response': {'status': 'completed', 'summary': 'source restored', 'payload': {'retry': True}}}
        action.update(changes)
        return self.call(service, action, operation)

    def projection(self, run):
        return read_runtime_projection(self.repository.path, run)

    def export(self):
        return self.host.continuity.export_records('task', read_run=self.projection, producer_commit='b' * 40)

    def test_clean_source_dispatch_automatically_exports_one_sealed_receipt(self):
        turn = self.start(self.service())
        document = self.export()
        self.assertEqual(verify_export(document), document['content_digest'])
        evidence = document['operation_evidence']
        self.assertEqual(evidence['status'], 'available', document)
        self.assertEqual(evidence['snapshot']['evidence_kind'], 'synthetic')
        row, = evidence['snapshot']['entries']
        self.assertEqual((row['run_ref'], row['source_commit'], row['status']),
                         (turn['run_id'], self.git('rev-parse', 'HEAD'), 'passed'))
        self.assertNotIn(str(self.root), json.dumps(document))
        self.assertNotIn('192.0.2.1', json.dumps(document))

    def test_dirty_drift_opens_gate_before_any_effect(self):
        (self.project / 'source').write_text('changed')
        turn = self.start(self.service())
        self.assertEqual(turn['gate']['name'], 'source.context')
        projection = self.projection(turn['run_id'])
        self.assertEqual(projection['operations'], [])
        self.assertEqual(projection['effect_intents'], [])
        self.assertEqual(self.export()['operation_evidence']['status'], 'unavailable')

    def test_restore_retry_and_duplicate_submission_dispatch_once(self):
        (self.project / 'source').write_text('changed')
        service = self.service()
        blocked = self.start(service)
        (self.project / 'source').write_text('initial')
        self.retry(service, blocked)
        self.retry(service, blocked)
        projection = self.projection(blocked['run_id'])
        self.assertEqual(len(projection['operations']), 1)
        self.assertEqual(len(projection['effect_intents']), 1)
        self.assertEqual(len(self.export()['operation_evidence']['snapshot']['entries']), 1)
        self.assertEqual(projection['start_input']['workspace_context'], self.bound)
        self.assertFalse(any(p.get('phase_type') == 'source.context' for p in projection['phase_records']))

    def test_retry_cannot_waive_mismatch_or_change_gate_identity(self):
        (self.project / 'source').write_text('changed')
        service = self.service()
        blocked = self.start(service)
        for changes in ({}, {'response': {'status': 'completed', 'summary': 'waive', 'payload': {'retry': True, 'accept_drift': True}}}, {'gate_version': 999}):
            with self.assertRaises(ValueError):
                self.retry(service, blocked, **changes)
        self.assertEqual(self.projection(blocked['run_id'])['operations'], [])

    def test_commit_drift_detected_even_with_clean_worktree(self):
        self.git('commit', '--allow-empty', '-qm', 'later')
        turn = self.start(self.service())
        self.assertEqual(turn['gate']['name'], 'source.context')
        self.assertIn('commit_changed', turn['gate']['input_schema']['description'])
        self.assertEqual(self.projection(turn['run_id'])['operations'], [])

    def test_project_switch_and_fresh_host_check_original_locator(self):
        self.select(self.root)
        self.host = InstalledHostRecords(self.state, environment={})
        self.assertEqual(self.host.check_source(self.bound).status, 'matched')
        self.assertNotEqual(self.host.workspace_context('task')['project_ref'], self.bound['project_ref'])
        turn = self.start(self.service())
        self.assertNotEqual(turn['gate']['name'], 'source.context')
        self.assertEqual(self.projection(turn['run_id'])['start_input']['workspace_context'], self.bound)

    def test_unreadable_original_repository_is_unavailable_and_recoverable(self):
        moved = self.project.with_name('moved')
        self.project.rename(moved)
        service = self.service()
        blocked = self.start(service)
        self.assertEqual(blocked['gate']['name'], 'source.context')
        moved.rename(self.project)
        self.retry(service, blocked)
        self.assertEqual(len(self.projection(blocked['run_id'])['operations']), 1)

    def test_observer_failure_has_no_effect_and_exposes_no_exception(self):
        def broken(_):
            raise OSError('SYNTHETIC-PRIVATE-PATH-DETAIL')
        turn = self.start(self.service(checker=broken))
        self.assertEqual(turn['gate']['name'], 'source.context')
        self.assertNotIn('SYNTHETIC-PRIVATE', json.dumps(turn))
        self.assertEqual(self.projection(turn['run_id'])['operations'], [])

    def test_source_gate_cancel_ends_run_without_dispatch(self):
        (self.project / 'source').write_text('changed')
        service = self.service()
        blocked = self.start(service)
        gate = blocked['gate']
        cancelled = self.call(service, {'kind': 'control', 'command': 'cancel', 'run_id': blocked['run_id'],
            **{k: gate[k] for k in ('gate_id', 'gate_version', 'schema_digest')}}, 'cancel')
        self.assertEqual(cancelled['state'], 'cancelled')
        self.assertEqual(self.projection(blocked['run_id'])['operations'], [])

    def test_dirty_bound_snapshot_does_not_invent_clean_source_receipt(self):
        (self.project / 'source').write_text('dirty at start')
        self.bound = self.host.workspace_context('task')
        turn = self.start(self.service())
        self.assertEqual(len(self.projection(turn['run_id'])['operations']), 1)
        self.assertEqual(self.export()['operation_evidence']['status'], 'unavailable')

    def test_drift_during_execution_does_not_claim_exact_source_provenance(self):
        project = self.project
        class EditingBackend(FakeDebugBackend):
            @staticmethod
            def debug_run(task, arguments, context):
                (project / 'source').write_text('changed during effect')
                return FakeDebugBackend.debug_run(task, arguments, context)
        turn = self.start(self.service(backend=EditingBackend()))
        self.assertEqual(len(self.projection(turn['run_id'])['operations']), 1)
        self.assertEqual(self.export()['operation_evidence']['status'], 'unavailable')

    def test_restart_and_repeat_export_do_not_execute_or_change_ledger(self):
        service = self.service()
        turn = self.start(service)
        document = self.export()
        revision = self.repository.current_revision(turn['run_id'])
        service.close()
        self.host = InstalledHostRecords(self.state, environment={})
        self.assertEqual(self.export(), document)
        self.assertEqual(self.export(), document)
        self.assertEqual(self.repository.current_revision(turn['run_id']), revision)

    def test_legacy_start_without_repository_binding_preserves_unknown_source(self):
        turn = self.start(self.service(provider=lambda _: None))
        self.assertEqual(len(self.projection(turn['run_id'])['operations']), 1)
        self.assertEqual(self.export()['operation_evidence']['status'], 'unavailable')

    def test_real_passed_and_failed_test_processes_export_exact_bindings(self):
        turn = self.start(self.service())
        revision = self.repository.current_revision(turn['run_id'])
        runner = TestRecordRunner(self.host, evidence_kind='synthetic')
        ref = self.bound['repositories'][0]['repo_ref']
        first = runner.run('task', turn['run_id'], ref, 'test:pass',
                           [sys.executable, '-c', 'print("actual subprocess")'])
        second = runner.run('task', turn['run_id'], ref, 'test:fail',
                            [sys.executable, '-c', 'raise SystemExit(7)'])
        self.assertEqual((first['status'], second['status']), ('passed', 'failed'))
        document = self.export()
        rows = [row for row in document['operation_evidence']['snapshot']['entries'] if row['kind'] == 'test']
        self.assertEqual(len(rows), 2)
        self.assertEqual({row['status'] for row in rows}, {'passed', 'failed'})
        self.assertEqual(self.repository.current_revision(turn['run_id']), revision)
        self.assertNotIn('actual subprocess', json.dumps(document))
        self.assertEqual(verify_export(document), document['content_digest'])

    def test_test_command_cannot_bind_to_unbookmarked_task_or_dirty_source(self):
        turn = self.start(self.service())
        runner = TestRecordRunner(self.host, evidence_kind='synthetic')
        ref = self.bound['repositories'][0]['repo_ref']
        with self.assertRaises(ValueError):
            runner.run('other-task', turn['run_id'], ref, 'test:pass', [sys.executable, '-c', 'pass'])
        (self.project / 'source').write_text('changed')
        with self.assertRaises(ValueError):
            runner.run('task', turn['run_id'], ref, 'test:pass', [sys.executable, '-c', 'pass'])

    def test_unstartable_and_timeout_tests_stay_unavailable(self):
        turn = self.start(self.service())
        runner = TestRecordRunner(self.host, evidence_kind='synthetic')
        ref = self.bound['repositories'][0]['repo_ref']
        missing = runner.run('task', turn['run_id'], ref, 'test:missing', ['not-an-installed-fixture-command'])
        timeout = runner.run('task', turn['run_id'], ref, 'test:timeout',
                             [sys.executable, '-c', 'import time; time.sleep(10)'], timeout=0.02)
        self.assertEqual((missing['status'], timeout['status']), ('unavailable', 'unavailable'))
        rows = [row for row in self.export()['operation_evidence']['snapshot']['entries'] if row['kind'] == 'test']
        self.assertTrue(all(row['log_digest'] is None for row in rows))

    def test_test_process_source_changes_do_not_report_passed(self):
        turn = self.start(self.service())
        runner = TestRecordRunner(self.host, evidence_kind='synthetic')
        result = runner.run('task', turn['run_id'], self.bound['repositories'][0]['repo_ref'], 'test:edit',
            [sys.executable, '-c', 'from pathlib import Path; Path("source").write_text("changed")'])
        self.assertEqual(result['status'], 'unavailable')
        row = next(row for row in self.export()['operation_evidence']['snapshot']['entries'] if row['kind'] == 'test')
        self.assertIsNone(row['log_digest'])

    def test_test_output_overflow_does_not_report_passed(self):
        turn = self.start(self.service())
        result = TestRecordRunner(self.host, evidence_kind='synthetic').run('task', turn['run_id'],
            self.bound['repositories'][0]['repo_ref'], 'test:overflow',
            [sys.executable, '-c', 'import sys; sys.stdout.write("x" * (17 * 1024 * 1024))'])
        self.assertEqual(result['status'], 'unavailable')

    def test_bound_source_without_registered_checker_opens_gate(self):
        service = RuntimeMcpService(self.backend, context_repository=self.repository,
            host_context_provider=lambda _: self.bound, host_continuity=self.host.continuity)
        self.addCleanup(service.close)
        turn = self.start(service)
        self.assertEqual(turn['gate']['name'], 'source.context')
        self.assertEqual(self.projection(turn['run_id'])['operations'], [])

    @unittest.skipIf(sys.platform == 'win32', 'POSIX process group cleanup; Windows timeout covered separately')
    def test_inherited_output_handle_cannot_become_passed_after_forced_cleanup(self):
        turn = self.start(self.service())
        script = 'import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"]); print("parent complete")'
        result = TestRecordRunner(self.host, evidence_kind='synthetic').run('task', turn['run_id'],
            self.bound['repositories'][0]['repo_ref'], 'test:inherited-pipe', [sys.executable, '-c', script], timeout=0.25)
        self.assertEqual(result['status'], 'unavailable')
