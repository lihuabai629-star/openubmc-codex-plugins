"""Reject stale identities, incomplete lifecycle evidence and unexecuted CI."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('release_gate', ROOT / 'scripts/check_release_gate.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class HostedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.run = {'repository': {'full_name': GATE.MARKETPLACE_REPOSITORY},
                    'id': 123, 'run_attempt': 2, 'html_url': 'https://github.com/run/123',
                    'head_sha': 'a' * 40, 'event': 'push', 'path': '.github/workflows/validate.yml',
                    'status': 'completed', 'conclusion': 'success'}
        self.jobs = [{'name': 'verify', 'status': 'completed', 'conclusion': 'success',
                      'steps': [{'name': 'Actual check', 'status': 'completed', 'conclusion': 'success'}]}]

    def assess(self):
        return GATE.assess_ci(self.run, self.jobs, repository=GATE.MARKETPLACE_REPOSITORY,
                              commit='a' * 40, workflow='validate.yml',
                              required_steps={'verify': ('Actual check',)})

    def test_executed_exact_commit_is_accepted(self):
        self.assertEqual(self.assess()['run_attempt'], 2)

    def test_green_other_source_or_workflow_or_repository_is_rejected(self):
        original = deepcopy(self.run)
        for key, value in (('head_sha', 'b' * 40), ('path', '.github/workflows/other.yml'),
                           ('repository', {'full_name': 'other/repository'}), ('event', 'pull_request')):
            with self.subTest(key=key):
                self.run = {**original, key: value}
                with self.assertRaises(ValueError):
                    self.assess()

    def test_missing_skipped_or_duplicate_required_job_is_rejected(self):
        original = deepcopy(self.jobs)
        for jobs in ([], original * 2, [{**original[0], 'conclusion': 'skipped'}]):
            with self.subTest(jobs=jobs):
                self.jobs = jobs
                with self.assertRaises(ValueError):
                    self.assess()

    def test_green_job_with_unexecuted_check_is_rejected(self):
        for conclusion in ('skipped', 'failure', None):
            with self.subTest(conclusion=conclusion):
                self.jobs[0]['steps'][0]['conclusion'] = conclusion
                with self.assertRaises(ValueError):
                    self.assess()
        self.jobs[0]['steps'] = []
        with self.assertRaises(ValueError):
            self.assess()


class QualificationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.release = GATE.document(ROOT / 'release.json')
        self.lock = GATE.document(ROOT / 'plugins/openubmc/plugin-lock.json')
        self.evidence = self.root / 'docs/qualification' / self.lock['version']
        shutil.copytree(ROOT / 'docs/qualification' / self.lock['version'], self.evidence)

    def assess(self):
        return GATE.assess_reports(self.root, self.lock, self.release, self.release['upgrade_baseline'])

    def change(self, name, mutate):
        path = self.evidence / (name + '.json')
        record = GATE.document(path)
        mutate(record)
        path.write_text(json.dumps(record))

    def test_all_qualified_reports_bind_to_one_package(self):
        self.assertEqual(len(self.assess()['sha256']), 8)

    def test_mixed_package_identity_is_rejected(self):
        self.change('public-behavior', lambda record: record.update(source_commit='b' * 40))
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            self.assess()

    def test_wrong_upgrade_baseline_is_rejected(self):
        self.change('plugin-qualification', lambda record: record['native_thread_resume'].update(from_version='0.0.1'))
        with self.assertRaisesRegex(ValueError, 'baseline'):
            self.assess()

    def test_failed_resume_is_rejected(self):
        self.change('plugin-qualification', lambda record: record['native_thread_resume'].update(resume_error='Transport closed'))
        with self.assertRaisesRegex(ValueError, 'resume'):
            self.assess()

    def test_missing_host_recovery_proof_is_rejected(self):
        self.change('installed-host-records', lambda record: record.update(native_resume_preserved_run=False))
        with self.assertRaisesRegex(ValueError, 'host records'):
            self.assess()

    def test_windows_scope_cannot_claim_native_runtime(self):
        self.change('portable-capabilities-windows', lambda record: record.update(native_windows_runtime='supported'))
        with self.assertRaisesRegex(ValueError, 'platform scope'):
            self.assess()

    def test_inconsistent_test_totals_are_rejected(self):
        self.change('repository-validation', lambda record: record.update(python_tests=1))
        with self.assertRaisesRegex(ValueError, 'test count mismatch'):
            self.assess()

    def test_false_repository_pass_is_rejected(self):
        self.change('repository-validation', lambda record: record['python_groups'][0].update(passed=False))
        with self.assertRaisesRegex(ValueError, 'tests incomplete'):
            self.assess()


if __name__ == '__main__':
    unittest.main()
