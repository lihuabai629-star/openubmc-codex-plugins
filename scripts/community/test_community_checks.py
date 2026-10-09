from pathlib import Path
import importlib.util
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('community_checks', Path(__file__).resolve().parents[2] / 'plugins/openubmc/skills/openubmc-developer/scripts/community_checks.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


class CommunityChecksTests(unittest.TestCase):
    def test_skip_unrelated_and_reject_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'README.md').write_text('text')
            self.assertEqual(checks.run_check('compliance', root, ['README.md'])['status'], 'skipped')
            (root / 'outside').symlink_to(Path(__file__))
            with self.assertRaises(ValueError):
                checks.run_check('compliance', root, ['outside'])

    def test_syntax_error_has_findings_and_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = root / 'intf/mdb/example.json'
            file.parent.mkdir(parents=True)
            file.write_text('{')
            result = checks.run_check('compliance', root, ['intf/mdb/example.json'])
        self.assertEqual(result['status'], 'findings')
        self.assertGreater(result['result']['summary']['errors'], 0)
        self.assertEqual(result['files'], ['intf/mdb/example.json'])

    def test_missing_node_is_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = root / 'messages/test.json'
            p.parent.mkdir()
            p.write_text('{}')
            with mock.patch.object(checks.shutil, 'which', return_value=None):
                self.assertEqual(checks.run_check('compliance', root, ['messages/test.json'])['status'], 'incomplete')

    def test_ref_option_cannot_become_git_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(checks.subprocess.CalledProcessError):
                checks.run_check('redfish-diff', root, old_ref='--help', new_ref='HEAD', output=root / 'out')
