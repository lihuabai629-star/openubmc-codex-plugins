import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / 'plugins/openubmc/skills/openubmc-developer/scripts'
spec = importlib.util.spec_from_file_location('interface_coverage_test_module', SCRIPTS / 'interface_coverage.py')
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)


class InterfaceCoverageTests(unittest.TestCase):
    def run_input(self, payload):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'input.json';p.write_text(json.dumps(payload))
            return coverage.check_interface_coverage(p)

    def test_unrelated_files_skip(self):
        result = self.run_input({'changedFiles':['README.md'], 'headSha':'abc'})
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['result']['conclusion'], 'skipped')

    def test_missing_docs_stays_unverified(self):
        result = self.run_input({'changedFiles':['interface_config/redfish/mapping_config/Systems/Bios/config.json'],
                                 'headSha':'abc','fileContents':{},'patchText':{},'prBody':''})
        self.assertNotEqual(result['result']['conclusion'], 'covered')
        self.assertIsNone(result['result']['coverage'][0]['cond2'])

    def test_dependency_failure_is_incomplete(self):
        with mock.patch.object(coverage.shutil, 'which', return_value=None):
            self.assertEqual(self.run_input({'changedFiles':[]})['status'], 'incomplete')
