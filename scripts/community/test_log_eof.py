import gzip
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[2] / 'plugins/openubmc/skills/openubmc-log-analyzer/scripts/pull_bundle.py'
spec = importlib.util.spec_from_file_location('community_pull_bundle', PATH)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class LogEofTests(unittest.TestCase):
    def test_exact_budget_final_line_and_true_overflow(self):
        for compressed in (False, True):
            for data in (b'error', b'error\n'):
                with self.subTest(compressed=compressed, data=data), tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / ('app.log.gz' if compressed else 'app.log')
                    path.write_bytes(gzip.compress(data) if compressed else data)
                    budget = module.AnalysisBudget(max_bytes=len(data))
                    self.assertEqual(list(module.iter_text_lines(path, budget)), ['error'])
                    self.assertFalse(budget.reasons)
                    budget = module.AnalysisBudget(max_bytes=3)
                    self.assertEqual(list(module.iter_text_lines(path, budget)), [])
                    self.assertIn('scan_bytes_exceeded', budget.reasons)
