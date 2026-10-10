#!/usr/bin/env python3
"""Run portable record acceptance against this plugin's actual Runtime payload."""
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/records'))
sys.path.insert(0, str(ROOT / 'plugins/openubmc/skills/openubmc-target-runtime'))
suite = unittest.defaultTestLoader.loadTestsFromNames([
    'test_source_operation_records', 'test_installed_host_records', 'test_windows_record_exports', 'test_record_export', 'test_workspace_run_record', 'test_run_measurements',
    'test_host_continuity', 'test_terminal_delivery', 'test_mcp_contracts',
])
raise SystemExit(0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1)
