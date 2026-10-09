#!/usr/bin/env python3
"""Run local community integration checks against the plugin payload."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DEV = ROOT / 'plugins/openubmc/skills/openubmc-developer'
commands = [[sys.executable, '-B', '-m', 'unittest', 'discover', '-s', 'scripts/community']]
for relative in ('resources/community/web-backend/scripts', 'resources/community/redfish-diff/scripts/tests'):
    commands.append([sys.executable, '-B', '-m', 'unittest', 'discover', '-s', str(DEV / relative)])
commands.append([sys.executable, '-B', str(DEV / 'resources/community/concurrency/evals/test_collect_candidates.py')])
commands.append(['node', '--test', *[str(DEV / p) for p in (
    'resources/community/compliance/scripts/compliance-lint.test.mjs',
    'resources/community/compliance/scripts/compliance-lint.cli.test.mjs',
    'resources/interface-coverage/scripts/doc-coverage.test.mjs')]])
for command in commands:
    subprocess.run(command, cwd=ROOT, check=True)
