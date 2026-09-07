#!/usr/bin/env python3
"""Run public behavior and cold-start checks against one final plugin directory."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
GROUPS = {
    'build': ['test_failure_gates.FailureGateTests'],
    'ssh': ['test_openssh_timeouts.OpenSshTimeoutTests'],
    'credentials': ['test_credential_commands.CredentialCommandTests'],
    'doctor': ['test_plugin_credentials.PluginCredentialTests'],
    'artifacts': ['test_artifact_retention.ArtifactRetentionTests'],
    'logs': ['test_bundle_extraction.ExtractArchiveTests'],
    'upgrade': ['test_upgrade_task_states.UpgradeTaskStateTests'],
    'migration': ['test_plugin_disable_migration.DisableMigrationTests'],
    'python_entrypoints': ['test_plugin_python_entrypoints.PythonEntrypointTests'],
}


def command(argv, environment, *, cwd, timeout=60):
    result = subprocess.run(argv, env=environment, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'command exited {result.returncode}: ' + (result.stdout + result.stderr)[-4000:])
    return result


def check(plugin: Path, report: dict) -> None:
    manifest = json.loads((ROOT/'behavior/source.json').read_text())
    for name, digest in manifest['files'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest() != digest:
            raise ValueError('behavior harness inventory mismatch: ' + name)
    if not shutil.which('codex'):
        raise ValueError('Codex is required; install the locked host from scripts/host')
    with tempfile.TemporaryDirectory(prefix='openubmc-public-checks-') as temporary:
        home = Path(temporary)
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(('OPENUBMC_', 'OPENAI_', 'CODEX_', 'XDG_', 'PYTHON', 'NODE_', 'NPM_'))}
        environment.update(HOME=str(home), CODEX_HOME=str(home/'.codex'), XDG_CONFIG_HOME=str(home/'.config'),
                           XDG_DATA_HOME=str(home/'.local/share'), XDG_CACHE_HOME=str(home/'.cache'),
                           XDG_STATE_HOME=str(home/'.local/state'), PYTHONDONTWRITEBYTECODE='1',
                           OPENUBMC_TEST_PLUGIN_ROOT=str(plugin), OPENUBMC_MCP_LIFECYCLE_DIR=str(home/'lifecycle'),
                           OPENUBMC_MCP_FORMAL_RUN='0')
        (home/'.codex').mkdir()
        cli = [sys.executable, '-I', str(plugin/'scripts/pluginctl.py')]
        identity = json.loads(command([*cli, 'verify'], environment, cwd=home).stdout)
        report.update({key: identity[key] for key in ('version', 'source_commit', 'content_digest')})
        if identity['source_commit'] != manifest['source_commit']:
            raise ValueError('behavior harness and final plugin use different source commits')
        report['platform'] = {'os': platform.system(), 'machine': platform.machine(), 'python': platform.python_version(),
                              'node': command(['node', '--version'], environment, cwd=home).stdout.strip(),
                              'codex': command(['codex', '--version'], environment, cwd=home).stdout.strip()}
        report['dependency_locks'] = {name: hashlib.sha256((plugin/name).read_bytes()).hexdigest()
                                      for name in ('requirements.lock', 'openubmc-kb-mcp/package-lock.json')}
        started = time.monotonic()
        prepared = json.loads(command([*cli, 'prepare'], environment, cwd=home, timeout=540).stdout)
        report['cold_dependencies'] = {'passed': True, 'seconds': round(time.monotonic() - started, 3)}
        environment['PYTHONPATH'] = os.pathsep.join([str(ROOT/'behavior'), str(Path(prepared['dependencies'])/'python-packages')])
        for name, selectors in GROUPS.items():
            started = time.monotonic()
            result = command([sys.executable, '-B', '-m', 'unittest', *selectors], environment, cwd=ROOT/'behavior', timeout=90)
            if 'skipped=' in result.stderr:
                raise RuntimeError('public behavior checks must not skip: ' + name)
            count = re.search(r'Ran (\d+) tests?', result.stderr)
            report['behavior'][name] = {'passed': True, 'tests': int(count[1]) if count else None,
                                        'seconds': round(time.monotonic() - started, 3)}
            print(name + ': passed', flush=True)
        node = command(['node', '--test', str(ROOT/'behavior/config.test.mjs')], environment, cwd=home)
        count = re.search(r'# tests (\d+)', node.stdout)
        report['behavior']['kb_loader'] = {'passed': True, 'tests': int(count[1]) if count else None}
        normal_python = {key: value for key, value in environment.items() if not key.startswith('PYTHON')}
        command([sys.executable, str(plugin/'skills/openubmc-debug/scripts/target_runtime_cli.py'), '--help'],
                normal_python, cwd=home)
        report['ordinary_python_cli_before_mcp'] = True
        doctor = json.loads(command([*cli, 'doctor'], environment, cwd=home, timeout=90).stdout)
        if not doctor['startup_ready'] or doctor['credentials_configured']:
            raise ValueError('cold startup must succeed independently of absent credentials')
        report['mcp_startup'] = doctor['mcp_health']
        records = [json.loads(path.read_text()) for path in (home/'lifecycle').glob('*.json')]
        runtime_records = [record for record in records if record.get('component') == 'target-runtime']
        if not runtime_records or any(record.get('lifecycle_state') != 'stopped' or record.get('active_requests') != 0 for record in runtime_records):
            raise ValueError('Runtime MCP did not finish with a stopped lifecycle record')
        if any(Path('/proc', str(record['process_id'])).exists() for record in runtime_records):
            raise ValueError('Runtime MCP process survived the startup probe')
        report['runtime_shutdown_verified'] = True
        after = json.loads(command([*cli, 'verify'], environment, cwd=home).stdout)
        if after != identity:
            raise ValueError('plugin identity changed during checks')
        report['package_integrity_after_checks'] = True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plugin', type=Path, default=ROOT.parent/'plugins/openubmc')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    plugin = args.plugin.resolve()
    if args.output.resolve().is_relative_to(plugin):
        parser.error('report must be outside the immutable plugin')
    report = {'schema': 'openubmc.public-behavior.v1', 'passed': False, 'behavior': {},
              'remote_business_qualification': 'not_run'}
    try:
        check(plugin, report)
        report['passed'] = True
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        print(str(error), file=sys.stderr)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
