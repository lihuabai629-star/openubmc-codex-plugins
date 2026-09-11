"""Inspect the packaged doctor at the actual credential-file boundary."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

if __package__:
    from .plugin_fixture import package_fixture
else:
    from plugin_fixture import package_fixture


class PluginCredentialTests(unittest.TestCase):
    def test_doctor_uses_runtime_redfish_environment_aliases_and_conflicts(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            plugin = package_fixture(base)
            env = {key: value for key, value in os.environ.items() if not key.startswith(('OPENUBMC_', 'REDFISH_', 'XDG_', 'PYTHON'))}
            env.update(HOME=str(base / 'home'), XDG_CONFIG_HOME=str(base / 'config'),
                       XDG_DATA_HOME=str(base / 'data'), OPENUBMC_REDFISH_USER='fixture',
                       OPENUBMC_REDFISH_PASSWORD='redfish-only-local-secret')
            cli = [sys.executable, '-I', str(plugin / 'scripts/pluginctl.py'), 'doctor']
            result = subprocess.run(cli, env=env, capture_output=True, text=True, timeout=30)
            report = json.loads(result.stdout)
            self.assertTrue(report['credentials_configured'], report['credentials'])
            self.assertTrue(report['credentials']['capabilities']['redfish'])
            env['REDFISH_USERNAME'] = 'conflicting-fixture'
            conflict = subprocess.run(cli, env=env, capture_output=True, text=True, timeout=30)
            rejected = json.loads(conflict.stdout)
            self.assertFalse(rejected['credentials_configured'])
            self.assertEqual(rejected['credentials']['code'], 'credentials_conflict')
            self.assertNotIn('redfish-only-local-secret', result.stdout + result.stderr + conflict.stdout + conflict.stderr)

    def test_runtime_launcher_keeps_standard_json_ahead_of_retained_legacy_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            plugin = package_fixture(base)
            home = base / 'home'
            config = home / '.config/openubmc'
            config.mkdir(parents=True)
            structured = config / 'credentials.json'
            structured.write_text('{"schema_version":1,"credentials":{},"defaults":{},"targets":{}}')
            structured.chmod(0o600)
            legacy = config / 'credentials.env'
            legacy.write_text('retained-legacy-invalid-content\n')
            legacy.chmod(0o600)
            env = {key: value for key, value in os.environ.items() if not key.startswith(('OPENUBMC_', 'XDG_', 'PYTHON'))}
            env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / '.config'),
                       XDG_STATE_HOME=str(base / 'state'), OPENUBMC_MCP_FORMAL_RUN='0',
                       OPENUBMC_TARGET_RUNTIME_STATE_DIR=str(base / 'runtime'))
            requests = [
                {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'qualification', 'version': '1'}}},
                {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'observe', 'arguments': {'target': '192.0.2.10', 'selectors': [{'kind': 'capability', 'names': ['ssh']}], 'deadline': 1}}},
            ]
            result = subprocess.run([sys.executable, '-I', '-B', str(plugin / 'scripts/launch_runtime.py')],
                                    input=''.join(json.dumps(request) + '\n' for request in requests),
                                    env=env, capture_output=True, text=True, timeout=30)
            responses = [json.loads(line) for line in result.stdout.splitlines()]
            response = next(value for value in responses if value.get('id') == 2)
            self.assertIn('credentials_missing', json.dumps(response))
            self.assertNotIn('KEY=VALUE', json.dumps(response))
            self.assertEqual(legacy.read_text(), 'retained-legacy-invalid-content\n')

    def test_doctor_uses_legacy_environment_credentials_when_no_file_is_selected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            plugin = package_fixture(base)
            env = {key: value for key, value in os.environ.items() if not key.startswith(('OPENUBMC_', 'XDG_', 'PYTHON'))}
            env.update(HOME=str(base / 'home'), XDG_CONFIG_HOME=str(base / 'config'),
                       XDG_DATA_HOME=str(base / 'data'), OPENUBMC_SSH_USER='fixture',
                       OPENUBMC_SSH_PASSWORD='environment-only-local-secret')
            result = subprocess.run([sys.executable, '-I', str(plugin / 'scripts/pluginctl.py'), 'doctor'],
                                    env=env, capture_output=True, text=True, timeout=30)
            report = json.loads(result.stdout)
            self.assertTrue(report['credentials_configured'], report['credentials'])
            self.assertEqual(report['credentials']['remote_authentication'], 'not_checked')
            self.assertNotIn('environment-only-local-secret', result.stdout + result.stderr)

    def test_doctor_recognizes_activated_target_credentials_without_a_source_file(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'openubmc-target-runtime'))
        from openubmc_target_runtime.configuration import LocalConfigurationStore

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            plugin = package_fixture(base)
            home = base / 'home'
            source = home / '.config/openubmc/credentials.json'
            store = LocalConfigurationStore(source, kind='targets')
            saved = store.save({'schema_version': 1,
                                'credentials': {'operator': {'user': 'fixture', 'password': 'only-local-doctor-secret'}},
                                'defaults': {'bmc': {'ssh': 'operator', 'redfish': 'operator'}},
                                'targets': {}}, expected_revision=None)
            store.activate(saved['revision'], expected_active_revision=None)
            env = {key: value for key, value in os.environ.items() if not key.startswith(('OPENUBMC_', 'XDG_', 'PYTHON'))}
            env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / '.config'),
                       XDG_DATA_HOME=str(home / '.local/share'))
            result = subprocess.run([sys.executable, '-I', str(plugin / 'scripts/pluginctl.py'), 'doctor'],
                                    env=env, capture_output=True, text=True, timeout=30)
            report = json.loads(result.stdout)
            self.assertTrue(report['credentials_configured'], report['credentials'])
            self.assertEqual(report['credentials']['remote_authentication'], 'not_checked')
            self.assertEqual(report['credentials']['active_revision'], saved['revision'])
            self.assertNotIn('only-local-doctor-secret', result.stdout + result.stderr)

    def test_doctor_reads_local_credentials_without_claiming_remote_authentication(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            plugin = package_fixture(base)
            home = base/'home'
            home.mkdir()
            credential_file = home/'credentials.env'
            env = {key: value for key, value in os.environ.items() if not key.startswith(('OPENUBMC_', 'XDG_', 'PYTHON'))}
            env.update(HOME=str(home), XDG_CONFIG_HOME=str(home/'.config'), XDG_DATA_HOME=str(home/'.local/share'),
                       OPENUBMC_CREDENTIALS_FILE=str(credential_file))
            bmc = 'OPENUBMC_SSH_USER=operator\nOPENUBMC_SSH_PASSWORD=dummy-doctor-secret\n'
            cases = [
                ('missing', None, 0o600, False),
                ('empty', '', 0o600, False),
                ('malformed', 'dummy-doctor-secret', 0o600, False),
                ('permissions', bmc, 0o644, False),
                ('partial-os', bmc + 'OPENUBMC_OS_SSH_USER=operator\n', 0o600, False),
                ('partial-telnet', bmc + 'OPENUBMC_TELNET_USER=operator\n', 0o600, False),
                ('bmc-only', bmc, 0o600, True),
                ('os-only', 'OPENUBMC_OS_SSH_USER=operator\nOPENUBMC_OS_SSH_PASSWORD=dummy-doctor-secret\n', 0o600, True),
            ]
            for name, content, mode, configured in cases:
                with self.subTest(name=name):
                    if content is not None:
                        credential_file.write_text(content)
                        credential_file.chmod(mode)
                    result = subprocess.run([sys.executable, '-I', str(plugin/'scripts/pluginctl.py'), 'doctor'],
                                            env=env, capture_output=True, text=True, timeout=30)
                    report = json.loads(result.stdout)
                    self.assertEqual(report['credentials_configured'], configured)
                    self.assertEqual(report['credentials']['remote_authentication'], 'not_checked')
                    self.assertTrue(report['credentials']['reason'])
                    self.assertFalse(report['startup_ready'])  # Dependencies were not prepared.
                    self.assertNotIn('dummy-doctor-secret', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
