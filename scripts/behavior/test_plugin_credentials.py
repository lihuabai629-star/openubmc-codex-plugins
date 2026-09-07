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
