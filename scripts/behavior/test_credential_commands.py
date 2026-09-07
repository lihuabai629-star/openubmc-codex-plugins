"""Credential commands round-trip through the Runtime and KB loaders."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PLUGIN_ROOT = Path(os.environ['OPENUBMC_TEST_PLUGIN_ROOT']) if os.environ.get('OPENUBMC_TEST_PLUGIN_ROOT') else None
ROOT = PLUGIN_ROOT / 'skills' if PLUGIN_ROOT else Path(__file__).resolve().parents[2]
KB_ROOT = (PLUGIN_ROOT or ROOT) / 'openubmc-kb-mcp'
SPEC = importlib.util.spec_from_file_location(
    "credential_command_installer", ROOT / "openubmc-environment-setup/scripts/install_environment.py"
)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)
sys.path.insert(0, str(ROOT / "openubmc-target-runtime"))
from openubmc_target_runtime.credential_file import read_credentials_file


class CredentialCommandTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("OPENUBMC_", "XDG_"))}
        self.environment = mock.patch.dict(os.environ, environment, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def run_command(self, *arguments, answers=(), secrets=()):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output), \
                mock.patch("sys.stdin.isatty", return_value=True), \
                mock.patch("builtins.input", side_effect=answers), \
                mock.patch("getpass.getpass", side_effect=secrets):
            result = installer.main(["credentials", "--home", str(self.home), *arguments])
        for secret in secrets:
            if secret:
                self.assertNotIn(secret, output.getvalue())
        return result, output.getvalue()

    def test_bmc_only_import_is_usable_without_os_credentials(self):
        source = self.home / "import.env"
        source.write_text("OPENUBMC_SSH_USER=operator\nOPENUBMC_SSH_PASSWORD=dummy-bmc-secret\n")
        source.chmod(0o600)
        result, output = self.run_command("--import-credentials", str(source), "--non-interactive")
        self.assertEqual(result, 0, output)
        values = read_credentials_file(self.home / ".config/openubmc/credentials.env")
        self.assertEqual(values["REDFISH_USERNAME"], "operator")
        self.assertEqual(values["REDFISH_PASSWORD"], "dummy-bmc-secret")
        self.assertNotIn("OPENUBMC_OS_SSH_PASSWORD", values)
        self.assertNotIn("dummy-bmc-secret", output)

    def test_interactive_bmc_configuration_can_skip_os(self):
        result, output = self.run_command(answers=("operator", ""), secrets=("dummy-bmc-secret",))
        self.assertEqual(result, 0, output)
        values = read_credentials_file(self.home / ".config/openubmc/credentials.env")
        self.assertEqual(values["REDFISH_USERNAME"], "operator")
        self.assertNotIn("OPENUBMC_OS_SSH_USER", values)

    def test_partial_os_import_reports_the_missing_field(self):
        source = self.home / "import.env"
        source.write_text("OPENUBMC_OS_SSH_USER=operator\n")
        source.chmod(0o600)
        result, output = self.run_command("--import-credentials", str(source))
        self.assertNotEqual(result, 0)
        self.assertIn("OPENUBMC_OS_SSH_PASSWORD", output)
        self.assertFalse((self.home / ".config/openubmc/credentials.env").exists())

    def test_partial_telnet_capability_is_not_reported_complete(self):
        source = self.home / "import.env"
        source.write_text("OPENUBMC_SSH_USER=operator\nOPENUBMC_SSH_PASSWORD=dummy-bmc-secret\nOPENUBMC_TELNET_USER=operator\n")
        source.chmod(0o600)
        result, output = self.run_command("--import-credentials", str(source))
        self.assertNotEqual(result, 0)
        self.assertIn("OPENUBMC_TELNET_PASSWORD", output)
        self.assertNotIn("dummy-bmc-secret", output)

    def load_kb(self, password, client_secret):
        loader = (KB_ROOT / "src/config.js").as_uri()
        script = f"""
            import {{ loadConfig }} from {json.dumps(loader)};
            const config = await loadConfig(process.argv[1]);
            console.log(JSON.stringify({{
                configured: config.credentialsConfigured,
                passwordMatches: config.password === process.argv[2],
                clientSecretMatches: config.clientSecret === process.argv[3]
            }}));
        """
        result = subprocess.run([
            "node", "--input-type=module", "-e", script,
            str(self.home / ".config/openubmc/kb-mcp.json"), password, client_secret,
        ], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "configured": True, "passwordMatches": True, "clientSecretMatches": True,
        })

    def test_new_interactive_kb_configuration_is_complete_for_the_loader(self):
        result, output = self.run_command("--kb", answers=("operator",), secrets=("dummy-password", "dummy-client-secret"))
        self.assertEqual(result, 0, output)
        self.load_kb("dummy-password", "dummy-client-secret")

    def test_kb_update_preserves_application_settings_and_secret_bytes(self):
        path = self.home / ".config/openubmc/kb-mcp.json"
        path.parent.mkdir(parents=True)
        application = {"clientId": "existing-app", "clientSecret": " secret!'  ",
                       "oauthBaseUrl": "https://auth.example.test", "scopes": ["openid"],
                       "tokenCachePath": "private/token.json"}
        path.write_text(json.dumps({**application, "username": "operator", "password": "old"}))
        path.chmod(0o600)
        result, output = self.run_command("--kb", answers=("",), secrets=(" password!  ", ""))
        self.assertEqual(result, 0, output)
        saved = json.loads(path.read_text())
        for field, value in application.items():
            self.assertEqual(saved[field], value)
        self.assertEqual(saved["password"], " password!  ")
        self.load_kb(" password!  ", " secret!'  ")

    def test_kb_missing_client_secret_is_not_reported_configured(self):
        result, output = self.run_command("--kb", answers=("operator",), secrets=("dummy-password", ""))
        self.assertNotEqual(result, 0)
        self.assertIn("clientSecret", output)
        self.assertNotIn("credentials: configured", output)
        self.assertFalse((self.home / ".config/openubmc/kb-mcp.json").exists())

    def test_kb_rejects_invalid_application_settings_before_write(self):
        path = self.home / ".config/openubmc/kb-mcp.json"
        path.parent.mkdir(parents=True)
        original = json.dumps({"username": "operator", "password": "old", "clientSecret": "old", "clientId": ""})
        path.write_text(original)
        path.chmod(0o600)
        result, output = self.run_command("--kb", answers=("",), secrets=("dummy-password", "dummy-secret"))
        self.assertNotEqual(result, 0)
        self.assertNotIn("credentials: configured", output)
        self.assertEqual(path.read_text(), original)

    def test_kb_import_requires_complete_configuration_and_preserves_secrets(self):
        source = self.home / "import.json"
        source.touch(mode=0o600)
        source.write_text(json.dumps({"username": "operator", "password": " secret!  "}))
        result, output = self.run_command("--kb-config", str(source), "--non-interactive")
        self.assertNotEqual(result, 0)
        self.assertNotIn(" secret!  ", output)
        self.assertFalse((self.home / ".config/openubmc/kb-mcp.json").exists())
        source.write_text(json.dumps({"username": "operator", "password": " secret!  ", "clientSecret": " app!  "}))
        result, output = self.run_command("--kb-config", str(source), "--non-interactive")
        self.assertEqual(result, 0, output)
        self.load_kb(" secret!  ", " app!  ")


if __name__ == "__main__":
    unittest.main()
