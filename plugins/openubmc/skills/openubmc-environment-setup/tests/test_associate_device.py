from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "openubmc-environment-setup" / "scripts" / "associate_device.py"
sys.path.insert(0, str(ROOT / "openubmc-target-runtime"))
from openubmc_target_runtime import CredentialResolver
from openubmc_target_runtime.configuration import LocalConfigurationStore


class AssociateDeviceCliTests(unittest.TestCase):
    def run_association(self, source: Path, bmc: str, os_host: str, *options: str):
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--bmc-ip", bmc, "--os-ip", os_host,
             "--confirm-same-device", *options],
            env={**os.environ, "OPENUBMC_CREDENTIALS_CONFIG": str(source)},
            text=True, capture_output=True,
        )

    def test_confirmed_pair_is_active_for_later_tasks_without_changing_credentials(self):
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "credentials.json"
            store = LocalConfigurationStore(source, kind="targets")
            initial = store.save({
                "schema_version": 1,
                "credentials": {"bmc": {"user": "fixture", "password": "private-fixture"}},
                "defaults": {"bmc": {"ssh": "bmc"}},
            }, expected_revision=None)
            store.activate(initial["revision"], expected_active_revision=None)
            environment = {**os.environ, "OPENUBMC_CREDENTIALS_CONFIG": str(source)}
            command = [sys.executable, "-B", str(SCRIPT), "--bmc-ip", "192.0.2.10",
                       "--os-ip", "192.0.2.20"]
            unconfirmed = subprocess.run(command, env=environment, text=True, capture_output=True)
            self.assertNotEqual(unconfirmed.returncode, 0)
            self.assertIsNone(CredentialResolver(config_path=source, environ={}).associated_os(
                task_id="before", bmc_host="192.0.2.10"))

            confirmed = subprocess.run(command + ["--confirm-same-device"],
                                       env=environment, text=True, capture_output=True)
            self.assertEqual(confirmed.returncode, 0, confirmed.stderr)
            receipt = json.loads(confirmed.stdout)
            self.assertEqual(receipt["bmc_ip"], "192.0.2.10")
            self.assertEqual(receipt["os_ip"], "192.0.2.20")
            self.assertNotIn("private-fixture", confirmed.stdout + confirmed.stderr)
            resolver = CredentialResolver(config_path=source, environ={})
            self.assertEqual(resolver.associated_os(task_id="later", bmc_host="192.0.2.10"), "192.0.2.20")
            self.assertEqual(resolver.resolve_local(task_id="later", host="192.0.2.10",
                                                    transport="ssh").credentials.password, "private-fixture")

    def test_conflicting_link_requires_explicit_replacement_and_repeating_a_link_is_idempotent(self):
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "credentials.json"
            store = LocalConfigurationStore(source, kind="targets")
            initial = store.save({"schema_version": 1,
                                  "devices": {"192.0.2.10": {"os_ip": "192.0.2.20"}}},
                                 expected_revision=None)
            store.activate(initial["revision"], expected_active_revision=None)
            repeated = self.run_association(source, "192.0.2.10", "192.0.2.20")
            self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
            self.assertFalse(json.loads(repeated.stdout)["changed"])
            self.assertEqual(store.status()["active_revision"], initial["revision"])

            conflict = self.run_association(source, "192.0.2.10", "192.0.2.30")
            self.assertEqual(conflict.returncode, 2)
            self.assertEqual(json.loads(conflict.stdout)["existing_os_ip"], "192.0.2.20")
            self.assertEqual(store.status()["active_revision"], initial["revision"])
            unbound_replace = self.run_association(source, "192.0.2.10", "192.0.2.30",
                                                   "--replace-existing")
            self.assertEqual(unbound_replace.returncode, 2)
            stale_replace = self.run_association(source, "192.0.2.10", "192.0.2.30",
                                                 "--replace-existing", "--expected-os-ip", "192.0.2.21")
            self.assertEqual(stale_replace.returncode, 2)
            self.assertEqual(store.status()["active_revision"], initial["revision"])
            replacement = self.run_association(source, "192.0.2.10", "192.0.2.30",
                                               "--replace-existing", "--expected-os-ip", "192.0.2.20")
            self.assertEqual(replacement.returncode, 0, replacement.stdout + replacement.stderr)
            self.assertEqual(CredentialResolver(config_path=source, environ={}).associated_os(
                task_id="new", bmc_host="192.0.2.10"), "192.0.2.30")

    def test_legacy_account_survives_and_a_pending_draft_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "credentials.env"
            legacy = "OPENUBMC_SSH_USER=fixture\nOPENUBMC_SSH_PASSWORD=legacy-private\n"
            source.write_text(legacy)
            source.chmod(0o600)
            linked = self.run_association(source, "192.0.2.10", "192.0.2.20")
            self.assertEqual(linked.returncode, 0, linked.stdout + linked.stderr)
            self.assertEqual(source.read_text(), legacy)
            self.assertNotIn("legacy-private", linked.stdout + linked.stderr)
            resolver = CredentialResolver(config_path=source, environ={})
            self.assertEqual(resolver.associated_os(task_id="later", bmc_host="192.0.2.10"), "192.0.2.20")
            self.assertEqual(resolver.resolve_local(task_id="later", host="192.0.2.10",
                                                    transport="ssh").credentials.password, "legacy-private")

            store = LocalConfigurationStore(source, kind="targets")
            active = store.status()["active_revision"]
            draft = store.save({"schema_version": 1, "devices": {
                "192.0.2.10": {"os_ip": "192.0.2.20"}}}, expected_revision=active)
            blocked = self.run_association(source, "192.0.2.11", "192.0.2.21")
            self.assertEqual(blocked.returncode, 2)
            self.assertEqual(json.loads(blocked.stdout)["code"], "configuration_conflict")
            self.assertEqual(store.status()["revision"], draft["revision"])
            self.assertEqual(store.status()["active_revision"], active)

    def test_explicit_source_can_match_a_runtime_with_a_private_mcp_source(self):
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "private" / "credentials.json"
            environment = {name: value for name, value in os.environ.items()
                           if not name.startswith("OPENUBMC_")}
            environment["HOME"] = raw
            result = subprocess.run(
                [sys.executable, "-I", "-B", str(SCRIPT), "--source", str(source),
                 "--bmc-ip", "192.0.2.40", "--os-ip", "192.0.2.50",
                 "--confirm-same-device"],
                env=environment, text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(CredentialResolver(config_path=source, environ={}).associated_os(
                task_id="later", bmc_host="192.0.2.40"), "192.0.2.50")
            self.assertEqual(source.parent.stat().st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
