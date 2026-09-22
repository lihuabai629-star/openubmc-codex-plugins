from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "config_page.py"


class ConfigPageTests(unittest.TestCase):
    def test_state_exposes_one_loopback_entry_and_reason_without_secrets(self):
        spec = importlib.util.spec_from_file_location("config_page", SCRIPT)
        page = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(page)
        with tempfile.TemporaryDirectory() as raw, page.LocalConfigurationServer(Path(raw)) as server:
            state = server.state()
            entry = state["configuration_entry"]
            self.assertEqual(entry["url"], server.url)
            self.assertEqual(entry["reason"], "configuration_required")
            self.assertNotIn("password", json.dumps(state))

    def test_existing_private_source_is_shown_and_kept_without_manual_import(self):
        spec = importlib.util.spec_from_file_location("config_page", SCRIPT)
        page = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(page)
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / 'credentials.env'
            source.write_text('OPENUBMC_SSH_USER=fixture\nOPENUBMC_SSH_PASSWORD=existing-private-password\n')
            source.chmod(0o600)
            with page.LocalConfigurationServer(Path(raw), sources={'targets': source}) as server:
                def request(path, data=None):
                    req = Request(server.origin+path, headers={'X-OpenUBMC-Session': server.session_token,
                        'Origin': server.origin, 'Content-Type': 'application/json'},
                        data=json.dumps(data).encode() if data is not None else None)
                    with urlopen(req, timeout=3) as response: return json.load(response)
                state = request('/api/state')['targets']
                config = state['config']
                name = config['defaults']['bmc']['ssh']
                self.assertEqual(config['credentials'][name]['user'], 'fixture')
                self.assertTrue(config['credentials'][name]['password_set'])
                config['credentials'][name]['user'] = 'updated'
                config['credentials'][name]['password'] = {'action': 'keep', 'source': name}
                saved = request('/api/save', {'kind': 'targets', 'expected_revision': None, 'config': config})
                request('/api/activate', {'kind': 'targets', 'revision': saved['revision'], 'expected_active_revision': None})
                from openubmc_target_runtime import CredentialResolver
                selected = CredentialResolver(config_path=source, environ={}).resolve_local(
                    task_id='existing-source', host='192.0.2.10', transport='ssh').credentials
                self.assertEqual(selected.password, 'existing-private-password')
                self.assertEqual(selected.user, 'updated')
                self.assertNotIn('existing-private-password', json.dumps(state) + json.dumps(saved))
                self.assertIn('OPENUBMC_SSH_USER=fixture', source.read_text())

    def test_activation_checks_only_authorized_bmc_and_keeps_authentication_failure_visible(self):
        spec = importlib.util.spec_from_file_location("config_page", SCRIPT)
        page = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(page)
        calls = []
        target = {"ip": "192.0.2.10", "purpose": "bmc", "transport": "ssh"}
        def checker(kind, config, selected, **kwargs):
            calls.append(selected)
            return {"verified": False, "code": "authentication_failed"}
        with tempfile.TemporaryDirectory() as raw, page.LocalConfigurationServer(
            Path(raw), checker=checker, authorized_targets=[target], focus_target=target["ip"]
        ) as server:
            def post(path, data):
                req = Request(server.origin + path, headers={"X-OpenUBMC-Session": server.session_token,
                    "Origin": server.origin, "Content-Type": "application/json"}, data=json.dumps(data).encode())
                with urlopen(req, timeout=3) as response: return json.load(response)
            saved = post("/api/save", {"kind": "targets", "expected_revision": None, "config": {
                "schema_version": 1, "credentials": {"common": {"user": "fixture",
                    "password": {"action": "replace", "value": "rejected-private-secret"}}},
                "defaults": {"bmc": {"ssh": "common", "redfish": "common"}},
                "devices": {"192.0.2.10": {"os_ip": "192.0.2.20"}}}})
            result = post("/api/activate", {"kind": "targets", "revision": saved["revision"], "expected_active_revision": None})
            self.assertEqual(calls, [target])
            self.assertFalse(result["checks"][0]["verified"])
            self.assertEqual(result["checks"][0]["code"], "authentication_failed")
            self.assertNotIn("rejected-private-secret", json.dumps(result))

    def test_closing_a_waiting_page_emits_cancellation_instead_of_success(self):
        import subprocess
        import sys
        import threading
        with tempfile.TemporaryDirectory() as raw:
            process = subprocess.Popen([sys.executable, '-B', str(SCRIPT), '--config-home', raw,
                '--no-browser', '--wait-for-save'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            timer = threading.Timer(10, process.kill); timer.start()
            try:
                url = process.stdout.readline().strip()
                self.assertTrue(url.startswith('http://127.0.0.1:'))
                origin, token = url.split('/#')
                req = Request(origin+'/api/close', data=b'{}', headers={'X-OpenUBMC-Session': token,
                    'Origin': origin, 'Content-Type': 'application/json'})
                with urlopen(req, timeout=3) as response: self.assertTrue(json.load(response)['closed'])
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(json.loads(stdout), {'event': 'configuration_cancelled', 'kind': 'targets'})
            finally:
                timer.cancel()
                if process.poll() is None: process.kill()
                process.communicate()

    def test_focused_cli_reports_only_the_requested_saved_configuration_without_secrets(self):
        import subprocess
        import sys
        import threading
        with tempfile.TemporaryDirectory() as raw:
            process = subprocess.Popen([sys.executable, '-B', str(SCRIPT), '--config-home', raw,
                '--no-browser', '--kind', 'kb', '--wait-for-save'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            timer = threading.Timer(10, process.kill)
            timer.start()
            try:
                url = process.stdout.readline().strip()
                self.assertTrue(url.startswith('http://127.0.0.1:'), url)
                origin, token = url.split('/#')
                def request(path, data=None):
                    req = Request(origin + path, headers={'X-OpenUBMC-Session': token,
                        'Origin': origin, 'Content-Type': 'application/json'},
                        data=json.dumps(data).encode() if data is not None else None)
                    with urlopen(req, timeout=3) as response:
                        return json.load(response)
                self.assertEqual(request('/api/state')['page_session']['kind'], 'kb')
                for kind, config in [
                    ('targets', {'schema_version': 1}),
                    ('kb', {'username': 'fixture', 'password': {'action': 'replace', 'value': 'private-password'},
                            'clientSecret': {'action': 'replace', 'value': 'private-oauth-secret'}}),
                ]:
                    saved = request('/api/save', {'kind': kind, 'expected_revision': None, 'config': config})
                    request('/api/activate', {'kind': kind, 'revision': saved['revision'], 'expected_active_revision': None})
                    if kind == 'targets':
                        self.assertIsNone(process.poll())
                        self.assertEqual(request('/api/state')['page_session']['kind'], 'kb')
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, stderr)
                receipt = json.loads(stdout)
                self.assertEqual(receipt['event'], 'configuration_saved')
                self.assertEqual(receipt['kind'], 'kb')
                self.assertEqual(receipt['revision'], saved['revision'])
                self.assertTrue(receipt['configured'])
                self.assertEqual(receipt['checks'], [])
                self.assertNotIn('private-password', stdout + stderr)
                self.assertNotIn('private-oauth-secret', stdout + stderr)
            finally:
                timer.cancel()
                if process.poll() is None: process.kill()
                process.communicate()

    def test_browser_session_guards_and_secret_keep_replace_remove(self):
        spec = importlib.util.spec_from_file_location("config_page", SCRIPT)
        page = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(page)
        with tempfile.TemporaryDirectory() as raw:
            with page.LocalConfigurationServer(Path(raw)) as server:

                def request(path, data=None, *, token=True, origin=None):
                    headers = (
                        {"X-OpenUBMC-Session": server.session_token} if token else {}
                    )
                    if data is not None:
                        headers.update(
                            {
                                "Content-Type": "application/json",
                                "Origin": origin or server.origin,
                            }
                        )
                    req = Request(
                        server.origin + path,
                        headers=headers,
                        data=json.dumps(data).encode() if data is not None else None,
                    )
                    with urlopen(req, timeout=3) as result:
                        return json.load(result)

                with self.assertRaises(HTTPError) as error:
                    request("/api/state", token=False)
                self.assertEqual(error.exception.code, 403)
                state = request("/api/state")
                self.assertIsNone(state["targets"]["revision"])
                edit = {
                    "kind": "targets",
                    "expected_revision": None,
                    "config": {
                        "schema_version": 1,
                        "credentials": {
                            "common": {
                                "user": "fixture",
                                "password": {
                                    "action": "replace",
                                    "value": "fixture-private",
                                },
                            }
                        },
                        "defaults": {"bmc": {"ssh": "common"}},
                    },
                }
                with self.assertRaises(HTTPError) as error:
                    request("/api/save", edit, origin="https://unrelated.example")
                self.assertEqual(error.exception.code, 403)
                saved = request("/api/save", edit)
                self.assertNotIn("fixture-private", json.dumps(saved))
                self.assertTrue(
                    saved["config"]["credentials"]["common"]["password_set"]
                )
                self.assertNotIn("password", saved["config"]["credentials"]["common"])
                edit["expected_revision"] = saved["revision"]
                edit["config"]["credentials"]["common"]["password"] = {"action": "keep"}
                kept = request("/api/save", edit)
                self.assertTrue(kept["config"]["credentials"]["common"]["password_set"])
                edit["expected_revision"] = kept["revision"]
                edit["config"]["credentials"]["renamed"] = edit["config"][
                    "credentials"
                ].pop("common")
                edit["config"]["credentials"]["renamed"]["password"] = {
                    "action": "keep",
                    "source": "common",
                }
                edit["config"]["defaults"]["bmc"]["ssh"] = "renamed"
                renamed = request("/api/save", edit)
                self.assertTrue(
                    renamed["config"]["credentials"]["renamed"]["password_set"]
                )
                edit["expected_revision"] = renamed["revision"]
                edit["config"]["credentials"]["renamed"]["password"] = {
                    "action": "remove"
                }
                removed = request("/api/save", edit)
                self.assertFalse(
                    removed["config"]["credentials"]["renamed"]["password_set"]
                )
                self.assertFalse(removed["verified"])

    def test_legacy_source_is_visible_without_activation_and_checks_require_a_selected_target(self):
        spec = importlib.util.spec_from_file_location("config_page", SCRIPT)
        page = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(page)
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "openubmc" / "credentials.json"
            source.parent.mkdir()
            original = json.dumps(
                {
                    "schema_version": 1,
                    "credentials": {
                        "old": {"user": "fixture", "password": "fixture-original"}
                    },
                    "defaults": {"bmc": {"ssh": "old"}},
                }
            )
            source.write_text(original)
            source.chmod(0o600)
            checks = []

            def checker(kind, config, target, **_metadata):
                checks.append((kind, config, target))
                return {"verified": True, "code": "connected"}

            with page.LocalConfigurationServer(Path(raw), checker=checker) as server:

                def request(path, data=None):
                    headers = {
                        "X-OpenUBMC-Session": server.session_token,
                        "Origin": server.origin,
                        "Content-Type": "application/json",
                    }
                    with urlopen(
                        Request(
                            server.origin + path,
                            headers=headers,
                            data=json.dumps(data).encode() if data else None,
                        ),
                        timeout=3,
                    ) as result:
                        return json.load(result)

                state = request("/api/state")
                self.assertIn(
                    "old", state["targets"]["config"].get("credentials", {})
                )
                self.assertIsNone(state["targets"]["revision"])
                self.assertIsNone(state["targets"]["active_revision"])
                self.assertNotIn("fixture-original", json.dumps(state))
                imported = request(
                    "/api/import", {"kind": "targets", "expected_revision": None}
                )
                self.assertNotIn("fixture-original", json.dumps(imported))
                request(
                    "/api/activate",
                    {
                        "kind": "targets",
                        "revision": imported["revision"],
                        "expected_active_revision": None,
                    },
                )
                self.assertEqual(checks, [])
                self.assertEqual(source.read_text(), original)
                missing = request("/api/check", {"kind": "targets"})
                self.assertFalse(missing["verified"])
                self.assertEqual(missing["code"], "target_required")
                connected = request(
                    "/api/check",
                    {
                        "kind": "targets",
                        "target": {
                            "ip": "192.0.2.10",
                            "purpose": "bmc",
                            "transport": "ssh",
                        },
                        "confirm": True,
                    },
                )
                self.assertTrue(connected["verified"])
                self.assertEqual(
                    checks[0][1]["credentials"]["old"]["password"], "fixture-original"
                )
                self.assertNotIn("fixture-original", json.dumps(request("/api/state")))

    def test_conan_accounts_are_saved_privately_and_verified_per_remote(self):
        spec = importlib.util.spec_from_file_location("config_page", SCRIPT)
        page = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(page)
        with tempfile.TemporaryDirectory() as raw:
            with page.LocalConfigurationServer(
                Path(raw),
                checker=lambda *_, **_metadata: {"verified": True, "code": "connected"},
            ) as server:

                def post(path, data):
                    req = Request(
                        server.origin + path,
                        headers={
                            "X-OpenUBMC-Session": server.session_token,
                            "Origin": server.origin,
                            "Content-Type": "application/json",
                        },
                        data=json.dumps(data).encode(),
                    )
                    with urlopen(req, timeout=3) as result:
                        return json.load(result)

                saved = post(
                    "/api/save",
                    {
                        "kind": "conan",
                        "expected_revision": None,
                        "config": {
                            "credentials": {
                                "fixture_remote": {
                                    "user": "fixture",
                                    "password": {
                                        "action": "replace",
                                        "value": "fixture-conan-secret",
                                    },
                                }
                            }
                        },
                    },
                )
                self.assertNotIn("fixture-conan-secret", json.dumps(saved))
                post(
                    "/api/activate",
                    {
                        "kind": "conan",
                        "revision": saved["revision"],
                        "expected_active_revision": None,
                    },
                )
                result = post(
                    "/api/check",
                    {
                        "kind": "conan",
                        "target": {"remote": "fixture_remote"},
                        "confirm": True,
                    },
                )
                self.assertTrue(result["verified"])
                self.assertEqual(result["target"], {"remote": "fixture_remote"})

    def test_connection_checker_uses_runtime_selection_and_only_a_read_command(self):
        import sys
        from unittest.mock import patch

        root = SCRIPT.parents[2]
        sys.path[:0] = [
            str(root / "openubmc-target-runtime"),
            str(root / "openubmc-target-runtime" / "tests"),
            str(root / "openubmc-debug" / "scripts"),
        ]
        from test_ssh_lane_contracts import FakeSshTransport
        import _remote_common

        spec = importlib.util.spec_from_file_location(
            "config_checks", SCRIPT.with_name("config_checks.py")
        )
        checks = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checks)
        transport = FakeSshTransport()
        config = {
            "schema_version": 1,
            "credentials": {
                "default": {"user": "bmc", "password": "fixture-bmc"},
                "host": {"user": "host", "password": "fixture-os"},
            },
            "defaults": {"bmc": {"ssh": "default"}, "os": {"ssh": "host"}},
        }
        with patch.object(
            _remote_common, "OpenSshControlMasterTransport", return_value=transport
        ):
            result = checks.check_target(
                config, {"ip": "192.0.2.10", "purpose": "os", "transport": "ssh"}
            )
        self.assertTrue(result["verified"])
        self.assertEqual(transport.last_credentials.password, "fixture-os")
        self.assertEqual(transport.channel_commands, ["true"])
        self.assertEqual(transport.closes, 1)
        self.assertNotIn("fixture-os", json.dumps(result))

    def test_conan_connection_failure_is_not_reported_as_a_rejected_password(self):
        import os
        import sys
        from unittest.mock import patch

        spec = importlib.util.spec_from_file_location("config_page", SCRIPT)
        page = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(page)
        spec = importlib.util.spec_from_file_location(
            "config_checks", SCRIPT.with_name("config_checks.py")
        )
        checks = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checks)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            binary = root / "bin"
            binary.mkdir()
            conan = binary / "conan"
            conan.write_text(
                "#!"
                + sys.executable
                + '\nimport sys\nsys.stderr.write("ERROR: Connection refused\\n")\nsys.exit(1)\n'
            )
            conan.chmod(0o755)
            with patch.dict(
                os.environ, {"PATH": str(binary) + os.pathsep + os.environ["PATH"]}
            ):
                with page.LocalConfigurationServer(
                    root, checker=checks.BoundedConfigurationChecker()
                ) as server:

                    def post(path, data):
                        req = Request(
                            server.origin + path,
                            headers={
                                "X-OpenUBMC-Session": server.session_token,
                                "Origin": server.origin,
                                "Content-Type": "application/json",
                            },
                            data=json.dumps(data).encode(),
                        )
                        with urlopen(req, timeout=8) as response:
                            return json.load(response)

                    saved = post(
                        "/api/save",
                        {
                            "kind": "conan",
                            "expected_revision": None,
                            "config": {
                                "credentials": {
                                    "fixture": {
                                        "user": "fixture",
                                        "password": {
                                            "action": "replace",
                                            "value": "fixture-not-rejected",
                                        },
                                    }
                                }
                            },
                        },
                    )
                    post(
                        "/api/activate",
                        {
                            "kind": "conan",
                            "revision": saved["revision"],
                            "expected_active_revision": None,
                        },
                    )
                    result = post(
                        "/api/check",
                        {
                            "kind": "conan",
                            "target": {"remote": "fixture"},
                            "confirm": True,
                        },
                    )
                    self.assertFalse(result["verified"])
                    self.assertEqual(result["code"], "network_error")
                    self.assertNotIn("fixture-not-rejected", json.dumps(result))
