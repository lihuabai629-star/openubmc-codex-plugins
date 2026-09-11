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

    def test_legacy_import_is_explicit_and_checks_require_a_selected_target(self):
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
                self.assertNotIn(
                    "old", state["targets"]["config"].get("credentials", {})
                )
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
