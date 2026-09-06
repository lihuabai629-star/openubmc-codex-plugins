#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import redirect_stderr
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest import mock
import urllib.error


REPO_ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = REPO_ROOT / "bootstrap.py"
SPEC = importlib.util.spec_from_file_location("openubmc_workflow_bootstrap", BOOTSTRAP)
assert SPEC is not None and SPEC.loader is not None
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)
INSTALLER = (
    REPO_ROOT / "openubmc-environment-setup" / "scripts" / "install_environment.py"
)
INSTALLER_SPEC = importlib.util.spec_from_file_location(
    "openubmc_environment_installer_for_bootstrap_contract", INSTALLER
)
assert INSTALLER_SPEC is not None and INSTALLER_SPEC.loader is not None
installer = importlib.util.module_from_spec(INSTALLER_SPEC)
INSTALLER_SPEC.loader.exec_module(installer)


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self) -> bytes:
        return b"#!/usr/bin/env python3\n"


class BootstrapTests(unittest.TestCase):
    def test_bootstrap_requires_an_explicit_immutable_ref_before_download(self) -> None:
        for arguments in ([], ["--ref", "main"]):
            with self.subTest(arguments=arguments):
                stderr = io.StringIO()
                with (
                    mock.patch.object(bootstrap.urllib.request, "urlopen") as urlopen,
                    mock.patch.object(bootstrap.subprocess, "run") as run,
                    redirect_stderr(stderr),
                    self.assertRaises(SystemExit) as raised,
                ):
                    bootstrap.main(arguments)

                self.assertEqual(raised.exception.code, 2)
                self.assertIn("release tag or full commit", stderr.getvalue())
                urlopen.assert_not_called()
                run.assert_not_called()

    def test_bootstrap_downloads_complete_installer_and_forwards_options(self) -> None:
        completed = subprocess.CompletedProcess([], 0)
        downloaded: dict[str, bytes] = {}

        def run_installer(command, **_kwargs):
            installer_path = Path(command[1])
            downloaded[installer_path.name] = installer_path.read_bytes()
            parser_path = installer_path.with_name("client_config.py")
            downloaded[parser_path.name] = parser_path.read_bytes()
            return completed

        with (
            mock.patch.dict(
                bootstrap.os.environ, {"GH_TOKEN": "fixture-token"}, clear=True
            ),
            mock.patch.object(
                bootstrap.urllib.request, "urlopen", return_value=_Response()
            ) as urlopen,
            mock.patch.object(
                bootstrap.subprocess, "run", side_effect=run_installer
            ) as run,
        ):
            result = bootstrap.main(
                [
                    "--ref",
                    "release-v1",
                    "--skill-profile",
                    "target-runtime",
                    "--clients",
                    "codex",
                ]
            )

        self.assertEqual(result, 0)
        requests = [call.args[0] for call in urlopen.call_args_list]
        self.assertEqual(
            [request.full_url for request in requests],
            [
                bootstrap.INSTALLER_API_TEMPLATE.format(ref="release-v1"),
                bootstrap.CLIENT_CONFIG_API_TEMPLATE.format(ref="release-v1"),
            ],
        )
        self.assertTrue(
            all(
                request.get_header("Authorization") == "Bearer fixture-token"
                for request in requests
            )
        )
        self.assertTrue(
            all(call.kwargs == {"timeout": 30} for call in urlopen.call_args_list)
        )
        self.assertEqual(set(downloaded), {"install_environment.py", "client_config.py"})
        command = run.call_args.args[0]
        self.assertNotIn("fixture-token", command)
        self.assertEqual(command[2:8], [
            "install",
            "--source-mode",
            "managed",
            "--repo-url",
            bootstrap.DEFAULT_REPO_URL,
            "--ref",
        ])
        self.assertEqual(command[8], "release-v1")
        self.assertIn("--non-interactive", command)
        self.assertEqual(command[-4:], [
            "--skill-profile",
            "target-runtime",
            "--clients",
            "codex",
        ])

    def test_bootstrap_rejects_retired_clients_before_download(self) -> None:
        for clients in ("claude", "openclaw", "codex,claude"):
            with self.subTest(clients=clients):
                stderr = io.StringIO()
                with (
                    mock.patch.object(bootstrap.urllib.request, "urlopen") as urlopen,
                    mock.patch.object(bootstrap.subprocess, "run") as run,
                    redirect_stderr(stderr),
                    self.assertRaises(SystemExit) as raised,
                ):
                    bootstrap.main(
                        ["--ref", "v2.0.3", "--clients", clients]
                    )

                self.assertEqual(raised.exception.code, 2)
                self.assertIn("only Codex is supported", stderr.getvalue())
                self.assertIn("--clients codex", stderr.getvalue())
                urlopen.assert_not_called()
                run.assert_not_called()

    def test_bootstrap_runs_legacy_installer_without_companion_module(self) -> None:
        completed = subprocess.CompletedProcess([], 0)

        def run_installer(command, **_kwargs):
            installer_path = Path(command[1])
            self.assertTrue(installer_path.is_file())
            self.assertFalse(installer_path.with_name("client_config.py").exists())
            return completed

        missing_companion = urllib.error.HTTPError(
            bootstrap.CLIENT_CONFIG_API_TEMPLATE.format(ref="v1.2.2"),
            404,
            "Not Found",
            {},
            None,
        )
        with (
            mock.patch.object(
                bootstrap.urllib.request,
                "urlopen",
                side_effect=[_Response(), missing_companion],
            ) as urlopen,
            mock.patch.object(
                bootstrap.subprocess, "run", side_effect=run_installer
            ) as run,
        ):
            result = bootstrap.main(["--ref", "v1.2.2"])

        self.assertEqual(result, 0)
        self.assertEqual(urlopen.call_count, 2)
        run.assert_called_once()

    def test_bootstrap_still_requires_the_installer_asset(self) -> None:
        missing_installer = urllib.error.HTTPError(
            bootstrap.INSTALLER_API_TEMPLATE.format(ref="v1.2.2"),
            404,
            "Not Found",
            {},
            None,
        )
        with (
            mock.patch.object(
                bootstrap.urllib.request,
                "urlopen",
                side_effect=missing_installer,
            ),
            mock.patch.object(bootstrap.subprocess, "run") as run,
        ):
            result = bootstrap.main(["--ref", "v1.2.2"])

        self.assertEqual(result, 2)
        run.assert_not_called()

    def test_bootstrap_does_not_ignore_other_companion_download_failures(self) -> None:
        failed_companion = urllib.error.HTTPError(
            bootstrap.CLIENT_CONFIG_API_TEMPLATE.format(ref="v1.2.2"),
            500,
            "Server Error",
            {},
            None,
        )
        with (
            mock.patch.object(
                bootstrap.urllib.request,
                "urlopen",
                side_effect=[_Response(), failed_companion],
            ),
            mock.patch.object(bootstrap.subprocess, "run") as run,
        ):
            result = bootstrap.main(["--ref", "v1.2.2"])

        self.assertEqual(result, 2)
        run.assert_not_called()

    def test_bootstrap_defaults_to_the_github_primary_release_source(self) -> None:
        completed = subprocess.CompletedProcess([], 0)
        with (
            mock.patch.dict(bootstrap.os.environ, {}, clear=True),
            mock.patch.object(
                bootstrap.urllib.request, "urlopen", return_value=_Response()
            ) as urlopen,
            mock.patch.object(bootstrap.subprocess, "run", return_value=completed) as run,
        ):
            self.assertEqual(bootstrap.main(["--ref", "v1.2.3"]), 0)

        requests = [call.args[0] for call in urlopen.call_args_list]
        self.assertEqual(
            [request.full_url for request in requests],
            [
                "https://api.github.com/repos/lihuabai629-star/openubmc-agent-workflow/"
                "contents/openubmc-environment-setup/scripts/install_environment.py?ref=v1.2.3",
                "https://api.github.com/repos/lihuabai629-star/openubmc-agent-workflow/"
                "contents/openubmc-environment-setup/scripts/client_config.py?ref=v1.2.3",
            ],
        )
        self.assertTrue(
            all(request.get_header("Authorization") is None for request in requests)
        )
        self.assertTrue(
            all(call.kwargs == {"timeout": 30} for call in urlopen.call_args_list)
        )
        command = run.call_args.args[0]
        repo_index = command.index("--repo-url") + 1
        ref_index = command.index("--ref") + 1
        self.assertEqual(
            command[repo_index],
            "https://github.com/lihuabai629-star/openubmc-agent-workflow.git",
        )
        self.assertEqual(command[ref_index], "v1.2.3")

    def test_bootstrap_rejects_source_overrides_before_download(self) -> None:
        for arguments in (
            ["--ref", "v1.2.3", "--repo-url", "https://github.com/example/fork.git"],
            ["--ref", "v1.2.3", "--installer-url", "https://example.invalid/installer.py"],
            ["--ref", "v1.2.3", "--source", "/tmp/untrusted-checkout"],
            ["--ref", "v1.2.3", "--source-mode=linked"],
            ["--ref", "v1.2.3", "--source-m", "linked"],
        ):
            with self.subTest(arguments=arguments):
                stderr = io.StringIO()
                with (
                    mock.patch.object(bootstrap.urllib.request, "urlopen") as urlopen,
                    mock.patch.object(bootstrap.subprocess, "run") as run,
                    redirect_stderr(stderr),
                    self.assertRaises(SystemExit) as raised,
                ):
                    bootstrap.main(arguments)

                self.assertEqual(raised.exception.code, 2)
                self.assertIn("primary GitHub release source", stderr.getvalue())
                urlopen.assert_not_called()
                run.assert_not_called()

    def test_bootstrap_and_installer_share_the_release_ref_contract(self) -> None:
        cases = {
            "v1.2.3": True,
            "release-2026.08": True,
            "a" * 40: True,
            "main": False,
            "refs/heads/release": False,
            "release candidate": False,
            "release..candidate": False,
            "-release": False,
        }
        for ref, expected in cases.items():
            with self.subTest(ref=ref):
                try:
                    bootstrap.release_ref(ref)
                    bootstrap_accepts = True
                except argparse.ArgumentTypeError:
                    bootstrap_accepts = False
                try:
                    installer.release_ref_kind(ref)
                    installer_accepts = True
                except installer.SetupError:
                    installer_accepts = False

                self.assertEqual(bootstrap_accepts, expected)
                self.assertEqual(installer_accepts, expected)


if __name__ == "__main__":
    unittest.main()
