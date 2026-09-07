from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


RUNTIME_ROOT = Path(os.environ['OPENUBMC_TEST_PLUGIN_ROOT']) / 'skills/openubmc-target-runtime' if os.environ.get('OPENUBMC_TEST_PLUGIN_ROOT') else Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME_ROOT))

from openubmc_target_runtime import TargetSpec, ResolvedSshCredentials
from openubmc_target_runtime.openssh import OpenSshControlMasterTransport, OpenSshMaster


class OpenSshTimeoutTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.payload = self.root / "payload.txt"
        self.payload.write_text("dummy content")
        self.master = OpenSshMaster(
            target=TargetSpec("192.0.2.1", credential_selector_fingerprint="0" * 64),
            credentials=ResolvedSshCredentials(user="fixture-user"),
            control_path=str(self.root / "control.sock"), tempdir=self.temporary,
        )
        self.transport = OpenSshControlMasterTransport()
        environment = patch.dict(os.environ, {"PATH": str(self.root) + os.pathsep + os.environ["PATH"]})
        environment.start()
        self.addCleanup(environment.stop)

    def external_program(self, stdout: bytes = b"", stderr: bytes = b"", *, timeout: bool = True, rc: int = 0) -> None:
        program = (
            f"#!{sys.executable}\nimport os,time\n"
            f"os.write(1, {stdout!r})\nos.write(2, {stderr!r})\n"
            + ("time.sleep(10)\n" if timeout else "")
            + f"raise SystemExit({rc})\n"
        )
        for name in ("ssh", "scp"):
            executable = self.root / name
            executable.write_text(program)
            executable.chmod(0o700)

    def operations(self):
        return {
            "command": lambda: self.transport.run_channel(self.master, "true", timeout=0.5),
            "download": lambda: self.transport.download_file(self.master, "/dummy", str(self.root / "download"), timeout=0.5),
            "upload": lambda: self.transport.upload_file(self.master, str(self.payload), "/dummy", timeout=0.5),
        }

    def test_command_and_transfers_return_text_when_partial_output_times_out(self) -> None:
        self.external_program(b"partial stdout\n", b"partial stderr\xff\n")
        for name, invoke in self.operations().items():
            with self.subTest(operation=name):
                result = invoke()
                self.assertEqual(result.returncode, 124)
                self.assertEqual(result.stdout, "partial stdout\n")
                self.assertIn("partial stderr\ufffd", result.stderr)
                self.assertIn("timed out", result.stderr)

    def test_timeout_without_stderr_returns_text(self) -> None:
        for stdout in (b"", b"partial stdout"):
            with self.subTest(stdout=stdout):
                self.external_program(stdout)
                result = self.transport.run_channel(self.master, "true", timeout=0.5)
                self.assertEqual(result.returncode, 124)
                self.assertIsInstance(result.stdout, str)
                self.assertIn("timed out", result.stderr)

    def test_timeout_keeps_bounded_diagnostics_with_a_truncation_marker(self) -> None:
        self.external_program(b"start\n" + b"x" * 32768 + b"\nend", b"error\n" + b"y" * 32768)
        for name, invoke in self.operations().items():
            with self.subTest(operation=name):
                result = invoke()
                self.assertEqual(result.returncode, 124)
                self.assertLessEqual(len(result.stdout), 8192)
                self.assertLessEqual(len(result.stderr), 8192 + 128)
                self.assertIn("truncated", result.stdout)
                self.assertIn("truncated", result.stderr)
                self.assertTrue(result.stdout.startswith("start\n"))
                self.assertTrue(result.stdout.endswith("\nend"))
                self.assertIn("timed out", result.stderr)

    def test_normal_completion_preserves_success_and_failure_results(self) -> None:
        for rc in (0, 7):
            self.external_program(b"output", b"diagnostic", timeout=False, rc=rc)
            for name, invoke in self.operations().items():
                with self.subTest(rc=rc, operation=name):
                    result = invoke()
                    self.assertEqual(result.returncode, rc)
                    self.assertEqual(result.stdout, "output")
                    self.assertEqual(result.stderr, "diagnostic")


if __name__ == "__main__":
    unittest.main()
