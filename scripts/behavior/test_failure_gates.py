from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BUILD_ROOT = Path(os.environ['OPENUBMC_TEST_PLUGIN_ROOT']) / 'skills/openubmc-build' if os.environ.get('OPENUBMC_TEST_PLUGIN_ROOT') else Path(__file__).resolve().parents[1]


class FailureGateTests(unittest.TestCase):
    def test_checked_command_preserves_normal_summary_and_nonzero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            for command_rc in (0, 7):
                result = subprocess.run(
                    [sys.executable, str(BUILD_ROOT / "scripts/run_bmcgo_checked.py"),
                     "--log", str(Path(raw) / "build.log"), "--", sys.executable, "-c",
                     f"print('test summary: 0 failed'); raise SystemExit({command_rc})"],
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode == 0, command_rc == 0)

    def test_checked_command_rejects_error_beside_zero_failure_summary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result = subprocess.run(
                [sys.executable, str(BUILD_ROOT / "scripts/run_bmcgo_checked.py"),
                 "--log", str(Path(raw) / "build.log"), "--", sys.executable, "-c",
                 "print('ERROR: build failed; test summary: 0 failed')"],
                capture_output=True, text=True, timeout=10,
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_attempt_rejects_error_beside_zero_failure_summary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "input.txt").write_text("source\n")
            subprocess.run(["git", "-C", str(repo), "add", "input.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "-c", "user.name=Fixture", "-c",
                 "user.email=fixture@example.com", "commit", "-qm", "fixture"], check=True,
            )
            plan = root / "plan.json"
            planned = subprocess.run(
                [sys.executable, str(BUILD_ROOT / "scripts/create_build_plan.py"),
                 "--mode", "validate", "--workspace", f"component={repo}",
                 "--cwd", str(repo), "--output", str(plan), "--run-root", str(root / "runs"),
                 "--", sys.executable, "-c",
                 "print('ERROR: build failed; test summary: 0 failed')"],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(planned.returncode, 0, planned.stderr)
            attempt = subprocess.run(
                [sys.executable, str(BUILD_ROOT / "scripts/run_build_attempt.py"),
                 "--plan", str(plan), "--run-root", str(root / "runs")],
                capture_output=True, text=True, timeout=15,
            )
            receipt = json.loads(attempt.stdout)
            self.assertEqual(receipt["status"], "failed", attempt.stdout + attempt.stderr)
            self.assertEqual(attempt.returncode, 1)

    def test_documented_conan_preflight_propagates_nonzero_exit_without_error_text(self) -> None:
        self.assert_conan_preflight("Network request timed out", 7, 1)

    def test_documented_conan_preflight_rejects_zero_exit_authentication_error(self) -> None:
        self.assert_conan_preflight("error: Authentication failed", 0, 1)

    def test_documented_conan_preflight_accepts_success(self) -> None:
        self.assert_conan_preflight("Authentication successful", 0, 0)

    def assert_conan_preflight(self, output: str, command_rc: int, expected_rc: int) -> None:
        document = (BUILD_ROOT / "references/conan-auth.md").read_text()
        blocks = [part.split("```", 1)[0] for part in document.split("```bash\n")[1:]]
        preflight = next(block for block in blocks if "for remote in " in block)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            executable = root / "conan"
            executable.write_text("#!/bin/sh\nprintf '%s\\n' \"$AUDIT_CONAN_OUTPUT\"\nexit \"$AUDIT_CONAN_RC\"\n")
            executable.chmod(0o700)
            result = subprocess.run(
                ["bash", "-c", preflight], capture_output=True, text=True, timeout=10,
                env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                     "TMPDIR": str(root), "AUDIT_CONAN_OUTPUT": output,
                     "AUDIT_CONAN_RC": str(command_rc)},
            )
        self.assertEqual(result.returncode, expected_rc, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
