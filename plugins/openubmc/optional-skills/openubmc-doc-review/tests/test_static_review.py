from __future__ import annotations

import json
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = SKILL_ROOT / "scripts" / "static_review.py"
SPEC = importlib.util.spec_from_file_location("static_review", SCRIPT)
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)


class StaticReviewTests(unittest.TestCase):
    def run_review(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_full_profile_runs_every_analyzer_without_executing_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = Path(directory) / "guide.md"
            document.write_text(
                "# Upgrade guide\n\n"
                "Run the following read-only check:\n\n"
                "```bash\n"
                "printf '%s\\n' status\n"
                "```\n",
                encoding="utf-8",
            )
            result = self.run_review(str(document), "--profile", "full")

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["command_execution"])
        self.assertEqual(payload["scanned_files"], 1)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(
            {name: value["status"] for name, value in payload["semantic_reviews"].items()},
            {"completeness": "not_run", "readability": "not_run", "product_consistency": "not_run"},
        )
        self.assertEqual(
            set(payload["analyzers"]),
            {
                "security",
                "links",
                "typo",
                "spelling",
                "punctuation",
                "cli",
                "consistency",
            },
        )
        self.assertTrue(
            all(item["status"] == "ok" for item in payload["analyzers"].values())
        )

    def test_missing_target_is_reported(self) -> None:
        result = self.run_review("/definitely/not/a/document.md")

        self.assertEqual(result.returncode, 2)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["scanned_files"], 0)
        self.assertEqual(payload["missing_targets"], ["/definitely/not/a/document.md"])

    def test_failed_lane_is_not_reported_as_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = Path(directory) / "guide.md"
            document.write_text("# Guide\n")
            output = io.StringIO()
            def analyzer(name, *args):
                return {"status": "unavailable"} if name == "links" else {"status": "ok", "result": {}}
            with mock.patch.object(review, "run_analyzer", side_effect=analyzer), contextlib.redirect_stdout(output):
                code = review.main([str(document), "--profile", "release"])
            payload = json.loads(output.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(payload["status"], "incomplete")
        self.assertEqual(payload["summary"]["successful"], 6)
        self.assertEqual(payload["summary"]["degraded"], ["links"])
        self.assertEqual(payload["semantic_reviews"]["command_validation"]["status"], "not_run")

    def test_process_launch_error_remains_a_lane_error(self) -> None:
        with mock.patch.object(review.subprocess, "run", side_effect=OSError("program unavailable")):
            result = review.run_process(["unavailable"], 1)
        self.assertEqual(result["status"], "error")
        self.assertIn("program unavailable", result["error"])

    def test_invalid_timeout_does_not_start_scanners(self) -> None:
        result = self.run_review(str(SKILL_ROOT / "SKILL.md"), "--timeout", "0")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--timeout must be", result.stderr)


if __name__ == "__main__":
    unittest.main()
