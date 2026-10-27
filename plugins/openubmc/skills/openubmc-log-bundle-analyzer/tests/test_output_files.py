"""Portable evidence paths and encoding for saved analyzer results."""
from __future__ import annotations

import io
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


SKILL = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL / "scripts"))
import analyze_bundle as analyzer  # noqa: E402


class SavedOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="openubmc-output-")
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.bundle = self.root / "input"
        logs = self.bundle / "dump_info" / "LogDump"
        logs.mkdir(parents=True)
        (logs / "security.log").write_text(
            "2026-09-02 13:00:01 ERROR login failed 用户 password=private-example\n",
            encoding="utf-8",
        )
        (self.bundle / "dump_info" / "dump_log").write_text("capture\n", encoding="utf-8")

    def run_cli(self, output: pathlib.Path) -> tuple[int, dict]:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = analyzer.main([
                "--bundle-dir", str(self.bundle), "--problem", "login failed 登录失败",
                "--json", "--output-json", str(output),
            ])
        return code, json.loads(stdout.getvalue())

    def test_saved_json_is_utf8_without_bom_and_matches_redacted_stdout(self) -> None:
        output = self.root / "分析 result.json"
        code, payload = self.run_cli(output)
        self.assertEqual(code, 0)
        raw = output.read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(json.loads(raw.decode("utf-8")), payload)
        self.assertNotIn("private-example", raw.decode("utf-8"))
        self.assertIn("登录失败", raw.decode("utf-8"))
        self.assertEqual(payload["result"]["validation"]["root_files"][0]["path"], "dump_info/dump_log")
        analysis = payload["result"]["analysis"]
        self.assertEqual(analysis["evidence"][0]["path"], "dump_info/LogDump/security.log")
        self.assertEqual(analysis["selected_logs"][0]["scanned_paths"], ["dump_info/LogDump/security.log"])

    def test_existing_output_is_preserved_and_reported_as_failure(self) -> None:
        output = self.root / "existing.json"
        output.write_bytes(b"existing content\n")
        code, payload = self.run_cli(output)
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "output_write_failed")
        self.assertEqual(output.read_bytes(), b"existing content\n")

    def test_output_inside_bundle_is_rejected_without_creating_a_file(self) -> None:
        output = self.bundle / "dump_info" / "result.json"
        code, payload = self.run_cli(output)
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "output_path_invalid")
        self.assertFalse(output.exists())

    def test_missing_output_parent_is_reported_without_a_traceback(self) -> None:
        code, payload = self.run_cli(self.root / "missing" / "result.json")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "output_write_failed")
        self.assertNotIn(str(self.root), json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
