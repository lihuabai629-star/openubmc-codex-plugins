"""Structured analysis, original evidence and bounded disclosure on native hosts."""
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
from offline_tools import call_tool


class OfflineToolsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="offline 中文 ' spaces ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / "input $(literal)"
        self.logs = self.bundle / "dump_info/LogDump"
        self.logs.mkdir(parents=True)
        (self.bundle / "dump_info/dump_log").write_text("capture\n", encoding="utf-8")
        (self.logs / "security.log").write_text(
            "2026-09-02 13:00:00 user=private-user host=internal-host password=secret-login login failed\n"
            "2026-09-02 13:01:00 login failed ip=192.0.2.7\n", encoding="utf-8")
        self.artifacts = self.root / "artifacts"

    def call(self, name, arguments):
        return call_tool(name, arguments, cwd=self.root, artifact_dir=self.artifacts)

    def analyze(self, **options):
        return self.call("openubmc_analyze_bundle", {"source": str(self.bundle), "problem": "login failed", **options})

    def read(self, **options):
        return self.call("openubmc_read_evidence", {"bundle_dir": str(self.bundle),
                         "path": "dump_info/LogDump/security.log", **options})

    def test_analysis_saves_complete_json_and_original_evidence_pointers(self):
        result = self.analyze(summary_limit=1, since="2026-09-02T12:59:00", until="2026-09-02T13:02:00")
        self.assertTrue(result["ok"], result)
        raw = Path(result["artifact"]).read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        payload = json.loads(raw.decode("utf-8"))
        evidence = payload["result"]["analysis"]["evidence"]
        self.assertEqual(result["evidence"]["total"], len(evidence))
        self.assertLessEqual(len(result["evidence"]["items"]), 1)
        pointer = result["evidence"]["items"][0]
        original = self.call("openubmc_read_evidence", {"bundle_dir": result["bundle_dir"], "path": pointer["path"],
                              "start_line": pointer["line_number"], "line_count": 1})
        self.assertTrue(original["ok"], original)
        self.assertEqual(original["lines"][0]["line_number"], pointer["line_number"])
        self.assertIn("login failed", original["lines"][0]["text"])
        for secret in ("private-user", "internal-host", "secret-login", "192.0.2.7"):
            self.assertNotIn(secret, raw.decode("utf-8"))
            self.assertNotIn(secret, json.dumps(original))

    def test_relative_paths_are_resolved_from_the_supplied_host_directory(self):
        result = self.call("openubmc_analyze_bundle", {"source": self.bundle.name, "problem": "login failed"})
        self.assertTrue(result["ok"], result)

    def test_large_path_lists_stay_in_the_artifact_and_keep_response_totals(self):
        initial = self.analyze()
        payload = json.loads(Path(initial["artifact"]).read_bytes())
        payload["result"]["bundle"]["bundle_root"] = str(self.bundle)
        payload["result"]["analysis"]["selected_logs"] = [
            {"name": f"log-{number}", "scanned_paths": ["dump_info/" + str(index) + "p" * 2000 for index in range(64)]}
            for number in range(32)]
        with patch("offline_tools.run_request", return_value=payload):
            result = self.analyze(summary_limit=32)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["response_truncated"])
        self.assertLessEqual(len(json.dumps(result, ensure_ascii=False).encode("utf-8")), 256 * 1024)
        self.assertEqual(result["selected_logs"]["total"], 32)
        full = json.loads(Path(result["artifact"]).read_bytes())
        self.assertEqual(len(full["result"]["analysis"]["selected_logs"][0]["scanned_paths"]), 64)

    def test_repeated_analysis_creates_new_files_and_preserves_existing_output(self):
        first = self.analyze()
        content = Path(first["artifact"]).read_bytes()
        second = self.analyze()
        self.assertTrue(second["ok"], second)
        self.assertNotEqual(first["artifact"], second["artifact"])
        self.assertEqual(Path(first["artifact"]).read_bytes(), content)

    def test_analyzer_never_writes_inside_its_input_tree(self):
        result = self.analyze(output_dir=str(self.logs / "output"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "output_path_invalid")
        self.assertFalse((self.logs / "output").exists())

    def test_archive_analysis_extracts_once_and_returns_a_readable_bundle(self):
        archive = self.root / "logs 中文.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            output.add(self.bundle / "dump_info", arcname="dump_info")
        result = self.call("openubmc_analyze_bundle", {"source": str(archive), "problem": "login failed"})
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(result["source_sha256"]), 64)
        pointer = result["evidence"]["items"][0]
        self.assertTrue(self.call("openubmc_read_evidence", {"bundle_dir": result["bundle_dir"],
                                                            "path": pointer["path"]})["ok"])

    def test_unknown_fields_and_invalid_values_cannot_become_commands(self):
        for arguments in ({"command": "echo unexpected"}, {"source": str(self.bundle), "problem": "login", "argv": []},
                          {"source": str(self.bundle), "problem": "login", "limits": {"max_files": 0}},
                          {"source": str(self.bundle), "problem": "login", "summary_limit": True}):
            with self.subTest(arguments=arguments):
                result = self.call("openubmc_analyze_bundle", arguments)
                self.assertFalse(result["ok"])
                self.assertEqual(result["code"], "invalid_request")

    def test_bad_time_window_and_missing_source_return_structured_failures(self):
        self.assertFalse(self.analyze(since="not-a-date")["ok"])
        result = self.call("openubmc_analyze_bundle", {"source": "missing", "problem": "login"})
        self.assertFalse(result["ok"])
        self.assertNotIn(str(self.root), result.get("error", ""))

    def test_traversal_absolute_paths_and_windows_streams_are_rejected(self):
        for path in ("../private", "/etc/passwd", "dump_info/../secret", "dump_info/./secret",
                     "C:/secret", "dump_info/LogDump/security.log:stream", "dump_info\\LogDump\\security.log"):
            with self.subTest(path=path):
                self.assertEqual(self.read(path=path)["code"], "evidence_path_invalid")

    def test_input_links_and_output_links_are_rejected(self):
        link = self.logs / "link.log"
        try:
            link.symlink_to(self.logs / "security.log")
        except OSError as error:
            self.skipTest(f"Host cannot create symbolic links: {type(error).__name__}")
        self.assertFalse(self.read(path="dump_info/LogDump/link.log")["ok"])
        output = self.root / "linked-output"
        output.symlink_to(self.logs, target_is_directory=True)
        self.assertFalse(self.analyze(output_dir=str(output))["ok"])

    def test_reader_preserves_line_numbers_for_gzip_and_dump_info_input(self):
        with gzip.open(self.logs / "rotated.log.1.gz", "wb") as handle:
            handle.write(b"first\nsecond password=never-show\nthird\n")
        result = self.read(bundle_dir=str(self.bundle / "dump_info"), path="dump_info/LogDump/rotated.log.1.gz",
                           start_line=2, line_count=1)
        self.assertTrue(result["ok"], result)
        self.assertEqual([line["line_number"] for line in result["lines"]], [2])
        self.assertNotIn("never-show", json.dumps(result))

    def test_limits_distinguish_output_truncation_and_incomplete_scan(self):
        result = self.read(max_output_bytes=1)
        self.assertTrue(result["output_truncated"])
        self.assertFalse(result["complete"])
        partial = self.read(max_scan_bytes=10)
        self.assertFalse(partial["complete"])
        self.assertEqual(partial["lines"], [])
        self.assertTrue(partial["warnings"])
        analysis = self.analyze(limits={"max_total_bytes": 10})
        self.assertTrue(analysis["ok"], analysis)
        self.assertFalse(analysis["scan"]["complete"])
        self.assertTrue(analysis["scan"]["warnings"]["total"])

    def test_binary_and_directory_inputs_return_explicit_failures(self):
        (self.logs / "binary").write_bytes(b"a\0b\n")
        self.assertFalse(self.read(path="dump_info/LogDump/binary")["ok"])
        self.assertFalse(self.read(path="dump_info/LogDump")["ok"])

    def test_padding_diagnostics_remain_bounded_when_seeking_to_a_later_line(self):
        (self.logs / "padding.log").write_bytes((b"\0" * 16 + b"\n") * 200 + b"login failed\n")
        result = self.read(path="dump_info/LogDump/padding.log", start_line=201, line_count=1)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["lines"][0]["line_number"], 201)
        self.assertEqual(result["diagnostic_counts"]["warnings"], 200)
        self.assertLessEqual(len(result["warnings"]), 32)
        self.assertTrue(result["diagnostics_truncated"])
        self.assertFalse(result["complete"])

    def test_private_key_body_is_hidden_even_when_window_starts_inside_block(self):
        (self.logs / "key.log").write_text("-----BEGIN PRIVATE KEY-----\nvery-private-body\n-----END PRIVATE KEY-----\nafter\n")
        result = self.read(path="dump_info/LogDump/key.log", start_line=2, line_count=1)
        self.assertTrue(result["redacted"])
        self.assertNotIn("very-private-body", json.dumps(result))

    def test_json_worker_handles_unicode_paths_without_shell_parsing(self):
        request = {"tool": "openubmc_analyze_bundle", "arguments": {"source": str(self.bundle), "problem": "login failed 中文"},
                   "cwd": str(self.root), "artifact_dir": str(self.artifacts)}
        process = subprocess.run([sys.executable, "-B", str(SCRIPTS / "offline_tools.py")],
                                 input=json.dumps(request).encode("utf-8"), capture_output=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(json.loads(process.stdout)["ok"])

    def test_native_long_resource_paths_keep_sibling_imports(self):
        if sys.platform != "win32":
            self.skipTest("Native Windows long-path import check")
        extended_root = Path("\\\\?\\" + str(self.root))
        nested = extended_root.joinpath(*(["resource directory 中文"] * 12))
        self.addCleanup(shutil.rmtree, extended_root / "resource directory 中文", True)
        skill = SCRIPTS.parent
        target = nested / "analyzer"
        shutil.copytree(skill / "scripts", target / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(skill / "references", target / "references")
        script = str(target / "scripts/offline_tools.py")
        self.assertGreater(len(script), 260)
        request = {"tool": "openubmc_read_evidence", "arguments": {"bundle_dir": str(self.bundle),
                   "path": "dump_info/LogDump/security.log"}, "cwd": str(self.root), "artifact_dir": str(self.artifacts)}
        process = subprocess.run([sys.executable, "-B", script], input=json.dumps(request).encode("utf-8"),
                                 capture_output=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(json.loads(process.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
