#!/usr/bin/env python3
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# openUBMC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#         http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.


"""用真实 rg 验证候选收集边界；不判定业务缺陷。"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCANNER = Path(__file__).resolve().parents[1] / "scripts/collect_candidates.py"


@unittest.skipUnless(shutil.which("rg") and shutil.which("git"), "需要 ripgrep 和 Git")
class CandidateCollectionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="coredump-candidates-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        subprocess.run(
            ["git", "init", "--quiet", "--template=", str(self.root)],
            check=True,
            capture_output=True,
        )

    def write(self, relative, content):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def run_scanner(self, *arguments, expected_code=0):
        process = subprocess.run(
            [sys.executable, str(SCANNER), "--root", str(self.root), *arguments],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(process.returncode, expected_code, process.stderr)
        return json.loads(process.stdout) if expected_code == 0 else process.stderr

    def paths(self, report, group):
        return [str(Path(entry["path"])) for entry in report["groups"][group]["candidates"]]

    def test_cpp_and_lua_are_candidates_without_defect_verdict(self):
        self.write(
            "source.cpp",
            "std::unordered_map<int, int> m_cache;\n"
            "std::shared_lock lock(m_mutex);\n"
            "queue.then([this] { use(); });\n"
            "std::string_view name;\n"
            "lua_pushinteger(L, value);\n",
        )
        self.write("boundary.lua", 'collectgarbage("collect")\n')
        self.write("notes.txt", "lua_pushinteger(L, value);\n")
        report = self.run_scanner()
        self.assertEqual(report["status"], "candidate_only")
        for group in ["containers", "shared_locks", "callbacks_and_lifecycle", "borrowed_views"]:
            self.assertIn("source.cpp", self.paths(report, group))
        self.assertEqual(self.paths(report, "lua_numbers_and_gc"), ["boundary.lua", "source.cpp"])
        self.assertNotIn("boundary.lua", self.paths(report, "callbacks_and_lifecycle"))
        self.assertNotIn("defects", report)

    def test_repository_ignore_rules_are_not_overridden_by_suffix_filters(self):
        self.write(".gitignore", "ignored.cpp\nignored-lua/\n")
        self.write(".ignore", "also-ignored.cpp\n")
        self.write("visible.cpp", "std::string_view visible;\n")
        self.write("ignored.cpp", "std::string_view hidden;\n")
        self.write("also-ignored.cpp", "std::string_view hidden;\n")
        self.write("ignored-lua/number.lua", 'collectgarbage("collect")\n')
        report = self.run_scanner()
        self.assertEqual(self.paths(report, "borrowed_views"), ["visible.cpp"])
        self.assertEqual(self.paths(report, "lua_numbers_and_gc"), [])

    def test_build_and_vendor_directories_are_excluded(self):
        for directory in ["builddir", "build", "third_party", "third-party", "vendor", "node_modules"]:
            self.write(f"{directory}/hidden.cpp", "std::string_view hidden;\n")
        self.write("src/visible.hpp", "std::string_view visible;\n")
        report = self.run_scanner()
        self.assertEqual(self.paths(report, "borrowed_views"), ["src/visible.hpp"])

    def test_repeated_scopes_and_paths_with_spaces(self):
        self.write("first scope/a.cpp", "std::string_view a;\n")
        self.write("second/b.hpp", "std::string_view b;\n")
        self.write("other/c.cpp", "std::string_view c;\n")
        report = self.run_scanner("--scope", "first scope", "--scope", "second")
        self.assertEqual(report["scopes"], ["first scope", "second"])
        self.assertEqual(self.paths(report, "borrowed_views"), ["first scope/a.cpp", "second/b.hpp"])

    def test_limit_reports_omissions_and_zero_includes_all(self):
        self.write("source.cpp", "std::string_view first;\nstd::string_view second;\n")
        limited = self.run_scanner("--limit", "1")["groups"]["borrowed_views"]
        self.assertEqual((limited["total"], limited["returned"], limited["omitted"]), (2, 1, 1))
        complete = self.run_scanner("--limit", "0")["groups"]["borrowed_views"]
        self.assertEqual((complete["total"], complete["returned"], complete["omitted"]), (2, 2, 0))
        self.assertEqual([entry["line"] for entry in complete["candidates"]], [1, 2])

    def test_default_scope_prefers_libraries_and_can_be_overridden(self):
        self.write("libraries/inside.cpp", "std::string_view inside;\n")
        self.write("outside.cpp", "std::string_view outside;\n")
        report = self.run_scanner()
        self.assertEqual(report["scopes"], ["libraries"])
        self.assertEqual(self.paths(report, "borrowed_views"), ["libraries/inside.cpp"])
        report = self.run_scanner("--scope", ".")
        self.assertEqual(self.paths(report, "borrowed_views"), ["libraries/inside.cpp", "outside.cpp"])

    def test_empty_repository_is_not_a_clean_bill_of_health(self):
        report = self.run_scanner()
        self.assertEqual(report["status"], "candidate_only")
        self.assertTrue(all(group["total"] == 0 for group in report["groups"].values()))
        self.assertIn("coverage", report)

    def test_invalid_arguments_are_rejected(self):
        for arguments, expected in [
            (("--scope", "../"), "不能超出"),
            (("--scope", "missing"), "不存在"),
            (("--limit", "-1"), "大于等于 0"),
            (("--root", str(self.root / "missing")), "必须为存在的目录"),
        ]:
            with self.subTest(arguments=arguments):
                self.assertIn(expected, self.run_scanner(*arguments, expected_code=2))

    def test_symlink_scope_cannot_escape_root(self):
        with tempfile.TemporaryDirectory(prefix="coredump-external-") as external:
            link = self.root / "outside"
            try:
                link.symlink_to(external, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("当前环境不支持目录符号链接")
            self.assertIn("不能超出", self.run_scanner("--scope", "outside", expected_code=2))

    def test_explicit_file_scope_documents_ignore_override(self):
        self.write(".gitignore", "ignored.cpp\n")
        self.write("ignored.cpp", "std::string_view explicitly_requested;\n")
        report = self.run_scanner("--scope", "ignored.cpp")
        self.assertEqual(self.paths(report, "borrowed_views"), ["ignored.cpp"])

    def test_source_files_are_unchanged(self):
        self.write("source.cpp", "std::string_view example;\n")
        self.write("boundary.lua", 'collectgarbage("collect")\n')
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.run_scanner()
        after = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main(verbosity=2)
