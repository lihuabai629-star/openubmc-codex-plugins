#!/usr/bin/env python3
"""Tests for rackmount_web_backend_check.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("rackmount_web_backend_check.py")


class CheckerTest(unittest.TestCase):
    def make_repo(self, exported_name: str) -> Path:
        root = Path(self.temp_dir.name)
        web_backend = root / "interface_config" / "web_backend"
        mapping = web_backend / "mapping_config" / "Services"
        plugin = web_backend / "plugins" / "orchestrator"
        script = web_backend / "script" / "services"
        mapping.mkdir(parents=True)
        plugin.mkdir(parents=True)
        script.mkdir(parents=True)

        data = {
            "Resources": [
                {
                    "Uri": "/UI/Rest/Services/Example",
                    "Statements": {
                        "PluginValue": {
                            "Steps": [
                                {
                                    "Type": "Plugin",
                                    "Formula": ("orchestrator.example.build_result(Input)"),
                                }
                            ]
                        },
                        "ScriptValue": {
                            "Steps": [
                                {
                                    "Type": "Script",
                                    "Formula": "services/get_value.lua",
                                }
                            ]
                        },
                    },
                }
            ]
        }
        (mapping / "Example.json").write_text(json.dumps(data), encoding="utf-8")
        (plugin / "example.lua").write_text(
            f"local m = {{}}\nfunction m.{exported_name}(input)\n" "    return input\nend\nreturn m\n",
            encoding="utf-8",
        )
        (script / "get_value.lua").write_text("return Input\n", encoding="utf-8")
        return root

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def run_checker(self, repo: Path, require_version: bool = False) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(repo),
            "--uri",
            "/UI/Rest/Services/Example",
        ]
        if require_version:
            command.append("--require-version")
        return subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
        )

    def init_git_repo(self, repo: Path) -> None:
        version_file = repo / "mds" / "service.json"
        version_file.parent.mkdir(parents=True)
        version_file.write_text('{"version": "1.0.0"}\n', encoding="utf-8")
        subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.name", "Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "add", "."],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-m", "test: baseline"],
            check=True,
            capture_output=True,
        )

    def test_valid_plugin_and_script(self) -> None:
        result = self.run_checker(self.make_repo("build_result"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("plugin export: orchestrator.example.build_result", result.stdout)
        self.assertIn("script formula services/get_value.lua", result.stdout)
        self.assertIn("Summary: 0 failure(s)", result.stdout)

    def test_missing_plugin_export_fails(self) -> None:
        result = self.run_checker(self.make_repo("other_function"))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("missing export orchestrator.example.build_result", result.stdout)

    def test_script_formula_cannot_escape_script_directory(self) -> None:
        repo = self.make_repo("build_result")
        mapping = repo / "interface_config" / "web_backend" / "mapping_config" / "Services" / "Example.json"
        data = json.loads(mapping.read_text(encoding="utf-8"))
        steps = data["Resources"][0]["Statements"]["ScriptValue"]["Steps"]
        steps[0]["Formula"] = "../plugins/orchestrator/example.lua"
        mapping.write_text(json.dumps(data), encoding="utf-8")

        result = self.run_checker(repo)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("escapes the script directory", result.stdout)

    def test_behavior_change_requires_component_version(self) -> None:
        repo = self.make_repo("build_result")
        self.init_git_repo(repo)
        plugin = repo / "interface_config" / "web_backend" / "plugins" / "orchestrator" / "example.lua"
        plugin.write_text(plugin.read_text(encoding="utf-8") + "\n", encoding="utf-8")

        result = self.run_checker(repo, require_version=True)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("component version is unchanged", result.stdout)

    def test_behavior_and_component_version_changes_pass(self) -> None:
        repo = self.make_repo("build_result")
        self.init_git_repo(repo)
        plugin = repo / "interface_config" / "web_backend" / "plugins" / "orchestrator" / "example.lua"
        plugin.write_text(plugin.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        version_file = repo / "mds" / "service.json"
        version_file.write_text('{"version": "1.0.1"}\n', encoding="utf-8")

        result = self.run_checker(repo, require_version=True)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("component version changed: mds/service.json", result.stdout)


if __name__ == "__main__":
    unittest.main()
