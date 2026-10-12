"""Exercise workflow hints from relocated packages without a prepared Runtime."""
from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import unittest

if __package__:
    from .plugin_fixture import package_fixture
else:
    from plugin_fixture import package_fixture


def native_hooks(cwd, environment):
    process = subprocess.Popen(["codex", "app-server", "--stdio"], cwd=cwd, env=environment,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True)
    timer = threading.Timer(15, process.kill)
    timer.start()
    try:
        for number, method, params in (
            (1, "initialize", {"clientInfo": {"name": "entry-test", "version": "1"},
                               "capabilities": {"experimentalApi": True}}),
            (2, "hooks/list", {"cwds": [str(cwd)]}),
        ):
            process.stdin.write(json.dumps({"id": number, "method": method, "params": params}) + "\n")
            process.stdin.flush()
            for line in process.stdout:
                response = json.loads(line)
                if response.get("id") == number:
                    if "error" in response:
                        raise AssertionError(response["error"])
                    if number == 2:
                        return response["result"]["data"][0]["hooks"]
                    break
            else:
                raise AssertionError("Codex closed before returning " + method)
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stdout.close()
        timer.cancel()


@unittest.skipUnless(shutil.which("node"), "Node.js is required")
class PluginSkillEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        cls.plugin = package_fixture(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def invoke(self, event, *, plugin=None, windows=False, raw=None, backend="unavailable"):
        with tempfile.TemporaryDirectory() as temporary:
            isolated = Path(temporary)
            called = isolated / "backend-called"
            unavailable = isolated / "unavailable-python"
            # Mock only the Python process, using a portable Node
            # preload so these checks also run in the Windows public gate.
            preload = isolated / "unavailable-python.cjs"
            preload.write_text(
                'const child = require("child_process");\n'
                'const original = child.spawnSync;\n'
                'child.spawnSync = (command, ...args) => {\n'
                f'  if (command === {json.dumps(str(unavailable))}) {{\n'
                f'    require("fs").writeFileSync({json.dumps(str(called))}, "called");\n'
                f'    const mode = {json.dumps(backend)};\n'
                '    if (mode !== "unavailable") {\n'
                '      const delay = mode === "slow_backend" && !args[0].includes("host-hook") ? 6500 : 20000;\n'
                '      return original(process.execPath, ["-e",\n'
                '        `process.on("SIGTERM", () => {}); setTimeout(() => {}, ${delay})`], args[1]);\n'
                '    }\n'
                '    return {status: 1, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0)};\n'
                '  }\n'
                '  return original(command, ...args);\n'
                '};\n',
                encoding="utf-8",
            )
            environment = {
                **os.environ,
                "CODEX_HOME": str(isolated / "codex"),
                "XDG_CONFIG_HOME": str(isolated / "config"),
                "XDG_DATA_HOME": str(isolated / "data"),
                "OPENUBMC_PLUGIN_PYTHON": str(unavailable),
                "OPENUBMC_PLUGIN_WINDOWS_PYTHON": str(unavailable),
                "OPENUBMC_PLUGIN_HOST_PLATFORM": "win32" if windows else "linux",
            }
            result = subprocess.run(
                ["node", "-r", str(preload),
                 str((plugin or self.plugin) / "scripts/openubmc-continuity-hook.js")],
                input=raw if raw is not None else json.dumps(event), env=environment,
                capture_output=True, text=True, timeout=14,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertFalse((isolated / "codex").exists())
            self.assertFalse((isolated / "data").exists())
            return json.loads(result.stdout), called.exists()

    def test_hung_python_returns_guidance_before_host_timeout(self):
        for windows in (False, True):
            with self.subTest(windows=windows):
                result, called = self.invoke({"hook_event_name": "UserPromptSubmit"},
                                             windows=windows, backend="hung_probe")
                self.assertTrue(called)
                self.assertIn("skill-routing.md", result["hookSpecificOutput"]["additionalContext"])

    def test_probe_and_backend_share_deadline(self):
        result, called = self.invoke({"hook_event_name": "SessionStart"}, backend="slow_backend")
        self.assertTrue(called)
        self.assertIn("skill-routing.md", result["hookSpecificOutput"]["additionalContext"])

    def test_prompt_entry_works_without_python_on_linux_and_windows_adapter(self):
        for windows in (False, True):
            with self.subTest(windows=windows):
                result, backend_called = self.invoke({
                    "hook_event_name": "UserPromptSubmit", "session_id": "new-task",
                    "prompt": "板卡启动后 Web 不通但 SSH 正常，先只读排查。",
                }, windows=windows)
                specific = result["hookSpecificOutput"]
                self.assertEqual(specific["hookEventName"], "UserPromptSubmit")
                guide = self.plugin / "skills/openubmc-debug/references/skill-routing.md"
                self.assertIn(json.dumps(str(guide)), specific["additionalContext"])
                self.assertTrue(guide.is_file())
                self.assertTrue(backend_called)
                self.assertLess(len(specific["additionalContext"].encode()), 2048)

    def test_session_start_keeps_local_entry_when_continuity_backend_is_unavailable(self):
        result, called = self.invoke({"hook_event_name": "SessionStart", "session_id": "new-task"})
        self.assertTrue(called)
        self.assertEqual(result["hookSpecificOutput"]["hookEventName"], "SessionStart")
        lock = json.loads((self.plugin / "plugin-lock.json").read_text())
        self.assertIn(lock["source_commit"], result["hookSpecificOutput"]["additionalContext"])

    def test_prompt_payload_is_not_reflected_and_generic_tasks_get_the_same_conditional_hint(self):
        baseline, _ = self.invoke({"hook_event_name": "UserPromptSubmit", "prompt": "openUBMC 编译失败"})
        result, called = self.invoke({
            "hook_event_name": "UserPromptSubmit", "prompt": "修正普通 Python 脚本的拼写",
            "credentials": "synthetic-secret-do-not-reflect",
            "cwd": "untrusted-path-do-not-reflect",
        })
        self.assertEqual(result, baseline)
        self.assertNotIn("synthetic-secret", json.dumps(result))
        self.assertNotIn("untrusted-path", json.dumps(result))
        self.assertTrue(called)

    def test_stop_does_not_add_a_workflow_hint(self):
        result, _ = self.invoke({"hook_event_name": "Stop", "session_id": "unknown-task"})
        self.assertEqual(result, {})

    def test_invalid_and_oversized_events_are_ignored(self):
        for raw in ("not JSON", "[]", json.dumps({"hook_event_name": "Other"}),
                    json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "x" * 65536})):
            with self.subTest(raw_length=len(raw)):
                result, called = self.invoke(None, raw=raw)
                self.assertEqual(result, {})
                self.assertFalse(called)

    def test_changed_package_does_not_emit_a_verified_skill_pointer(self):
        with tempfile.TemporaryDirectory() as temporary:
            copy = Path(temporary) / "modified"
            shutil.copytree(self.plugin, copy)
            guide = copy / "skills/openubmc-debug/references/skill-routing.md"
            guide.write_text(guide.read_text() + "\nChanged instructions\n")
            result, called = self.invoke({"hook_event_name": "UserPromptSubmit"}, plugin=copy)
            self.assertEqual(result, {})
            self.assertTrue(called)

    def test_packaged_stage_links_resolve_and_keep_existing_invocation_policy(self):
        guide = self.plugin / "skills/openubmc-debug/references/skill-routing.md"
        workflow = json.loads((self.plugin / "workflow.json").read_text())
        for skill in workflow["skills"]:
            if skill["name"] not in workflow["profiles"]["full"]:
                continue
            entry = self.plugin / "skills" / skill["path"] / "SKILL.md"
            pointers = re.findall(r"\[the phase handoff\]\(<?([^>)]+)>?\)", entry.read_text())
            self.assertEqual(len(pointers), 1, skill["name"])
            self.assertEqual((entry.parent / pointers[0]).resolve(), guide.resolve())
        lua_policy = self.plugin / "skills/lua-component/agents/openai.yaml"
        self.assertIn("allow_implicit_invocation: false", lua_policy.read_text())


@unittest.skipUnless(shutil.which("codex") and shutil.which("node"),
                     "Codex and Node are required for native Hook context qualification")
class NativePluginSkillEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.plugin = package_fixture(Path(cls.directory.name))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_native_codex_delivers_packaged_hook_context_to_loopback_model(self):
        # This qualifies trusted Host injection, not natural model selection.
        # The only provider is a local scripted server; no real model is called.
        help_result = subprocess.run(["codex", "exec", "--help"], capture_output=True, text=True)
        if "--dangerously-bypass-hook-trust" not in help_result.stdout:
            self.skipTest("This Codex does not expose the Hook trust qualification interface")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            home = base / "codex-home"
            home.mkdir()
            marketplace = base / "marketplace"
            manifest = marketplace / ".agents/plugins/marketplace.json"
            manifest.parent.mkdir(parents=True)
            (marketplace / "plugins").mkdir()
            shutil.copytree(self.plugin, marketplace / "plugins/openubmc")
            manifest.write_text(json.dumps({"name": "entry-test", "plugins": [{
                "name": "openubmc", "source": {"source": "local", "path": "./plugins/openubmc"},
                "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
                "category": "Productivity",
            }]}))
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(("CODEX_", "OPENAI_", "OPENUBMC_", "XDG_", "PYTHON"))}
            environment.update(CODEX_HOME=str(home), OPENUBMC_ENTRY_TEST_KEY="loopback-fixture",
                               XDG_DATA_HOME=str(base / "data"),
                               OPENUBMC_PLUGIN_PYTHON=str(base / "absent-python"))
            for args in (["plugin", "marketplace", "add", str(marketplace)],
                         ["plugin", "add", "openubmc@entry-test", "--json"]):
                result = subprocess.run(["codex", *args], env=environment,
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
            hooks = native_hooks(base, environment)
            self.assertEqual(len(hooks), 3)
            # Authorize only this verified fixture's exact Hook hashes. Keep
            # normal Host trust enforcement active during the native test.
            trusted = "{" + ", ".join(
                json.dumps(hook["key"]) + " = { trusted_hash = " + json.dumps(hook["currentHash"]) + " }"
                for hook in hooks
            ) + "}"
            observed = []

            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_args):
                    pass

                def do_POST(self):
                    body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                    # Retain only booleans, never the complete model context.
                    observed.append(b"skill-routing.md" in body and b"Plugin version:" in body)
                    item = {"type": "message", "id": "entry-fixture-final", "role": "assistant",
                            "phase": "final_answer", "content": [{"type": "output_text",
                            "text": "Synthetic workflow context checked."}]}
                    events = [
                        {"type": "response.created", "response": {"id": "entry-fixture"}},
                        {"type": "response.output_item.done", "output_index": 0, "item": item},
                        {"type": "response.completed", "response": {"id": "entry-fixture",
                         "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}},
                    ]
                    content = "".join("event: " + event["type"] + "\ndata: " + json.dumps(event)
                                      + "\n\n" for event in events).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            settings = {
                "features.hooks": "true", "model_provider": '"entry_fixture"',
                "hooks.state": trusted,
                "model_providers.entry_fixture.name": '"Loopback entry fixture"',
                "model_providers.entry_fixture.base_url": json.dumps(f"http://127.0.0.1:{server.server_port}/v1"),
                "model_providers.entry_fixture.env_key": '"OPENUBMC_ENTRY_TEST_KEY"',
                "model_providers.entry_fixture.wire_api": '"responses"',
                "model_providers.entry_fixture.supports_websockets": "false",
                # Disabled overrides still need a valid transport when Codex
                # parses the config, before merging the plugin's MCP entries.
                "mcp_servers.openubmc-target-runtime.command": '"node"',
                "mcp_servers.openubmc-target-runtime.enabled": "false",
                "mcp_servers.openubmc-kb.command": '"node"',
                "mcp_servers.openubmc-kb.enabled": "false",
            }
            config = [part for key, value in settings.items() for part in ("-c", key + "=" + value)]
            try:
                result = subprocess.run([
                    "codex", "exec", "--json", "--skip-git-repo-check",
                    "--dangerously-bypass-approvals-and-sandbox",
                    "-C", str(base), "--model", "gpt-6.1-sol", *config,
                    "板卡启动后 Web 不通但 SSH 正常，请先只读定位。",
                ], env=environment, capture_output=True, text=True, timeout=45)
            finally:
                server.shutdown()
                server.server_close()
            self.assertEqual(result.returncode, 0, result.stderr[-1000:])
            self.assertTrue(observed)
            self.assertTrue(all(observed), "Native Codex did not forward the packaged workflow hint")
            contexts = []
            for rollout in home.glob("sessions/**/rollout-*.jsonl"):
                for line in rollout.read_text().splitlines():
                    event = json.loads(line)
                    if event.get("type") == "turn_context":
                        contexts.append(event["payload"])
            self.assertTrue(contexts)
            self.assertTrue(all(item["approval_policy"] == "never" and
                                item["sandbox_policy"]["type"] == "danger-full-access" for item in contexts))


if __name__ == "__main__":
    unittest.main()
