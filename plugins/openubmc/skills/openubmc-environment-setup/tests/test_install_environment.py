#!/usr/bin/env python3
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent
INSTALLER = ROOT / "scripts" / "install_environment.py"
SPEC = importlib.util.spec_from_file_location("openubmc_environment_installer", INSTALLER)
assert SPEC is not None and SPEC.loader is not None
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)

from scripts.codex_process_probe import probe_codex_runtime


EXPECTED_BUNDLE = (
    ("openubmc-environment-setup", "openubmc-environment-setup"),
    ("openubmc-debug", "openubmc-debug"),
    ("openubmc-log-analyzer", "openubmc-log-analyzer"),
    ("openubmc-developer", "openubmc-developer"),
    ("openubmc-build", "openubmc-build"),
    ("openubmc-upgrade", "openubmc-upgrade"),
    ("openubmc-live-patch", "openubmc-live-patch"),
    ("openubmc-dt-testing", "testing"),
    ("openubmc-publish", "openubmc-publish"),
    ("openubmc-lua-component", "lua-component"),
    ("openubmc-qemu-testing", "qemu-testing"),
)
EXPECTED_TARGET_RUNTIME_BUNDLE = (
    ("openubmc-environment-setup", "openubmc-environment-setup"),
    ("openubmc-debug", "openubmc-debug"),
    ("openubmc-log-analyzer", "openubmc-log-analyzer"),
    ("openubmc-developer", "openubmc-developer"),
    ("openubmc-build", "openubmc-build"),
    ("openubmc-upgrade", "openubmc-upgrade"),
    ("openubmc-live-patch", "openubmc-live-patch"),
)

class EnvironmentSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.source = self.root / "skills-source"
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        fixture_tools = {
            *installer.REQUIRED_TOOLS,
            *installer.CONDITIONAL_TOOLS,
            *installer.RECOMMENDED_TOOLS,
            "codex",
        }
        for tool in fixture_tools:
            executable = self.bin_dir / tool
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
        for canonical, relative in EXPECTED_BUNDLE:
            directory = self.source / relative
            directory.mkdir(parents=True)
            (directory / "SKILL.md").write_text(
                f"---\nname: {canonical}\ndescription: Test fixture.\n---\n",
                encoding="utf-8",
            )
        shutil.copytree(
            REPO_ROOT / "openubmc-target-runtime" / "openubmc_target_runtime",
            self.source / "openubmc-target-runtime" / "openubmc_target_runtime",
        )
        shutil.copytree(
            REPO_ROOT / "openubmc-kb-mcp",
            self.source / "openubmc-kb-mcp",
            ignore=shutil.ignore_patterns("node_modules"),
        )
        kb_sdk = (
            self.source
            / "openubmc-kb-mcp"
            / "node_modules"
            / "@modelcontextprotocol"
            / "sdk"
        )
        kb_sdk.mkdir(parents=True)
        (kb_sdk / "package.json").write_text("{}\n", encoding="utf-8")
        debug_mcp = self.source / "openubmc-debug" / "scripts" / "target_runtime_mcp.py"
        debug_mcp.parent.mkdir(parents=True)
        debug_mcp.write_text(
            "import json, os\n"
            "from pathlib import Path\n"
            "from openubmc_target_runtime import JsonRpcMcpEndpoint, McpProcessLifecycle, RuntimeMcpService, StdioMcpServer\n"
            "class Task:\n"
            "    def __init__(self, task_id):\n"
            "        self.task_id = task_id\n"
            "class Backend:\n"
            "    def open_task(self, task_id):\n"
            "        return Task(task_id)\n"
            "    def close_task(self, task):\n"
            "        return None\n"
            "    def maintain_task(self, task):\n"
            "        return 0\n"
            "    def task_status(self, task):\n"
            "        return {'task_id': task.task_id}\n"
            "    def debug_run(self, task, arguments, context):\n"
            "        context.raise_if_stopped()\n"
            "        return {'schema': 'openubmc-debug.v1', "
            "'task': task.task_id, 'root_cause': 'hermetic diagnosis', "
            "'observed_at': '2026-08-31T00:00:00Z', "
            "'freshness': {'status': 'fresh'}}\n"
            "    def debug_collect(self, task, arguments, context):\n"
            "        return self.debug_run(task, arguments, context)\n"
            "service = RuntimeMcpService(Backend())\n"
            "endpoint = JsonRpcMcpEndpoint(service, "
            "session_task_id='codex-adoption-probe')\n"
            "state_root = Path(os.environ.get('OPENUBMC_TARGET_RUNTIME_STATE_DIR', Path.home() / '.local/state/openubmc-test-runtime'))\n"
            "lifecycle_root = Path(os.environ.get('OPENUBMC_MCP_LIFECYCLE_DIR', state_root / 'mcp-processes'))\n"
            "lifecycle = McpProcessLifecycle(\n"
            "    component='target-runtime', version='openubmc.target-runtime.v1',\n"
            "    client=os.environ.get('OPENUBMC_MCP_CLIENT', 'codex'),\n"
            "    task_id=os.environ.get('OPENUBMC_MCP_TASK_ID', 'runtime-health'),\n"
            "    session_id=os.environ.get('OPENUBMC_MCP_SESSION_ID', 'runtime-health'),\n"
            "    source_commit=os.environ.get('OPENUBMC_MCP_SOURCE_COMMIT', 'unknown-source-commit'),\n"
            "    model_identity=json.loads(os.environ.get('OPENUBMC_MCP_MODEL_IDENTITY', '{}')),\n"
            "    codex_identity=json.loads(os.environ.get('OPENUBMC_MCP_CODEX_IDENTITY', '{}')),\n"
            "    formal_run=os.environ.get('OPENUBMC_MCP_FORMAL_RUN') == '1',\n"
            "    parent_pid=os.getppid(), state_path=state_root,\n"
            "    lifecycle_root=lifecycle_root,\n"
            "    idle_timeout_seconds=30,\n"
            ")\n"
            "StdioMcpServer(endpoint, process_lifecycle=lifecycle).serve()\n",
            encoding="utf-8",
        )
        for helper in (
            "_target_runtime_adapter.py",
            "target_runtime_cli.py",
            "workflow_remote.py",
        ):
            (debug_mcp.parent / helper).write_text("# test fixture\n", encoding="utf-8")
        release_validator = self.source / "scripts" / "validate_workflow.py"
        release_validator.parent.mkdir(parents=True)
        release_validator.write_text(
            "#!/usr/bin/env python3\nraise SystemExit(0)\n",
            encoding="utf-8",
        )
        release_validator.chmod(0o755)
        (self.source / "workflow.json").write_text(
            json.dumps(
                {
                    "schema_version": "openubmc-agent-workflow.v1",
                    "version": "1.1.1",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.original_tool_search_path = installer.tool_search_path
        self.tool_search_path_patch = mock.patch.object(
            installer,
            "tool_search_path",
            side_effect=lambda tool_dirs: self.original_tool_search_path(
                [str(self.bin_dir), *tool_dirs]
            ),
        )
        self.tool_search_path_patch.start()
        self.environment_patch = mock.patch.dict(
            installer.os.environ, {"SHELL": "/bin/bash"}, clear=False
        )
        self.environment_patch.start()
        installer.os.environ.pop("XDG_CONFIG_HOME", None)
        installer.os.environ.pop("OPENUBMC_KB_CONFIG", None)

    def tearDown(self) -> None:
        self.environment_patch.stop()
        self.tool_search_path_patch.stop()
        self.temporary.cleanup()

    @staticmethod
    def credential_values() -> dict[str, str]:
        return {
            "OPENUBMC_SSH_USER": "fixture-bmc-user",
            "OPENUBMC_SSH_PASSWORD": "fixture-bmc-password",
            "OPENUBMC_TELNET_USER": "fixture-telnet-user",
            "OPENUBMC_TELNET_PASSWORD": "fixture-telnet-password",
            "REDFISH_USERNAME": "fixture-bmc-user",
            "REDFISH_PASSWORD": "fixture-bmc-password",
            "OPENUBMC_OS_SSH_USER": "fixture-os-user",
            "OPENUBMC_OS_SSH_PASSWORD": "fixture-os-password",
        }

    def prepare_credentials(self) -> Path:
        path = installer.credentials_path(self.home)
        installer.write_credentials_file(path, self.credential_values(), False)
        return path

    def create_release_remote(self) -> tuple[Path, str]:
        source = self.root / "release-repository"
        for canonical, relative in EXPECTED_TARGET_RUNTIME_BUNDLE:
            directory = source / relative
            directory.mkdir(parents=True)
            (directory / "SKILL.md").write_text(
                f"---\nname: {canonical}\ndescription: Release fixture.\n---\n",
                encoding="utf-8",
            )
        fixture_installer = (
            source
            / "openubmc-environment-setup"
            / "scripts"
            / "install_environment.py"
        )
        fixture_installer.parent.mkdir(parents=True)
        fixture_installer.write_text(
            "#!/usr/bin/env python3\n"
            "import json\n"
            "import os\n"
            "from pathlib import Path\n"
            "import sys\n"
            "capture = os.environ.get('OPENUBMC_REMEDIATION_CAPTURE')\n"
            "if capture:\n"
            "    Path(capture).write_text(json.dumps(sys.argv[1:]), encoding='utf-8')\n",
            encoding="utf-8",
        )
        release_verifier = (
            source
            / "openubmc-target-runtime"
            / "openubmc_target_runtime"
            / "release.py"
        )
        release_verifier.parent.mkdir(parents=True)
        release_verifier.write_text(
            "#!/usr/bin/env python3\nraise SystemExit(0)\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["git", "init", "--initial-branch", "main", str(source)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            ["git", "-C", str(source), "config", "user.name", "Workflow Tests"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(source), "config", "user.email", "workflow@example.invalid"],
            check=True,
        )
        subprocess.run(["git", "-C", str(source), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(source), "commit", "-m", "release fixture"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        commit = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "-C", str(source), "tag", "v1.2.3"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(source), "branch", "release-v1"],
            check=True,
        )
        remote = self.root / "release-repository.git"
        subprocess.run(
            ["git", "clone", "--bare", str(source), str(remote)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        return remote, commit

    def publish_second_release(self, remote: Path, tag: str = "v1.2.4") -> str:
        release_source = self.root / "release-repository"
        skill = release_source / "openubmc-debug" / "SKILL.md"
        skill.write_text(
            skill.read_text(encoding="utf-8") + "\nSecond release.\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(release_source), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(release_source), "commit", "-m", "second release"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        commit = subprocess.run(
            ["git", "-C", str(release_source), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "-C", str(release_source), "tag", tag],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(release_source), "push", str(remote), "main", "--tags"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        return commit

    def args(self, *extra: str):
        return installer.parse_args(
            [
                "--home",
                str(self.home),
                "--source",
                str(self.source),
                "--non-interactive",
                *extra,
            ]
        )

    def install(self, *extra: str) -> tuple[int, str]:
        output = io.StringIO()
        with (
            mock.patch.object(
                installer, "resolve_tool_dirs", return_value=([str(self.bin_dir)], [])
            ),
            mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
            mock.patch.object(
                installer,
                "knowledge_mcp_health",
                return_value=(True, "ok", ["openubmc_kb_query", "openubmc_kb_status", "openubmc_kb_list"], False),
            ),
            redirect_stdout(output),
        ):
            result = installer.perform_install(self.args("--install", *extra))
        return result, output.getvalue()

    def check(self) -> tuple[int, str]:
        output = io.StringIO()
        args = installer.parse_args(["--home", str(self.home), "--check"])
        with (
            mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
            mock.patch.object(
                installer,
                "knowledge_mcp_health",
                return_value=(True, "ok", ["openubmc_kb_query", "openubmc_kb_status", "openubmc_kb_list"], False),
            ),
            redirect_stdout(output),
        ):
            result = installer.perform_check(args)
        return result, output.getvalue()

    def qualify_product_client(
        self,
        client: str,
    ) -> tuple[dict[str, object], Path]:
        self.prepare_credentials()
        repository = os.environ.get("OPENUBMC_PRODUCT_CLIENT_REPO_URL", "")
        release_commit = os.environ.get(
            "OPENUBMC_PRODUCT_CLIENT_RELEASE_COMMIT", ""
        )
        if repository and release_commit:
            output_stream = io.StringIO()
            args = installer.parse_args(
                [
                    "install",
                    "--home",
                    str(self.home),
                    "--source-mode",
                    "managed",
                    "--repo-url",
                    repository,
                    "--ref",
                    release_commit,
                    "--clients",
                    client,
                    "--non-interactive",
                ]
            )
            with (
                mock.patch.object(
                    installer,
                    "resolve_tool_dirs",
                    return_value=([str(self.bin_dir)], []),
                ),
                mock.patch.object(
                    installer,
                    "knowledge_http_health",
                    return_value=(True, "ok"),
                ),
                mock.patch.object(
                    installer,
                    "knowledge_mcp_health",
                    return_value=(
                        True,
                        "ok",
                        [
                            "openubmc_kb_query",
                            "openubmc_kb_status",
                            "openubmc_kb_list",
                        ],
                        False,
                    ),
                ),
                redirect_stdout(output_stream),
            ):
                result = installer.perform_install(args)
            output = output_stream.getvalue()
        else:
            result, output = self.install("--clients", client)
        self.assertEqual(result, 0, output)
        state = installer.load_state(self.home)
        installed_source = Path(str(state["source_root"]))
        skills_dir = installer.client_skills_dir(self.home, client)
        for canonical, relative in EXPECTED_BUNDLE:
            self.assertTrue(
                installer.same_target(
                    skills_dir / canonical,
                    installed_source / relative,
                )
            )
        launcher = Path(state["runtime"]["launcher_path"])
        return state, launcher

    def record_product_client_evidence(
        self,
        *,
        client: str,
        command: Path,
        adapter_available: bool,
        mcp_registration_verified: bool,
    ) -> None:
        healthy, detail, tools = installer.runtime_mcp_health(
            command,
            self.home,
        )
        self.assertTrue(healthy, detail)
        self.assertEqual(tools, ["execute", "observe"])
        requests = "\n".join(
            json.dumps(request, separators=(",", ":"))
            for request in (
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {
                            "name": "codex-adoption-qualification",
                            "version": "1",
                        },
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "execute",
                        "arguments": {
                            "kind": "resume",
                        },
                        "_meta": {"codex/taskId": "codex-adoption-probe"},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/openubmc-task-complete",
                    "params": {
                        "_meta": {"codex/taskId": "codex-adoption-probe"}
                    },
                },
            )
        ) + "\n"
        harness_lifecycle_root = (
            self.home / ".local" / "state" / "codex-product-harness-lifecycle"
        )
        lifecycle_root = self.home / ".local" / "state" / "codex-product-lifecycle"
        runtime_state_root = self.home / ".local" / "state" / "codex-product-runtime"
        environment = {
            **os.environ,
            "HOME": str(self.home),
            "CODEX_HOME": str(self.home / ".codex"),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "OPENUBMC_MCP_CLIENT": "codex",
            "OPENUBMC_MCP_TASK_ID": "codex-adoption-probe",
            "OPENUBMC_MCP_SESSION_ID": "codex-adoption-session",
            "OPENUBMC_MCP_MODEL_IDENTITY": os.environ.get(
                "OPENUBMC_PRODUCT_CLIENT_MODEL_IDENTITY",
                json.dumps({"model": "codex-product-client-qualification"}),
            ),
            "OPENUBMC_MCP_CODEX_IDENTITY": os.environ.get(
                "OPENUBMC_PRODUCT_CLIENT_CODEX_IDENTITY",
                json.dumps({"version": "codex-cli 0.151.0"}),
            ),
            "OPENUBMC_MCP_FORMAL_RUN": "0",
            "OPENUBMC_MCP_LIFECYCLE_DIR": str(harness_lifecycle_root),
            "OPENUBMC_TARGET_RUNTIME_STATE_DIR": str(runtime_state_root),
        }
        def run_runtime(payload: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [str(command)],
                input=payload,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=15,
                env=environment,
            )

        completed = run_runtime(requests)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        responses = {
            document.get("id"): document
            for document in (
                json.loads(line) for line in completed.stdout.splitlines()
            )
            if isinstance(document, dict)
        }
        workflow_result = responses[3]["result"]
        structured = workflow_result["structuredContent"]
        self.assertTrue(workflow_result["isError"])
        self.assertEqual(
            structured["interaction_telemetry"]["classification"],
            "preflight_failure",
            structured,
        )
        self.assertEqual(structured["error"]["field"], "run_id")
        self.assertTrue(structured["error"]["example"]["run_id"])
        state = installer.load_state(self.home)
        runtime = state["runtime"]
        harness_records = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(harness_lifecycle_root.glob("*.json"))
        ]
        self.assertEqual(len(harness_records), 1)
        self.assertFalse(harness_records[0]["formal_run"])
        self.assertEqual(harness_records[0]["exit_reason"], "task-closeout")
        launcher_state_verified = command.read_text(encoding="utf-8") == (
            installer.render_runtime_launcher(runtime)
        )
        evidence_path = os.environ.get("OPENUBMC_PRODUCT_CLIENT_EVIDENCE", "")
        if not evidence_path:
            return
        model_identity = json.loads(
            os.environ["OPENUBMC_PRODUCT_CLIENT_MODEL_IDENTITY"]
        )
        codex_identity = json.loads(
            os.environ["OPENUBMC_PRODUCT_CLIENT_CODEX_IDENTITY"]
        )
        self.assertIsInstance(model_identity, dict)
        self.assertIsInstance(codex_identity, dict)
        codex_probe = probe_codex_runtime(
            repository_root=REPO_ROOT,
            home=self.home,
            qualification_root=self.root,
            lifecycle_root=lifecycle_root,
            runtime_state_root=runtime_state_root,
            model_identity=model_identity,
            codex_identity=codex_identity,
            source_commit=runtime["source_commit"],
            task_id="codex-adoption-probe",
            session_id="codex-adoption-session",
        )
        lifecycle_records = codex_probe["mcp_lifecycle_records"]
        self.assertEqual(len(lifecycle_records), 2)
        process_runs = codex_probe["codex_process_runs"]
        self.assertEqual(len(process_runs), 2)
        process_bindings = {
            (run["process_id"], run["process_identity"])
            for run in process_runs
        }
        for lifecycle in lifecycle_records:
            self.assertEqual(lifecycle["client"], "codex")
            self.assertEqual(lifecycle["task_id"], "codex-adoption-probe")
            self.assertEqual(lifecycle["session_id"], "codex-adoption-session")
            self.assertEqual(lifecycle["source_commit"], runtime["source_commit"])
            self.assertTrue(lifecycle["formal_run"])
            self.assertTrue(lifecycle["parent_identity_verified"])
            self.assertIsInstance(
                lifecycle["parent_identity_currently_verified"], bool
            )
            self.assertIn(
                (lifecycle["parent_pid"], lifecycle["parent_identity"]),
                process_bindings,
            )
            self.assertEqual(
                lifecycle["runtime_state_root"], str(runtime_state_root)
            )
            self.assertEqual(lifecycle["lifecycle_state"], "stopped")
            self.assertEqual(lifecycle["active_requests"], 0)
            self.assertEqual(lifecycle["exit_reason"], "client-terminated")
        operator_status_process = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "mcp_process_lifecycle.py"),
                "status",
                "--root",
                str(lifecycle_root),
                "--task-id",
                "codex-adoption-probe",
                "--session-id",
                "codex-adoption-session",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
        )
        self.assertEqual(
            operator_status_process.returncode,
            0,
            operator_status_process.stderr,
        )
        operator_status = json.loads(operator_status_process.stdout)
        task_home = self.home.absolute()
        codex_config_root = (self.home / ".codex").absolute()
        runtime_state_root = runtime_state_root.absolute()
        lifecycle_root = lifecycle_root.absolute()
        qualification_root = task_home
        isolated_roots = (
            task_home,
            codex_config_root,
            runtime_state_root,
            lifecycle_root,
        )
        global_home = Path.home().absolute()
        global_codex_config = Path(
            os.environ.get("CODEX_HOME", global_home / ".codex")
        ).absolute()
        global_xdg_config = Path(
            os.environ.get("XDG_CONFIG_HOME", global_home / ".config")
        ).absolute()
        global_codex_state_used = any(
            selected == inherited
            for selected, inherited in (
                (task_home, global_home),
                (codex_config_root, global_codex_config),
                ((self.home / ".config").absolute(), global_xdg_config),
            )
        )
        isolation_verified = (
            all(path.is_relative_to(qualification_root) for path in isolated_roots)
            and len(set(isolated_roots)) == len(isolated_roots)
            and not global_codex_state_used
        )
        identity_records_valid = all(
            lifecycle["client"] == "codex"
            and lifecycle["task_id"] == "codex-adoption-probe"
            and lifecycle["session_id"] == "codex-adoption-session"
            and lifecycle["source_commit"] == runtime["source_commit"]
            and lifecycle["formal_run"] is True
            and lifecycle["parent_identity_verified"] is True
            and (
                lifecycle["parent_pid"], lifecycle["parent_identity"]
            ) in process_bindings
            and lifecycle["active_requests"] == 0
            and lifecycle["exit_reason"] == "client-terminated"
            for lifecycle in lifecycle_records
        )
        closeout_checks = operator_status["closeout_checks"]
        check_args = installer.parse_args(
            ["check", "--home", str(self.home), "--deep"]
        )
        with (
            mock.patch.object(
                installer, "knowledge_http_health", return_value=(True, "ok")
            ),
            mock.patch.object(
                installer,
                "knowledge_mcp_health",
                return_value=(
                    True,
                    "ok",
                    [
                        "openubmc_kb_query",
                        "openubmc_kb_status",
                        "openubmc_kb_list",
                    ],
                    False,
                ),
            ),
        ):
            check_report = installer.collect_check_report(check_args)
        check_report.pop("_messages", None)
        release = check_report.get("release", {})
        launcher_identity = {
            "schema": "openubmc-agent-workflow.codex-launcher-identity.v1",
            "runtime_api": runtime["api_version"],
            "runtime_content_digest": runtime["content_digest"],
            "source_commit": release.get("source_commit", ""),
            "entrypoint": "openubmc-debug/scripts/target_runtime_mcp.py",
        }
        launcher_identity_digest = "sha256:" + hashlib.sha256(
            json.dumps(
                launcher_identity,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        source = check_report["source"]
        stable_source = {
            key: source[key]
            for key in (
                "mode",
                "valid",
                "requested_ref",
                "ref_kind",
                "resolved_commit",
                "expected_commit",
                "current_commit",
                "dirty",
                "dirty_scope",
            )
        }
        Path(evidence_path).write_text(
            json.dumps(
                {
                    "client": client,
                    "adapter_available": adapter_available,
                    "support_mode": (
                        "skills-and-runtime-mcp"
                        if adapter_available
                        else "skills-only"
                    ),
                    "mcp_registration_verified": mcp_registration_verified,
                    "runtime_launcher_verified": healthy,
                    "launcher_state_verified": launcher_state_verified,
                    "launcher_identity": launcher_identity,
                    "launcher_identity_digest": launcher_identity_digest,
                    "runtime_invocation": (
                        "installed-runtime-launcher-protocol"
                        if adapter_available
                        else "runtime-launcher-without-client-adapter"
                    ),
                    "protocol_exchange": [
                        "initialize",
                        "tools/list",
                        "tools/call:execute",
                    ],
                    "tools": tools,
                    "source_commit": release.get("source_commit", ""),
                    "installation": {
                        "ok": check_report["ok"],
                        "clients": check_report["clients"],
                        "operational_ready": check_report[
                            "operational_ready"
                        ],
                        "release_identity_verified": check_report[
                            "release_identity_verified"
                        ],
                        "evaluation_ready": check_report["evaluation_ready"],
                        "source": stable_source,
                        "release": release,
                    },
                    "runtime_api": runtime["api_version"],
                    "runtime_content_digest": runtime["content_digest"],
                    "workflow_exchange": {
                        "tool": "execute",
                        "state": "preflight_failed",
                        "classification": structured[
                            "interaction_telemetry"
                        ]["classification"],
                        "error_field": structured["error"]["field"],
                        "canonical_retry": structured["error"]["example"],
                        "is_error": workflow_result["isError"],
                    },
                    "codex_process_invocation": codex_probe[
                        "codex_process_invocation"
                    ],
                    "codex_process_runs": process_runs,
                    "captured_model_tools": codex_probe[
                        "captured_model_tools"
                    ],
                    "captured_runtime_tool_contracts": codex_probe[
                        "captured_runtime_tool_contracts"
                    ],
                    "captured_orchestrator_tool_contracts": codex_probe[
                        "captured_orchestrator_tool_contracts"
                    ],
                    "restart_verified": codex_probe["restart_verified"],
                    "mcp_lifecycle_records": lifecycle_records,
                    "mcp_closeout": {
                        "status": (
                            "passed"
                            if identity_records_valid
                            and isolation_verified
                            and all(closeout_checks.values())
                            else "failed"
                        ),
                        "task_closeout_ready": (
                            identity_records_valid
                            and isolation_verified
                            and all(closeout_checks.values())
                        ),
                        "identity_records_valid": identity_records_valid,
                        "isolation_verified": isolation_verified,
                        "summary": operator_status["summary"],
                        "closeout_checks": closeout_checks,
                        "operator_status": operator_status,
                        "isolation": {
                            "qualification_root": str(qualification_root),
                            "task_home": str(task_home),
                            "codex_config_root": str(codex_config_root),
                            "runtime_state_root": str(runtime_state_root),
                            "lifecycle_root": str(lifecycle_root),
                            "global_codex_state_used": global_codex_state_used,
                            "installed_launcher_invocation": (
                                adapter_available
                                and mcp_registration_verified
                                and command.is_file()
                                and os.access(command, os.X_OK)
                            ),
                        },
                    },
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    def test_bundle_manifest_has_eleven_canonical_mappings(self) -> None:
        self.assertEqual(installer.SKILL_BUNDLE, EXPECTED_BUNDLE)
        self.assertEqual(
            installer.TARGET_RUNTIME_SKILL_BUNDLE,
            EXPECTED_TARGET_RUNTIME_BUNDLE,
        )
        full = installer.resolve_skill_profile("full")
        target_runtime = installer.resolve_skill_profile("target-runtime")
        self.assertEqual(full.bundle, EXPECTED_BUNDLE)
        self.assertTrue(full.manages_knowledge_mcp)
        self.assertEqual(target_runtime.bundle, EXPECTED_TARGET_RUNTIME_BUNDLE)
        self.assertFalse(target_runtime.manages_knowledge_mcp)
        self.assertEqual(installer.validate_source(self.source), self.source.absolute())

    def test_bundle_git_paths_materializes_iterators_once(self) -> None:
        paths = installer.bundle_git_paths(iter(EXPECTED_TARGET_RUNTIME_BUNDLE))
        self.assertIn("openubmc-target-runtime", paths)
        self.assertNotIn("openubmc-kb-mcp", paths)
        self.assertEqual(
            paths[: len(EXPECTED_TARGET_RUNTIME_BUNDLE)],
            tuple(path for _, path in EXPECTED_TARGET_RUNTIME_BUNDLE),
        )
        self.assertIn("openubmc-kb-mcp", installer.bundle_git_paths(EXPECTED_BUNDLE))

    def test_managed_install_stops_before_links_when_release_validation_fails(self) -> None:
        managed_source = installer.managed_source_dir(self.home)
        shutil.copytree(self.source, managed_source)
        validator = managed_source / "scripts" / "validate_workflow.py"
        validator.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "print('manifest contract failed', file=sys.stderr)\n"
            "raise SystemExit(17)\n",
            encoding="utf-8",
        )
        validator.chmod(0o755)
        args = installer.parse_args(
            [
                "install",
                "--home",
                str(self.home),
                "--source-mode",
                "managed",
                "--ref",
                "v1.2.3",
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
                "--skip-credentials",
                "--skip-tool-install",
                "--non-interactive",
            ]
        )

        with (
            mock.patch.object(
                installer, "checkout_managed_release", return_value="a" * 40
            ),
            self.assertRaisesRegex(
                installer.SetupError,
                "manifest contract failed",
            ),
        ):
            installer.perform_install(args)

        skills_dir = installer.client_skills_dir(self.home, "codex")
        self.assertFalse((skills_dir / "openubmc-debug").exists())

    def test_managed_v1_2_release_requires_lock_before_links(self) -> None:
        managed_source = installer.managed_source_dir(self.home)
        shutil.copytree(self.source, managed_source)
        (managed_source / "workflow.json").write_text(
            json.dumps(
                {
                    "schema_version": "openubmc-agent-workflow.v1",
                    "version": "1.2.0",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        args = installer.parse_args(
            [
                "install",
                "--home",
                str(self.home),
                "--source-mode",
                "managed",
                "--ref",
                "v1.2.0",
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
                "--skip-credentials",
                "--skip-tool-install",
                "--non-interactive",
            ]
        )

        with (
            mock.patch.object(
                installer, "checkout_managed_release", return_value="a" * 40
            ),
            self.assertRaisesRegex(installer.SetupError, "release lock is missing"),
        ):
            installer.perform_install(args)

        skills_dir = installer.client_skills_dir(self.home, "codex")
        self.assertFalse((skills_dir / "openubmc-debug").exists())

    def test_linked_source_without_workflow_records_development_identity(self) -> None:
        (self.source / "workflow.json").unlink()
        self.prepare_credentials()

        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )

        release = installer.load_state(self.home)["release"]
        self.assertEqual(release["schema"], "linked-development-source")
        self.assertFalse(release["immutable"])

    def test_linked_source_with_valid_lock_remains_mutable(self) -> None:
        lock_path = self.source / "release-lock.json"
        lock_path.write_text("{}\n", encoding="utf-8")
        verifier = (
            self.source
            / "openubmc-target-runtime"
            / "openubmc_target_runtime"
            / "release.py"
        )
        verifier.parent.mkdir(parents=True, exist_ok=True)
        verifier.write_text("# fixture\n", encoding="utf-8")
        verified = {
            "schema": "openubmc-agent-workflow.release-lock.v1",
            "release_version": "1.1.1",
            "source_commit": "a" * 40,
            "lock_digest": "sha256:" + "b" * 64,
        }

        with mock.patch.object(
            installer,
            "run_command",
            return_value=subprocess.CompletedProcess(
                [], 0, stdout=json.dumps(verified), stderr=""
            ),
        ):
            identity = installer.release_identity(
                self.source,
                source_mode="linked",
                dry_run=False,
            )

        self.assertEqual(identity["schema"], "linked-development-source")
        self.assertFalse(identity["immutable"])
        self.assertEqual(identity["verified_release_lock"], verified)

    def test_check_json_displays_immutable_release_identity(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        identity = {
            "schema": "openubmc-agent-workflow.release-lock.v1",
            "release_version": "1.2.0",
            "source_commit": "a" * 40,
            "lock_digest": "sha256:" + "b" * 64,
            "immutable": True,
        }
        state = installer.load_state(self.home)
        state["source_mode"] = "managed"
        state["managed_checkout"] = True
        state["ref"] = "v1.2.0"
        state["requested_ref"] = "v1.2.0"
        state["ref_kind"] = "tag"
        state["source_commit"] = "a" * 40
        state["resolved_commit"] = "a" * 40
        state["release"] = identity
        installer.save_state(self.home, state, False)
        output = io.StringIO()

        with (
            mock.patch.object(installer, "git_commit", return_value="a" * 40),
            mock.patch.object(installer, "git_dirty", return_value=False),
            mock.patch.object(installer, "release_identity", return_value=identity),
            mock.patch.object(
                installer, "knowledge_http_health", return_value=(False, "offline")
            ),
            redirect_stdout(output),
        ):
            result = installer.main(["check", "--home", str(self.home), "--json"])

        self.assertEqual(result, 0, output.getvalue())
        document = json.loads(output.getvalue())
        self.assertTrue(document["operational_ready"])
        self.assertTrue(document["release_identity_verified"])
        self.assertTrue(document["evaluation_ready"])
        self.assertTrue(document["readiness"]["release_identity"])
        self.assertTrue(document["readiness"]["evaluation"])
        self.assertEqual(
            document["release"]["trust_mode"], "verified-immutable-source"
        )
        self.assertTrue(document["release"]["verified"])
        self.assertEqual(
            document["release"]["lock_digest"],
            identity["lock_digest"],
        )
        release_check = next(
            check
            for check in document["checks"]
            if check["name"] == "release_identity"
        )
        self.assertTrue(release_check["ok"])
        self.assertIn(identity["lock_digest"], release_check["detail"])

    def test_check_json_rejects_release_identity_when_checkout_commit_changed(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        identity = {
            "schema": "openubmc-agent-workflow.release-lock.v1",
            "release_version": "1.2.0",
            "source_commit": "a" * 40,
            "lock_digest": "sha256:" + "b" * 64,
            "immutable": True,
        }
        state = installer.load_state(self.home)
        state.update(
            {
                "source_mode": "managed",
                "managed_checkout": True,
                "ref": "v1.2.0",
                "requested_ref": "v1.2.0",
                "ref_kind": "tag",
                "source_commit": "a" * 40,
                "resolved_commit": "a" * 40,
                "release": identity,
            }
        )
        installer.save_state(self.home, state, False)
        output = io.StringIO()

        with (
            mock.patch.object(installer, "git_commit", return_value="c" * 40),
            mock.patch.object(installer, "git_dirty", return_value=False),
            mock.patch.object(installer, "release_identity", return_value=identity),
            mock.patch.object(
                installer, "knowledge_http_health", return_value=(False, "offline")
            ),
            redirect_stdout(output),
        ):
            result = installer.main(["check", "--home", str(self.home), "--json"])

        self.assertEqual(result, 1, output.getvalue())
        document = json.loads(output.getvalue())
        self.assertTrue(document["operational_ready"])
        self.assertFalse(document["release_identity_verified"])
        self.assertFalse(document["evaluation_ready"])
        self.assertEqual(
            document["release"]["trust_mode"], "unverified-managed-source"
        )
        commit = next(
            check for check in document["checks"] if check["name"] == "source_commit"
        )
        self.assertFalse(commit["ok"])

    def test_clone_source_rejects_a_branch_as_a_release_tag(self) -> None:
        remote, _commit = self.create_release_remote()
        destination = self.root / "managed-release"

        with self.assertRaisesRegex(installer.SetupError, "release tag"):
            installer.clone_source(
                destination,
                str(remote),
                "release-v1",
                False,
                EXPECTED_TARGET_RUNTIME_BUNDLE,
            )

        self.assertFalse(destination.exists())

    def test_primary_github_fetch_uses_an_ephemeral_auth_header(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with (
            mock.patch.dict(
                installer.os.environ,
                {
                    "GH_TOKEN": "fixture-github-token",
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": "credential.helper",
                    "GIT_CONFIG_VALUE_0": "cache",
                },
                clear=True,
            ),
            mock.patch.object(
                installer,
                "git_output",
                side_effect=[installer.DEFAULT_REPO_URL, "a" * 40],
            ),
            mock.patch.object(installer, "run_command", return_value=completed) as run,
        ):
            ref_kind, commit = installer.fetch_immutable_release(
                self.root / "managed-release",
                "v1.2.3",
            )

        self.assertEqual(ref_kind, "tag")
        self.assertEqual(commit, "a" * 40)
        command = run.call_args_list[0].args[0]
        environment = run.call_args_list[0].kwargs["env"]
        self.assertNotIn("--depth", command)
        self.assertNotIn("fixture-github-token", command)
        self.assertEqual(environment["GIT_CONFIG_COUNT"], "2")
        self.assertEqual(environment["GIT_CONFIG_KEY_0"], "credential.helper")
        self.assertEqual(environment["GIT_CONFIG_VALUE_0"], "cache")
        self.assertEqual(
            environment["GIT_CONFIG_KEY_1"],
            "http.https://github.com/.extraheader",
        )
        self.assertEqual(
            environment["GIT_CONFIG_VALUE_1"],
            "Authorization: Basic eC1hY2Nlc3MtdG9rZW46Zml4dHVyZS1naXRodWItdG9rZW4=",
        )

    def test_fetch_existing_shallow_checkout_requests_complete_history(self) -> None:
        root = self.root / "managed-release"
        (root / ".git").mkdir(parents=True)
        (root / ".git" / "shallow").write_text("a" * 40 + "\n", encoding="utf-8")
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")

        with (
            mock.patch.object(
                installer,
                "git_output",
                side_effect=[installer.DEFAULT_REPO_URL, "b" * 40],
            ),
            mock.patch.object(installer, "run_command", return_value=completed) as run,
        ):
            installer.fetch_immutable_release(root, "b" * 40)

        self.assertIn("--unshallow", run.call_args_list[0].args[0])

    def test_clone_source_resolves_tag_and_full_commit_to_detached_head(self) -> None:
        remote, commit = self.create_release_remote()

        for label, ref in (("tag", "v1.2.3"), ("commit", commit)):
            with self.subTest(label=label):
                destination = self.root / f"managed-{label}"
                installed = installer.clone_source(
                    destination,
                    str(remote),
                    ref,
                    False,
                    EXPECTED_TARGET_RUNTIME_BUNDLE,
                )

                self.assertEqual(installed, destination.absolute())
                self.assertEqual(installer.git_commit(destination), commit)
                detached = subprocess.run(
                    ["git", "-C", str(destination), "symbolic-ref", "-q", "HEAD"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.assertNotEqual(detached.returncode, 0)

    def test_clone_source_keeps_the_lock_commit_parent_available(self) -> None:
        remote, _first_commit = self.create_release_remote()
        second_commit = self.publish_second_release(remote)
        destination = self.root / "managed-lock-release"

        installer.clone_source(
            destination,
            str(remote),
            "v1.2.4",
            False,
            EXPECTED_TARGET_RUNTIME_BUNDLE,
        )

        self.assertEqual(
            installer.git_output(destination, "rev-parse", "HEAD^{commit}"),
            second_commit,
        )
        parent = installer.git_output(
            destination, "rev-parse", "HEAD^1^{commit}"
        )
        self.assertRegex(parent, r"^[0-9a-f]{40}$")

    def test_clone_source_keeps_history_referenced_by_release_validation(self) -> None:
        remote, main_commit = self.create_release_remote()
        release_source = self.root / "release-repository"
        subprocess.run(
            ["git", "-C", str(release_source), "switch", "-c", "qualification-side"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        side_evidence = release_source / "qualification.txt"
        side_evidence.write_text("qualified\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(release_source), "add", "qualification.txt"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(release_source), "commit", "-m", "qualification"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        side_commit = installer.git_output(release_source, "rev-parse", "HEAD")
        subprocess.run(
            [
                "git",
                "-C",
                str(release_source),
                "push",
                str(remote),
                "qualification-side",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            ["git", "-C", str(release_source), "switch", "main"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        destination = self.root / "managed-validation-release"

        installer.clone_source(
            destination,
            str(remote),
            main_commit,
            False,
            EXPECTED_TARGET_RUNTIME_BUNDLE,
        )

        self.assertEqual(
            installer.git_output(destination, "rev-parse", f"{side_commit}^{{commit}}"),
            side_commit,
        )

    def test_clone_source_keeps_tag_only_release_validation_history(self) -> None:
        remote, main_commit = self.create_release_remote()
        release_source = self.root / "release-repository"
        subprocess.run(
            ["git", "-C", str(release_source), "switch", "-c", "historical-release"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        historical_evidence = release_source / "historical-release.txt"
        historical_evidence.write_text("published\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(release_source), "add", "historical-release.txt"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(release_source), "commit", "-m", "historical release"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        historical_commit = installer.git_output(release_source, "rev-parse", "HEAD")
        subprocess.run(
            [
                "git",
                "-C",
                str(release_source),
                "tag",
                "-a",
                "v1.2.2-history",
                "-m",
                "historical release",
            ],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(release_source),
                "push",
                str(remote),
                "refs/tags/v1.2.2-history",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            ["git", "-C", str(release_source), "switch", "main"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        destination = self.root / "managed-tag-validation-release"

        installer.clone_source(
            destination,
            str(remote),
            main_commit,
            False,
            EXPECTED_TARGET_RUNTIME_BUNDLE,
        )

        self.assertEqual(
            installer.git_output(
                destination,
                "rev-parse",
                "v1.2.2-history^{commit}",
            ),
            historical_commit,
        )

    def test_explicit_new_release_ref_updates_an_existing_managed_checkout(self) -> None:
        remote, first_commit = self.create_release_remote()
        destination = installer.managed_source_dir(self.home)
        installer.clone_source(
            destination,
            str(remote),
            "v1.2.3",
            False,
            EXPECTED_TARGET_RUNTIME_BUNDLE,
        )
        self.assertEqual(installer.git_commit(destination), first_commit)

        second_commit = self.publish_second_release(remote)

        args = installer.parse_args(
            [
                "install",
                "--home",
                str(self.home),
                "--source-mode",
                "managed",
                "--repo-url",
                str(remote),
                "--ref",
                "v1.2.4",
            ]
        )
        source, mode = installer.resolve_source(
            args,
            bundle=EXPECTED_TARGET_RUNTIME_BUNDLE,
        )

        self.assertEqual(source, destination.absolute())
        self.assertEqual(mode, "managed")
        self.assertEqual(installer.git_commit(destination), second_commit)
        detached = subprocess.run(
            ["git", "-C", str(destination), "symbolic-ref", "-q", "HEAD"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.assertNotEqual(detached.returncode, 0)

    def test_recorded_release_tag_fails_if_the_remote_tag_moves(self) -> None:
        remote, first_commit = self.create_release_remote()
        destination = installer.managed_source_dir(self.home)
        installer.clone_source(
            destination,
            str(remote),
            "v1.2.3",
            False,
            EXPECTED_TARGET_RUNTIME_BUNDLE,
        )
        second_commit = self.publish_second_release(remote)
        release_source = self.root / "release-repository"
        subprocess.run(
            ["git", "-C", str(release_source), "tag", "--force", "v1.2.3", second_commit],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(release_source),
                "push",
                "--force",
                str(remote),
                "refs/tags/v1.2.3",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )

        args = installer.parse_args(
            [
                "install",
                "--home",
                str(self.home),
                "--source-mode",
                "managed",
                "--repo-url",
                str(remote),
                "--ref",
                "v1.2.3",
            ]
        )
        with self.assertRaisesRegex(installer.SetupError, "release tag moved"):
            installer.resolve_source(
                args,
                bundle=EXPECTED_TARGET_RUNTIME_BUNDLE,
                expected_commit=first_commit,
            )

        self.assertEqual(installer.git_commit(destination), first_commit)

    def test_bootstrap_tools_install_all_missing_debian_dependencies(self) -> None:
        with (
            mock.patch.object(installer.shutil, "which", return_value=None),
            mock.patch.object(installer, "python_pip_available", return_value=False),
            mock.patch.object(installer, "install_apt_packages") as install_apt,
            mock.patch.object(installer, "install_codex_client") as install_codex,
        ):
            installer.install_bootstrap_tools(
                self.home,
                ["codex"],
                [str(installer.user_tool_bin(self.home))],
                dry_run=False,
            )

        installed = set(install_apt.call_args.args[0])
        self.assertEqual(
            installed,
            {
                "git",
                "openssh-client",
                "sshpass",
                "ripgrep",
                "python3-pip",
                "nodejs",
                "npm",
            },
        )
        install_codex.assert_called_once_with(
            self.home,
            [str(installer.user_tool_bin(self.home))],
            dry_run=False,
        )

    def test_install_fixture_resolves_tools_without_host_dependencies(self) -> None:
        search_path = installer.tool_search_path(
            [str(installer.user_tool_bin(self.home))]
        )

        for tool in (*installer.REQUIRED_TOOLS, "codex"):
            with self.subTest(tool=tool):
                self.assertEqual(
                    installer.shutil.which(tool, path=search_path),
                    str(self.bin_dir / tool),
                )

    def test_apt_install_is_noninteractive(self) -> None:
        completed = subprocess.CompletedProcess(["apt-get"], 0, "", "")
        with (
            mock.patch.object(installer.shutil, "which", return_value="/usr/bin/apt-get"),
            mock.patch.object(
                installer, "privileged_command", side_effect=lambda command: command
            ),
            mock.patch.object(installer, "run_command", return_value=completed) as run,
        ):
            installer.install_apt_packages(["ripgrep", "sshpass"], dry_run=False)

        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].args[0], ["apt-get", "update"])
        self.assertEqual(
            run.call_args_list[1].args[0],
            [
                "apt-get",
                "install",
                "-y",
                "--no-install-recommends",
                "ripgrep",
                "sshpass",
            ],
        )
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["env"]["DEBIAN_FRONTEND"], "noninteractive")

    def test_python_workflow_installs_bmcgo_and_conan_together(self) -> None:
        wheel = ROOT / "assets" / installer.BMCGO_WHEEL_NAME

        def find_tool(tool: str, **_: object) -> str | None:
            return None if tool in {"bmcgo", "conan"} else f"/usr/bin/{tool}"

        completed = subprocess.CompletedProcess(["pip"], 0, "", "")
        with (
            mock.patch.object(installer.shutil, "which", side_effect=find_tool),
            mock.patch.object(installer, "discover_bmcgo_wheel", return_value=wheel),
            mock.patch.object(installer, "run_command", return_value=completed) as run,
        ):
            installer.install_python_workflow_tools(
                self.home,
                self.source,
                [str(installer.user_tool_bin(self.home))],
                dry_run=False,
            )

        command = run.call_args.args[0]
        self.assertIn(str(wheel), command)
        self.assertIn("conan", command)
        self.assertEqual(run.call_args.kwargs["env"]["HOME"], str(self.home))
        self.assertEqual(
            run.call_args.kwargs["env"]["PYTHONUSERBASE"],
            str(self.home / ".local"),
        )

    def test_python_install_retries_for_older_pip(self) -> None:
        wheel = ROOT / "assets" / installer.BMCGO_WHEEL_NAME

        def find_tool(tool: str, **_: object) -> str | None:
            return None if tool == "bmcgo" else f"/usr/bin/{tool}"

        unsupported = subprocess.CompletedProcess(
            ["pip"], 2, "", "no such option: --break-system-packages"
        )
        completed = subprocess.CompletedProcess(["pip"], 0, "", "")
        with (
            mock.patch.object(installer.shutil, "which", side_effect=find_tool),
            mock.patch.object(installer, "discover_bmcgo_wheel", return_value=wheel),
            mock.patch.object(
                installer, "run_command", side_effect=[unsupported, completed]
            ) as run,
        ):
            installer.install_python_workflow_tools(
                self.home,
                self.source,
                [str(installer.user_tool_bin(self.home))],
                dry_run=False,
            )

        self.assertEqual(run.call_count, 2)
        self.assertIn("--break-system-packages", run.call_args_list[0].args[0])
        self.assertNotIn("--break-system-packages", run.call_args_list[1].args[0])

    def test_codex_is_installed_under_user_local(self) -> None:
        def find_tool(tool: str, **_: object) -> str | None:
            return "/usr/bin/npm" if tool == "npm" else None

        completed = subprocess.CompletedProcess(["npm"], 0, "", "")
        with (
            mock.patch.object(installer.shutil, "which", side_effect=find_tool),
            mock.patch.object(installer, "run_command", return_value=completed) as run,
        ):
            installer.install_codex_client(
                self.home,
                [str(installer.user_tool_bin(self.home))],
                dry_run=False,
            )

        self.assertEqual(
            run.call_args.args[0],
            [
                "/usr/bin/npm",
                "install",
                "--global",
                "--prefix",
                str(self.home / ".local"),
                installer.CODEX_NPM_PACKAGE,
            ],
        )

    def test_bmcgo_wheel_digest_mismatch_is_rejected(self) -> None:
        damaged = self.root / installer.BMCGO_WHEEL_NAME
        damaged.write_bytes(b"not the bundled wheel")
        with (
            mock.patch.dict(
                installer.os.environ,
                {"OPENUBMC_BMCGO_PACKAGE": str(damaged)},
                clear=False,
            ),
            self.assertRaisesRegex(installer.SetupError, "digest mismatch"),
        ):
            installer.discover_bmcgo_wheel(self.source)

    def test_skip_tool_install_bypasses_all_package_installers(self) -> None:
        with (
            mock.patch.object(installer, "install_bootstrap_tools") as bootstrap,
            mock.patch.object(installer, "install_python_workflow_tools") as python_tools,
        ):
            result, _ = self.install("--clients", "codex", "--skip-tool-install")

        self.assertEqual(result, 0)
        bootstrap.assert_not_called()
        python_tools.assert_not_called()

    def test_tool_install_failure_does_not_write_installer_state(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(
                installer,
                "install_bootstrap_tools",
                side_effect=installer.SetupError("apt failed"),
            ),
            redirect_stderr(stderr),
        ):
            result = installer.main(
                [
                    "install",
                    "--home",
                    str(self.home),
                    "--source",
                    str(self.source),
                    "--clients",
                    "codex",
                    "--non-interactive",
                ]
            )

        self.assertEqual(result, 2)
        self.assertIn("apt failed", stderr.getvalue())
        self.assertFalse(installer.state_path(self.home).exists())
        self.assertFalse(installer.client_skills_dir(self.home, "codex").exists())

    def test_resolve_source_materializes_one_shot_bundle_before_fallback(self) -> None:
        invalid_local = self.root / "invalid-local"
        invalid_local.mkdir()
        managed_source = installer.managed_source_dir(self.home)
        managed_source.mkdir(parents=True)
        args = installer.parse_args(
            [
                "install",
                "--home",
                str(self.home),
                "--source-mode",
                "auto",
                "--ref",
                "v1.2.3",
            ]
        )

        def reject_local(bundle):
            try:
                installer.validate_source(invalid_local, bundle)
            except installer.SetupError:
                return None
            raise AssertionError("invalid local source unexpectedly passed validation")

        with (
            mock.patch.object(
                installer,
                "local_repository_from_script",
                side_effect=reject_local,
            ),
            self.assertRaisesRegex(installer.SetupError, "missing .*SKILL.md"),
        ):
            installer.resolve_source(
                args,
                bundle=(item for item in EXPECTED_TARGET_RUNTIME_BUNDLE),
            )

    def test_install_removes_retired_compatibility_links(self) -> None:
        skills_dir = installer.client_skills_dir(self.home, "codex")
        skills_dir.mkdir(parents=True)
        for retired_name, relative in installer.RETIRED_SKILL_LINKS:
            target = self.source / relative
            target.mkdir(exist_ok=True)
            (skills_dir / retired_name).symlink_to(target, target_is_directory=True)

        result, _ = self.install("--clients", "codex")

        self.assertEqual(result, 0)
        for retired_name, _ in installer.RETIRED_SKILL_LINKS:
            retired = skills_dir / retired_name
            self.assertFalse(retired.exists())
            self.assertFalse(retired.is_symlink())

    def test_target_runtime_profile_manages_only_its_seven_skills(self) -> None:
        self.prepare_credentials()
        shutil.rmtree(self.source / "testing")
        skills_dir = installer.client_skills_dir(self.home, "codex")
        skills_dir.mkdir(parents=True)
        untouched_targets = {}
        for name in ("openubmc-dt-testing",):
            target = self.root / f"existing-{name}"
            target.mkdir()
            link = skills_dir / name
            link.symlink_to(target, target_is_directory=True)
            untouched_targets[link] = target

        result, output = self.install(
            "--clients", "codex", "--skill-profile", "target-runtime"
        )

        self.assertEqual(result, 0)
        self.assertIn("skills=7", output)
        state = installer.load_state(self.home)
        self.assertEqual(state["skill_profile"], "target-runtime")
        self.assertEqual(
            {Path(link).name for link in state["links"]},
            {canonical for canonical, _ in EXPECTED_TARGET_RUNTIME_BUNDLE},
        )
        for canonical, relative in EXPECTED_TARGET_RUNTIME_BUNDLE:
            self.assertTrue(
                installer.same_target(skills_dir / canonical, self.source / relative)
            )
        for link, target in untouched_targets.items():
            self.assertTrue(installer.same_target(link, target))

        codex = self.home / ".codex" / "config.toml"
        self.assertNotIn("openubmc-kb", codex.read_text(encoding="utf-8"))
        self.assertIn("openubmc-target-runtime", codex.read_text(encoding="utf-8"))
        self.assertEqual(self.check()[0], 0)

        reinstall_result, _ = self.install("--clients", "codex")
        self.assertEqual(reinstall_result, 0)
        self.assertEqual(
            installer.load_state(self.home)["skill_profile"], "target-runtime"
        )
        for link, target in untouched_targets.items():
            self.assertTrue(installer.same_target(link, target))

        (skills_dir / "openubmc-debug").unlink()
        repair_args = installer.parse_args(["repair", "--home", str(self.home)])
        with mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")):
            self.assertEqual(installer.perform_repair(repair_args), 0)
        self.assertTrue(
            installer.same_target(
                skills_dir / "openubmc-debug", self.source / "openubmc-debug"
            )
        )

        uninstall_args = installer.parse_args(["uninstall", "--home", str(self.home)])
        self.assertEqual(installer.perform_uninstall(uninstall_args), 0)
        for canonical, _ in EXPECTED_TARGET_RUNTIME_BUNDLE:
            self.assertFalse((skills_dir / canonical).exists())
        for link, target in untouched_targets.items():
            self.assertTrue(installer.same_target(link, target))

    def test_explicit_managed_full_install_replaces_recorded_linked_target_source(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )

        old_source = self.root / "old-target-runtime-source"
        for _canonical, relative in EXPECTED_TARGET_RUNTIME_BUNDLE:
            shutil.copytree(self.source / relative, old_source / relative)
        state = installer.load_state(self.home)
        state["source_root"] = str(old_source)
        state["source_mode"] = "linked"
        state["managed_checkout"] = False
        state["skill_profile"] = "target-runtime"
        installer.save_state(self.home, state, False)

        managed_source = installer.managed_source_dir(self.home)

        def clone_managed_source(
            destination: Path,
            repo_url: str,
            ref: str,
            dry_run: bool,
            bundle: tuple[tuple[str, str], ...],
        ) -> Path:
            self.assertEqual(destination, managed_source)
            self.assertEqual(repo_url, installer.DEFAULT_REPO_URL)
            self.assertEqual(ref, "v1.2.3")
            self.assertFalse(dry_run)
            self.assertEqual(bundle, EXPECTED_BUNDLE)
            shutil.copytree(self.source, destination)
            return installer.validate_source(destination, bundle)

        args = installer.parse_args(
            [
                "install",
                "--home",
                str(self.home),
                "--source-mode",
                "managed",
                "--ref",
                "v1.2.3",
                "--skill-profile",
                "full",
                "--clients",
                "codex",
                "--skip-credentials",
                "--skip-tool-install",
                "--non-interactive",
            ]
        )
        with (
            mock.patch.object(
                installer,
                "clone_source",
                side_effect=clone_managed_source,
            ) as clone_source,
            mock.patch.object(
                installer,
                "resolve_tool_dirs",
                return_value=([str(self.bin_dir)], []),
            ),
            mock.patch.object(
                installer,
                "knowledge_mcp_health",
                return_value=(
                    True,
                    "ok",
                    [
                        "openubmc_kb_query",
                        "openubmc_kb_status",
                        "openubmc_kb_list",
                    ],
                    False,
                ),
            ),
            mock.patch.object(installer, "git_commit", return_value="a" * 40),
        ):
            self.assertEqual(installer.perform_install(args), 0)

        clone_source.assert_called_once()
        installed = installer.load_state(self.home)
        self.assertEqual(installed["source_root"], str(managed_source))
        self.assertEqual(installed["source_mode"], "managed")
        self.assertEqual(installed["skill_profile"], "full")
        self.assertEqual(installed["requested_ref"], "v1.2.3")
        self.assertEqual(installed["ref_kind"], "tag")
        self.assertEqual(installed["resolved_commit"], "a" * 40)
        summary = installer.workflow_json_summary(installed, installed=True)
        self.assertEqual(summary["source"]["requested_ref"], "v1.2.3")
        self.assertEqual(summary["source"]["ref_kind"], "tag")
        self.assertEqual(summary["source"]["resolved_commit"], "a" * 40)
        skills_dir = installer.client_skills_dir(self.home, "codex")
        for canonical, relative in EXPECTED_BUNDLE:
            self.assertTrue(
                installer.same_target(
                    skills_dir / canonical,
                    managed_source / relative,
                )
            )

    def test_target_profile_migrates_legacy_standalone_kb_name(self) -> None:
        self.prepare_credentials()
        codex = self.home / ".codex" / "config.toml"
        codex.parent.mkdir(parents=True)
        codex.write_text(
            "[mcp_servers.openubmc-studio]\n"
            'command = "/opt/openubmc-standalone-mcp"\n'
            'args = ["--config", "/opt/openubmc-kb.json"]\n',
            encoding="utf-8",
        )

        result, _ = self.install(
            "--clients",
            "codex",
            "--skill-profile",
            "target-runtime",
        )

        self.assertEqual(result, 0)
        installed = codex.read_text(encoding="utf-8")
        self.assertNotIn("[mcp_servers.openubmc-studio]", installed)
        self.assertIn("[mcp_servers.openubmc-kb]", installed)
        self.assertIn('command = "/opt/openubmc-standalone-mcp"', installed)
        self.assertIn("[mcp_servers.openubmc-target-runtime]", installed)

        uninstall_args = installer.parse_args(["uninstall", "--home", str(self.home)])
        self.assertEqual(installer.perform_uninstall(uninstall_args), 0)
        remaining = codex.read_text(encoding="utf-8")
        self.assertIn("[mcp_servers.openubmc-kb]", remaining)
        self.assertNotIn("[mcp_servers.openubmc-target-runtime]", remaining)

    def test_preserved_debug_survives_source_switch_repair_and_uninstall(self) -> None:
        self.prepare_credentials()
        result, _output = self.install(
            "--clients",
            "codex",
            "--skill-profile",
            "target-runtime",
        )
        self.assertEqual(result, 0)

        updated_debug = self.root / "updated-debug"
        shutil.copytree(self.source / "openubmc-debug", updated_debug)
        (updated_debug / "updated.marker").write_text("updated\n", encoding="utf-8")
        debug_link = installer.client_skills_dir(self.home, "codex") / "openubmc-debug"
        debug_link.unlink()
        debug_link.symlink_to(updated_debug, target_is_directory=True)

        replacement = self.root / "replacement-source"
        shutil.copytree(self.source, replacement)
        install_args = installer.parse_args(
            [
                "install",
                "--home",
                str(self.home),
                "--source",
                str(replacement),
                "--source-mode",
                "linked",
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
                "--preserve-skills",
                "openubmc-debug",
                "--skip-credentials",
                "--non-interactive",
            ]
        )
        with (
            mock.patch.object(
                installer, "resolve_tool_dirs", return_value=([str(self.bin_dir)], [])
            ),
            mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
        ):
            self.assertEqual(installer.perform_install(install_args), 0)

        setup_link = (
            installer.client_skills_dir(self.home, "codex")
            / "openubmc-environment-setup"
        )
        self.assertTrue(installer.same_target(debug_link, updated_debug))
        self.assertTrue(
            installer.same_target(
                setup_link,
                replacement / "openubmc-environment-setup",
            )
        )
        state = installer.load_state(self.home)
        self.assertEqual(state["preserved_skills"], ["openubmc-debug"])
        self.assertEqual(state["links"][str(debug_link)], str(updated_debug))

        check_args = installer.parse_args(["check", "--home", str(self.home)])
        with mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")):
            report = installer.collect_check_report(check_args)
        preserved_check = next(
            item
            for item in report["checks"]
            if item["name"] == "link:" + str(debug_link)
        )
        self.assertTrue(preserved_check["ok"])
        self.assertIn("preserved", preserved_check["detail"])

        wrong_debug = self.root / "wrong-debug"
        shutil.copytree(self.source / "openubmc-debug", wrong_debug)
        debug_link.unlink()
        debug_link.symlink_to(wrong_debug, target_is_directory=True)
        repair_args = installer.parse_args(["repair", "--home", str(self.home)])
        with (
            mock.patch.object(
                installer, "resolve_tool_dirs", return_value=([str(self.bin_dir)], [])
            ),
            mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
        ):
            self.assertEqual(installer.perform_repair(repair_args), 0)
        self.assertTrue(installer.same_target(debug_link, updated_debug))

        debug_link.unlink()
        with (
            mock.patch.object(
                installer, "resolve_tool_dirs", return_value=([str(self.bin_dir)], [])
            ),
            mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
        ):
            self.assertEqual(installer.perform_repair(repair_args), 0)
        self.assertTrue(installer.same_target(debug_link, updated_debug))

        uninstall_args = installer.parse_args(["uninstall", "--home", str(self.home)])
        self.assertEqual(installer.perform_uninstall(uninstall_args), 0)
        self.assertTrue(installer.same_target(debug_link, updated_debug))
        self.assertFalse(setup_link.exists())

    def test_preserve_skills_none_returns_link_to_selected_source(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        skills_dir = installer.client_skills_dir(self.home, "codex")
        debug_link = skills_dir / "openubmc-debug"
        updated_debug = self.root / "updated-debug"
        shutil.copytree(self.source / "openubmc-debug", updated_debug)
        debug_link.unlink()
        debug_link.symlink_to(updated_debug, target_is_directory=True)

        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
                "--preserve-skills",
                "openubmc-debug",
            )[0],
            0,
        )
        self.assertTrue(installer.same_target(debug_link, updated_debug))

        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
                "--preserve-skills",
                "none",
            )[0],
            0,
        )
        state = installer.load_state(self.home)
        self.assertEqual(state["preserved_skills"], [])
        self.assertTrue(
            installer.same_target(debug_link, self.source / "openubmc-debug")
        )

    def test_repair_rejects_an_unavailable_recorded_preserved_target(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        debug_link = installer.client_skills_dir(self.home, "codex") / "openubmc-debug"
        updated_debug = self.root / "updated-debug"
        shutil.copytree(self.source / "openubmc-debug", updated_debug)
        debug_link.unlink()
        debug_link.symlink_to(updated_debug, target_is_directory=True)
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
                "--preserve-skills",
                "openubmc-debug",
            )[0],
            0,
        )

        shutil.rmtree(updated_debug)
        fallback_debug = self.root / "fallback-debug"
        shutil.copytree(self.source / "openubmc-debug", fallback_debug)
        debug_link.unlink()
        debug_link.symlink_to(fallback_debug, target_is_directory=True)
        repair_args = installer.parse_args(["repair", "--home", str(self.home)])
        with (
            mock.patch.object(
                installer, "resolve_tool_dirs", return_value=([str(self.bin_dir)], [])
            ),
            self.assertRaisesRegex(installer.SetupError, "target is unavailable"),
        ):
            installer.perform_repair(repair_args)
        state = installer.load_state(self.home)
        self.assertEqual(state["links"][str(debug_link)], str(updated_debug))
        self.assertTrue(installer.same_target(debug_link, fallback_debug))

    def test_repair_migrates_state_without_preserved_skills(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        state = installer.load_state(self.home)
        state.pop("preserved_skills")
        installer.save_state(self.home, state, False)

        repair_args = installer.parse_args(["repair", "--home", str(self.home)])
        with (
            mock.patch.object(
                installer, "resolve_tool_dirs", return_value=([str(self.bin_dir)], [])
            ),
            mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
        ):
            self.assertEqual(installer.perform_repair(repair_args), 0)
        self.assertEqual(installer.load_state(self.home)["preserved_skills"], [])

    def test_preserve_skills_rejects_unknown_skill_name(self) -> None:
        args = installer.parse_args(
            [
                "install",
                "--home",
                str(self.home),
                "--source",
                str(self.source),
                "--preserve-skills",
                "unknown-skill",
                "--skip-credentials",
                "--non-interactive",
            ]
        )
        with mock.patch.object(
            installer, "resolve_tool_dirs", return_value=([str(self.bin_dir)], [])
        ):
            with self.assertRaisesRegex(installer.SetupError, "unknown-skill"):
                installer.perform_install(args)

    def test_uninstall_rejects_unknown_preserved_skill_without_side_effects(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        debug_link = installer.client_skills_dir(self.home, "codex") / "openubmc-debug"
        expected_target = self.source / "openubmc-debug"
        state = installer.load_state(self.home)
        state["preserved_skills"] = ["unknown-skill"]
        installer.save_state(self.home, state, False)

        uninstall_args = installer.parse_args(["uninstall", "--home", str(self.home)])
        with self.assertRaisesRegex(installer.SetupError, "unknown-skill"):
            installer.perform_uninstall(uninstall_args)
        self.assertTrue(installer.same_target(debug_link, expected_target))
        self.assertTrue(installer.state_path(self.home).is_file())

    def test_target_profile_uninstall_preserves_knowledge_mcp_but_removes_runtime(self) -> None:
        self.prepare_credentials()
        codex = self.home / ".codex" / "config.toml"
        codex.parent.mkdir(parents=True)
        codex.write_text("[other]\nvalue = 1\n", encoding="utf-8")

        self.assertEqual(self.install("--clients", "codex")[0], 0)
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )

        uninstall_args = installer.parse_args(
            ["uninstall", "--home", str(self.home)]
        )
        self.assertEqual(installer.perform_uninstall(uninstall_args), 0)
        remaining = codex.read_text(encoding="utf-8")
        self.assertIn("[other]", remaining)
        self.assertIn("openubmc-kb", remaining)
        self.assertNotIn("openubmc-target-runtime", remaining)

    def test_full_target_full_roundtrip_preserves_knowledge_mcp_ownership(self) -> None:
        self.prepare_credentials()
        codex = self.home / ".codex" / "config.toml"
        codex.parent.mkdir(parents=True)
        codex.write_text("[other]\nvalue = 1\n", encoding="utf-8")

        self.assertEqual(self.install("--clients", "codex")[0], 0)
        full_state = installer.load_state(self.home)
        self.assertIs(full_state["mcp"]["codex"]["created_entry"], True)
        full_text = codex.read_text(encoding="utf-8")

        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        target_state = installer.load_state(self.home)
        self.assertIs(target_state["mcp"]["codex"]["created_entry"], True)
        self.assertEqual(codex.read_text(encoding="utf-8"), full_text)

        repair_args = installer.parse_args(
            ["repair", "--home", str(self.home)]
        )
        with mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")):
            self.assertEqual(installer.perform_repair(repair_args), 0)
        self.assertEqual(codex.read_text(encoding="utf-8"), full_text)

        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "full",
            )[0],
            0,
        )
        restored_state = installer.load_state(self.home)
        self.assertIs(restored_state["mcp"]["codex"]["created_entry"], True)

        uninstall_args = installer.parse_args(
            ["uninstall", "--home", str(self.home)]
        )
        self.assertEqual(installer.perform_uninstall(uninstall_args), 0)
        remaining = codex.read_text(encoding="utf-8")
        self.assertIn("[other]", remaining)
        self.assertNotIn("openubmc-kb", remaining)
        self.assertNotIn("openubmc-target-runtime", remaining)

    def test_target_profile_uninstall_keeps_source_used_by_excluded_links(self) -> None:
        self.prepare_credentials()
        managed_source = installer.managed_source_dir(self.home)
        shutil.copytree(self.source, managed_source)

        def install_managed(*extra: str) -> int:
            args = installer.parse_args(
                [
                    "install",
                    "--home",
                    str(self.home),
                    "--source-mode",
                    "managed",
                    "--ref",
                    "v1.2.3",
                    "--clients",
                    "codex",
                    "--non-interactive",
                    *extra,
                ]
            )
            with (
                mock.patch.object(
                    installer,
                    "resolve_tool_dirs",
                    return_value=([str(self.bin_dir)], []),
                ),
                mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
                mock.patch.object(
                    installer, "checkout_managed_release", return_value="a" * 40
                ),
            ):
                return installer.perform_install(args)

        self.assertEqual(install_managed(), 0)
        self.assertEqual(
            install_managed("--skill-profile", "target-runtime"),
            0,
        )
        skills_dir = installer.client_skills_dir(self.home, "codex")
        excluded_link = skills_dir / "openubmc-dt-testing"
        self.assertTrue(
            installer.same_target(excluded_link, managed_source / "testing")
        )
        uninstall_args = installer.parse_args(
            ["uninstall", "--home", str(self.home)]
        )
        with (
            mock.patch.object(
                installer, "git_output", return_value=installer.DEFAULT_REPO_URL
            ),
            mock.patch.object(installer, "git_dirty", return_value=False),
        ):
            self.assertEqual(installer.perform_uninstall(uninstall_args), 0)

        self.assertTrue(managed_source.is_dir())
        self.assertTrue(
            installer.same_target(excluded_link, managed_source / "testing")
        )
        codex_text = (self.home / ".codex" / "config.toml").read_text(
            encoding="utf-8"
        )
        self.assertIn("openubmc-kb", codex_text)
        self.assertNotIn("openubmc-target-runtime", codex_text)

    def test_uninstall_keeps_source_used_by_changed_managed_link(self) -> None:
        self.prepare_credentials()
        managed_source = installer.managed_source_dir(self.home)
        shutil.copytree(self.source, managed_source)
        install_args = installer.parse_args(
            [
                "install",
                "--home",
                str(self.home),
                "--source-mode",
                "managed",
                "--ref",
                "v1.2.3",
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
                "--non-interactive",
            ]
        )
        with mock.patch.object(
            installer,
            "resolve_tool_dirs",
            return_value=([str(self.bin_dir)], []),
        ), mock.patch.object(
            installer, "checkout_managed_release", return_value="a" * 40
        ):
            self.assertEqual(installer.perform_install(install_args), 0)

        changed_link = installer.client_skills_dir(self.home, "codex") / "openubmc-debug"
        changed_link.unlink()
        changed_link.symlink_to(managed_source / "openubmc-build", target_is_directory=True)

        uninstall_args = installer.parse_args(
            ["uninstall", "--home", str(self.home)]
        )
        with (
            mock.patch.object(
                installer, "git_output", return_value=installer.DEFAULT_REPO_URL
            ),
            mock.patch.object(installer, "git_dirty", return_value=False),
        ):
            self.assertEqual(installer.perform_uninstall(uninstall_args), 0)

        self.assertTrue(managed_source.is_dir())
        self.assertTrue(
            installer.same_target(changed_link, managed_source / "openubmc-build")
        )

    def test_uninstall_keeps_source_used_by_unmanaged_legacy_client_link(self) -> None:
        self.prepare_credentials()
        managed_source = installer.managed_source_dir(self.home)
        shutil.copytree(self.source, managed_source)
        install_args = installer.parse_args(
            [
                "install",
                "--home",
                str(self.home),
                "--source-mode",
                "managed",
                "--ref",
                "v1.2.3",
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
                "--non-interactive",
            ]
        )
        with (
            mock.patch.object(
                installer,
                "resolve_tool_dirs",
                return_value=([str(self.bin_dir)], []),
            ),
            mock.patch.object(
                installer, "checkout_managed_release", return_value="a" * 40
            ),
        ):
            self.assertEqual(installer.perform_install(install_args), 0)

        legacy_link = self.home / ".claude" / "skills" / "private-openubmc"
        legacy_link.parent.mkdir(parents=True)
        legacy_link.symlink_to(
            managed_source / "openubmc-debug", target_is_directory=True
        )
        uninstall_args = installer.parse_args(
            ["uninstall", "--home", str(self.home)]
        )
        with (
            mock.patch.object(
                installer, "git_output", return_value=installer.DEFAULT_REPO_URL
            ),
            mock.patch.object(installer, "git_dirty", return_value=False),
        ):
            self.assertEqual(installer.perform_uninstall(uninstall_args), 0)

        self.assertTrue(managed_source.is_dir())
        self.assertTrue(
            installer.same_target(legacy_link, managed_source / "openubmc-debug")
        )

    def test_new_subcommands_and_legacy_flags_parse_to_the_same_commands(self) -> None:
        modern = installer.parse_args(["check", "--json", "--home", str(self.home)])
        legacy = installer.parse_args(["--check", "--home", str(self.home)])
        managed = installer.parse_args(
            ["install", "--source-mode", "managed", "--home", str(self.home)]
        )
        profiled = installer.parse_args(
            [
                "install",
                "--skill-profile",
                "target-runtime",
                "--home",
                str(self.home),
            ]
        )
        self.assertEqual(modern.command, "check")
        self.assertTrue(modern.json)
        self.assertEqual(legacy.command, "check")
        self.assertTrue(legacy.legacy_cli)
        self.assertEqual(managed.command, "install")
        self.assertEqual(managed.source_mode, "managed")
        self.assertEqual(profiled.skill_profile, "target-runtime")

    def test_install_is_idempotent_for_all_clients_and_shell_hook(self) -> None:
        credentials = self.prepare_credentials()
        (self.home / ".claude").mkdir(parents=True)
        (self.home / ".openclaw").mkdir(parents=True)
        (self.home / ".bash_profile").write_text("user login content\n", encoding="utf-8")
        first, first_output = self.install("--clients", "auto")
        second, second_output = self.install("--clients", "all")
        self.assertEqual(first, 0)
        self.assertEqual(second, 0)

        state = installer.load_state(self.home)
        self.assertEqual(state["clients"], ["codex"])
        for canonical, relative in EXPECTED_BUNDLE:
            link = self.home / ".agents" / "skills" / canonical
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.resolve(), (self.source / relative).resolve())
            self.assertFalse((self.home / ".claude" / "skills" / canonical).exists())
            self.assertFalse((self.home / ".openclaw" / "skills" / canonical).exists())

        for profile in (
            self.home / ".bashrc",
            self.home / ".profile",
            self.home / ".bash_profile",
        ):
            content = profile.read_text(encoding="utf-8")
            self.assertEqual(content.count(installer.MARKER_START), 1)
            self.assertEqual(content.count(installer.MARKER_END), 1)

        env_file = installer.openubmc_config_dir(self.home) / "env.sh"
        env_text = env_file.read_text(encoding="utf-8")
        self.assertIn("unset OPENUBMC_BUILD_SKILL_ROOT", env_text)
        self.assertNotIn("export OPENUBMC_BUILD_SKILL_ROOT", env_text)
        self.assertNotIn("export OPENUBMC_DEBUG_SKILL_ROOT", env_text)
        self.assertNotIn("export OPENUBMC_UPGRADE_SKILL_ROOT", env_text)

        probe = subprocess.run(
            [
                "bash",
                "-c",
                ". \"$1\"; printf '%s|%s|%s|%s|%s' "
                '"${OPENUBMC_BUILD_SKILL_ROOT:+set}" '
                '"${OPENUBMC_DEBUG_SKILL_ROOT:+set}" '
                '"${OPENUBMC_UPGRADE_SKILL_ROOT:+set}" '
                '"${OPENUBMC_CREDENTIALS_FILE}" '
                '"${OPENUBMC_SSH_PASSWORD:+set}"',
                "probe",
                str(env_file),
            ],
            check=False,
            capture_output=True,
            text=True,
            env={
                "HOME": str(self.home),
                "PATH": "/usr/bin:/bin",
                "OPENUBMC_BUILD_SKILL_ROOT": "/stale/build",
                "OPENUBMC_DEBUG_SKILL_ROOT": "/stale/debug",
                "OPENUBMC_UPGRADE_SKILL_ROOT": "/stale/upgrade",
            },
        )
        self.assertEqual(probe.returncode, 0, probe.stderr)
        self.assertEqual(probe.stdout, f"|||{credentials}|")

        combined_output = first_output + second_output
        for secret in ("fixture-bmc-password", "fixture-os-password"):
            self.assertNotIn(secret, combined_output)
        self.assertTrue(
            installer.check_toml_mcp(
                self.home / ".codex/config.toml", "", state["mcp"]["codex"]
            )
        )
        self.assertFalse((self.home / ".claude.json").exists())

    def test_explicit_non_codex_client_fails_before_filesystem_mutation(self) -> None:
        for selection in ("claude", "openclaw", "codex,claude", "openclaw,codex"):
            with self.subTest(selection=selection):
                shutil.rmtree(self.home, ignore_errors=True)
                stdout = io.StringIO()
                stderr = io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    result = installer.main(
                        [
                            "install",
                            "--home",
                            str(self.home),
                            "--source",
                            str(self.source),
                            "--clients",
                            selection,
                            "--non-interactive",
                        ]
                    )

                self.assertEqual(result, 2)
                self.assertIn("only Codex is supported", stderr.getvalue())
                self.assertIn("--clients codex", stderr.getvalue())
                self.assertFalse(self.home.exists())

    def test_install_deploys_runtime_launcher_and_registers_stdio_mcp(self) -> None:
        self.prepare_credentials()
        codex = self.home / ".codex" / "config.toml"
        codex.parent.mkdir(parents=True)
        codex.write_text("[other]\nvalue = 1\n", encoding="utf-8")

        result, _ = self.install("--clients", "codex")

        self.assertEqual(result, 0)
        state = installer.load_state(self.home)
        runtime = state["runtime"]
        self.assertEqual(runtime["api_version"], "openubmc.target-runtime.v1")
        self.assertRegex(runtime["content_digest"], r"^sha256:[0-9a-f]{64}$")
        package = Path(runtime["package_path"])
        launcher = Path(runtime["launcher_path"])
        self.assertTrue((package / "__init__.py").is_file())
        self.assertTrue((package / "runtime.py").is_file())
        self.assertTrue(launcher.is_file())
        self.assertTrue(os.access(launcher, os.X_OK))

        codex_text = codex.read_text(encoding="utf-8")
        self.assertIn("[other]", codex_text)
        self.assertIn("[mcp_servers.openubmc-kb]", codex_text)
        self.assertIn("[mcp_servers.openubmc-target-runtime]", codex_text)
        self.assertIn(f"command = {json.dumps(str(launcher))}", codex_text)

    def test_install_qualifies_codex_product_client(self) -> None:
        state, launcher = self.qualify_product_client("codex")

        self.assertEqual(state["clients"], ["codex"])
        self.assertTrue(
            installer.check_toml_mcp(
                self.home / ".codex" / "config.toml",
                "",
                state["mcp"]["codex"],
            )
        )
        config_path = self.home / ".codex" / "config.toml"
        registration_verified = installer.check_toml_runtime_mcp(
            config_path,
            launcher,
        )
        self.assertTrue(registration_verified)
        configured = installer.toml_stdio_mcp_entry(config_path)
        assert configured is not None
        expected_launcher_source = (
            state["release"].get("source_commit") or state["source_commit"]
        )
        self.assertEqual(
            state["runtime"]["source_commit"],
            expected_launcher_source,
        )
        knowledge_launcher = Path(state["knowledge_mcp"]["launcher_path"])
        self.assertEqual(
            state["knowledge_mcp"]["source_commit"],
            expected_launcher_source,
        )
        node = self.root / "capture-node"
        capture = self.root / "knowledge-launcher-source.txt"
        node.write_text(
            "#!/bin/sh\n"
            "printf '%s' \"$OPENUBMC_MCP_SOURCE_COMMIT\" > "
            '"$OPENUBMC_TEST_SOURCE_CAPTURE"\n',
            encoding="utf-8",
        )
        node.chmod(0o755)
        capture_launcher = self.root / "openubmc-kb-mcp-capture"
        capture_launcher.write_text(
            installer.render_knowledge_launcher(
                {**state["knowledge_mcp"], "node_path": str(node)}
            ),
            encoding="utf-8",
        )
        capture_launcher.chmod(0o755)
        completed = subprocess.run(
            [str(capture_launcher)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={
                **os.environ,
                "HOME": str(self.home),
                "OPENUBMC_TEST_SOURCE_CAPTURE": str(capture),
            },
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(capture.read_text(encoding="utf-8"), expected_launcher_source)
        self.record_product_client_evidence(
            client="codex",
            command=Path(str(configured["command"])),
            adapter_available=True,
            mcp_registration_verified=registration_verified,
        )

    def test_install_migrates_owned_codex_runtime_entry_without_args(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        codex = self.home / ".codex" / "config.toml"
        before_runtime, header, runtime_section = codex.read_text(
            encoding="utf-8"
        ).partition("[mcp_servers.openubmc-target-runtime]")
        codex.write_text(
            before_runtime + header + runtime_section.replace("args = []\n", "", 1),
            encoding="utf-8",
        )

        result, output = self.install("--clients", "codex")

        self.assertEqual(result, 0, output)
        runtime_section = codex.read_text(encoding="utf-8").split(
            "[mcp_servers.openubmc-target-runtime]", 1
        )[1]
        self.assertIn("args = []", runtime_section)

    def test_credentials_map_bmc_to_redfish_and_require_private_import(self) -> None:
        values = {
            "OPENUBMC_SSH_USER": "shared-user",
            "OPENUBMC_SSH_PASSWORD": "shared-password",
            "OPENUBMC_OS_SSH_USER": "os-user",
            "OPENUBMC_OS_SSH_PASSWORD": "os-password",
        }
        normalized = installer.normalize_credentials(values, require_complete=True)
        self.assertEqual(normalized["REDFISH_USERNAME"], "shared-user")
        self.assertEqual(normalized["REDFISH_PASSWORD"], "shared-password")

        import_file = self.root / "import.env"
        import_file.write_text(installer.render_credentials(values), encoding="utf-8")
        import_file.chmod(0o644)
        args = self.args("--install", "--clients", "codex", "--import-credentials", str(import_file))
        with self.assertRaises(installer.SetupError):
            installer.configure_credentials(args)

        import_file.chmod(0o600)
        self.assertEqual(installer.configure_credentials(args), "imported")
        destination = installer.credentials_path(self.home)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        parsed = installer.parse_credentials(
            destination.read_text(encoding="utf-8"), require_complete=True
        )
        self.assertEqual(parsed["OPENUBMC_SSH_USER"], parsed["REDFISH_USERNAME"])
        self.assertEqual(parsed["OPENUBMC_SSH_PASSWORD"], parsed["REDFISH_PASSWORD"])

        with self.assertRaises(installer.SetupError):
            installer.normalize_credentials(
                {
                    "OPENUBMC_SSH_USER": "one",
                    "REDFISH_USERNAME": "two",
                }
            )

    def test_credentials_subcommand_changes_only_the_private_file(self) -> None:
        import_file = self.root / "import.env"
        import_file.write_text(
            installer.render_credentials(self.credential_values()), encoding="utf-8"
        )
        import_file.chmod(0o600)
        output = io.StringIO()
        with redirect_stdout(output):
            result = installer.main(
                [
                    "credentials",
                    "--home",
                    str(self.home),
                    "--import-credentials",
                    str(import_file),
                    "--non-interactive",
                ]
            )
        self.assertEqual(result, 0)
        self.assertIn("credentials: imported", output.getvalue())
        self.assertTrue(installer.credentials_path(self.home).is_file())
        self.assertFalse(installer.state_path(self.home).exists())
        self.assertFalse((self.home / ".bashrc").exists())

    def test_credentials_subcommand_imports_private_kb_config_only(self) -> None:
        source = self.root / "kb-config.json"
        source.write_text(
            json.dumps({"username": "fixture-user", "password": "fixture-secret"}),
            encoding="utf-8",
        )
        source.chmod(0o600)
        output = io.StringIO()
        with redirect_stdout(output):
            result = installer.main(
                [
                    "credentials",
                    "--home",
                    str(self.home),
                    "--kb",
                    "--kb-config",
                    str(source),
                    "--non-interactive",
                ]
            )
        self.assertEqual(result, 0)
        self.assertIn("openUBMC KB credentials: imported", output.getvalue())
        destination = installer.knowledge_config_path(self.home)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        self.assertEqual(json.loads(destination.read_text(encoding="utf-8"))["username"], "fixture-user")
        self.assertFalse(installer.state_path(self.home).exists())
        self.assertFalse((self.home / ".bashrc").exists())

    def test_mcp_upsert_remove_and_preexisting_ownership(self) -> None:
        backups = installer.backup_path(self.home)
        codex = self.home / ".codex" / "config.toml"
        claude = self.home / ".claude.json"
        codex.parent.mkdir(parents=True)
        codex.write_text("[other]\nvalue = 1\n", encoding="utf-8")
        claude.write_text('{"keep": true}\n', encoding="utf-8")

        state = installer.configure_mcp(
            self.home,
            ("codex", "claude"),
            installer.LEGACY_STUDIO_HTTP_URL,
            backups,
            False,
        )
        state = installer.configure_mcp(
            self.home,
            ("codex", "claude"),
            installer.LEGACY_STUDIO_HTTP_URL,
            backups,
            False,
            state,
        )
        installer.remove_toml_mcp(codex, state["codex"], backups, False)
        installer.remove_json_mcp(claude, state["claude"], backups, False)
        self.assertEqual(codex.read_text(encoding="utf-8").strip(), "[other]\nvalue = 1")
        self.assertEqual(json.loads(claude.read_text(encoding="utf-8")), {"keep": True, "mcpServers": {}})

        codex.write_text(
            '[mcp_servers.openubmc-kb]\nurl = "http://localhost:9876/mcp"\n',
            encoding="utf-8",
        )
        preexisting = installer.upsert_toml_mcp(
            codex, installer.LEGACY_STUDIO_HTTP_URL, backups, False
        )
        self.assertFalse(preexisting["created_entry"])
        installer.remove_toml_mcp(codex, preexisting, backups, False)
        self.assertTrue(installer.check_toml_mcp(codex, installer.LEGACY_STUDIO_HTTP_URL))

        with self.assertRaises(installer.SetupError):
            installer.upsert_toml_mcp(
                codex, "http://localhost:9999/mcp", backups, False
            )

    def test_external_codex_kb_stdio_survives_runtime_lifecycle(self) -> None:
        self.prepare_credentials()
        codex = self.home / ".codex" / "config.toml"
        codex.parent.mkdir(parents=True)
        legacy_kb = (
            "[mcp_servers.openubmc-studio]\n"
            'command = "/opt/openubmc-standalone-mcp"\n'
            'args = ["serve", "--stdio"]\n'
        )
        migrated_kb = legacy_kb.replace("openubmc-studio", "openubmc-kb")
        codex.write_text(legacy_kb, encoding="utf-8")

        result, _ = self.install("--clients", "codex")

        self.assertEqual(result, 0)
        installed = codex.read_text(encoding="utf-8")
        self.assertTrue(installed.startswith(migrated_kb))
        self.assertIn("[mcp_servers.openubmc-target-runtime]", installed)
        state = installer.load_state(self.home)
        self.assertEqual(state["mcp"]["codex"]["ownership"], "external")
        self.assertEqual(self.check()[0], 0)

        repair_args = installer.parse_args(["repair", "--home", str(self.home)])
        with mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")):
            self.assertEqual(installer.perform_repair(repair_args), 0)
        self.assertTrue(codex.read_text(encoding="utf-8").startswith(migrated_kb))

        uninstall_args = installer.parse_args(["uninstall", "--home", str(self.home)])
        self.assertEqual(installer.perform_uninstall(uninstall_args), 0)
        self.assertEqual(codex.read_text(encoding="utf-8"), migrated_kb)

    def test_quoted_external_codex_kb_stdio_is_preserved_without_duplicate(self) -> None:
        self.prepare_credentials()
        codex = self.home / ".codex" / "config.toml"
        codex.parent.mkdir(parents=True)
        external = (
            '[mcp_servers."openubmc\\u002dkb"]\n'
            'command = "/opt/external-kb"\n'
            'args = ["serve", "--stdio"]\n'
        )
        codex.write_text(external, encoding="utf-8")

        result, output = self.install("--clients", "codex")

        self.assertEqual(result, 0, output)
        installed = codex.read_text(encoding="utf-8")
        self.assertTrue(installed.startswith(external))
        self.assertNotIn("[mcp_servers.openubmc-kb]", installed)
        self.assertIn("[mcp_servers.openubmc-target-runtime]", installed)
        state = installer.load_state(self.home)
        self.assertEqual(state["mcp"]["codex"]["ownership"], "external")
        self.assertEqual(self.check()[0], 0)

    def test_custom_external_claude_runtime_entry_is_not_claimed(self) -> None:
        self.home.mkdir(parents=True)
        claude = self.home / ".claude.json"
        external = {
            "type": "stdio",
            "command": str(installer.runtime_launcher_path(self.home)),
            "env": {"MODE": "read-only"},
        }
        claude.write_text(
            json.dumps(
                {"mcpServers": {installer.TARGET_RUNTIME_MCP_NAME: external}},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            installer.SetupError,
            "existing openubmc-target-runtime MCP command differs",
        ):
            installer.validate_runtime_mcp_configuration(
                self.home,
                ["claude"],
                installer.runtime_launcher_path(self.home),
            )

        preserved = json.loads(claude.read_text(encoding="utf-8"))
        self.assertEqual(
            preserved["mcpServers"][installer.TARGET_RUNTIME_MCP_NAME], external
        )

    def test_known_legacy_standalone_codex_kb_migrates_to_managed_stdio(self) -> None:
        self.prepare_credentials()
        codex = self.home / ".codex" / "config.toml"
        codex.parent.mkdir(parents=True)
        codex.write_text(
            "[mcp_servers.openubmc-kb]\n"
            'command = "/usr/local/bin/node"\n'
            "args = [\n"
            '  "/mnt/c/Users/test/.codex/mcp/openubmc-standalone-mcp/src/server.js",\n'
            '  "--config",\n'
            '  "/mnt/c/Users/test/.codex/mcp/openubmc-standalone-mcp/config.local.json",\n'
            "]\n"
            "startup_timeout_sec = 30\n"
            "tool_timeout_sec = 120\n",
            encoding="utf-8",
        )

        result, output = self.install("--clients", "codex")

        self.assertEqual(result, 0, output)
        installed = codex.read_text(encoding="utf-8")
        launcher = str(installer.knowledge_launcher_path(self.home))
        self.assertIn("[mcp_servers.openubmc-kb]", installed)
        self.assertIn(f"command = {json.dumps(launcher)}", installed)
        self.assertIn("args = []", installed)
        self.assertNotIn("openubmc-standalone-mcp", installed)
        state = installer.load_state(self.home)
        self.assertIs(state["mcp"]["codex"]["created_entry"], True)
        self.assertNotEqual(
            state["mcp"]["codex"].get("ownership"),
            "external",
        )

    def test_full_profile_migrates_legacy_http_kb_to_managed_stdio(self) -> None:
        self.prepare_credentials()
        codex = self.home / ".codex" / "config.toml"
        codex.parent.mkdir(parents=True)
        codex.write_text(
            '[mcp_servers.openubmc-studio]\nurl = "http://localhost:9876/mcp"\n',
            encoding="utf-8",
        )

        result, output = self.install("--clients", "codex")

        self.assertEqual(result, 0, output)
        state = installer.load_state(self.home)
        installed = codex.read_text(encoding="utf-8")
        self.assertNotIn("openubmc-studio", installed)
        self.assertNotIn("localhost:9876", installed)
        self.assertIn("[mcp_servers.openubmc-kb]", installed)
        self.assertIn(
            f"command = {json.dumps(str(installer.knowledge_launcher_path(self.home)))}",
            installed,
        )
        self.assertIs(state["mcp"]["codex"]["created_entry"], True)

    def test_install_removes_duplicate_default_legacy_kb_alias(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        codex = self.home / ".codex" / "config.toml"
        codex.write_text(
            codex.read_text(encoding="utf-8")
            + "\n[mcp_servers.openubmc-studio]\n"
            + f"url = {json.dumps(installer.LEGACY_STUDIO_HTTP_URL)}\n",
            encoding="utf-8",
        )
        result, output = self.install("--clients", "codex")

        self.assertEqual(result, 0, output)
        self.assertNotIn("openubmc-studio", codex.read_text(encoding="utf-8"))

    def test_install_removes_escaped_default_legacy_kb_alias_in_codex(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        codex = self.home / ".codex" / "config.toml"
        codex.write_text(
            codex.read_text(encoding="utf-8")
            + '\n[mcp_servers."openubmc\\u002dstudio"]\n'
            + f"url = {json.dumps(installer.LEGACY_STUDIO_HTTP_URL)}\n",
            encoding="utf-8",
        )

        result, output = self.install("--clients", "codex")

        self.assertEqual(result, 0, output)
        installed = codex.read_text(encoding="utf-8")
        self.assertNotIn("openubmc\\u002dstudio", installed)
        self.assertEqual(installed.count("[mcp_servers.openubmc-kb]"), 1)

    def test_install_rejects_custom_duplicate_legacy_kb_alias_in_codex(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        codex = self.home / ".codex" / "config.toml"
        codex.write_text(
            codex.read_text(encoding="utf-8")
            + "\n[mcp_servers.openubmc-studio]\n"
            + f"url = {json.dumps(installer.LEGACY_STUDIO_HTTP_URL)}\n"
            + "[mcp_servers.openubmc-studio.headers]\n"
            + 'Authorization = "custom"\n',
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            installer.SetupError, "both openubmc-studio and openubmc-kb"
        ):
            self.install("--clients", "codex")
        self.assertIn("Authorization", codex.read_text(encoding="utf-8"))

    def test_install_rejects_quoted_nested_legacy_kb_alias_in_codex(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        codex = self.home / ".codex" / "config.toml"
        codex.write_text(
            codex.read_text(encoding="utf-8")
            + "\n[mcp_servers.openubmc-studio]\n"
            + f"url = {json.dumps(installer.LEGACY_STUDIO_HTTP_URL)}\n"
            + '[mcp_servers."openubmc-studio".headers]\n'
            + 'Authorization = "custom"\n',
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            installer.SetupError, "both openubmc-studio and openubmc-kb"
        ):
            self.install("--clients", "codex")
        self.assertIn("Authorization", codex.read_text(encoding="utf-8"))

    def test_install_rejects_escaped_nested_legacy_kb_alias_in_codex(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        codex = self.home / ".codex" / "config.toml"
        codex.write_text(
            codex.read_text(encoding="utf-8")
            + "\n[mcp_servers.openubmc-studio]\n"
            + f"url = {json.dumps(installer.LEGACY_STUDIO_HTTP_URL)}\n"
            + '[mcp_servers."openubmc\\u002dstudio".headers]\n'
            + 'Authorization = "custom"\n',
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            installer.SetupError, "both openubmc-studio and openubmc-kb"
        ):
            self.install("--clients", "codex")
        self.assertIn("Authorization", codex.read_text(encoding="utf-8"))

    def test_install_rejects_array_table_legacy_kb_alias_in_codex(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        codex = self.home / ".codex" / "config.toml"
        codex.write_text(
            codex.read_text(encoding="utf-8")
            + "\n[[mcp_servers.openubmc-studio]]\n"
            + f"url = {json.dumps(installer.LEGACY_STUDIO_HTTP_URL)}\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            installer.SetupError, "mcp_servers.openubmc-studio must be a TOML table"
        ):
            self.install("--clients", "codex")

    def test_install_rejects_inline_table_legacy_kb_alias_in_codex(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        codex = self.home / ".codex" / "config.toml"
        codex.write_text(
            codex.read_text(encoding="utf-8")
            + "\n[mcp_servers]\n"
            + '"openubmc\\u002dstudio" = '
            + f'{{ url = {json.dumps(installer.LEGACY_STUDIO_HTTP_URL)}, '
            + 'headers = { Authorization = "custom" } }\n',
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            installer.SetupError, "both openubmc-studio and openubmc-kb"
        ):
            self.install("--clients", "codex")

    def test_install_rejects_legacy_alias_after_multiline_toml_string(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        codex = self.home / ".codex" / "config.toml"
        codex.write_text(
            'notes = """\n'
            + "[other]\n"
            + '"""\n'
            + "mcp_servers.openubmc-studio = {\n"
            + f"  url = {json.dumps(installer.LEGACY_STUDIO_HTTP_URL)},\n"
            + '  headers = { Authorization = "custom" }\n'
            + "}\n\n"
            + codex.read_text(encoding="utf-8"),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            installer.SetupError, "both openubmc-studio and openubmc-kb"
        ):
            self.install("--clients", "codex")

    def test_install_rejects_default_legacy_alias_next_to_unmanaged_codex_kb(self) -> None:
        self.prepare_credentials()
        codex = self.home / ".codex" / "config.toml"
        codex.parent.mkdir(parents=True)
        codex.write_text(
            "[mcp_servers.openubmc-kb]\n"
            'command = "/opt/external-kb"\n'
            "args = []\n\n"
            "[mcp_servers.openubmc-studio]\n"
            f"url = {json.dumps(installer.LEGACY_STUDIO_HTTP_URL)}\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            installer.SetupError, "both openubmc-studio and openubmc-kb"
        ):
            self.install("--clients", "codex")

    def test_external_codex_kb_stdio_skips_legacy_http_health_probe(self) -> None:
        self.prepare_credentials()
        codex = self.home / ".codex" / "config.toml"
        codex.parent.mkdir(parents=True)
        codex.write_text(
            "[mcp_servers.openubmc-kb]\n"
            'command = "/opt/openubmc-standalone-mcp"\n'
            'args = ["serve", "--stdio"]\n',
            encoding="utf-8",
        )
        install_output = io.StringIO()
        with (
            mock.patch.object(
                installer,
                "resolve_tool_dirs",
                return_value=([str(self.bin_dir)], []),
            ),
            mock.patch.object(
                installer,
                "knowledge_http_health",
                side_effect=AssertionError("legacy HTTP health must not be probed"),
            ),
            redirect_stdout(install_output),
        ):
            result = installer.perform_install(
                self.args("--install", "--clients", "codex")
            )
        self.assertEqual(result, 0, install_output.getvalue())
        self.assertIn("client starts it on demand", install_output.getvalue())

        check_output = io.StringIO()
        with (
            mock.patch.object(
                installer,
                "knowledge_http_health",
                side_effect=AssertionError("legacy HTTP health must not be probed"),
            ),
            redirect_stdout(check_output),
        ):
            result = installer.main(
                ["check", "--home", str(self.home), "--json"]
            )
        self.assertEqual(result, 0, check_output.getvalue())
        document = json.loads(check_output.getvalue())
        self.assertTrue(document["readiness"]["knowledge"])
        self.assertTrue(document["readiness"]["studio"])
        self.assertEqual(document["knowledge_mcp"]["transport"], "external-stdio")
        self.assertIn("external stdio", document["knowledge_mcp"]["detail"])

    def test_repair_restores_installer_owned_knowledge_mcp_entries(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        codex = self.home / ".codex" / "config.toml"
        codex.write_text(
            codex.read_text(encoding="utf-8").replace(
                str(installer.knowledge_launcher_path(self.home)),
                "/tmp/broken-openubmc-kb",
            ),
            encoding="utf-8",
        )
        self.assertEqual(self.check()[0], 1)
        repair_args = installer.parse_args(["repair", "--home", str(self.home)])
        with mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")):
            self.assertEqual(installer.perform_repair(repair_args), 0)

        repaired = installer.load_state(self.home)
        self.assertTrue(installer.check_toml_mcp(codex, "", repaired["mcp"]["codex"]))

    def test_non_boolean_mcp_ownership_never_authorizes_replacement_or_removal(self) -> None:
        codex = self.home / ".codex" / "config.toml"
        codex.parent.mkdir(parents=True)
        external = (
            "[mcp_servers.openubmc-target-runtime]\n"
            'command = "/opt/external-runtime"\n'
            "args = []\n"
        )
        codex.write_text(external, encoding="utf-8")
        launcher = self.root / "managed-runtime"
        prior = {"codex": {"created_entry": "false", "created_file": 1}}

        with self.assertRaises(installer.SetupError):
            installer.validate_runtime_mcp_configuration(
                self.home,
                ["codex"],
                launcher,
                prior,
            )

        installer.remove_toml_stdio_mcp(
            codex,
            {
                "command": "/opt/external-runtime",
                "args": [],
                "created_entry": "false",
                "created_file": 1,
            },
            installer.backup_path(self.home),
            False,
        )
        self.assertEqual(codex.read_text(encoding="utf-8"), external)

        installer.remove_toml_stdio_mcp(
            codex,
            {
                "command": "/opt/external-runtime",
                "args": [],
                "created_entry": True,
                "created_file": "false",
            },
            installer.backup_path(self.home),
            False,
        )
        self.assertTrue(codex.is_file())
        self.assertEqual(codex.read_text(encoding="utf-8"), "")

    def test_mcp_conflict_fails_before_any_managed_write(self) -> None:
        self.prepare_credentials()
        codex = self.home / ".codex/config.toml"
        codex.parent.mkdir(parents=True)
        original = '[mcp_servers.openubmc-kb]\nurl = "http://localhost:9999/mcp"\n'
        codex.write_text(original, encoding="utf-8")

        with (
            mock.patch.object(
                installer, "resolve_tool_dirs", return_value=([str(self.bin_dir)], [])
            ),
            mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
            self.assertRaises(installer.SetupError),
        ):
            installer.perform_install(self.args("--install", "--clients", "codex"))

        self.assertEqual(codex.read_text(encoding="utf-8"), original)
        self.assertFalse((self.home / ".agents").exists())
        self.assertFalse((self.home / ".bashrc").exists())
        self.assertFalse((self.home / ".profile").exists())
        self.assertFalse(installer.state_path(self.home).exists())

    def test_check_detects_state_link_profile_and_permission_damage_then_repair_fixes_it(self) -> None:
        credentials = self.prepare_credentials()
        result, _ = self.install("--clients", "codex")
        self.assertEqual(result, 0)
        self.assertEqual(self.check()[0], 0)

        state = installer.load_state(self.home)
        damaged_link = self.home / ".agents/skills/openubmc-debug"
        damaged_link.unlink()
        state_links = state["links"]
        assert isinstance(state_links, dict)
        state_links.pop(str(self.home / ".agents/skills/openubmc-build"))
        installer.save_state(self.home, state, False)
        bashrc = self.home / ".bashrc"
        bashrc.write_text("user content\n", encoding="utf-8")
        original_credentials = credentials.read_bytes()
        credentials.chmod(0o644)

        checked, output = self.check()
        self.assertEqual(checked, 1)
        self.assertIn("missing from installer state", output)
        self.assertIn("missing hook", output)
        self.assertIn("expected 0600", output)

        repair_args = installer.parse_args(["--home", str(self.home), "--repair"])
        with mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")):
            self.assertEqual(installer.perform_repair(repair_args), 0)
        self.assertTrue(damaged_link.is_symlink())
        self.assertEqual(credentials.read_bytes(), original_credentials)
        self.assertEqual(stat.S_IMODE(credentials.stat().st_mode), 0o600)
        self.assertEqual(self.check()[0], 0)

    def test_repair_restores_corrupt_runtime_launcher_and_managed_mcp_entry(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        state = installer.load_state(self.home)
        runtime = state["runtime"]
        package = Path(runtime["package_path"])
        launcher = Path(runtime["launcher_path"])
        (package / "runtime.py").write_text("# corrupt\n", encoding="utf-8")
        launcher.unlink()
        codex = self.home / ".codex" / "config.toml"
        codex.write_text(
            "[other]\nvalue = 1\n\n"
            "[mcp_servers.openubmc-kb]\n"
            f"url = {json.dumps(installer.LEGACY_STUDIO_HTTP_URL)}\n",
            encoding="utf-8",
        )

        self.assertEqual(self.check()[0], 1)
        repair_args = installer.parse_args(["repair", "--home", str(self.home)])
        with mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")):
            self.assertEqual(installer.perform_repair(repair_args), 0)

        self.assertIn("[other]", codex.read_text(encoding="utf-8"))
        self.assertTrue(launcher.is_file())
        self.assertEqual(self.check()[0], 0)

    def test_repair_migrates_state_without_runtime_mcp_ownership(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        state = installer.load_state(self.home)
        state.pop("runtime_mcp")
        installer.save_state(self.home, state, False)

        repair_args = installer.parse_args(["repair", "--home", str(self.home)])
        with mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")):
            self.assertEqual(installer.perform_repair(repair_args), 0)

        repaired = installer.load_state(self.home)
        self.assertIs(repaired["runtime_mcp"]["codex"]["created_entry"], True)
        self.assertEqual(self.check()[0], 0)

        uninstall_args = installer.parse_args(
            ["uninstall", "--home", str(self.home)]
        )
        self.assertEqual(installer.perform_uninstall(uninstall_args), 0)
        codex = self.home / ".codex" / "config.toml"
        self.assertNotIn(
            installer.TARGET_RUNTIME_MCP_NAME,
            codex.read_text(encoding="utf-8") if codex.exists() else "",
        )

    def test_repair_migrates_managed_multiclient_state_to_codex_only(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        state = installer.load_state(self.home)
        knowledge_launcher = Path(state["knowledge_mcp"]["launcher_path"])
        runtime_launcher = Path(state["runtime"]["launcher_path"])

        for client in ("claude", "openclaw"):
            skills = installer.client_skills_dir(self.home, client)
            skills.mkdir(parents=True)
            for canonical, relative in EXPECTED_BUNDLE:
                link = skills / canonical
                link.symlink_to(self.source / relative, target_is_directory=True)
                state["links"][str(link)] = str(self.source / relative)
        unrelated_skill = self.home / ".claude" / "skills" / "private-skill"
        unrelated_skill.mkdir()
        (unrelated_skill / "SKILL.md").write_text("private\n", encoding="utf-8")
        openclaw_note = self.home / ".openclaw" / "keep.txt"
        openclaw_note.write_text("keep\n", encoding="utf-8")

        claude = self.home / ".claude.json"
        claude.write_text(
            json.dumps(
                {
                    "keep": True,
                    "mcpServers": {
                        installer.KNOWLEDGE_MCP_NAME: {
                            "type": "stdio",
                            "command": str(knowledge_launcher),
                            "args": [],
                        },
                        installer.TARGET_RUNTIME_MCP_NAME: {
                            "type": "stdio",
                            "command": str(runtime_launcher),
                            "args": [],
                        },
                        "private-server": {
                            "type": "stdio",
                            "command": "/opt/private-server",
                            "args": ["serve"],
                        },
                    },
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        original_claude = claude.read_text(encoding="utf-8")
        state["clients"] = ["codex", "claude", "openclaw"]
        state["mcp"]["claude"] = {
            "path": str(claude),
            "transport": "stdio",
            "command": str(knowledge_launcher),
            "args": [],
            "created_entry": True,
            "created_file": False,
        }
        state["mcp"]["openclaw"] = {"adapter_available": False}
        state["runtime_mcp"]["claude"] = {
            "path": str(claude),
            "command": str(runtime_launcher),
            "args": [],
            "created_entry": True,
            "created_file": False,
        }
        state["runtime_mcp"]["openclaw"] = {"adapter_available": False}
        installer.save_state(self.home, state, False)

        for _ in range(2):
            repair_args = installer.parse_args(["repair", "--home", str(self.home)])
            with mock.patch.object(
                installer, "knowledge_http_health", return_value=(True, "ok")
            ):
                self.assertEqual(installer.perform_repair(repair_args), 0)

        repaired = installer.load_state(self.home)
        self.assertEqual(repaired["clients"], ["codex"])
        self.assertEqual(sorted(repaired["mcp"]), ["codex"])
        self.assertEqual(sorted(repaired["runtime_mcp"]), ["codex"])
        for client in ("claude", "openclaw"):
            skills = installer.client_skills_dir(self.home, client)
            for canonical, _ in EXPECTED_BUNDLE:
                self.assertFalse((skills / canonical).exists())
        self.assertTrue(unrelated_skill.is_dir())
        self.assertEqual(openclaw_note.read_text(encoding="utf-8"), "keep\n")
        claude_document = json.loads(claude.read_text(encoding="utf-8"))
        self.assertTrue(claude_document["keep"])
        self.assertEqual(
            claude_document["mcpServers"],
            {
                "private-server": {
                    "type": "stdio",
                    "command": "/opt/private-server",
                    "args": ["serve"],
                }
            },
        )
        claude_backups = list(
            (installer.openubmc_config_dir(self.home) / "backups").rglob(
                ".claude.json"
            )
        )
        self.assertEqual(len(claude_backups), 1)
        self.assertEqual(
            claude_backups[0].read_text(encoding="utf-8"), original_claude
        )

        uninstall_args = installer.parse_args(["uninstall", "--home", str(self.home)])
        self.assertEqual(installer.perform_uninstall(uninstall_args), 0)
        self.assertEqual(
            json.loads(claude.read_text(encoding="utf-8"))["mcpServers"],
            claude_document["mcpServers"],
        )
        self.assertTrue(unrelated_skill.is_dir())

    def test_launcher_rejects_digest_mismatch_before_mcp_entrypoint_runs(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        state = installer.load_state(self.home)
        runtime = state["runtime"]
        marker = self.root / "entrypoint-ran"
        source_entrypoint = Path(runtime["mcp_entrypoint"])
        source_entrypoint.write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('ran', encoding='utf-8')\n",
            encoding="utf-8",
        )
        package = Path(runtime["package_path"])
        with (package / "runtime.py").open("a", encoding="utf-8") as handle:
            handle.write("\n# digest mismatch\n")

        result = subprocess.run(
            [runtime["launcher_path"]],
            input="",
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, "HOME": str(self.home)},
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("content digest mismatch", result.stderr.lower())
        self.assertIn("repair", result.stderr.lower())
        self.assertFalse(marker.exists())

    def test_launcher_rejects_mcp_entrypoint_drift_before_startup(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        state = installer.load_state(self.home)
        runtime = state["runtime"]
        marker = self.root / "entrypoint-drift-ran"
        source_entrypoint = Path(runtime["mcp_entrypoint"])
        source_entrypoint.write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('ran', encoding='utf-8')\n",
            encoding="utf-8",
        )

        result = subprocess.run(
            [runtime["launcher_path"]],
            input="",
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, "HOME": str(self.home)},
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mcp entrypoint content digest mismatch", result.stderr.lower())
        self.assertFalse(marker.exists())
        self.assertFalse(installer.inspect_runtime_installation(state)["healthy"])

    def test_inspection_reports_corrupt_launcher_as_unhealthy(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        state = installer.load_state(self.home)
        launcher = Path(state["runtime"]["launcher_path"])
        launcher.write_bytes(b"\xff\xfe\x80")
        corrupt = installer.inspect_runtime_installation(state)
        self.assertFalse(corrupt["healthy"])
        self.assertIn("repair", corrupt["detail"])
        launcher.unlink()
        missing = installer.inspect_runtime_installation(state)
        self.assertFalse(missing["matches_installed_state"])
        self.assertIn("repair", missing["detail"])

    def test_launcher_binds_instructions_for_every_installer_skill(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        state = installer.load_state(self.home)
        runtime = state["runtime"]
        for _name, relative in installer.SKILL_BUNDLE:
            with self.subTest(skill=relative):
                skill = Path(runtime["composition_source"]) / relative / "SKILL.md"
                original = skill.read_bytes()
                try:
                    skill.write_bytes(original + b"\nchanged instructions\n")
                    self.assertFalse(installer.inspect_runtime_installation(state)["healthy"])
                    result = subprocess.run(
                        [runtime["launcher_path"]], input="", text=True,
                        capture_output=True, check=False,
                        env={**os.environ, "HOME": str(self.home)},
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("composition mismatch", result.stderr)
                    self.assertIn(relative + "/SKILL.md", result.stderr)
                finally:
                    skill.write_bytes(original)
        self.assertTrue(installer.inspect_runtime_installation(state)["healthy"])

    def test_launcher_rejects_an_added_native_extension(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        state = installer.load_state(self.home)
        runtime = state["runtime"]
        (Path(runtime["package_path"]) / "runtime.so").write_bytes(b"unbound extension")
        result = subprocess.run(
            [runtime["launcher_path"]], input="", text=True,
            capture_output=True, check=False,
            env={**os.environ, "HOME": str(self.home)},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unbound executable", result.stderr)
        self.assertFalse(installer.inspect_runtime_installation(state)["healthy"])

    def test_launcher_ignores_preexisting_timestamp_valid_bytecode(self) -> None:
        import py_compile

        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        state = installer.load_state(self.home)
        runtime = state["runtime"]
        source = Path(runtime["package_path"]) / "__init__.py"
        clean = source.read_bytes()
        original = source.stat()
        malicious = b"raise RuntimeError('stale-bytecode-executed')\n"
        self.assertGreater(len(clean), len(malicious))
        source.write_bytes(malicious.ljust(len(clean), b" "))
        os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
        py_compile.compile(str(source), doraise=True)
        source.write_bytes(clean)
        os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
        healthy, detail, tools = installer.runtime_mcp_health(
            Path(runtime["launcher_path"]), self.home,
        )
        self.assertTrue(healthy, detail)
        self.assertEqual(tools, ["execute", "observe"])

    def test_launcher_keeps_verified_helpers_after_source_changes_during_execution(self) -> None:
        self.prepare_credentials()
        scripts = self.source / "openubmc-debug" / "scripts"
        entrypoint = scripts / "target_runtime_mcp.py"
        helper = scripts / "late_helper.py"
        helper.write_text("VALUE = 'verified bytes'\n", encoding="utf-8")
        entrypoint.write_text(
            "print('ready', flush=True)\n"
            "input()\n"
            "from late_helper import VALUE\n"
            "print(VALUE, flush=True)\n",
            encoding="utf-8",
        )
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        runtime = installer.load_state(self.home)["runtime"]
        child = subprocess.Popen(
            [runtime["launcher_path"]], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, "HOME": str(self.home)},
        )
        try:
            self.assertEqual(child.stdout.readline().strip(), "ready")
            helper.write_text("VALUE = 'drifted bytes'\n", encoding="utf-8")
            stdout, stderr = child.communicate("continue\n", timeout=5)
            self.assertEqual(child.returncode, 0, stderr)
            self.assertEqual(stdout.strip(), "verified bytes")
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)

    def test_real_repository_launcher_initializes_and_lists_domain_tools(self) -> None:
        args = installer.parse_args(
            [
                "install",
                "--home",
                str(self.home),
                "--source",
                str(REPO_ROOT),
                "--clients",
                "codex",
                "--skip-credentials",
                "--non-interactive",
            ]
        )
        with (
            mock.patch.object(
                installer, "resolve_tool_dirs", return_value=([str(self.bin_dir)], [])
            ),
            mock.patch.object(installer, "knowledge_http_health", return_value=(False, "offline")),
        ):
            self.assertEqual(installer.perform_install(args), 0)
        state = installer.load_state(self.home)
        healthy, detail, tools = installer.runtime_mcp_health(
            Path(state["runtime"]["launcher_path"]), self.home, timeout=45.0
        )
        self.assertTrue(healthy, detail)
        self.assertEqual(tools, ["execute", "observe"])
        knowledge = state["knowledge_mcp"]
        kb_healthy, kb_detail, kb_tools, kb_configured = installer.knowledge_mcp_health(
            Path(knowledge["launcher_path"]), self.home
        )
        self.assertTrue(kb_healthy, kb_detail)
        self.assertFalse(kb_configured)
        self.assertEqual(
            kb_tools,
            ["openubmc_kb_list", "openubmc_kb_query", "openubmc_kb_status"],
        )
        kb_config = installer.knowledge_config_path(self.home)
        self.assertTrue(kb_config.is_file())
        self.assertEqual(stat.S_IMODE(kb_config.stat().st_mode), 0o600)
        persistent_root = (
            self.home / ".local" / "state" / "openubmc-target-runtime"
        )
        self.assertTrue((persistent_root / "context-runtime.sqlite3").is_file())
        self.assertTrue((persistent_root / "evidence-blobs").is_dir())
        marker = persistent_root / "preserve-on-uninstall"
        marker.write_text("case-history\n", encoding="utf-8")
        uninstall_args = installer.parse_args(
            ["uninstall", "--home", str(self.home), "--non-interactive"]
        )
        self.assertEqual(installer.perform_uninstall(uninstall_args), 0)
        self.assertEqual(marker.read_text(encoding="utf-8"), "case-history\n")
        self.assertFalse(installer.knowledge_install_root(self.home).exists())
        self.assertTrue(kb_config.is_file())
        codex = self.home / ".codex" / "config.toml"
        if codex.exists():
            self.assertNotIn("openubmc-kb", codex.read_text(encoding="utf-8"))

    def test_uninstall_preserves_credentials_and_unrelated_client_config(self) -> None:
        credentials = self.prepare_credentials()
        codex = self.home / ".codex/config.toml"
        codex.parent.mkdir(parents=True)
        codex.write_text("[other]\nvalue = 1\n", encoding="utf-8")
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        self.assertTrue(installer.runtime_install_root(self.home).is_dir())

        args = installer.parse_args(["--home", str(self.home), "--uninstall"])
        self.assertEqual(installer.perform_uninstall(args), 0)
        self.assertTrue(credentials.is_file())
        self.assertFalse(installer.state_path(self.home).exists())
        self.assertFalse((installer.openubmc_config_dir(self.home) / "env.sh").exists())
        self.assertFalse((self.home / ".agents/skills/openubmc-build").exists())
        self.assertNotIn("openubmc-kb", codex.read_text(encoding="utf-8"))
        self.assertNotIn("openubmc-target-runtime", codex.read_text(encoding="utf-8"))
        self.assertIn("[other]", codex.read_text(encoding="utf-8"))
        self.assertFalse(installer.runtime_install_root(self.home).exists())

    def test_uninstall_removes_codex_file_created_for_both_mcp_entries(self) -> None:
        self.prepare_credentials()
        codex = self.home / ".codex" / "config.toml"
        self.assertFalse(codex.exists())

        self.assertEqual(self.install("--clients", "codex")[0], 0)
        state = installer.load_state(self.home)
        self.assertIs(state["mcp"]["codex"]["created_file"], True)
        self.assertIs(state["runtime_mcp"]["codex"]["created_file"], True)

        args = installer.parse_args(["uninstall", "--home", str(self.home)])
        self.assertEqual(installer.perform_uninstall(args), 0)
        self.assertFalse(codex.exists())

    def test_uninstall_decodes_invalid_state_before_removing_anything(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        original_state = installer.load_state(self.home)
        managed_links = [Path(link) for link in original_state["links"]]
        codex = self.home / ".codex" / "config.toml"
        original_config = codex.read_text(encoding="utf-8")
        args = installer.parse_args(["uninstall", "--home", str(self.home)])

        for field, value, pattern in (
            ("source_mode", {}, "unsupported source mode"),
            ("source_root", {}, "source_root in installer state"),
            ("profiles", [{}], "profiles in installer state"),
            ("mcp", {"codex": []}, "mcp in installer state"),
            (
                "runtime_mcp",
                {"codex": []},
                "runtime_mcp in installer state",
            ),
        ):
            with self.subTest(field=field):
                state = dict(original_state)
                state[field] = value
                installer.save_state(self.home, state, False)
                with self.assertRaisesRegex(installer.SetupError, pattern):
                    installer.perform_uninstall(args)
                self.assertTrue(installer.state_path(self.home).is_file())
                self.assertTrue(all(link.is_symlink() for link in managed_links))
                self.assertEqual(codex.read_text(encoding="utf-8"), original_config)

    def test_uninstall_rejects_missing_client_ownership_without_side_effects(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        original_state = installer.load_state(self.home)
        managed_links = [Path(link) for link in original_state["links"]]
        codex = self.home / ".codex" / "config.toml"
        original_config = codex.read_text(encoding="utf-8")
        runtime_root = installer.runtime_install_root(self.home)
        env_file = installer.openubmc_config_dir(self.home) / "env.sh"
        original_env = env_file.read_text(encoding="utf-8")
        original_profiles = {
            profile: Path(profile).read_text(encoding="utf-8")
            for profile in original_state["profiles"]
        }
        args = installer.parse_args(["uninstall", "--home", str(self.home)])

        for field in ("mcp", "runtime_mcp"):
            with self.subTest(field=field):
                state = json.loads(json.dumps(original_state))
                state[field].pop("codex")
                installer.save_state(self.home, state, False)
                state_before = installer.state_path(self.home).read_text(
                    encoding="utf-8"
                )

                with self.assertRaisesRegex(
                    installer.SetupError,
                    rf"{field}\.codex.*run repair before uninstalling",
                ):
                    installer.perform_uninstall(args)

                self.assertEqual(
                    installer.state_path(self.home).read_text(encoding="utf-8"),
                    state_before,
                )
                self.assertTrue(all(link.is_symlink() for link in managed_links))
                self.assertEqual(codex.read_text(encoding="utf-8"), original_config)
                self.assertTrue(runtime_root.is_dir())
                self.assertEqual(env_file.read_text(encoding="utf-8"), original_env)
                for profile, content in original_profiles.items():
                    self.assertEqual(Path(profile).read_text(encoding="utf-8"), content)

    def test_dry_run_does_not_create_target_home(self) -> None:
        output = io.StringIO()
        args = self.args("--install", "--clients", "all", "--skip-credentials", "--dry-run")
        with (
            mock.patch.object(
                installer, "resolve_tool_dirs", return_value=([str(self.bin_dir)], [])
            ),
            mock.patch.object(installer, "knowledge_http_health", return_value=(False, "offline")),
            redirect_stdout(output),
        ):
            self.assertEqual(installer.perform_install(args), 0)
        self.assertFalse(self.home.exists())
        self.assertIn("would link", output.getvalue())

    def test_managed_dry_run_allows_the_planned_clone_to_be_absent(self) -> None:
        output = io.StringIO()
        args = installer.parse_args(
            [
                "install",
                "--home",
                str(self.home),
                "--source-mode",
                "managed",
                "--ref",
                "v1.2.3",
                "--clients",
                "codex",
                "--skip-credentials",
                "--non-interactive",
                "--dry-run",
            ]
        )
        with (
            mock.patch.object(installer, "local_repository_from_script", return_value=None),
            mock.patch.object(
                installer, "resolve_tool_dirs", return_value=([str(self.bin_dir)], [])
            ),
            mock.patch.object(installer, "knowledge_http_health", return_value=(False, "offline")),
            redirect_stdout(output),
        ):
            self.assertEqual(installer.perform_install(args), 0)
        self.assertFalse(self.home.exists())
        self.assertIn("would clone", output.getvalue())

    def test_new_managed_install_requires_an_explicit_immutable_ref(self) -> None:
        base = [
            "install",
            "--home",
            str(self.home),
            "--source-mode",
            "managed",
            "--clients",
            "codex",
            "--skill-profile",
            "target-runtime",
            "--skip-credentials",
            "--skip-tool-install",
            "--non-interactive",
            "--dry-run",
        ]
        for extra in ([], ["--ref", "main"]):
            with self.subTest(extra=extra):
                stderr = io.StringIO()
                with (
                    mock.patch.object(
                        installer, "local_repository_from_script", return_value=None
                    ),
                    redirect_stderr(stderr),
                ):
                    result = installer.main([*base, *extra])

                self.assertEqual(result, 2)
                self.assertIn("release tag or full commit", stderr.getvalue())
                self.assertFalse(self.home.exists())

    def test_reinstall_with_explicit_source_restores_recorded_knowledge_url(self) -> None:
        self.prepare_credentials()
        custom_url = "http://localhost:9988/mcp"
        self.assertEqual(
            self.install("--clients", "codex", "--kb-url", custom_url)[0],
            0,
        )
        args = installer.parse_args(
            [
                "install",
                "--home",
                str(self.home),
                "--source",
                str(self.source),
                "--clients",
                "codex",
                "--non-interactive",
            ]
        )
        with (
            mock.patch.object(
                installer, "resolve_tool_dirs", return_value=([str(self.bin_dir)], [])
            ),
            mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
        ):
            self.assertEqual(installer.perform_install(args), 0)
        self.assertEqual(installer.load_state(self.home)["knowledge_url"], custom_url)

    def test_legacy_studio_url_state_and_cli_alias_remain_readable(self) -> None:
        custom_url = "http://localhost:9988/mcp"
        args = installer.parse_args(
            ["install", "--home", str(self.home), "--studio-url", custom_url]
        )
        self.assertEqual(args.knowledge_url, custom_url)

        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex", "--kb-url", custom_url)[0], 0)
        state = installer.load_state(self.home)
        state["studio_url"] = state.pop("knowledge_url")
        installer.save_state(self.home, state, False)
        self.assertEqual(
            installer.decode_recorded_install(installer.load_state(self.home)).knowledge_url,
            custom_url,
        )

    def test_legacy_link_and_profile_markers_are_migrated(self) -> None:
        self.prepare_credentials()
        skills_dir = self.home / ".agents/skills"
        skills_dir.mkdir(parents=True)
        (skills_dir / "openubmc-environment").symlink_to(self.source, target_is_directory=True)
        self.home.mkdir(exist_ok=True)
        (self.home / ".bashrc").write_text(
            "before\n"
            f"{installer.OLD_MARKER_START}\nold body\n{installer.OLD_MARKER_END}\n"
            f"{installer.LEGACY_CREDENTIALS_START}\nsecret source\n{installer.LEGACY_CREDENTIALS_END}\n"
            "after\n",
            encoding="utf-8",
        )
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        content = (self.home / ".bashrc").read_text(encoding="utf-8")
        self.assertFalse((skills_dir / "openubmc-environment").exists())
        self.assertNotIn(installer.OLD_MARKER_START, content)
        self.assertNotIn(installer.LEGACY_CREDENTIALS_START, content)
        self.assertEqual(content.count(installer.MARKER_START), 1)
        self.assertIn("before", content)
        self.assertIn("after", content)

    def test_legacy_branch_install_requires_immutable_reinstall_before_update(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        state = installer.load_state(self.home)
        state["managed_checkout"] = True
        state["source_mode"] = "managed"
        state["repo_url"] = installer.DEFAULT_REPO_URL
        state.pop("requested_ref", None)
        state.pop("resolved_commit", None)
        state.pop("ref_kind", None)
        installer.save_state(self.home, state, False)

        args = installer.parse_args(["--home", str(self.home), "--update"])
        with (
            mock.patch.object(installer, "checkout_managed_release") as checkout_release,
            self.assertRaisesRegex(installer.SetupError, "mutable legacy branch"),
        ):
            installer.perform_update(args)
        checkout_release.assert_not_called()

        reinstall = installer.parse_args(
            [
                "install",
                "--home",
                str(self.home),
                "--clients",
                "codex",
                "--skip-credentials",
                "--skip-tool-install",
                "--non-interactive",
            ]
        )
        with self.assertRaisesRegex(installer.SetupError, "mutable legacy branch"):
            installer.perform_install(reinstall)

        repair = installer.parse_args(["repair", "--home", str(self.home)])
        with self.assertRaisesRegex(installer.SetupError, "mutable legacy branch"):
            installer.perform_repair(repair)

        output = io.StringIO()
        with (
            mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
            redirect_stdout(output),
        ):
            result = installer.main(["check", "--home", str(self.home), "--json"])
        self.assertEqual(result, 1)
        document = json.loads(output.getvalue())
        self.assertEqual(document["source"]["ref_kind"], "legacy-branch")
        revision = next(
            check for check in document["checks"] if check["name"] == "source_revision"
        )
        self.assertFalse(revision["ok"])
        self.assertIn("mutable legacy branch", revision["detail"])

    def test_update_revalidates_recorded_immutable_release_without_branch_merge(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        state = installer.load_state(self.home)
        state.update(
            {
                "managed_checkout": True,
                "source_mode": "managed",
                "repo_url": installer.DEFAULT_REPO_URL,
                "ref": "v1.2.3",
                "requested_ref": "v1.2.3",
                "ref_kind": "tag",
                "source_commit": "a" * 40,
                "resolved_commit": "a" * 40,
            }
        )
        state["clients"] = ["codex", "claude", "openclaw"]
        state["mcp"]["openclaw"] = {"adapter_available": False}
        legacy_link = self.home / ".claude" / "skills" / "openubmc-debug"
        legacy_link.parent.mkdir(parents=True)
        legacy_link.symlink_to(
            self.source / "openubmc-debug", target_is_directory=True
        )
        state["links"][str(legacy_link)] = str(self.source / "openubmc-debug")
        claude = self.home / ".claude.json"
        runtime_launcher = Path(state["runtime"]["launcher_path"])
        claude.write_text(
            json.dumps(
                {
                    "keep": True,
                    "mcpServers": {
                        installer.TARGET_RUNTIME_MCP_NAME: {
                            "type": "stdio",
                            "command": str(runtime_launcher),
                            "args": [],
                        },
                        "private-server": {
                            "type": "stdio",
                            "command": "/opt/private-server",
                            "args": [],
                        },
                    },
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        state["runtime_mcp"]["claude"] = {
            "path": str(claude),
            "command": str(runtime_launcher),
            "args": [],
            "created_entry": True,
            "created_file": False,
        }
        state["runtime_mcp"]["openclaw"] = {"adapter_available": False}
        installer.save_state(self.home, state, False)

        args = installer.parse_args(["update", "--home", str(self.home)])
        with (
            mock.patch.object(
                installer,
                "checkout_managed_release",
                return_value="a" * 40,
            ) as checkout_release,
            mock.patch.object(installer, "git_commit", return_value="a" * 40),
            mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
        ):
            self.assertEqual(installer.perform_update(args), 0)

        checkout_release.assert_called_once_with(
            self.source,
            installer.DEFAULT_REPO_URL,
            "v1.2.3",
            False,
            bundle=EXPECTED_TARGET_RUNTIME_BUNDLE,
            expected_commit="a" * 40,
        )
        updated = installer.load_state(self.home)
        self.assertEqual(updated["requested_ref"], "v1.2.3")
        self.assertEqual(updated["ref_kind"], "tag")
        self.assertEqual(updated["resolved_commit"], "a" * 40)
        self.assertEqual(updated["clients"], ["codex"])
        self.assertEqual(updated["mcp"], {})
        self.assertEqual(sorted(updated["runtime_mcp"]), ["codex"])
        self.assertFalse(legacy_link.exists())
        claude_document = json.loads(claude.read_text(encoding="utf-8"))
        self.assertTrue(claude_document["keep"])
        self.assertEqual(
            claude_document["mcpServers"],
            {
                "private-server": {
                    "type": "stdio",
                    "command": "/opt/private-server",
                    "args": [],
                }
            },
        )

    def test_explicit_release_upgrade_records_revision_and_public_check(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        state = installer.load_state(self.home)
        state.update(
            {
                "source_mode": "managed",
                "managed_checkout": True,
                "ref": "v1.2.3",
                "requested_ref": "v1.2.3",
                "ref_kind": "tag",
                "source_commit": "a" * 40,
                "resolved_commit": "a" * 40,
            }
        )
        installer.save_state(self.home, state, False)
        args = installer.parse_args(
            [
                "install",
                "--home",
                str(self.home),
                "--source-mode",
                "managed",
                "--ref",
                "v1.2.4",
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
                "--skip-credentials",
                "--skip-tool-install",
                "--non-interactive",
            ]
        )
        with (
            mock.patch.object(installer, "resolve_source", return_value=(self.source, "managed")),
            mock.patch.object(installer, "git_commit", return_value="b" * 40),
            mock.patch.object(
                installer,
                "resolve_tool_dirs",
                return_value=([str(self.bin_dir)], []),
            ),
        ):
            self.assertEqual(installer.perform_install(args), 0)

        upgraded = installer.load_state(self.home)
        self.assertEqual(upgraded["requested_ref"], "v1.2.4")
        self.assertEqual(upgraded["ref_kind"], "tag")
        self.assertEqual(upgraded["resolved_commit"], "b" * 40)
        self.assertEqual(upgraded["rollback_commit"], "a" * 40)

        output = io.StringIO()
        verified_identity = {
            "schema": "openubmc-agent-workflow.release-lock.v1",
            "release_version": "1.2.4",
            "source_commit": "b" * 40,
            "lock_digest": "sha256:" + "c" * 64,
            "immutable": True,
        }
        with (
            mock.patch.object(installer, "git_commit", return_value="b" * 40),
            mock.patch.object(installer, "git_dirty", return_value=False),
            mock.patch.object(
                installer,
                "release_identity",
                return_value=verified_identity,
            ),
            redirect_stdout(output),
        ):
            result = installer.main(["check", "--home", str(self.home), "--json"])
        self.assertEqual(result, 0)
        document = json.loads(output.getvalue())
        self.assertEqual(document["source"]["requested_ref"], "v1.2.4")
        self.assertEqual(document["source"]["ref_kind"], "tag")
        self.assertEqual(document["source"]["resolved_commit"], "b" * 40)
        self.assertTrue(document["release_identity_verified"])

    def test_rollback_toggles_between_the_last_two_managed_revisions(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        state = installer.load_state(self.home)
        state.update(
            {
                "managed_checkout": True,
                "source_mode": "managed",
                "ref": "v1.2.3",
                "requested_ref": "v1.2.3",
                "ref_kind": "tag",
                "source_commit": "a" * 40,
                "resolved_commit": "a" * 40,
                "rollback_commit": "b" * 40,
            }
        )
        state["clients"] = ["codex", "claude", "openclaw"]
        state["mcp"]["openclaw"] = {"adapter_available": False}
        state["runtime_mcp"]["openclaw"] = {"adapter_available": False}
        installer.save_state(self.home, state, False)

        args = installer.parse_args(["rollback", "--home", str(self.home)])
        with (
            mock.patch.object(installer, "checkout_managed_revision") as checkout,
            mock.patch.object(installer, "git_commit", return_value="b" * 40),
            mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
        ):
            self.assertEqual(installer.perform_rollback(args), 0)
        checkout.assert_called_once_with(
            self.source,
            "b" * 40,
            False,
            EXPECTED_TARGET_RUNTIME_BUNDLE,
        )
        rolled_back = installer.load_state(self.home)
        self.assertEqual(rolled_back["source_commit"], "b" * 40)
        self.assertEqual(rolled_back["resolved_commit"], "b" * 40)
        self.assertEqual(rolled_back["requested_ref"], "b" * 40)
        self.assertEqual(rolled_back["ref_kind"], "commit")
        self.assertEqual(rolled_back["rollback_commit"], "a" * 40)
        self.assertEqual(rolled_back["clients"], ["codex"])

        args = installer.parse_args(["rollback", "--home", str(self.home)])
        with (
            mock.patch.object(installer, "checkout_managed_revision") as checkout,
            mock.patch.object(installer, "git_commit", return_value="a" * 40),
            mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
        ):
            self.assertEqual(installer.perform_rollback(args), 0)
        checkout.assert_called_once_with(
            self.source,
            "a" * 40,
            False,
            EXPECTED_TARGET_RUNTIME_BUNDLE,
        )
        restored = installer.load_state(self.home)
        self.assertEqual(restored["source_commit"], "a" * 40)
        self.assertEqual(restored["resolved_commit"], "a" * 40)
        self.assertEqual(restored["requested_ref"], "a" * 40)
        self.assertEqual(restored["ref_kind"], "commit")
        self.assertEqual(restored["rollback_commit"], "b" * 40)

    def test_linked_source_uses_refresh_instead_of_update(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        state = installer.load_state(self.home)
        self.assertEqual(state["source_mode"], "linked")

        update_args = installer.parse_args(["update", "--home", str(self.home)])
        with self.assertRaises(installer.SetupError):
            installer.perform_update(update_args)

        refresh_args = installer.parse_args(["refresh", "--home", str(self.home)])
        with mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")):
            self.assertEqual(installer.perform_refresh(refresh_args), 0)
        self.assertEqual(installer.load_state(self.home)["source_mode"], "linked")

    def test_repair_preserves_recorded_commit_until_refresh(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        state = installer.load_state(self.home)
        state["source_commit"] = "recorded-commit"
        installer.save_state(self.home, state, False)

        repair_args = installer.parse_args(["repair", "--home", str(self.home)])
        with (
            mock.patch.object(installer, "git_commit", return_value="current-commit"),
            mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
        ):
            self.assertEqual(installer.perform_repair(repair_args), 0)
        self.assertEqual(
            installer.load_state(self.home)["source_commit"],
            "recorded-commit",
        )

        refresh_args = installer.parse_args(["refresh", "--home", str(self.home)])
        with (
            mock.patch.object(installer, "git_commit", return_value="current-commit"),
            mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
        ):
            self.assertEqual(installer.perform_refresh(refresh_args), 0)
        self.assertEqual(
            installer.load_state(self.home)["source_commit"],
            "current-commit",
        )

    def test_non_boolean_legacy_checkout_marker_never_enables_managed_lifecycle(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        state = installer.load_state(self.home)
        state.pop("source_mode")
        state["managed_checkout"] = "false"
        installer.save_state(self.home, state, False)

        update_args = installer.parse_args(
            ["update", "--home", str(self.home)]
        )
        with self.assertRaisesRegex(installer.SetupError, "source is linked"):
            installer.perform_update(update_args)

        refresh_args = installer.parse_args(
            ["refresh", "--home", str(self.home)]
        )
        with mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")):
            self.assertEqual(installer.perform_refresh(refresh_args), 0)
        refreshed = installer.load_state(self.home)
        self.assertEqual(refreshed["source_mode"], "linked")
        self.assertIs(refreshed["managed_checkout"], False)

        for value in ("invalid", [], {}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    installer.SetupError, "unsupported source mode"
                ):
                    installer.source_mode_from_state({"source_mode": value})

    def test_recorded_lifecycle_reads_one_state_snapshot(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        repair_args = installer.parse_args(
            ["repair", "--home", str(self.home)]
        )
        original_load_state = installer.load_state
        with (
            mock.patch.object(
                installer,
                "load_state",
                wraps=original_load_state,
            ) as load_state,
            mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
        ):
            self.assertEqual(installer.perform_repair(repair_args), 0)
        self.assertEqual(load_state.call_count, 1)
        self.assertEqual(
            installer.load_state(self.home)["skill_profile"],
            "target-runtime",
        )

    def test_check_json_is_structured_and_contains_readiness_layers(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        output = io.StringIO()
        with (
            mock.patch.object(installer, "knowledge_http_health", return_value=(False, "offline")),
            redirect_stdout(output),
        ):
            result = installer.main(["check", "--home", str(self.home), "--json"])
        self.assertEqual(result, 0)
        document = json.loads(output.getvalue())
        self.assertTrue(document["ok"])
        self.assertTrue(document["operational_ready"])
        self.assertFalse(document["release_identity_verified"])
        self.assertFalse(document["evaluation_ready"])
        self.assertTrue(document["readiness"]["core"])
        self.assertTrue(document["readiness"]["credentials"])
        self.assertFalse(document["readiness"]["release_identity"])
        self.assertFalse(document["readiness"]["evaluation"])
        self.assertFalse(document["readiness"]["knowledge"])
        self.assertFalse(document["readiness"]["studio"])
        self.assertEqual(document["source"]["mode"], "linked")
        self.assertEqual(document["release"]["trust_mode"], "linked-development")
        self.assertFalse(document["release"]["verified"])
        self.assertEqual(document["source"]["requested_ref"], "")
        self.assertEqual(document["source"]["ref_kind"], "linked")
        self.assertEqual(
            document["source"]["resolved_commit"],
            document["source"]["expected_commit"],
        )
        self.assertTrue(
            any(
                action.get("code") == "install_immutable_release"
                for action in document["next_actions"]
            )
        )

    def test_check_json_rejects_inconsistent_immutable_revision_state(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        state = installer.load_state(self.home)
        state.update(
            {
                "source_mode": "managed",
                "managed_checkout": True,
                "ref": "v1.2.3",
                "requested_ref": "v1.2.3",
                "ref_kind": "tag",
                "source_commit": "a" * 40,
                "resolved_commit": "b" * 40,
            }
        )
        installer.save_state(self.home, state, False)
        output = io.StringIO()

        with (
            mock.patch.object(installer, "git_commit", return_value="a" * 40),
            mock.patch.object(installer, "git_dirty", return_value=False),
            redirect_stdout(output),
        ):
            result = installer.main(["check", "--home", str(self.home), "--json"])

        self.assertEqual(result, 1)
        document = json.loads(output.getvalue())
        self.assertTrue(document["operational_ready"])
        self.assertFalse(document["release_identity_verified"])
        self.assertFalse(document["evaluation_ready"])
        self.assertEqual(document["source"]["ref_kind"], "tag")
        revision = next(
            check for check in document["checks"] if check["name"] == "source_revision"
        )
        self.assertFalse(revision["ok"])
        self.assertIn("resolved commit does not match source commit", revision["detail"])

    def test_check_text_distinguishes_development_health_from_release_trust(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        output = io.StringIO()

        with (
            mock.patch.object(installer, "knowledge_http_health", return_value=(False, "offline")),
            redirect_stdout(output),
        ):
            result = installer.main(["check", "--home", str(self.home)])

        self.assertEqual(result, 0, output.getvalue())
        rendered = output.getvalue()
        self.assertIn("operational readiness: ready", rendered)
        self.assertIn("release identity verified: no", rendered)
        self.assertIn("evaluation readiness: not ready", rendered)
        self.assertIn("managed installation pinned to an immutable", rendered)
        self.assertIn("release trust mode: linked-development", rendered)
        self.assertNotIn("vX.Y.Z", rendered)
        self.assertIn(
            "/repos/lihuabai629-star/openubmc-agent-workflow/releases/latest",
            rendered,
        )
        self.assertIn("GITHUB_API_URL", rendered)
        self.assertIn(installer.DEFAULT_REPO_URL, rendered)
        self.assertIn("install_environment.py\" install", rendered)

    def test_release_remediation_uses_recorded_github_repository(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        state = installer.load_state(self.home)
        state["repo_url"] = "https://github.com/example/workflow-fork.git"
        installer.save_state(self.home, state, False)
        output = io.StringIO()

        with (
            mock.patch.object(
                installer, "knowledge_http_health", return_value=(False, "offline")
            ),
            redirect_stdout(output),
        ):
            result = installer.main(["check", "--home", str(self.home)])

        self.assertEqual(result, 0, output.getvalue())
        rendered = output.getvalue()
        self.assertIn("/repos/example/workflow-fork/releases/latest", rendered)
        self.assertIn("https://github.com/example/workflow-fork.git", rendered)
        self.assertIn("git clone --quiet", rendered)
        self.assertIn("install_environment.py\" install", rendered)
        self.assertNotIn("lihuabai629-star/openubmc-agent-workflow", rendered)

        remote, _commit = self.create_release_remote()
        api_root = self.root / "github-api"
        release_endpoint = (
            api_root
            / "repos"
            / "example"
            / "workflow-fork"
            / "releases"
            / "latest"
        )
        release_endpoint.parent.mkdir(parents=True)
        release_endpoint.write_text(
            json.dumps({"tag_name": "v1.2.3"}),
            encoding="utf-8",
        )

        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(api_root), **kwargs)

            def log_message(self, _format, *args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        fake_bin = self.root / "fake-git-bin"
        fake_bin.mkdir()
        fake_git = fake_bin / "git"
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)
        fake_git.write_text(
            "#!/usr/bin/env bash\n"
            "set -e\n"
            "args=()\n"
            "for arg in \"$@\"; do\n"
            "  if [[ \"$arg\" == "
            "\"https://github.com/example/workflow-fork.git\" ]]; then\n"
            f"    arg={json.dumps(str(remote))}\n"
            "  fi\n"
            "  args+=(\"$arg\")\n"
            "done\n"
            f"exec {real_git} \"${{args[@]}}\"\n",
            encoding="utf-8",
        )
        fake_git.chmod(0o755)
        capture = self.root / "github-remediation-arguments.json"
        environment = dict(os.environ)
        environment.update(
            {
                "GITHUB_API_URL": (
                    f"http://127.0.0.1:{server.server_address[1]}"
                ),
                "OPENUBMC_REMEDIATION_CAPTURE": str(capture),
                "PATH": str(fake_bin) + os.pathsep + environment["PATH"],
            }
        )
        json_output = io.StringIO()
        with (
            mock.patch.object(
                installer, "knowledge_http_health", return_value=(False, "offline")
            ),
            redirect_stdout(json_output),
        ):
            json_result = installer.main(
                ["check", "--home", str(self.home), "--json"]
            )
        self.assertEqual(json_result, 0, json_output.getvalue())
        command = next(
            action["command"]
            for action in json.loads(json_output.getvalue())["next_actions"]
            if action.get("code") == "install_immutable_release"
        )
        try:
            completed = subprocess.run(
                ["bash", "-c", command],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            json.loads(capture.read_text(encoding="utf-8")),
            [
                "install",
                "--source-mode",
                "managed",
                "--repo-url",
                "https://github.com/example/workflow-fork.git",
                "--ref",
                "v1.2.3",
                "--non-interactive",
            ],
        )

    def test_release_remediation_for_non_github_repository_avoids_github_api(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        remote, _commit = self.create_release_remote()
        source = self.root / "release-repository"
        subprocess.run(
            ["git", "-C", str(source), "tag", "v1.2.4-rc2"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(source), "tag", "experiment-9"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(source), "push", str(remote), "--tags"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        state = installer.load_state(self.home)
        state["repo_url"] = str(remote)
        installer.save_state(self.home, state, False)
        output = io.StringIO()

        with (
            mock.patch.object(
                installer, "knowledge_http_health", return_value=(False, "offline")
            ),
            redirect_stdout(output),
        ):
            result = installer.main(["check", "--home", str(self.home), "--json"])

        self.assertEqual(result, 0, output.getvalue())
        document = json.loads(output.getvalue())
        action = next(
            action
            for action in document["next_actions"]
            if action.get("code") == "install_immutable_release"
        )
        command = action["command"]
        self.assertIn("git ls-remote --tags --refs", command)
        self.assertIn(str(remote), command)
        self.assertIn("git clone --quiet", command)
        self.assertIn("release.py\" verify", command)
        self.assertIn("install_environment.py\" install", command)
        self.assertNotIn("gh release view", command)
        self.assertNotIn("gh api", command)
        self.assertNotIn("vX.Y.Z", command)

        capture = self.root / "remediation-arguments.json"
        environment = dict(os.environ)
        environment["OPENUBMC_REMEDIATION_CAPTURE"] = str(capture)
        completed = subprocess.run(
            ["bash", "-c", command],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            json.loads(capture.read_text(encoding="utf-8")),
            [
                "install",
                "--source-mode",
                "managed",
                "--repo-url",
                str(remote),
                "--ref",
                "v1.2.3",
                "--non-interactive",
            ],
        )

    def test_linked_identity_mismatch_is_operational_but_not_evaluation_ready(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        output = io.StringIO()
        identity = {
            "schema": "linked-development-source",
            "release_version": "2.0.0",
            "immutable": False,
            "validation_error": (
                "release lock does not match repository: runtime, skills, "
                "source_tree_digest"
            ),
        }

        with (
            mock.patch.object(installer, "release_identity", return_value=identity),
            mock.patch.object(installer, "knowledge_http_health", return_value=(False, "offline")),
            redirect_stdout(output),
        ):
            result = installer.main(["check", "--home", str(self.home), "--json"])

        self.assertEqual(result, 0, output.getvalue())
        document = json.loads(output.getvalue())
        self.assertTrue(document["operational_ready"])
        self.assertFalse(document["release_identity_verified"])
        self.assertFalse(document["evaluation_ready"])
        self.assertIn("runtime, skills", document["release"]["validation_error"])

    def test_managed_identity_mismatches_do_not_hide_runtime_operability(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        state = installer.load_state(self.home)
        state.update(
            {
                "source_mode": "managed",
                "managed_checkout": True,
                "ref": "v2.0.0",
                "requested_ref": "v2.0.0",
                "ref_kind": "tag",
                "source_commit": "a" * 40,
                "resolved_commit": "a" * 40,
            }
        )
        installer.save_state(self.home, state, False)

        mismatches = (
            "installed release lock identity changed",
            "release lock does not match repository: runtime",
            "release lock does not match repository: skills",
            "release lock does not match repository: source_tree_digest",
        )
        for mismatch in mismatches:
            with self.subTest(mismatch=mismatch):
                output = io.StringIO()
                with (
                    mock.patch.object(installer, "git_commit", return_value="a" * 40),
                    mock.patch.object(installer, "git_dirty", return_value=False),
                    mock.patch.object(
                        installer,
                        "release_identity",
                        side_effect=installer.SetupError(mismatch),
                    ),
                    mock.patch.object(
                        installer, "knowledge_http_health", return_value=(False, "offline")
                    ),
                    redirect_stdout(output),
                ):
                    result = installer.main(
                        ["check", "--home", str(self.home), "--json"]
                    )

                self.assertEqual(result, 1, output.getvalue())
                document = json.loads(output.getvalue())
                self.assertTrue(document["operational_ready"])
                self.assertFalse(document["release_identity_verified"])
                self.assertFalse(document["evaluation_ready"])
                self.assertIn(mismatch, document["release"]["validation_error"])

    def test_managed_immutable_identity_validation_error_is_top_level_unhealthy(
        self,
    ) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        state = installer.load_state(self.home)
        state.update(
            {
                "source_mode": "managed",
                "managed_checkout": True,
                "ref": "v2.0.0",
                "requested_ref": "v2.0.0",
                "ref_kind": "tag",
                "source_commit": "a" * 40,
                "resolved_commit": "a" * 40,
            }
        )
        installer.save_state(self.home, state, False)
        output = io.StringIO()
        identity = {
            "schema": "openubmc-agent-workflow.release-lock.v1",
            "release_version": "2.0.0",
            "source_commit": "a" * 40,
            "lock_digest": "sha256:" + "b" * 64,
            "immutable": True,
            "validation_error": (
                "release lock does not match repository: runtime, skills, "
                "source_tree_digest"
            ),
        }

        with (
            mock.patch.object(installer, "git_commit", return_value="a" * 40),
            mock.patch.object(installer, "git_dirty", return_value=False),
            mock.patch.object(installer, "release_identity", return_value=identity),
            mock.patch.object(
                installer, "knowledge_http_health", return_value=(False, "offline")
            ),
            redirect_stdout(output),
        ):
            result = installer.main(["check", "--home", str(self.home), "--json"])

        self.assertEqual(result, 1, output.getvalue())
        document = json.loads(output.getvalue())
        self.assertFalse(document["ok"])
        self.assertTrue(document["operational_ready"])
        self.assertFalse(document["release_identity_verified"])
        self.assertFalse(document["evaluation_ready"])
        self.assertEqual(
            document["release"]["trust_mode"], "unverified-managed-source"
        )
        release_check = next(
            check
            for check in document["checks"]
            if check["name"] == "release_identity"
        )
        self.assertFalse(release_check["ok"])
        self.assertTrue(release_check["blocking"])
        self.assertTrue(
            any(
                action.get("code") == "install_immutable_release"
                for action in document["next_actions"]
            )
        )

    def test_legacy_managed_release_without_lock_is_top_level_unhealthy(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        state = installer.load_state(self.home)
        state.update(
            {
                "source_mode": "managed",
                "managed_checkout": True,
                "ref": "v1.1.0",
                "requested_ref": "v1.1.0",
                "ref_kind": "tag",
                "source_commit": "a" * 40,
                "resolved_commit": "a" * 40,
            }
        )
        installer.save_state(self.home, state, False)
        output = io.StringIO()
        identity = {
            "schema": "legacy-release-without-lock",
            "release_version": "1.1.0",
            "immutable": False,
        }

        with (
            mock.patch.object(installer, "git_commit", return_value="a" * 40),
            mock.patch.object(installer, "git_dirty", return_value=False),
            mock.patch.object(installer, "release_identity", return_value=identity),
            mock.patch.object(
                installer, "knowledge_http_health", return_value=(False, "offline")
            ),
            redirect_stdout(output),
        ):
            result = installer.main(["check", "--home", str(self.home), "--json"])

        self.assertEqual(result, 1, output.getvalue())
        document = json.loads(output.getvalue())
        self.assertFalse(document["ok"])
        self.assertTrue(document["operational_ready"])
        self.assertFalse(document["release_identity_verified"])
        self.assertFalse(document["evaluation_ready"])
        release_check = next(
            check for check in document["checks"] if check["name"] == "release_identity"
        )
        self.assertFalse(release_check["ok"])
        self.assertTrue(release_check["blocking"])

    def test_noninteractive_dry_run_does_not_plan_tty_credentials(self) -> None:
        args = self.args("--install", "--dry-run")
        plan = installer.prepare_credentials(args)
        self.assertEqual(plan["result"], "missing")
        self.assertNotIn("missing_count", plan)

    def test_dry_run_json_separates_current_and_planned_workflows(self) -> None:
        self.prepare_credentials()
        self.assertEqual(
            self.install(
                "--clients",
                "codex",
                "--skill-profile",
                "target-runtime",
            )[0],
            0,
        )
        output = io.StringIO()
        with (
            mock.patch.object(
                installer,
                "resolve_tool_dirs",
                return_value=([str(self.bin_dir)], []),
            ),
            mock.patch.object(installer, "knowledge_http_health", return_value=(False, "offline")),
            redirect_stdout(output),
        ):
            result = installer.main(
                [
                    "install",
                    "--home",
                    str(self.home),
                    "--source",
                    str(self.source),
                    "--source-mode",
                    "linked",
                    "--clients",
                    "codex",
                    "--skill-profile",
                    "full",
                    "--preserve-skills",
                    "none",
                    "--non-interactive",
                    "--dry-run",
                    "--json",
                ]
            )
        self.assertEqual(result, 0, output.getvalue())
        document = json.loads(output.getvalue())
        self.assertEqual(document["workflow"]["skill_profile"], "target-runtime")
        self.assertEqual(document["workflow"]["skill_count"], 7)
        self.assertEqual(document["planned_workflow"]["skill_profile"], "full")
        self.assertEqual(document["planned_workflow"]["skill_count"], 11)
        self.assertTrue(document["planned_workflow"]["openubmc_kb_managed"])
        self.assertEqual(document["knowledge_mcp"]["transport"], "stdio")

    def test_tooling_report_distinguishes_required_optional_and_client_tools(self) -> None:
        required_bin = self.root / "required-bin"
        required_bin.mkdir()
        for tool in installer.REQUIRED_TOOLS:
            executable = required_bin / tool
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
        with (
            mock.patch.dict(
                installer.os.environ, {"PATH": str(required_bin)}, clear=True
            ),
            mock.patch.object(
                installer,
                "tool_search_path",
                self.original_tool_search_path,
            ),
        ):
            tooling = installer.inspect_tooling([str(required_bin)], ["codex"])
        self.assertTrue(tooling["ready"])
        self.assertTrue(all(tooling["required"].values()))
        self.assertFalse(tooling["conditional"]["sshpass"])
        self.assertFalse(tooling["recommended"]["rg"])
        self.assertFalse(tooling["clients"]["codex"])

    def test_check_json_reports_nonblocking_capability_gaps_and_next_actions(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        tooling = {
            "ready": True,
            "client_ready": False,
            "required": {tool: True for tool in installer.REQUIRED_TOOLS},
            "conditional": {"sshpass": False},
            "recommended": {"rg": False},
            "clients": {"codex": False},
        }
        output = io.StringIO()
        with (
            mock.patch.object(installer, "inspect_tooling", return_value=tooling),
            mock.patch.object(installer, "knowledge_http_health", return_value=(False, "offline")),
            redirect_stdout(output),
        ):
            result = installer.main(["check", "--home", str(self.home), "--json"])
        self.assertEqual(result, 0, output.getvalue())
        document = json.loads(output.getvalue())
        self.assertTrue(document["readiness"]["tooling"])
        self.assertFalse(document["readiness"]["password_ssh"])
        self.assertFalse(document["readiness"]["source_search"])
        self.assertFalse(document["readiness"]["client"])
        checks = {check["name"]: check for check in document["checks"]}
        for name in ("tool:sshpass", "tool:rg", "client:codex"):
            self.assertFalse(checks[name]["ok"])
            self.assertFalse(checks[name]["blocking"])
        action_codes = {action["code"] for action in document["next_actions"]}
        self.assertIn("repair_tooling", action_codes)
        repair = next(
            action
            for action in document["next_actions"]
            if action["code"] == "repair_tooling"
        )
        self.assertEqual(repair["tools"], "codex,rg,sshpass")

    def test_lifecycle_commands_emit_one_structured_json_document(self) -> None:
        self.prepare_credentials()
        commands = (
            (
                "install",
                [
                    "install",
                    "--home",
                    str(self.home),
                    "--source",
                    str(self.source),
                    "--source-mode",
                    "linked",
                    "--clients",
                    "codex",
                    "--skill-profile",
                    "target-runtime",
                    "--skip-credentials",
                    "--non-interactive",
                    "--json",
                ],
            ),
            (
                "repair",
                ["repair", "--home", str(self.home), "--non-interactive", "--json"],
            ),
            (
                "refresh",
                ["refresh", "--home", str(self.home), "--non-interactive", "--json"],
            ),
            (
                "uninstall",
                ["uninstall", "--home", str(self.home), "--non-interactive", "--json"],
            ),
        )
        with (
            mock.patch.object(
                installer,
                "resolve_tool_dirs",
                return_value=([str(self.bin_dir)], []),
            ),
            mock.patch.object(installer, "knowledge_http_health", return_value=(True, "ok")),
        ):
            for command, argv in commands:
                with self.subTest(command=command):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        result = installer.main(argv)
                    self.assertEqual(result, 0, output.getvalue())
                    document = json.loads(output.getvalue())
                    self.assertTrue(document["ok"])
                    self.assertEqual(document["command"], command)
                    self.assertIsInstance(document["messages"], list)
                    self.assertTrue(document["credentials"]["configured"])
                    if command == "uninstall":
                        self.assertFalse(document["workflow"]["installed"])
                        self.assertTrue(document["credentials"]["preserved"])
                        self.assertEqual(document["next_actions"], [])
                    else:
                        self.assertTrue(document["workflow"]["installed"])
                        self.assertEqual(
                            document["workflow"]["skill_profile"],
                            "target-runtime",
                        )
                        self.assertEqual(document["workflow"]["skill_count"], 7)

    def test_check_json_blocks_missing_supported_client_ownership_records(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        state = installer.load_state(self.home)
        state["mcp"].pop("codex")
        state["runtime_mcp"].pop("codex")
        installer.save_state(self.home, state, False)
        output = io.StringIO()

        with (
            mock.patch.object(installer, "knowledge_http_health", return_value=(False, "offline")),
            redirect_stdout(output),
        ):
            result = installer.main(["check", "--home", str(self.home), "--json"])

        self.assertEqual(result, 1)
        document = json.loads(output.getvalue())
        self.assertFalse(document["ok"])
        self.assertFalse(document["readiness"]["core"])
        self.assertFalse(document["readiness"]["mcp"])
        checks = {check["name"]: check for check in document["checks"]}
        for name in ("mcp:codex", "runtime_mcp:codex"):
            self.assertFalse(checks[name]["ok"])
            self.assertTrue(checks[name]["blocking"])
            self.assertIn("ownership missing", checks[name]["detail"])

    def test_check_json_reports_invalid_source_mode_as_core_failure(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        state = installer.load_state(self.home)
        state["source_mode"] = []
        installer.save_state(self.home, state, False)
        output = io.StringIO()

        with (
            mock.patch.object(installer, "knowledge_http_health", return_value=(False, "offline")),
            redirect_stdout(output),
        ):
            result = installer.main(["check", "--home", str(self.home), "--json"])

        self.assertEqual(result, 1)
        document = json.loads(output.getvalue())
        self.assertFalse(document["ok"])
        self.assertFalse(document["readiness"]["core"])
        self.assertEqual(document["source"]["mode"], "unknown")
        source_mode = next(
            check for check in document["checks"] if check["name"] == "source_mode"
        )
        self.assertFalse(source_mode["ok"])
        self.assertIn("unsupported source mode", source_mode["detail"])

    def test_check_json_handles_non_object_and_invalid_collection_state(self) -> None:
        state_file = installer.state_path(self.home)
        installer.atomic_write(state_file, "[]\n", 0o600)
        output = io.StringIO()
        with redirect_stdout(output):
            result = installer.main(["check", "--home", str(self.home), "--json"])
        self.assertEqual(result, 1)
        document = json.loads(output.getvalue())
        self.assertFalse(document["ok"])
        self.assertIn("must be an object", document["checks"][0]["detail"])

        self.prepare_credentials()
        state_file.unlink()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        original_state = installer.load_state(self.home)
        for field, value, check_name in (
            ("clients", [{}], "clients"),
            ("profiles", [{}], "profiles"),
            ("source_root", {}, "source_root"),
            ("mcp", [], "mcp"),
            ("mcp", {"codex": []}, "mcp"),
            ("runtime_mcp", [], "runtime_mcp"),
            ("runtime_mcp", {"codex": []}, "runtime_mcp"),
        ):
            with self.subTest(field=field):
                state = dict(original_state)
                state[field] = value
                installer.save_state(self.home, state, False)
                output = io.StringIO()
                with (
                    mock.patch.object(
                        installer,
                        "knowledge_http_health",
                        return_value=(False, "offline"),
                    ),
                    redirect_stdout(output),
                ):
                    result = installer.main(
                        ["check", "--home", str(self.home), "--json"]
                    )
                self.assertEqual(result, 1)
                document = json.loads(output.getvalue())
                invalid = [
                    check
                    for check in document["checks"]
                    if check["name"] == check_name and not check["ok"]
                ]
                self.assertTrue(invalid)

    def test_check_json_reports_runtime_mcp_and_engine_readiness_without_secrets(self) -> None:
        self.prepare_credentials()
        self.assertEqual(self.install("--clients", "codex")[0], 0)
        output = io.StringIO()
        with (
            mock.patch.object(installer, "knowledge_http_health", return_value=(False, "offline")),
            redirect_stdout(output),
        ):
            result = installer.main(["check", "--home", str(self.home), "--json"])

        self.assertEqual(result, 0)
        serialized = output.getvalue()
        document = json.loads(serialized)
        self.assertTrue(document["readiness"]["runtime"])
        self.assertTrue(document["readiness"]["mcp"])
        self.assertTrue(document["readiness"]["engine"])
        self.assertEqual(
            document["runtime"]["api_version"], "openubmc.target-runtime.v1"
        )
        self.assertRegex(
            document["runtime"]["content_digest"], r"^sha256:[0-9a-f]{64}$"
        )
        self.assertTrue(document["runtime"]["matches_installed_state"])
        self.assertTrue(document["runtime_mcp"]["healthy"])
        self.assertEqual(
            document["runtime_mcp"]["tools"],
            ["execute", "observe"],
        )
        self.assertTrue(document["engines"]["mcp"])
        self.assertTrue(document["engines"]["cli"])
        self.assertTrue(document["engines"]["one_shot"])
        for secret in ("fixture-bmc-password", "fixture-os-password"):
            self.assertNotIn(secret, serialized)

    def test_fast_dirty_check_scopes_git_commands_to_the_bundle(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch.object(installer, "run_command", side_effect=fake_run):
            self.assertFalse(
                installer.git_dirty(self.source, paths=installer.bundle_git_paths())
            )
        self.assertEqual(calls[0][3], "diff-index")
        self.assertIn("openubmc-environment-setup", calls[0])
        self.assertIn("openubmc-target-runtime", calls[0])
        self.assertEqual(calls[1][3], "ls-files")

        calls.clear()
        with mock.patch.object(installer, "run_command", side_effect=fake_run):
            self.assertFalse(
                installer.git_dirty(
                    self.source,
                    paths=installer.bundle_git_paths(
                        installer.TARGET_RUNTIME_SKILL_BUNDLE
                    ),
                )
            )
        self.assertNotIn("testing", calls[0])
        self.assertIn("openubmc-target-runtime", calls[0])


if __name__ == "__main__":
    unittest.main()
