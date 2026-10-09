from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME_ROOT))

from openubmc_target_runtime import (  # noqa: E402
    JsonRpcMcpEndpoint,
    OperationCatalog,
    OperationCatalogError,
    OperationDescriptor,
    OrchestratedMcpBackend,
    RuntimeMcpService,
    TaskContextStore,
    PendingCaseEvent,
    SQLiteRuntimeRepository,
)
from openubmc_target_runtime import mcp as runtime_mcp  # noqa: E402


class FakeTask:
    def __init__(self, task_id: str) -> None:
        self.task_id = task_id
        self.calls: list[str] = []
        self.closed = False


class FakeDebugBackend:
    def __init__(self) -> None:
        self.created: list[FakeTask] = []

    def open_task(self, task_id: str) -> FakeTask:
        task = FakeTask(task_id)
        self.created.append(task)
        return task

    @staticmethod
    def close_task(task: FakeTask) -> None:
        task.closed = True

    @staticmethod
    def maintain_task(_task: FakeTask) -> int:
        return 0

    @staticmethod
    def task_status(task: FakeTask) -> dict[str, object]:
        return {
            "task_id": task.task_id,
            "calls": list(task.calls),
            "closed": task.closed,
        }

    @staticmethod
    def debug_run(task: FakeTask, arguments, context) -> dict[str, object]:
        context.raise_if_stopped()
        task.calls.append("debug_run")
        return {
            "schema": "openubmc-debug.v1",
            "task": task.task_id,
            "root_cause": "the bounded fake diagnosis completed",
            "observed_at": "2026-08-25T00:00:00Z",
            "freshness": {"status": "fresh"},
        }

    @staticmethod
    def debug_collect(task: FakeTask, arguments, context) -> dict[str, object]:
        context.raise_if_stopped()
        task.calls.append("debug_collect")
        return {
            "schema": "openubmc-debug.v1",
            "task": task.task_id,
            "profile": arguments.get("profile", "standard"),
        }


class CapturingDomainBackend:
    def __init__(self) -> None:
        self.created: list[FakeTask] = []
        self.arguments: list[dict[str, object]] = []

    def open_task(self, task_id: str) -> FakeTask:
        task = FakeTask(task_id)
        self.created.append(task)
        return task

    @staticmethod
    def close_task(task: FakeTask) -> None:
        task.closed = True

    @staticmethod
    def maintain_task(_task: FakeTask) -> int:
        return 0

    @staticmethod
    def task_status(task: FakeTask) -> dict[str, object]:
        return {"task_id": task.task_id, "closed": task.closed}

    def debug_run(self, task, arguments, context) -> dict[str, object]:
        context.raise_if_stopped()
        captured = dict(arguments)
        self.arguments.append(captured)
        return {
            "ok": True,
            "task": task.task_id,
            "ip": captured.get("ip"),
            "targets": captured.get("targets"),
        }

    def debug_collect(self, task, arguments, context) -> dict[str, object]:
        context.raise_if_stopped()
        captured = dict(arguments)
        self.arguments.append(captured)
        return {
            "ok": True,
            "task": task.task_id,
            "ip": captured["ip"],
            "profile": captured.get("profile", "standard"),
        }

    def live_patch_run(self, task, arguments, context) -> dict[str, object]:
        context.raise_if_stopped()
        captured = dict(arguments)
        self.arguments.append(captured)
        return {
            "ok": True,
            "task": task.task_id,
            "journal": {"stage": "verified"},
        }


class RegistryClock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class CountingTaskContextStore(TaskContextStore):
    def __init__(self, root: Path, **options) -> None:
        super().__init__(root, **options)
        self.save_count = 0

    def save(self, task_id: str, context) -> None:
        self.save_count += 1
        super().save(task_id, context)


class CapturingOrchestratedMcpBackend(OrchestratedMcpBackend):
    def __init__(self, tool_backends, *, state_store: TaskContextStore) -> None:
        super().__init__(tool_backends, state_store=state_store)
        self.opened_tasks = []

    def open_task(self, task_id: str):
        task = super().open_task(task_id)
        self.opened_tasks.append(task)
        return task


class RuntimeMcpServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = FakeDebugBackend()
        self.service = RuntimeMcpService(self.backend)

    def tearDown(self) -> None:
        self.service.close()

    def test_catalog_metadata_is_derived_from_one_operation_contract_registry(self) -> None:
        contracts = runtime_mcp._OPERATION_CONTRACTS
        descriptors = self.service._test.catalog.descriptors()
        descriptor_names = {descriptor.name for descriptor in descriptors}
        active_contracts = tuple(
            contract for contract in contracts if contract.name in descriptor_names
        )

        self.assertEqual(
            tuple(descriptor.name for descriptor in descriptors),
            tuple(contract.name for contract in active_contracts),
        )
        for descriptor, contract in zip(descriptors, active_contracts, strict=True):
            self.assertEqual(descriptor.lifecycle, contract.lifecycle)
            self.assertEqual(descriptor.handler_name, contract.handler_name)
            self.assertEqual(descriptor.mutation, contract.mutation)
        self.assertEqual(
            runtime_mcp._DOMAIN_TO_TOOL,
            {
                contract.domain: contract.name
                for contract in contracts
                if contract.domain and contract.workflow_entry
            },
        )

    def test_only_semantic_agent_tools_are_exposed(self) -> None:
        definitions = self.service.tool_definitions()
        names = [definition["name"] for definition in definitions]

        self.assertEqual(names, ["observe", "execute"])
        rendered = json.dumps(definitions, sort_keys=True)
        for forbidden in (
            "debug_run",
            "debug_collect",
            "phase_record",
            "workflow.advance",
            "workflow.next",
            "remote_command",
            "shell",
            "ssh_command",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_agent_catalog_excludes_retired_compatibility_writers(self) -> None:
        self.assertEqual(self.service.interface_catalog.names(), ("observe", "execute"))

    def test_catalog_is_the_source_for_listing_and_dispatch(self) -> None:
        self.assertEqual(
            self.service._test.catalog.names(),
            (
                "debug_run",
                "debug_collect",
                "case_read",
                "evidence_attach",
                "evidence_query",
                "evidence_read",
                "case_replay_export",
                "case_replay_run",
                "session_outcome_record",
                "session_outcome_summary",
                "session_outcome_transition",
                "session_outcome_promote",
                "case_close",
                "case_forget",
                "runtime_status",
            ),
        )
        self.assertEqual(
            self.service.interface_catalog.names(),
            ("observe", "execute"),
        )
        self.assertEqual(
            self.service.tool_definitions(),
            self.service.interface_catalog.tool_definitions(),
        )
        debug = self.service._test.catalog.require("debug_run")
        self.assertEqual(debug.handler_name, "debug_run")
        self.assertEqual(debug.lifecycle, "invoke")
        status = self.service._test.catalog.require("runtime_status")
        self.assertIsNone(status.handler_name)
        self.assertEqual(status.lifecycle, "status")

    def test_retired_writer_names_cannot_be_dispatched(self) -> None:
        for name in ("phase_record", "workflow.advance", "workflow.next"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    ValueError, "unknown openUBMC domain tool"
                ):
                    self.service.call_tool(
                        name,
                        {},
                        task_id="retired-writer-task",
                        operation_id=f"retired-writer-{name}",
                    )

    def test_catalog_rejects_duplicate_or_unbound_operations(self) -> None:
        descriptor = OperationDescriptor(
            name="debug_run",
            description="debug",
            input_schema={"type": "object"},
            handler_name="debug_run",
        )
        with self.assertRaisesRegex(OperationCatalogError, "duplicate"):
            OperationCatalog((descriptor, descriptor), backend=self.backend)
        with self.assertRaisesRegex(OperationCatalogError, "unavailable"):
            OperationCatalog(
                (
                    OperationDescriptor(
                        name="missing",
                        description="missing",
                        input_schema={"type": "object"},
                        handler_name="missing",
                    ),
                ),
                backend=self.backend,
            )

        with self.assertRaisesRegex(OperationCatalogError, "schema"):
            OperationDescriptor(
                name="invalid-schema",
                description="invalid",
                input_schema={
                    "type": "object",
                    "properties": {"value": {"type": "not-a-json-type"}},
                },
            )

    def test_catalog_validates_arguments_against_the_exposed_schema(self) -> None:
        with self.assertRaisesRegex(ValueError, "unexpected"):
            self.service.call_tool(
                "case_read",
                {"case_id": "case-a", "unexpected": True},
                task_id="schema-task",
                operation_id="schema-operation",
            )

        with self.assertRaisesRegex(ValueError, "deadline"):
            self.service.call_tool(
                "debug_run",
                {"ip": "target.example", "deadline": "slow"},
                task_id="schema-task",
                operation_id="schema-operation-two",
            )

    def test_legacy_underscore_and_live_patch_aliases_are_canonicalized(self) -> None:
        backend = CapturingDomainBackend()
        service = RuntimeMcpService(backend)
        try:
            result = service.call_tool(
                "live_patch_run",
                {
                    "ip": "target.example",
                    "intent": "live_patch",
                    "action": "live_patch",
                    "local_path": "/tmp/unit.lua",
                    "remote_path": "/opt/bmc/apps/demo/unit.lua",
                },
                task_id="alias-task",
                operation_id="alias-operation",
            )
            case = service.call_tool(
                "case_read",
                {"case_id": result.envelope["case_id"]},
                task_id="alias-task",
                operation_id="alias-case-read",
            )
        finally:
            service.close()

        self.assertTrue(result["ok"])
        self.assertEqual(backend.arguments[0]["action"], "apply")
        self.assertEqual(case["intent"], "live-patch")

    def test_calls_reuse_one_task_and_isolate_different_codex_tasks(self) -> None:
        first = self.service.call_tool(
            "debug_run",
            {"ip": "target.example", "deadline": 2},
            task_id="codex-task-a",
            operation_id="1",
        )
        follow_up = self.service.call_tool(
            "debug_collect",
            {"ip": "target.example", "profile": "standard", "deadline": 2},
            task_id="codex-task-a",
            operation_id="2",
        )
        other = self.service.call_tool(
            "debug_run",
            {"ip": "other.example", "deadline": 2},
            task_id="codex-task-b",
            operation_id="3",
        )

        self.assertEqual(first["task"], follow_up["task"])
        self.assertNotEqual(first["task"], other["task"])
        self.assertEqual(len(self.backend.created), 2)
        status = self.service.call_tool(
            "runtime_status",
            {},
            task_id="codex-task-a",
            operation_id="4",
        )
        self.assertEqual(status["task_count"], 2)
        task_a = next(
            task for task in status["tasks"] if task["task_id"] == "codex-task-a"
        )
        self.assertEqual(task_a["resource"]["calls"], ["debug_run", "debug_collect"])

    def test_operator_status_derives_bounded_current_run_evidence_from_the_ledger(
        self,
    ) -> None:
        operator = RuntimeMcpService(self.backend, interface_profile="operator")
        try:
            repository = operator._test.context_runtime.repository
            run_id = "run-operator-projection"
            artifact = {
                "handle": "artifact://firmware/example",
                "digest": "sha256:" + "a" * 64,
                "kind": "openubmc-hpm",
                "size": 4096,
                "target": "target-a",
                "run_id": run_id,
            }
            repository.commit(
                run_id,
                expected_revision=0,
                events=(
                    PendingCaseEvent(
                        "CaseOpened",
                        {
                            "intent": "diagnose-and-fix",
                            "targets": [
                                {
                                    "target_id": "target-a",
                                    "epochs": {"target_epoch": 7},
                                }
                            ],
                        },
                        "start",
                    ),
                    PendingCaseEvent(
                        "OperationAccepted",
                        {
                            "operation": "upgrade_run",
                            "inputs": {"artifact_ref": artifact},
                            "workflow_cycle_id": "cycle-1",
                            "workflow_step_id": "upgrade",
                            "workflow_step_kind": "operation",
                            "target_id": "target-a",
                            "target_version": 1,
                        },
                        "upgrade-1",
                    ),
                    PendingCaseEvent(
                        "OperationProgressed",
                        {"status": "failed", "target_epoch": 7},
                        "upgrade-1",
                    ),
                    PendingCaseEvent(
                        "OperationAccepted",
                        {
                            "operation": "upgrade_run",
                            "inputs": {"artifact_ref": artifact},
                            "workflow_cycle_id": "cycle-1",
                            "workflow_step_id": "upgrade",
                            "workflow_step_kind": "operation",
                            "target_id": "target-a",
                            "target_version": 1,
                        },
                        "upgrade-2",
                    ),
                    PendingCaseEvent(
                        "RunDecisionCommitted",
                        {
                            "schema": (
                                "openubmc.target-runtime.v1/run-decision-v1"
                            ),
                            "version": 1,
                            "turn": {
                                "turn_id": "turn-upgrade-2",
                                "state": "incident",
                            }
                        },
                        "decision-upgrade-2",
                    ),
                    PendingCaseEvent(
                        "RunIncidentRaised",
                        {
                            "incident": {
                                "incident_id": "incident-upgrade",
                                "code": "mutation_outcome_unknown",
                                "effect_id": "upgrade-2",
                                "message": "upgrade result is unknown",
                            }
                        },
                        "incident",
                    ),
                ),
            )
            repository.bind_task("codex-task-a", run_id)
            for index in range(20):
                repository.commit(
                    f"run-newer-{index}",
                    expected_revision=0,
                    events=(
                        PendingCaseEvent(
                            "CaseOpened",
                            {"intent": "noise", "targets": []},
                            f"noise-{index}",
                        ),
                    ),
                )

            status = operator.call_tool(
                "runtime_status",
                {},
                task_id="codex-task-a",
                operation_id="operator-status",
            )
        finally:
            operator.close()

        projection = status["operator_projection"]
        self.assertEqual(projection["source"], "runtime-ledger")
        self.assertFalse(projection["state_store"])
        self.assertEqual(projection["current_run"]["run_id"], run_id)
        self.assertEqual(projection["current_run"]["run_state"], "incident")
        self.assertEqual(projection["current_run"]["turn_state"], "incident")
        self.assertEqual(
            projection["current_run"]["current_turn"],
            {"turn_id": "turn-upgrade-2", "state": "incident"},
        )
        self.assertEqual(
            projection["current_run"]["interaction_classification"], "incident"
        )
        self.assertEqual(projection["current_run"]["retry_count"], 1)
        self.assertEqual(
            projection["current_run"]["recovery"]["effect_id"], "upgrade-2"
        )
        self.assertEqual(projection["current_run"]["target_epoch"], 7)
        self.assertEqual(
            projection["current_run"]["artifact_outcome_linkage"][
                "artifact_refs"
            ],
            [artifact],
        )
        self.assertIsNone(
            projection["current_run"]["artifact_outcome_linkage"]["outcome"]
        )
        self.assertLessEqual(len(projection["runs"]), 16)

    def test_operator_status_without_task_binding_has_no_current_run(self) -> None:
        operator = RuntimeMcpService(self.backend, interface_profile="operator")
        try:
            repository = operator._test.context_runtime.repository
            repository.commit(
                "run-operator-overview",
                expected_revision=0,
                events=(
                    PendingCaseEvent(
                        "CaseOpened",
                        {"intent": "overview", "targets": []},
                        "start",
                    ),
                ),
            )

            status = operator.call_tool(
                "runtime_status",
                {},
                task_id="unbound-operator-task",
                operation_id="operator-overview",
            )
        finally:
            operator.close()

        projection = status["operator_projection"]
        self.assertIsNone(projection["current_run"])
        self.assertEqual(
            [run["run_id"] for run in projection["runs"]],
            ["run-operator-overview"],
        )

    def test_task_completion_closes_owned_runtime(self) -> None:
        self.service.call_tool(
            "debug_run",
            {"ip": "target.example", "deadline": 2},
            task_id="codex-task-a",
            operation_id="1",
        )

        self.assertTrue(self.service.complete_task("codex-task-a"))
        self.assertTrue(self.backend.created[0].closed)


class PersistentTaskContextTests(unittest.TestCase):
    @staticmethod
    def service_for(
        root: Path,
        domain: CapturingDomainBackend,
        **registry_options,
    ) -> RuntimeMcpService:
        backend = OrchestratedMcpBackend(
            {
                "debug_run": domain,
                "debug_collect": domain,
            },
            state_store=TaskContextStore(root),
        )
        return RuntimeMcpService(backend, **registry_options)

    def test_public_execute_redacts_worker_credential_echo_from_response_and_events(self) -> None:
        secret = "synthetic-worker-password-9471"

        class EchoingBackend(FakeDebugBackend):
            @staticmethod
            def debug_run(task, arguments, context):
                result = FakeDebugBackend.debug_run(task, arguments, context)
                result["root_cause"] = (
                    "remote echoed "
                    + arguments["_credential_values"]["OPENUBMC_SSH_PASSWORD"]
                )
                return result

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            backend = OrchestratedMcpBackend(
                {"debug_run": EchoingBackend()}, state_store=TaskContextStore(root)
            )
            service = RuntimeMcpService(
                backend, context_repository=SQLiteRuntimeRepository(root / "runtime.sqlite3")
            )
            try:
                with mock.patch(
                    "openubmc_target_runtime.mcp.load_selected_credentials_file",
                    return_value={"OPENUBMC_SSH_PASSWORD": secret},
                ):
                    response = service.call_exposed_tool(
                        "execute",
                        {
                            "kind": "start", "target": "192.0.2.10",
                            "intent": "diagnose-and-fix",
                            "delivery_strategy": "source-only",
                        },
                        task_id="synthetic-secret-task",
                        operation_id="synthetic-start",
                    )
            finally:
                service.close()
            persisted = b"".join(path.read_bytes() for path in root.rglob("*") if path.is_file())
        self.assertNotIn(secret, json.dumps(response, sort_keys=True))
        self.assertNotIn(secret.encode(), persisted)

    def test_process_restart_restores_context_but_rebuilds_domain_resources(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first_domain = CapturingDomainBackend()
            first_service = self.service_for(root, first_domain)
            first_service.call_tool(
                "debug_run",
                {
                    "ip": "192.0.2.40",
                    "intent": "diagnosis-only",
                    "final_purpose": "定位风扇状态差异",
                    "allow_insecure_tls": True,
                    "ssh_password": "must-not-be-persisted",
                    "deadline": 2,
                },
                task_id="stable-codex-task",
                operation_id="first",
            )
            first_resource = first_domain.created[0]
            first_service.close()

            self.assertTrue(first_resource.closed)
            persisted = "".join(
                path.read_text(encoding="utf-8")
                for path in root.glob("*.json")
            )
            self.assertNotIn("must-not-be-persisted", persisted)
            self.assertIn("authorization_policy", persisted)
            second_domain = CapturingDomainBackend()
            second_service = self.service_for(root, second_domain)
            try:
                follow_up = second_service.call_tool(
                    "debug_collect",
                    {"profile": "object-alarm", "deadline": 2},
                    task_id="stable-codex-task",
                    operation_id="second",
                )
                status = second_service.call_tool(
                    "runtime_status",
                    {},
                    task_id="stable-codex-task",
                    operation_id="status",
                )
            finally:
                second_service.close()

        self.assertEqual(follow_up["ip"], "192.0.2.40")
        self.assertEqual(len(second_domain.created), 1)
        self.assertIsNot(second_domain.created[0], first_resource)
        task_status = status["tasks"][0]["resource"]
        self.assertTrue(task_status["task_context"]["recovered"])
        self.assertFalse(task_status["task_context"]["connections_recovered"])
        self.assertFalse(task_status["task_context"]["evidence_results_recovered"])
        self.assertTrue(
            task_status["orchestration"]["intent"]["authorization"][
                "allow_insecure_tls"
            ]
        )

    def test_authorization_policy_restore_is_legacy_compatible_and_fail_closed(self) -> None:
        for mode in ("legacy", "tampered"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                store = TaskContextStore(root)
                domain = CapturingDomainBackend()
                first = self.service_for(root, domain)
                try:
                    first.call_tool(
                        "debug_run",
                        {
                            "ip": "192.0.2.42",
                            "intent": "diagnosis-only",
                            "allow_insecure_tls": True,
                            "deadline": 2,
                        },
                        task_id="policy-restore-task",
                        operation_id="policy-first",
                    )
                finally:
                    first.close()
                persisted = store.load("policy-restore-task")
                assert persisted is not None
                orchestration = persisted["orchestration"]
                if mode == "legacy":
                    orchestration.pop("authorization_policy")
                else:
                    orchestration["authorization_policy"]["allowed_actions"] = [
                        "upgrade"
                    ]
                store.save("policy-restore-task", persisted)

                backend = OrchestratedMcpBackend(
                    {
                        "debug_run": CapturingDomainBackend(),
                        "debug_collect": CapturingDomainBackend(),
                    },
                    state_store=store,
                )
                task = backend.open_task("policy-restore-task")
                try:
                    status = backend.task_status(task)
                finally:
                    backend.close_task(task)

                if mode == "legacy":
                    self.assertTrue(
                        status["orchestration"]["intent"]["authorization"][
                            "allow_insecure_tls"
                        ]
                    )
                    self.assertTrue(status["task_context"]["recovered"])
                else:
                    self.assertIsNone(status["orchestration"])
                    self.assertFalse(status["task_context"]["recovered"])
                    self.assertIn(
                        "ValueError",
                        status["task_context"]["last_error"],
                    )
                    self.assertIsNone(store.load("policy-restore-task"))

    def test_target_replacement_reuses_credentials_in_memory_without_persisting_them(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            domain = CapturingDomainBackend()
            service = self.service_for(Path(raw), domain)
            try:
                first = service.call_tool(
                    "debug_run",
                    {
                        "ip": "192.0.2.50",
                        "ssh_port": 2222,
                        "telnet_port": 2323,
                        "ssh_user": "root",
                        "ssh_password": "shared-secret",
                        "telnet_user": "root",
                        "telnet_password": "shared-secret",
                        "ssh_host_key_policy": "strict",
                    },
                    task_id="replace-target",
                    operation_id="target-a",
                )
                case_id = first.envelope["case_id"]
                service.call_tool(
                    "debug_run",
                    {"case_id": case_id, "ip": "192.0.2.51"},
                    task_id="replace-target",
                    operation_id="target-b",
                )
                case = service.call_tool(
                    "case_read",
                    {"case_id": case_id},
                    task_id="replace-target",
                    operation_id="read-target-b",
                )
            finally:
                service.close()

        second = domain.arguments[-1]
        self.assertEqual(second["ip"], "192.0.2.51")
        self.assertEqual(second["ssh_port"], 22)
        self.assertEqual(second["telnet_port"], 23)
        self.assertEqual(second["ssh_user"], "root")
        self.assertEqual(second["ssh_password"], "shared-secret")
        self.assertEqual(second["telnet_password"], "shared-secret")
        self.assertEqual(second["ssh_host_key_policy"], "strict")
        self.assertNotIn("ssh_port", case["workflow_inputs"])
        self.assertNotIn("telnet_port", case["workflow_inputs"])
        self.assertNotIn("ssh_password", case["workflow_inputs"])
        self.assertNotIn("telnet_password", case["workflow_inputs"])
        self.assertNotIn("shared-secret", json.dumps(case, sort_keys=True))
        self.assertEqual(case["target_version"], 2)

    def test_absolute_runtime_lifetime_rehydrates_a_recent_long_running_task(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            clock = RegistryClock()
            domain = CapturingDomainBackend()
            service = self.service_for(
                Path(raw),
                domain,
                clock=clock,
                idle_timeout_seconds=1000,
                max_lifetime_seconds=10,
            )
            try:
                service.call_tool(
                    "debug_run",
                    {"ip": "192.0.2.41", "deadline": 2},
                    task_id="long-running-task",
                    operation_id="first",
                )
                clock.advance(11)
                result = service.call_tool(
                    "debug_collect",
                    {"profile": "standard", "deadline": 2},
                    task_id="long-running-task",
                    operation_id="second",
                )
            finally:
                service.close()

        self.assertEqual(result["ip"], "192.0.2.41")
        self.assertEqual(len(domain.created), 2)
        self.assertTrue(domain.created[0].closed)

    def test_multi_target_context_restores_each_target_selector(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first_domain = CapturingDomainBackend()
            first_service = self.service_for(root, first_domain)
            first_service.call_tool(
                "debug_run",
                {
                    "targets": [
                        {
                            "ip": "192.0.2.50",
                            "target_id": "reference-a",
                            "role": "reference",
                        },
                        {
                            "ip": "192.0.2.51",
                            "target_id": "candidate-b",
                            "role": "candidate",
                        },
                    ],
                    "deadline": 2,
                },
                task_id="comparison-task",
                operation_id="first",
            )
            first_service.close()

            second_domain = CapturingDomainBackend()
            second_service = self.service_for(root, second_domain)
            try:
                selected = second_service.call_tool(
                    "debug_collect",
                    {
                        "target_id": "candidate-b",
                        "profile": "object-alarm",
                        "deadline": 2,
                    },
                    task_id="comparison-task",
                    operation_id="second",
                )
            finally:
                second_service.close()

        self.assertEqual(selected["ip"], "192.0.2.51")

    def test_explicit_task_completion_retains_the_durable_context(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            domain = CapturingDomainBackend()
            service = self.service_for(root, domain)
            service.call_tool(
                "debug_run",
                {"ip": "192.0.2.42", "deadline": 2},
                task_id="completed-task",
                operation_id="first",
            )

            self.assertTrue(service.complete_task("completed-task"))
            self.assertIsNotNone(TaskContextStore(root).load("completed-task"))
            service.close()

    def test_explicit_completion_blocks_late_workflow_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            domain = CapturingDomainBackend()
            backend = CapturingOrchestratedMcpBackend(
                {
                    "debug_run": domain,
                    "debug_collect": domain,
                },
                state_store=TaskContextStore(root),
            )
            service = RuntimeMcpService(backend)
            service.call_tool(
                "debug_run",
                {"ip": "192.0.2.45", "deadline": 2},
                task_id="completed-race-task",
                operation_id="first",
            )
            task = backend.opened_tasks[0]
            started = threading.Event()
            release = threading.Event()

            def record_late_summary() -> None:
                started.set()
                release.wait(timeout=2)
                task.record_workflow_summary(
                    "late-summary",
                    {
                        "completed": False,
                        "partial": True,
                        "next_action": "retry",
                        "phase_states": {},
                    },
                )

            worker = threading.Thread(target=record_late_summary)
            worker.start()
            self.assertTrue(started.wait(timeout=2))
            self.assertTrue(service.complete_task("completed-race-task"))
            release.set()
            worker.join(timeout=2)

            self.assertFalse(worker.is_alive())
            persisted = TaskContextStore(root).load("completed-race-task")
            self.assertIsNotNone(persisted)
            self.assertEqual(persisted.get("workflow_summaries", []), [])
            service.close()

    def test_identical_follow_up_calls_do_not_rewrite_unchanged_context(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            domain = CapturingDomainBackend()
            store = CountingTaskContextStore(Path(raw))
            service = RuntimeMcpService(
                OrchestratedMcpBackend(
                    {
                        "debug_run": domain,
                        "debug_collect": domain,
                    },
                    state_store=store,
                )
            )
            try:
                service.call_tool(
                    "debug_run",
                    {"ip": "192.0.2.43", "deadline": 2},
                    task_id="low-write-task",
                    operation_id="first",
                )
                for operation_id in ("second", "third"):
                    service.call_tool(
                        "debug_collect",
                        {"profile": "object-alarm", "deadline": 2},
                        task_id="low-write-task",
                        operation_id=operation_id,
                    )
            finally:
                service.close()

        self.assertEqual(store.save_count, 1)

    def test_failed_persistence_invalidates_old_target_without_retry_loop(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            domain = CapturingDomainBackend()
            store = CountingTaskContextStore(root, max_state_bytes=1024)
            service = RuntimeMcpService(
                OrchestratedMcpBackend(
                    {
                        "debug_run": domain,
                        "debug_collect": domain,
                    },
                    state_store=store,
                )
            )
            try:
                service.call_tool(
                    "debug_run",
                    {"ip": "192.0.2.46", "deadline": 2},
                    task_id="oversized-switch-task",
                    operation_id="first",
                )
                switched = service.call_tool(
                    "debug_run",
                    {
                        "ip": "192.0.2.47",
                        "final_purpose": "x" * 4096,
                        "deadline": 2,
                    },
                    task_id="oversized-switch-task",
                    operation_id="second",
                )
                follow_up = service.call_tool(
                    "debug_collect",
                    {"profile": "standard", "deadline": 2},
                    task_id="oversized-switch-task",
                    operation_id="third",
                )
            finally:
                service.close()
            restored = TaskContextStore(root).load("oversized-switch-task")

        self.assertEqual(switched["ip"], "192.0.2.47")
        self.assertEqual(follow_up["ip"], "192.0.2.47")
        self.assertEqual(store.save_count, 2)
        self.assertIsNone(restored)

    def test_reconnect_restores_only_mutation_journal_identity_not_cached_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first_domain = CapturingDomainBackend()
            first_service = RuntimeMcpService(
                OrchestratedMcpBackend(
                    {
                        "debug_collect": first_domain,
                        "live_patch_run": first_domain,
                    },
                    state_store=TaskContextStore(root),
                )
            )
            first_service.call_tool(
                "live_patch_run",
                {
                    "ip": "192.0.2.44",
                    "intent": "live-patch",
                    "local_path": "/tmp/unit.lua",
                    "remote_path": "/opt/bmc/apps/unit.lua",
                    "deadline": 2,
                },
                task_id="mutation-task",
                operation_id="first",
            )
            first_service.close()

            second_domain = CapturingDomainBackend()
            second_service = RuntimeMcpService(
                OrchestratedMcpBackend(
                    {
                        "debug_collect": second_domain,
                        "live_patch_run": second_domain,
                    },
                    state_store=TaskContextStore(root),
                )
            )
            try:
                second_service.call_tool(
                    "debug_collect",
                    {"profile": "standard", "deadline": 2},
                    task_id="mutation-task",
                    operation_id="second",
                )
                status = second_service.call_tool(
                    "runtime_status",
                    {},
                    task_id="mutation-task",
                    operation_id="status",
                )
            finally:
                second_service.close()

        resource = status["tasks"][0]["resource"]
        self.assertEqual(
            resource["task_context"]["mutation_journal_identity_count"],
            1,
        )
        self.assertEqual(resource["cached_mutation_count"], 0)


class JsonRpcEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = FakeDebugBackend()
        self.service = RuntimeMcpService(self.backend)
        self.endpoint = JsonRpcMcpEndpoint(
            self.service,
            session_task_id="stdio-session-task",
        )

    def tearDown(self) -> None:
        self.service.close()

    def test_unknown_protocol_negotiates_a_supported_version_without_domain_calls(self) -> None:
        for version in ("unsupported-not-a-version", "2026-07-28"):
            with self.subTest(version=version):
                response = self.endpoint.handle({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": version},
                })
                self.assertEqual(response["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(self.backend.created, [])

    def test_model_visible_tools_reject_nested_secret_values_without_echoing_them(self) -> None:
        secret = "fixture-secret-that-must-not-enter-rollout-output"
        response = self.endpoint.handle(
            {
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {
                    "name": "execute",
                    "arguments": {
                        "kind": "start",
                        "target": "target.example",
                        "intent": "diagnosis-only",
                        "entry_operation": "debug_run",
                        "entry_arguments": {"ssh_password": secret},
                    },
                },
            }
        )

        encoded = json.dumps(response, sort_keys=True)
        self.assertTrue(response["result"]["isError"])
        self.assertIn("secret_material_rejected", encoded)
        self.assertNotIn(secret, encoded)
        self.assertEqual(self.backend.created, [])
        self.assertIsNone(
            self.service._test.context_runtime.repository.case_for_task(
                "stdio-session-task"
            )
        )

    def test_initialize_rejects_malformed_version_parameters(self) -> None:
        for params in ([], "invalid", {"protocolVersion": None},
                       {"protocolVersion": 20250618}, {"protocolVersion": ""}):
            with self.subTest(params=params):
                response = self.endpoint.handle({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params,
                })
                self.assertEqual(response.get("error", {}).get("code"), -32602)
        self.assertEqual(self.backend.created, [])

    def test_legacy_initialize_without_version_uses_supported_default(self) -> None:
        response = self.endpoint.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(response["result"]["protocolVersion"], "2025-06-18")

    def test_initialize_list_and_call_follow_mcp_json_rpc_shape(self) -> None:
        initialized = self.endpoint.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            }
        )
        self.assertEqual(initialized["result"]["protocolVersion"], "2025-06-18")
        self.assertIn("tools", initialized["result"]["capabilities"])

        listed = self.endpoint.handle(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        )
        self.assertEqual(
            [tool["name"] for tool in listed["result"]["tools"]],
            ["observe", "execute"],
        )

        called = self.endpoint.handle(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "execute",
                    "arguments": {
                        "kind": "start",
                        "target": "target.example",
                        "intent": "diagnosis-only",
                        "entry_operation": "debug_run",
                    },
                    "_meta": {"codex/taskId": "codex-task-a"},
                },
            }
        )
        self.assertFalse(called["result"]["isError"])
        turn = called["result"]["structuredContent"]
        self.assertTrue(turn["run_id"])
        self.assertEqual(turn["state"], "waiting_response")
        self.assertEqual(turn["gate"]["name"], "diagnosis.acceptance")
        self.assertEqual(
            self.service._test.context_runtime.repository.case_for_task(
                "codex-task-a"
            ),
            turn["run_id"],
        )
        summary = called["result"]["content"][0]["text"]
        self.assertIn("diagnosis.acceptance", summary)
        self.assertIn("DiagnosticReceipt status=complete", summary)
        self.assertIn("result[diagnosis]", summary)
        self.assertEqual(
            turn["diagnostic_receipt"]["results"][0]["value"]["root_cause"],
            "the bounded fake diagnosis completed",
        )
        self.assertNotIn("bounded fake diagnosis completed", summary)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(summary)

    def test_unknown_methods_and_tools_fail_without_remote_fallback(self) -> None:
        unknown_method = self.endpoint.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "ssh/exec", "params": {}}
        )
        self.assertEqual(unknown_method["error"]["code"], -32601)

        unknown_tool = self.endpoint.handle(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "remote_command", "arguments": {}},
            }
        )
        self.assertTrue(unknown_tool["result"]["isError"])
        self.assertIn("下一步", unknown_tool["result"]["content"][0]["text"])
        self.assertEqual(self.backend.created, [])

    def test_execute_gate_text_preserves_the_latest_diagnostic_receipt(self) -> None:
        response = self.endpoint.handle(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "execute",
                    "arguments": {
                        "kind": "start",
                        "target": "target.example",
                        "intent": "diagnose-and-fix",
                        "delivery_strategy": "source-only",
                        "entry_operation": "debug_run",
                    },
                    "_meta": {"codex/taskId": "diagnostic-gate-task"},
                },
            }
        )

        turn = response["result"]["structuredContent"]
        self.assertEqual(turn["state"], "waiting_response")
        self.assertIsNotNone(turn["gate"])
        self.assertIsNotNone(turn["diagnostic_receipt"])
        summary = response["result"]["content"][0]["text"]
        self.assertIn("phase diagnosis.acceptance", summary)
        self.assertIn(f"run_id={turn['run_id']}", summary)
        self.assertIn(f"gate_id={turn['gate']['gate_id']}", summary)
        self.assertIn(f"gate_version={turn['gate']['gate_version']}", summary)
        self.assertIn(f"schema_digest={turn['gate']['schema_digest']}", summary)
        self.assertIn("DiagnosticReceipt status=complete", summary)
        self.assertEqual(
            turn["diagnostic_receipt"]["results"][0]["value"]["root_cause"],
            "the bounded fake diagnosis completed",
        )
        self.assertNotIn("bounded fake diagnosis completed", summary)

    def test_execute_gate_text_preserves_binding_without_a_diagnostic_receipt(
        self,
    ) -> None:
        response = self.endpoint._tool_result(
            {
                "state": "waiting_response",
                "run_id": "run-actionable",
                "gate": {
                    "kind": "phase",
                    "name": "developer.change",
                    "gate_id": "gate-actionable",
                    "gate_version": 3,
                    "schema_digest": "sha256:" + "a" * 64,
                },
            },
            tool_name="execute",
        )

        summary = response["content"][0]["text"]
        self.assertIn("run_id=run-actionable", summary)
        self.assertIn("gate_id=gate-actionable", summary)
        self.assertIn("gate_version=3", summary)
        self.assertIn("schema_digest=sha256:" + "a" * 64, summary)

    def test_execute_text_distinguishes_source_and_visible_receipt_coverage(
        self,
    ) -> None:
        receipt = {
            "status": "complete",
            "coverage": {
                "requested": 64,
                "evaluable": 64,
                "unavailable": 0,
                "not_checked": 0,
                "complete": True,
                "visible_evaluable": 32,
                "visible_unavailable": 0,
                "visible_not_checked": 32,
                "compacted": 64,
            },
            "results": [
                {
                    "result_id": f"result-{index}",
                    "status": "available",
                    "kind": "bounded-logs",
                    "request": f"request-{index}",
                    "value": {"summary": [{"path": "$.value", "value": "x" * 512}]},
                }
                for index in range(32)
            ],
            "freshness": {"status": "fresh"},
            "capabilities": {"ssh": "available"},
            "truncated": False,
            "content_complete": True,
            "evidence": [{"evidence_id": "evidence-citable"}],
            "gaps": ["diagnostic_receipt_compacted", "critical-gap"],
        }

        response = self.endpoint._tool_result(
            {
                "state": "completed",
                "diagnostic_receipt": receipt,
            },
            tool_name="execute",
        )

        summary = response["content"][0]["text"]
        self.assertLessEqual(len(summary.encode("utf-8")), 4096)
        self.assertIn("source_coverage=64/64", summary)
        self.assertIn("visible=32/64", summary)
        self.assertIn("agent_acceptance=partial", summary)
        self.assertIn("results_shown=8/32", summary)
        self.assertIn("gaps: diagnostic_receipt_compacted, critical-gap", summary)
        self.assertIn("evidence_ids: evidence-citable", summary)

    def test_execute_text_does_not_treat_projection_compaction_as_incomplete_source(self) -> None:
        response = self.endpoint._tool_result(
            {
                "state": "completed",
                "diagnostic_receipt": {
                    "status": "complete",
                    "coverage": {
                        "requested": 7,
                        "evaluable": 7,
                        "unavailable": 0,
                        "not_checked": 0,
                        "complete": True,
                        "visible_evaluable": 7,
                        "visible_unavailable": 0,
                        "visible_not_checked": 0,
                        "compacted": 7,
                    },
                    "results": [],
                    "freshness": {"status": "fresh"},
                    "truncated": False,
                    "content_complete": True,
                    "gaps": ["diagnostic_receipt_compacted"],
                },
            },
            tool_name="execute",
        )

        summary = response["content"][0]["text"]
        self.assertIn("DiagnosticReceipt status=complete", summary)
        self.assertIn("agent_acceptance=complete", summary)

    def test_related_domain_results_share_concise_chinese_text_content(self) -> None:
        cases = (
            (
                "log_bundle_collect",
                {
                    "ok": True,
                    "result": {
                        "bundle_root": "/tmp/bundle",
                        "next_step": "分析日志",
                    },
                },
                "日志包采集已完成",
            ),
            (
                "live_patch_run",
                {"journal": {"stage": "verified"}},
                "Live Patch已完成",
            ),
            (
                "upgrade_run",
                {"journal": {"stage": "verified"}},
                "固件升级已完成",
            ),
            (
                "runtime_status",
                {
                    "task_count": 1,
                    "persistent_task_contexts": {"entry_count": 2},
                },
                "磁盘保留 2 个可恢复上下文",
            ),
        )

        for tool_name, value, expected in cases:
            with self.subTest(tool=tool_name):
                result = self.endpoint._tool_result(value, tool_name=tool_name)
                self.assertIn(expected, result["content"][0]["text"])
                self.assertEqual(result["structuredContent"], value)

    def test_mutation_summary_does_not_report_non_success_stage_as_completed(self) -> None:
        cases = (
            ("upgrade_run", "replan_required", "需要重新规划"),
            ("live_patch_run", "rollback_verified", "已回滚"),
            ("upgrade_run", "verification_failed_terminal", "验证失败"),
        )

        for tool_name, stage, expected in cases:
            with self.subTest(tool=tool_name, stage=stage):
                result = self.endpoint._tool_result(
                    {"journal": {"stage": stage}},
                    tool_name=tool_name,
                )
                summary = result["content"][0]["text"]
                self.assertNotIn(f"{self.endpoint._tool_label(tool_name)}已完成", summary)
                self.assertIn(expected, summary)
                self.assertIn("下一步", summary)

    def test_task_completion_notification_uses_internal_session_identity(self) -> None:
        self.endpoint.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "observe",
                    "arguments": {
                        "target": "target.example",
                        "selectors": [
                            {"kind": "capability", "names": ["ssh"]}
                        ],
                    },
                },
            }
        )
        response = self.endpoint.handle(
            {
                "jsonrpc": "2.0",
                "method": "notifications/openubmc-task-complete",
                "params": {},
            }
        )

        self.assertIsNone(response)
        self.assertTrue(self.backend.created[0].closed)


if __name__ == "__main__":
    unittest.main()
