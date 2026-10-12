from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "plugins/openubmc/skills/openubmc-debug/scripts"))
sys.path.insert(0, str(ROOT / "scripts/property"))
import mdb_property_backend as backend
from test_mdb_property_mutation import contract as plain_contract

runtime = backend._runtime


class Transport:
    def __init__(self):
        self.value = 30
        self.commands = []
        self.writes = 0
        self.override = False
        self.access = "readwrite"
        self.owner = ":1.2"
        self.generation = "generation-1"
        self.fail_write = False
        self.on_write = None
        self.store = None

    def open_master(self, *, target, credentials):
        return object()

    def close_master(self, _master):
        pass

    def channel_lost_master(self, _master, _result):
        return False

    def run_channel(self, _master, command, **kwargs):
        self.commands.append(shlex.split(command))
        args = self.commands[-1]
        if args == ["cat", "/etc/machine-id"]:
            stdout = "a" * 32
        elif args == ["cat", "/proc/sys/kernel/random/boot_id"]:
            stdout = "12345678-1234-1234-1234-123456789abc"
        elif args[:2] == ["mdbctl", "getprop"]:
            stdout = str(self.value)
        elif "GetNameOwner" in args:
            stdout = "s " + json.dumps(self.owner)
        elif "introspect" in args:
            stdout = f'<node><interface name="bmc.example.Configuration"><property name="Interval" type="u" access="{self.access}"/></interface></node>'
        elif "get-property" in args:
            prop = args[-1]
            stdout = {"Interval": f"u {self.value}", "Version": 's "fixture-v1"',
                "Generation": "s " + json.dumps(self.generation), "OverrideActive": "b " + str(self.override).lower(),
                "ObjectName": 's "Dashboard_0"'}[prop]
        elif "set-property" in args:
            if self.store is not None:
                records = [json.loads(p.read_text()) for p in self.store.root.rglob("*.json")]
                assert any(row.get("effects_started") is True and row.get("property_state") for row in records)
            self.writes += 1
            self.value = int(args[-1])
            if self.on_write:
                self.on_write()
            if self.fail_write:
                return SimpleNamespace(returncode=124, stdout="", stderr="timeout")
            stdout = ""
        else:
            raise AssertionError(f"unexpected target command: {args}")
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="", stdout_truncated=False)


class MdbPropertyBackendTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temporary.cleanup)
        if os.name == "nt":
            from importlib import import_module
            import_module(runtime.__name__ + ".windows_private")._harden(Path(self.temporary.name), directory=True)
        self.store = runtime.MutationJournalStore(Path(self.temporary.name) / "journals")
        self.transport = Transport()
        self.transport.store = self.store
        self.contract = backend._state.PropertyContract.from_value(plain_contract().to_public_dict())
        self.backend = backend.MdbPropertyBackend(journal_store=self.store, contracts={"interval": self.contract},
            transport_factory=lambda: self.transport)
        self.task = self.backend.open_task("property-backend-test")
        self.addCleanup(self.backend.close_task, self.task)
        self.context = runtime.OperationContext(task_id=self.task.task_id, operation_id="property-effect",
            deadline_at=time.monotonic() + 120, cancellation=runtime.CancellationToken(), _clock=time.monotonic)
        self.arguments = {"ip": "bmc.example", "contract_id": "interval",
            "expected_value": {"base_type": "U32", "value": 30}, "value": {"base_type": "U32", "value": 60},
            "_credential_values": {"OPENUBMC_SSH_USER": "operator", "OPENUBMC_SSH_PASSWORD": ""},
            "_task_authorization_policy": runtime.TaskAuthorizationPolicy.from_task_intent("property-update-and-verify").to_public_dict()}
        from importlib import import_module
        configuration = import_module(runtime.__name__ + ".configuration")
        source = Path(self.temporary.name) / "credentials.json"
        store = configuration.LocalConfigurationStore(source, kind="targets")
        saved = store.save({"schema_version": 1,
            "credentials": {"fixture": {"user": "operator", "password": "fixture-password"}},
            "defaults": {"bmc": {"ssh": "fixture"}}}, expected_revision=None)
        store.activate(saved["revision"], expected_active_revision=None)
        patcher = patch(runtime.__name__ + ".mcp.CredentialResolver",
                   side_effect=lambda: runtime.CredentialResolver(config_path=source, environ={}))
        patcher.start()
        self.addCleanup(patcher.stop)

    def service(self):
        service = runtime.RuntimeMcpService(runtime.OrchestratedMcpBackend({"mdb_property_modify": self.backend,
                                                                          "mdb_property_verify": self.backend}))
        self.addCleanup(service.close)
        return service

    def start(self, service, **changes):
        action = {"kind": "start", "target": "bmc.example", "intent": "property-update-and-verify",
            "entry_operation": "mdb_property_modify", "purpose": "set one reviewed interval",
            "entry_arguments": {key: self.arguments[key] for key in ("contract_id", "expected_value", "value")}}
        action.update(changes)
        return service.call_exposed_tool("execute", action, task_id="property-agent", operation_id="property-start")

    def test_actual_adapter_uses_one_bound_owner_setter_and_fresh_mdb_read(self):
        result = self.backend.mdb_property_modify(self.task, self.arguments, self.context)
        self.assertTrue(result["ok"])
        self.assertEqual(self.transport.writes, 1)
        setter = [a for a in self.transport.commands if "set-property" in a]
        self.assertEqual(setter[0], ["busctl", "--system", "--no-pager", "set-property", ":1.2",
            self.contract.path, self.contract.interface, self.contract.property, "u", "60"])
        self.assertTrue(all(a[:2] != ["mdbctl", "setprop"] for a in self.transport.commands))

    def test_missing_or_changed_contract_or_forged_policy_never_reaches_transport(self):
        for change in [{"contract_id": "unknown"}, {"property": "Interval; reboot"},
                       {"_task_authorization_policy": None}, {"ip": "other.example"},
                       {"value": {"base_type": "U32", "value": "60"}}]:
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError, PermissionError)):
                self.backend.mdb_property_modify(self.task, {**self.arguments, **change}, self.context)
        self.assertEqual(self.transport.commands, [])

    def test_read_only_property_or_override_never_sends_setter(self):
        self.transport.access = "read"
        with self.assertRaises(ValueError):
            self.backend.mdb_property_modify(self.task, self.arguments, self.context)
        self.transport.access = "readwrite"
        self.transport.override = True
        with self.assertRaises(ValueError):
            self.backend.mdb_property_modify(self.task, self.arguments, self.context)
        self.assertEqual(self.transport.writes, 0)

    def test_send_timeout_preserves_unknown_and_recovery_never_resends(self):
        self.transport.fail_write = True
        with self.assertRaises(RuntimeError) as caught:
            self.backend.mdb_property_modify(self.task, self.arguments, self.context)
        self.assertEqual(caught.exception.mutation_outcome, "unknown")
        self.backend.close_task(self.task)
        self.task = self.backend.open_task("property-backend-test")
        result = self.backend.mdb_property_modify(self.task,
            {**self.arguments, "_runtime_effect_recovery": "reconcile"}, self.context)
        self.assertTrue(result["ok"])
        self.assertEqual(self.transport.writes, 1)

    def test_internal_verifier_reuses_original_journal_and_read_after_change_blocks(self):
        self.backend.mdb_property_modify(self.task, self.arguments, self.context)
        args = {"ip": "bmc.example", "_runtime_property_mutation_id": "property-effect",
            "_credential_values": self.arguments["_credential_values"]}
        context = self.context.derive("property-verifier")
        self.transport.value = 90
        result = self.backend.mdb_property_verify(self.task, args, context)
        self.assertEqual(result["outcome_status"], "blocked")
        self.assertEqual(result["property_observation"]["value"]["value"], 90)
        self.assertEqual(self.transport.writes, 1)

    def test_verifier_rejects_unbound_or_other_mutation_identity(self):
        for mutation_id in ["", "unrelated"]:
            with self.subTest(id=mutation_id), self.assertRaises(ValueError):
                self.backend.mdb_property_verify(self.task, {"_runtime_property_mutation_id": mutation_id}, self.context)
        self.assertEqual(self.transport.commands, [])

    def test_operator_allowlist_has_no_implicit_default_and_rejects_duplicate_ids(self):
        self.assertEqual(backend.load_contracts(), {})
        p = Path(self.temporary.name) / "contracts.json"
        value = {"schema": backend.CONTRACTS_SCHEMA, "contracts": [self.contract.to_public_dict()]}
        p.write_text(json.dumps(value))
        if os.name == "nt":
            from importlib import import_module
            import_module(runtime.__name__ + ".windows_private").harden_new_file(p)
        else:
            p.chmod(0o600)
        self.assertEqual(backend.load_contracts(str(p))["interval"], self.contract)
        value["contracts"] *= 2
        p.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            backend.load_contracts(str(p))

    def test_default_agent_surface_is_two_tools_and_execute_completes_both_real_adapter_stages(self):
        service = self.service()
        self.assertEqual({item["name"] for item in service.tool_definitions()}, {"observe", "execute"})
        turn = self.start(service)
        self.assertEqual(turn["state"], "completed", turn)
        self.assertEqual(turn["outcome"]["status"], "completed")
        self.assertEqual({a["requirement_id"] for a in turn["outcome"]["acceptance"]},
                         {"stage.property_update", "stage.verification"})
        self.assertEqual(self.transport.writes, 1)

    def test_execute_noop_has_fresh_closeout_and_zero_setters(self):
        self.arguments["value"] = self.arguments["expected_value"]
        turn = self.start(self.service())
        self.assertEqual(turn["state"], "completed", turn)
        self.assertEqual(self.transport.writes, 0)
        journal = self.store.load_for_task(turn["run_id"])[0]
        self.assertFalse(journal.effects_started)
        self.assertEqual(journal.epoch_before, journal.epoch_after)

    def test_execute_unknown_reconciles_same_effect_without_resend(self):
        service = self.service()
        self.transport.fail_write = True
        self.transport.on_write = lambda: setattr(self.transport, "value", 45)
        turn = self.start(service)
        self.assertEqual(turn["state"], "incident", turn)
        self.assertEqual(turn["incident"]["code"], "mutation_outcome_unknown")
        effect = turn["incident"]["effect_id"]
        self.transport.value = 60
        recovered = service.call_exposed_tool("execute", {"kind": "control", "run_id": turn["run_id"],
            "command": "reconcile"}, task_id="property-agent", operation_id="property-reconcile")
        self.assertEqual(recovered["state"], "completed", recovered)
        self.assertEqual(self.transport.writes, 1)
        self.assertEqual(self.store.load_for_task(turn["run_id"])[0].operation_id, effect)

    def test_property_entry_rejects_unknown_fields_wrong_intent_and_multiple_targets(self):
        from importlib import import_module
        semantic = import_module(runtime.__name__ + ".semantic_runtime")
        base = {"kind": "start", "target": "bmc.example", "intent": "property-update-and-verify",
                "entry_operation": "mdb_property_modify", "entry_arguments": {
                    k: self.arguments[k] for k in ("contract_id", "expected_value", "value")}}
        for change in [{"entry_arguments": {**base["entry_arguments"], "mode": "set"}},
                       {"intent": "diagnosis-only"}, {"entry_operation": ""},
                       {"targets": [{"ip": "bmc.example"}, {"ip": "other.example"}]}]:
            with self.subTest(change=change), self.assertRaises(semantic.AgentGatewayError):
                semantic.decode_run_command({**base, **change}, operation_id="property-start")
        self.assertEqual(self.transport.commands, [])

    def test_compensation_is_a_new_conditional_write_and_rejects_external_change(self):
        self.backend.mdb_property_modify(self.task, self.arguments, self.context)
        compensation = {**self.arguments, "expected_value": self.arguments["value"],
                         "value": self.arguments["expected_value"]}
        self.transport.value = 90
        with self.assertRaises(ValueError):
            self.backend.mdb_property_modify(self.task, compensation, self.context.derive("compensation-effect"))
        self.assertEqual(self.transport.writes, 1)

    def test_existing_binding_rechecks_allowlisted_principal(self):
        self.backend.mdb_property_modify(self.task, self.arguments, self.context)
        self.backend.contracts["interval"] = replace(self.contract, allowed_ssh_users=("another-operator",))
        with self.assertRaises(PermissionError):
            self.backend.mdb_property_modify(self.task, self.arguments, self.context.derive("property-effect-2"))
        self.assertEqual(self.transport.writes, 1)

    def test_execute_initial_principal_denial_is_known_zero_write(self):
        self.backend.contracts["interval"] = replace(self.contract, allowed_ssh_users=("another-operator",))
        turn = self.start(self.service())
        self.assertEqual(turn["state"], "failed", turn)
        self.assertIsNone(turn["incident"])
        self.assertEqual(self.transport.commands, [])

    def assert_recovery_preserves_contract_rejection(self, changed_contract):
        service = self.service()
        self.transport.fail_write = True
        self.transport.on_write = lambda: setattr(self.transport, "value", 45)
        turn = self.start(service)
        self.assertEqual(turn["state"], "incident", turn)
        if changed_contract is None:
            self.backend.contracts.clear()
        else:
            self.backend.contracts["interval"] = changed_contract
        before = len(self.transport.commands)
        recovered = service.call_exposed_tool("execute", {"kind": "control", "run_id": turn["run_id"],
            "command": "reconcile"}, task_id="property-agent", operation_id="property-reconcile-denied")
        self.assertEqual(recovered["state"], "incident", recovered)
        self.assertEqual(recovered["incident"]["code"], "mutation_outcome_unknown")
        self.assertEqual(recovered["incident"]["effect_id"], turn["incident"]["effect_id"])
        self.assertEqual(len(self.transport.commands), before)
        self.assertEqual(self.transport.writes, 1)

    def test_recovery_contract_removal_does_not_resolve_unknown_write(self):
        self.assert_recovery_preserves_contract_rejection(None)

    def test_recovery_changed_contract_does_not_resolve_unknown_write(self):
        self.assert_recovery_preserves_contract_rejection(replace(self.contract, firmware_id="new-firmware"))

    def test_recovery_changed_principal_keeps_original_unknown_write(self):
        self.assert_recovery_preserves_contract_rejection(replace(self.contract, allowed_ssh_users=("another-operator",)))


if __name__ == "__main__":
    unittest.main()
