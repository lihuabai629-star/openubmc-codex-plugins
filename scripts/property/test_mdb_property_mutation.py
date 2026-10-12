from __future__ import annotations

from dataclasses import replace
import copy
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "plugins/openubmc/skills/openubmc-target-runtime"))
from openubmc_target_runtime import (CredentialResolver, CredentialSelector, ResolvedSshCredentials,
    TargetSpec, TargetIdentity, OpenUBMCTaskRun, MutationJournalStore, TaskAuthorizationPolicy,
    MutationAuthorizationDenied, MutationOperationConflict, MutationJournal, MutationJournalCorrupt)
from openubmc_target_runtime.capability import EffectRecoveryMode
from openubmc_target_runtime.property_state import PropertyContract, PropertyValue, PropertyObservation
from openubmc_target_runtime.property_mutation import PropertyMutation


def contract():
    return PropertyContract(contract_id="interval", target="bmc.example", service="bmc.example.Owner",
        path="/bmc/example/Dashboard_0", interface="bmc.example.Configuration", property="Interval",
        object="Dashboard_0", base_type="U32", minimum=5, maximum=3600, source_sha256="c" * 64,
        firmware_id="fixture-v1", firmware_service="bmc.example.BMC", firmware_path="/bmc/example/BMC_00",
        firmware_interface="bmc.example.BMC", firmware_property="Version", generation_interface="bmc.example.Configuration",
        generation_property="Generation", override_interface="bmc.example.Configuration", override_property="OverrideActive",
        allowed_ssh_users=("operator",), persistence="runtime")


class PropertyMutationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temporary.cleanup)
        if os.name == "nt":
            from openubmc_target_runtime.windows_private import _harden
            _harden(Path(self.temporary.name), directory=True)
        self.store = MutationJournalStore(Path(self.temporary.name) / "journals")
        self.contract = contract()
        self.selector = CredentialSelector.for_ssh(user="operator", user_env="", password_env="", identity_file="", environ={})
        self.target = TargetSpec.for_credential_selectors(host="bmc.example", credential_selectors=(self.selector,))
        self.authorization = TaskAuthorizationPolicy.from_task_intent("property-update-and-verify")
        self.value, self.reads, self.writes = PropertyValue("U32", 30), 0, 0
        self.owner, self.generation = ":1.2", "generation-1"
        self.override, self.writable, self.visible = False, True, None
        self.identity = TargetIdentity(machine_id="machine", firmware_id="fixture-v1", reboot_anchor="boot")
        self.read_hook = self.write_hook = None
        self.new_run()

    def new_run(self):
        self.run = OpenUBMCTaskRun(task_id="property-test", mutation_journal_store=self.store,
            credential_resolver=CredentialResolver(ssh_loader=lambda _selector: ResolvedSshCredentials(user="operator", password="")))
        self.addCleanup(self.run.close)
        self.driver = PropertyMutation(task_run=self.run, target=self.target, selector=self.selector,
            observe=self.observe, assign=self.assign)

    def observe(self, contract):
        self.reads += 1
        if self.read_hook:
            self.read_hook(self.reads)
        return PropertyObservation(self.identity, contract.fingerprint, self.owner, self.generation,
            self.value, self.visible or self.value, self.override, self.writable, f"sample-{self.reads}")

    def assign(self, state):
        journal = self.run.mutation_journal("property-effect")
        persisted = self.store.load_for_task("property-test")[0]
        self.assertTrue(journal.effects_started)
        self.assertTrue(persisted.effects_started)
        self.assertEqual(persisted.property_state.to_public_dict(), state.to_public_dict())
        self.writes += 1
        self.value = state.desired
        if self.write_hook:
            self.write_hook()
        return {"returncode": 0}

    def modify(self, **overrides):
        values = dict(operation_id="property-effect", contract=self.contract, expected=PropertyValue("U32", 30),
            desired=PropertyValue("U32", 60), authorization=self.authorization)
        values.update(overrides)
        return self.driver.run(**values)

    def test_scalar_types_are_exact_and_bounded(self):
        for kind, value in [("U32", True), ("Boolean", 1), ("U8", 256), ("I16", -32769),
                            ("U64", "18446744073709551615"), ("U32", 3.0), ("U32", "30; reboot"),
                            ("String", "hello")]:
            with self.subTest(kind=kind, value=value), self.assertRaises((TypeError, ValueError)):
                PropertyValue(kind, value)

    def test_source_contract_rejects_unreviewed_setters_and_addresses(self):
        for fields in [{"setter_kind": "trigger-job"}, {"object_lifetime": "dynamic"},
                       {"property": "Interval; reboot"}, {"path": "/bmc/../bad"},
                       {"interface": "bmc.example.$(id)"}, {"source_sha256": "unknown"},
                       {"allowed_ssh_users": ()}, {"persistence": "unknown"}, {"minimum": -1}]:
            with self.subTest(fields=fields), self.assertRaises((ValueError, TypeError)):
                replace(self.contract, **fields)

    def test_success_persists_before_single_dispatch_and_reads_fresh(self):
        result = self.modify()
        self.assertTrue(result["ok"])
        self.assertEqual((self.writes, self.reads), (1, 3))
        self.assertEqual(result["journal"]["stage"], "verified")
        self.assertEqual(result["verification"]["target_epoch"], 1)
        self.assertIsNone(result["verification"]["setter_exactly_once"])
        self.assertFalse(result["verification"]["reboot_persistence_verified"])
        self.assertEqual(result["journal"]["expected_checksum"], "")

    def test_completed_replay_returns_retained_result_without_writes_or_reads(self):
        self.modify()
        self.value = PropertyValue("U32", 90)
        before = (self.reads, self.writes)
        result = self.modify()
        self.assertTrue(result["idempotent_replay"])
        self.assertIsNone(result["verification"])
        self.assertEqual((self.reads, self.writes), before)

    def test_same_effect_different_value_is_rejected(self):
        self.modify()
        with self.assertRaises(MutationOperationConflict):
            self.modify(desired=PropertyValue("U32", 90))
        self.assertEqual(self.writes, 1)

    def test_noop_keeps_zero_dispatch_boundary_and_collects_new_evidence(self):
        result = self.modify(desired=self.value)
        self.assertEqual(self.writes, 0)
        self.assertEqual(result["mutation"]["new_write_requests"], 0)
        self.assertFalse(result["journal"]["effects_started"])
        self.assertEqual(result["epoch_before"], result["epoch_after"])
        self.assertEqual(self.reads, 3)

    def test_read_only_intent_cannot_authorize_a_setter(self):
        with self.assertRaises(MutationAuthorizationDenied):
            self.modify(authorization=TaskAuthorizationPolicy.from_task_intent("diagnosis-only"))
        self.assertEqual((self.reads, self.writes), (0, 0))

    def test_range_and_type_are_rejected_before_observing_target(self):
        for desired in [PropertyValue("U32", 1), PropertyValue("U16", 60)]:
            with self.subTest(desired=desired), self.assertRaises(ValueError):
                self.modify(desired=desired)
        self.assertEqual((self.reads, self.writes), (0, 0))

    def test_stale_expectation_sends_no_write(self):
        self.value = PropertyValue("U32", 45)
        with self.assertRaises(ValueError) as caught:
            self.modify()
        self.assertEqual(caught.exception.mutation_outcome, "not_started")
        self.assertEqual(self.writes, 0)

    def test_foreign_target_sends_no_write(self):
        with self.assertRaises(ValueError):
            self.modify(contract=replace(self.contract, target="other.example"))
        self.assertEqual((self.reads, self.writes), (0, 0))

    def test_unknown_recovery_without_journal_never_creates_a_write(self):
        with self.assertRaises(MutationOperationConflict):
            self.modify(recovery_mode=EffectRecoveryMode.RECONCILE)
        self.assertEqual((self.reads, self.writes), (0, 0))

    def test_override_or_readonly_or_mismatched_visible_value_blocks_dispatch(self):
        for field, value in [("override", True), ("writable", False), ("visible", PropertyValue("U32", 31))]:
            with self.subTest(field=field):
                setattr(self, field, value)
                with self.assertRaises(ValueError):
                    self.modify()
                setattr(self, field, None if field == "visible" else field == "writable")
        self.assertEqual(self.writes, 0)

    def test_owner_generation_or_value_change_between_checks_blocks_dispatch(self):
        for field, value in [("owner", ":1.3"), ("generation", "generation-2"), ("value", PropertyValue("U32", 45))]:
            with self.subTest(field=field):
                previous = getattr(self, field)
                first = self.reads
                self.read_hook = lambda count, f=field, v=value, n=first: setattr(self, f, v) if count == n + 2 else None
                with self.assertRaises(ValueError):
                    self.modify()
                setattr(self, field, previous)
        self.assertEqual(self.writes, 0)

    def lost_reply(self):
        self.write_hook = lambda: (_ for _ in ()).throw(TimeoutError("lost response"))
        with self.assertRaises(TimeoutError) as caught:
            self.modify()
        self.assertEqual(caught.exception.mutation_outcome, "unknown")

    def test_send_then_timeout_reconciles_desired_state_without_second_setter(self):
        self.lost_reply()
        self.run.close()
        self.new_run()
        result = self.modify(recovery_mode=EffectRecoveryMode.RECONCILE)
        self.assertTrue(result["ok"])
        self.assertEqual(self.writes, 1)
        self.assertEqual(result["journal"]["recovery_decision"], "verify")

    def test_timeout_then_before_value_does_not_replan_or_repeat_setter(self):
        self.lost_reply()
        self.value = PropertyValue("U32", 30)
        result = self.modify(recovery_mode=EffectRecoveryMode.RECONCILE)
        self.assertEqual(result["outcome_status"], "mutation_outcome_unknown")
        self.assertEqual(result["journal"]["stage"], "recovery_blocked")
        self.assertEqual(self.writes, 1)

    def test_timeout_then_external_third_value_never_compensates(self):
        self.lost_reply()
        self.value = PropertyValue("U32", 90)
        result = self.modify(recovery_mode=EffectRecoveryMode.RECONCILE)
        self.assertFalse(result["ok"])
        self.assertEqual(self.value.value, 90)
        self.assertEqual(self.writes, 1)

    def test_recovery_rejects_changed_boot_owner_firmware_generation_or_override(self):
        self.lost_reply()
        for field, value in [("owner", ":1.7"), ("generation", "new-object"), ("override", True),
                            ("identity", replace(self.identity, reboot_anchor="new-boot")),
                            ("identity", replace(self.identity, firmware_id="different-firmware"))]:
            with self.subTest(field=field):
                previous = getattr(self, field)
                setattr(self, field, value)
                result = self.modify(recovery_mode=EffectRecoveryMode.RECONCILE)
                self.assertFalse(result["ok"])
                setattr(self, field, previous)
        self.assertEqual(self.writes, 1)

    def test_fresh_mismatch_is_not_success_and_recovers_by_reading(self):
        self.write_hook = lambda: setattr(self, "visible", PropertyValue("U32", 30))
        with self.assertRaises(ValueError):
            self.modify()
        self.assertEqual(self.run.mutation_journal("property-effect").stage, "verification_failed")
        self.visible = None
        self.assertTrue(self.modify(recovery_mode=EffectRecoveryMode.RECONCILE)["ok"])
        self.assertEqual(self.writes, 1)

    def test_pre_send_failure_recovery_is_read_only(self):
        self.value = PropertyValue("U32", 45)
        with self.assertRaises(ValueError):
            self.modify()
        result = self.modify(recovery_mode=EffectRecoveryMode.RECONCILE)
        self.assertEqual(result["new_write_requests"], 0)
        self.assertEqual(self.writes, 0)

    def test_legacy_file_journal_roundtrip_omits_property_state(self):
        legacy = MutationJournal(task_id="old", operation_id="old", operation_fingerprint="a" * 64,
            action="live_patch", original_intent="live-patch", target_fingerprint="b" * 64,
            target_identity=None, epoch_before=0)
        payload = legacy.to_public_dict()
        self.assertNotIn("property_state", payload)
        self.assertEqual(MutationJournal.from_public_dict(payload).to_public_dict(), payload)

    def test_property_journal_roundtrip_and_unknown_state_version(self):
        result = self.modify()
        payload = result["journal"]
        self.assertEqual(MutationJournal.from_public_dict(payload).to_public_dict(), payload)
        payload["property_state"]["schema"] = "future-unsupported"
        with self.assertRaises(MutationJournalCorrupt):
            MutationJournal.from_public_dict(payload)

    def test_property_journal_rejects_mixed_state_and_coerced_identity(self):
        payload = self.modify()["journal"]
        for change in [{"action": "live_patch"}, {"effects_started": "false"},
                       {"expected_checksum": "a" * 64}, {"target_identity": None},
                       {"epoch_after": True}]:
            with self.subTest(change=change), self.assertRaises(MutationJournalCorrupt):
                MutationJournal.from_public_dict({**payload, **change})
        for field, item in [("machine_id", True), ("firmware_id", 1)]:
            broken = copy.deepcopy(payload)
            broken["property_state"]["before"]["target_identity"][field] = item
            with self.subTest(field=field), self.assertRaises(MutationJournalCorrupt):
                MutationJournal.from_public_dict(broken)

    def test_distinct_effects_do_not_share_a_fresh_read_identity(self):
        self.modify(desired=self.value)
        self.modify(operation_id="second-property-effect", desired=self.value)
        self.assertEqual(self.writes, 0)
        self.assertEqual(self.reads, 6)

    def test_abrupt_process_exit_at_dispatch_boundary_never_causes_replay(self):
        # A separate process disappears with no exception/cleanup path. The
        # transport fixture persists its simulated remote value independently.
        source = Path(__file__).resolve().parent
        script = '''
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from test_mdb_property_mutation import *
from openubmc_target_runtime.property_state import PropertyValue, PropertyObservation
from openubmc_target_runtime.property_mutation import PropertyMutation
root, after = Path(sys.argv[2]), sys.argv[3] == "after"
spec = contract()
selector = CredentialSelector.for_ssh(user="operator", user_env="", password_env="", identity_file="", environ={})
target = TargetSpec.for_credential_selectors(host="bmc.example", credential_selectors=(selector,))
run = OpenUBMCTaskRun(task_id="crash-property", mutation_journal_store=MutationJournalStore(root / "journals"),
    credential_resolver=CredentialResolver(ssh_loader=lambda _: ResolvedSshCredentials(user="operator")))
def observe(_):
    value = PropertyValue("U32", int((root / "value").read_text()))
    return PropertyObservation(TargetIdentity(machine_id="machine", firmware_id="fixture-v1", reboot_anchor="boot"),
        spec.fingerprint, ":1.2", "generation-1", value, value, False, True, "fixture")
def assign(_):
    if after:
        (root / "value").write_text("60")
        (root / "dispatch-count").write_text("1")
    os._exit(31)
PropertyMutation(task_run=run, target=target, selector=selector, observe=observe, assign=assign).run(
    operation_id="crash-effect", contract=spec, expected=PropertyValue("U32", 30), desired=PropertyValue("U32", 60),
    authorization=TaskAuthorizationPolicy.from_task_intent("property-update-and-verify"))
'''
        for point in ("before", "after"):
            with self.subTest(point=point), tempfile.TemporaryDirectory(dir=Path.home()) as directory:
                root = Path(directory)
                if os.name == "nt":
                    from openubmc_target_runtime.windows_private import _harden
                    _harden(root, directory=True)
                (root / "value").write_text("30")
                completed = subprocess.run([sys.executable, "-B", "-c", script, str(source), str(root), point],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(completed.returncode, 31, completed.stderr)
                store = MutationJournalStore(root / "journals")
                journal = store.load_for_task("crash-property")[0]
                self.assertTrue(journal.effects_started)
                self.assertEqual(journal.stage, "applying")
                run = OpenUBMCTaskRun(task_id="crash-property", mutation_journal_store=store,
                    credential_resolver=CredentialResolver(ssh_loader=lambda _: ResolvedSshCredentials(user="operator")))
                self.addCleanup(run.close)
                self.value = PropertyValue("U32", int((root / "value").read_text()))
                driver = PropertyMutation(task_run=run, target=self.target, selector=self.selector,
                    observe=self.observe, assign=lambda _: self.fail("recovery must never call setter"))
                result = driver.run(operation_id="crash-effect", contract=self.contract,
                    expected=PropertyValue("U32", 30), desired=PropertyValue("U32", 60),
                    authorization=self.authorization, recovery_mode=EffectRecoveryMode.RECONCILE)
                self.assertEqual(result["ok"], point == "after")
                self.assertEqual((root / "dispatch-count").exists(), point == "after")


if __name__ == "__main__":
    unittest.main()
