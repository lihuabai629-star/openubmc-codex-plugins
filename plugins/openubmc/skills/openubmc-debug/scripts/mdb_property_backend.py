"""Typed property Domain adapter. The diagnostic MDB collector stays read-only."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
import importlib
import json
import os
from pathlib import Path
import re
import shlex
import xml.etree.ElementTree as ET

from _target_runtime_adapter import _load_runtime_module
from _remote_common import OpenSshControlMasterTransport, resolve_ssh_host_key_config

_runtime = _load_runtime_module()
_state = importlib.import_module(_runtime.__name__ + ".property_state")
_mutation = importlib.import_module(_runtime.__name__ + ".property_mutation")
_credential_file = importlib.import_module(_runtime.__name__ + ".credential_file")

CONTRACTS_SCHEMA = "openubmc.mdb-property-contracts.v1"


def load_contracts(path: str = "") -> dict[str, object]:
    if not path:
        return {}
    source = Path(path).expanduser()
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate property allowlist key")
            result[key] = value
        return result
    raw = json.loads(_credential_file.read_private_text(source, max_bytes=65536), object_pairs_hook=unique_pairs)
    if (not isinstance(raw, Mapping) or set(raw) != {"schema", "contracts"}
            or raw["schema"] != CONTRACTS_SCHEMA or not isinstance(raw["contracts"], list)
            or len(raw["contracts"]) > 64):
        raise ValueError("unsupported property allowlist schema")
    contracts = {}
    for row in raw["contracts"]:
        contract = _state.PropertyContract.from_value(row)
        if contract.contract_id in contracts:
            raise ValueError("duplicate property contract identity")
        contracts[contract.contract_id] = contract
    return contracts


class PropertyRemote:
    """One fixed SSH lane; exact D-Bus owner/path setter, no transport fallback.

    Normal MDB modify semantics are implemented by busctl set-property, whose
    equivalence is documented by mdbctl. set/unset and alias-based writes are
    deliberately absent. Owner-supplied generation and override proof properties
    are mandatory; unsupported targets fail before any write is sent.
    """

    def __init__(self, lane, *, timeout: float, context) -> None:
        self.lane, self.timeout, self.context = lane, min(timeout, 15.0), context

    def command(self, argv: list[str]) -> str:
        self.context.raise_if_stopped()
        result = self.lane.run_channel(shlex.join(argv), timeout=min(self.timeout, self.context.remaining()),
            stdout_limit_bytes=32768, stderr_limit_bytes=2048, replay_safe=False)
        if result.returncode != 0:
            raise RuntimeError("property transport command did not complete")
        if getattr(result, "stdout_truncated", False):
            raise RuntimeError("property evidence is truncated")
        return result.stdout.strip()

    def owner(self, contract) -> str:
        output = self.command(["busctl", "--system", "--no-pager", "call", "org.freedesktop.DBus",
            "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", "s", contract.service])
        if not output.startswith("s "):
            raise ValueError("D-Bus owner evidence is invalid")
        owner = json.loads(output[2:])
        if not isinstance(owner, str) or re.fullmatch(r":[0-9]+\.[0-9]+", owner) is None:
            raise ValueError("D-Bus unique owner is unavailable")
        return owner

    def read(self, service: str, path: str, interface: str, prop: str, signature: str):
        output = self.command(["busctl", "--system", "--no-pager", "get-property", service, path, interface, prop])
        prefix = signature + " "
        if not output.startswith(prefix):
            raise ValueError("D-Bus property type mismatch")
        raw = output[len(prefix):]
        if signature == "s":
            value = json.loads(raw)
            if not isinstance(value, str):
                raise TypeError("D-Bus string evidence is invalid")
            return value
        if signature == "b":
            if raw not in {"true", "false"}:
                raise ValueError("D-Bus boolean evidence is invalid")
            return raw == "true"
        if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", raw) is None:
            raise ValueError("D-Bus integer evidence is invalid")
        return int(raw)

    def observe(self, contract):
        machine = self.command(["cat", "/etc/machine-id"])
        boot = self.command(["cat", "/proc/sys/kernel/random/boot_id"])
        if re.fullmatch(r"[0-9a-f]{32}", machine) is None or re.fullmatch(r"[0-9a-f-]{36}", boot) is None:
            raise ValueError("target boot/machine evidence is invalid")
        firmware = self.read(contract.firmware_service, contract.firmware_path,
            contract.firmware_interface, contract.firmware_property, "s")
        if firmware != contract.firmware_id:
            raise ValueError("target firmware differs from the allowlist")
        owner = self.owner(contract)
        generation = self.read(owner, contract.path, contract.generation_interface, contract.generation_property, "s")
        override = self.read(owner, contract.path, contract.override_interface, contract.override_property, "b")
        object_name = self.read(owner, contract.path, "bmc.kepler.Object.Properties", "ObjectName", "s")
        if object_name != contract.object:
            raise ValueError("MDB object does not match the bound D-Bus path")
        xml = self.command(["busctl", "--system", "--no-pager", "--xml-interface", "introspect", owner, contract.path])
        if "<!DOCTYPE" in xml or "<!ENTITY" in xml:
            raise ValueError("unexpected introspection XML declarations")
        props = [p for interface in ET.fromstring(xml).findall("interface")
            if interface.get("name") == contract.interface for p in interface.findall("property")
            if p.get("name") == contract.property]
        sample = _state.PropertyValue(contract.base_type, self.read(owner, contract.path,
            contract.interface, contract.property, _state.PropertyValue(contract.base_type,
            False if contract.base_type == "Boolean" else contract.minimum).signature))
        contract.validate_value(sample)
        if len(props) != 1 or props[0].get("type") != sample.signature or props[0].get("access") != "readwrite":
            raise ValueError("target property is not uniquely writable with the declared type")
        visible = self.command(["mdbctl", "getprop", contract.object, contract.interface, contract.property])
        if any(kind in visible for kind in ("type: synchronization", "reference object", "reference property")):
            raise ValueError("synchronized or referenced MDB properties are excluded")
        first = visible.splitlines()[0] if visible else ""
        if contract.base_type == "Boolean":
            if first not in {"true", "false", "0", "1"}:
                raise ValueError("MDB boolean evidence is invalid")
            value = first in {"true", "1"}
        else:
            if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", first) is None:
                raise ValueError("MDB scalar evidence is invalid")
            value = int(first)
        visible_value = _state.PropertyValue(contract.base_type, value)
        if (owner != self.owner(contract) or generation != self.read(owner, contract.path,
                contract.generation_interface, contract.generation_property, "s")
                or boot != self.command(["cat", "/proc/sys/kernel/random/boot_id"])):
            raise ValueError("property snapshot crossed an owner/object/boot change")
        return _state.PropertyObservation(_runtime.TargetIdentity(machine_id=machine, firmware_id=firmware,
            reboot_anchor=boot), contract.fingerprint, owner, generation, sample, visible_value,
            override, True, datetime.now(timezone.utc).isoformat())

    def assign(self, state):
        # Fixed normal setter transport, addressed to the observed unique owner.
        value = ("true" if state.desired.value else "false") if state.desired.base_type == "Boolean" else str(state.desired.value)
        self.command(["busctl", "--system", "--no-pager", "set-property", state.before.owner,
            state.contract.path, state.contract.interface, state.contract.property, state.desired.signature, value])
        return {"transport": "dbus-set-property-v1", "returncode": 0, "setter_exactly_once": None}


@dataclass
class _Binding:
    task_run: object
    target: object
    selector: object
    lane: object


@dataclass
class _Task:
    task_id: str
    bindings: dict = field(default_factory=dict)


class MdbPropertyBackend:
    def __init__(self, *, journal_store, contracts=None, transport_factory=None, remote_factory=None) -> None:
        self.journal_store = journal_store
        self.contracts = dict(contracts) if contracts is not None else load_contracts(
            os.environ.get("OPENUBMC_MDB_PROPERTY_CONTRACTS", ""))
        self.transport_factory = transport_factory
        self.remote_factory = remote_factory or PropertyRemote

    @staticmethod
    def open_task(task_id: str):
        return _Task(task_id)

    @staticmethod
    def close_task(task):
        for binding in task.bindings.values():
            binding.task_run.close()
        task.bindings.clear()

    @staticmethod
    def maintain_task(task):
        return sum(binding.task_run.prune_dead_connections() for binding in task.bindings.values())

    @staticmethod
    def task_status(task):
        return {"targets": len(task.bindings), "property_journals": [j.to_public_dict()
            for b in task.bindings.values() for j in b.task_run.mutation_journals()]}

    def contract(self, arguments):
        contract_id = arguments.get("contract_id")
        if not isinstance(contract_id, str) or contract_id not in self.contracts:
            raise ValueError("property is not in the operator allowlist")
        contract = self.contracts[contract_id]
        for name in ("object", "interface", "property"):
            if name in arguments and arguments[name] != getattr(contract, name):
                raise ValueError("property address differs from allowlist")
        return contract

    def binding(self, task, arguments, contract):
        host = str(arguments.get("ip", "")).strip().lower()
        if host != contract.target.strip().lower():
            raise ValueError("property target differs from allowlist")
        port = arguments.get("ssh_port", 22)
        key = (host, port)
        values = arguments.get("_credential_values")
        if not isinstance(values, Mapping):
            raise ValueError("property adapter requires Runtime-resolved credentials")
        credentials = _runtime.ResolvedSshCredentials(user=values.get("OPENUBMC_SSH_USER", ""),
            password=values.get("OPENUBMC_SSH_PASSWORD", ""),
            identity_file=values.get("OPENUBMC_SSH_IDENTITY_FILE", ""))
        if credentials.user not in contract.allowed_ssh_users:
            raise PermissionError("SSH principal is not allowed by the property contract")
        selector = _runtime.CredentialSelector.for_ssh(user=credentials.user, user_env="", password_env="",
            identity_file=credentials.identity_file, environ={})
        existing = task.bindings.get(key)
        if existing is not None:
            if existing.selector.fingerprint != selector.fingerprint:
                raise PermissionError("property credentials differ from the frozen binding")
            return existing
        host_key = resolve_ssh_host_key_config()
        target = _runtime.TargetSpec.for_credential_selectors(host=host, ssh_port=port,
            credential_selectors=(selector,), policy=_runtime.TargetPolicy(read_only=False, ssh_host_key_policy=host_key["policy"]))
        run = _runtime.OpenUBMCTaskRun(task_id=task.task_id,
            credential_resolver=_runtime.CredentialResolver(ssh_loader=lambda _selector: credentials),
            mutation_journal_store=self.journal_store)
        transport = self.transport_factory() if self.transport_factory else OpenSshControlMasterTransport(
            host_key_policy=host_key["policy"], known_hosts_file=host_key["_known_hosts_file"],
            allow_insecure_host_key=host_key["policy"] == "insecure")
        lane = run.ssh_lane(target=target, credential_selector=selector, lease_name="mdb-property", transport=transport)
        binding = _Binding(run, target, selector, lane)
        task.bindings[key] = binding
        return binding

    def mdb_property_modify(self, task, arguments, context):
        recovery_mode = _runtime.effect_recovery_mode(arguments)
        if self.journal_store is None:
            raise ValueError("property mutation requires a durable journal store")
        existing = next((j for j in self.journal_store.load_for_task(task.task_id)
                         if j.operation_id == context.operation_id), None)
        try:
            context.raise_if_stopped()
            policy = arguments.get("_task_authorization_policy")
            if not isinstance(policy, Mapping):
                raise ValueError("property write requires frozen Runtime task authorization")
            task_policy = _runtime.TaskAuthorizationPolicy.from_public_dict(policy)
            task_policy.require("mdb_property_modify")
            contract = self.contract(arguments)
            expected = _state.PropertyValue.from_value(arguments.get("expected_value"))
            desired = _state.PropertyValue.from_value(arguments.get("value"))
            contract.validate_value(expected)
            contract.validate_value(desired)
            binding = self.binding(task, arguments, contract)
            if arguments.get("_minimum_target_epoch", 0):
                binding.task_run.ensure_target_epoch(binding.target, arguments["_minimum_target_epoch"], reason="property-run-binding")
            remote = self.remote_factory(binding.lane, timeout=context.remaining(), context=context)
            return _mutation.PropertyMutation(task_run=binding.task_run, target=binding.target, selector=binding.selector,
                observe=remote.observe, assign=remote.assign).run(operation_id=context.operation_id, contract=contract,
                expected=expected, desired=desired, authorization=task_policy,
                recovery_mode=recovery_mode, operation_context=context)
        except Exception as error:
            _mutation.annotate_property_preflight_failure(error, existing, recovery_mode)
            raise

    def mdb_property_verify(self, task, arguments, context):
        mutation_id = arguments.get("_runtime_property_mutation_id")
        if not isinstance(mutation_id, str) or not mutation_id:
            raise ValueError("property verification requires Runtime journal binding")
        journals = self.journal_store.load_for_task(task.task_id) if self.journal_store else [
            j for b in task.bindings.values() for j in b.task_run.mutation_journals()]
        journal = next((j for j in journals if j.operation_id == mutation_id), None)
        if journal is None or journal.task_id != task.task_id or journal.action != "mdb_property_modify" or journal.stage != "verified" or journal.property_state is None:
            raise ValueError("verified property mutation journal is unavailable")
        state = journal.property_state
        approved = self.contracts.get(state.contract.contract_id)
        if approved is None or approved.fingerprint != state.contract.fingerprint:
            raise ValueError("frozen property contract is no longer approved")
        binding = self.binding(task, arguments, state.contract)
        if binding.target.fingerprint != journal.target_fingerprint:
            raise ValueError("property verifier target differs from original mutation")
        epoch = max(journal.epoch_after or journal.epoch_before, int(arguments.get("_minimum_target_epoch", 0)))
        binding.task_run.ensure_target_epoch(binding.target, epoch, reason="property-verification")
        remote = self.remote_factory(binding.lane, timeout=context.remaining(), context=context)
        request = _runtime.RemoteReadRequest.create(request_id=context.operation_id, target=binding.target,
            credential_selector=binding.selector, collector_name="mdb-property-fresh-verifier",
            operation={"mutation_id": mutation_id, "state": state.to_public_dict(), "epoch": epoch,
                       "verification_operation_id": context.operation_id})
        observation = binding.task_run.run_read(request, lambda _read: remote.observe(state.contract)).value
        matched = state.matches(observation)
        return {"ok": matched, "outcome_status": "verified" if matched else "blocked",
            "journal": journal.to_public_dict(), "property_observation": observation.to_public_dict(),
            "target_epoch": epoch, "epoch_after": epoch, "setter_exactly_once": None,
            "reboot_persistence_verified": False}
