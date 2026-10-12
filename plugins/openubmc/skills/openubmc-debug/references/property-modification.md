# Ordinary MDB property assignment

Read-only questions use `observe`. An explicitly requested ordinary configuration
assignment uses `execute`; it creates a Run with a property Effect and a separate
fresh read-only verification step. The Agent tool surface remains `observe` and
`execute`. Diagnostic `mdbctl_remote.py` and `busctl_remote.py` stay read-only.

## Start a qualified assignment

```json
{
  "kind": "start",
  "intent": "property-update-and-verify",
  "target": "<BMC address>",
  "entry_operation": "mdb_property_modify",
  "entry_arguments": {
    "contract_id": "<operator-approved contract ID>",
    "expected_value": {"base_type": "U32", "value": 30},
    "value": {"base_type": "U32", "value": 60}
  },
  "purpose": "Apply the requested configuration value and verify the same property"
}
```

Use the approved property's type and current expected value. One target and one
property are supported. Optional `object`, `interface`, `property` must exactly
match the contract; `ssh_port` may select a configured SSH port. Unknown entry
fields and Runtime-owned fields are rejected. Boolean, U8, I16, U16, I32 and U32
values are exact JSON booleans or integers, without coercion. Strings, 64-bit
values, composite values, batches and action-triggering setters are unsupported.

## Operator contract

`OPENUBMC_MDB_PROPERTY_CONTRACTS` selects a private current-user JSON file with
`schema="openubmc.mdb-property-contracts.v1"` and a `contracts` array. Without it
the allowlist is empty. On POSIX use mode 0600; Windows uses the Runtime's existing
current-user ACL checks. This file is operator configuration, never Agent input.

Each entry is a complete `PropertyContract` with:

| Fields | Required evidence |
| --- | --- |
| `contract_id`, `target`, `service`, `path`, `interface`, `property`, `object` | Exact reviewed target and owner address; no alias-based write |
| `base_type`, `minimum`, `maximum` | Writable scalar type and legal application range |
| `source_sha256`, `setter_kind="ordinary-assignment"`, `persistence` | Owner implementation reviewed for setter effects and runtime/persistent lifetime |
| `firmware_id`, `firmware_service/path/interface/property` | Readable firmware identity matched to that reviewed implementation |
| `object_lifetime="owner-generation"`, `generation_interface/property` | Owner-provided string generation that changes whenever this object is recreated |
| `override_interface/property` | Owner-provided Boolean proof that an MDB debug override is active; missing proof is not false |
| `allowed_ssh_users` | Approved local SSH principals; server-side permissions still apply |

The adapter checks strict SSH host identity, machine/boot/firmware identity,
unique D-Bus owner, object generation, exact MDB object-to-path binding,
introspection type/readwrite access, no override, and matching direct-owner/MDB
values. Generation/override proof properties must already be implemented and
qualified on the target. Unsupported firmware remains unavailable; this package
does not install proof properties or enable a sample device contract.

The fixed setter is `busctl set-property` addressed to the observed unique owner
and exact path. This implements the ordinary setter semantics documented for
`mdbctl setprop modify`; it is not a fallback and never uses debug `set`/`unset`.
[Official MDB semantics](https://www.openubmc.cn/docs/zh/latest/debug_tools/mdbctl_cmds/mdbctl_setprop.html)
distinguish the three modes: `set` masks underlying values, while `unset` reveals
the current underlying value rather than restoring a historical reading.

## Dispatch, uncertainty and compensation

The journal freezes the contract, before identity, expected and desired values.
A second observation rejects a changed owner/generation/value before dispatch.
This is not atomic compare-and-set: another writer can still race the setter.
Expected equals desired is a zero-write no-op with fresh verification.

Before sending the setter, Runtime persists `effects_started`. It sends at most
one setter request for this Effect and never retries a write after a timeout or
process loss. An unknown result reconciles the same Effect with read-only evidence.
Desired state on the same identity can complete verification; before/third values,
changed identity, missing proof or missing journal stay unknown/blocked. Readback
proves requested state, not causal attribution or exactly-once setter execution.

A completed replay returns the retained receipt; it is not a new observation.
The workflow's verifier reads fresh evidence and binds the same task and journal.
Persistent metadata does not establish survival across a reboot. Compensation is
a newly authorized conditional assignment from the verified current value to the
earlier value, with a new Effect; there is no automatic rollback, and any external
change must be reviewed before a replacement plan. Do not recreate a Run to evade
an unresolved Effect.
