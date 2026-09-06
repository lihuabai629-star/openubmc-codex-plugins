# Agent Gateway and Runtime Continuation

Read this reference when a task needs Runtime continuation, recovery, profile selection, or the
precise semantic contract behind `observe` and `execute`.

## Agent profile

The default `openubmc-target-runtime` profile exposes only `observe` and `execute`.

`observe` returns an inline `ObservationReceipt` in MCP `structuredContent`. Follow the entrypoint's
single-observation selector rule. Split the declared scope only when the Receipt is incomplete and
requests a narrower observation.

Do not send the legacy `assurance` hint from the Agent profile; the Runtime applies its single
automatic observation policy. Live evidence uses `max_age_seconds: 0`; freshness is a time
property, not a profile. Bind every capability conclusion and diagnostic claim to Receipt coverage.

`execute` owns stateful work. Its action kinds are:

- `start`: create and advance a Run from typed intent and delivery strategy;
- `respond`: satisfy the current Gate using its returned binding and a typed phase receipt;
- `resume`: continue the retained `run_id` without reconstructing the request;
- `control`: reconcile an unknown mutation result, or cancel only at a returned Gate/Incident.

When a Turn is `waiting_response`, load the Skill named by the Gate owner, execute that phase, and
respond once with `run_id`, `gate_id`, `gate_version`, `schema_digest`, and `response.payload`.
Return control to the user only for a terminal Outcome or a concrete blocker requiring new input,
new authority, an unavailable external capability, or unresolved mutation reconciliation.

For `diagnose-and-fix`, reusable Observation Evidence and accepted diagnosis are separate facts.
The Runtime always returns a `diagnosis.acceptance` Gate before `developer.change`, even when the
DiagnosticReceipt is complete. Complete that Gate with a grounded `root_cause`, non-empty
`evidence_ids` drawn from the current DiagnosticReceipt, `causal_chain`, `code_owner`,
`contradictions`, `remaining_gaps`, and `verification_status=verified`. Acceptance requires empty
contradictions.
The Runtime owns observation time and freshness. A plain `resume` reattaches the same unanswered
Gate and cannot make diagnosis acceptable; a failed or cancelled diagnosis terminates before
development.

## Canonical calls and preflight

Use only canonical capability names. `mdbctl` is the capability name; MDB queries use selector
kind `mdb`:

```json
{
  "target": "<BMC IP>",
  "selectors": [
    {
      "id": "capabilities",
      "kind": "capability",
      "names": ["ssh", "mdbctl"]
    },
    {
      "id": "objects",
      "kind": "mdb",
      "queries": ["lsprop Object0"]
    }
  ]
}
```

Execute deadlines are caller wait bounds from greater than zero through 120 seconds:

```json
{
  "kind": "resume",
  "run_id": "<current Run ID>",
  "deadline": 120
}
```

If resume returns the same Gate, the Turn explicitly reports:

```json
{
  "response_required": true,
  "progress": {"status": "no_progress", "reason": "response_required"}
}
```

Use the returned `next_action` Gate binding and answer it. Do not retry resume. Explicit recovery
is valid only after the same Run reports an unknown mutation outcome:

```json
{
  "kind": "control",
  "run_id": "<current Run ID>",
  "command": "reconcile"
}
```

Completed artifact-producing Gates require the full returned binding plus an `artifact_ref` bound
to the same Run and target:

```json
{
  "kind": "respond",
  "run_id": "<current Run ID>",
  "gate_id": "<current Gate ID>",
  "gate_version": 1,
  "schema_digest": "sha256:<current Gate schema digest>",
  "response": {
    "status": "completed",
    "summary": "artifact produced",
    "payload": {
      "source_revision": "<built source revision>",
      "artifact_ref": {
        "handle": "<absolute artifact path>",
        "digest": "sha256:<64 lowercase hex characters>",
        "kind": "<Gate artifact kind>",
        "size": 0,
        "provenance": "openubmc-build",
        "retention_hint": "run-lifetime",
        "target": "<current Run target>",
        "run_id": "<current Run ID>"
      }
    }
  }
}
```

Preflight failures return `error.field`, the accepted `error.limit` or `error.supported`, a
canonical `error.example`, and one `next_action`. Correct that field before retrying; validation
does not open a Run, dispatch target work, or create an Effect.

## Idempotency and recovery

The Runtime supplies or derives submission identity from the persisted Gate binding. Retrying an
identical response is idempotent; changing input, Gate identity, or Gate version is a conflict.
Mutation authority is frozen in the Run and cannot be broadened by continuation.

Unknown mutation outcomes are reconciled read-first with the same durable operation identity. If
automatic recovery cannot converge, the Turn returns an Incident with bounded allowed commands.
Use explicit reconcile only as the bounded recovery fallback. Repeated reconcile or cancel
requests reuse the existing Incident outcome instead of duplicating lifecycle facts.

The restartable TaskContext is secret-free. After a local MCP restart, reuse the task identity and
`run_id`; the Runtime restores typed intent, target bindings, workflow summaries, and mutation
journal identity, but never restores a live connection or treats an old observation as fresh.

## Target scheduling

Capability readiness may be reused only for the same declared scope, target epoch, and connection
lane epoch. Requested values are always recollected. A target replacement, connection rebuild, or
mutation epoch change invalidates readiness.

Connection bindings and leases use bounded per-task LRU caches (default capacity 32 per domain).
This is not a target-count limit: an evicted target reconnects when selected again. Replacing or
selecting a target must never leak the prior target's host, ports, credential selector, or epoch.

Cold capability checks release each evidence lane when its own prerequisites complete. MDB may
start after SSH/MDB checks, D-Bus/alarm after D-Bus and busctl checks, and log/file after Telnet;
the full preflight still remains one audit surface.

## Operator profile

Do not call `case_read`, `evidence_read`, `evidence_query`, `workflow.advance`, `workflow.next`,
`phase_record`, Replay, Session Outcome governance, or Runtime status from the Agent profile.
The legacy operations are retired. Operator operations exist for evidence discovery, CI, incident
metrics, and governance.

`workflow_remote.py` and `compare_remote.py` remain input-compatible CLI baselines but enter the
same Runtime Core. The generic CLI uses `observe` and `execute`. Historical benchmark tooling may
check out a pinned pre-retirement source for its baseline arm. New evidence kinds should become
internal selector Adapters behind `observe`, not additional Agent-facing tools.

Agent `structuredContent` remains bounded to `ObservationReceipt` or `Turn`. Raw Evidence, Case
ledgers, Runtime sequencing, incident metrics, and governance projections remain operator-facing.
