# Task handoff and terminal answer recovery

Use this reference when a host session reconnects, compacts, or loses its final
answer. Runtime remains the sole owner of Run, Gate, Incident, Effect and Outcome.
Never restart an operation because a summary or a host checkpoint is missing.

## Automatic integration

After MCP `execute`, a best-effort bookmark records the task and Run identities.
No target credentials are copied to this store. Host storage failure is metadata,
not a failed device operation. Multiple Runs stay separate within one task.

The plugin's trusted `SessionStart` hook supplies the local workflow entry and
rereads current Runtime facts. `UserPromptSubmit` supplies the same bounded entry
even when Python or prepared dependencies are unavailable; the Agent reads the
current owner's Skill from that workflow entry.
These hints are advisory and do not prove a Skill was read. The trusted
`Stop` hook can ask for one text-only final from a persisted terminal Outcome.
Do not call `execute`, `resume` or `observe` to deliver that text. An untrusted or
unavailable hook does not block the existing workflow; use the local CLI below.

If continuity or entry hints are missing, inspect the Host's native hook list.
An enabled plugin can have `untrusted` or `modified` handlers that do not run.
Package integrity and MCP readiness do not prove Hook trust. After reviewing
the installed handler and its package identity within the user's authorization,
use the Host's trust configuration for that handler's exact current hash.
Verify the returned trust status; do not infer activation from installation.
Hooks do not prepare dependencies, choose a build host, or grant trust.

## Explicit local recovery

Run on the host of the same Runtime (native Windows, Linux, or an explicitly
selected WSL environment), with its existing `OPENUBMC_TARGET_RUNTIME_STATE_DIR`.
Use the packaged script or source script:

```sh
python openubmc-debug/scripts/host_continuity.py handoff --task-id '<task-id>'
python openubmc-debug/scripts/host_continuity.py answer --task-id '<task-id>' --run-id '<run-id>'
```

In an installed plugin, the prefix is `skills/openubmc-debug/scripts/`.
These commands read the ledger without creating/migrating it or opening a target.
`answer` prints a prepared final; printing alone does not mark it delivered.
If the ledger is unavailable, restore it rather than using an old host status.

For hosts without the hook, an operator may audit an actual persisted Codex final:

```sh
python openubmc-debug/scripts/host_continuity.py audit --task-id '<task-id>' \
  --run-id '<run-id>' --rollout '/path/to/actual-codex-rollout.jsonl'
```

The audit requires the matching session, exact prepared text, and a final event
after preparation. Do not generate a synthetic rollout to certify real delivery.

## Bounded reasoning notes

Before compaction or handoff, save concise current reasoning automatically when
useful. No save confirmation is needed. Supported fields are `goal` (text) and
lists `authorization_refs`, `source_identities`, `evidence_refs`, `hypotheses`,
`contradictions`, `open_questions` (at most 32 entries each, 24 KiB total):

```sh
python openubmc-debug/scripts/host_continuity.py notes --task-id '<task-id>' \
  --notes-file '/path/to/bounded-notes.json'
```

Store references, not credentials or full raw logs. Notes are explicitly
non-authoritative, may be stale, and cannot authorize an action or prove success.
On recovery, use current Gate/Incident bindings. A terminal Outcome needs only
delivery; an unknown mutation needs the existing Incident recovery commands.
Revalidate referenced evidence before new work, using normal Runtime freshness
rules. This handoff does not silently refresh observations or copy a task into a
different session; cross-session use requires the original task identity.
