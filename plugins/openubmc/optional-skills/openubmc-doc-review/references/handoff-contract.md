# Runtime evidence handoff

Documentation-only work produces a local review report. It does not start a Run,
create an approval step or require target access. The public Agent interface has
`observe` and `execute`; legacy Case workflow and phase-record tools are unavailable.

For an existing relevant Run, carry its `run_id`, document/source revision, selected
review paths, profile, report path, confirmed findings, unverified claims and gaps.
Keep target/product evidence scoped to its actual version and collection time.
These are review facts, not a fabricated Runtime Gate response.

Use the current returned Turn:

- `running`: follow the bounded `next_action` only while this active Run belongs to
  the current task; a report does not authorize another device action.
- `waiting_response`: use the returned Gate's `input_schema`, `gate_id`,
  `gate_version`, `schema_digest` and supplied `submission_id`. Submit through
  `execute` with `kind: respond` only when the actual schema accepts the evidence.
  Do not add undocumented review fields or invent a documentation Gate.
- `incident`: preserve its Run/Effect identity and follow the advertised recovery
  policy. An unknown mutation outcome must not be replayed.
- `completed`, `failed` or `cancelled`: read the saved Outcome. Do not resume or
  observe the historical task just to deliver its review report.

For read-only product verification already authorized by the task, `observe`
accepts its target and selectors; keep the returned observation reference and
original evidence. Missing KB or target access remains a stated gap while local
checks continue. It does not create an automatic release failure or permission
request. Use [the report fields](report-contract.md) for the local verdict and
[the current Agent interface](../../../skills/openubmc-debug/references/agent-gateway.md)
for Runtime request examples.
