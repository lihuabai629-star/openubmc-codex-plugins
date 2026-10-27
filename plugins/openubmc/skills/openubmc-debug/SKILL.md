---
name: openubmc-debug
description: "Diagnose openUBMC/BMC runtime problems: 设备不识别、传感器异常、告警、服务启动失败、接口报错、两台 BMC 对比。Use for live symptoms, diagnostic handoff, delivery verification, or authorized MDB property adjustment. Diagnosis is read-only; assignments use Runtime execute. Route source, builds, upgrades, and patches to their owners."
---

# openUBMC Runtime Debug

At a stage change, read [the phase handoff](<references/skill-routing.md>) and its owner; carry the Run and authorization.

Resolve `<plugin-root>` from the active Skill file's parent `skills` directory.
Use helpers from that installation.

## Scope and ownership
Diagnose live symptoms and verify requested deployed behavior.

Route by task:
- source or design change -> `openubmc-developer` or the matching specialist;
- component or product build -> `openubmc-build`;
- firmware upgrade or rollback -> `openubmc-upgrade`;
- temporary runtime replacement -> `openubmc-live-patch`;
- remote bundle collection -> `openubmc-log-analyzer`;
- local bundle analysis -> `openubmc-log-bundle-analyzer`.
- Save an explicitly confirmed BMC/OS address association -> `openubmc-environment-setup`.

## Choose `observe` or `execute`

Use the default `openubmc-target-runtime` MCP through its semantic Agent Interface:

- For service failures, use a `systemd` selector with literal `.service` names or `["failed"]`.
- For an authorized OS task with BMC IP and no OS IP, select `os_console`; see its reference below.
- Call `observe` for an exact read-only question using only required selectors.
  Use the established target and credentials. Internal Gate response fields are
  filled by the Agent from evidence; they are not requests for human approval.
  A narrow MDB or capability query should complete in one call and return an inline
  `ObservationReceipt`.
- Combine capability, MDB, systemd and OS-console selectors in the same `observe` call.
  Do not run a separate capability preflight.
- Call `execute` for diagnosis Runs, source changes, builds, patches, upgrades, verification
  or an authorized MDB assignment. Read its property reference before any assignment.
- A build-upgrade Run may declare `hardware_acceptance.devices` for exact Drive convergence.
  Only post-upgrade `debug_collect` applies it: missing, unhealthy, unidentified or
  protocol-mismatched Drives keep verification partial and require fresh evidence.
- An `ObservationRef` proves reusable observation evidence; it does not by itself prove a root
  cause. Every diagnosis workflow reaches the Runtime-owned `diagnosis.acceptance` Gate before
  `developer.change`, including a complete collection receipt.
- Answer `diagnosis.acceptance` using its returned binding and input schema.
  Accept only a verified causal chain supported by non-empty evidence IDs from
  the current DiagnosticReceipt, with an identified owner and no contradictions.
  The Runtime derives observation time and freshness from persisted evidence.
- `execute(kind=resume)` reattaches the Run; it cannot answer an unanswered Gate.
  For `response_required=true` and `progress.status=no_progress`, submit the
  returned Gate binding. When no defensible diagnosis exists, fail or cancel
  that Gate and preserve the gap while continuing independent authorized work.
- For `completed`, `failed`, or `cancelled`, deliver the Outcome and remaining gaps.
  A terminal Run stays terminal when resumed. Start a new Run for a new target or intent,
  record its link to the prior Run, and use its returned bindings. An unknown Effect instead
  retains its original Run, Incident and Effect identities for recovery.
- Treat one `ObservationReceipt` or `Turn` as the semantic result. Capability is tri-state:
  `available`, `unavailable`, or `not_checked`; never infer an unobserved capability.
- In an `execute` MCP result, inspect `structured_content.diagnostic_receipt`; `content` is a state
  summary, not the full result. Treat every result with `status=available` and a substantive `value` or
  bounded `summary` as citable visible evidence. Raw Evidence bytes do not need a separate read.
  `projection_truncated` and `content_compacted` describe the display; determine source
  completeness from the receipt's `truncated`, `content_complete`, freshness, coverage, and gaps.
- Do not use compatibility or operator operations from the default Agent profile.
Windows/WSL: see `references/windows-routing.md`.

For read-only diagnosis, fill the target and purpose in this `execute` Action:

```json
{
  "kind": "start",
  "intent": "diagnosis-only",
  "target": "<BMC IP>",
  "purpose": "Explain the reported service failure using read-only evidence",
  "deadline": 60
}
```

Put the symptom and requested conclusion in `purpose`. `diagnose` is not an accepted intent;
`symptom` is not an Action field. Omit a delivery strategy for diagnosis-only work. The deadline
is the caller wait bound, greater than zero and at most 120 seconds. Before adding collection
arguments or continuing the Run, read the Agent Gateway reference. A valid start proves no
diagnostic conclusion; only current evidence and an accepted diagnosis can support completion.

## Diagnostic workflow

### 1. Frame the question

Record the symptom or acceptance item, target/source scope, expected behavior, and the last reboot,
replacement, upgrade, reload, or other change boundary. “Now” requires fresh evidence.

### 2. Select a delivery route when fixing

Choose from the diagnosed edit boundary and requested outcome:

- `source-only`: complete source changes and local validation without changing a target;
- `live-patch`: temporarily deploy a runtime-compatible file, then recollect fresh evidence;
- `build-upgrade`: build a verified artifact, upgrade it, then recollect fresh evidence.

Use `source-only` until a concrete mutation route exists. Preserve target, credentials, purpose,
and delivery intent already present in the task. Debug never performs the mutation itself.

### 3. Compose an evidence plan

Use two to four complementary evidence surfaces for a composite causal claim:

- source/configuration: definition, emitter, trigger, owner, caller, generated boundary;
- northbound interface: Redfish, IPMI, Web, CLI, or another exposed contract;
- object/alarm: current MDB/D-Bus objects, properties, services, and active alarms;
- log/file: bounded timeline, loaded configuration, transition, or startup evidence;
- OS/hardware: host-side visibility only when explicitly relevant and accessible.

Use one surface only for a narrow lookup. Knowledge routes candidates but is not evidence.

### 4. Collect and correlate

Use the smallest exact selectors that answer the question. Run independent read-only surfaces in
parallel when useful, while keeping one owner for target access and credentials. For comparisons,
apply the same request and freshness boundary to every target.

Correlate by stable identity and time: object path, component or slot, event identity, BDF, state
transition, sample/threshold, target timestamp, and reboot/change boundary. A definition hit,
similar incident, or knowledge match does not prove root cause. Treat absence as evidence only
after a successful, bounded, complete query observed it; timeouts and truncated reads remain gaps.

### 5. Conclude or route

Identify the strongest evidenced owner and editable boundary. Route a source change only when the
caller/trigger or exposed contract supports ownership. Otherwise state the next missing read-only
observation. For delivery verification, account for every requested item and keep deployed target
identity separate from local source or package evidence.

## Result contract
Report concisely unless machine-readable output was requested:

1. status and shortest evidence-backed conclusion;
2. target/source scope and freshness boundary;
3. evidence with surface, query, observation time, finding, and limitation;
4. causal chain or acceptance results;
5. contradictions, unavailable surfaces, and unverified claims;
6. next read-only check or owning Skill.

For a terminal Run, use the Runtime Turn and authoritative Outcome. Only an explicit compatibility
closeout may supply `closeout_markdown` and `closeout_bundle`; phase completion alone is not
business acceptance.

## Read-only invariants

- Keep all remote actions read-only in diagnostic helpers and `observe`. BMC SSH
  and the typed property workflow reuse the configured host-key policy; no extra
  strict-host prerequisite is added for an already authorized property assignment.
- Bound object trees, logs, files, source searches, deadlines, and output. Preserve timestamps and
  relevant excerpts.
- Treat current alarm reads as current state and historical event APIs as history.
- Keep failures, stale evidence, unavailable capabilities, and incomplete collection explicit.

## Reference routing

Read the relevant one-hop references:

- Run, Gate and recovery: `references/agent-gateway.md`, `references/host-continuity.md`
- Remote credentials, preflight, helpers, concurrency, and target automation: `references/remote-automation.md`
- OS identity/network through BMC SOL: `references/os-console.md`
- Evidence selection and correlation: `references/evidence-workflow.md`
- Hypothesis-directed Drive diagnosis and fault-chain comparison: `references/diagnostic-advice.md`
- Combined snapshot details: `references/workflow.md`
- Structured result fields: `references/diagnostic-contract.md`
- Focused mechanism checks: `references/mechanism-debugging.md`
- Knowledge candidate routing: `references/knowledge-routing.md`
- Optional user-configured integrations: `references/optional-integrations.md`
- Component ownership hints: `references/components.md`
- MDB access: `references/mdbctl-access.md`
- Authorized MDB assignment and recovery: `references/property-modification.md`
- D-Bus access: `references/busctl-access.md`
- Generic object access: `references/object-access.md`
- Active alarm access: `references/alarm-access.md`
- Runtime log access: `references/logs.md`
- Live file access: `references/file-access.md`
- Comparison result schema: `references/openubmc-debug-compare-v1.schema.json`
