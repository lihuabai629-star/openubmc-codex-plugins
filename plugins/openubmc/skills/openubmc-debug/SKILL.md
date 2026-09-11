---
name: openubmc-debug
description: "Diagnose openUBMC/BMC runtime problems: 设备不识别、传感器异常、告警、服务启动失败、接口报错、两台 BMC 对比。Use for live target symptoms, a supplied BMC IP, diagnostic handoff, or post-upgrade verification; correlate source, MDB/D-Bus, Redfish, logs, and optional OS evidence. Remote diagnosis is read-only; route implementation, builds, upgrades, and file replacement to their owning skills."
---

# openUBMC Runtime Debug

## Scope and ownership

Own read-only runtime diagnosis and post-change verification. Infer whether the request is:

- diagnosis: explain and localize a current or reproduced symptom;
- delivery verification: verify requested behavior on the deployed target.

Accept prose or a concise handoff; do not require a transport envelope. Keep diagnosis separate
from implementation:

- source or design change -> `openubmc-developer` or the matching specialist;
- component or product build -> `openubmc-build`;
- firmware upgrade or rollback -> `openubmc-upgrade`;
- temporary runtime replacement -> `openubmc-live-patch`;
- offline dump or log-bundle-only analysis -> `openubmc-log-analyzer`.

## Choose `observe` or `execute`

Use the default `openubmc-target-runtime` MCP through its semantic Agent Interface:

- For current systemd service failures, use a `systemd` selector with literal `.service` names
  or `["failed"]` discovery; see the Agent semantic interface reference below.
- Call `observe` for an exact read-only question. Declare only the selectors needed for the
  answer. A narrow MDB or capability query should complete in one call and return an inline
  `ObservationReceipt`.
- Treat one answer as one observation: combine related capability, MDB and systemd selectors needed for
  the answer in the same `observe` call. Do not run a separate capability preflight; the internal
  Observation Adapter performs it.
- Call `execute` when work can cross diagnosis, source change, build, live patch, upgrade,
  recovery, verification, or acceptance phases, including a read-only diagnosis Run.
- A build-upgrade Run that requires exact Drive convergence may carry a bounded
  `hardware_acceptance.devices` declaration in its Debug entry arguments. It is validated
  before mutation but applied only to post-upgrade `debug_collect`: missing, unhealthy,
  unidentified, protocol-mismatched, or incorrectly attributed Drives keep verification
  `partial` so the same Runtime step recollects fresh evidence instead of forming an early
  success Outcome.
- An `ObservationRef` proves reusable observation evidence; it does not by itself prove a root
  cause. Every diagnosis workflow reaches the Runtime-owned `diagnosis.acceptance` Gate before
  `developer.change`, including a complete collection receipt.
- Answer `diagnosis.acceptance` once with the returned `run_id`, `gate_id`, `gate_version`, and
  `schema_digest`. A completed response supplies `root_cause`, non-empty `evidence_ids` drawn only
  from the current DiagnosticReceipt, `causal_chain`, `code_owner`, `contradictions`,
  `remaining_gaps`, and `verification_status=verified` when accepting the diagnosis. Contradictions
  must be empty for acceptance. The Runtime derives observation time and freshness from its
  persisted evidence; do not restate or invent them.
- `execute(kind=resume)` only reattaches the current Run. It does not answer or repair an
  unanswered diagnosis Gate, so an unchanged Gate is not a reason to retry resume. Mark the Gate
  failed or cancelled when no defensible diagnosis can be formed; development must remain closed.
  `response_required=true` with `progress.status=no_progress` means respond using the returned
  binding instead of issuing another resume.
- Treat one `ObservationReceipt` or `Turn` as the semantic result. Capability is tri-state:
  `available`, `unavailable`, or `not_checked`; never infer an unobserved capability.
- In an `execute` MCP result, inspect `structured_content.diagnostic_receipt`; the short `content`
  text is only a state summary. If the receipt exists, do not report that `execute` returned only
  generic completion. Treat every result with `status=available` and a substantive `value` or
  bounded `summary` as citable visible evidence. Raw Evidence bytes do not need a separate read.
  `projection_truncated` and `content_compacted` describe the display; determine source
  completeness from the receipt's `truncated`, `content_complete`, freshness, coverage, and gaps.
- Do not use compatibility or operator operations from the default Agent profile.

For a read-only diagnosis, replace the target and purpose in this complete `execute` Action:

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

One surface is sufficient only for a narrow value or definition lookup. Knowledge retrieval may
route candidates, but it is not evidence and never blocks live or source collection.

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

Return a concise report unless machine-readable output was requested:

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

- Keep all remote actions read-only. Never restart services, mutate properties, upload, upgrade,
  replace files, or invoke arbitrary methods from this Skill.
- Bound object trees, logs, files, source searches, deadlines, and output. Preserve timestamps and
  relevant excerpts.
- Treat current alarm reads as current state and historical event APIs as history.
- Keep failures, stale evidence, unavailable capabilities, and incomplete collection explicit.

## Reference routing

Read only the directly relevant one-hop references:

- Agent semantic interface and Runtime continuation: `references/agent-gateway.md`
- Remote credentials, preflight, helpers, concurrency, and target automation: `references/remote-automation.md`
- Evidence selection and correlation: `references/evidence-workflow.md`
- Hypothesis-directed Drive diagnosis and fault-chain comparison: `references/diagnostic-advice.md`
- Combined snapshot details: `references/workflow.md`
- Structured result fields: `references/diagnostic-contract.md`
- Focused mechanism checks: `references/mechanism-debugging.md`
- Knowledge candidate routing: `references/knowledge-routing.md`
- Optional user-configured integrations: `references/optional-integrations.md`
- Component ownership hints: `references/components.md`
- MDB access: `references/mdbctl-access.md`
- D-Bus access: `references/busctl-access.md`
- Generic object access: `references/object-access.md`
- Active alarm access: `references/alarm-access.md`
- Runtime log access: `references/logs.md`
- Live file access: `references/file-access.md`
- Comparison result schema: `references/openubmc-debug-compare-v1.schema.json`
