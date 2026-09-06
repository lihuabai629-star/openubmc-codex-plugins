# Evidence Workflow

Use this reference to compose a diagnostic plan from the evidence surfaces relevant to the claim.
Most causal questions need two to four complementary surfaces; a narrow value or definition lookup
may use one surface but must not be promoted into a root-cause conclusion.

## Contents

- Source resolution
- Evidence planning
- Capability selection
- Local evidence
- Remote object evidence
- Remote log/file evidence
- Optional OS-host corroboration
- Combined snapshot
- Cross-target comparison
- Red quality
- Direct runtime final report

## Source resolution

Resolve source only from:

1. Developer handoff repository/worktree
2. explicit `--source-root` or `--repo-root`
3. `OPENUBMC_SOURCE_ROOT`
4. git root containing the current working directory, only when one of its
   remotes identifies an openUBMC repository

An unresolved or unverified repository produces no source root; it never
triggers a fallback to an example, author, control-plane, or Skill directory and
cannot support a negative source finding.

## Evidence planning

Treat source/configuration, northbound interface, object/alarm, log/file, and optional OS/hardware
visibility as composable surfaces. Select the smallest set that can prove or disprove the current
claim, normally two to four for a composite runtime failure.

Knowledge-base results are candidate routing only. They may suggest an owner, property, keyword, or
similar incident, but they do not count as one of the evidence surfaces.

## Capability selection

Keep the working directory at the task's openUBMC repository and run the helper
through its canonical installed Skill path:

```bash
python "$HOME/.agents/skills/openubmc-debug/scripts/preflight_remote.py" \
  --ip <ip> --json --compact-json
```

Add `--skip-telnet` when SSH-backed object/alarm evidence is needed. Use `--mdb-only` when MDB is
the only required object lane so preflight does not probe D-Bus or busctl.

Use `result.capabilities`, not failed optional checks or a transport preference:

- `remote_object`: at least one read-only object lane is usable.
- `remote_log_file`: bounded runtime log/live-file evidence is usable.
- `combined_snapshot`: both remote evidence surfaces are usable in the same snapshot.

Compatibility aliases such as `ssh_object` or `telnet_files` may appear in older automation. New orchestration consumes the evidence capability names.

The `remote_object` capability means SSH is usable and at least one read-only object lane passed preflight: `mdbctl`, or a live D-Bus environment plus `busctl`. It does not mean every object helper is usable, and it does not verify an active-alarm endpoint.

When available, also consume `mdbctl`, `busctl`, and `active_alarm_transport`
separately. The compatibility `active_alarms` preflight flag means the transport
prerequisites can attempt discovery; it does not verify an endpoint.
`mdbctl` can remain usable without a D-Bus environment; bus/alarm helpers require
the live D-Bus environment reported by preflight.

The bundled helpers currently implement object access over SSH and log/file access over Telnet. This implementation fact is not a routing law. If a target exposes a different validated read-only channel, record the actual transport.

## Local evidence

Search stable error text, EventName/EventCode, object path, property, interface, or stack symbols. With `.codegraph/`, use CodeGraph for caller/callee, dependency, and impact; use `rg` for exact strings and files. Without `.codegraph/`, use `rg` and direct source inspection.

Distinguish these evidence levels:

- definition: constant, event dictionary, schema, or interface declaration
- emit: code that reports/returns/signals the failure
- trigger: predicate and state that select the failing branch
- owner: service/module responsible for the trigger
- caller: direct entry into the responsible behavior

A definition hit alone cannot establish root cause.

## Remote object evidence

Capture the exact service, object path, interface, member/property, method signature, state, and target clock. Prefer `mdbctl` for model-oriented exploration and `busctl` for precise D-Bus semantics. Treat business-error text as failure even when the shell exit code is zero.

For active alarms, introspect the live interface before calling `GetAlarmList`. Keep historical event queries separate from current-alarm state.

## Remote log/file evidence

Bound reads by files, keyword, line count, rotation range, or boot time. Record whether `since-boot` was actually applied. A missing log/file, truncated transport frame, or unreadable rotation is a failure or limitation, not an empty successful observation.

## Optional OS-host Corroboration

Enter this auxiliary lane only when the question explicitly requires host-side visibility and the user supplied `OPENUBMC_OS_*` access. It is not a fifth BMC capability and does not replace object, alarm, log, or file evidence.

```bash
python "$HOME/.agents/skills/openubmc-debug/scripts/doctor.py" --ip <bmc-ip> --os-check --json --compact-json
```

The OS probe is fixed and read-only: host identity plus a bounded PCI sample. Keep its target, timestamp, command, and result separate from BMC evidence. Host visibility may corroborate that hardware is visible to the OS, but it does not establish why a BMC model object is absent.

## Combined snapshot

Use the combined collector when both object/alarm and log/file evidence are needed.

Take start and end snapshots when freshness matters. Correlate with stable fields:

- EventName/EventCode
- component name/location/labelled instance
- Assert/Deassert or equivalent state transition
- sample and threshold/state values
- object path/property
- target timestamp and reboot boundary

Mark correlation complete only when the claim's required dimensions and semantic source relationship are present. Preserve type-level, instance-level, time-aligned, and implementation-candidate evidence as different strengths.

Do not assemble completeness from unrelated lines. Instance, state, and timestamp must intersect on at least one log reference. When measurement evidence is required, sample/reading and threshold/limit must also intersect on that same identity-aligned reference. Keep the individual hits as partial evidence when these intersections are empty.

Do not assemble a root cause from unrelated source hits. The bundled bounded search may identify an `implementation_candidate` only when emit, trigger, and any required sample/threshold dimensions occur in one source file. Even that candidate is not a root cause until direct inspection or CodeGraph evidence proves the responsible owner and caller/callee path. Tests, examples, generated dictionaries, and similarly named modules must remain supporting evidence rather than closing the causal chain.

Convert log timestamps only with the target's captured numeric UTC offset (for example, `+0800` as `480` minutes). A timezone abbreviation or a missing offset is not enough to compare a local log timestamp with an epoch alarm timestamp.

For start/end alarm snapshots, report stable identity changes separately from mutable payload changes. Mutable payload includes state, severity, timestamp, sample/reading/value, threshold/limit, and unit. Compare uptime growth with observer or BMC elapsed time so a reboot is still detected when the new uptime has already grown beyond the old uptime.

## Cross-target comparison

Use `compare_remote.py` for two or more targets. Repeat `--candidate-ip` to compare one reference
with any number of candidates, or repeat `--target` for a symmetric comparison without inventing a
reference role. There is no fixed maximum target count. `--concurrency` and the global deadline
provide scheduling and backpressure; queued targets remain visible in scheduler metadata. The
scheduler submits only a concurrency-sized sliding window instead of constructing one Future for
every target at once.

Apply one equivalent request, evidence scope, source-root policy, and freshness boundary to every
target. Each target owns its own runtime lease and connection state. Do not share a session across
targets, and do not let one target failure discard completed evidence from the others. A failed or
timed-out target produces a partial comparison with a target-local failure.

In reference/candidate mode, compare the reference with each candidate rather than generating all
candidate-to-candidate pairs. In symmetric mode, group equal values and capability support instead
of generating an unbounded pairwise diff. Preserve every raw single-target result and normalize
only the comparison view.

```bash
python "$HOME/.agents/skills/openubmc-debug/scripts/compare_remote.py" \
  --reference-ip <reference-ip> \
  --candidate-ip <candidate-ip-1> \
  --candidate-ip <candidate-ip-2> \
  --concurrency auto --json
```

## Red quality

Strong red feedback is repeatable and changes under the future fix while keeping the same input. Preferred seams are failing UT/IT, stable replay, API/object request, coredump stack, or a read-only runtime query with an explicit expected state.

Intermittent feedback remains usable when repeatability and capture conditions are explicit. A single stale log line, keyword hit, or event definition is supporting evidence, not a complete red.

## Direct Runtime Final Report

For a direct runtime request without an existing cross-Skill handoff, return a concise
human-readable report rather than inventing a transport envelope. Use this order:

1. **Status and conclusion**: `completed`, `partial`, `blocked`, `routed`, or `failed`, followed by the shortest evidence-backed conclusion.
2. **Scope**: target or resolved source root, selected evidence surfaces, and diagnostic question.
3. **Freshness**: capture time, target clock/uptime/version when available, reboot/change boundary, and excluded stale evidence.
4. **Executed evidence**: commands or queries, timestamps, bounded results, and artifact paths.
5. **Findings**: separate positive findings from negative findings. Report absence only after a successful bounded query observed it.
6. **Gaps**: unavailable capabilities, failed or truncated collection, unresolved ownership, and every unverified claim.
7. **Ownership and next action**: evidenced owner/call/generated boundary when relevant, the next read-only check, and `next_skill` when routing is justified.

If the user requests machine-readable output for a direct runtime task, preserve these same
sections in a task-local JSON object, but do not label it as the canonical Developer result.
