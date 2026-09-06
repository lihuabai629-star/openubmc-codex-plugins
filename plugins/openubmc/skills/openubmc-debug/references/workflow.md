# Read-only Combined Snapshot

Use `workflow_remote.py` when the diagnosis needs a fresh object + alarm + log/file snapshot and local source correlation.
Pass `--skip-telnet` to keep the workflow on SSH/source evidence when log/file evidence is not
needed.
Keep the working directory at the task's openUBMC repository and invoke the
bundled workflow through the canonical installed Skill path:

```bash
python "$HOME/.agents/skills/openubmc-debug/scripts/workflow_remote.py" \
  --ip <ip> \
  --mdb-query 'lsobj BusinessConnector' \
  --mdb-query 'lsobj PcieAddrInfo' \
  --mdb-expand-class PCIeDevice \
  --mdb-concurrency auto \
  --source-root <actual-repository-root> \
  --keyword '<literal>' \
  --include-rotated --rotated-limit 3 \
  --log-max-bytes 262144 \
  --json --compact-json
```

Repeat `--mdb-query` for issue-specific model reads. The workflow accepts only the same reviewed
read-only grammar as `mdbctl_remote.py`; supplying specific queries replaces the generic `lsclass`
probe and keeps every query in the same task-scoped SSH lease.

Use `--mdb-expand-class <class>` when the object names are not known in advance. The workflow first
executes `lsobj <class>`, validates and deduplicates the returned object tokens, then executes each
dependent `lsprop` through the same TargetRun. Expansion results use stable object-derived keys so
two-target comparisons align the same object instead of aligning by discovery order.

`--mdb-concurrency auto` bounds simultaneous MDB reads per target while keeping the total number of
requested queries and discovered objects unrestricted. Use an explicit positive integer for a
known target budget or `unbounded` only when the target can sustain it.

For a genuinely narrow model-only question, add `--mdb-only`. It retains start/end SSH freshness,
checks only the MDB capability at preflight, and does not enumerate D-Bus, active alarms, the bus
tree, logs, or live files.

For a narrow interactive MDB or capability read through MCP, use `observe` with exact selectors.
Object/alarm collection remains a CLI or explicit compatibility path until its selector Adapter is
available behind `observe`. Use `execute` when the task needs change-boundary verification or a
multi-surface causal conclusion.

## Contents

- Source root resolution
- Capability gate
- Execution
- Stable result
- Optional parallel analysis
- Success semantics

## Source Root Resolution

Source root resolution is: explicit `--source-root`, `OPENUBMC_SOURCE_ROOT`, then
the Git repository containing the current working directory only when one of its
remotes identifies an openUBMC repository. If the containing repository is
unrelated or the root is otherwise unresolved, remote lanes continue and source
correlation is reported as skipped. No example, author, control-plane, or Skill
repository is used as an implicit source root.

## Capability gate

The workflow starts with preflight and consumes `result.capabilities`:

- The `remote_object` capability means SSH is usable and at least one read-only object lane passed preflight: `mdbctl`, or a live D-Bus environment plus `busctl`. It does not mean every object helper is usable, and it does not verify an active-alarm endpoint. Consume the detailed
  `mdbctl`, `busctl`, and `active_alarm_transport` fields when present and independently
  run or skip each helper. An alarm transport flag proves only that endpoint discovery may
  be attempted. Pass
  `--tree-service`, `--alarm-service`, or `--alarm-path` only as explicit
  overrides.
- `remote_log_file`: run bounded log collection and live-file reads.
- `combined_snapshot`: run both evidence surfaces and correlate them.

The current helper implementation uses SSH for object tools and Telnet for log/file tools. A failed transport skips only the capability it supports; an optional helper that preflight already marked unavailable is skipped and does not disable another usable capability. A helper that was declared usable but then fails during the snapshot remains a real workflow partial failure.

Within one MCP task, a TargetRun reuses capability readiness only when the immutable ScopeContract,
target epoch, and relevant lane epochs still match. Requested values are always recollected. An
`observe` call does not open a Case. Stateful work returns a `run_id`; resume it through `execute`
instead of reconstructing Runtime operations.

During a cold typed preflight, capability checks publish readiness independently. The MDB plan may
start after SSH and MDB are ready while D-Bus and Telnet checks continue; busctl/alarm collection
waits for the D-Bus/busctl gate, and log/file collection waits for Telnet. The completed preflight
is still returned as one result, and no capability check is repeated merely to start a lane early.

## Execution

1. Capture start target time with numeric UTC offset and either establish or reuse the epoch-bound
   capability snapshot; on a cold typed run, release each evidence lane when its own capability gate
   is ready while the full preflight continues in the background.
2. Run available remote object and remote log/file lanes in parallel.
3. Extract stable `EventName`/`EventCode` terms from active alarms and perform a separate since-boot log query.
4. Run the workflow's bounded exact source search. If its result reports `codegraph_available: true`, use CodeGraph after the snapshot to expand matched symbols into callers, callees, dependencies, and impact; the workflow itself does not claim that analysis was executed.
5. Correlate definition, emitter/trigger, runtime state, instance, time, sample, and threshold evidence. Require instance + state + time on the same log reference; required measurement values must intersect that identity-aligned reference.
6. Repeat preflight, current alarms, version, and uptime for freshness. When the
   start alarm snapshot discovered one exact endpoint, re-introspect that same
   service/path for the end snapshot instead of repeating the full candidate
   scan. An invalidated endpoint is a freshness failure, not permission to hide
   the change by silently selecting a different endpoint.

All operations are read-only. A global `--deadline` bounds the workflow; per-tool `--timeout` remains subordinate to it. The wrapper may wait up to five additional seconds for a child that reached its own work deadline to serialize a structured result and exit. This completion grace never enlarges the child's remote-operation budget and is still capped by the global deadline.

The workflow forwards `--timeout` to every child's SSH timeout, Telnet
connect/login timeout, and Telnet command timeout, then rewrites those child
budgets downward when the global remaining time is smaller. A source search timeout or
failure is included in `summary.failed` and produces `workflow_partial_failure`;
a bounded search that succeeds but reports `truncated: true` remains usable
partial evidence and is not itself a command failure.

When alarms provide no stable source term, an explicit `--keyword` becomes the
bounded source-search term. With neither alarm terms nor a user keyword, source
search is `skipped` rather than a successful zero-hit query.

The Python fallback inspects only regular files and reads long physical lines in
bounded chunks. Symlinks and special files are skipped without opening them.
Walk errors or unreadable regular files return `source_search_incomplete`, expose
only bounded relative `incomplete_paths`, mark every term truncated, and cannot
support a source-level negative finding.

## Stable result

The common envelope contains `schema_version`, `tool`, `ip`, `observed_at`, `ok`, `code`, `request`, `result`, `warnings`, and `error`.

Important result fields:

- `capabilities`: evidence capabilities used for lane selection.
- `source_root_resolution.root/source`: actual root and whether it came from explicit input, environment, repository discovery, or remained unresolved.
- `lanes.ssh`: current helper results for object/alarm evidence.
- `lanes.telnet`: current helper results for log/file evidence.
- `correlation`: source/log/object evidence dimensions and completeness.
- `correlation.source_search.codegraph_available`: whether the resolved source root supports a follow-up CodeGraph call/dependency analysis.
- `freshness`: start/end comparability, alarm identity versus payload changes, version/time deltas, and uptime reboot detection using observer/BMC elapsed time.
- `freshness.status`: `complete`, `partial`, or `unavailable`, plus comparable,
  unavailable, and lost dimensions, `after_last_reboot_or_change`, and
  `stale_evidence`. A lane available at the start but unavailable at the end,
  or evidence that changed during capture, prevents unconditional success.
- `summary.executed/failed/skipped`: actual tool states.

Lane names retain transport-oriented compatibility keys; orchestration decisions use capability names.

With `--compact-json`, verbose child output is reduced to bounded previews while every child retains its command, request, `started_at`, `completed_at`, and `observed_at` without automatic masking. Canonical correlation evidence stays in `correlation.evidence_pool`: source matches carry stable `id` values, and selected alarm/workflow log lines are objects with their original `id`. `source_refs` and `log_refs` point to those IDs. Use non-compact JSON only when the bounded previews are insufficient for a specific follow-up.

## Optional parallel analysis

Keep one root owner for the target, credentials, collection, recollection, and final
report. Collect the live snapshot once. If independent source, object/alarm, and log/file reasoning
lanes remain, they may be analyzed in parallel from the same bounded snapshot.

Analysis workers must not open remote sessions, read credential sources or raw private dumps, or
recollect the target. Require every claim to cite an evidence ID or source location. Agreement
between workers is not evidence. The root resolves contradictions, rejects unsupported negative
findings, and invalidates old analysis after any reboot, recollection, or change boundary.

## Success semantics

- `ok`: every executed required child succeeded within the deadline.
- `workflow_partial_failure`: at least one required executed child failed; unavailable capability lanes remain `skipped`.
- `workflow_deadline_exceeded`: the global budget prevented completion.

Child failure codes remain visible. Missing source correlation, unavailable transport, or stale snapshots must not be rendered as successful negative evidence.
