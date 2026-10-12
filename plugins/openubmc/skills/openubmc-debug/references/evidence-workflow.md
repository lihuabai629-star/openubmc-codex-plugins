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

For a workspace containing both community and internal repositories, bounded
search now attaches per-hit repository, commit, branch, inspected-file digest and
modification status. Declare the product/component mapping once in the optional
`<source-root>/.openubmc/source-catalog.json`. Missing or invalid mapping never
blocks search; results remain unclassified/reference evidence. A community copy,
wrong-product checkout or wrong pinned commit cannot become a product owner just
because the symbol or directory name matches.

```json
{
  "schema_version": 1,
  "product": "board-a",
  "repositories": [
    {
      "path": "community/network_adapter",
      "origin": "community",
      "component": "network_adapter",
      "products": ["board-a"],
      "role": "reference"
    },
    {
      "path": "internal/network_adapter",
      "origin": "internal",
      "component": "network_adapter",
      "products": ["board-a"],
      "role": "implementation"
    }
  ]
}
```

Paths stay under the source root. `origin` is `community`, `internal`, `third_party`
or `unknown`; `role` is `reference` or `implementation`. Optional `commit` pins a
full immutable Git hash. Product/ownership labels are local declarations, not
externally verified facts. A matching implementation is a `product_source_candidate`,
not proof of deployed firmware or runtime execution. Another product, a pinned
revision mismatch, or a reference-only tree cannot contribute product implementation
alignment. Two selected implementations of one component remain ambiguous; neither
silently wins. Unmapped repositories stay `unknown` rather than guessing ownership
from their names or remote visibility.

Metadata lookup supports linked worktrees and is bounded to 32 repositories,
2 seconds and the remaining search budget. File identity reads at most 1 MiB per
matched file, without Git clean filters/hooks; `modified` covers that file only.
Metadata failure yields warnings, never a search failure. Compact Evidence pools
retain the annotations. This is local attribution, not a remote index upload.

For a bounded offline lookup across Lua, C/C++ and model/configuration files,
use the packaged Debug helper's query mode:

```bash
python <debug-skill>/scripts/source_trace.py --source-root <mixed-source-root> --query '0xE001' --timeout 8
```

The disposable SQLite index defaults to a private file under the user's cache
directory; `--index-path` selects another cache file. It hashes each supported
source file and rebuilds token/line entries only when content changes. Search
results resolve catalog selection, repository root, commit, branch and file
modification state at query time. `index.updated_files`, `unchanged_files` and
`removed_files` describe that pass. `source.dirty` covers the matched file, not
the whole checkout. Exact identifiers and paths rank first; query text without
indexable identifiers uses the existing bounded source search. An unreadable or
unavailable index also falls back to that search with `status=partial`. A
language service is not required; syntax resolution remains the separate Lua
trace below or a corroborated CodeGraph result.

For a natural-language question, optionally save the already obtained
`openubmc_kb_query` JSON MCP receipt and pass `--kb-result-file <receipt.json>`.
The helper reads at most 64 KiB, accepts only bounded `reference_id` and
`file_path` labels, and does not call the KB itself. Returned KB rows are
`knowledge_candidate` entries with `applicability=unverified`; they never
inherit a local source product or commit. A KB outage yields `status=partial`
while retaining local hits. `evidence_ref` and `freshness` bind each local
result to inspected bytes and query time. The index can cover at most 4,096
files and 64 MiB per pass by default; partial coverage, truncation and missing
provenance remain visible. Neither a local hit nor a KB candidate proves the
source was deployed or that the path executed on a target.

Distinguish these evidence levels:

- definition: constant, event dictionary, schema, or interface declaration
- emit: code that reports/returns/signals the failure
- trigger: predicate and state that select the failing branch
- owner: service/module responsible for the trigger
- caller: direct entry into the responsible behavior

A definition hit alone cannot establish root cause.

When a symbol hit leaves the caller or owner unresolved, inspect bounded Lua
references using the installed Debug helper:

```bash
python <debug-skill>/scripts/source_trace.py --source-root <repository> --symbol <qualified-symbol>
```

Use a qualified symbol to narrow duplicate terminal names. The result binds
declarations, direct call candidates, callback registration candidates and value
references to exact file bytes and the observed Git revision. Generated paths
including `gen/` are marked. `source.dirty` compares only inspected Lua bytes
with raw committed blobs; it is not a whole-worktree status. `incomplete` and
`gaps` preserve unreadable files, limits, unsupported
languages and unresolved dispatch; increase scope only when the missing evidence
is needed. The helper reads Lua syntax without executing project code. Aliases,
dynamic table lookups and runtime registration require direct inspection or
CodeGraph corroboration. Static references do not prove that a call executed;
retain the runtime instance, time and state evidence before accepting an owner
or causal path.

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

The OS probe is fixed and read-only: host identity plus a bounded PCI sample. It uses the
internal-development `insecure` SSH host-key policy. Keep its target, timestamp, command, and
result separate from BMC evidence. Host visibility may corroborate that hardware is visible to
the OS, but it does not establish why a BMC model object is absent.

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

### Local evidence batch

`_evidence_batch.summarize_captured_snapshot` accepts only already captured `active_alarms` and `collect_logs` helper results. Pass the explicit target, source version and target epoch from the capture boundary. It groups exact duplicate events or lines within their source and path, retains a count and every `/alarms/...` or `/logs/...` raw pointer, and labels unknown timezone, failed timestamp parsing, missing physical sequence and partial collection. A grouped line is a display view; the original helper result remains the evidence.

`compare_snapshots(before, after)` reports `incomparable` when target, source version or target epoch is unknown or differs, or either collection is partial. It never uses a matching log line to infer a cause. The combined workflow's `correlation.records[].temporal_relation` reports a bounded time match with `causal_proof=false`; source ownership and trigger still need independent evidence. If local batch processing fails, `correlation.batch` says `processor_failed` and the original evidence pool remains available.

Compact workflow JSON groups exact duplicate selected log lines; each group keeps `ids` for every original `log_refs` index and `pointers` back to each raw line. Full workflow JSON still contains the unmodified captured lanes. The compact `batch` carries counts and uncertainty flags without repeating all group text.

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

## Optional source-search failure

`source_search_failed` means the auxiliary local source lookup failed, not that
the device observations failed. Retain collected alarm/log lanes, finish normal
freshness checks, and report the missing source correlation. After fixing the
catalog/index, retry only the missing local lookup when the evidence is still
valid; do not repeat a device operation merely to reconstruct a source result.
