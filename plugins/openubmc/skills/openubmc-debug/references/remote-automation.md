# Remote Automation Contract

Read this file after choosing a remote evidence path. It defines credentials, capability preflight, JSON output, and diagnostic dumps.

## Contents

- Command path and working directory
- Explicit credentials
- Capability preflight
- Orchestration entrypoints
- Task iteration and delivery deduplication
- Common JSON envelope
- Helper boundaries
- Debug dumps
- Transport security and local dependencies

## Command Path and Working Directory

Keep the working directory at the task's openUBMC repository so source-root discovery remains
valid. Invoke each selected bundled helper from the canonical installed Skill path, for example
`python "$HOME/.agents/skills/openubmc-debug/scripts/preflight_remote.py" ...`; do not change into the
Skill directory merely to run a helper.

## Explicit credentials

Internal development behavior is enabled by default. Helpers accept direct `--ssh-password`,
`--telnet-password`, and `--os-ssh-password` values, default SSH host-key verification to
`insecure`, allow sensitive path/member reads, and skip result redaction.

The Skill contains no username, password, token, key, or credentials-file default. Use one user-supplied source:

- explicit username plus password environment-variable name
- standard `OPENUBMC_SSH_*`, `OPENUBMC_TELNET_*`, or `OPENUBMC_OS_*` environment variables
- SSH key/agent with an explicit user when required
- `OPENUBMC_CREDENTIALS_FILE` pointing to a user-selected mode-0600 file
- the compatibility alias `OPENUBMC_DEBUG_CREDENTIALS_FILE` for an existing debug-only setup
- an explicitly declared isolated test fixture

Resolution order is an explicit `--*-password-env` selector, then the standard password environment variable, then an empty value for key/agent or an intentionally credential-free test target. For a selected name, an explicit environment export takes precedence over the credentials-file mapping. Non-secret usernames and ports may still be CLI arguments. A credentials file is parsed only when one of the two file selectors is explicitly set. If both selectors are set, they must resolve to the same path or parsing fails before any value is returned.

Password-value flags are accepted directly.

```bash
export OPENUBMC_SSH_USER='<user>'
export OPENUBMC_SSH_PASSWORD='<secret>'
export OPENUBMC_TELNET_USER='<user>'
export OPENUBMC_TELNET_PASSWORD='<secret>'
python "$HOME/.agents/skills/openubmc-debug/scripts/preflight_remote.py" --ip <ip> --json --compact-json
```

For an explicit file:

```bash
export OPENUBMC_CREDENTIALS_FILE='<private-credentials-file>'
python "$HOME/.agents/skills/openubmc-debug/scripts/preflight_remote.py" --ip <ip> --json --compact-json
```

The file uses one `KEY=VALUE` entry per non-comment line. Its allowlist is the documented `OPENUBMC_SSH_*`, `OPENUBMC_TELNET_*`, and `OPENUBMC_OS_*` access keys plus `REDFISH_USERNAME` and `REDFISH_PASSWORD`. `REDFISH_BASE_URL` is target metadata and must remain an ordinary environment variable, not a credentials-file entry. The same file may be selected by openubmc-upgrade, which reads only the Redfish pair; Build does not read either credentials-file selector and does not manage remote credentials.

Single- or double-quoted values are accepted only when the quotes are balanced. The file must exist, contain valid UTF-8, be a regular non-symlink file owned by the current user, have mode 0600 or stricter, and be no larger than 64 KiB. The loader opens it non-blocking and rechecks the byte limit while reading, so FIFOs, device files, size races, and oversized inputs fail closed instead of hanging or consuming unbounded memory.

Because selecting this file is explicit, configuration errors fail fast: missing files, malformed lines or quotes, unknown keys, and conflicting duplicate keys are errors rather than ignored input. Identical duplicate entries are harmless. Validation is atomic: the loader returns a mapping only after the whole file passes, never writes `os.environ`, and identifies only the class/line of an error. Each resolver call parses the currently selected file, so changing selectors in one process cannot inherit values from an earlier file. Environment exports remain unchanged and take precedence over matching file keys. `doctor.py` merges the mapping only for credential-presence reporting; it does not export file values.

Internal development mode accepts direct credential arguments. Commands, diagnostic results, and debug dumps preserve collected values instead of applying an automatic masking pass. Prefer environment-variable selectors or the credentials file when they make repeated use more convenient; they are not mandatory safety gates.

When a machine-readable Debug result records credential provenance, use a source category
such as `user_supplied: environment`, `credential_helper: credentials_file`, or
`credential_helper: ssh_identity_or_agent`. Keep provenance separate from collected evidence; the
doctor and raw dump may still expose the exact configured values or paths needed for diagnosis.

## Transport security and local dependencies

SSH-backed lanes require the local `ssh` executable. `sshpass` is conditional on password
authentication; key/agent authentication does not need it. `rg` is conditional on local source
analysis when CodeGraph is unavailable. Missing executables are capability gaps: return stable
metadata (for example `ssh_client_missing` with return code `127`) and route preparation to
`openubmc-environment-setup` instead of installing from this Skill.

BMC SSH host-key verification defaults to `insecure` in the internal-development workflow so a
replaceable BMC whose key changes does not trigger a user confirmation loop. The transport emits
`ssh_host_key_verification_disabled`. `OPENUBMC_SSH_HOST_KEY_POLICY` or an explicit argument may
override the BMC lane with `strict` or `accept-new`; under either verified policy, host-key mismatch
or unknown-key failures are classified as `ssh_host_key_verification_failed` rather than generic
SSH failure. Machine-readable metadata records the effective policy, its source, and only the
known-hosts source category (`ssh_default`, `environment`, `explicit_argument`, or `disabled`),
never the known-hosts path.

This default is limited to BMC access. `doctor.py --os-check` explicitly keeps OS-host SSH at
`strict`; never inherit the BMC policy into `OPENUBMC_OS_*` access.

Typed Debug object and alarm reads may reconnect and replay once only when an established SSH
ControlMaster is lost during that explicitly read-only request. Unclassified or mutating SSH
operations keep the Runtime default of no replay. Runtime status records the recovery as
`ssh_replay_safe_retries`.

Typed Debug log and file reads keep their independent Telnet session and may likewise reconnect
and replay once when the framed read proves that the session closed or became incomplete. Generic
Telnet commands retain the Runtime default of no replay, and command exceptions remain
non-replayed. Runtime status records the read-only recovery as `telnet_replay_safe_retries`.

For a bounded real-target recovery check that mutates no BMC service or file, run
`openubmc-debug-dev/tools/verify_target_runtime_recovery.py --ip <ip> --json`. The verifier opens
the task-owned SSH/Telnet lanes, performs fixed read-only clock reads, closes only its own local
connections, and requires the same request to recover with exactly one reconnect and one
replay-safe retry per selected lane. Use repeated `--lane` arguments to select only SSH or Telnet.

Use `--skip-telnet` when object-only evidence is sufficient. Login/expect input is capped at 64 KiB and each
command response at 8 MiB. Exceeding either limit closes the connection, returns
`telnet_output_limit_exceeded`/`125`, keeps public JSON free of the captured prefix, and writes at
most the configured ceiling to a private debug dump.

## Capability preflight

Run full preflight when log/file capability must be discovered. Add `--skip-telnet` for an
object-only capability check, or `--mdb-only` when only the MDB lane is required. The public
preflight resolves the selected credential source once and reuses one task-scoped SSH lease plus,
when requested, one Telnet session across its checks.

```bash
python "$HOME/.agents/skills/openubmc-debug/scripts/preflight_remote.py" --ip <ip> --json --compact-json
```

When `workflow_remote.py` is invoked repeatedly through the same MCP task, its TargetRun keeps at
most one capability snapshot for each `mdb-only`, object-only, or combined profile (and exact
preflight selector). The cache key includes the target epoch and relevant SSH/Telnet lane epochs.
The next workflow replaces a repeated full capability probe with a lightweight clock/uptime-anchor
refresh; reconnect, upgrade/mutation epoch advancement, or a failed required SSH/Telnet anchor at
either refresh boundary removes the stale entry. Separate CLI processes do not share live
connections or capability snapshots, but they do share the same persistent Case when `--case-id` is
supplied. Runtime status exposes only entry counts/profile names and cache hit/miss/store/
invalidation counters. It never caches or reports remote result bodies through this mechanism.

For a cold typed run, preflight publishes capability gates as their required checks finish. MDB,
D-Bus/alarm, and Telnet collectors can therefore start independently without waiting for unrelated
checks. The complete preflight still finishes once, is recorded once, and supplies the same cache
entry; readiness scheduling does not introduce a second preflight.

Consume `result.capabilities`:

- `remote_object`: at least one read-only object lane is usable.
- `remote_log_file`: current helper log/live-file access is usable.
- `combined_snapshot`: both evidence surfaces are usable.
- `mdbctl` and `busctl`: verified fine-grained transport/tool prerequisites.
- `active_alarm_transport` (with compatibility alias `active_alarms`): SSH,
  D-Bus, and busctl are ready to attempt the current-alarm helper.
  `active_alarm_endpoint_verified` remains false during preflight because
  endpoint enumeration and `GetAlarmList` belong to the bounded reader. Preserve
  any later discovery/read failure.

The `remote_object` capability means SSH is usable and at least one read-only object lane passed preflight: `mdbctl`, or a live D-Bus environment plus `busctl`. It does not mean every object helper is usable, and it does not verify an active-alarm endpoint. A missing D-Bus environment does not disable a successful MDB lane, and an available bus lane does not require `mdbctl` to pass. New workflow callers use the fine-grained fields and mark unavailable optional helpers `skipped`.

`overall_code` is `ok`, `partial`, or `unavailable`. A failed optional check can coexist with a usable capability. Use the capability instead of requiring every check to pass.

Compatibility fields `ssh_object`, `telnet_files`, and `telnet_logs` may remain for older callers. New orchestration uses the evidence capability names.

## Orchestration Entrypoints

The default MCP Interface exposes only `observe` and `execute`. The domain operation names in this
section describe internal Runtime adapters; ordinary Agents must not orchestrate them directly.

`workflow_remote.py` is the canonical combined-snapshot CLI. It preserves the established input
flags, then enters `debug_run` through the same OperationCatalog, Case repository, evidence store,
and idempotency path as MCP. Its DomainAdapter performs preflight, gates each helper by the reported
fine-grained capability, collects the bounded snapshot, and computes freshness under one global
deadline. The package intentionally contains no terminal-multiplexer or detached-pane launcher.
Starting a shell session is neither collection completion nor evidence.

The internal `debug_collect` adapter accepts `profile: object-alarm` for a single current SSH-backed
object/alarm snapshot. That profile skips Telnet, source correlation, and the end freshness pass.
On an epoch-valid follow-up, its cached MDB gate can release that read concurrently with the start
SSH anchor refresh; D-Bus/alarm reads still wait for the refreshed anchor. A failed refresh still
fails the result and invalidates the cache. Use `debug_run` for the full freshness and correlation
workflow.

For a current MDB-only answer, default MCP callers use an `observe` MDB selector. The internal
`debug_collect` adapter accepts `profile: mdb`. Supplying `mdb_only: true`
with the default profile selects the same fast path. It forces the MDB-only capability profile,
skips Telnet/source correlation/end freshness, and enables the cached capability gate to release
fresh MDB reads during the SSH anchor refresh. This is not result caching: every requested MDB
query is executed again. `debug_run --mdb-only` keeps the full start/end freshness boundary.
`freshness` is not a profile and is rejected.

For post-upgrade Drive convergence, the Runtime may pass a bounded
`hardware_acceptance` object with one `devices` array. Each item has `device_id` (`Drive<N>`),
`protocol` (`NVMe`, `SATA`, or `SAS`), and `resource_id` (`positive` or `zero`). The declaration is
validated when the workflow starts but is enforced only by `debug_collect`. Every declared Drive
must also be present, healthy, and identified; NVMe Drives must be direct. If any condition is not
yet true, the native result is `partial` with `hardware_acceptance_pending` and exact gaps. A later
Runtime resume recollects the same verification step; no target state is changed and elapsed time
alone never satisfies acceptance.

Use `openubmc-debug-dev/tools/benchmark_fast_mdb.py --target <ip> --iterations 2 --json` to record
one cold and one epoch-valid warm snapshot in the same task. Repeat `--target` for a small
comparison; the tool keeps target-specific leases isolated and reports timing plus bounded Runtime
status rather than retaining MDB result bodies.

Use repeatable `--mdb-query '<reviewed command>'` arguments when the diagnostic question needs
specific model objects or properties. They replace the workflow's generic `lsclass` probe and run
through the same TargetRun instead of opening one helper process per query. Use repeatable
`--mdb-expand-class <class>` when current object names must be discovered before their properties
can be read. Add `--mdb-only` for a narrow model-only task so its preflight checks only SSH/MDB and
unrelated bus, alarm, log, and file collectors remain skipped. `--mdb-concurrency auto` bounds
simultaneous reads per target without limiting the total query or object count.

`compare_remote.py` maps the established comparison flags into the Catalog's multi-target
`debug_run`. It accepts repeated reference candidates or repeated symmetric targets without a fixed
target-count limit. Concurrency and deadline settings provide scheduling and backpressure; a
target-local failure yields a partial comparison while preserving completed target results. It
accepts the same evidence bounds and exact selectors as `workflow_remote.py`, including known alarm
service/path overrides. Add `--json --compact-json` for a bounded Agent Envelope; read the complete
comparison through its evidence reference only when needed.

Native subagents, when available, are an agent-level analysis layer after a validated workflow
snapshot exists. The root agent retains credentials and live-target ownership; analysis workers
receive only the same immutable, bounded evidence and may inspect the resolved source root. They
must not run preflight, helpers, or other target commands. The root agent correlates their cited
evidence and remains responsible for the final result. If subagents are unavailable or
fail, perform the same analysis sequentially and preserve the missing dimension as unresolved.

## Task iteration and delivery deduplication

One MCP task may bind a new single target, replace a target set, or update ports and credential
selectors. A call that omits target coordinates incrementally inherits the currently bound targets.
A call that supplies `ip` or `targets` resets the old host and ports, then uses default ports unless
the call supplies replacements. For a single active target, direct users/passwords and the matching
SSH policy may continue within the active task so an address replacement does not force credential
re-entry. Environment selectors, identity files, known-hosts paths, insecure overrides, and an old
multi-target set are not copied into a newly supplied binding. The task purpose, delivery strategy,
and a single target's ID/role remain available without being repeated, while the earlier
orchestration context is retained in a bounded history.

The restartable TaskContext retains the secret-free SSH, Telnet, and Redfish target description and
credential selectors, but each domain backend receives only its own connection arguments. Debug
receives SSH and Telnet, Log Analyzer receives SSH and Redfish, Live Patch receives SSH and Telnet
plus its SSH host-key settings, and Upgrade receives Redfish. Target-specific connection arguments
are stored by `target_id`, so a later Upgrade or Live Patch selection cannot inherit another
target's host or ports. Cache-resident domain leases remain available for a later return to a
previously used target within the same process. Each domain keeps a 32-entry LRU by default; an
evicted target reconnects when selected again, and all remaining leases close with the task.
Changing a direct password, credential selector, or SSH policy selects a distinct domain binding
without limiting the number of targets that may be requested.

Treat matching target bindings, credential selectors, artifact identities, delivery strategy, and
task-level authorization as reusable Case facts. A direct user request to apply/live-patch,
upgrade, or rollback authorizes that named mutation and is projected onto internal gates without a
second confirmation. Apply or upgrade authorization never implies rollback. Insecure TLS and the
Live Patch exceptions `force_path`, `no_backup`, and `no_remount` are frozen task facts. Internal
BMC workflows authorize insecure TLS by default and may explicitly set it to `false` for a trusted
certificate; Live Patch exceptions remain explicit. A Case that already carries the matching facts
must not ask again. Stop automatic advancement when a mutation outcome is unknown, or when recovery
requires a rollback that was not separately authorized.

The local stdio server persists the material TaskContext under the Target Runtime state directory.
Reconnecting with the same task ID restores the typed intent, target bindings/selectors, at most 16
workflow summaries, and at most 32 mutation journal identities. That TaskContext does not persist
resolved or directly supplied credential values, domain resources, SSH/Telnet/Redfish sessions,
capability snapshots, MDB objects, alarms, logs, files, or comparison results. The persistent Case
is separate: in internal development mode its unredacted workflow inputs may include direct
credentials so `execute(kind=resume)` can reattach after a process restart. Case evidence and workflow
inputs remain until explicit forget or retention cleanup. The first follow-up still opens new
domain resources and performs fresh reads; it never restores a connection or an old evidence
result. TaskContext files use atomic replacement, a schema version, a per-file byte ceiling, a
seven-day idle TTL, and a 128-entry LRU ceiling by default. Explicit task completion removes the
TaskContext but leaves the Case. The TTL, count, and byte ceiling are configurable through
`OPENUBMC_TARGET_RUNTIME_CONTEXT_TTL`, `OPENUBMC_TARGET_RUNTIME_CONTEXT_MAX_ENTRIES`, and
`OPENUBMC_TARGET_RUNTIME_CONTEXT_MAX_BYTES`.

Case target-set or port replacement increments `target_version`, so operation steps completed on
the previous binding cannot satisfy the current workflow. Selecting an already bound target by
`target_id` does not increment that version. A completed Developer phase submitted again starts a
new delivery cycle. A repeated downstream phase invalidates only its successors. A failed ordinary
operation remains incomplete, and the next `execute(kind=resume)` reattaches the same Run so
`RunEngine` can derive a new safe attempt; an unknown mutation outcome remains blocked for explicit
journal reconciliation.

`diagnose-and-fix` uses one of three delivery strategies:

- `source-only`: Debug -> diagnosis acceptance -> Developer;
- `live-patch`: Debug -> diagnosis acceptance -> Developer -> Live Patch -> fresh Debug;
- `build-upgrade`: Debug -> diagnosis acceptance -> Developer -> externally supplied Build result
  -> Upgrade -> fresh Debug.

The diagnosis acceptance step is explicit, including when Runtime already has a complete
DiagnosticReceipt. Respond with the returned Gate binding and a grounded `root_cause`,
current-receipt `evidence_ids`, `causal_chain`, `code_owner`, `contradictions`, `remaining_gaps`,
and `verification_status=verified`. Acceptance requires empty contradictions. Repeated
`execute(kind=resume)` only reattaches that same Gate; it never substitutes for a Gate response.

The MCP layer infers the strategy from typed workflow sections or from the mutation domain invoked
later in the same task. It must not default every fix to Live Patch or ask for an intent already
carried by the task. Build is an external typed result and never acquires a target lease.

Every workflow request uses fresh Debug diagnosis and verification evidence unless Runtime safely
reuses one unique, unexpired same-task ObservationRef after its bounded scope probe; an exact
repeat in the same task reattaches the original Run. Mutation identity is computed separately from verification parameters and
includes the target plus mutation arguments; for Live Patch it also includes the local file
SHA-256. Reusing the same mutation returns the prior outcome without applying it again, while the
surrounding Debug phases still run with fresh evidence. The stable mutation operation ID is also
used by the durable mutation journal, so recreating the MCP process with the same task ID does not
upload or patch the same target operation again.

Retention is bounded at every layer. Task-local request receipts, Debug leases, Case projections,
Capsules, orchestration summaries, and evidence read windows use explicit limits. Complete domain
results are content-addressed, compressed evidence blobs referenced by the persistent Case rather
than held in the TaskRun or repeated in normal responses. Runtime status exposes summaries,
budgets, cache/eviction metrics, mutation/journal identity counts, persistence metadata, and
connection/runtime state; it does not inline mutation payloads. Debug, Log Analyzer, Live Patch,
and Upgrade retain up to 32 reusable target-specific leases or bindings per task and domain by
default. This LRU bound controls idle reuse, not target count. Debug pins every actively collecting
lease, may temporarily exceed the retained-cache bound when requested parallelism is higher, and
trims inactive leases after collection instead of closing an in-flight target. Returning to an
evicted target reconnects it. Multi-target scheduling uses a sliding submission window no larger
than the active concurrency budget, and Runtime status exposes the active/peak lease and peak
in-flight submission counts. Context maintenance attempts, failures, and the last failure are also
visible in Runtime status.

During active work, default MCP `structuredContent` is an `ObservationReceipt` or `Turn`. Start a
stateful Run with `execute(kind=start)`, continue it with `execute(kind=resume)`, and satisfy a
returned phase Gate with `execute(kind=respond)`. For a `diagnosis.acceptance` Gate, bind the
response to its `run_id`, `gate_id`, `gate_version`, and `schema_digest`; use only Evidence IDs
listed by the current DiagnosticReceipt. `RunEngine` commits every Gate transition directly. Terminal Runs persist Closeout
and one authoritative Run Outcome. Session Outcome is an
explicit operator projection of that persisted fact; raw Evidence, Replay, Case inspection,
review, approval, and promotion stay in the operator profile.

## Common JSON envelope

Agent automation should use `--json --compact-json`. Every public helper returns:

- `schema_version`
- `tool`
- `ip`
- `observed_at`
- `ok`
- `code` and `normalized_code`
- `returncode`
- `warnings`
- `error`
- `request`
- `result`

Treat `ok=false`, contract mismatch, invalid JSON, timeout, incomplete transport framing, and business-error text as failures. Do not infer success from a shell return code alone.

Telnet file/log helpers separate `--connect-timeout`, `--prompt-timeout`, and `--command-timeout`. All must be positive. Orchestrators must propagate their remaining child budget into `--command-timeout`; the helper default is not permission to exceed a parent workflow deadline.

The combined workflow wrapper additionally preserves each child command plus `started_at` and `completed_at`. Compact output may bound large stdout/log bodies, but it must retain those audit fields and the child request without automatic value masking.

`workflow_remote.py --timeout` is propagated to SSH, Telnet connect/login, and
Telnet command execution for every child helper. The global `--deadline` still
caps the whole workflow and may shorten an individual child budget.

## Helper boundaries

- `active_alarms.py`: metadata-only XML introspection and current `GetAlarmList`; it tries the standard `bmc.kepler.event` endpoint first and falls back to bounded service/path discovery. A TargetRun caches only the automatically discovered endpoint metadata, while every call recollects current alarms. Stale endpoint errors invalidate that metadata and permit one bounded rediscovery without dropping the SSH master. Discovery stdout has a 4 MiB ceiling, XML stdout stops at the `1 MiB + 1 byte` probe, and the final alarm result has an 8 MiB ceiling. Stderr is independently limited to 64 KiB. Per-document size and end-to-end discovery deadlines apply, and invalid XML, discovery ambiguity, incomplete enumeration, and unknown signatures fail closed.
- `mdbctl_remote.py`: reviewed read-only model queries with an 8 MiB stdout and 64 KiB stderr transport ceiling; reject mutating or unclassified queries before credentials, allow any valid property name, and preserve returned text.
- `busctl_remote.py`: exact D-Bus list/tree/metadata-only introspection/property evidence with a 4 MiB stdout and 64 KiB stderr transport ceiling; reject every method call before credential resolution or transport, while allowing `get-property` for any valid member name.
- `collect_logs.py`: bounded logs, rotation, filters, and optional since-boot window; require regular non-symlink paths, keep rotation discovery under hard candidate and byte limits, accept only a positive capped rotation count, batch keyword filters below the Telnet input-line boundary, and enforce a default/hard-capped per-file byte probe before Telnet framing. Each entry exposes `bytes_returned`/`truncated`/`content_complete`; a truncated successful prefix remains useful positive evidence but never proves absence. Bound framing errors and preserve every returned output surface.
- `read_remote_file.py`: bounded live-file reads for any explicit absolute path; require a regular non-symlink file and expose `bytes_returned`/`truncated`/`content_complete` so a bounded prefix cannot masquerade as complete absence. Returned content and errors are preserved.
- `workflow_remote.py`: capability-gated combined snapshot and freshness comparison.
- `doctor.py`: credential-presence, route, proxy, SSH configuration, and port diagnostics; optional OS SSH smoke uses one fixed, bounded, read-only probe and exposes no arbitrary remote-command option. It preserves exact proxy and SSH configuration values plus stable OS access failures such as `os_ssh_auth_failed`, `os_ssh_tcp_timeout`, and `os_ssh_connection_refused`.

The current object helpers use SSH; current log/file helpers use Telnet. Those are helper implementations, not universal routing rules.

The object helpers expose no write override. Route property mutation, service control, arbitrary method calls, and other remote state changes to the owning Skill with explicit authorization, target, and rollback boundaries.

## Debug dumps

Use `--debug-dump <output-dir>` when raw transport output is needed. Dumps include bounded commands, stdout/stderr, raw bytes, decoded text, timestamps, and metadata exactly as collected; no automatic masking pass is applied.

When an SSH caller supplies stdout/stderr byte limits, `run_ssh` streams both pipes concurrently, kills the process on the first exceeded limit, returns code `125`, and records per-stream limit flags and byte counts. Public JSON classifies this as `ssh_output_limit_exceeded`, omits the captured over-limit prefix, and retains only safe transport metadata. A non-timeout pipe read failure fails closed as `ssh_transport_capture_failed`/`126`; output-limit and timeout termination keep precedence so their expected pipe closure is not misclassified. The returned text and debug-dump inputs remain within the requested bounds; code `124` remains reserved for timeout. D-Bus environment detection and preflight probes use smaller 64 KiB/1 MiB ceilings appropriate to their fixed commands.

Never put a dump directory, credentials file, notebook ID, vault, or personal path into the Skill as a runtime default.
