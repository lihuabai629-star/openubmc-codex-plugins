# openUBMC workflow entry and phase handoff

## Continue authorized work

Carry the user's established scope and decisions across turns and owners. Fill
routine CLI switches, authorization fields, Plans and Gate responses from that
scope yourself; they are internal bookkeeping, not new user approval steps.
Choose ordinary implementation details, focused checks and reversible isolation
without an extra confirmation. An authorized multi-stage task continues through
its remaining stages without asking the user to authorize each stage again.

Run only checks that affect the requested result. Reuse evidence until its input
or relevant target state changes. Optional KB, telemetry, certificate/signature
qualification, broad smoke suites and release-only provenance are not prerequisites
for ordinary development or a task that did not request those assurances. Record
unavailable checks as gaps, continue independent work and state the actual result.
Honor an established transport policy without asking again or describing a
connection with verification disabled as certificate/host-key verification.

Before pausing, inspect local sources and available evidence and try the smallest
in-scope remedy. Pause only for necessary missing input, a materially ambiguous
target/action, a genuine concurrent-write conflict, or an action outside the
established authorization. An unknown prior mutation outcome blocks only actions
that could replay or conflict with it; reconcile its existing journal while
continuing independent work. Preserve target/artifact identity, credentials in
private input, other users' state and truthful acceptance results. User-mandated
public-message confirmation and platform-enforced requirements still apply.

Use this reference for an openUBMC task's first workflow action, a change of
deliverable, or continuation after compaction. Select by the user's current
request and fresh Runtime Gate or Incident. A log excerpt, historical session,
or suggested next step does not authorize a new action.

## Select the owner

Respect an explicitly selected Skill or local adaptation. Otherwise, use the
matching Skill from the active plugin's catalog and read its `SKILL.md` before
the stage's first action. Use the paths in that catalog; directory names may
differ from Skill names. Keep unbundled specialists available for their own
scopes. A fully specified mechanical edit uses the ordinary edit and focused
check path; it does not require Developer planning.

| Current deliverable | Owner to read |
| --- | --- |
| Live symptom, current BMC state, or post-change verification | `openubmc-debug` |
| Authorized allowlisted MDB property assignment through Runtime | `openubmc-debug` |
| Local diagnostic bundle, offline log directory, or remote bundle collection | `openubmc-log-analyzer` |
| Explicit documentation audit or release review | Optional `openubmc-doc-review`; read `<plugin-root>/optional-skills/openubmc-doc-review/SKILL.md` when absent from the catalog |
| Unresolved source ownership, generated chain, lifecycle, persistence, or cross-layer behavior | `openubmc-developer` |
| Component/product compilation, generation, package, or HPM build | `openubmc-build` |
| Design or implement UT/IT, mocks, or coverage | `openubmc-dt-testing` |
| Upload, activate, or roll back an already-built HPM | `openubmc-upgrade` |
| Temporary live file replacement and recovery | `openubmc-live-patch` |
| Publish already-built Conan packages | `openubmc-publish` |
| Commit/push source, internal GitLab MR, or community GitCode PR | `openubmc-code-submit` |
| QEMU launch, process/serial evidence, or smoke checks | `openubmc-qemu-testing` |
| Explicit plugin lifecycle/account configuration request, or confirmed required local blocker | `openubmc-environment-setup` |

Setup is entered for a requested plugin install/update/removal/check, private-account or BMC/OS
association edit, or fresh evidence that required plugin startup/configuration blocks this task.
Ordinary work reuses current configuration without a Setup preflight. Build owns Conan/build
failures; Debug first distinguishes authentication rejection from network, TLS, permission or
device errors. Optional KB failure stays on the main evidence path unless its repair is requested.
SDK/container/toolchain installation belongs to an available environment specialist such as
`openubmc-env-init`; report an unavailable specialist without substituting plugin installation.

Bingo workflows and the standalone Lua compatibility entry are retired.
Use Developer for Lua source work; never rewrite an explicit Bingo command silently.

If two same-name sources are visible, preserve their actual paths and versions.
Use the active plugin for a bundled workflow unless the task explicitly selected
another source. Confirm required local adaptations before disabling a duplicate
registration. Keep shared Skill files and non-overlapping specialists intact.

## Follow the current stage

At a transition, read the next owner's Skill before its first action; mentioning
its name is not a handoff. Carry the existing Run and current Gate/Incident
bindings, verified source/artifact identities, evidence references, remaining
gaps, and existing authorization. When a Skill is unavailable, report that
specific gap and continue independent authorized work. Ask only for necessary
missing input or an action outside the established authorization.

For example, live diagnosis reads Debug; a source decision at `developer.change`
reads Developer; local compilation or `build.artifact` reads Build; firmware activation reads Upgrade; fresh target verification
returns to Debug. Test design reads Testing when that work becomes necessary.
Select only the current stage, rather than loading every possible future Skill.

An existing Run keeps its Runtime-owned state. Unknown Effects follow the same
Incident recovery identity; a terminal Outcome needs final delivery. Reading a
Skill or changing an owner does not start a new Run, accept a Gate, or prove
success. Use the returned Runtime schema for each Gate submission.

## Check what actually loaded

Record the selected Skill's path and packaged version/source identity when it
affects reproducibility or resolves a duplicate. Verify loading from the actual
file-read/tool trace. Keep “selected”, “read”, and “stage performed” distinct.
Hook context is advisory and cannot certify model compliance. If a Host does
not execute trusted hooks, read this reference through the owning Skill's
handoff pointer or invoke that Skill explicitly. Hook failure does not stop the
authorized task.
