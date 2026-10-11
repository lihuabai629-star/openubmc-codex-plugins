# openUBMC workflow entry and phase handoff

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
| Diagnostic log bundle or offline log directory | `openubmc-log-analyzer` |
| Unresolved source ownership, generated chain, lifecycle, persistence, or cross-layer behavior | `openubmc-developer` |
| Component/product compilation, generation, package, or HPM build | `openubmc-build` |
| Explicit Bingo command or Bingo-managed build workspace | `openubmc-bingo-build` |
| Modify the Bingo CLI implementation | `openubmc-bingo-development` |
| Design or implement UT/IT, mocks, or coverage | `openubmc-dt-testing` |
| Upload, activate, or roll back an already-built HPM | `openubmc-upgrade` |
| Temporary live file replacement and recovery | `openubmc-live-patch` |
| Publish already-built Conan packages | `openubmc-publish` |
| QEMU launch, process/serial evidence, or smoke checks | `openubmc-qemu-testing` |
| Install, configure, update, or repair the plugin/Runtime | `openubmc-environment-setup` |

An explicit Lua compatibility invocation retains its existing invocation policy.
For a general new-component request, select Developer or an available component
specialist according to the unresolved work; do not force the compatibility
entrypoint merely because the language is Lua.

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
reads Developer; local compilation or `build.artifact` reads Build (or Bingo
when specified); firmware activation reads Upgrade; fresh target verification
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
