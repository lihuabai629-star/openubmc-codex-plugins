---
name: openubmc-developer
description: "Use only for unresolved openUBMC decisions about source ownership, repository extension patterns, authored/generated chains, component lifecycle, persistence, or cross-layer behavior. Exclude specified edits, documentation-only work, and workflows owned by other Skills."
---

# OpenUBMC Developer

Fit requested behavior into the repository's current structure. Own source
analysis, design, implementation in existing components, and component-local
verification. Scale the work to the uncertainty and risk instead of imposing a
fixed ceremony on every change.

## Keep the primary owner clear

Own work whose primary deliverable is understanding or changing behavior
controlled by existing openUBMC source. This includes component code, models,
service metadata, manifests, and declarative configuration.

If the request also includes a later build, live patch, upgrade, or publication,
complete the source stage and pass only verified source facts. Let each downstream
Skill discover or request its own stage-specific inputs. Do not use this Skill
merely to route work owned entirely by another Skill.

## Choose the lightest safe path

- For a fully specified mechanical edit that needs no openUBMC-specific
  judgment, use the ordinary direct edit path even if this Skill was loaded. Do
  not add Developer-specific planning or load references. Inspect the target and
  local context, edit, run the focused check, and report briefly.
- Treat analysis, review, assessment, and design requests as read-only. Words
  such as fix, change, implement, or update authorize source edits when the
  request asks for the files or behavior to be changed.
- A straightforward local change has one evident owner, follows an existing
  pattern, and does not materially change a public contract, generated chain,
  persistence, cross-component state, lifecycle, concurrency, compatibility, or
  accepted risk. For this path, proceed directly after inspection without a
  separate pre-write ceremony.
- Keep that path operationally small and use no intermediate planning artifact.
  When the request already identifies the target and validator, inspect
  repository instructions, the target, nearby precedent or test, and the
  validator in a focused pass. Avoid rediscovering the same tree, rereading
  unchanged files, or repeating checks without a concrete reason. Add another
  inspection or verification pass whenever new evidence, workspace state, or
  risk makes it useful.
- Once the selected evidence proves the changed contract and no new failure or
  gap appears, stop discovery. Use a validator named by the user as the primary
  check, but treat it as sufficient only when its scope can establish the
  changed behavior. If it cannot prove syntax, compilation, or execution that
  materially matters, add the smallest relevant check when practical. Do not
  probe unrelated toolchains, traverse Git internals, or reread unchanged
  context merely to add confidence. Never reopen a file merely to obtain line
  numbers or a clickable final link. If the decision-relevant read did not
  retain a location, cite the observed path without a line. This applies in
  particular to unchanged adjacent findings already covered by a validator.
- For a deeper change, communicate only the useful facts before the first write:
  the responsible area, expected change surface, material risk, and validation
  approach. An explicit implementation request does not need a second approval
  merely because the change is non-trivial.
- Pause only when repository evidence leaves alternatives that materially change
  behavior, compatibility, risk, or scope; a required contract or generator is
  unavailable; user work overlaps inseparably; or safe validation cannot be
  established. Explain the concrete decision or blocker. Determine the
  behavior-owning module or layer from the repository instead of asking the user
  to name an owner.

When the user says “continue”, resume while the objective, accepted design,
source state, and environment remain valid. Re-read affected source before a
new write when one of them may have changed.

## Locate the correct change

Read applicable repository instructions and express the request as an observable
outcome: what triggers it, what must change, what must remain, and any material
compatibility or lifecycle constraint.

Investigate only as far as the decision requires:

1. Follow the behavior entry point to the module or layer that owns the rule or
   state.
2. Inspect the nearest comparable implementation, its extension point, direct
   callers, and the repository-selected test or validator.
3. Expand the trace only when the change crosses an authored/generated boundary,
   public contract, state writer, component boundary, startup/teardown path, or
   persistence lifecycle.

Current source, repository instructions, and tests establish the implemented
structure. Use version-matched specifications when the intended contract can
change the design. Use the openUBMC KB only to discover likely material;
trace material claims to current source or primary documentation. Use history
and Obsidian records only when the user asks for earlier rationale or current
evidence conflicts or leaves a material gap; never use them as proof of the
current implementation. Record source identity and version when an external
claim affects the change.

Follow a stable repository precedent by default. If precedents conflict or none
can satisfy the requirement correctly, present the material alternatives before
a deviation or refactor.

For a model/interface change or a multi-component handoff, use the impact and
component-acceptance contract in
[`openubmc-build/references/handoff-contract.md`](../openubmc-build/references/handoff-contract.md).
Carry the task's explicit paths and evidence-backed dependency edges; preserve
unknown coverage as a gap. Submit actual component checks through the current
`developer.change` Gate, using partial submissions when work remains.

## Implement in the existing structure

- Put behavior in the layer that already owns it. Keep adapters thin, preserve a
  single authoritative state writer, and reuse existing helpers, interfaces,
  lifecycle hooks, registration mechanisms, and error paths.
- Match nearby naming, dependency direction, logging, async/concurrency style,
  cleanup, and test conventions.
- Make the smallest complete change: update every required layer, but avoid
  unrelated cleanup, speculative abstraction, and parallel implementations.
- Treat human-maintained models, service metadata, manifests, and declarative
  configuration as authored source when they control behavior.
- Change generated behavior through its authored input and repository generator.
  Inspect created, replaced, deleted, empty, truncated, and sibling outputs.
  When a required generator or contract is unavailable, follow repository
  policy. Stop before leaving authored and generated sources inconsistent when
  they must change together. Edit only the authored input when deferred
  generation is explicitly supported; never manually synchronize derivatives,
  and report the generation gap.
- Preserve tracked and untracked user work. Report nearby defects separately and
  change them only when they are inseparable or the user adds them to scope.
- Add or update focused component-local tests and fixtures when the repository
  has a practical seam. Component-local testing remains part of this Skill. Use
  `openubmc-dt-testing` only when the user explicitly requests shared runners,
  fixtures, mocks, cleanup mechanisms, coverage, or cross-component test
  infrastructure as work in its own right.

## Use worktrees conditionally

Use the current checkout by default. Create a linked worktree when explicit
isolation, parallel alternatives, inseparable dirty overlap, or a stable source
snapshot is needed during source work. Use a full clone only when a linked
worktree is unsuitable. Do not create either for routine local edits or solely
to manufacture a downstream handoff field.

Inspect and report workspace state only when needed to protect existing work,
explain an isolated workspace, or prepare a requested downstream handoff.
Include Git identity only when it was already observed and materially identifies
that handoff; do not probe Git solely to populate the final report. Let the
downstream Build workflow decide whether its operation requires a particular
Git root. Never remove an isolated workspace automatically. Report its absolute
path, purpose, and retention intent. Cleanup requires an explicit request after
confirming the workspace is no longer needed.

## Verify and hand off

Run the smallest sufficient repository-selected checks that prove the changed
contract. Repository-local generation, compilation, unit-test builds, tests,
and validators remain source verification. Prefer executing changed behavior or
compiling the affected code when practical; distinguish that evidence from text
inspection, product builds, and runtime validation.
Classify official UT separately from supplementary checks. A dependency-blocked
test never started, and supplementary success is never promoted to official UT,
compilation, package, firmware, or hardware-validation success.

Review the completed diff against the selected precedent for misplaced logic,
duplicate ownership, layer leakage, bypassed interfaces, unnecessary public
abstractions, incomplete generation, and missed consumers.

For a straightforward implementation, hand off concisely: changed behavior,
key files, focused checks and results, workspace state, and any remaining gap.
For read-only work, report the responsible area, relevant flow and precedent,
recommended change surface, material alternatives, and unresolved evidence.

Source completion alone does not authorize dependency resolution, a product or
package build, a live-target patch, firmware upgrade, or publication. When the
user asks only for a downstream-ready handoff, read
[downstream-handoffs.md](references/downstream-handoffs.md), provide the minimal
source facts, and stop without loading the downstream Skill. Continue with
`openubmc-build`, `openubmc-live-patch`, `openubmc-upgrade`, or
`openubmc-publish` only when the user explicitly asks to execute that stage.
Carry the user's requested sequence forward, but let each owner validate its own
inputs and authorization.

## Load references only for a material decision
Do not load references from keywords, file types, directories, or language
alone. Read one reference at a time when the task materially involves its
contract or inspected source leaves a material decision unresolved. If a
separate material decision remains afterward, read the next relevant reference.
Do not open references merely to add background or a generic checklist. Do not
load a language or domain reference when current source and a direct precedent
already resolve the decision. Do not manufacture a reference decision by
proposing validation, refactoring, or compatibility behavior outside the
requested outcome; a possible improvement is material only when the requested
change requires it.

- Competing ownership, lifecycle, cross-module state, or workspace isolation:
  [development-guidelines.md](references/development-guidelines.md)
- A Lua-specific lifecycle hook, concurrency primitive, modeled-object
  contract, error path, persistence hook, or test seam remains unresolved after
  inspecting current source and direct precedent:
  [lua-component.md](references/lua-component.md)
- MDB/MDS contracts, authored models, generators, and direct consumers:
  [mdb-mds.md](references/mdb-mds.md)
- Persistence lifetime, migration, deletion, upgrade, or rollback:
  [persistence-compatibility.md](references/persistence-compatibility.md)
- Northbound or management-interface translation:
  [interface-mapping.md](references/interface-mapping.md)
- User-space device files, sysfs, ioctl, mmap, or driver ABI:
  [native-user-space-and-driver-abi.md](references/native-user-space-and-driver-abi.md)
- Service startup, dependency ordering, manifests, and product assembly:
  [startup-product-assembly.md](references/startup-product-assembly.md)
- Hardware VPD acquisition, byte validation, snapshots, refresh, and removal:
  [hardware-vpd.md](references/hardware-vpd.md)
- SR/DDS product records and effective product selection: [sr-dds-product-records.md](references/sr-dds-product-records.md)
- ProfileSchema import/export, adapters, redaction, and compatibility: [profile-schema-import-export.md](references/profile-schema-import-export.md)
