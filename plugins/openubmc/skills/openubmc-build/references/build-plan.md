# Build Plan and Attempt

Read this before creating or retrying a build.

## Plan boundary

One Plan binds one exact command. Generation, component packaging, product packaging, and publication are separate Plans when they execute separate commands.

Complete all planned compare-and-set writes before creating the Plan. After creation, these fields are immutable:

- mode;
- checkout roots, Git HEADs, git-dir/common-dir identity, and dirty-content hash;
- cwd and argv;
- semantic environment;
- input locks and expected versions;
- dependency allowlist and expected artifact;
- `runner.execution_contract_sha256`, enforced by the runner and product finalizer;
- `runner.skill_sha256`, recorded only as Plan-creation audit provenance;
- canonical product output resources.

The recorded Plan document is immutable. Changing a semantic build input or the execution contract creates a new Plan; retrying creates only a new Attempt. Changes limited to documentation, references, tests, or other files outside the execution-contract set do not invalidate an existing Plan merely because the current full-Skill digest differs from `runner.skill_sha256`.

## Create a Plan

Resolve `<skill-dir>` from the selected Skill's `SKILL.md` path.

The Plan file and run root must stay outside every bound checkout. For any command that intentionally writes inside a checkout, repeat `--mutable-path NAME=RELATIVE_PATH` for only the command-owned output subtrees, such as `gen/`, a build directory, or coverage output. Source and configuration paths remain frozen; an undeclared write is workspace contamination.

For validation:

```bash
python3 <skill-dir>/scripts/create_build_plan.py \
  --mode validate \
  --workspace component=<component-root> \
  --cwd <component-root> \
  --output <run-root>/plan.json \
  -- <exact command and arguments>
```

For a product artifact:

```bash
python3 <skill-dir>/scripts/create_build_plan.py \
  --mode product-artifact \
  --workspace manifest=<manifest-root> \
  --manifest-root <manifest-root> \
  --community <community> \
  --artifact-path <absolute-hpm-path> \
  --rootfs-image <absolute-final-ext4-path> \
  --product-version <target-version> \
  --baseline-resolved-lock <absolute-pre-build-package.lock> \
  --resolved-lock-path <absolute-built-package.lock> \
  --rootfs-service 'ssdp=104:104=/opt/bmc/apps/ssdp,/run/ssdp' \
  --allowed-dependency-change <component> \
  --cwd <manifest-root> \
  --output <run-root>/plan.json \
  -- <exact command and arguments>
```

Repeat `--workspace`, `--rootfs-service`, and `--allowed-dependency-change` when needed. Each service entry binds one UID/GID set to only its comma-separated paths; `/opt/bmc/apps` and `/opt/bmc/drivers` are added to that service. Before Plan creation, copy the selected known-good complete resolved lock to immutable evidence outside the checkout and pass that copy as `--baseline-resolved-lock`; never point it at the output file the build will overwrite. The lock must contain `requires`, `build_requires`, `python_requires`, and `config_requires`. If no trustworthy complete baseline exists, stop instead of substituting the smaller community lock. Use `--resolved-lock-path` or `--conan-home` when repository defaults do not identify those inputs.

Product Plan creation fails when `build/<community>.lock` is missing. Do not rename or substitute a different community lock implicitly. This file is a frozen community/product input; it is not the complete dependency baseline. `--baseline-resolved-lock` must point to a separately captured full resolved graph with the same four role lists as the built lock.

Product Plans automatically treat Manifest `output/` and `temp/` as planned mutable paths so normal in-checkout build products do not trigger workspace contamination. Add `--mutable-path manifest=<relative-path>` only for another command-owned output subtree; source and configuration paths remain frozen.

`--hpm-key-file <absolute-path>` selects required containment verification for the supported
openUBMC PICMG/ext4 package format. The file is a private frozen Plan input; the runner and
finalizer reject drift. Omit it for a local-only build whose HPM cannot yet be qualified.

## Execute an Attempt

```bash
python3 <skill-dir>/scripts/run_build_attempt.py \
  --plan <run-root>/plan.json \
  --run-root <run-root>
```

The runner:

- verifies Plan integrity, the frozen command executable identity, and `runner.execution_contract_sha256` against the current execution-contract files;
- verifies each checkout and frozen input lock before and after execution;
- obtains non-blocking Plan, checkout, and product-output locks in canonical order;
- executes argv as an array with `shell=False`;
- runs the command under a separate lock guardian; the build process receives no lock descriptors, and runner loss makes the guardian terminate the build group before releasing locks;
- records command, log, before/after identities, process rc, and checked-log result;
- writes a terminal state atomically.

Product output locks cover the canonical HPM, final ext4 rootfs image, and resolved lock paths. The image is also the product-version evidence source. These locks coordinate Plans in different checkouts and run roots on the same host/kernel; they are not distributed across separate containers or WSL distributions.

## Finalize a product Attempt

After a successful product Attempt, run:

```bash
python3 <skill-dir>/scripts/finalize_product_attempt.py \
  --plan <run-root>/plan.json \
  --attempt-state <attempt>/state.json
```

The finalizer reacquires the same Plan, checkout, and output locks; verifies current outputs still equal `outputs_after`; requires the HPM, final ext4 image, and built resolved lock each to have been absent before the Attempt or to have a different SHA-256 afterward; recomputes both gates; reads `/etc/version.json` from the final image; writes verification and metadata; then checks freshness again before releasing the locks. mtime, ctime, or inode changes with identical bytes do not satisfy freshness. Previous standalone gate reports cannot authorize acceptance. One Attempt has one immutable terminal finalization; use a new Attempt for another build/finalization cycle.

If checkout content, argv, or `runner.execution_contract_sha256` changed, create a new Plan instead of weakening the check. A differing full-Skill provenance digest alone is not runtime drift.

## Retry

Run the same Attempt command with the same Plan path. `--run-root` is only an assertion against the path already frozen in the Plan. A retry must not rerun a version bump, rewrite a Manifest ref, switch checkout, shrink gate scope, or regenerate argv. It reuses the Plan checkout and does not create a worktree.

If a deterministic build may reproduce identical bytes, preserve and move aside the old HPM, final ext4 image, and built resolved lock before retrying. Touching, renaming over, or otherwise changing only output metadata cannot make old bytes fresh.

An Attempt with no terminal state is `interrupted` evidence, not a successful build.

## Reuse completed local evidence

For a local compile or official UT command with fully identified inputs, add these
options when creating its `validate` or `component-package` Plan:

```bash
--reuse-evidence official-ut \
--evidence-input toolchain=<absolute-toolchain-file> \
--evidence-input dependencies=<absolute-resolved-dependency-lock> \
--evidence-output report=<absolute-result-file>
```

Use `compile` for compilation evidence. Repeat `--evidence-input NAME=PATH` for
the command's additional compiler, script, profile, and dependency files. The
`toolchain` role and at least one result file are required. A toolchain lock must
pin the environment actually used by the command; a label for a mutable image or
an unobserved remote environment does not establish that identity. Omit reuse
when dependencies cannot be completely identified. Source inputs remain covered
by the bound checkout identities, and result paths inside a checkout still need
their existing `--mutable-path` declarations. Never declare credential files as
evidence inputs.

The normal Attempt command reuses the latest completed evidence only when the
Plan, executable, source, input files, execution environment, command record,
checked log, and all result files still match. Output files receive the same
host-local resource locks used for product outputs. Environment equality uses a
private keyed proof bound to the current host boot; environment values and the
private key are absent from receipts. Missing or changed outputs, changed environment, invalid private proof,
or a later failed/interrupted Attempt cause real execution. Frozen source, tool,
or input drift still requires a new Plan.

A reused receipt keeps the original Attempt ID, paths, and `finished_at`, with
`reused: true`. It creates no new successful Attempt. Add `--fresh` to the runner
to execute again. Plans without `--reuse-evidence` retain the normal retry behavior.
Product finalization, publication, remote checks, and real-device verification
always require their own execution and fresh acceptance evidence.
