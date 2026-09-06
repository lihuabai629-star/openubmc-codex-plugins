---
name: openubmc-build
description: Validate or package openUBMC components and products with bmcgo, immutable build plans, checked attempts, and locally finalized Conan/HPM evidence. Use for local compile/gen/test, component Conan packages, product HPM builds, or build-failure diagnosis. Do not use for live-target diagnosis, firmware upload, activation, or runtime file replacement.
---

# openUBMC Build

## Boundary

Own the local build lifecycle: select one build mode, bind the chosen checkout and exact command, execute checked attempts, and return locally finalized build evidence.

Build never reads target credentials or opens SSH, Telnet, or Redfish sessions. `openubmc-upgrade` owns firmware upload and activation; `openubmc-debug` owns fresh runtime verification.

Resolve every helper path relative to this `SKILL.md`. In examples, `<skill-dir>` means the directory containing this file. Never copy an installation-specific absolute Skill path into a command or document.

## Route First

Choose one mode before any persistent write:

| Mode | Use when | Default persistent writes |
| --- | --- | --- |
| `validate` | Compile, generate code, run UT, or execute a user-supplied validation command | Tool outputs only; versions and Manifest remain unchanged |
| `component-package` | Create a Conan package for an explicitly identified source identity | Planned component version and package output |
| `product-artifact` | Build a rootfs/HPM from a selected Manifest checkout | Planned Manifest/product writes and build outputs |
| `diagnose` | Explain an existing build/package failure | None |
| `publish` | Upload an already planned package to a named remote | Explicit remote publication only |

A request to “compile”, “gen”, or “test” routes to `validate` unless the supplied command is already known to produce a product rootfs/HPM. A Manifest `bmcgo build` with a board target is explicit `product-artifact` intent by command effect; never execute it under `validate`. If its product inputs are incomplete, stop before execution instead of weakening the mode. A request to inspect a failed log routes to `diagnose`. Publishing must be explicit and independently authorized.

Read only the selected mode reference:

- `validate`: [references/modes/validate.md](references/modes/validate.md)
- `component-package`: [references/modes/component-package.md](references/modes/component-package.md)
- `product-artifact`: [references/modes/product-artifact.md](references/modes/product-artifact.md)
- `diagnose`: [references/modes/diagnose.md](references/modes/diagnose.md)
- `publish`: [references/modes/publish.md](references/modes/publish.md)

## Shared Contract

### Preserve the command

Command precedence:

1. A complete user-provided argv.
2. A complete structured-handoff argv.
3. A generated candidate only when no complete command exists.

Store argv as an array and execute it unchanged. A wrapper may add logging and state capture around the command, but it does not append `-t`, `--stage`, `-r`, `-v`, or any other `bmcgo` argument.

Treat `build_type`, `stage`, `target`, `remote`, and `version` as independent inputs. Derive one from another only when the selected repository contains an explicit policy requiring it.

### Reuse the selected checkout

Use the checkout already selected by the user, handoff, or active task. Record its canonical root, Git HEAD, concrete git dir/common dir, and dirty-content fingerprint in the Build Plan.

The default new-worktree budget is zero. Use another checkout only when the user or handoff selected it, or after showing a concrete Git-ref or write-conflict isolation need and receiving user confirmation. A dirty tree by itself is not such a conflict. A retry uses the Plan checkout; changing checkout creates a new Plan.

Worktree is not a cache, log, version, or retry-isolation mechanism.

### Make planned writes idempotent

`validate` and `diagnose` do not change component versions, product versions, or Manifest refs.

For packaging modes, determine explicit expected and target values once, then use compare-and-set helpers before freezing the Plan:

- Current value equals target: success, no-op.
- Current value equals expected: atomically write target.
- Any other value: stop with a drift conflict.

A retry never recalculates or increments a version.

### One Plan, one exact command

A Build Plan binds one semantic command. `bmcgo gen`, a component package build, and a product HPM build are separate Plans when each must run.

Create the Plan with `scripts/create_build_plan.py`. It records:

- mode and exact argv;
- selected checkout identities and dirty-content hashes;
- cwd and semantic environment such as `umask` and community;
- product lock identity when applicable;
- expected versions, artifact identity, and allowed dependency changes;
- execution-contract digest enforced at Attempt and finalization time, plus a full Skill digest recorded only as Plan-creation provenance;
- same-host output resources that must not be written concurrently.

`runner.execution_contract_sha256` is the runtime Skill-code invariant. `runner.skill_sha256` is an audit snapshot from Plan creation; later changes limited to documentation, references, tests, or other files outside the execution-contract set do not invalidate the Plan or require a new one.

Read [references/build-plan.md](references/build-plan.md) before creating or retrying a Plan.

### Retry as an Attempt

Execute only through `scripts/run_build_attempt.py --plan <plan.json> --run-root <run-root>`.

An Attempt has the state sequence:

```text
prepared → running → succeeded | failed | cancelled | interrupted
```

`succeeded` means the exact command returned zero, the checked log contains no terminal failure signal, and frozen checkout/input identities still match after execution. It does not mean a product artifact is accepted.

Retrying creates another Attempt under the same Plan. It does not accept a replacement argv, checkout, version, or dependency policy.

### Verify before metadata

For `product-artifact`, an accepted result requires all Plan gates:

- successful Attempt with explicit rc;
- HPM, complete built resolved lock, and final ext4 rootfs image each absent before the Attempt or carrying a different SHA-256 afterward; mtime, ctime, or inode churn with identical bytes is stale evidence;
- version read from `/etc/version.json` inside the Plan-bound final image equals the Plan;
- dependency delta is within the Plan allowlist;
- each planned non-root service can traverse its own mapped image paths.

Run `scripts/finalize_product_attempt.py` after a successful product Attempt. It reacquires the Plan, checkout, and product-output locks and recomputes dependency, image-access, verification, and metadata evidence in one lock cycle. Standalone gate reports are diagnostic evidence, not acceptance tokens. Read [references/artifact-verification.md](references/artifact-verification.md).

When a deterministic retry may reproduce identical bytes, preserve and move aside the old HPM, final ext4 image, and built resolved lock before starting the new Attempt so each planned output begins absent.

Until HPM containment of the inspected image is proved, final verification and metadata remain `package_binding_unverified` with `upgrade_eligible: false`.

## Runtime Handoff

After local product finalization, return the typed Build result with `artifact_path`, `artifact_sha256`, `product_version`, `package_binding`, `upgrade_eligible`, and `evidence_ids`. An accepted local result remains `package_binding_unverified` and `upgrade_eligible: false` until the finalizer proves that the HPM contains the inspected image.

For a `build-upgrade` Run, use `execute(kind=respond)` only after the result is upgrade-eligible. Copy the Run ID and GateBinding from the current `build.artifact` Gate; use its schema for the response. Map the finalized artifact identity into `artifact_ref`:

```yaml
execute:
  kind: respond
  run_id: <current Run ID>
  gate_id: <current Gate ID>
  gate_version: <current Gate version>
  schema_digest: <current Gate schema digest>
  response:
    status: completed
    summary: product artifact finalized
    payload:
      source_revision: <frozen source revision>
      artifact_ref:
        handle: <absolute HPM path>
        digest: sha256:<64 lowercase hex characters>
        kind: openubmc-hpm
        size: <artifact byte count>
        provenance: openubmc-build
        retention_hint: run-lifetime
        version: <verified product version>
        target: <Run target>
        run_id: <current Run ID>
      package_binding: package_binding_verified
      upgrade_eligible: true
      evidence_ids:
        - <plan evidence ID>
        - <attempt evidence ID>
        - <verification evidence ID>
      dependency_readiness:
        readiness_id: <dependency readiness ID>
        status: ready
        resolution: available
        summary: build dependencies resolved
        check_commands: [<completed dependency check command>]
        evidence_ids: [<dependency evidence ID>]
        attempt_count: 1
        reused_by: [build]
      validation_results:
        - kind: build
          status: compiled
          summary: product compilation completed
          commands: [<exact Plan command>]
          evidence_ids: [<checked build log evidence ID>]
          dependency_readiness_id: <dependency readiness ID>
```

`package_binding_verified`, `upgrade_eligible: true`, and at least one evidence ID are required for a completed product Gate. If containment proof is unavailable, return the local-only result and report the missing proof; leave the Build Gate pending. A failed build submission must classify `validation_results` as `compile_failed` or `dependency_graph_blocked` with dependency-readiness evidence. It closes the Run; local Attempt retries should finish before submitting the final Gate response.

Resume an interrupted continuation with `execute(kind=resume)` and the current `run_id`. A completed Gate cannot be reopened to replace its artifact; start a new Run for another delivery. Runtime owns the Upgrade continuation. Do not upload from Build or acquire a target lease. Do not perform an upgrade from Build.

## Supporting References

Read only when the selected branch requires them:

- [references/handoff-contract.md](references/handoff-contract.md): structured upstream inputs and typed result.
- [references/conan-auth.md](references/conan-auth.md): remote authentication and missing binaries.
- [references/product-build-pitfalls.md](references/product-build-pitfalls.md): signing, cache, umask, and rootfs concerns.
- [references/2630-wsl-profile.md](references/2630-wsl-profile.md): optional local dual-WSL profile.
- [references/redfish-upgrade.md](references/redfish-upgrade.md): Build-to-Upgrade boundary.

## Helper Inventory

- `scripts/create_build_plan.py`: immutable Plan creation and checkout binding.
- `scripts/run_build_attempt.py`: exact-argv execution, locking, log checks, and Attempt state.
- `scripts/finalize_product_attempt.py`: single-lock product gates, verification, and metadata finalization.
- `scripts/ensure_planned_version.py`: component/product version compare-and-set.
- `scripts/update_manifest_conan_ref.py`: exact-file Manifest ref compare-and-set.
- `scripts/check_dependency_delta.py`: finalizer-owned Conan lock gate; standalone use is diagnostic only.
- `scripts/check_rootfs_access.py`: finalizer-owned service-path gate; standalone use is diagnostic only.
- `scripts/verify_product_artifact.py`: finalizer-owned Plan/Attempt/artifact/gate verification.
- `scripts/write_artifact_metadata.py`: finalizer-owned accepted-verification metadata writer.
- `scripts/detect_changed_components.py`: read-only changed-component candidates.
- `scripts/preflight_build_env.sh`: read-only environment diagnostics.
- `scripts/run_bmcgo_checked.py`: shared checked-log semantics.
