---
name: openubmc-live-patch
description: Temporarily plan, apply, verify, or roll back a file replacement on a live openUBMC/BMC target during runtime debugging. Use for runtime-compatible Lua or SR/CSR replacement with explicit target mapping, checksum or backup evidence, mount restoration, bounded restart scope, and fresh verification. Do not use for permanent source delivery, component/product builds, or full firmware upgrade.
---

# openUBMC Live Patch

Use this Skill for temporary runtime validation. It does not replace a source change, build, package, or review workflow.

## Execution contract

- Every CLI is plan-only by default. A plan must not load credentials or contact the BMC.
- Mutation uses all four CLI gates: `--apply --intent live_patch --authorize-live-patch --restart-scope <none|skynet>`. Select the restart scope internally; the user does not need to name it separately.
- On a bound Case, use Target Runtime's typed decision without reinterpreting or reconfirming it.
  The admitted action must match the transaction; Apply authorization never implies rollback.
- Use `none` when replacement is effective without a framework reload. Use `skynet` when reload is required to complete an explicitly requested live-patch verification. Announce the bounded restart and expected transient disconnect, but do not ask for redundant confirmation.
- Back up an existing target with its file attributes, preserve its numeric owner/group during replacement, verify deployed checksum and metadata, run `sync`, and restore the original root mount mode.
- Treat copy, checksum, metadata, mount restoration, health, and requested business verification failures as failures. Return `ok=false` and a nonzero exit status.
- Internal development mode accepts direct SSH/Telnet password arguments as well as the
  openubmc-debug credential source and `OPENUBMC_*` environment variables. Never print them.
- BMC SSH host-key verification defaults to `insecure` for replaceable development targets, including
  host-key changes. `strict` and `accept-new` remain optional overrides; this policy does not weaken
  OS-host SSH.
- `force_path`, `no_backup`, and `no_remount` are narrowly scoped task-level exceptions. Require an
  explicit user request or an already-carried typed authorization for each one; do not infer them
  from convenience, and do not reconfirm them once bound to the Case.

Read [references/live-patch-contract.md](references/live-patch-contract.md) for CLI fields, credential/helper discovery, exit semantics, and evidence requirements. Read [references/remote-file-patterns.md](references/remote-file-patterns.md) before choosing a target or restart scope.

## Input

Accept a direct request or concise handoff that binds one local artifact, one remote target, backup,
verification, and any requested rollback; host-key policy may use the BMC default. Infer the minimum
restart scope from the runtime consumer and requested verification. Planning keeps `apply=false`;
mutation still uses the typed transaction and internal CLI gates. A direct request to live patch and
verify carries the required action decision and authorizes the minimum `none` or `skynet` scope
needed for that verification without a second prompt.

When Target Runtime invokes this Skill with a `case_id`, consume the carried artifact, target,
credential selectors, restart scope, and typed decision. Do not derive a different route or ask the
user to repeat those facts.

## Workflow

1. Inspect the changed file and its runtime owner.
2. Resolve the local and remote paths. For `/opt/bmc/apps/<app>/...`, require an explicit app mapping; repository name alone is not evidence.
3. Run the relevant command without `--apply` and inspect its JSON plan internally.
4. Check backup, remount, target, mode, inferred restart scope, host-key policy, health checks, and business verification. Inform the user before a `skynet` restart; do not pause for a second confirmation when live-patch verification is already authorized.
5. Execute only after the typed transaction admits the action. Do not ask for confirmation already represented by it; ask only when the artifact, target mapping, or mutation intent itself remains ambiguous.
6. Report before/after checksums, backup path or created-target state, mount restoration, restart scope, verification evidence, and the plan-only rollback command. When the target did not exist before Apply, generate a checksum-guarded `--remove-created` rollback instead of leaving a temporary file behind.
7. After a temporary patch or validation succeeds, return to `openubmc-developer` for the permanent source fix and focused validation; it routes any requested build and review to their owners. Never treat the live patch as the final production change.

On the MCP path, the mutation operation identity includes the target, patch parameters, and local
file SHA-256 but excludes later Debug verification selectors. Repeating the same patch with changed
acceptance checks reuses the durable mutation journal and runs only fresh Debug verification. Change
the patch identity or start a new task when a deliberate re-application is required.
If the local MCP process reconnects with the same task ID, Target Runtime restores the target and
typed delivery context but opens new SSH/Telnet resources; the durable journal remains the only
source for deciding whether mutation work may be reused.

When a Runtime `run_id` is present, bare “继续” or “continue” means call `execute(kind=resume)`.
Keep the Live Patch operation in that Run; never replay Apply, create a new operation, or create a
new journal merely because the transport disconnected. A terminal MutationJournal receipt, target
epoch advance, and fresh verification are recorded by the Runtime; do not duplicate them.

If the mutation outcome is unknown, stop automatic resume and call
`execute(kind=control, command=reconcile)` for the same durable
journal explicitly. This is not a request for another Apply confirmation. Automatic recovery may
execute rollback only when the Case carries the distinct rollback authorization. Otherwise preserve
the original operation as `recovery_blocked`. A later explicit rollback intent is necessary but is
not by itself proof that recovery ran; keep the Run blocked until a recovery-capable path
reconciles that same journal. Never reinterpret Apply authorization as permission to restore or
remove a file. When the Run becomes terminal, return its terminal Outcome. Closeout documents,
evidence, artifacts, backups, and checksums remain available through the Operator / CI Plane.
The task keeps direct SSH/Telnet credentials for warm continuation, and the persistent Case keeps
the internal-development workflow inputs used by `execute`. Target-specific bindings use
a 32-entry LRU by default; target count is not limited, and returning to an evicted target simply
opens a new binding.

When a Runtime `run_id` is present, keep the Live Patch operation in that Run. A terminal
MutationJournal receipt, target epoch advance, and fresh verification are recorded by the Runtime;
do not duplicate them. If the mutation outcome is unknown, stop automatic progression and
reconcile the durable journal explicitly with the same Run and Effect
identity. A terminal ordinary failure remains retryable as the next workflow attempt. Do not create
a new mutation identity merely because the transport disconnected. Post-patch Debug acceptance
must report an epoch at or after the mutation epoch.

Before mutation, synchronize the domain-local TargetRun to the Case-provided target epoch floor.
The patch then advances that shared epoch exactly once. Never restart epoch numbering from the
Live Patch backend's local zero, and never ask the user to supply or reconcile epoch values.

## Commands

Set `SKILL_DIR` to this installed Skill directory.

Inspect changed-file mappings:

```bash
python "$SKILL_DIR/scripts/infer_live_patch.py" \
  --cwd <repository> \
  --app <runtime-app> \
  --json
```

Plan the only supported current change:

```bash
python "$SKILL_DIR/scripts/deploy_current_patch.py" \
  --cwd <repository> \
  --app <runtime-app> \
  --ip <bmc-host> \
  --json
```

Apply without restarting a process:

```bash
python "$SKILL_DIR/scripts/deploy_current_patch.py" \
  --cwd <repository> \
  --app <runtime-app> \
  --ip <bmc-host> \
  --apply \
  --intent live_patch \
  --authorize-live-patch \
  --restart-scope none \
  --json
```

When framework reload is required for the requested verification, select `--restart-scope skynet --health-check` automatically. Otherwise select `--restart-scope none`. Add only domain-relevant `--verify-mdbctl '<command>'` checks.

For a directly supplied target, use `deploy_live_file.py` with `--local` and `--remote`; it has the same plan/apply gates. Use `rollback_live_file.py` with the reported backup path. If Apply reports that it created a previously absent target, use its generated `--remove-created --expected-current-sha256 <sha256>` rollback. Both rollback forms remain plan-only until all mutation gates are present.

## Result

Return the local artifact identity, target and backup identity, applied state, restart scope, and
verification result:

```yaml
live_patch_result:
  execution_mode: plan_only | apply | rollback
  target: <confirmed target>
  checksums: <before/local/after or unknown>
  metadata: <before/after mode, uid, gid or not_applicable>
  backup: <path and identity or not_applicable>
  root_mount_restored: true | false | not_applicable
  restart_scope: none | skynet
  verification: <health and business results>
```

A successful plan is completion only for a plan request; it does not claim the remote file changed. A failed checksum, metadata, mount restoration, health check, business check, or rollback returns non-completed status and literal evidence.

## Stop conditions

Do not apply when any of these is unresolved:

- multiple candidate files or an ambiguous target mapping;
- missing live-patch intent, carried `delivery_strategy=live-patch`, or mutation authorization;
- unknown credentials or helper discovery;
- `force_path`, `no_backup`, or `no_remount` requested without its task-level authorization;
- no acceptable backup strategy for an existing target unless `no_backup` is authorized;
- inability to determine or restore the original root mount mode unless an authorized
  `no_remount` plan has already proved the target writable;
- an unknown prior mutation outcome that has not been reconciled;
- recovery that requires rollback when the distinct rollback action is not authorized;
- verification requirements that cannot be executed or interpreted.
