# Live-patch CLI contract

## Public commands

| Command | Purpose | Default |
| --- | --- | --- |
| `infer_live_patch.py` | Inspect changed files and candidate mappings | Read-only |
| `deploy_current_patch.py` | Select one changed runtime file and delegate deployment | Plan-only |
| `deploy_live_file.py` | Plan or replace one explicit local/remote file pair | Plan-only |
| `rollback_live_file.py` | Plan a backup restore or checksum-guarded removal of a target created from absence | Plan-only |

## Mutation authorization

An apply operation receives all of:

```text
--apply --intent live_patch --authorize-live-patch --restart-scope <none|skynet>
```

`--intent live_patch` and `--authorize-live-patch` project the Runtime's typed mutation
authorization onto the local helper CLI for the bound target and plan. Runtime Core keeps Apply and
rollback as distinct canonical actions even though both scripts use these legacy CLI gates. A
direct user request to apply/live-patch authorizes Apply; a direct rollback request authorizes only
rollback. Do not ask again when the Case carries the matching authorization, and never infer
rollback authorization from Apply. `--restart-scope` bounds process impact; infer `none` or
`skynet` from the consumer and requested verification. Announce a `skynet` restart and expected
disconnect without pausing for another confirmation. A missing CLI gate remains a usage error and
must not load credentials or contact the target.

`force_path`, `no_backup`, and `no_remount` require their own explicit task-level boolean
authorization. Project an already-carried exception onto the CLI flag without reconfirming it; do
not infer an exception from the path, mount state, or absence of a convenient backup.

## Credentials and dependencies

The scripts load openubmc-debug integration from either:

1. `OPENUBMC_DEBUG_HELPERS` and `OPENUBMC_DEBUG_SCRIPTS`, when explicitly configured; or
2. an `openubmc-debug` sibling Skill discovered relative to the running script.

Credential values may come from direct internal-development CLI arguments, the openubmc-debug credential loader, or `OPENUBMC_*` environment variables. The runtime passes SSH passwords to `sshpass` through its child environment when opening the actual transport.

SSH host-key policies:

- `insecure` is the BMC default for replaceable internal-development targets and tolerates key
  changes without a confirmation loop.
- `strict` requires a known host key.
- `accept-new` may add a previously unseen key while rejecting changed keys.
- `--known-hosts <path>` and `--ssh-identity <path>` make the trust and identity sources explicit.

The BMC default does not apply to OS-host SSH, which remains `strict`.

## Plan result

A successful plan returns exit `0`, `ok=true`, and `dry_run=true`. It records at least:

- local and remote paths;
- local SHA256;
- backup/remount intent;
- restart scope and whether a restart will occur;
- host-key policy;
- health and business verification requests.

No credential loading, SSH, Telnet, remount, copy, or restart is allowed during planning.

Before any remount, staging, backup, deploy, or rollback mutation, the remote side must resolve the authorized root and every parent directory with `readlink -f`, require the resolved path to remain inside that root, and reject target/staging/backup paths or parent chains containing symlinks. Execute these guards as bounded per-path Telnet commands so a valid multi-path plan cannot exceed the target console's single-line input boundary. Run one bounded BusyBox codec check per apply or rollback, then gzip/base64-wrap longer atomic shell bodies so every framed Telnet command stays within that same input boundary without adding SSH uploads to rollback. Staging uses a fresh owner-only directory. Backup names contain a random operation token and are created exclusively; an existing file or symlink is a hard failure. Backups preserve file attributes. Deploy preserves an existing target's numeric uid/gid and applies the reviewed mode; rollback restores the backup uid/gid and verifies the reviewed mode. Deploy and rollback copy into a fresh same-directory work directory, verify checksum and metadata on the regular non-symlink payload, then rename it over the target so the final write never follows a target symlink.

When Apply observes that the target did not exist, return a rollback plan using
`--remove-created --expected-current-sha256 <deployed-sha256>`. That rollback
must require the current regular file to match the deployed checksum, remove
only that exact path, and freshly verify that neither the path nor a symlink
exists. It must not accept a backup at the same time.

## Apply result

A successful apply returns exit `0`, `ok=true`, and `dry_run=false`. Evidence includes:

- backup path when an existing file was backed up, or created-target state when rollback must remove it;
- before/after SHA256 values;
- before/after mode, numeric uid, and numeric gid when the target existed;
- original root mount options and restoration result;
- exact restart scope;
- health attempts and requested MDB verification results;
- a plan-only rollback command.

Health is successful only when preflight and log collection succeed, startup completion has equal total/normal component counts, and no startup error marker is present. Every requested MDB verification command must also exit successfully.

Supplying `--verify-mdbctl` also enables the generic framework health sequence, so business evidence is never evaluated against an already unhealthy framework.

## Failure semantics

| Exit | Meaning |
| --- | --- |
| `0` | Plan produced or apply/rollback fully verified |
| `1` | Remote operation, checksum, metadata, mount restoration, health, or business verification failed |
| `2` | Invalid/ambiguous target or missing mutation gate |

JSON failures return `ok=false` with an `error` field. A checksum, mode, uid, gid, health, or business verification failure cannot be reported as a successful deployment even when the file copy itself completed.

If the transport fails after mutation may have started and the durable journal cannot determine
the outcome, return `mutation_outcome_unknown` and stop. Do not reapply, continue to Debug, or run
automatic rollback until the same operation identity is reconciled. If recovery needs rollback but
the task lacks the distinct rollback authorization, stop as `recovery_blocked`.
