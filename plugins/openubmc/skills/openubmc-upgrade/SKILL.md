---
name: openubmc-upgrade
description: Use when an already-built openUBMC HPM must be uploaded, activated, and verified on one or many BMCs through Redfish or the same-origin openUBMC WebUI upgrade API, including component firmware such as CPLD, VRD, and CSR. Also assess an explicit firmware rollback request against a separately available recovery path. Requires current-task mutation authorization, target(s), and verified artifact identity. Do not use to build HPMs, publish Conan packages, or diagnose source code.
---

# openUBMC Upgrade

Upgrade owns remote BMC firmware mutation. It accepts either a verified HPM
summary returned by Build or an already-built HPM whose path, SHA-256, and
product version are supplied by the current task. It starts when Target Runtime
selects the typed Upgrade operation for a Case or a direct non-Case request enters
that operation. Use the typed decision without reinterpreting or reconfirming it.

It does not build components, edit a manifest, publish Conan packages, or claim
runtime acceptance by itself.

An `upgrade-and-verify` intent or `diagnose-and-fix` plus
`delivery_strategy=build-upgrade` is parsed once and carried through upload,
reconnect, installed-version verification, and optional Debug acceptance.
Internal phases do not ask the user to repeat the target, credentials,
artifact identity, final purpose, or authorization. Build supplies the HPM
path, SHA-256, product version, and build evidence; it never opens the target.

When a Context Runtime Case is present, consume `build.artifact`, target, credential selector,
final purpose, and authorization from that Case. A continuation is submitted through the
Agent-facing `execute` operation with the persisted Run identity; the Runtime decides whether
the next step is a Gate, Incident, reattach point, or terminal Outcome. Do not re-upload an HPM
or reconstruct the operation from conversation history.
Upload, activation, reconnect, and fresh Debug verification stay in the same workflow. A mutation
outcome unknown blocks automatic continuation until the same durable MutationJournal is reconciled
with the same Case and operation identity. Upgrade results are domain operations, not
`phase_record` claims.
Build evidence IDs remain attached to the Case's `build.artifact` provenance; consume the artifact
identity from that record without asking the user to restate or confirm it.

Before upload, synchronize the Upgrade domain's local TargetRun to the Case-provided target epoch
floor. A successful upgrade advances the shared epoch once, so later Debug and other mutation
domains invalidate older capability state even when they own separate local connections. Never
restart epoch numbering from the Upgrade backend's local zero or ask the user to manage epochs.

Resolve bundled helpers relative to this `SKILL.md`. In examples,
`<skill-dir>` is the directory containing this file. The managed launcher
selects the release-owned Skill; never substitute an installation-specific
path from another machine.

`operation_state.py` stores WebUI task correlation evidence only.
MutationJournal remains the sole authority for mutation state and outcome.

## Required input

Before an upgrade write to a BMC, require all of the following:

- a typed Upgrade authorization accepted by Target Runtime;
- one or more HTTPS BMC targets;
- HPM absolute path, expected SHA-256, and expected product version;
- a Redfish credential selector already carried by Target Runtime, explicit
  Redfish environment variables, a direct internal-development Redfish password,
  or a user-selected credentials file.
- When `upgrade_protocol=redfish` selects a legacy staged-upload target, an
  explicit BMC-reachable `image_uri` for the advertised `SimpleUpdate` action.

Require a confirmed recovery path only when rollback or recovery is actually in
scope. Authorization does not create a capability that the backend lacks.

When a shared credentials file is selected, it must contain the Redfish entries
below. It may also contain the documented openubmc-debug SSH, Telnet, and
OS-host credential keys; Upgrade ignores those values and reads only the
Redfish pair.

~~~text
REDFISH_USERNAME=...
REDFISH_PASSWORD=...
~~~

Direct Redfish password arguments are accepted in internal development mode and
may continue through the current Case workflow. Do not read SSH credentials as
a Redfish fallback.

## Preflight

Prefer the unified read-only preflight when all artifact fields are available. It performs stable
artifact hashing, credential validation, target-local UpdateService discovery, and the current
Manager version read without uploading:

~~~bash
python3 <skill-dir>/scripts/preflight_upgrade.py \
  --target https://<bmc> \
  --artifact-path <hpm> \
  --artifact-sha256 <sha256> \
  --product-version <version> \
  --upgrade-protocol auto \
  --verification-mode auto
~~~

Its result reports the selected protocol, verification mode, artifact size versus any advertised
`MaxImageSizeBytes`, the upload encoding/compatibility plan, and WebUI readiness when selected. A green
result authorizes no mutation by itself; pass the same typed artifact identity and protocol policy
into the task-owned Upgrade operation so target, credentials, and artifact are not asked for again.

Re-hash the HPM before touching the target:

~~~bash
python3 <skill-dir>/scripts/artifact_identity.py \
  --path <hpm> --expected-sha256 <sha256> --product-version <version>
~~~

This identity check also binds a four-part product version embedded in the HPM
filename and, when `<hpm>.metadata.json` exists, requires its SHA-256, size, and
`product_version` to match the typed Upgrade request. A stale, malformed, or
symlinked sidecar is a hard preflight failure; do not delete or ignore it to
continue an upgrade.

Validate the target and credential source without printing secrets:

~~~bash
python3 <skill-dir>/scripts/redfish_credentials.py \
  --target https://<bmc>
~~~

Target Runtime defaults to `allow_insecure_tls=true` for internal BMC environments; set it to
`false` when the target has a trusted certificate. The standalone preflight retains system
verification unless `--allow-insecure-tls` is supplied. Do not follow cross-host redirects or reuse
an upload URI discovered from another BMC.

Read the current installed version through the selected target's Redfish
service before upload. A separate openubmc-debug baseline is optional and is
requested only when the caller explicitly needs pre-upgrade runtime evidence.

For multiple targets, call `upgrade_batch` with a non-empty `targets` array. The
HPM identity and authorization are shared; each target may provide its own
Redfish selector, port, and legacy `image_uri`. `max_concurrency` defaults to 4
and is bounded by the backend safety limit (32). The operation returns one
result per target with `completed`, `failed`, `unknown`, or `skipped` status. A failed or
ambiguous target does not cancel already-admitted sibling upgrades; a stop
policy may skip later rollout groups. Reconcile an `unknown` target's durable
journal before retrying that target.

Batch execution performs a read-only preflight for every target by default.
Preflight discovers each target's UpdateService, upload encoding and
compatibility mode, staged-activation requirement, and current version before
any new upload starts. If one target cannot pass preflight, the batch records
that failure and marks every otherwise-ready target as skipped; it does not
partially mutate the batch. Set `preflight=false` only when the caller has an
explicit reason to defer those reads; the worker still verifies the artifact
before its own mutation.

The artifact is verified once per batch and streamed with a fixed
`Content-Length`; workers do not copy the full HPM into independent byte
buffers. If the file changes, disappears, or is replaced while a request is
being streamed, classify that target as `unknown` and reconcile its journal;
do not retry the upload automatically.

Use `target_deadline` for the budget of each target after its worker starts and
`batch_deadline` for an explicit end-to-end cap. If `batch_deadline` is omitted,
Target Runtime derives a cap covering preflight waves and rollout groups. A
`canary_count` admits an initial canary group; `rollout_batch_size` controls
later groups. `max_failures` stops admission after the configured failure
threshold, and `stop_on_unknown=true` stops admission as soon as any target is
ambiguous. Targets not admitted receive `skipped=true` and no mutation journal.

When a batch response is cached with `unknown` targets, use a new outer request
or idempotency identity for the reconciliation call while retaining the same
task, target, and artifact identity. The per-target backend discovers the
unfinished journal and verifies it before any upload path is reopened.

Changing arguments under an already-used outer batch idempotency key is
rejected before the domain backend runs; a changed request cannot create a new
child operation or remote effect. A new outer identity may carry the complete
target list: matching terminal journals are replayed per target, so completed
siblings are not uploaded again. Terminal activation-fallback journals replay
their failed outcome and remain non-blocking for a separately identified
operation.

## Upgrade workflow

1. Query each target's own Redfish UpdateService before the effect boundary.
2. With `upgrade_protocol=auto`, select Redfish when it advertises a complete usable path. Prefer MultipartHttpPushUri,
   then HttpPushUri, then SimpleUpdate. A `HttpPushUri` ending in
   `/FirmwareInventory` with no advertised MultipartHttpPushUri is a known
   legacy compatibility shape: send the HPM as `multipart/form-data` on the
   advertised URI on the first write. Do not send an octet-stream request first
   and then retry with multipart.
3. For SimpleUpdate, use only an image URI that the target can reach; do not
   pretend a local HPM path is a reachable URI. In the legacy staged shape, an
   explicit `image_uri` plus an advertised SimpleUpdate action is required: upload
   once, wait for staging to complete, then submit SimpleUpdate in the same
   mutation transaction.
4. When the legacy Redfish path requires an `image_uri` that was not supplied,
   `auto` selects the same-origin WebUI path before any upload. Explicit
   `upgrade_protocol=redfish` keeps the `image_uri` requirement; explicit
   `upgrade_protocol=webui` bypasses Redfish upload selection. Never change
   protocols after a request crosses the effect boundary.
5. The WebUI path logs in with the Redfish credential pair, uploads the verified
   HPM to `/UI/Rest/FirmwareInventory`, starts it with the server-side
   `/tmp/web/<filename>` path, monitors `UpdateProgress`, and removes its session.
   Read [WebUI upgrade flow](references/webui-upgrade.md) before using this path.
6. Upload once through an in-process HTTP client that keeps credentials out of
   command arguments and output. Large byte uploads use a separate 600-second
   request timeout, bounded by the task deadline; `upload_timeout` may override
   it. Record target, time, request size/timeout on transport failure, HTTP
   status, selected method/encoding, and Task or Monitor URI.
7. Monitor the selected protocol's task before activation or verification. A lost
   response during upload or activation is ambiguous: inspect the durable
   journal and target version/inventory before reopening the local artifact or
   uploading again. Recovery can finish even when the temporary local HPM has
   already been removed. When read-only evidence proves there was no installed,
   available, or pending artifact effect, return `replan_required` without
   uploading in that recovery call.
8. Treat a timeout or connection loss on the SimpleUpdate POST as an
   `activation_connection_lost` observation. Reconnect and poll the installed
   version through the activation window before classifying the result. A
   returned TCP port, completed staging task, or HTTP 202 alone is not success.
9. Use `verification_mode=manager-version` for BMC firmware and require the
   fresh Manager version to match `product_version`. Use
   `verification_mode=task-completion` for component HPMs and require a fresh
   matching WebUI task snapshot with every task `Completed` and `ErrorCode=0`.
   `auto` chooses Manager verification for Redfish and task verification for
   WebUI. A recovered TCP
   port or HTTPS listener is not success. When the target returns on the old
   ActiveBMC version, the requested version exists only as AvailableBMC, and
   UpdateService reports no pending activation work, classify the result as an
   activation fallback instead of polling forever or uploading again. Record
   it as a terminal failed verification so it does not block later work on the
   target; replaying the same operation reports the same failure without
   uploading again.
10. If the caller requested runtime acceptance for a single target, hand the target, installed
   version, and acceptance checks to openubmc-debug.

Use `scripts/target_runtime_adapter.py` for the typed transaction. Upgrade owns
the `upgrade` Redfish lease; Log Analyzer and formal Redfish Testing retain
separate sessions. A completed upgrade advances the target epoch, invalidates
all old lanes, reconnects Redfish for the installed-version read, and admits
optional Debug verification only as fresh evidence from the new epoch.

The MCP mutation operation identity excludes later Debug verification
selectors but includes the target, verified artifact identity, protocol policy,
verification mode, and legacy image URI. Repeating
the same upgrade with changed acceptance checks reuses the durable mutation
journal and does not upload the HPM again; fresh Debug verification still
runs. Change the artifact or mutation parameters, or start a new task, when a
deliberate new upgrade operation is required.
If the local MCP process reconnects with the same task ID, Target Runtime restores the target,
artifact-routing intent, and mutation journal identity but opens a new Redfish resource. Never use
the restored task context as proof that an upload or verification completed; inspect the durable
journal and collect fresh installed-version evidence.

Upgrade keeps a 32-entry target-binding LRU per task by default. This limits retained Redfish
resources, not the number of environments in the Case; selecting an evicted target reconnects it.
Failed workflow steps receive a new attempt through the Runtime's `execute` continuation, while a
durable terminal journal receipt prevents an already completed or terminally failed upload from
being executed again.

`upgrade_batch` uses a separate child operation identity and mutation journal
for every target. Replaying the same batch operation is idempotent per target;
it does not re-upload a terminal journal, and it preserves successful siblings
when another target remains unresolved.

Read [Redfish upgrade flow](references/redfish-upgrade.md) for Redfish and
[WebUI upgrade flow](references/webui-upgrade.md) for WebUI before performing
the write.

## Rollback

The current production Upgrade backend does not expose an independent firmware rollback action. A
Case may carry a distinct rollback authorization, but that decision does not create the missing
backend capability. Do not invent one, relabel a normal upgrade as rollback, or claim that a rollback
HPM was applied. Use only a separately available, explicitly selected recovery mechanism; if none
exists, report the capability gap and stop. Never roll back automatically because an upload,
timeout, restart, or mutation outcome is ambiguous, and never treat Upgrade authorization as
rollback authorization.

## Report

Return the target, artifact path and SHA-256, protocol, method plus encoding,
task URI/status, component task results or installed-version result according to
the verification mode, and activation status when present. Include the separate openubmc-debug verification status only
when runtime acceptance was requested. Report a partial external mutation
honestly when the task state is unknown.

When the Case becomes terminal, Target Runtime automatically derives and
persists `closeout`, `closeout_markdown`, and the default `closeout_bundle`.
Use the Markdown as the user-facing first screen and the bundle as the immutable
index for Closeout documents, build evidence, HPM identity, mutation journal,
installed-version proof, and fresh Debug acceptance evidence.

## Resources

- [Redfish upgrade flow](references/redfish-upgrade.md)
- [WebUI upgrade flow](references/webui-upgrade.md)
- scripts/artifact_identity.py
- scripts/redfish_credentials.py
- scripts/target_runtime_adapter.py
