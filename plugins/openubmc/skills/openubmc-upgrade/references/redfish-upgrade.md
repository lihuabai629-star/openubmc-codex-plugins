# Redfish Upgrade Flow

This reference covers `upgrade_protocol=redfish`. For the same-origin WebUI
transport, read [WebUI upgrade flow](webui-upgrade.md). Protocol selection is a
pre-effect decision; an ambiguous Redfish upload is reconciled through its
journal and is never followed by a WebUI upload in the same operation.

## Discovery

Read the target's own:

~~~text
GET /redfish/v1/UpdateService
~~~

Use only its target-local advertised URI. Prefer:

1. MultipartHttpPushUri
2. HttpPushUri
3. Actions/#UpdateService.SimpleUpdate

Require an in-process HTTPS client with Basic or session authentication sourced
from direct internal-development input, the task context, environment selectors,
or the selected credentials file. Reject a URI that is not relative to, or on
the same HTTPS origin as, the selected BMC.

The Target Runtime lane defaults to disabled certificate verification for internal BMC targets.
Before any fresh upload, bind `artifact_path`, `artifact_sha256`, and
`product_version` as one identity. If the HPM filename contains a four-part
version, it must equal `product_version`. If `<hpm>.metadata.json` exists, its
SHA-256, byte size, and product version must also match; malformed, stale, or
symlinked metadata blocks the operation without creating a remote effect.

Set `allow_insecure_tls=false` when the target certificate is trusted. Standalone preflight keeps
system certificate verification unless `--allow-insecure-tls` is supplied.

### Legacy endpoint compatibility

If `MultipartHttpPushUri` is absent and `HttpPushUri` ends in
`/FirmwareInventory`, classify the target as the legacy collection-endpoint
shape. Send the HPM as the standard multipart envelope to that advertised URI
on the first write. This avoids a binary request that the endpoint may reject
with a gateway error after the effect boundary.

When that shape also advertises `#UpdateService.SimpleUpdate`, require an
explicit target-reachable `image_uri` from the target response or deployment
contract. Wait for the upload/staging task, then post SimpleUpdate with that
URI. Never guess a `/tmp/web` path and never change encoding after an ambiguous
response in the same operation.

## Mutation

- Multipart upload sends the HPM as the UpdateFile part and follows the target's
  documented parameters.
- HttpPush uploads the HPM body to the target-advertised URI. For the legacy
  collection-endpoint shape, use the multipart envelope and record
  `encoding=multipart/form-data`.
- SimpleUpdate posts an explicitly supplied, BMC-reachable ImageURI; it does
  not upload a local file.

Use the normal Redfish timeout for discovery and status reads. Use the separate
`upload_timeout` for MultipartHttpPushUri and HttpPushUri byte transfer; its
default is 600 seconds and the task deadline remains the outer bound. A lost
transport response must report the selected path, request byte count, timeout,
and exception type without including credentials or artifact content.

Capture the returned Location, TaskMonitor, or task URI. Do not retry an
ambiguous request before checking that resource.

For SimpleUpdate, a timeout or transport loss is an
`activation_connection_lost` observation. Reconnect and verify the installed
version through the reboot window before declaring failure; an old version
read immediately after the disconnect is not enough to classify an activation
fallback.

## Monitoring

Poll the returned task or monitor URI until a terminal state. Handle a reboot
window by reconnecting and checking the same task or installed version. Treat
Completed as necessary but not sufficient: re-read the installed version.
Invoke openubmc-debug afterward only when the caller requested runtime
acceptance.

After an observed activation disconnect, correlate the Manager version with
the target's FirmwareInventory and pending UpdateService work. If the old
version is ActiveBMC, the requested version remains only in AvailableBMC, and
there is no pending task or firmware-to-take-effect entry, report an activation
fallback. This is a completed failed outcome, not a reason to repeat the
upload. Persist it as a terminal failed verification: a replay of the same
operation returns the same activation-fallback outcome without uploading, and
the completed journal does not block a later, separately identified operation
on the target. Keep a plain old-version observation retryable when the target
does not provide enough inventory or pending-work evidence to classify it.

For an upload that failed after the effect boundary, run the same read-only
classification before reopening the local artifact. If the expected version is
neither installed nor present in inventory and no activation work is pending,
transition the journal to `replan_required` and return that result without an
upload. This recovery remains possible when the temporary HPM file is gone;
any later deliberate replan must provide and re-hash the artifact again.

The Target Runtime transaction keeps the Upgrade Redfish Session isolated from
other domains. After activation, it advances the target epoch and reopens the
Upgrade Session before reading the installed version. Any optional Debug
acceptance must run through the same fresh-verification context and cannot use
pre-upgrade evidence.

## Batch execution

`upgrade_batch` applies this transaction independently to every target. It
shares only the immutable artifact identity and verified streaming HPM source;
target bindings, credentials, Redfish sessions, mutation leases,
operation IDs, journals, reconnect loops, and version evidence remain isolated.
Use bounded worker concurrency (default 4, maximum 32), preserve input order in
the report, and reject duplicate `ip:redfish_port` endpoints before starting
workers. One target failure or ambiguous result must be recorded without
cancelling already-admitted sibling transactions; later groups may be skipped
by the rollout policy.

By default, the batch first performs a read-only preflight wave for all targets.
Each preflight reads the target-local UpdateService and Manager version and
reports the selected method, encoding, compatibility mode, and staged
activation. No new upload is admitted until every target passes this barrier;
targets that pass are returned as `skipped` if another target fails preflight.
Existing unfinished journals may use a recovery inspection instead of upload
discovery, and terminal successful journals are replayed without contacting the
target. `preflight=false` disables only the barrier; the worker still validates
the artifact before mutating.

The shared artifact is hashed once and each request streams directly from the
verified regular file with a fixed Content-Length. The stream re-checks the
file descriptor and path identity. A replacement, truncation, deletion, or
other change during streaming is an ambiguous local-input failure: persist the
target outcome as `unknown` when effects had started and reconcile before any
retry.

The aggregate result reports completed, failed, unknown, and skipped counts. A target
with a non-terminal or uncertain journal is `unknown`; reconcile that journal
before any later upload. Replaying the same batch operation uses the same child
operation identities, so completed targets remain idempotent.
If the outer Runtime has already cached the aggregate response, start the
reconciliation with a new outer request identity but the same task, target, and
artifact identity. The per-target recovery scan still binds to the unfinished
journal and prohibits a blind upload.

`target_deadline` starts when each worker is admitted; `batch_deadline` is an
optional explicit end-to-end cap. Without it, Runtime derives a cap from the
target count, concurrency, preflight waves, rollout groups, and per-target
deadline. `canary_count` and `rollout_batch_size` control admission groups.
`max_failures` stops later groups after the failure threshold, while
`stop_on_unknown` stops on the first ambiguous target. Unadmitted targets are
reported with `skipped=true` and `BatchRolloutStopped` and have no remote side
effect.

An outer idempotency-key conflict is rejected before the batch domain backend
runs, so changing the target list cannot create a new child operation as a
side-effect of reporting the conflict. A new outer identity may reconcile a
complete list: terminal successful journals are replayed per target and
terminal activation-fallback journals replay their failed result without a
second upload.

## Failure

Stop on TLS, authentication, discovery, hash, or target-origin failure. Do not
fall back to SSH, Telnet, a copied upload URI, or a second upload. Rollback
needs a separate explicit authorization and artifact identity.

### Task diagnostics

The monitor retains `TaskState`, `TaskStatus` and standard `Messages` fields after
sanitization. `Completed` with `Warning` remains visible alongside fresh firmware
version verification. Missing or malformed message data is reported explicitly;
an absent message does not imply an `OK` task status.

Task diagnostics are saved with the upgrade operation before terminal failure is
raised. Message collections exceeding the inline evidence budget are preserved in
a redacted ArtifactRef bound to the target, task and operation. The artifact index
persists across Runtime restarts. The inline receipt points to the full evidence;
large message collections are not silently discarded.
