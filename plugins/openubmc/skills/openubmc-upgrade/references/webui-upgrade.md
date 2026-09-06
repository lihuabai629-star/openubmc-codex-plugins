# openUBMC WebUI Upgrade Flow

Use this path only when the typed Upgrade operation selects
`upgrade_protocol=webui`, or when `auto` deterministically selects it before any
upload. It is a same-origin firmware transport, not browser automation.

## Selection

The WebUI path is appropriate for openUBMC targets whose Redfish UpdateService
advertises the legacy `/FirmwareInventory` staging shape but cannot complete
that flow without an unavailable BMC-reachable `image_uri`. An explicit
`upgrade_protocol=redfish` keeps the Redfish requirement and does not fall back.

Protocol selection belongs before the effect boundary. An accepted, timed-out,
or otherwise ambiguous Redfish upload is reconciled through its existing
journal; it is never followed by a WebUI upload in the same operation.

## Session and upload

Use the Redfish username and password only as the WebUI login payload. Keep the
password in memory and out of command arguments, logs, journal fields, and
reports.

1. `POST /UI/Rest/Login` and retain the returned `SessionId` cookie and CSRF
   token.
2. `POST /UI/Rest/FirmwareInventory` as `multipart/form-data` with the HPM in
   the `imgfile` part. Stream the already-verified artifact with a fixed
   `Content-Length`.
3. Accept only a returned path beneath `/tmp/web` whose basename equals the
   artifact basename. When the upload response omits the path, use
   `/tmp/web/<artifact-basename>`.
4. `POST /UI/Rest/BMCSettings/UpdateService/FirmwareUpdate` with only
   `FilePath`. Extra update flags require a separately typed feature because
   older targets reject unsupported properties and their semantics affect the
   mutation identity.
5. Remove the created session through SessionService when the operation or
   read-only verification finishes. Cleanup failure is reported as cleanup
   evidence, not as proof that the firmware task failed.

## Task monitoring

Poll `/UI/Rest/BMCSettings/UpdateService/UpdateProgress`. Scope global progress
to tasks whose `FileName` basename matches the uploaded artifact. A task URL
returned by the start response supplies a task ID for a more specific fallback
read when the global response has no matching entry.

Success requires a non-empty matching task set where every task has a success
state and `ErrorCode=0`. Treat `Exception`, `Failed`, `Warning`, `Killed`,
`Cancelled`, `Interrupted`, `Suspended`, any non-zero error code, or an invalid
error code as failure. Preserve the component, percentage, version, firmware
ID, and error code in the result.

A connection loss after the upload or start boundary is ambiguous. Reopen a
fresh WebUI session and search for the matching artifact task before deciding.
Before upload, persist an order-independent multiset of stable matching-task
identities (`TaskName`, `Component`, `FileName`, `FirmwareId`, and `Version`).
Without a task ID, recovery accepts only identity instances added beyond that
baseline; task order, percentage, state, and error-code changes do not make a
historical task fresh. If a fresh task is running, continue verification; if
completed, finish recovery; if failed, persist a terminal failure. A missing
task alone is not evidence to upload again when the earlier response was
ambiguous.

## Verification modes

- `task-completion`: for CPLD, VRD, CSR, HWSR, and other component packages.
  Fresh verification reopens the WebUI session and requires the matching task
  result again. It does not label the package version as the installed BMC
  Manager version.
- `manager-version`: for a BMC image transported through WebUI. After the WebUI
  task completes, reconnect through Redfish and require the Manager version to
  equal `product_version`.
- `auto`: selects task completion for WebUI. Callers upgrading a BMC image
  through WebUI should select `manager-version` explicitly.

## Batch behavior

Preflight every target before admitting the batch. A WebUI preflight logs in,
reads UpdateProgress, and closes the session without uploading. Each target
retains its own WebUI cookie jar, CSRF token, task observation, mutation
journal, and deadline. A session or task from one target is never reused for a
sibling.
