# Installed Host records

The plugin registers SessionStart and UserPromptSubmit hooks. When Codex enables
trusted plugin hooks, their session identity and working directory select the
project for new Runs. Git status supplies the repository commit, branch and dirty
state. The private Host bookmark store retains the local directory; Run records
and exports contain opaque references only. No selection from an Agent argument,
notes or MCP metadata becomes a workspace snapshot.

A Start freezes that observation in the Runtime transaction. Existing Runs keep
their original context through selection changes and restart. Missing hooks or
unsupported identities remain unavailable; no plugin cache directory is used as
a project fallback. A Start retry with changed context can conflict and must
retain the original operation binding.

## Local records and export

Use the installed plugin's `scripts/pluginctl.py` with the same Runtime state root
as its MCP service:

```sh
python3 -I /path/to/installed/openubmc/scripts/pluginctl.py records --task-id TASK_ID
python3 -I /path/to/installed/openubmc/scripts/pluginctl.py export-records \
  --task-id TASK_ID --output-directory /private/export-directory
python3 -I /path/to/installed/openubmc/scripts/pluginctl.py verify-records \
  --record-file /private/export-directory/DIGEST.json
python3 -I /path/to/installed/openubmc/scripts/pluginctl.py prune-records \
  --output-directory /private/export-directory --before-timestamp UTC_EPOCH_SECONDS
```

Pruning defaults to a preview. Add `--apply` for deletion. Only valid,
content-addressed exports inside the owned private directory are eligible.
Linux/WSL uses private POSIX permissions; native Windows export storage uses the
existing current-user ACL authority. Shared directories are rejected rather than
silently repaired.

`export-records --evidence FILE` accepts the existing W03 operation evidence
snapshot. Only exact Run/repository/clean-commit/command-digest/log-digest bindings
survive projection. Missing evidence stays unavailable. Export validation checks
schema and integrity, not the trust of an arbitrary file's producer.

On native Windows, use the dependency-free offline tool with an existing handoff
exported by the Runtime Host:

```powershell
python /path/to/installed/openubmc/skills/openubmc-target-runtime/tools/record_export.py export `
  --handoff handoff.json --producer-commit FULL_SOURCE_COMMIT --output-directory PRIVATE_DIRECTORY
```

This offline command uses the record modules and current-user ACLs. The public
plugin's execution backend on Windows remains WSL.

## Measurement registration

Records use v2. With no trusted source, usage, time and human intervention remain
unavailable/null. Codex cumulative session usage is not split into invocations.
The Host can register one source in the process environment:

- `OPENUBMC_HOST_MEASUREMENTS_FILE`: an existing W02 normalized snapshot.
- Or `OPENUBMC_HOST_PROVIDER_REPORT` with `OPENUBMC_HOST_PROVIDER_REF`: a durable
  `openubmc.provider-requests/v1` report. `OPENUBMC_HOST_EVIDENCE_KIND` defaults
  to `observed`; use `synthetic` for a controlled fixture.

The report must match the Task, provider and evidence kind. It supplies an
explicit boolean `inventory_complete`; partial/crashed producers cannot claim
complete totals. The existing model-measurement relay persists a fresh physical
invocation identity before each upstream request and an updated observation after
completion. A new physical retry gets a new identity. Reports without exact Run
attribution count only toward the Task; they do not fill Run usage. An unavailable
or conflicting source clears the projection to unknown on the next read.

Hooks and registration do not grant device authority, attest test success, or
identify a human actor. Gate responses alone are not human events. Native Host
qualification uses a loopback response fixture separately from live model/device
acceptance.
