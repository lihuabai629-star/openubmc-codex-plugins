# Build Handoff Contract

When another workflow routes into `openubmc-build`, prefer a structured handoff over `git diff`. The handoff records what was changed in the active session; it is not a dirty-worktree inventory.

## Minimal Handoff

```json
{
  "mode": "validate",
  "changed_files": [
    "general_hardware/src/lualib/example.lua",
    "general_hardware/mds/model.json"
  ],
  "changed_components": [
    {
      "name": "general_hardware",
      "root": "/home/workspace/source/general_hardware",
      "reason": "code and MDS model changed",
      "need_bmcgo_gen": true
    }
  ],
  "command": {
    "source": "handoff",
    "cwd": "/home/workspace/source/general_hardware",
    "argv": ["bmcgo", "build", "-bt", "debug"]
  }
}
```

## Field Rules

| Field | Rule |
| --- | --- |
| `mode` | One of `validate`, `component-package`, `product-artifact`, `diagnose`, or `publish`. Choose the least-side-effect mode that safely contains the command's actual effects; reject or reroute a handoff whose mode contradicts a known product command before creating the Plan. |
| `changed_files` | Files actually touched in the current task/session, not every dirty file from git status. |
| `changed_components` | Component roots to build; include interface/model packages when they must be rebuilt. |
| `need_bmcgo_gen` | `true` when MDS, MDB interface/path JSON, properties, methods, events, or generated-contract inputs changed. |
| `command` | Exact cwd and argv when already known. Preserve argv unchanged; do not infer target, stage, remote, or version from another field. |
| `delivery_strategy` | `build-upgrade` requests an Upgrade continuation; actual handoff still requires `upgrade_eligible: true`. Omit it for a standalone build. Live Patch does not consume a Build result. |
| `deployment.requested` | Routing metadata only. `true` requests Upgrade after an eligible Build result; `package_binding_unverified` keeps the route blocked. Build performs no target access. |
| `deployment.method` | `redfish` for the Upgrade handoff. Build does not implement transport fallback. |
| `deployment.target_bmc` | Optional target identity retained by the task. Null means build only. Do not store credentials here. |
| `deployment.rollback_required` | Passed through to Upgrade; Build does not inspect or execute rollback. |

If a handoff is missing, reconstruct it from the current conversation and explicit paths first. Use git status only as a fallback candidate list.

## Build Result

Return a typed artifact identity after accepted local finalization completes:

```json
{
  "artifact_path": "/absolute/path/to/openubmc.hpm",
  "artifact_sha256": "<64 lowercase hex characters>",
  "product_version": "<version verified inside the final rootfs image>",
  "package_binding": "package_binding_unverified",
  "upgrade_eligible": false,
  "evidence_ids": ["<build evidence ID>"]
}
```

For `build-upgrade`, pass these fields to `openubmc-upgrade` only when `upgrade_eligible` is true. `package_binding_unverified` is a local build result, not an Upgrade authorization. Target coordinates and credential selectors stay in the task-owned TargetRun and are not copied into the Build result.
