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

## Component impact and acceptance

For changes that cross a model/interface boundary or require several components,
collect the task's explicit changed paths and an evidence-backed dependency graph:

```bash
python3 <build-skill>/scripts/detect_changed_components.py \
  --root <workspace> --path interface/mds/model.json \
  --impact --dependency-graph <graph.json> --json
```

The graph is data, using this structure (roots are relative to the workspace;
evidence paths are relative to the graph file):

```json
{
  "schema": "openubmc.component-dependencies.v1",
  "complete": true,
  "components": {"interface": "interface", "consumer": "consumer"},
  "edges": [{"provider": "interface", "consumer": "consumer", "evidence_path": "resolved-dependencies.json"}],
  "dynamic_dependencies": []
}
```

Set `complete` only when the supplied dependency evidence covers the selected
workspace. List unresolved dynamic dependency owners explicitly. The helper does
not discover missing graph edges or execute repository configuration. Model,
interface and protocol inputs expand through the supplied consumer edges; ordinary
source changes retain their direct component and upstream source bindings.
Unmapped paths, incomplete graphs, dynamic dependencies and cycles appear in
`gaps`. They cannot establish completed component acceptance. Explicit MDS, proto,
or interface/path contract directories expand proven consumers, including paths
with a trailing slash. Other directory inputs retain `directory_scope_unresolved`;
provide the specific changed files to resolve that scope.

Graph and individual dependency-evidence files are limited to 1 MiB; distinct
evidence totals at most 16 MiB. A graph contains at most 128 components and 1,024
edges. Source binding reads raw local files through a Git file inventory without
running clean filters or fsmonitor: `source` binds the absolute component root,
`git_head`, and `content_sha256` (paths, modes and local bytes, including untracked
nonignored files). It has limits of 50,000 files, 16 MiB per file and 256 MiB total.
These are source identities, not a declaration that a build executed.

Attach the emitted report unchanged as `change_impact` in a `developer.change`
or `build.artifact` Gate response. Each `component_validation` row contains:

- `component`, `source` and `dependencies`, copied from its impact entry and checked
  against the source and dependency inputs actually used for validation;
- `dependency_readiness` and `validation_results`, using the existing Validation
  Readiness contract independently for that component. Both official UT and build
  must pass; supplementary checks do not replace them.

The Runtime checks coverage, identities and classifications. It does not rerun
commands or infer successful execution from source hashes. Supply actual command
Evidence IDs under the existing validation rules. Existing product artifact
binding and fresh target verification still apply.

For incomplete work, respond with `status: partial`, the fixed impact report, and
available component rows. RunEngine records that submission and returns the same
phase at a new Gate version. After resuming, submit only missing or updated rows;
previous rows from that phase persist across process restart. A replacement row
supersedes that component's earlier result. `completed` requires full passing
coverage. An invalid completed submission leaves the Gate unchanged and records
none of that rejected submission's rows.

The accepted impact remains fixed through later handoffs in the same Run cycle.
A changed source, dependency identity or impact scope needs a new Run. Build-phase
rows are collected separately from developer-phase rows. Legacy responses without
an impact report keep their existing single-component behavior.
