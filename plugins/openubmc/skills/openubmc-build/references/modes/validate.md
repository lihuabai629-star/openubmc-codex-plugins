# Validate Mode

Use for `bmcgo gen`, local component compilation, UT, static checks, or another command that does not produce a product rootfs/HPM. A Manifest product build cannot run in this mode.

## Inputs

- selected component or repository checkout;
- exact user/handoff argv when supplied;
- changed files/components relevant to this task.

Use `scripts/detect_changed_components.py` only as a candidate scan when the active task does not already identify the component.

## Procedure

1. Reuse the selected checkout.
2. Leave component versions, product versions, and Manifest refs unchanged.
3. Preserve a complete supplied argv exactly. If no command exists, inspect the selected checkout and local help, then form one candidate for the requested validation only.
4. Before creating the Plan, identify only the command-owned checkout outputs. Add precise `--mutable-path` entries for directories such as `gen/`, build output, or coverage data that the command is expected to rewrite.
5. Create a `validate` Plan.
6. Execute an Attempt and report its terminal state and log.

Generation can partially rewrite `gen/` before failing. Account for every resulting source-tree change before completion.

## Completion

The exact validation command has a checked terminal result. Changes below declared command-owned mutable outputs are expected; every other source-tree change is identified as drift. No package publication or HPM build is implied.
