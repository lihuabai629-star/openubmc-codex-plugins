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
4. Identify command-owned outputs such as `gen/`, build output and coverage data.
5. For ordinary local validation, execute the command directly and retain its cwd,
   argv, log and exit status. Reuse an existing Plan/Attempt when one is already
   selected or a Runtime build Gate requires it; declare its precise mutable paths.
6. Report the result and resulting source-tree changes. Release-only metadata,
   artifact qualification and unrelated environment checks do not gate validation.

Generation can partially rewrite `gen/` before failing. Account for every resulting source-tree change before completion.

## Completion

The exact validation command has a checked terminal result. Changes below declared command-owned mutable outputs are expected; every other source-tree change is identified as drift. No package publication or HPM build is implied.
