# Cross-Module State and Lifecycle

Read this reference only when a change has competing owners, spans lifecycle
states or modules, or needs workspace isolation. The core workflow in
`SKILL.md` is sufficient for ordinary local changes.

## Resolve competing ownership

When several locations could make the test pass, choose by behavioral
responsibility, state ownership, dependency direction, consumer locality, and
testability. Compare only the precedents that can change that decision.

Prefer one authoritative state writer. Keep adapters and query surfaces from
becoming repair loops or secondary owners. Create a public abstraction only
when the behavior is genuinely shared, no existing extension point fits, and
the added ownership is clearer than a local implementation.

## Trace state and lifecycle

Follow observable behavior through the complete path:

```text
input or event
  -> validation and normalization
  -> state transitions
  -> externally visible state or side effect
  -> direct consumers
```

Identify the source of truth and every writer. Prefer one authoritative writer
over repair loops between competing implementations. Distinguish unavailable,
absent, transitional, stale, ambiguous, failed, and usable states when callers
can observe the difference.

Account for the lifecycle branches that can materially change the contract:

- startup and dependency ordering;
- producer or consumer restart;
- add, remove, replacement, and hotplug;
- work already in flight when a new event arrives;
- late or stale completion;
- partial registration, publication, or cleanup;
- retry exhaustion and recovery ownership;
- mixed-version upgrade and rollback;
- stale persistent, cached, or generated state.

Normal-path success proves only that path. Select the lifecycle branches that
can change the requested contract instead of expanding every local edit into a
full failure-mode review.

## Protect the workspace

Treat existing tracked and untracked content as active user work. Apply the
core worktree policy only when workspace state affects the source decision or
safe implementation.

A dirty tree does not by itself require isolation. Inspect current changes,
preserve unrelated hunks, and pause only when an overlap cannot be separated
confidently. For a multi-repository change, determine isolation independently
for each repository instead of treating the parent directory as one workspace.

When a worktree or clone is created for the task, record its absolute path,
reason for isolation, and intended consumer. Record revision identity only when
it materially identifies the state being handed off. Preserve the workspace
when later work still needs that exact source state; cleanup remains a separate
explicit action.

## Review material effects

Select only dimensions relevant to the change: public contracts, persistence,
async ordering, startup and replacement, hardware I/O, sensitive data, and
direct consumer assumptions.

Compare the completed diff with the selected precedent. Check for duplicate
ownership, misplaced policy, layer leakage, bypassed interfaces, unnecessary
abstractions, and omitted lifecycle branches. Keep source checks and later
product or runtime evidence distinct.
