# Diagnose Mode

Use to explain an existing build, package, signing, dependency, or artifact-verification failure.

## Procedure

1. Read `finalization.json` first when available, then its bound Plan, Attempt state, command, log, verification, and gate reports.
2. Classify the failure without changing checkout, versions, Manifest refs, Conan cache, remotes, or Skill installation.
3. Separate facts, high-confidence inference, and unproven boundaries.
4. Identify the smallest next experiment or corrected Plan.

Do not automatically rebuild. If the user requests a retry and no semantic input changes, create another Attempt from the same Plan. If an input changes, show the Plan delta and create a new Plan.

Standalone gate reports are diagnostic evidence only. They do not prove artifact acceptance without the matching locked finalization.

## Completion

The root-cause category, supporting evidence, unresolved boundary, and next action are explicit.
