---
name: openubmc-bingo-development
description: "Develop or debug the openUBMC Bingo CLI itself: command registration, argument parsing, workspace detection, build task orchestration, tests, and Python packaging. Do not use merely to run bingo in a component or Manifest workspace."
---

# openUBMC Bingo Development

Use this Skill only when the requested change is in the Bingo CLI source. A
request to run `bingo build`, `bingo test`, `bingo gen`, or another installed
Bingo command belongs to `openubmc-bingo-build`.

## Locate the owning code

Inspect the current repository before editing. Confirm the CLI entry point,
command registration, workspace availability check, parser, and the component or
product task implementation that owns the behavior. Bingo exposes commands based
on workspace type, so a command must not become globally available unless it is
safe in every workspace.

Preserve the existing command-extension contract, including command metadata,
availability checks, argument validation, and dispatch through the public CLI.
Do not bypass the dispatcher to make one example pass.

## Verify the change

Add a behavior test at the public command or parser seam, then implement the
smallest source change that makes it pass. Run the focused suite and the real CLI
path from an isolated sample workspace. If imports, entry points, or package data
change, also verify the locally built `openubmc-bingo` package and `bingo --help`.

Keep product builds, Conan remotes, credentials, and live BMC operations outside
source-development tests. If validation needs a remote or a large product tree,
report that dependency and retain the available deterministic checks.
