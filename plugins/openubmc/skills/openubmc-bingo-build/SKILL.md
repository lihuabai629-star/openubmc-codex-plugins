---
name: openubmc-bingo-build
description: "Run openUBMC Bingo component or product builds, tests, code generation, source fetch, dependency analysis, and manifest package creation. Use for explicit bingo commands or Bingo-managed workspaces; route Bingo CLI source changes to openubmc-bingo-development."
---

# openUBMC Bingo Build

When the task enters another workflow stage, read [the phase handoff](<../openubmc-debug/references/skill-routing.md>)
and load its owner before acting; carry the existing Run and authorization.

Use the repository's installed `bingo` command and its current help output. This
Skill owns running Bingo in component and Manifest workspaces. It does not modify
the Bingo CLI source, upload an already-built Conan component package, or deploy
firmware to a BMC.

On native Windows without a selected capable build environment, report
`build_environment_unavailable` with the actual host and missing Bingo/toolchain
prerequisites. Device Runtime remains on Windows. Use WSL for this build only
when the task explicitly selected it.

## Establish the workspace and command

Run `bingo --version` and the relevant `bingo <command> --help` before selecting
options. Classify the working directory from repository evidence:

- `mds/service.json` identifies a component workspace.
- `.bingo/config`, `build/frame.py`, or `build/product/` identifies a Manifest
  product workspace.
- If neither is present, stop and identify the correct checkout instead of
  falling through to `bmcgo` or raw `conan create`.

Preserve an explicit user command exactly unless current help proves an option is
invalid. Do not add `-sc` to product builds. A normal stable product release uses:

```bash
bingo build -t publish -b <board> -bt release --stage stable
```

Resolve `<board>` from the requested product and the repository's
`build/product/` entries. Do not invent a default board.

## Component work

Use the command that matches the requested artifact or check:

```bash
bingo gen
bingo build -bt release --stage stable
bingo test
bingo analysis
```

Treat `-u` or any remote upload option as publication. Use it only when the user
explicitly requested that upload and the remote identity is established. An
already-built Conan package belongs to `openubmc-publish`.

## Product and Manifest work

For a product build, record the Manifest checkout, board, target, build type,
stage, dependency or lock identity, and expected output before execution. A
successful command is only a build result. Accept the product package after the
required syntax, integrity, unpack, service-start, and rollback gates produce
evidence for that exact artifact.

Use `bingo fetch`, `bingo diff`, `bingo analysis`, or `bingo lock` only when the
request requires those operations. Inspect the command's current help and the
repository's lock convention before changing a lock file.

## Ownership boundaries

- Changes to Bingo's own parser, commands, workspace detection, or packaging go
  to `openubmc-bingo-development`.
- `bmcgo` validation and non-Bingo component or product plans go to
  `openubmc-build`.
- Uploading an existing Conan component package goes to `openubmc-publish`.
- Firmware upload, activation, and target verification go to `openubmc-upgrade`.

Do not substitute another build tool without the source, profile, options,
dependency graph, expected artifact, and release-gate equivalence receipt.

## Command and source references

For command selection, read the [command cheatsheet](references/bingo-command-cheatsheet.md).
For workspace ownership or unexpected dispatch, read the [source map](references/bingo-source-map.md).
For dependency resolution and UT profiles, read [dependency and profile compatibility](../openubmc-build/references/dependency-profile-compatibility.md).
