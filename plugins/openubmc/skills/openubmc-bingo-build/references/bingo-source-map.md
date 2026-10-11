# Bingo Source Map

This reference summarizes source facts from the community `openUBMC/bingo` repository.

Source snapshot used when creating this skill: `3e14980 !422 merge full_use into main`.

## Entry Point

- `setup.py` exposes the `bingo` console command.
- The CLI dispatcher defines command groups and dispatches built-in and functional commands.
- The command set shown by `bingo --help` changes according to repository configuration.

## Workspace Detection

The bingo CLI decides command availability from repository signals:

- Component workspace: `bconfig.component` is set, normally from component metadata such as `mds/service.json`.
- Integrated manifest workspace: `.bingo/config`, `build/frame.py`, `frame.py`, or manifest config is present.
- Functional commands can add their own `if_available(bconfig)` checks.

## Main Built-in Commands

| Command | Workspace | Purpose |
| --- | --- | --- |
| `bingo build` | component or manifest | Build component Conan package or product target |
| `bingo publish` | manifest | Alias path that appends `-t publish` and runs the product build frame |
| `bingo test` | component | Run component DT test flow |
| `bingo gen` | component | Generate Lua/C code, defaulting to `mds/service.json` when present |
| `bingo deploy` | component or product path depending on command availability | Deploy package or product image according to config |

## Functional Commands

Functional commands are loaded by the CLI and are visible when their availability checks match the current workspace.

| Command | Availability | Purpose |
| --- | --- | --- |
| `bingo fetch` | manifest or package-info mode | Fetch source for product, subsystem, manifest.yml, or package refs |
| `bingo diff` | manifest | Compare component version changes between two manifest commits/version ids |
| `bingo analysis` | component or manifest | Analyze dependency and interface consistency |
| `bingo lock` | manifest or SDK-style repository | Create/update product or platform lockfile |
| `bingo config` | always | Manage global/local/environment/deploy configuration |
| `bingo upgrade` | always | Install or upgrade bingo and related tools |
| `bingo check` | always, but meaningful with component/manifest context | Syntax and model consistency check |

## Product Build Frame

The product build frame drives integrated product builds:

- Discovers built-in targets and optional repository target extensions.
- Allows repository target extension from `build/target/*.yml`.
- Parses common product args such as board, build type, stage, version, target, and deploy flag.
- Writes build outputs under manifest `output/`.
- Can optionally deploy an HPM after a successful build when `--deploy` is used.

## Component Build

Component build commands commonly support:

- `-bt/--build_type`
- `--stage`
- `-u/--upload`
- `-r/--remote`
- `--conan2`
- `-o/--options`
- `--user`
- `-pr/--profile`
- `-jit/--enable_luajit`
- `-wb/--without_build`

Component builds generate helper files and then run Conan create/upload flows according to the selected options.

## Conan Selection

Bingo checks whether Conan 1 or Conan 2 is needed:

- Component: inspect `conanfile.py` `required_conan_version` unless `--conan2` forces Conan 2.
- Manifest/SDK: inspect `.bingo/config` `conan.version`.
- If the installed Conan major version mismatches the required one, bingo attempts to install the expected version and asks the user to rerun.
