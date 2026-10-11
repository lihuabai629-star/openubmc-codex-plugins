# Bingo Architecture Map

This reference maps the community bingo source tree for development tasks. Public wording should call the project `bingo`; source paths below use the repository's real file names so agents can navigate accurately.

Source snapshot used when creating this skill: `3e14980 !422 merge full_use into main`.

## Entry and CLI Dispatch

| Source path | Responsibility |
| --- | --- |
| `setup.py` | Defines the `openubmc-bingo` package and `bingo` console script entrypoint. |
| `bmcgo/bmcgo.py` | Runtime entry that calls the CLI dispatcher. |
| `bmcgo/cli/cli.py` | Main command dispatcher, help rendering, dynamic functional command loading, Conan version checks, and error analyzer hook. |
| `bmcgo/misc.py` | Shared command group constants, `CommandInfo`, stage/build-type helpers, and common constants. |
| `bmcgo/bmcgo_config.py` | Workspace/config detection for component, manifest, SDK, conan-index, signing, and encryption configuration. |

## Command Groups

The CLI owns built-in command dictionaries, then loads extra functional commands from `bmcgo/functional/*.py`.

| Group | Typical commands | Notes |
| --- | --- | --- |
| Integrated commands | `build`, `publish` | Product/manifest build flow. |
| Component commands | `build`, `deploy`, `test`, `gen` | Component build, deploy, test, and code generation. |
| Misc commands | `help`, `fetch`, `diff`, `config`, `upgrade`, `analysis`, `lock`, etc. | Functional command modules decide availability. |
| Conan Index commands | `build` | Conan-index specific build flow. |
| SDK commands | command set depends on config | SDK style repositories. |
| Studio commands | `studio`, `check` | Studio and model consistency checks. |

## Functional Command Pattern

Each functional command module should expose:

- `command_info`: command metadata.
- `if_available(bconfig)`: workspace availability check.
- `BmcgoCommand`: command implementation class.

The dispatcher ignores modules that do not provide the required contract.

## Component Development Areas

| Source path | Responsibility |
| --- | --- |
| `bmcgo/component/package_info.py` | Component package metadata, common build arguments, Conan package identity, codegen policy checks. |
| `bmcgo/component/build.py` | Component build and Conan create/upload flow. |
| `bmcgo/component/gen.py` | Lua/C code generation command behavior. |
| `bmcgo/component/test.py` | Component unit, integration, fuzz, mock, and coverage-oriented test command behavior. |
| `bmcgo/component/deploy.py` | Component deploy behavior. |

## Manifest/Product Build Areas

| Source path | Responsibility |
| --- | --- |
| `bmcgo/frame.py` | Product build argument parsing, target selection, output coordination, and optional deploy hook. |
| `bmcgo/target/*.yml` | Built-in product build targets such as `personal`, `publish`, `app`, and `install_sdk`. |
| `bmcgo/tasks/*.py` | Product build tasks including dependency download, rootfs image, HPM packaging, metadata, and packet generation. |
| `bmcgo/utils/config.py` | Product/manifest config loading used by build frame. |

## Important Functional Commands

| Source path | Command | Development focus |
| --- | --- | --- |
| `bmcgo/functional/fetch.py` | `bingo fetch` | Source fetching from manifest, subsystem, package-info, or package refs. |
| `bmcgo/functional/diff.py` | `bingo diff` | Component version diff and source merge record tracing. |
| `bmcgo/functional/analysis.py` | `bingo analysis` | Dependency and interface analysis. |
| `bmcgo/functional/conan_lock.py` | `bingo lock` | Product/platform lockfile create and update. |
| `bmcgo/functional/config.py` | `bingo config` | Global, local, environment, and deploy configuration. |
| `bmcgo/functional/upgrade.py` | `bingo upgrade` | Tool upgrade flow. |
| `bmcgo/functional/new.py` | `bingo new` | Component creation flow. |
| `bmcgo/functional/json_check.py` | `bingo json_check` | JSON validation flow. |
| `bmcgo/functional/schema_valid.py` | `bingo schema_validate` | JSON/YAML schema validation. |
| `bmcgo/functional/hpm_signer.py` | `bingo hpm_signer` | HPM re-signing. |
| `bmcgo/functional/wbd_build.py` | `bingo wbd_build` | White-label package build flow. |
| `bmcgo/functional/openubmc_sdk_build.py` | `bingo sdk_build` | SDK build flow. |
| `bmcgo/functional/conan_index_build.py` | `bingo build` in conan-index | Conan-index package build flow. |

## Errors, Logs, and Tests

| Source path | Responsibility |
| --- | --- |
| `bmcgo/errors.py` | User-facing exception classes and error codes. |
| `bmcgo/error_analyzer/` | Log parsing and unified error analysis. |
| `bmcgo/error_cases/` | Error case definitions and templates. |
| `tests/unittests/` | Focused unit tests for command and helper behavior. |
| `tests/integrationtests/` | Integration-style command tests that may need network or Conan remotes. |

## Development Rule

When changing a behavior, start from the owning source path above, then trace outward to the CLI dispatcher, config detection, and tests. Do not patch unrelated modules just because they share a command name.
