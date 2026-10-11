# Bingo Component Codegen and Test Map

Use this reference when a bingo source change touches component code generation, component tests, dependency analysis, fixtures, or coverage.

## Main Component Command Owners

| Source path | Responsibility | When to read |
| --- | --- | --- |
| `bmcgo/component/package_info.py` | Component package metadata, common build args, Conan identity, codegen policy. | Build args, package version, stage, profile, Conan 1/2 behavior. |
| `bmcgo/component/build.py` | Component build flow and Conan create/upload orchestration. | `bingo build` changes in a component workspace. |
| `bmcgo/component/gen.py` | Component Lua/C code generation command. | `bingo gen`, service.json handling, codegen version flags. |
| `bmcgo/component/test.py` | Unit, integration, fuzz, mock, coverage test command. | `bingo test`, test flags, coverage behavior. |
| `bmcgo/component/deploy.py` | Component deploy command behavior. | Component deployment behavior. |
| `bmcgo/component/component_helper.py` | Shared component helpers. | Cross-command component metadata utilities. |

## Code Generation Areas

| Source path | Responsibility |
| --- | --- |
| `bmcgo/codegen/lua/` | Lua code generation implementation, templates, formatting support. |
| `bmcgo/codegen/c/` | C code generation implementation. |
| `bmcgo/ipmigen/` | IPMI command generation helpers and templates. |
| `bmcgo/component/template/` | Conan 1 component package templates. |
| `bmcgo/component/template_v2/` | Conan 2 component package templates. |

When changing generated output, trace from command parser to renderer/template, then update tests or examples that assert generated structure.

## Test, Fixture, and Coverage Areas

| Source path | Responsibility |
| --- | --- |
| `bmcgo/component/fixture/` | DBus/busctl fixture generation, mock utilities, recorded case helpers. |
| `bmcgo/component/coverage/` | Incremental coverage report logic and templates. |
| `bmcgo/component/busctl_log_parse/` | busctl log parsing and test data extraction. |
| `tests/unittests/` | Focused unit tests for command/helper behavior. |
| `tests/integrationtests/` | Integration command tests that may require network or Conan setup. |

## Dependency and Interface Analysis Areas

| Source path | Responsibility |
| --- | --- |
| `bmcgo/component/analysis/analysis.py` | Component dependency/interface analysis entry. |
| `bmcgo/component/analysis/build_deps.py` | Build dependency analysis. |
| `bmcgo/component/analysis/data_deps.py` | Data dependency analysis. |
| `bmcgo/component/analysis/intf_deps.py` | Interface dependency analysis. |
| `bmcgo/component/analysis/intf_validation.py` | Interface validation. |
| `bmcgo/component/analysis/sr_validation.py` | SR validation helpers. |
| `bmcgo/component/analysis/dep-rules.json` | Dependency rule data. |

## Development Guidance

- For parser-only changes, test the command parser and help output.
- For codegen changes, inspect both Lua/C generator paths before assuming the behavior is language-specific.
- For Conan template changes, check both `template/` and `template_v2/`.
- For fixture or coverage changes, keep generated reports stable unless the output contract intentionally changes.
- For analysis changes, update rule data and analysis expectations together.

## Validation Suggestions

```bash
python3 -m unittest discover tests
python3 -m unittest tests.unittests.test_luajit_version_check
python3 -m unittest tests.unittests.test_modularized_csr_build
bingo gen --help
bingo test --help
```

If a command requires a real component workspace, use `debug.py` with `DEBUG_TARGET_RELATIVE_PATH` pointing at that workspace.
