# Bingo Package, Signing, and Special Flow Map

Use this reference for bingo changes outside the normal component build and product build happy paths.

## Signing and Package Utilities

| Source path | Command or area | Responsibility |
| --- | --- | --- |
| `bmcgo/functional/hpm_signer.py` | `bingo hpm_signer` | HPM file re-signing. |
| `bmcgo/functional/simple_sign.py` | `bingo simple_sign` | Simple HTTPS signing helper. |
| `bmcgo/utils/firmware_packager.py` | firmware packager | Firmware layout packing/unpacking helpers. |
| `demo/cms_sign/` | signing demo | CMS signing demo scripts. |
| `demo/ecc_sign/` | signing demo | ECC signing demo scripts. |

Keep signing changes isolated from normal build task changes unless the build path explicitly invokes signing.

## White-Label, SDK, and Conan-Index Flows

| Source path | Command or area | Responsibility |
| --- | --- | --- |
| `bmcgo/functional/wbd_build.py` | `bingo wbd_build` | White-label build flow. |
| `bmcgo/tasks/task_build_wbd_up.py` | WBD task | White-label update package task. |
| `bmcgo/functional/openubmc_sdk_build.py` | `bingo sdk_build` | openUBMC SDK build flow. |
| `bmcgo/functional/conan_index_build.py` | conan-index `bingo build` | Conan-index component package build. |
| `bmcgo/functional/maintain.py` | `bingo maintain` | Maintenance component script/version/patch flow. |
| `bmcgo/functional/full_component.py` | `bingo build_full` | Fetch component source and build full binaries. |

These flows often have narrower workspace assumptions than normal component or manifest commands. Read `if_available` before changing command visibility.

## Validation and Check Commands

| Source path | Command | Responsibility |
| --- | --- | --- |
| `bmcgo/functional/json_check.py` | `bingo json_check` | JSON file validation. |
| `bmcgo/functional/schema_valid.py` | `bingo schema_validate` | JSON/YAML schema validation. |
| `bmcgo/functional/check.py` | `bingo check` | Studio/model consistency check. |
| `bmcgo/functional/analysis.py` | `bingo analysis` | Dependency and interface analysis. |
| `bmcgo/utils/json_validator.py` | validator utility | Shared JSON validator implementation. |
| `bmcgo/utils/combine_json_schemas.py` | schema utility | JSON schema combination. |
| `bmcgo/utils/combine_whitelist_json.py` | whitelist utility | whitelist JSON combination. |

For validation behavior, prefer changing shared validators only when all callers should change. Otherwise patch the command-specific layer.

## Config, Upgrade, and Installation

| Source path | Command or area | Responsibility |
| --- | --- | --- |
| `bmcgo/functional/config.py` | `bingo config` | Global/local/environment/deploy configuration. |
| `bmcgo/functional/upgrade.py` | `bingo upgrade` | Tool upgrade workflow. |
| `bmcgo/utils/install_manager.py` | install manager | Tool installation orchestration. |
| `bmcgo/utils/installations/` | installation framework | installer implementations and version utilities. |
| `install_local.sh` | local install script | Local package build/install for development validation. |
| `build.py` | package build script | Source package build entry. |

Config and upgrade changes can affect all workspaces. Keep validation broad enough to cover component and manifest contexts.

## Git History and Release Notes

| Source path | Command | Responsibility |
| --- | --- | --- |
| `bmcgo/functional/git_history.py` | `bingo git_history` | Generate release-note style commit history for a date range. |
| `docs/25.09/bingo支持组件release note信息的生成.md` | design doc | Release note generation behavior and intent. |

## Development Guidance

- Confirm whether the command is visible, hidden, or workspace-specific before changing it.
- Keep special flows out of the common build path unless the task target explicitly includes them.
- For signing behavior, avoid embedding environment-specific endpoints or credentials in code or docs.
- For validators, distinguish syntax validation, schema validation, and model consistency checks.
- For upgrade/install changes, test both source execution and installed CLI behavior when possible.

## Validation Suggestions

```bash
bingo hpm_signer --help
bingo json_check --help
bingo schema_validate --help
bingo config --help
bingo upgrade --help
python3 -m unittest discover tests
```

Run command behavior tests only when the required sample files, signing setup, or repository workspace exists.
