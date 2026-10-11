# Bingo Product Build Task Map

Use this reference when a bingo source change touches manifest/product builds, build targets, task ordering, output artifacts, rootfs/HPM generation, or package metadata.

## Build Frame and Config

| Source path | Responsibility | When to read |
| --- | --- | --- |
| `bmcgo/frame.py` | Product build parser, target selection, frame execution, optional deploy. | Any `bingo build` or `bingo publish` change in manifest workspace. |
| `bmcgo/utils/config.py` | Manifest/product config loading used by the build frame. | Board, manifest, target, or product config behavior. |
| `bmcgo/target/*.yml` | Built-in build targets such as `personal`, `publish`, `app`, `install_sdk`. | Target composition or task sequence changes. |
| Repository `build/target/*.yml` | Product-specific target extension. | Behavior differs by repository target. |

## Product Build Tasks

| Source path | Responsibility |
| --- | --- |
| `bmcgo/tasks/task.py` | Base task behavior and shared task utilities. |
| `bmcgo/tasks/task_prepare.py` | Build preparation. |
| `bmcgo/tasks/task_download_dependency.py` | Dependency download. |
| `bmcgo/tasks/task_download_buildtools.py` | Build tool download. |
| `bmcgo/tasks/task_build_conan.py` | Conan package build integration. |
| `bmcgo/tasks/task_build_rootfs_img.py` | rootfs image build. |
| `bmcgo/tasks/task_buildhpm_ext4.py` | HPM/ext4 package build. |
| `bmcgo/tasks/task_sign_and_pack_hpm.py` | HPM signing and packaging. |
| `bmcgo/tasks/task_packet_to_supporte.py` | Release packet and ToSupportE packaging. |
| `bmcgo/tasks/task_package_metadata.py` | Package metadata generation. |
| `bmcgo/tasks/task_create_interface_config.py` | Interface config generation task. |
| `bmcgo/tasks/task_custom_installer.py` | Custom installer task. |
| `bmcgo/tasks/task_buildgppbin.py` | GPP/bin image build support. |
| `bmcgo/tasks/task_build_wbd_up.py` | White-label update package task. |
| `bmcgo/tasks/task_oct_rtos.py` | RTOS-related task. |

## Output Contracts

Typical product outputs include:

- `output/rootfs_<board>.hpm`
- `output/packet/<board>/*.zip`
- `output/package.lock`
- metadata and performance files under `output/`

Do not rename or move outputs unless the product build contract intentionally changes. If output paths change, update README/help text and any tests or downstream references.

## Change Strategy

- For argument changes, start in `bmcgo/frame.py`.
- For target/task ordering, start with target YAML, then read the referenced task classes.
- For generated artifacts, trace the exact task that writes the artifact.
- For packaging changes, check whether both personal and publish targets are affected.
- For heavy product builds, provide a narrower validation path when full HPM build is not practical.

## Validation Suggestions

```bash
bingo build --help
bingo build -t personal -b openUBMC -bt release --stage rc
bingo build -t publish -sc <supporte-code> -b openUBMC -bt release --stage stable
```

Use full build commands only when required inputs and remotes are available. Otherwise, validate parser/help output and task selection logic with focused tests or `debug.py`.
