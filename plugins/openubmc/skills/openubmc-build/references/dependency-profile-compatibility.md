# Dependency and Profile Compatibility

Use before dependency-resolving compilation or UT/IT, and when diagnosing missing settings, dependency drift, or an ignored profile. Reuse evidence when the tool, source, baseline and effective configuration still match.

## Establish the Inputs

1. Identify the selected target baseline from its Manifest, resolved lock or package_info. Compare resolved references and recipe revisions with that baseline. Broad ranges and update flags can select newer dependencies even when the component source did not change. An intentionally unpinned test is exploratory evidence, not validation of a pinned target.
2. Identify the selected CLI and Conan versions, actual command expansion, host/build profiles, includes, settings schema, Lua options, compiler tool reference and test runtime. Retain the user/workspace entrypoint (`bmcgo` or `bingo`); community examples do not override that choice, even when both entrypoints share modules. Inspect local help and wrapper code or existing logs when argument handling is uncertain. Preserve a supplied command; present any needed command delta before execution.
3. Check the dependency graph and package availability for the test architecture. An ARM product baseline can guide versions for x86 UT, but its ARM binaries do not satisfy x86 package IDs. A partial lock or package_info may leave test-only dependencies unresolved. Verify those separately.
4. Bind external inputs with the Build Plan's `--input-file PATH`, including profile includes and settings extensions that actually exist. Record the expanded profiles and graph as evidence. After execution, compare the effective configuration and graph with the intended baseline.

A wrapper can accept a flag in help and subsequently override it. Some Bingo Conan 2 test implementations append `-pr profile.dt.ini` after user arguments and separately select that profile for the build context. Verify the installed implementation before recommending `bingo test -pr` or raw Conan options. Keep the user's chosen build tool and its existing routing.

Boolean flags can also have mode-dependent defaults or polarity. In some partner-mode implementations, supplying `-jit` disables the default LuaJIT selection. Verify the expanded `enable_luajit` option instead of inferring its value from the flag name.

For `--package_info`, inspect which file and dependencies the installed tool updates. Some versions operate on `temp/service.json`, leave test-framework dependencies outside the Manifest mapping, and resolve indirect dependencies separately. Verify that this helper forwards the selected remote and profiles; an outer `-r` does not prove that an inner graph query received it. The option alone does not prove that the entire graph is pinned. A graph generated from a non-test recipe also cannot establish that test-only dependencies are resolved.

When using Conan's automatic `conan.lock` discovery, verify the lock loaded by each phase. Component creation and test deployment can run in different directories; locking only the first does not pin the second. Preserve existing files and keep temporary validation locks out of formal source changes.

Manifest preparation may regenerate profiles from repository templates. When this occurs, identify the authoritative template and separate preparation from the subsequent frozen compilation/test Plan. Repeatedly editing only a generated global profile can lose the change on the next preparation.

## Diagnose Lua Settings

These inputs have different roles in recipes that use them:

| Input | Role |
| --- | --- |
| settings schema | Defines custom setting names and allowed values |
| `[settings] luacompiler` and its version | Package configuration dimension when declared by the recipe |
| `enable_luajit` option | Selects the actual compilation branch in applicable recipes; normally also contributes to package identity |
| `[conf] user.tools:luajit` | Selects the concrete compiler tool dependency in applicable recipes |

The custom value `luacompiler.version=v1` is not a LuaJIT release number. Match settings, options, tools and runtime to the selected baseline. Standard Lua and LuaJIT bytecode are not interchangeable.

| Failure | Next check |
| --- | --- |
| `settings.luacompiler value not defined` | First compare dependency versions. If the intended recipes require it, check assignment in each applicable host/build context. |
| Unknown setting or invalid value | Check the active schema and its configuration source before adding a value. |
| Missing binary | Compare architecture, compiler, settings, options, recipe revision and package availability. |
| Failure in `source()` | Diagnose the recipe's source configuration, access and download result independently of settings. |
| A profile selection has no effect | Inspect wrapper argument ordering and final Conan argv. |

Older recipes may not declare this setting. Do not add it universally, upgrade dependencies to suppress an error, clear caches by default, or change business code for a dependency-setup failure. Prefer the repository's existing configuration entrypoint and show the affected files when correcting it.

## Report the Actual Test Scope

Record whether failure occurred during dependency resolution, compilation, framework startup or assertions. A zero-exit graph inspection can still contain Invalid or Missing packages. Inspect those node states before starting a build.

For test success, verify that the intended cases were discovered and executed, and report skips or exclusions. A filtered run proves only its selected cases. Standalone Lua checks with mocked transport do not establish complete component UT or target-runtime acceptance. Keep the evidence tied to the source and configuration that produced it.
