# Bingo Local Debug and Test Guide

Use this guide to validate bingo source changes before submitting a PR.

## Local Development Install

The repository provides `install_local.sh` for local development installation.

```bash
sh install_local.sh
```

The script:

- Builds the Python package.
- Uninstalls and reinstalls `openubmc-bingo` from the generated wheel.
- Builds and installs the generated Debian package.

Use this for changes that touch package metadata, entrypoints, imports, package data, or installed command behavior.

## Debug Through the Real CLI

Use `debug.py` for command debugging. It changes to a target workspace, clears bingo cache, and dispatches through the real CLI.

Edit:

```python
DEBUG_TARGET_RELATIVE_PATH = "."
DEBUG_COMMAND = "bingo help"
```

Examples:

```python
DEBUG_TARGET_RELATIVE_PATH = "../manifest"
DEBUG_COMMAND = "bingo build --help"
```

```python
DEBUG_TARGET_RELATIVE_PATH = "../component"
DEBUG_COMMAND = "bingo gen --help"
```

Then run:

```bash
python3 debug.py
```

## Unit and Integration Tests

Run all tests when practical:

```bash
python3 -m unittest discover tests
```

Run focused tests for narrower changes:

```bash
python3 -m unittest tests.unittests.test_conan_index_build
python3 -m unittest tests.unittests.test_luajit_version_check
python3 -m unittest tests.unittests.test_modularized_csr_build
python3 -m unittest tests.integrationtests.test_maintain_command
```

Some integration tests may clone community repositories or require Conan configuration. If those dependencies are unavailable, report the blocker and still run tests that do not require them.

## Static Checks Before PR

At minimum:

```bash
python3 -m py_compile bmcgo/cli/cli.py
python3 -m py_compile <changed-python-file>
bingo --help
```

If a command was changed:

```bash
bingo <command> --help
```

If packaging was changed:

```bash
sh install_local.sh
bingo --version
bingo --help
```

## Debugging Common Development Failures

### Import works from source but not after install

Check `setup.py`, `MANIFEST.in`, package data inclusion, and whether the changed file is inside an installed package.

### Command appears in the wrong workspace

Check `if_available(bconfig)` and the workspace fields populated by `BmcgoConfig`.

### Command is missing from help

Check `command_info.group`, `command_info.name`, `hidden`, and whether the functional module imports successfully.

### Test requires external services

Separate pure logic from network or Conan access where possible. Test the pure logic directly and document the skipped external dependency.
