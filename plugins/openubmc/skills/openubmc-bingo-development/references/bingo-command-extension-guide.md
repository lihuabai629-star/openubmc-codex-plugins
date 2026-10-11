# Bingo Command Extension Guide

Use this guide when adding or modifying a bingo subcommand.

## Choose the Right Command Type

| Change | Recommended location |
| --- | --- |
| Component build/gen/test/deploy behavior | Existing module under `bmcgo/component/` |
| Product build target behavior | `bmcgo/frame.py`, `bmcgo/target/*.yml`, or `bmcgo/tasks/*.py` |
| New optional command visible by workspace | New or existing module under `bmcgo/functional/` |
| Conan-index specific behavior | `bmcgo/functional/conan_index_build.py` or related config |
| Global config/upgrade behavior | Existing `config.py` or `upgrade.py` functional command |

## Functional Command Contract

A functional command module should provide:

```python
command_info = CommandInfo(
    group=<command_group>,
    name="<command-name>",
    description=["short user-facing description"],
    hidden=False,
)

def if_available(bconfig):
    return <workspace-condition>

class BmcgoCommand:
    def __init__(self, bconfig, *args):
        ...
```

Implementation rules:

- Put the command in the narrowest correct group.
- Keep `if_available` conservative; commands should not appear in unrelated workspaces.
- Use `argparse` for user parameters and expose useful `--help` text.
- Raise bingo exceptions for user mistakes rather than leaking raw tracebacks.
- Keep hidden commands hidden unless they are ready for normal users.

## Availability Checks

Use workspace signals from `BmcgoConfig`:

- Component-only commands should require component metadata.
- Manifest/product commands should require manifest configuration.
- Conan-index commands should require conan-index configuration.
- Truly global commands such as config or upgrade may return true for all workspaces.

When in doubt, make the command less broadly available and document the expected workspace.

## Argument Design

Follow existing naming:

- `-b/--board_name` for board/product selection.
- `-bt/--build_type` for debug/release build type.
- `--stage` for dev/rc/stable package stage.
- `-r/--remote` for Conan remote.
- `-p/--path` for output or source path when the command already follows that convention.

Before adding a new flag, search the codebase for the same concept and reuse the existing spelling when possible.

## Error Handling

Prefer:

- Validating arguments before running expensive work.
- Giving the user the invalid value and expected format.
- Reusing existing exception classes from `bmcgo/errors.py`.
- Leaving logs under the existing bingo log/cache locations.

Avoid:

- Swallowing exceptions without actionable output.
- Calling `sys.exit` deep inside reusable helpers.
- Printing success when partial work failed.

## Tests

For a new command:

1. Add a unit test for argument parsing or command setup when possible.
2. Add a command behavior test if the command can run without large external services.
3. For network/Conan-heavy behavior, isolate the pure decision logic and test that part.
4. Run the closest existing test module plus `python3 -m unittest discover tests` when practical.

## Review Checklist

- `bingo --help` shows the command only in intended workspaces.
- `bingo <command> --help` is useful and matches the real parser.
- Invalid arguments fail early with a clear message.
- Existing commands in the same group still appear and dispatch.
- Tests or documented manual validation cover the changed behavior.
