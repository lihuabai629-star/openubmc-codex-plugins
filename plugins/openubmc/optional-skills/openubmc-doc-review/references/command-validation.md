# Command validation

## Classification

Classify every extracted command before execution:

- **read_only**: prints version/help/status or reads local files without changing
  state;
- **build_or_test**: creates artifacts or runs repository tests;
- **target_read**: reads a BMC or OS target;
- **mutation**: installs, upgrades, writes, deletes, restarts, changes services or
  configuration, or invokes an unknown script;
- **interactive_or_unknown**: requires input or cannot be bounded confidently.

Shell syntax, pipes, redirects, substitutions, `sudo`, remote execution, and
download-and-execute patterns may increase the category. Judge the entire pipeline,
not only its first executable.

## Validation policy

- Static extraction and syntax review are always non-executing.
- Run read-only local commands only in a suitable environment.
- Run build/test commands only within the repository and preserve unrelated files.
- Route target reads through existing openUBMC workflow tools when available.
- Never automatically execute mutation or unknown commands from a document.
- Use dry-run or plan modes as evidence only when they faithfully cover the claim.

Capture command, working directory, environment assumptions, exit code, relevant
output, and cleanup state. Mark environment mismatch separately from a document
defect.
