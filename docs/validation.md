# Validate a checkout

On Linux with Python 3.12, Node.js 20+, npm and Git:

```bash
npm ci --ignore-scripts --no-audit --no-fund --prefix scripts/host
export PATH="$PWD/scripts/host/node_modules/.bin:$PATH"
python3 -I scripts/check_marketplace.py
python3 -I scripts/check_behavior.py --output /tmp/openubmc-public-behavior.json
```

The behavior harness uses the checked-out `plugins/openubmc` directory and an isolated temporary
home. It prepares the package's locked dependencies, exercises local build, transport, credential,
artifact, archive, upgrade and migration behavior, and starts and closes both MCP servers. Test
fixtures provide external commands and Redfish responses. No device, Conan remote or OneID account
is contacted.

`scripts/behavior/source.json` binds the exported checks to the plugin's source commit and records
their hashes. A failed test, skipped native Codex check, startup failure or changed package produces
a nonzero exit status. The report records the actual host versions and package identity; local
behavior and startup checks do not establish authenticated remote business qualification.

`release.json` with `status: candidate` identifies an unpublished candidate. Its version number
alone does not imply a release or qualification on another operating system.
