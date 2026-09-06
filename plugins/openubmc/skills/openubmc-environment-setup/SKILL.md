---
name: openubmc-environment-setup
description: Inspect and repair an installed openUBMC Codex plugin, configure private BMC and knowledge-base credentials, and explain required local tools on Linux or WSL.
---

# openUBMC plugin environment

Resolve `<plugin-root>` as the parent of the `skills` directory containing this Skill. Codex manages the plugin's Skills and MCP registration. Keep credentials, dependencies and Runtime history outside the plugin directory.

## Inspect and repair

```bash
python3 -I <plugin-root>/scripts/pluginctl.py doctor
python3 -I <plugin-root>/scripts/pluginctl.py prepare --repair
```

The MCP launchers prepare locked Python and npm dependencies on first startup. Subsequent starts verify and reuse the cache. Installation progress goes to stderr. A modified package or dependency cache fails verification; use the repair command for dependency drift and reinstall the selected marketplace version for package drift. Do not modify the installed package, bypass hashes or create duplicate loose Skill/MCP registrations.

Linux, Python 3.12 with pip, Node.js 20+ with npm, Git and Codex are the required host tools. On Debian/Ubuntu, install missing command-line tools when environment setup is requested. SDKs, compilers, Docker installation and Conan remotes belong to their respective workflows.

## Private credentials

Use the bundled credential helper with hidden terminal input for BMC/OS credentials:

```bash
python3 -I <plugin-root>/skills/openubmc-environment-setup/scripts/install_environment.py credentials
```

Select the resulting mode-0600 credentials file through `OPENUBMC_CREDENTIALS_FILE` when needed. Never put credential values in command arguments, logs or ordinary documentation.

Knowledge-base authentication also requires the user's authorized OAuth application configuration. Import a private JSON file containing `username`, `password` and `clientSecret`, with `clientId`, `redirectUri` and service URLs when the application uses non-default values:

```bash
python3 -I <plugin-root>/skills/openubmc-environment-setup/scripts/install_environment.py credentials --kb --kb-config <private-kb-config.json>
```

Keep that file mode 0600. The plugin does not distribute an OAuth client secret. Missing credentials leave the knowledge MCP available for status checks; they do not prevent Runtime startup. `doctor` proves local package and MCP startup readiness, not BMC or knowledge-service access.

## Lifecycle

Use `codex plugin list` to identify the installed marketplace and `codex plugin remove openubmc@<marketplace>` to uninstall. For a Git marketplace, refresh with `codex plugin marketplace upgrade <marketplace>` and reinstall with `codex plugin add openubmc@<marketplace>`. Start a new Codex task after a version change.

For an archive installation managed by `install_plugin.py`, use its `plugin_admin.py audit` and recorded rollback entries. Do not apply archive-administration commands to an installation managed only by the native marketplace. Credentials and durable Runtime records survive plugin removal.
