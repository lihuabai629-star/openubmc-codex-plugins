# openUBMC for Codex

Diagnose openUBMC systems, analyze log bundles, develop components, build firmware and verify delivery with persistent Runtime evidence.

## Install

Requires Linux, Codex CLI 0.153.4, Python 3.12 with pip, Node.js 20+ with npm, and Git. Run this in the environment where Codex starts its MCP servers:

```bash
codex plugin marketplace add lihuabai629-star/openubmc-codex-plugins && codex plugin add openubmc@openubmc-public
```

Alternatively, add `lihuabai629-star/openubmc-codex-plugins` as a Git marketplace in Codex, then install **openUBMC** from **Openubmc Public**. This is a community marketplace; OpenAI's default catalog is managed separately.

Start a new Codex task after installation. The first startup downloads and verifies Python/npm dependencies; allow up to ten minutes on a slow connection. Later startups reuse the verified local cache. Credentials are configured separately.

Try: “检查 openUBMC Runtime 状态，并说明缺少哪些配置。”

## Credentials

BMC access uses your own target credentials. Ask Codex to configure the openUBMC environment; it uses a private file outside the plugin.

Knowledge-base access needs an authorized OneID account and OAuth application configuration. Import a private JSON file with `username`, `password` and `clientSecret`; include the application's `clientId` and `redirectUri` when different from the defaults. No OAuth client secret is distributed with this plugin. Without these credentials, the knowledge tools report that configuration is incomplete while Runtime remains available.

## Update and remove

```bash
codex plugin marketplace upgrade openubmc-public
codex plugin add openubmc@openubmc-public
codex plugin remove openubmc@openubmc-public
```

The last command uninstalls the plugin. Credentials and Runtime history stay outside its cache. Start a new task after updates.

For an older personal plugin or loose Skill/MCP installation, preview and apply the bundled disable-only migration:

```bash
python3 -I <plugin-root>/scripts/pluginctl.py migrate --disable-only --preview
python3 -I <plugin-root>/scripts/pluginctl.py migrate --disable-only
```

The helper disables owned legacy entries, retains files, links, credentials and history, and preserves `openubmc@openubmc-public`. Start a new Codex task to load the saved state. Restore with `restore-legacy --transaction <id>`; later configuration or ownership changes require reconciliation. The explicit `migrate --remove` route remains available for removing owned loose registrations and links.

## Dependency recovery

For Python integrations, follow the packaged [entrypoint and import guide](plugins/openubmc/PYTHON.md).

Use `codex plugin list --json` to identify the installed version. The plugin directory is under `${CODEX_HOME:-$HOME/.codex}/plugins/cache/openubmc-public/openubmc/<version>`.

```bash
python3 -I <plugin-directory>/scripts/pluginctl.py doctor
python3 -I <plugin-directory>/scripts/pluginctl.py prepare --repair
```

`doctor` verifies the package, dependencies and local MCP startup. It does not establish access to a BMC or knowledge service. Native Windows has not been qualified; run the plugin in a Linux environment.

## License

[MulanPSL-2.0](LICENSE). Third-party dependencies retain their own licenses and are downloaded from their package registries.
