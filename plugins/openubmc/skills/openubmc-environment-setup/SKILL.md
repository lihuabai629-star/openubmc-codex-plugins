---
name: openubmc-environment-setup
description: "Configure or repair an installed openUBMC plugin on Linux/WSL: 新电脑配置、配置密钥、默认 BMC 账号密码、按 IP 覆盖、Conan 登录、KB 知识库配置、MCP 启动失败、插件检查。Use for local credentials, required tools, migration, and installation health; device diagnosis belongs to openubmc-debug."
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

### Reuse existing configuration

Run `pluginctl.py doctor` first. Its `credentials` report includes local capabilities and
`active_revision`; `remote_authentication=not_checked` is a local readiness result. The Runtime
prefers the selected structured `credentials.json` source, including its activated revision, over
retained legacy defaults. An absent logical source file does not mean its active snapshot is absent.

Use `observe`/`execute` for authorized target work; the Runtime resolves credentials locally. If a
local target/purpose/transport lookup itself needs diagnosis, use the public task-bound resolver:

```python
import json
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, "<plugin-root>/skills/openubmc-target-runtime")
from openubmc_target_runtime import CredentialResolver

resolver = CredentialResolver()
lookup = {"task_id": "local-credential-check", "host": "<BMC IP>",
          "purpose": "bmc", "transport": "redfish"}
selected = resolver.resolve_local(**lookup)
reused = resolver.resolve_local(**lookup)
print(json.dumps({"configured": selected.credentials is not None,
                  "cache_reused": reused.cache_hit,
                  "active_revision": resolver.configuration_revision(lookup["task_id"]),
                  "remote_authentication": "not_checked"}))
```

Replace only the plugin root, authorized target, purpose (`bmc` or `os`), and transport (`ssh` or
`redfish`). This checks local resolution and cache reuse without connecting. Keep the resolved
credential object in local memory; print only readiness metadata. `CredentialResolver.resolve_local`
selects and pins the activated snapshot. Direct `LocalCredentialSource.resolve`, reading the logical
file, or calling a legacy loader bypasses that selection and cannot establish Runtime readiness.
An exact IP override selects a complete record; authentication failure never falls back to a default.

### Change or check an account

When the user needs to enter or change BMC/OS, KB or Conan credentials, open the local browser page:

```bash
python3 -I <plugin-root>/scripts/pluginctl.py configure
```

Keep the page process alive while the user edits. The page displays the Linux/WSL environment and exact local source, separates global BMC/OS defaults from IP overrides, and supports explicit import while retaining the original file. Secret fields support keep, replace and remove; values stay in the local page and Runtime. Ask for missing target or account context only, never ask the user to paste a password or application secret into chat.

Saving creates a private revision; **Save and activate** selects it for subsequent Runtime/KB requests. Existing requests keep their original account. With an already authorized target, append `--target <ip> --purpose bmc|os --transport ssh|redfish`; activation then runs that bounded connection check. Without a target, saving performs no device probe. The page also offers explicit checks for selected targets and configured KB/Conan services. Report their actual status: saved and active do not mean verified.

SSH checks preserve strict host identity verification, Redfish checks verify TLS, and no check retries a rejected IP override with global credentials. Conan authenticates only an existing named remote and uses the native per-user token cache. KB requires the user's authorized OAuth application settings; interactive authentication requirements remain visible as such. The plugin supplies no shared OAuth client secret.

These strict checks are distinct from historical Runtime transport bindings that may permit
insecure TLS. A strict-check failure remains unverified. Report the certificate or endpoint trust
problem; never silently retry the check with TLS verification disabled or reinterpret it as missing
credentials. If insecure transport is already explicitly authorized, report any connection result
within that scope with certificate verification disabled: it does not qualify certificate validation
or replace the strict check. Reuse that authorization without asking again; it does not change the
check policy.

For a machine without an accessible browser, the existing `install_environment.py credentials` hidden-input helper remains available. A headless page can be started with `configure --no-browser`; open its session URL in the same machine's browser. Use the WSL environment containing the installed plugin and credentials.

## Lifecycle

For a legacy loose installation or `openubmc@personal`, use `pluginctl.py migrate --disable-only --preview` to inspect ownership and pending changes, then `migrate --disable-only` to save them. Keep the returned transaction ID for `restore-legacy --transaction <id>`. This route retains old files and links, disables the canonical Skill entries and owned MCP entries, and preserves the target `openubmc@openubmc-public` registration. Use `--target-plugin` when preserving a different target registration. Start a new Codex task to load the saved state. A later config or ownership edit blocks restoration until reconciled. Explicit `migrate --remove` retains the old removal behavior.

Use `codex plugin list` to identify the installed marketplace and `codex plugin remove openubmc@<marketplace>` to uninstall. For a Git marketplace, refresh with `codex plugin marketplace upgrade <marketplace>` and reinstall with `codex plugin add openubmc@<marketplace>`. Start a new Codex task after a version change.

The local configuration page includes “插件状态与修复”: check version, package integrity,
Runtime/KB startup and user-level override conflicts. Preview recognized override removal
before applying it; the page retains a guarded undo for that repair during the page session.
Use the per-service dependency repair buttons when dependencies are unavailable. Custom
wrappers and environment settings require reconciliation and are retained.

After a native marketplace upgrade, run the new package's `doctor`. Its
`codex_configuration` result checks the selected Codex home's user-level MCP overrides;
`startup_ready` describes the packaged servers only. A healthy package does not prove that
an existing desktop task can resume.

If `doctor` reports a version-pinned override, run `pluginctl.py repair-overrides --preview`
from the new package, then `pluginctl.py repair-overrides` to remove recognized Runtime/KB
launch overrides. The selected native plugin must be enabled. Configuration backups are
private migration transactions; `restore-legacy --transaction <id>` restores the original
configuration if it has not changed since repair. Custom launch arguments or environment
settings require reconciliation before repair. `--codex-home` overrides `CODEX_HOME`;
otherwise the home defaults to `~/.codex`. Keep MCP startup owned by the plugin so upgrades
resolve the current launcher. After repair, reopen the affected desktop task and verify
that resume completes without error before reporting desktop recovery.

For an archive installation managed by `install_plugin.py`, use its `plugin_admin.py audit` and recorded rollback entries. Do not apply archive-administration commands to an installation managed only by the native marketplace. Credentials and durable Runtime records survive plugin removal.

Runtime cache files under `__pycache__` are ignored by package verification. They are derived by Python during MCP startup and cannot invalidate a verified release; packaged files and dependency caches remain hash checked.
