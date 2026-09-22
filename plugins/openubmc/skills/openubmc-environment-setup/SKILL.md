---
name: openubmc-environment-setup
description: "Configure or repair an installed openUBMC plugin on Linux/WSL: 账号缺失或认证失败、配置网页、默认 BMC 账号、关联 OS、Conan 登录、KB 知识库配置、MCP 启动失败、插件检查。Use for local credentials, required tools, migration, and installation health; device diagnosis belongs to openubmc-debug."
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

When local credentials are missing, authentication is rejected, or the user requests an account
change, explain the specific reason and start the relevant page yourself. Do not make the user
find the entry point or run the command. Reuse available credentials without opening a page.
Configuration conflicts require diagnosing the selected source first; TLS, host identity and
network failures are not reasons to ask for another password.

If a credential may already have appeared in a persisted task, treat it as exposed and follow
[Credential exposure response](references/credential-exposure-response.md). Identify affected
accounts from non-secret target, purpose, record, revision and time metadata; never ask the user
to paste the old value into chat or a command. Rotation stays an explicit operator action at the
account authority, followed by local revision activation and capability verification.

```bash
python3 -I -B <plugin-root>/scripts/pluginctl.py configure --kind targets --wait-for-save
```

Use `--kind kb` or `--kind conan` for those accounts. Add `--focus-target <BMC IP>` to
open that device's settings without authorizing a connection. The launcher attempts to open the
browser and prints a session URL first. Always present that exact URL as a clickable configuration
link in the conversation, even when browser launch was attempted. Do not claim a browser opened
without evidence. Preserve the URL's fragment. Keep the process alive and retain its execution
session while the user edits; wait in bounded intervals of at most 60 seconds, continuing unrelated
work if available. Do not finish the task by asking the user to report that configuration is done.

The page uses one BMC account for SSH and Redfish. Default OS credentials are optional; a device
can associate an OS IP and override either account. Existing independent protocol records remain
in advanced account management until explicitly unified. Secrets stay in the local browser and
Runtime. Ask only for missing target context, never passwords or application secrets in chat.

**保存** saves and activates a private revision for subsequent requests; in-flight requests retain
their snapshot. With an already authorized connection check, append
`--target <ip> --purpose bmc|os --transport ssh|redfish`. Only that scope is checked automatically.
`--focus-target` and an associated OS address do not authorize probes. Without `--target`, saving
performs no device probe. KB/Conan checks remain explicit page actions.

With `--wait-for-save`, activation of the requested kind prints a `configuration_saved` JSON event
containing the revision, local `configured` state and bounded `checks`, then closes the page service.
Saving another category does not complete the request. Closing or expiration before saving emits
`configuration_cancelled`. On a saved event, inspect local readiness and any check failures, then
continue the already authorized task at its next Runtime request boundary without asking “配置好了
吗”. Preserve the Run and mutation identities when resuming; a saved event never authorizes a new
write or proves remote authentication. For missing fields or rejected authentication, reopen the
matching page and explain the remaining reason. Cancellation is not completion; do not reopen
automatically after the user closes it. Omit `--wait-for-save` for a general settings session.

For an OS task associated with a known BMC, call
`resolver.associated_os(task_id=..., bmc_host=...)` on the same `CredentialResolver` used above.
It returns only the activated OS address or `None`, pins the same task snapshot, and opens no
connection. Use that address only within the user's OS task scope. An explicit target takes
precedence; a conflicting explicit target needs reconciliation instead of silent replacement.

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
