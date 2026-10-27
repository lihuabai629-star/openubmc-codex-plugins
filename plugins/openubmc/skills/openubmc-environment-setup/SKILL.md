---
name: openubmc-environment-setup
description: "Use for explicit openUBMC plugin installation, update, removal, health-check or private-account configuration requests (插件安装、修改账号、保存 BMC/OS 关联), or a confirmed plugin/MCP startup or required local-configuration blocker. Ordinary development, build/Conan failures, device diagnosis and optional KB failures stay with their task owner."
---

# openUBMC plugin environment

When the task enters another workflow stage, read [the phase handoff](../openubmc-debug/references/skill-routing.md)
and load its owner before acting; carry the existing Run and authorization.

Resolve `<plugin-root>` as the parent of the `skills` directory containing this Skill. Codex manages the plugin's Skills and MCP registration. Keep credentials, dependencies and Runtime history outside the plugin directory.

Runtime identity and recovery are part of plugin management. `doctor` reports package identity
and startup readiness; `observe` and `execute` own operational workflows. Runtime state and
MutationJournal records live outside the package and survive updates or removal.
Explicit documentation reviews can read `<plugin-root>/optional-skills/openubmc-doc-review/SKILL.md`;
this resource is outside the default Skill catalog. The legacy bootstrap and `target-runtime`
profile remain migration tools; native marketplace installation is the supported entry.

## Enter only for the affected capability

Apply the Setup entry conditions in the phase handoff. Continue ordinary tasks with their
existing configuration; Setup is not a prerequisite. A reported blocker must identify the
capability needed now and its current failure. Tool visibility, an unused account, an optional
dependency warning or a missing logical credential file alone does not establish that blocker.

## Inspect and repair

For an explicit plugin check or confirmed local blocker, inspect first:

```bash
python3 -I <plugin-root>/scripts/pluginctl.py doctor
```

The MCP launchers check locked dependencies on startup and expose setup tools on failure.
Runtime and KB are optional Host startup dependencies: an unavailable backend does
not prevent an ordinary or offline conversation. Device work still requires the
selected Runtime to return its current protocol state before execution.
If the affected service is needed now, call `openubmc_setup_status`, then repair only its reported
cause. Missing or damaged dependencies use `openubmc_setup_prepare` (CLI: `pluginctl.py prepare
--repair` with `--capability runtime` or `--capability kb`); a modified package requires reinstalling
the selected marketplace version. Do not modify the package, bypass hashes or duplicate registrations.
After startup repair, start a new task when needed to reload that service.

Runtime and KB require Node.js 20+, Git, Codex, Python 3.11+ with pip, and `flock` (util-linux) inside Linux or WSL.
Their backend, credentials, dependency caches and Run history remain there.
Windows clients use an explicitly selected WSL distribution and the stdio bridge
`scripts/openubmc-wsl-bridge.js`; native Windows execution of Runtime and KB is unsupported.
The independent `openubmc-offline` MCP supports native Windows, Linux and WSL with Python 3.11+ and the Codex Node host. Its local analysis and evidence tools require no third-party Python packages, device accounts or Runtime startup. Pass absolute paths; see [Python entrypoints](../../PYTHON.md) for launch isolation.
SDKs, compilers, Docker installation and Conan remotes belong to their respective workflows.

Use `openubmc_setup_open_configuration` only for an account change identified below, not after
every dependency repair. Present its loopback URL. For `unsupported_platform`, connect through WSL.

## Private credentials

### Reuse existing configuration

For local credential diagnosis, the `doctor` report includes capabilities and
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

If the user has already supplied an account for the authorized target and purpose,
follow [Credentials supplied for an authorized task](references/credential-exposure-response.md#credentials-supplied-for-an-authorized-task)
and continue directly. A missing saved record does not require repeated entry or
rotation. Use the page below when the required input is missing, the user chooses
it, or private local handling of the supplied account is unavailable.

Open the focused page for an explicit account change, a Runtime-resolved missing required account,
or a confirmed authentication rejection for the selected target/account that needs replacement.
Explain the specific reason and start the page yourself. Reuse working accounts without a page.
Diagnose source conflicts first; TLS, host identity, timeouts, permissions and business errors
stay with the task owner and are not evidence of a missing password. Conan remote/profile and
dependency failures stay with Build; only a confirmed account update uses this private entry.

When a task has a target IP and the user wants its account remembered after a successful connection,
start the targets page with `--focus-target <IP> --purpose bmc|os --transport ssh|redfish --wait-for-save`.
Show the page URL and direct the user to **连接并记住这台设备**. The user enters the username and password
there and starts a connection check using the task's transport policy. Only a successful connection creates an active
IP-specific credential; a rejected check or concurrent configuration edit leaves the active account
unchanged. The completion event is secret-free and subsequent Runtime requests use the newly active
revision. A verified SSH scope does not verify Redfish, and a BMC account does not authorize OS access.
Keep credential values in private local input; tool arguments and command text contain only
non-secret references.

If a credential may already have appeared in a persisted task, treat it as exposed and follow
[Credential exposure response](references/credential-exposure-response.md). Identify affected
accounts from non-secret target, purpose, record, revision and time metadata; never ask the user
to paste the old value into chat or a command. This response does not block authorized use as
described above. Rotation stays an explicit operator action at the account authority, followed
by local revision activation and capability verification.

```bash
python3 -I -B <plugin-root>/scripts/pluginctl.py configure --kind targets --wait-for-save
```

Use `--kind kb` or `--kind conan` for those accounts. Add `--focus-target <target IP>` to
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

If the user explicitly confirms that a particular BMC IP and OS IP belong to the same device,
record their association directly from the conversation. State the exact pair and ask only when
the relationship is ambiguous; an unambiguous statement already confirms it. Never infer it
from a login, shared account, or nearby address. Run this local command yourself:

```bash
<python-3.12> -B <plugin-root>/skills/openubmc-environment-setup/scripts/associate_device.py --bmc-ip <BMC-IP> --os-ip <OS-IP> --confirm-same-device
```

The command uses Runtime credential-source selection rules in the CLI environment. If the MCP
entry selects a different explicit local source, pass its path with `--source <path>` so the
association lands in the source used by that Runtime. It returns only address and revision
metadata. If it returns `association_conflict`, show the existing and
proposed OS addresses and ask for explicit replacement confirmation before rerunning with
`--replace-existing --expected-os-ip <existing-OS-IP>`. The old address binding prevents
replacement if the mapping changed after confirmation. If it returns `configuration_conflict`,
reconcile the pending edit or revision before retrying. A later task sees the activated
association; a task already holding a snapshot needs a request-boundary refresh. This address
mapping never verifies credentials
or authorizes an OS connection.

BMC connection checks use the existing internal Runtime transport defaults:
Redfish accepts device certificates and SSH uses its configured host-key policy.
OS SSH retains strict host-key verification. Use `configure --strict-checks`
only when certificate/host-key qualification is requested. Results record
`transport_verification` separately from successful authentication; a disabled
check is not a certificate-verification pass. A strict-check failure affects
that assurance, not unrelated task work or an already authorized runtime
connection. No authentication rejection retries another account automatically.
Conan authenticates only an existing named remote through its native token
cache. KB uses the user's OAuth settings and exposes required interaction; the
plugin supplies no shared OAuth client secret.

For an established SSH policy, including an authorized OS test with verification
disabled, pass `--ssh-host-key-policy strict|accept-new|insecure` yourself. The
existing task decision supplies this choice; it needs no repeated confirmation.

For a machine without an accessible browser, the existing `install_environment.py credentials` hidden-input helper remains available. A headless page can be started with `configure --no-browser`; open its session URL in the same machine's browser. Run the helper on the host containing the installed plugin and credentials.

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
