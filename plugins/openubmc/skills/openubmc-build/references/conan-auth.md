# Conan remote authentication

Reuse the native Conan authentication cache for the remote actually required by
the selected build or publication. An unrelated remote is not a prerequisite.

Agent calls contain remote/configuration references only. Private local
configuration, a secret resolver, or an already inherited environment supplies
credentials at process creation. Keep values out of chat, tool parameters,
command text, saved plans and Case inputs. Preserve secret bytes exactly.
Manual terminal login remains available to the user.

## Diagnose the selected remote

Inspect the selected dependency graph, package identity and failing remote.
Separate missing binary/profile/revision errors, network/proxy/TLS failures,
authorization denial and authentication rejection. A missing binary alone does
not justify login or a local-source fallback.

When fresh evidence requires an authentication check, use the existing cache
and noninteractive mode for that one remote:

```bash
python scripts/check_conan_auth.py --remote <selected-remote>
```

The helper checks both exit status and per-remote errors: Conan can return zero
while a remote failed. It invokes only the named remote without forcing login
and emits no raw authentication output. `conan remote list-users` reports cached state, not current
server acceptance. Do not force authentication, log out, disable remotes or
probe every configured remote as a routine build preflight.

For an actual account change, let the local private configuration path supply
the corrected values. Confirm the selected remote with one bounded check,
then retry the original failed read or build within its existing authorization.
Do not replace Git URLs, rebuild dependencies or change remote configuration to
hide a resolution failure.

For stalled resolution, inspect the proxy configuration relevant to that remote
without displaying secret-bearing environment values. Preserve unrelated
working remotes and the task's selected profiles and revisions.
