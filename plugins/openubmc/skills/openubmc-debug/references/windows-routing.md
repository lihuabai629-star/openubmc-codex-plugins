# Windows client and WSL execution

The backend runs in Linux or WSL. A Windows Codex client must select an explicit
WSL distribution and an installed Linux plugin root through
`scripts/openubmc-wsl-bridge.js`. Native Windows Runtime, Python, SSH and private
storage adapters are retired. An unsupported Windows backend returns
`unsupported_platform`; it does not install dependencies or pick a distribution.

Probe the selected backend with bounded `initialize` and `tools/list` requests.
Require the same backend to answer both and advertise `observe` and `execute`.
Then continue through the typed Runtime operation. A process, port, relay or
remembered tool list cannot establish current protocol health.

The bridge forwards bounded non-secret task identity only. Credentials, KB
authentication, dependencies and durable Runtime records remain in WSL. The
MCP bootstrap emits an `openubmc-routing` receipt before each structured Runtime
call. For this bridge, it records `client_environment="windows"`,
`execution_host="wsl"` and the selected distribution. Its process-keyed HMAC
does not expose raw arguments, credentials or a guessable digest. An unhealthy
probe stays on the setup surface; inconsistent tools block Runtime forwarding.

When MCP cannot serve the requested operation, retain the fallback decision
from `ExecutionRouter.choose` in `scripts/execution_router.py`, including its
`reason_code` and total command budget (at most 32). Specify the
actual shell origin and pass every argument vector through `admit_shell` with
the adapter-observed host. A PowerShell origin is still `windows-native` for
transport accounting; that label does not make it a supported Runtime backend.
PowerShell to WSL to SSH counts as two host transitions and remains bound to the
requested target. Host mismatch, repeated equivalent commands and an exhausted
budget reject further calls. Do not put passwords or tokens on command lines.

Shell output is observational. It cannot close a typed Gate or prove mutation,
deployment, verification or rollback success. Runtime alone owns Run, Gate,
Incident, Effect and Outcome state. An unobserved Host terminal command cannot
be described as a routed fallback; the MCP bootstrap cannot inspect those
commands or infer their host from Hook input.
