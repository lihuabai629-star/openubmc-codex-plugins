# OS access through BMC SOL

For an authorized host OS task with no OS address, address `observe` to the BMC:

```json
{
  "target": "<BMC IP>",
  "selectors": [
    {"id": "host", "kind": "os_console", "names": ["identity", "network"]}
  ],
  "deadline": 60
}
```

Use `identity` to verify OS login, serial tty, kernel, hostname and boot ID.
Add `network` when the answer needs host interfaces, IPv4/IPv6 addresses or IPv4 routes.
The probes share one login window and check the OS boot ID again before logout.
The receipt retains OS identity separately from BMC identity. An observed host
address can support subsequent authorized OS access; it does not update the
local BMC/OS association automatically.

## Account selection and prerequisites

The adapter opens a BMC SSH terminal and uses the native `ipmcset` SOL command
from its CLP or shell prompt. It requires Paramiko locally and does not use
`ipmitool`, OS networking, or MDB preflight. The OS must
already expose a serial login prompt with a usable password account.
Existing baud and serial routing are preserved.

The adapter reads `ipmcset -t sol -d activate -h` to select the option labelled
`SYS COM`; that number differs between firmware versions. It then checks
`ipmcget -t sol -d session` for two idle session slots before activating
`ipmcset -t sol -d activate -v <SYS-COM-option> 0`. An occupied or unverified
session table stops collection before activation. The supported native banner
advertises `Esc(` as the exit sequence. An unrecognized banner stays incomplete.

Runtime resolves two complete records from the same activated task snapshot:

- BMC `ssh` credentials supply the SSH username and password or identity file.
  An explicit `ssh_port` selects that port's BMC credential override and SSH
  connection; it does not change the OS serial account scope.
- OS `ssh` credentials supply the independent console username/password. A
  configured BMC/OS association selects the associated OS IP's account. With no
  association, the BMC IP's **OS-purpose** override selects the account, falling
  back only to the OS-purpose default when no override exists. Legacy
  `OPENUBMC_OS_SSH_*` records also work without `OPENUBMC_OS_IP`.

The OS serial login requires a password even when BMC SSH uses a key. A missing
OS account never selects the BMC account. Authentication rejection preserves
the selected record and returns a gap without trying other accounts. Use the
private configuration workflow for a required missing account; keep passwords
out of Agent arguments and shell command lines.

For a missing device-specific console account, open the private targets page
focused on the **BMC IP** (`--focus-target <BMC-IP> --purpose bmc`). In its device
row, enable the separate OS account and leave the associated OS IP empty. Saving
stores the OS-purpose record under that BMC IP. Re-resolve console readiness
after saving; do not test OS SSH against the BMC address.

## Session ownership and results

The collector owns one SSH terminal and makes one OS login attempt. English and
Chinese login/password prompts are supported. It executes only the named
read-only probes after reaching a shell and verifies Linux/serial/boot identity.
It logs out its own OS login, sends the advertised `Esc(` sequence, confirms
the BMC prompt, and closes its SSH connection. Terminal input,
passwords and raw login transcripts are excluded from retained evidence.

`sol_busy`, `sol_session_state_unverified`, `sol_unavailable`,
`sol_permission_denied`, `console_not_at_login`, `bmc_authentication_failed`,
`os_authentication_failed`, `deadline_exceeded`, `output_limit` and
`os_logout_unconfirmed` / `sol_close_unconfirmed` remain explicit gaps. An existing authenticated shell
or firmware screen is not taken over. A failed session is not automatically
replayed for assurance. The adapter never force-deactivates an existing SOL,
changes serial routing, powers/reboots the host, or changes OS networking.

The observation receipt and its reference use the existing Runtime evidence
path. For a diagnosis Run, pass the returned reference to `execute` and answer
the Runtime's diagnosis Gate with the collected evidence. SOL facts do not
establish the cause of an OS networking failure by themselves.

## Manual console access

For an interactive session outside the read-only probes, SSH to the BMC:

```bash
ssh <BMC-account>@<BMC-IP>
```

At the BMC prompt, inspect the native help and current sessions:

```text
ipmcset -t sol -d activate -h
ipmcget -t sol -d session
ipmcset -t sol -d activate -v <number-labelled-SYS-COM> 0
```

At `login:`, enter the **OS** account and its password. `Password:` may be shown
as `密码：`. End your OS login with `exit`, then press `Esc` followed by `(`
as advertised by the native banner. Confirm the BMC prompt before closing SSH.
An occupied SOL requires coordination with its owner; do not deactivate it.
