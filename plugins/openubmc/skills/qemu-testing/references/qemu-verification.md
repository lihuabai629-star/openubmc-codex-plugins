# QEMU Verification Reference

## Launcher Identity

Record the launcher path, repository-relative ownership, file identity or revision, cwd, sanitized argv, environment keys that affect QEMU selection, and the source of every option. A forum command is evidence only after the current repository confirms it.

## Authorization Enforcement Seam

The contract records intent and authorization already established by the task;
the agent fills both from that scope without separate user approvals. Inspect
the repository launcher's actual argv and effects. Ordinary authorized commands
can use `task_command`: the agent checks scope, runtime and process ownership at
the command boundary and retains that source/command review as evidence. A
dedicated launcher authorization API or a new wrapper is not a prerequisite.

Record `qemu_testing_result.launcher.authorization_enforcement` with:

- `mode`: `task_command`, `repository_launcher`, `reviewed_wrapper`, or `read_only_blocked`;
- `seam`: the function, command boundary, or wrapper stage that validates normalized intent, same-named authorization, and target scope;
- `evidence`: the scoped command/source review, or an existing negative test of the launcher/wrapper.

Use `read_only_blocked` only when necessary scope/input is unresolved. A true
handoff boolean alone is not user authorization; the current task supplies it.

## Image Identity

For each consumed input—kernel, initramfs/rootfs, DTB, flash, disk, firmware, shared directory—record:

- role and resolved absolute path;
- symlink target where applicable;
- size and modification time;
- checksum or trusted manifest/build identity;
- relationship to the requested build/change.

Repeat identity after launch when inputs can be replaced concurrently. A smoke result against an unknown or stale image does not verify the requested delivery.

## PID Identity and Ownership

Use a task-scoped runtime directory containing a run manifest, PID reference, serial path, command metadata, and timestamps. A PID is valid only when process start time, executable, argv/image references, and run ownership all match.

Before stop/restart:

1. read the recorded PID;
2. prove the PID still exists;
3. compare start time to prevent PID reuse;
4. compare executable and relevant argv/image paths;
5. verify the run manifest belongs to this task;
6. send a bounded graceful stop, then verify exit and ports released.

An identity mismatch is evidence, not permission to select another process by name.

## Serial Evidence

- Store serial output under the run directory and record the byte/line offset at launch or attach.
- Separate current boot output from retained historical logs.
- Track milestones such as firmware handoff, kernel boot, userspace init, service readiness, reboot loops, panic, OOM, and coredump signatures.
- Bound waits by an observable milestone and report the last fresh line/timestamp on timeout.

## Port Mapping

For each endpoint record protocol, bind address, host port, guest port, configured source, current listener owner, and probe result.

- Detect conflicts before launch.
- Treat loopback and non-loopback exposure separately.
- Prove the listener belongs to the current QEMU PID or its intended proxy.
- A TCP connect only verifies reachability; the service smoke must still validate protocol identity.

## Verification Strength

Use the task's established transport policy. For verified test certificates, use
a scoped CA bundle or endpoint fingerprint. For already authorized isolated
tests with verification disabled, fill the corresponding flags and derive the
endpoint, task-bounded time window and restoration steps yourself. Renew expired
local plan bookkeeping within that same authorization; preserve prior evidence.
For targeted checks without Web/Redfish, use `tls_mode=not_applicable`.

Record authentication/business results separately from certificate/identity
verification. An unavailable trust check does not block independent probes.

## Smoke Classification

| Layer | Example evidence | Interpretation |
| --- | --- | --- |
| launcher | argv accepted, process created | host orchestration only |
| process identity | PID/start/executable/images match | expected instance exists |
| serial | boot milestones, fatal signatures | guest boot progress |
| port mapping | listener owner and forwarding config | host-to-guest path exists |
| guest readiness | login/service manager/MDB baseline ready | system can receive probes |
| service smoke | protocol response and semantic assertion | requested service behavior |
| stability | bounded observation without restart/coredump | short-term runtime stability |

Report the earliest failed layer and keep later checks blocked or independently evidenced. Avoid attributing resource pressure or a component defect until fresh serial/service evidence supports that classification.

## Persistent x86 Instances

A persistent runtime binds its initialized disk, initial artifact, machine UUID,
mock state, credentials, host keys and retained reports. A launcher `restart`
normally reboots that disk; it does not prove that a newly built HPM was installed.
Use a fresh runtime for a new artifact unless the requested subject is explicitly
the existing disk state. Compare report time and guest boot ID so a failed retry
cannot inherit a stale passing report.

For full x86 service acceptance, use the selected repository verifier and the
checks defined in `x86-development-workflow.md`. Preserve the first failing boot
when a later bounded recovery succeeds. The recovered result is evidence for the
new boot and does not erase the initial failure.
