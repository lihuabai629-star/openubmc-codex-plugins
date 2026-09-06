# QEMU Verification Reference

## Launcher Identity

Record the launcher path, repository-relative ownership, file identity or revision, cwd, sanitized argv, environment keys that affect QEMU selection, and the source of every option. A forum command is evidence only after the current repository confirms it.

## Authorization Enforcement Seam

The contract payload records intent and authorization; it does not itself stop a process or network mutation. Before launch, stop, non-loopback exposure, or verification weakening, inspect the selected repository launcher or a reviewed wrapper and prove an enforceable authorization seam exists before the mutation call.

Record `qemu_testing_result.launcher.authorization_enforcement` with:

- `mode`: `repository_launcher`, `reviewed_wrapper`, or `read_only_blocked`;
- `seam`: the function, command boundary, or wrapper stage that validates normalized intent, same-named authorization, and target scope;
- `evidence`: a source review or negative test showing an unauthorized mutation is rejected before process/network control.

If no such seam exists, keep the run read-only/blocked. Do not compensate by trusting a true boolean in the handoff or by issuing the launcher command directly.

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

Keep protocol verification enabled. For test certificates, prefer a scoped CA bundle or an exact certificate fingerprint bound to the expected endpoint. A request to weaken verification must name the endpoint, isolation boundary, time window, risk, and restoration action, and must carry `qemu_authorization.weaken_verification=true`.

Never convert a certificate/identity failure into a pass. If authorization is absent, preserve the failure in `unverified` or `smoke_classification` and suggest the trusted verification path.

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
