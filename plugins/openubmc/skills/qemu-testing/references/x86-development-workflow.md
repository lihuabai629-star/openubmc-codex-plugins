# x86 QEMU Development Workflow

Use this workflow when the selected repository contains an x86 QEMU product and
repository-owned launcher. It captures the verified 26.12 and migrated 26.06
development loop without making either baseline, machine model, port set, or
launcher command universal.

For the repository's concrete x86 launcher, persistent disk behavior, verifier
review and 26.06 compatibility findings, read
[Repository x86 Launcher](x86-repository-launcher.md).

## Ownership

The workflow has three owners:

1. `openubmc-build` produces and locally qualifies a product artifact with the
   repository-selected `bmcgo` command.
2. `openubmc-qemu-testing` owns launcher discovery, a task-scoped instance,
   readiness, service smoke, stability, and cleanup.
3. Runtime stores an already validated result as task evidence when a Runtime
   Run exists. Runtime does not launch, restart, stop, or provision QEMU.

The packaged workflow has no Bingo build fallback. If a selected x86 product
only documents a Bingo build, preserve that fact as an unsupported build route;
do not silently translate it to `bmcgo`. An existing artifact may still enter
QEMU verification when the current repository launcher verifies its full input
index and identities.

## 1. Select the development scenario

Classify the requested result before collecting inputs:

For ordinary launch or focused debugging, use targeted checks and disable fault
injection. A full healthy-device/alarm baseline is needed only for requested
full acceptance or fault injection; targeted plans may mark it `not_requested`.

| Scenario | Baseline | Additional acceptance |
| --- | --- | --- |
| `daily-development` | All expected devices and services healthy | Inject faults only after the healthy baseline and only when requested |
| `model-simulation` | Selected machine model and topology load successfully | Model, mock fixture and resource-tree identities match the request |
| `alarm-testing` | Requested initial alarm state is explicit | Injection, alarm appearance, recovery and residue are each verified |

For daily development, do not normalize a large active-alarm set by suppressing
collectors or thresholds. Map each unexpected alarm to missing mock data,
topology, threshold, or a live component failure and repair the baseline owner.

## 2. Establish repository and build identity

Record the Manifest root, Git revision and local-content identity. Confirm the
actual product entry, launcher, target, image index and model fixtures from the
checkout. A release number alone does not prove x86 support. Older baselines may
need an isolated platform migration before they produce a launchable artifact;
that migration remains Developer and Build work.

The Build handoff must include:

- accepted local artifact path, digest and product version;
- repository-specific launch index path and digest;
- every kernel, rootfs, boot/data disk, firmware, DTB, mock fixture directory,
  or other input selected by the launcher;
- source revision and remaining package-binding gaps.

The launch index is the preferred launcher input when it binds a complete
release directory. A lone HPM filename is insufficient when the launcher also
requires boot/data images, firmware, certificates, mock data, or licenses.
QEMU verification proves the guest that actually ran. It does not upgrade a
real BMC and does not erase a Build package-binding gap by assertion.

## 3. Create the QEMU plan

Create one `openubmc-qemu-workflow-plan/v1` document following
[the result contract](qemu-result-contract.md). Include the final launcher and
input identities, a task-scoped runtime root, port plan, requested smoke checks,
verification mode, normalized intent and matching authorization.

Validate it before process or network mutation. The Agent fills internal fields
from the established task, using `task_command` for ordinary scoped commands or
an existing launcher/wrapper boundary. Do not request a new approval for that
bookkeeping. Choose targeted verification unless full acceptance was requested:

```bash
python3 <qemu-skill>/scripts/qemu_workflow_contract.py validate-plan <plan.json>
```

For the common x86 path, check the host architecture, read/write KVM access,
launcher help, memory, disk allocation and every requested host port. Defaults
such as Q35, CPU model, vCPU count, memory, serial socket and port offsets come
from the selected launcher. Bind services to loopback unless non-loopback intent
and authorization are both present.

## 4. Choose fresh or existing instance state

Use a fresh runtime directory to verify a newly built HPM. A persistent runtime
keeps its original disk; `restart` normally restarts that disk and does not flash
a newly generated artifact. Keep an existing instance for stateful regression
only when its disk and initial artifact are the intended test subject.

Before launch, write a task-owned run manifest. After launch, bind PID, process
start time, executable, argv, image identity, runtime root, QMP/monitor channel,
serial start offset and port listeners. Never select or stop a process only by
name. Keep other instances, disks and caches intact.

## 5. Reach guest readiness

Readiness is a finite, observable sequence:

1. launcher returns and the owned process exists;
2. current-boot serial reaches kernel and userspace milestones without a panic,
   OOM, reboot loop or fatal service chain;
3. forwarded listeners belong to this instance;
4. the guest service manager, maintenance channel, account resources and MDB
   baseline are ready;
5. the requested business probes can run.

On timeout, preserve serial, host pressure, QMP status, failed units and the last
fresh milestone. A normal reboot is a recovery experiment only for an instance
owned by this task and only with local-process-control authorization. Retain the
first failed boot and the recovered boot as separate evidence. Sending console
input, rebooting, or increasing resources does not prove a root cause by itself.

Provisioning may initialize the repository's factory development account and
write a private password file. Use only the selected development instance, keep
credentials out of argv and results, and do not reset an existing customized
account. Provision success is readiness evidence, not complete service smoke.

## 6. Run layered service acceptance

For a full x86 acceptance, request and record the applicable checks below:

- instance/KVM, guest architecture, boot ID, product/model and persistent mounts;
- systemd state, failed units, SELinux enforcing and MDB component health;
- maintenance SSH plus actual BMC-user SSH and CLP/MDB queries;
- Web static resources plus browser login, refresh and logout;
- Redfish Basic and Session authentication with semantic resources;
- IPMI RMCP+ device identity;
- bus permissions and real log delivery;
- expected resource tree, mock topology and active-alarm baseline;
- at least 120 seconds without guest reboot, coredump, unexpected service identity
  change, or resource-pressure failure.

Select `verification.profile=full-x86` for that acceptance. A narrow requested
probe uses `targeted` and cannot be reported as full x86 acceptance.

Use the repository verifier when present, but inspect its implementation and
dependencies. Bind HTTPS to a scoped CA or exact certificate fingerprint, SSH to
the instance host key, and IPMI to the protocol's authentication. A port connect
or QMP `running` is not service acceptance. `NRestarts=0` does not exclude an
externally initiated service restart, so compare process identity and relevant
configuration timestamps across the stability window.

SNMP daemon stability does not prove the SNMP protocol. Firmware upgrade,
continuous fault injection, hot plug, and physical I2C/SPI hardware remain
separate acceptance items unless explicitly executed.

## 7. Fault injection and model work

Begin fault injection only after a fresh healthy baseline is recorded. Use the
repository's model/mock interfaces, bind the exact object and expected alarm,
and record the original value and recovery action. Verify the injected symptom,
alarm creation, alarm clearing, restored resource state and absence of residue.
Stop after an unexpected mutation succeeds or cleanup cannot be proved.

Model simulation also records machine model, topology scenario, fixture digest,
resource-tree coverage and unsupported real-hardware behavior. Do not claim that
one default machine model covers another product customization.

## 8. Return and persist the result

Produce one `openubmc-qemu-workflow-result/v1` receipt, validate it against the
exact plan, and preserve its digest and evidence files:

```bash
python3 <qemu-skill>/scripts/qemu_workflow_contract.py \
  validate-result <plan.json> <result.json>
```

A completed result requires every requested layer and smoke item to pass. Report
the earliest failed layer while retaining independent later evidence. If an
active Runtime Run needs the result, attach the validated receipt and referenced
evidence through the Runtime evidence interface; do not invent a QEMU Runtime
operation or mark a Build/Upgrade Gate complete with QEMU evidence.

Stop only the instance owned by this plan. Verify exit and released ports, retain
the requested run manifest, serial, plan and result, and preserve the runtime
disk unless deletion was explicitly requested.
