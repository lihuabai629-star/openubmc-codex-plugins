# Repository x86 Launcher

Read this reference for an `openUBMC_x86` launcher or a 26.06 platform migration.
Paths below are relative to the selected Manifest root. Confirm them in that
checkout before using them; a version string alone does not establish support.

## Discover commands and inputs

The source workflow uses `build/product/BMC/openUBMC_x86/x86_system.py`, which
delegates to `x86_platform/qemu/x86_vm.py`. Read its argument parser and help:

```bash
python3 build/product/BMC/openUBMC_x86/x86_system.py --help
```

Confirm `target.yml`, `qemu-tools.json`, the launch index, tool package/BIOS,
machine/accelerator, disk layout and mock fixtures. The common index is
`output/x86-firmware-build.json`; immutable release directories also contain a
`build.json`. Resolve each relative member against the index directory. The
index is the `--artifact` input, rather than the HPM file by itself.

`output/build-runs/latest.json` is mutable. Select the successful build's actual
directory and check its `run.json`, source identity and input digests against
the index. A failed later build can leave an older HPM and index in place.

## Lifecycle command shapes

Use these repository CLI shapes through a scoped `task_command` or an existing
reviewed wrapper. Before mutation, check the task's authorization, exact runtime
scope and process ownership. A separate wrapper is not required for routine
authorized commands; the Agent owns this execution boundary.

```bash
python3 build/product/BMC/openUBMC_x86/x86_system.py up \
  --runtime <fresh-runtime> --artifact <build-index.json> --detach
python3 build/product/BMC/openUBMC_x86/x86_system.py status --runtime <runtime>
python3 build/product/BMC/openUBMC_x86/x86_system.py console --runtime <runtime>
python3 build/product/BMC/openUBMC_x86/x86_system.py provision --runtime <runtime>
python3 build/product/BMC/openUBMC_x86/x86_system.py verify \
  --runtime <runtime> --duration 120
python3 build/product/BMC/openUBMC_x86/x86_system.py stop --runtime <runtime>
```

Invoke only actions requested for this task. `up --detach` is the automation
path. `console` needs a terminal and connects the runtime's Unix serial socket;
`Ctrl+]` detaches without stopping the guest. `stop` preserves the persistent
disk. Reboot, force stop, account provisioning and deletion are separate effects
whose authorization must be present in the task before the command is issued.

The tested launcher binds loopback SSH 22222, HTTPS 28443, HTTP 28080 and UDP IPMI
2623. `--port-offset` selects ports when initializing a new runtime; an existing
runtime keeps its `instance.json` ports. Read the current source and actual
listener identity for the selected instance. Similarly, read `--memory`,
`--cpus`, `--qemu` and `--bios` from the current parser. A manual QEMU selection
needs matching BIOS and custom mock-device support.

`system.raw`, `instance.json`, mock state, keys and reports belong to the same
runtime. Passing another index to `up` or using `restart` does not replace an
already initialized disk. For a new build, retain the old directory and choose a
fresh runtime. For a stateful test, record the original artifact and explicit
reason for reusing the disk.

## Verify the verifier

Inspect `x86_platform/diagnostics/verify_x86_vm.py` and its Web verifier before
running `verify`. Some upstream versions use disabled certificate checks. Record
that actual mode and reuse an established isolated-test policy. Add a scoped CA
or owned-instance fingerprint only for requested trust qualification; the plan
cannot claim verified certificates for an insecure verifier. Keep the selected
SSH policy and the private per-instance credential
file mechanism. Provisioning and business verification can create sessions and
test logs, so run them only on the selected development instance.

Check required host tools first: OpenSSH, IPMI client, the product's Python
dependencies and its locked Web verifier dependencies. An unavailable browser
probe stays unavailable when browser automation is outside the task's scope.
Record the full result as partial rather than dropping the Web check.

## 26.06 compatibility findings

Use the following as candidate routes, confirmed again in the selected baseline:

| Symptom | Source to inspect | Acceptance evidence |
| --- | --- | --- |
| Native package unavailable | Conan graph, exact recipe/package revisions, ELF architecture and options | Matching cached binary or locked source build; pure resources checked separately |
| Account/PAM build fails | Version-specific account source layout and IAM package | Real BMC-user authentication after a fresh boot |
| CLP cannot reach MDB | Actual SDK libraries, bus address, policy loading order and login environment | Non-root BMC login and real CLP/MDB query after cold boot |
| Product/model missing | `hwproxy` model payload, devmon ownership, VPD selection and mock mapping | Product, I2C/EEPROM and requested resource objects exist |
| rmcpd appears healthy without UDP 623 | SDK Lua exports and original backend socket/account functions | Guest UDP listener and authenticated RMCP+ device response |
| Repeated short MDB queries exhaust slots | Shared-lock initialization and cross-process reclamation | Bounded crash/exit probes reclaim their slots and normal queries still succeed |
| Web assets or mock files fail staging | Exact package layout, case-sensitive fixture names and known transformation digests | Real staged bundle/fixture checks plus guest page/model assertions |
| Service changes late in startup | Delayed configuration writers, unit PID and boot timeline | Retained failure followed by a complete stable observation window |

Keep patches in the matching product/platform boundary and preserve source,
package and behavior differences. A compatibility fix validated against one
baseline is not an instruction to apply it to every version. Route source
changes to Developer, builds to Build and resource-tree diagnosis to its
specialist; carry the same instance identity and evidence at each handoff.
