# QEMU Plan and Result Contract

The contract is a secret-free boundary between Build evidence, a repository
launcher and QEMU acceptance. Paths are absolute. File identities contain
`path`, lowercase `sha256`, and byte `size`.

## Plan

```json
{
  "schema": "openubmc-qemu-workflow-plan/v1",
  "scenario": "daily-development",
  "actions": ["discover", "launch", "observe", "smoke"],
  "repository": {"root": "/workspace/manifest", "revision": "<revision>"},
  "launcher": {
    "path": "/workspace/manifest/path/to/launcher.py",
    "sha256": "<sha256>",
    "size": 1234,
    "authorization_enforcement": {
      "mode": "reviewed_wrapper",
      "seam": "authorize() before subprocess creation",
      "evidence_ids": ["launcher-negative-test"]
    }
  },
  "runtime": {
    "root": "/workspace/output/qemu-run-123",
    "mode": "fresh",
    "preserve_data": true
  },
  "artifact": {
    "index": {"path": "/workspace/output/build.json", "sha256": "<sha256>", "size": 4567},
    "source_revision": "<revision>",
    "product_version": "<guest version>",
    "image_inputs": [
      {"role": "hpm", "path": "/workspace/output/openubmc.hpm", "sha256": "<sha256>", "size": 9876}
    ]
  },
  "ports": [
    {"protocol": "tcp", "bind": "127.0.0.1", "host_port": 22222, "guest_port": 22}
  ],
  "intent": {"expose_non_loopback_ports": false, "weaken_verification": false},
  "authorization": {
    "local_process_control": true,
    "expose_non_loopback_ports": false,
    "weaken_verification": false
  },
  "verification": {
    "profile": "full-x86",
    "required_smoke": ["identity", "ssh", "web", "redfish", "ipmi", "mdb", "systemd", "selinux", "logs", "bus-permissions", "resource-tree", "alarms"],
    "tls_mode": "exact_fingerprint",
    "not_before": "<RFC3339 timestamp before this run>",
    "max_evidence_age_seconds": 900,
    "check_modes": {
      "identity": "host_key_pinned", "ssh": "host_key_pinned",
      "web": "exact_fingerprint", "redfish": "exact_fingerprint",
      "ipmi": "protocol_native", "mdb": "host_key_pinned",
      "systemd": "host_key_pinned", "selinux": "host_key_pinned",
      "logs": "host_key_pinned", "bus-permissions": "host_key_pinned",
      "resource-tree": "host_key_pinned", "alarms": "host_key_pinned"
    },
    "stability_seconds": 120
  },
  "baseline": {"expected_state": "healthy", "fault_injection": "after-baseline"}
}
```

`launcher.authorization_enforcement.mode=read_only_blocked` is valid only for a
plan without `launch` or `stop`. `task_command` records the agent's scoped
command-boundary review and needs no separate wrapper. Intent and authorization
fields are filled from the same established task decisions, not separate user
approval steps. Non-loopback ports and weakened verification
each need matching intent and authorization. Full smoke has a minimum 120-second
stability window. An authorized weakened plan additionally records
`verification.weakened_scope`, a future RFC3339 `verification.expires_at`, the
exact `verification.weakened_checks`, and a non-empty
`verification.recovery_steps`; its smoke rows use `weakened_authorized`.
For a narrow requested probe, select `verification.profile=targeted` and list
only the requested checks. If these exclude Web/Redfish, `tls_mode=not_applicable`
is accepted without a certificate check. A targeted probe without fault injection
can use `baseline={"expected_state":"not_requested","fault_injection":"disabled"}`;
it does not require an unrelated healthy-device/active-alarm baseline. Full x86
acceptance and fault injection retain their requested healthy baseline.

## Result

```json
{
  "schema": "openubmc-qemu-workflow-result/v1",
  "plan_digest": "sha256:<canonical plan digest>",
  "status": "completed",
  "started_at": "<RFC3339 observation start>",
  "finished_at": "<RFC3339 observation finish>",
  "instance": {
    "runtime_root": "/workspace/output/qemu-run-123",
    "identity": "<run manifest identity>",
    "artifact_index_sha256": "<build index sha256>",
    "pid": 123,
    "process_start": "<host process start identity>",
    "executable": "/workspace/qemu-system-x86_64",
    "boot_id": "<guest boot id>",
    "product_version": "<guest version>"
  },
  "layers": {
    "launcher": {"status": "passed", "summary": "launcher accepted argv", "evidence_ids": ["launcher-log"]},
    "process": {"status": "passed", "summary": "owned process matches", "evidence_ids": ["process-record"]},
    "serial": {"status": "passed", "summary": "current boot reached userspace", "evidence_ids": ["serial-current-boot"]},
    "ports": {"status": "passed", "summary": "listeners owned by instance", "evidence_ids": ["port-record"]},
    "readiness": {"status": "passed", "summary": "guest ready", "evidence_ids": ["readiness-record"]},
    "services": {"status": "passed", "summary": "required services passed", "evidence_ids": ["service-record"]},
    "stability": {"status": "passed", "summary": "stable for requested window", "evidence_ids": ["stability-record"], "observed_seconds": 120, "boot_id_start": "<guest boot id>", "boot_id_end": "<guest boot id>", "service_identities_unchanged": true}
  },
  "baseline": {"status": "healthy", "evidence_ids": ["healthy-baseline"]},
  "smoke": [
    {
      "name": "ssh",
      "endpoint": "127.0.0.1:22222",
      "observed_at": "<timestamp>",
      "verification_mode": "host_key_pinned",
      "status": "passed",
      "evidence_ids": ["ssh-record"]
    }
  ],
  "failure_classification": "none",
  "evidence_ids": ["qemu-result-bundle"]
}
```

Layer and smoke statuses are `passed`, `failed`, `blocked`, or `skipped`.
Top-level status is `completed`, `failed`, `partial`, or `blocked`. A completed
receipt has no failed classification and every plan-required item is `passed`.
Accepted verification modes are `ca_bundle`, `exact_fingerprint`,
`protocol_native`, `host_key_pinned`, and `local_process_identity`.
Every layer also requires `observed_at`. All observation timestamps must fall
between `started_at` and `finished_at`, after the plan's `not_before` and within
`max_evidence_age_seconds` (1–3600) of validation. Future or invalid timestamps
are rejected. `--historical` audits a past result relative to its finish time;
it emits `freshness_verified=false` and cannot authorize execution or Runtime attachment.

`check_modes` binds every requested check to its protocol: SSH uses a pinned
host key; Web/Redfish match the plan's TLS mode (CA or exact fingerprint); IPMI
uses native protocol verification; process checks use local process identity.
Guest checks use the verified SSH transport or native protocol. Weak verification
requires the exact check in `weakened_checks` and an observation before expiry.
The displayed `smoke` array shows one row; repeat it for every required check in
the plan. Blocked or skipped checks may use `verification_mode=not_run`. When
launch fails before process creation, omit PID and boot fields and mark later
layers blocked; a passing process requires PID/start/executable identity, and
passing guest layers require the matching version and boot ID. A passing
stability layer also requires measured duration, unchanged boot IDs and service
identities. Completed daily development requires a healthy baseline backed by
evidence. A failed or partial receipt preserves an observed unhealthy baseline
and its evidence rather than inventing a healthy result.

The canonical plan digest is SHA-256 over UTF-8 JSON with sorted keys, ASCII
escaping and separators `,` and `:` with no whitespace. The validator emits the
exact digest and rejects a result created for another plan. It also re-hashes
each current file identity. Directory identities use SHA-256 over sorted regular
files as `relative-path NUL decimal-size NUL raw-file-sha256 NUL`; `size` is the
sum of file bytes. An existing runtime additionally supplies a non-empty
`stateful_reason` and `initial_artifact` identity.

## Runtime evidence handoff

With an active Run, create a task-local bundle:

```bash
python scripts/qemu_workflow_contract.py prepare-evidence <plan.json> <result.json> \
  --run-id <active-run> --target <run-target> --output <absolute-new-evidence.json>
```

Pass the emitted object to the default Runtime `execute` tool. The
`attach_qemu_evidence` action rechecks file digest, Run/target binding, plan,
artifact files, freshness and verification modes before attaching evidence.
The bundle schema is `openubmc-qemu-evidence/v1` with `run_id`, `target`, `plan`
and `result`; it is bounded to 1 MiB. Runtime preserves the current Gate and
Outcome, does not run QEMU or resume target Effects, and replays the same
operation idempotently. The general `evidence_attach` API remains Operator-only.
