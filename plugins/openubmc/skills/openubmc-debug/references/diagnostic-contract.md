# Diagnostic Result

Use one diagnostic intent per run:

- `diagnose`: explain and localize a current or reproduced runtime symptom.
- `verify_delivery`: check requested acceptance items against the currently deployed target.

This is a local Debug result shape, not a Developer transport protocol.

## Common fields

```yaml
diagnostic_intent: diagnose | verify_delivery
status: completed | partial | failed | blocked | routed
target: <target identity or unresolved>
freshness:
  captured_at: <time>
  target_clock: <time or unavailable>
  after_last_reboot_or_change: true | false | unknown
  stale_evidence: []
commands:
  - command: <bounded read-only command>
    observed_at: <time>
    read_only: true
    mutates_target: false
    result: <exit/status and relevant output>
verified: []
unverified: []
next_skill: <skill name or none>
```

Use `completed` only when every requested item has fresh evidence and passed. Use `partial` for
mixed or useful incomplete evidence, `failed` when all evaluated requested items failed, and
`blocked` when none can be evaluated.

## Diagnose

```yaml
diagnosis:
  conclusion: <shortest evidence-backed conclusion or unresolved>
  code_owner: <repository/module/service or unresolved>
  call_path: [<evidenced caller/callee path>]
  generated_boundary: <authored source and generated output or unresolved>
  red_feedback:
    status: established | unavailable | inconclusive
    trigger: <repeatable action or input>
    expected: <expected behavior>
    actual: <observed behavior>
    repeatability:
      classification: deterministic | intermittent | once | unknown
      attempts: <count>
      reproduced: <count>
    evidence:
      - kind: test | replay | interface_request | object | alarm | log | file | coredump | command
        source: <command, file, object, or artifact>
        observed_at: <time>
        excerpt: <bounded diagnostic evidence>
```

Include `red_feedback` when the diagnosis needs an observable failure before implementation. A
source keyword hit or event definition alone is not an established red. Require a repeatable
failure, stable replay, interface request, object query, log sequence, coredump, or equivalent
bounded observation.

Recommend implementation based on the evidenced source boundary:

- handwritten Lua, MDB/MDS/interface/model, or Redfish/Web/CLI/SNMP/IPMI mapping -> `openubmc-developer` with the evidenced domain edit intent
- specialized driver, WebUI, compute, or other source -> its matching specialist
- insufficient ownership evidence -> no implementation recommendation

## Verify delivery

```yaml
runtime_verification:
  status: verified | partial | failed | unavailable
  deployed_identity: <version/artifact identity or unknown>
  acceptance_results:
    - item: <requested acceptance item>
      command: <bounded read-only command>
      result: passed | failed | not_run
      evidence: <fresh evidence or reason>
```

Account for every requested acceptance item. An unavailable deployed identity keeps any item that
depends on that identity at `not_run`; do not infer deployment from a local package or source tree.

## Safety

- Keep every remote command read-only.
- Preserve collected commands, configuration, and returned fields without automatic masking.
- Treat unavailable, timed-out, stale, or truncated evidence as unverified, not as absence.
- Route mutation, build, upgrade, live patch, or source implementation to its owning skill.
