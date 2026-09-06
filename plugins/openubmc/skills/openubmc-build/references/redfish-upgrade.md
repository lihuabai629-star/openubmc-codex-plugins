# Redfish Upgrade Handoff

Build does not connect to a BMC or execute an upgrade. Use this reference to decide whether a typed
artifact result is eligible for handoff to `openubmc-upgrade` when the selected delivery strategy is
`build-upgrade`.

The current product finalizer returns local evidence in this shape:

```yaml
build_result:
  artifact_path: /absolute/path/to/openubmc.hpm
  artifact_sha256: <64 lowercase hex characters>
  product_version: <version verified inside the final rootfs image>
  package_binding: package_binding_unverified
  upgrade_eligible: false
  evidence_ids:
    - <build evidence ID>
```

The artifact must have `accepted_local_only` Plan-bound finalization and fresh
`<hpm>.metadata.json` generated from that verification. Include the Plan,
Attempt, dependency, permission, and verification evidence in `evidence_ids`.
Do not return an HPM left by a failed, interrupted, rejected, or stale Attempt.

The current finalizer reports `package_binding_unverified` and `upgrade_eligible: false` because it has not proved that the HPM contains the inspected final image. That result is valid local build evidence but must not be handed automatically to `openubmc-upgrade`. Continue only after a product-specific containment proof produces an explicitly eligible typed result.

Pass target identity, Redfish credential selectors, rollback requirements, and runtime acceptance
checks separately through the task context. Never place credentials in the Build result.

`openubmc-upgrade` owns UpdateService discovery, upload, activation monitoring, target epoch
advancement, installed-version verification, ambiguity recovery, and rollback. After Upgrade,
`openubmc-debug` owns fresh runtime acceptance evidence. Build must not implement a fallback upload
path or use SSH, Telnet, Web REST, Live Patch, or a vendor CLI to mutate the target.
