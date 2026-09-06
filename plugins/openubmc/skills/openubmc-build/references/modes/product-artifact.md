# Product Artifact Mode

Use when the requested result or supplied command produces a product rootfs/HPM. A board-targeted `bmcgo build` in a Manifest checkout belongs here even when the user simply says “build”.

## Required inputs

- selected Manifest checkout;
- exact command when supplied;
- community and matching `build/<community>.lock`;
- expected product version, absolute HPM path, and absolute final ext4 image path;
- separate complete pre-build and built resolved-lock paths;
- allowed dependency changes;
- per-service UID/GID-to-path mappings.

## Procedure

1. Reuse the selected Manifest checkout.
2. Apply only explicit product-version and Manifest-ref compare-and-set writes.
3. Run relevant read-only environment, signing, remote, lock, and cache preflight.
4. Freeze the final image, complete resolved baseline, service mappings, built resolved lock, and output resources in a `product-artifact` Plan.
5. Execute an Attempt.
6. Run `finalize_product_attempt.py`; it recomputes both gates, verification, and metadata under the same locks.
7. Treat `package_binding_unverified` as ineligible for automatic Upgrade until HPM containment is proved.
8. Return the `accepted_local_only` typed Build result.

`build_type`, `stage`, `target`, `remote`, and `version` remain independent. Preserve a complete supplied command rather than expanding it from examples.

Read [../artifact-verification.md](../artifact-verification.md) for the sole finalization entrypoint and optional diagnostic gates.

## Completion

The HPM has `accepted_local_only` Plan-bound finalization and fresh metadata backed by content-fresh HPM, final ext4 image, and built resolved-lock evidence. An old, cross-Attempt, interrupted, dependency-drifted, permission-blocked, or version-mismatched HPM is not a result. Accepted local evidence does not imply Upgrade eligibility while package binding is unverified.
