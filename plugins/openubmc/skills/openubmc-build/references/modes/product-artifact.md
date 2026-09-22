# Product Artifact Mode

Use when the requested result or supplied command produces a product rootfs/HPM. A board-targeted `bmcgo build` in a Manifest checkout belongs here even when the user simply says “build”.

## Required inputs

- selected Manifest checkout;
- exact command when supplied;
- community and matching `build/<community>.lock`;
- expected product version, absolute HPM path, and absolute final ext4 image path;
- separate complete pre-build and built resolved-lock paths;
- allowed dependency changes;
- per-service UID/GID-to-path mappings;
- an absolute, executable `luac` path matching the product Lua version.

## Procedure

1. Reuse the selected Manifest checkout.
2. Apply only explicit product-version and Manifest-ref compare-and-set writes.
3. Run relevant read-only environment, signing, remote, lock, and cache preflight.
4. Freeze the final image, complete resolved baseline, service mappings, Lua checker, built resolved lock, and output resources in a `product-artifact` Plan.
5. Execute an Attempt.
6. Run `finalize_product_attempt.py`; it recomputes dependency, image-access, and final-image Lua syntax gates, verification, and metadata under the same locks.
7. Treat `package_binding_unverified` as ineligible for automatic Upgrade until HPM containment is proved.
8. Return the `accepted_local_only` typed Build result.

`build_type`, `stage`, `target`, `remote`, and `version` remain independent. Preserve a complete supplied command rather than expanding it from examples.

## Bingo release package

When the user requests the ordinary Bingo product release package, hand the exact command to
`openubmc-bingo-build` and run it from the selected Manifest root:

```bash
bingo build -t publish -b <board> -bt release --stage stable
```

Use the actual board directory name under the Manifest for `<board>`. Do not infer or append
extra selectors. When the user supplied a complete command, preserve it exactly.

Read [../artifact-verification.md](../artifact-verification.md) for the sole finalization entrypoint and optional diagnostic gates.

## Completion

The HPM has `accepted_local_only` Plan-bound finalization and fresh metadata backed by content-fresh HPM, final ext4 image, built resolved-lock evidence, and syntax-valid Lua from the planned image roots. An old, cross-Attempt, interrupted, dependency-drifted, permission-blocked, Lua-invalid, or version-mismatched HPM is not a result. Accepted local evidence does not imply Upgrade eligibility while package binding is unverified.
