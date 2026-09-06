# Product Build Pitfalls

Read this only for `product-artifact` or `publish`.

## Remote dependencies

If dependency resolution reports a missing binary, first verify Conan authentication and remote availability using [conan-auth.md](conan-auth.md). A stable product dependency is not silently replaced with a local source package.

Record the selected community, Conan home, PATH, executable identity, and product lock hash in the Plan. Preserve remote/profile preflight output as supplemental evidence; the current Plan does not fully attest Conan profiles, remotes, or a Python package behind a launcher. When `build/<community>.lock` is absent but another community lock exists, stop at Plan creation.

## Online signing

Prove the configured signing service is available before a long product Attempt. Missing signing resources are product/signing failures, not evidence that component source must be rebuilt.

If the host cleans detached services, keep the signer in a managed live session and preserve its status as Attempt evidence.

## Umask and cached payloads

The Attempt runner applies the Plan `umask` to the child process. Use `022` for ordinary product packaging unless the selected repository has an explicit different policy.

A safe umask protects newly created directories; it does not repair an existing Conan payload whose shared ancestors are already `0700`. Inspect packages in the resolved graph before packaging. Reacquire or repair only the affected package identities.

## Rootfs access

A mode-only spot check of `/opt` or `/opt/bmc` is insufficient. Before creating the immutable Plan:

1. identify every non-root service identity;
2. enumerate its `ExecStart`, `WorkingDirectory`, runtime libraries, and data paths;
3. freeze those per-service mappings in the Plan, including shared paths such as `/opt/bmc/apps` and `/opt/bmc/drivers`.

After the Attempt, let the locked finalizer check `/` and every required ancestor in the final ext4 image and create the authoritative `rootfs-access` gate report.

Private paths unrelated to a planned service may remain `0700`. The gate evaluates actual service reachability, not a global ban on restrictive permissions.

The helper checks classic mode-bit traversal from final-image inode metadata only. File read/execute permissions, ACLs, runtime overlays, and service startup require additional product-specific evidence.

## Concurrent output

An Attempt and its finalizer separately acquire the same canonical same-host resource locks for the HPM, final ext4 image, and resolved lock. The locks are not held continuously between those phases; the finalizer rejects any intervening change through the Attempt snapshot comparison. Reuse the selected checkout when those resources are free. A lock collision is a reason to wait or choose genuinely separate output paths, not an automatic reason to create a worktree.

## Stale output

A filename in `output/` is not evidence of a successful Attempt. Locked finalization requires the HPM, final ext4 image, and built resolved lock each to be absent before the successful Attempt or have a different SHA-256 afterward, together with the matching product version, recomputed dependency and permission gates, and fresh metadata. mtime, ctime, or inode-only changes are rejected. When a deterministic retry is expected to reproduce identical bytes, preserve and move all three old outputs aside before starting it.

## Package binding

Image inspection does not by itself prove that the HPM contains that exact image. Until a product-specific containment parser establishes that relation, preserve `package_binding_unverified` and `upgrade_eligible: false` in verification, metadata, and the Build result. Do not auto-route the HPM to Upgrade.
