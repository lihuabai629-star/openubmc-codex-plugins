# Product Artifact Verification

Use this after a `product-artifact` Attempt succeeds. Attempt success proves command completion only; `finalize_product_attempt.py` is the sole acceptance entrypoint.

## Locked finalization

```bash
python3 <skill-dir>/scripts/finalize_product_attempt.py \
  --plan <plan.json> \
  --attempt-state <state.json>
```

The finalizer obtains the same canonical Plan, checkout, and output locks as the Attempt. Within one lock cycle it checks all current output identities against `outputs_after`; requires the HPM, final ext4 image, and built resolved lock each to have been absent before the Attempt or to have a different SHA-256 afterward; overwrites and recomputes both gate reports; reads `/etc/version.json` from the final image; writes verification; writes metadata only for accepted verification; and checks output freshness again. mtime, ctime, or inode churn with identical bytes cannot launder output left by a failed or earlier Attempt. `verify_product_artifact.py` and `write_artifact_metadata.py` are internal finalizer helpers; their standalone CLIs cannot authorize acceptance.

For a deterministic retry expected to reproduce identical bytes, preserve and move aside all three old planned outputs before starting the new Attempt. Freshness is content-bound, so touching an output or replacing it with another inode containing the same bytes remains stale.

The internal verification status is `accepted`; the public finalization status remains `accepted_local_only` until package containment is proved. Keep those states distinct. `finalization.json` is the immutable terminal record for that Attempt; rerunning finalization against the same Attempt is rejected instead of overwriting its reports, verification, or metadata binding.

The metadata writer re-hashes the unchanged HPM and preserves `artifact.sha256`, `artifact.size`, and `product_version`. It also binds `plan_id`, `attempt_id`, `finalization_id`, Plan digest, and verification digest. Until HPM containment of the inspected image is proved, verification and metadata state `package_binding_unverified` with `upgrade_eligible: false`; do not route that result to automatic Upgrade.

## Optional diagnostics

The standalone gate commands below cannot authorize verification or metadata. Use them only to explain a rejected finalization or test a corrected Plan before retrying.

Compare the frozen baseline lock with the actual product `package.lock`:

```bash
python3 <skill-dir>/scripts/check_dependency_delta.py \
  --plan <plan.json> \
  --attempt-state <state.json> \
  --output <attempt>/reports/dependency-delta.json
```

The checker reads the frozen complete baseline and built lock paths from the Plan. Both locks must contain `requires`, `build_requires`, `python_requires`, and `config_requires`. Role movement is a dependency change, and every changed component must appear in the Plan allowlist.

## Rootfs access gate

Check each required service path using its target identity:

```bash
python3 <skill-dir>/scripts/check_rootfs_access.py \
  --plan <plan.json> \
  --attempt-state <state.json> \
  --output <attempt>/reports/rootfs-access.json
```

The checker opens the Plan-bound final ext4 image with the frozen `debugfs` executable and reads inode UID, GID, type, and mode for `/` plus every ancestor of each service's mapped paths. Add mappings at Plan creation with repeated `--rootfs-service 'NAME=UID:GID[:SUP...]=/path[,/path...]'`. A service is never checked against another service's private paths.

This gate proves classic Unix directory traversal from ext4 inode metadata for the frozen UID/GID sets. It does not prove file read/execute bits, ACL behavior, runtime mount overlays, or service startup.

A bad Conan cache is a preflight failure for packages in the current resolved graph. Repair or reacquire only those package identities; do not globally chmod the Conan cache.

## Package containment

For a product that will be upgraded, create the Plan with `--hpm-key-file <local-package-key>`.
Use an explicit regular 16-byte AES key already available before Plan creation. The selected
build command must retain that key unchanged; a command that regenerates it cannot satisfy
the frozen-key policy. Keep the private Plan and Attempt records with the local build evidence.
The Plan binds that private local input before the Attempt. Finalization parses the HPM and
signed wrapper, decrypts the exact APP payload, and checks the embedded gzip/tar rootfs against
the already inspected final ext4 digest. It never executes an embedded upgrade script.

A matching proof yields `package_binding_verified`, `upgrade_eligible: true`, and an `accepted`
result. Missing keys, unsupported packaging, truncation, or any digest mismatch keep the
handoff blocked. Without a containment policy the result remains `accepted_local_only`.
The public proof includes only artifact and rootfs identities and bounded payload locations;
it contains no key bytes, key digest, or credential values.

The Python running the finalizer needs `cryptography>=42.0.7,<47`. Existing bmcgo environments
may already provide it. For a separate build environment, install
`python3 -m pip install -r <skill-dir>/requirements-containment.txt` before creating the Plan.
An unavailable backend returns `crypto_backend_unavailable`; it cannot qualify an artifact.

The supported layout is the raw PICMG image or its seven-field ASCII-hex signed wrapper,
one CONFIG and one APP bank, chunked AES-128-CBC, the GPP ext4 subcontainer, and one regular
`rootfs_iBMC.img` member in a single gzip/tar stream. Unknown layouts, extra candidates,
overlapping ranges, invalid padding, and unexpected trailers are rejected. The verifier uses
bounded reads and an anonymous temporary spool for decoded GPP bytes, so temporary disk
space up to the encrypted APP size is required; it never extracts the rootfs into the filesystem.

For signed wrappers, the Manifest digest is verified against the enclosed PICMG bytes.
`signature_trust_verified: false` records that this containment check does not validate the
CMS certificate chain, signing authority, board compatibility, or firmware authenticity.
