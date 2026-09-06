# Component Package Mode

Use only when the requested result is a component Conan package.

## Inputs

- one selected component checkout and source fingerprint;
- exact package command or enough local repository evidence to generate one;
- explicit expected and target component versions when a new package identity is required;
- expected package ref and upload intent.

## Procedure

1. Reuse the selected checkout.
2. If the source identity needs a new version, apply it once with `scripts/ensure_planned_version.py --kind component`.
3. If the package command writes inside the checkout, declare only its command-owned output subtrees with `--mutable-path`; follow [../build-plan.md](../build-plan.md).
4. Create a `component-package` Plan after the version write.
5. Execute the exact command through an Attempt.
6. Verify the produced package ref and evidence.
7. Stop locally unless `publish` was explicitly requested.

A retry reuses the Plan and target version. It does not increment the version again.

## Completion

The planned package identity and checked Attempt evidence are known. Manifest wiring and product HPM generation are separate requested operations.
