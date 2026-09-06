# Startup and Product Assembly

Service metadata and product manifests connect source components into a running
product. Treat deployment identity, startup dependencies, modeled requirements,
package selection, options, and product variants as one observable assembly
contract.

## Trace the assembly chain

Follow:

```text
component service metadata
  -> generated deployment/service configuration
  -> package and subsystem selection
  -> product manifest and options
  -> root filesystem installation
  -> service startup and ready state
  -> direct consumers
```

Inspect current component metadata fields such as component name, type,
deployment configuration, code-generation policy, dependency groups, options,
and required modeled interfaces. Inspect subsystem and product manifests for
the concrete package, version/range, option, deletion, override, and product
variant that selects the component.

## Define readiness rather than process existence

Specify which condition makes the service usable. Starting a process, creating
a socket, registering an interface, loading persistent state, discovering
hardware, and publishing ready state may occur at different times.

Account for:

- required versus optional modeled dependencies;
- provider unavailable at boot and appearing later;
- provider or consumer restart;
- partial interface registration;
- cyclic startup assumptions;
- product variants that omit or replace a provider;
- degraded mode and recovery;
- shutdown and replacement ordering.

Avoid fixing ordering by arbitrary sleeps. Prefer an explicit dependency,
subscription, readiness signal, or retry contract with bounded recovery.

## Keep source assembly separate from delivery mutation

Source-stage work may change authored service metadata, required contracts,
product options, or manifest composition when those definitions are the source
of the accepted behavior. Version bumps, concrete release references, package
creation, signing, and HPM production are delivery operations.

Build recipes may materialize or copy assembly files. Run that behavior in an
isolated copy and inspect the resulting product graph without adopting
incidental writeback into working source.

## Review product variants

Compare every supported board, platform, build type, or product variant
whose dependency list or options can change the behavior. Verify option names,
defaults, conditional packages, overrides, and deletions. A component present
in one manifest does not prove it is present in another.

For a dependency change, identify both the component-level declaration and the
product-level selection. Check mixed versions and rollback when the contract
changes across packages.

## Validate

Run service metadata, manifest, dependency, option, and generated deployment
validators. Inspect the resolved assembly graph in an isolated environment.
Use focused startup tests to verify readiness, late providers, restart,
degraded mode, and cleanup. Treat successful packaging as separate from a
correct running lifecycle.
