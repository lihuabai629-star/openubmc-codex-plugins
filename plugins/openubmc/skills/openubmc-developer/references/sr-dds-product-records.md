# SR and DDS Product Records

SR/DDS records select product and component configuration through hierarchy,
matching, inheritance, soft variants, and product-specific overrides. Preserve
both record semantics and the selection chain that makes a record effective on
a product.

## Locate the record owner

Determine whether the behavior belongs to:

- whole-machine hardware or platform configuration;
- a product-line-specific component;
- a shared component family;
- a modular component hierarchy;
- a public or shared product definition;
- product customization such as schemas or northbound mappings.

Inspect `.sr`, `.dds`, `root.sr`, platform records, product profiles, vendor and
component directories, soft variants, and product-specific overrides that
participate in selection. A record existing in the repository does not prove a
given product profile includes it.

## Preserve identity and matching

Treat BOM, board ID, auxiliary ID, vendor/device/subsystem identity, connector
type, slot or position, presence source, identify mode, and bus topology as a
coherent match contract.

Verify the effective selection chain:

```text
parent record and inherited defaults
  -> product profile inclusion
  -> hardware identity and fallback match
  -> presence and identity acquisition
  -> soft-record selection
  -> object path and stable identity
  -> direct consumers
```

Keep match rules specific enough to avoid activating a record on unintended
hardware. Preserve behavior for unreadable identities, absent hardware,
replacement, and hotplug.

## Handle inheritance and overrides

Trace effective values through root records, included records, platform
overrides, public definitions, and product customization. Distinguish omission,
inheritance, explicit empty value, and deletion. Review both base and soft
records when a field differs by firmware or hardware capability.

Keep machine-wide policy in the machine owner and reusable device behavior in
the component-family owner. Avoid cloning a full record to change one value
when the format supports a narrow override.

## Review operational effects

Record changes can alter discovery, scan intervals, hardware access, thermal or
power policy, alarms, product schemas, and northbound visibility. Trace direct
consumers rather than treating the record as static inventory.

For timing changes, verify the established device classification, failure
threshold, bus load, and recovery behavior. For hardware configuration, check
both present and absent or replaced devices.

## Validate

Run repository SR/DDS/profile validators and product-specific generation.
Confirm the intended product includes the record and inspect the effective
merged output. Test identity matching, inheritance, soft-record selection,
absence, replacement, and affected consumer behavior.
