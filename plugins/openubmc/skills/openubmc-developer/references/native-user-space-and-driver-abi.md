# Native User-Space and Driver ABI

Treat the user-space/driver seam as a versioned contract. The kernel or device
implementation may live elsewhere, but user-space source must preserve the
actual device-node, sysfs, ioctl, mmap, register, event, and error semantics it
consumes.

## Locate both sides of the seam

Inspect:

- the user-space wrapper, Lua C module, native library, or application caller;
- exported UAPI or shared headers;
- device-tree identity and driver binding where they affect discovery;
- device-node name, permissions, ownership, and creation timing;
- sysfs attributes and read/write formats;
- ioctl numbers, directions, structures, and return conventions;
- mmap offsets, lengths, alignment, ownership, and cache behavior;
- event, poll, interrupt, timeout, reset, and hotplug behavior.

Generated or copied headers can drift from the driver source. Identify the
authoritative definition and verify the version packaged for the target product.

## Preserve binary compatibility

Check integer width, signedness, enum representation, structure layout,
padding, packing, alignment, pointer size, endianness, and flexible arrays.
Keep reserved fields stable and initialize them predictably.

For an ioctl change, verify:

```text
magic and command number
read/write direction
payload size and layout
input validation
partial result behavior
errno mapping
32/64-bit compatibility
old user-space with new driver
new user-space with old driver
```

Prefer additive evolution. Use explicit version or capability discovery when
old and new layouts must coexist. Avoid interpreting a short read, partial
structure, unknown enum, or unsupported ioctl as ordinary success.

## Handle lifecycle and concurrency

Define behavior for device absence, delayed probe, permission failure, open
during reset, hot removal, replacement, concurrent callers, interrupted I/O,
timeout, stale file descriptors, and service restart.

Keep ownership of file descriptors, mappings, buffers, callbacks, and worker
threads explicit. Pair every acquisition with cleanup on all failure paths.
Validate kernel-provided lengths and indices before allocation or access.

## Keep hardware access testable

Place device operations behind the narrowest existing user-space interface.
Use a local adapter or fake device for deterministic tests when available.
Test callers through exported user-space behavior rather than private wrapper
functions.

Use target-hardware validation for electrical, timing, interrupt, and reset
facts that a fake cannot prove. Keep that evidence distinct from source-level
contract tests.

## Validate

Run native compiler warnings, static analysis, unit/integration tests, ABI or
layout assertions, and repository-selected checks. Exercise malformed data,
short transfers, unsupported commands, timeouts, reset, hot removal, and
reopen/recovery as applicable.
