# Hardware VPD Acquisition and Snapshots

Treat hardware VPD as a bounded byte protocol whose acquisition, validation,
publication, and refresh behavior form one contract. A device read is not valid
merely because the transport returned success.

## Locate the acquisition owner

Inspect the complete path from hardware to consumer:

```text
device identity and presence
  -> transport or PIA access
  -> header and reported length
  -> bounded payload acquisition
  -> format and checksum validation
  -> immutable published snapshot
  -> inventory, topology, persistence, or northbound consumers
```

Identify which component owns device access and which component owns the
published VPD state. Avoid several readers publishing competing partial views
of the same device.

## Validate the byte contract

Derive minimum header size, total length, field boundaries, byte order,
alignment, terminators, padding, checksum coverage, and maximum supported size
from the applicable format and current implementation.

Reject or classify distinctly:

- short header or payload reads;
- zero, wrapped, or oversized reported lengths;
- fields extending beyond the validated buffer;
- invalid format identifiers, versions, or checksums;
- transport success with incomplete data;
- unsupported but well-formed records;
- a device disappearing or changing identity during acquisition.

Validate lengths before allocation, slicing, copying, or parsing. Initialize
buffers predictably and never publish bytes that were not successfully read and
validated.

## Publish one consistent snapshot

Do not assemble visible state from reads that may belong to different device
generations. When acquisition requires multiple operations, verify that device
identity and relevant header facts still match before publication, or use an
existing atomic snapshot mechanism.

Publish the new snapshot only after all required fields and integrity checks
succeed. Keep the previous valid snapshot, clear it, or expose an unavailable
state according to the existing contract; do not silently merge new partial
data with old values.

Distinguish at least absent, unreadable, malformed, unsupported, stale, and
valid states when consumers react differently. Keep raw bytes, parsed fields,
validity, timestamp or generation, and error details under one owner.

## Handle refresh and lifecycle

Define when VPD is read or reread: startup, explicit refresh, device addition,
replacement, reset, transport recovery, or product reconfiguration. Bound
retries and concurrent refreshes. Discard late results when a newer refresh or
device generation has superseded them.

On removal or replacement, invalidate cached identity and parsed fields
together. On restart, prove whether persisted or cached VPD may be reused and
how freshness is established before consumers see it.

## Validate

Use deterministic byte fixtures for minimum and maximum valid records, short
reads, inconsistent lengths, checksum failure, unknown versions, replacement
during acquisition, concurrent refresh, and late completion. Verify consumers
never observe partially updated fields.

Use target hardware to validate transport timing, device-specific access,
reset, hotplug, and error behavior that fixtures cannot prove. Keep those
results distinct from source-level parser and lifecycle tests.
