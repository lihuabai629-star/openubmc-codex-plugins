# Persistence Compatibility

Persistence behavior depends on the authored model, generator, language
runtime, persistence owner, and product version. Verify the complete chain
before treating similarly named usage values as equivalent.

## Contents

- [Identify ownership and lifetime](#identify-ownership-and-lifetime)
- [Inspect language-specific Retain behavior](#inspect-language-specific-retain-behavior)
- [Review keys, rows, and deletion](#review-keys-rows-and-deletion)
- [Plan upgrade and rollback](#plan-upgrade-and-rollback)
- [Validate the contract](#validate-the-contract)

## Identify ownership and lifetime

Determine whether the component owns a local database or synchronizes through
the persistence service. Inspect current schemas and generated code for the
supported values; names and precedence differ between model generations.

Common lifetime families include:

| Family | Typical intent |
| --- | --- |
| `Memory` | Process-local working state |
| `TemporaryPer` | Temporary persistence cleared by reset policy |
| `ResetPer` | State retained through selected resets |
| `PoweroffPer` | Flash-backed state retained through power cycles |
| `PermanentPer` | Small-capacity permanent state |
| `*Retain` | A retain variant whose actual semantics depend on runtime support |

Inspect class/table fields such as table identity, location, lifetime, maximum
rows, key definitions, field type, default, nullability, sensitivity, critical
backup, and property-level usage. Preserve source spelling and schema
precedence rather than normalizing from memory.

Map generated database code to its authored input. Common Lua outputs include
database definitions, local database definitions, ORM classes, and default data;
the exact paths and names are version-specific.

## Inspect language-specific Retain behavior

Retain is not portable by name alone. Trace the authored usage value through the
target branch's generator, language binding, runtime persistence key, storage
owner, and lifecycle behavior. Do not reuse a mapping remembered from another
branch, language, or product without current source evidence and provenance.

Therefore:

- inspect the actual language binding and runtime path;
- avoid promising retain semantics from model text alone;
- treat a Lua-to-C++ or C++-to-Lua migration as a behavior change even when the
  authored usage string is unchanged;
- add a compatibility test that observes the intended restart/reset behavior.

## Review keys, rows, and deletion

Trace:

- table, view, alias, extension table, and field ordering;
- primary, composite, unique, and persistence keys;
- default-data insertion and existing-row backfill;
- object creation, update, replacement, and removal;
- tombstone or deleted-data tables where present;
- cache invalidation versus persistent deletion.

Do not infer database deletion from an in-memory object removal callback. Trace
the target branch from the removal event to the persistence owner and the actual
row, tombstone, or cache operation. Another component may own deletion, or the
row may intentionally remain for recreation or synchronization.

Specify whether deleting an object must:

- delete the persistent row immediately;
- retain a tombstone for synchronization;
- retain data for later object recreation;
- clear only working memory;
- restore authored defaults.

Treat this as externally observable compatibility, not an implementation detail.

## Plan upgrade and rollback

Build an old/new matrix:

| Direction | Questions |
| --- | --- |
| old → new | Can new code read existing rows, aliases, defaults, and enum values? |
| new → old rollback | Can old code tolerate rows or fields written by the new version? |
| mixed services | Can producers and consumers disagree on keys, lifetime, or deletion? |
| reset/restart | Which data survives each relevant lifecycle event? |

For additions, define backfill, missing-value, and default semantics. For rename
or movement, define aliases or migration and the rollback window. For type,
key, field-order, lifetime, or ownership changes, use an explicit migration or
dual-read/write strategy when compatibility requires it.

Review capacity and write frequency for flash-backed or permanent storage.
Review sensitive-data collection, export, redaction, and cleanup separately
from ordinary persistence.

## Validate the contract

Use independent fixtures representing old rows and new rows. Verify:

- cold start with no database;
- restart with existing data;
- upgrade from the previous supported version;
- rollback after the new version has written data;
- deletion and object recreation;
- reset/power-cycle behavior for the selected lifetime;
- Lua/C++ behavior where both implementations consume the same model;
- default-data and partial-migration recovery.

Schema parsing and build success cannot establish these runtime semantics.
