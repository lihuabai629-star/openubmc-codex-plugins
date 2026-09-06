# ProfileSchema Import and Export

ProfileSchema defines user-visible configuration import/export data, value
constraints, directionality, redaction, and product customization. Treat the
schema and the component adapter as two sides of one public contract.

## Trace the complete contract

Inspect:

- the component schema under the ProfileSchema repository;
- product-specific schema overrides or customization;
- the component's import/export adapter and class/property mapping;
- the validation engine and the target version's supported schema keywords;
- permissions, operation logging, sensitive values, and side effects;
- old exported profiles that must remain importable.

Confirm from target-version source where schemas are installed, which owner
performs import validation, and whether export follows the same path. Do not
assume a read-only directory or shared validation owner across versions; prove
both directions independently.

## Keep schema and adapter aligned

For each user-visible field, align:

```text
collection and property name
type and nested shape
ImportAndExport or ExportOnly direction
required, default, nullable, and additional-property behavior
enum, range, length, pattern, and uniqueness constraints
instance identity and ordering
HideValue and sensitive-data handling
adapter import function, export function, and error mapping
```

Use only schema keywords supported by the deployed validation engine. Preserve
the fixed top-level structure expected by the product, including component
description, configuration data, and customization sections where applicable.

## Design import semantics

Define whether import is replace, merge, patch, create, or update. Specify
ordering and rollback when several fields or objects form one logical
transaction. Keep validation errors tied to user-visible paths.

Handle duplicate identities, missing instances, read-only/export-only fields,
unknown properties, partial failure, retries, and idempotent re-import. Validate
before mutating component state whenever the framework permits it.

Keep operation logs useful without recording credentials, hidden values, keys,
or full sensitive profiles.

## Preserve compatibility

Compare previous exported files with the new importer. For renamed or moved
fields, define aliases or migration. For enum/type/default changes, define how
old values are read and how rollback handles newly exported data.

Product-specific overrides can change defaults or visible properties. Verify
both the shared schema and the effective product schema.

## Validate

Run repository schema tests and the validation engine supported by the target
version. Exercise valid import/export round trips, old-profile import, hidden
values, export-only fields, invalid types and constraints, unknown fields,
duplicate instances, partial failure, rollback, and product customization.
