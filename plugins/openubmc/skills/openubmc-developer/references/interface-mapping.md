# Northbound Interface Mapping

Keep a mapping layer focused on translating an existing backend contract into
Redfish, Web, CLI, SNMP, or modeled IPMI behavior. Keep business transactions,
persistence ownership, and complex policy in the backend owner.

## Trace the visible contract

Confirm:

```text
protocol and version
URI, command, resource, or operation identity
backend path, interface, member, and signature
request fields, validation, defaults, and sensitivity
response fields and their dynamic source
errors and caller-visible related properties or completion codes
privileges, locks, and resource visibility
side effects, idempotency, concurrency, and compatibility
```

Trace every dynamic response field to a statement, method, property, or context
value. Use static values only for explicit constants, identity, or protocol
metadata.

## Build processing flows

Use only flow elements supported by the target repository version. Keep path,
member, parameter order, and types aligned with the backend contract. Make
aliases unique and ordering dependencies visible.

Define empty, absent, nullable, unknown-enum, partial-failure, and collection
index behavior for conditional and iterative flows. Give asynchronous operations
stable task identity, completion, status, timeout, and error behavior.

Prefer existing declarative conversions and statements. Use a script or plugin
for a narrow transformation only when the declaration language cannot express
it; keep inputs minimal and output shape fixed.

## Validate requests and responses

For writable data, specify required/optional, nullable, default, enum, range,
length, pattern, format, unknown-field, and read-only-field behavior. Mark
sensitive values and keep them out of logs, errors, and unintended persistence.

Keep field names, casing, types, collections, and required/nullability rules
aligned with the protocol schema. Map backend errors to stable protocol errors
instead of exposing natural-language logs.

Distinguish authentication, authorization, validation, resource lookup,
conflict, locked, unsupported, unavailable, timeout, and partial success without
leaking resource existence.

## Validate protocol behavior

Run repository-selected mapping, JSON, protocol schema, formatting, and focused
contract validators. Confirm the changed resource or operation was selected.
Static validation proves mapping shape, not backend correctness or deployed API
behavior; verify those through their own seams when the accepted outcome needs
them.
