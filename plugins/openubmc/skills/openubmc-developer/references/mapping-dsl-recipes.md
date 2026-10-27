# Mapping DSL recipes

Use the selected rackmount revision's `interface_mapping.md`, schema, parser and
neighboring configurations as the executable syntax contract. These recipes
describe the Market dialect; validate its availability in the target version.

## Select a flow operation

| Type | Inputs to trace | Output/behavior to prove |
| --- | --- | --- |
| `Property` | Object `Path`, `Interface`; `Source` property → request expression for writes | `Destination` property → unique local alias for reads; preserve type and error semantics |
| `Method` | `Name`, ordered `Params`, context and backend signature | Named result → alias, multi-return/completion handling and observable side effect |
| `List` | Parent path, interface, supported depth/filters | Collection identity, ordering, empty/missing objects and per-item visibility |
| `Task` | Async method, accepted input and task creation boundary | Stable task identity, progress/completion/error, timeout and cancellation |

For example, this is a schematic read operation; the path/interface/member must
exist in the selected source:

```json
{
  "Type": "Property",
  "Path": "/bmc/kepler/Example",
  "Interface": "bmc.kepler.Example",
  "Destination": {"Enabled": "BackendEnabled"}
}
```

In dialects with 1-based flow references, the response expression is
`${ProcessingFlow[1]/Destination/BackendEnabled}`. Validate the target parser's
index convention; never derive a new index from the JSON array's host-language
index. Keep aliases unique across operations and inspect every downstream reference
when inserting or deleting a flow entry.

## Validate input before backend effects

For `ReqBody`, define object/property types, required and optional fields,
nullability and sensitivity. Use supported `Validator` forms (`Enum`, `Length`,
`Range`, `Nonempty`, `Regex`, `IPFormat`, or a narrow `Script`) with the target
schema's actual `Formula` shape. Validate boundaries and unknown/read-only fields.
Mark passwords/tokens sensitive and verify they stay out of logs and diagnostics.

`CallIf` may test `${ReqBody/Field}` with `#WITH`/`#WITHOUT`; distinguish absent,
null, false, zero and empty strings using current parser semantics. Record which
conditions combine and what the response becomes when no operation runs.

For `Foreach`, trace the input collection and `#INDEX` substitution through each
path and parameter. Bound the collection, define partial failure, and ensure
privilege and object selection apply to every item. A loop index is not automatically
a physical slot or a stable resource identifier.

## Shape the response

Use supported `Statements` and `${Statements/Name()}` expressions to express
switch/enum conversion, prefixes/suffixes, counting, formatting and collection
shapes. Trace an expression through its `Input` and `Steps` back to the backend.
Prefer an existing declaration; use Script/Plugin only for the missing transform,
with explicit input/context, fixed return shape and error handling. Verify null,
empty array/object and single/multiple return values at the response consumer.

For a new resource inspect main/versioned schema, JSONSchemas indices, URI/type
registration and packaging in the target branch. The Market's four-file layout,
lowercase filenames, implicit GET-before-PATCH and `LockdownAllow` precedence are
version-dependent. Confirm actual generator/parser behavior and required changes
instead of applying them to every mapping edit. Test locked and unlocked behavior
where a write is affected.

Validate one read, one request-bearing method and the changed collection/task seam
when relevant. Report schema/generator results separately from actual backend or
REST/CLI execution. Carry affected identifiers into documentation and contract tests.

Source: `skills/interface-mapping/SKILL.md` at Market revision
`1f016fd13d6999599bb8d011265cc6238f0059e3`.
