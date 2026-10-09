# Rackmount Web Backend Plugin Patterns

Use this reference when editing
`interface_config/web_backend/plugins/orchestrator/*.lua` or
`interface_config/web_backend/script/**/*.lua`.

## Source Layout

- `mapping_config/**/*.json` declares `/UI/Rest` resources and calls Lua through
  Statements or ProcessingFlow formulas.
- `plugins/orchestrator/<module>.lua` exposes reusable functions called as
  `orchestrator.<module>.<function>(...)`.
- `script/**/*.lua` contains Script Formula files.
- `plugins/orchestrator/utils.lua` is shared by many resources and has a larger
  regression surface.

## Data Available To Lua

Common formula inputs are:

- `Input`: value passed into a Statements step;
- `ReqBody`: validated request body;
- `Query`: query parameters such as `Skip` and `Top`;
- `Uri`: URI path parameters;
- `Context`: session, user, authentication, and privilege context;
- `ProcessingFlow[N]`: result of a previous 1-based flow step.

Count the complete ProcessingFlow array before using an index. Inserting a flow
step can silently redirect later formulas to the wrong data.

## Return Shape Rules

- Return the exact scalar, object, array, or explicit-null type expected by the
  caller.
- Follow nearby uses of `cjson.json_object_new_array()`,
  `cjson.json_object_new_object()`, and `cjson.json_object_from_table()`.
- Use `cjson.null` when a field must be present as JSON null. Lua `nil` normally
  removes the field.
- Keep empty collection behavior stable. Do not alternate between `null`, `{}`,
  and `[]`.
- Preserve pagination names such as `TotalCount` and `List`.

## Validation And Error Rules

- Put simple type, range, enum, and string rules in `ReqBody`.
- Use Lua for cross-field validation, resource state checks, privilege
  filtering, and complex collection shaping.
- Reuse the structured base or custom message style found in nearby files.
- Include the related property path in validation errors when the surrounding
  implementation does so.
- Follow existing helpers and local patterns for privilege checks.

## File And Command Safety

File-backed state is acceptable only when its behavior is explicit:

- use a public repository path convention rather than an environment-specific
  path;
- serialize ordinary JSON rather than framework cjson userdata;
- handle missing files, invalid JSON, permission failures, overwrite, and
  cleanup;
- do not persist credentials, tokens, session IDs, or uploaded secrets;
- avoid shell execution; when an existing pattern requires it, use fixed
  arguments and bound every external input.

## Task And Long Operation Rules

- Keep task IDs and task URLs where the mapping and clients expect them.
- Do not return an immediate completed response for an asynchronous operation.
- Make failure observable through the follow-up task resource.
- Avoid duplicate side effects when a client retries or refreshes.

## Review Checklist

- The mapping formula resolves to an existing plugin export or script file.
- `luac -p` passes for changed Lua files when `luac` is available.
- The Lua return type matches `RspBody`.
- `nil`, `cjson.null`, empty objects, and empty arrays are intentional.
- Every `ProcessingFlow[N]` still points to the intended 1-based step.
- Privilege and system-lock behavior match the surrounding endpoint.
- Runtime paths and errors do not expose sensitive information.
- `rackmount/mds/service.json` changes with runtime behavior.
