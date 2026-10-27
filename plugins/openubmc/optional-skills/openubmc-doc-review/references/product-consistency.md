# Product consistency

## Claims to extract

Extract version numbers, supported platforms, defaults, ports, paths, service names,
commands and flags, configuration keys, interface names, response fields, error
codes, and stated side effects. Include negative claims such as unsupported or
deprecated behavior.

Cover nine dimensions as applicable: parameter names, defaults, displayed output,
operation results, workflow steps, feature/support claims, screenshots, version and
feature pairing, and error messages. The bundled
[consistency checklist](../resources/analyzers/consistency/references/consistency-checklist.md)
and [dimension details](../resources/analyzers/consistency/references/dimension-details.md)
provide examples; their shell recipes do not change command-execution policy.

## Verification

For each material claim:

1. Locate the closest versioned source of truth: schema, source, configuration,
   generated help, build artifact, or test.
2. Use openUBMC KB MCP to discover likely repositories or concepts when useful.
   Treat the result as a lead, not final evidence.
3. Use existing Target Runtime evidence when the claim is runtime-dependent.
   Collect new read-only evidence only when authorized and necessary.
4. Record product version and target identity for runtime observations.
5. Classify the result as `verified`, `contradicted`, `unverified`, or
   `not_applicable`.

Distinguish a documentation defect from a source defect and from behavior that varies
by version or platform. When source and runtime disagree, report both and avoid
silently rewriting the document.

Retain a claim record: ID, dimension, document path/line and stated value,
source revision/path/value, runtime target/version/time/evidence/value when used,
verification state, and reason. Preserve unavailable observations as `unverified`.
Static extraction only locates claims. A suspected product defect needs versioned
design/contract evidence; the document alone is not the intended-behavior authority.
