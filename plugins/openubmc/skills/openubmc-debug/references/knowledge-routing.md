# Knowledge Routing

Use the openUBMC KB to generate a candidate investigation route. Do not use it
as runtime, source, or configuration evidence.

## When to Query

Query when at least one applies:

- the symptom spans multiple components or layers;
- the owner, object, property, event, or source entry is unfamiliar;
- a community incident may provide useful search terms or a known misdiagnosis.

Skip the query when the exact owner and bounded evidence request are already known, the user asks
not to use external knowledge, or the tools are unavailable. Do not pause the main evidence path to
repair an optional knowledge integration unless the user asks for that repair.

## Retrieval Strategy

Use `openubmc_kb_query` with:

```json
{
  "query": "<symptom and exact identifiers>. Return only candidate components, objects and properties, log keywords, source entry points, similar incidents, and common misdiagnoses. Do not assert root cause.",
  "mode": "naive",
  "only_need_context": true,
  "include_references": true,
  "enable_rerank": true
}
```

`naive` is the default because it returns direct document chunks with less graph noise. If it is
insufficient, retry once with `mode: local` to expand entity and component relationships. Do not use
`mix` by default; reserve it for broad architecture exploration and inspect its references carefully.

Call `openubmc_kb_status` only when a query fails, appears stale, or indexing activity is relevant.
Use `openubmc_kb_list` only to browse document metadata; it does not answer diagnostic questions.

## Route Card

Reduce the response to this internal route card:

```yaml
candidate_components: []
object_checks: []
interface_checks: []
log_checks: []
source_entries: []
configuration_checks: []
common_misdiagnoses: []
references: []
```

Every entry is unverified. Select only the candidates relevant to the current target and map each
retained candidate to a real evidence surface. Prefer the directly matching incident over adjacent
hardware or protocol cases.

## Failure and Conflict

- Tool missing, authentication failure, timeout, empty answer, or backend error: continue without it.
- Noisy result: keep only referenced candidates that can be checked in source, objects, interfaces,
  logs, files, or configuration.
- Conflict with current target evidence: current source and fresh target evidence win.
- Similar incident with a different model, topology, version, or object identity: use only its search
  terms and checks, not its conclusion.
