# Completeness and navigation checks

Classify the document and scope first. Retain check ID, applicability, evidence
and decision. A file can refer to shared prerequisites or metadata elsewhere.
State why an item is not applicable; absent inventory means unknown coverage.

## Single-document checks

| ID | Check | Evidence needed |
| --- | --- | --- |
| C01 | Audience, task and scope | Reader can select this document and identify the expected outcome |
| C02 | Prerequisites and applicability | Roles, hardware, tools, initial state and supported versions are supplied or linked |
| C03 | Reproducible procedure | Working directory, variables, inputs, sequence, optional branches and intermediate results are clear |
| C04 | Success and recovery | Final acceptance, likely failures and safe retry/cleanup match the operation |
| C05 | Support and lifecycle | Supported, experimental and deprecated behavior and replacement policy are discoverable |
| C06 | Reference parameters | Names, type, required/default/nullability, constraints, privilege and effects cover the selected API/configuration |
| C07 | Returns and errors | Response/completion/error shapes, meaning and handling cover the selected interface; examples match them |
| C08 (upstream D8) | Specifications and dependencies | Capacity/range/platform limits and component/SDK/firmware pairings have a source or an explicit unknown |
| C09 (upstream D9) | Calling/configuration examples | Initialization, placeholders, input/output and cleanup suffice; examples use supported APIs |
| C10 (upstream D10) | Operational errors and alarms | Reader can recognize likely errors/alarms, assess impact and reach corrective action; deduplicate C07 |
| C11 | Explanation | Rationale, terms, alternatives and tradeoffs support the stated behavior and connect to action/reference |

Follow the learner path for tutorials, the selected task for how-to guides, the
declared interface set for references and supported claims for explanations.
FAQ text, fixed word counts and all four TEGR types are not universal requirements.
Report mixed types only when they obstruct the task or hide needed information.

## Document-set checks

| ID | Check | Evidence needed |
| --- | --- | --- |
| S01 | Entry and next step | Actual site/sidebar/TOC entry and reachable task paths |
| S02 | Versioned scope inventory | Feature/task/API/configuration/error inventory, revision, product scope and exclusions |
| S03 | Content coverage | Applicable inventory items map to sections whose content matches the item |
| S04 | Cross-navigation | Necessary concept/procedure/reference and troubleshooting transitions are reachable |
| S05 | Orphan/lifecycle review | Unreachable pages and deprecated pages without replacement are identified |
| S06 | Assembly consistency | Shared terms, variables, versions, links and reused modules agree |

Build a matrix with inventory item, version, applicable task/type, document/section,
evidence and status `covered`, `partial`, `missing`, `unknown` or `not_applicable`.
Allow many-to-many mappings. Review content before marking coverage; a matching
filename is only a location candidate. Report status counts and exclusions. Use
a percentage only with a credible denominator and a caller-requested metric.

Developer's checker supplies candidates from a prepared snapshot through
[interface coverage](../../../skills/openubmc-developer/references/interface-coverage.md).
Retain code/docs revisions, `conclusion`, `coverage`, `manualActions`, `skippedFiles`
and `unmatchedFiles`. `status=ok` indicates execution; `uncovered`/`incomplete` is a
separate coverage conclusion. This evidence handoff introduces no Runtime Gate
and does not prove semantic consistency.

Source: Market `agent-doc-completeness`, `doc-structure-meta-tester` and
`doc-tegr-content-tester`, revision `1f016fd13d6999599bb8d011265cc6238f0059e3`.
