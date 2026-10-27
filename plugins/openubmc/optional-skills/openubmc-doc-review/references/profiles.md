# Review profiles

## quick

Run the `security`, `links`, `typo`, `spelling`, and `punctuation`
analyzers. Inspect headings, prerequisites, applicability/version statements, and
verification steps directly when the document is operational.

Use quick for routine author feedback and early drafts. External URLs are checked
for syntax and local resolution only unless the user requests network validation.

## full

Run every quick lane plus `cli` and `consistency`. Classify each document as a
tutorial, how-to guide, reference, explanation, or mixed/unclear. Apply the content
and readability review. Compare factual claims with repository evidence when a
source tree is available.

Use full for pull-request documentation review or a pre-publication audit.

## release

Perform the full review. Then build a validation plan for extracted commands and
product claims. Execute only the subset already authorized and safe in the available
environment. Use Target Runtime for real BMC evidence instead of embedding target
access in this Skill.

Use release for a publication gate. A release verdict is `incomplete` when a
material claim requires unavailable evidence. It is `fail` only when evidence
demonstrates a release-blocking defect.

## Degradation

- Missing optional source: keep static results and mark product claims unverified.
- KB MCP unavailable: search local source; do not block static review.
- Target Runtime unavailable: do not emulate its mutation or Case state.
- Analyzer failure: retain results from successful lanes, identify the missing lane,
  and use `incomplete` if it affects the requested verdict.
- Non-Markdown input: review only when it can be read as text; otherwise route to a
  format-specific document Skill.
