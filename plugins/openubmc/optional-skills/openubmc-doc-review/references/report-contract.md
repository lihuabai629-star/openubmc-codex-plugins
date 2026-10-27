# Report contract

Return one report with:

## Summary

- profile and reviewed scope;
- verdict: `pass`, `pass_with_warnings`, `fail`, or `incomplete`;
- checks completed, skipped, or degraded;
- release blockers first.

Include a check-coverage table with lane, applicability, execution state
(`completed`, `partial`, `failed`, `not_run`, `unavailable`, `not_applicable`),
evidence reference, retained/pending/excluded candidate counts and reason for gaps.
Include semantic completeness/readability and product/command verification lanes,
not just the deterministic scanners. Keep the scan's raw state separate from the
reviewer's confirmation. Preserve unsuccessful lanes and unfinished candidate
review even when other checks succeeded.

## Finding

Each finding contains:

- stable ID and category;
- severity: `critical`, `major`, or `minor`;
- file and line, or the smallest available location;
- concise rule and observed evidence;
- confidence: `high`, `medium`, or `low`;
- verification: `verified`, `contradicted`, `unverified`, or
  `not_applicable`;
- recommended action;
- source of evidence: static scan, document context, source, KB candidate, build/test,
  or Target Runtime Case.

Deduplicate overlapping language, readability, and completeness findings. A
confirmed scanner hit can still be a false positive in context; a pending hit must
not be presented as confirmed without review.

## Verdict rules

- `fail`: at least one verified release blocker, such as a live credential,
  materially wrong command, broken required path, or contradicted product claim.
- `incomplete`: a required lane failed or material release claims remain
  unverified.
- `pass_with_warnings`: no blocker, but verified non-blocking defects remain.
- `pass`: requested lanes completed with no retained defects.

Do not average unrelated findings into a numeric score by default.
