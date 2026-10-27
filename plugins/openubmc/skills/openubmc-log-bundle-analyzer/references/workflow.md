---
name: openubmc-log-bundle-analyzer
description: Validate and analyze local openUBMC one-click log bundles with bounded problem-driven routing and file-and-line evidence. Use for a supplied .tar/.tar.gz archive or extracted dump_info tree; not for collecting a bundle from a BMC, live-runtime debugging, or observability-system diagnosis.
---

# openUBMC local log bundle analysis

Analyze a supplied local `.tar`/`.tar.gz` or extracted `dump_info` tree. Reuse the task's problem statement; for a general request to inspect a bundle, use that inspection intent as `problem` and begin a broad scan without asking for a narrower symptom. This Skill opens no network connection. Remote collection and live investigation require their own available workflow owners.

Prefer `openubmc_analyze_bundle` for analysis and `openubmc_read_evidence` for original file-and-line verification. Codex prefixes both names with `mcp__openubmc-offline__` and requires absolute input/output directory paths; native DSH uses the unprefixed names and resolves relative paths from the Session directory. Read the returned scan limits and errors before drawing conclusions. Full redacted JSON is saved at `artifact`.

When these tools are unavailable, run `python3 scripts/analyze_bundle.py --bundle <archive> --problem '<question>' --output-json analysis.json`, or use `--bundle-dir <directory>`. Resolve scripts from this Skill's resource directory. Read [the analysis workflow](workflow-guide.md) for input limits and the evidence/report rules.

Keep file-and-line evidence, scan failures, truncation, definition reliability and missing coverage explicit. Timelines and event correlations provide context and do not establish causality. Structured summaries omit sensitive values; unknown status codes remain opaque. Use `scripts/audit_catalog_coverage.py` for explicit catalog coverage audits.

## References to load only when needed

The analyzer owns the maintained catalog; normal analysis does not require loading these catalog references into context. Load [analysis details](analysis.md), [catalog definitions](catalog-schema.md) or [the output schema](analysis-output.schema.json) only for the current question or an analyzer change.

At a stage change, select and read the current owner through the Host catalog; carry the existing Run and authorization. Report the smallest missing read-only probe when bundle evidence is insufficient.
