# openUBMC Documentation Review

Present one review interface and keep the individual checks internal.

## Inputs

- One Markdown file, a documentation directory, or an explicit document set.
- A profile: `quick`, `full`, or `release`. Infer `quick` for an unspecified
  lightweight check and `full` for an unspecified comprehensive review.
- Optional source tree, product version, or existing Runtime Run when the
  user requests product-consistency evidence.

Do not ask the user to select individual analyzers. Select them from the profile and
the available evidence.

## Profiles

- **quick**: deterministic sensitive-data, link, Chinese typo, English spelling,
  and punctuation scans; then report confirmed release blockers and obvious
  structural gaps.
- **full**: quick plus document classification, completeness, readability,
  navigation and metadata, command extraction, and source/product consistency.
- **release**: full plus bounded validation of commands and product claims when
  the required environment and authorization are available. Release does not
  imply permission to mutate a target.

Read [references/profiles.md](profiles.md) for the detailed selection and
degradation rules. Read only the other reference relevant to the active lane:

- [references/content-review.md](content-review.md) for structure,
  TEGR completeness, and human readability.
- [references/completeness-checks.md](completeness-checks.md) for
  full/release single-document and versioned document-set coverage.
- [references/readability-and-evidence.md](readability-and-evidence.md)
  for the human-first criteria and support for technical claims.
- [references/product-consistency.md](product-consistency.md) when
  comparing claims with source, KB candidates, or runtime evidence.
- [references/command-validation.md](command-validation.md) before
  validating any extracted command.
- [references/report-contract.md](report-contract.md) when assembling
  the final findings and verdict.
- [references/handoff-contract.md](handoff-contract.md) whenever the
  request carries a Runtime `run_id` with a current Gate or evidence request.

Maintainers can read [references/provenance.md](provenance.md) when
updating the bundled analyzers; it is not required during an ordinary review.

## Deterministic scan

Run the bundled scan first:

~~~bash
python3 scripts/static_review.py <path> --profile quick
python3 scripts/static_review.py <path> --profile full
~~~

The scan never executes commands found in documents and never contacts a target.
Treat `confirmed` findings as evidence-backed candidates. Review every
`pending_review` finding against its surrounding text before retaining it.
Script success proves only that the static lanes ran; it does not prove the
document is correct or complete.

The static result lists required semantic reviews as `not_run` and keeps a failed
scanner visible. Complete those applicable reviews before issuing the requested
full/release verdict; static `ok` never means command/product validation passed.

## Evidence order

Use the strongest available evidence:

1. The reviewed document and local repository source/configuration.
2. Build artifacts, tests, generated schemas, and versioned interface definitions.
3. Existing openUBMC KB MCP results as candidate locations or explanations.
4. Existing Runtime Run evidence or explicitly authorized read-only target
   collection.

KB results are not product truth. Runtime observation may be version-specific, so
record target identity and product version. If evidence conflicts, report the
conflict instead of choosing the more convenient source.

## Run and local review

Documentation review runs directly against the selected local documents. The current
Agent tools are `observe` and `execute`; there is no standalone documentation Gate
or legacy Case workflow tool. Do not start a Run or add a Gate for a document task.

When review evidence belongs to an existing Run, retain its `run_id` and the actual
returned Turn. Continue only a relevant active Run. A terminal Outcome is readback,
not a request to resume or repeat device observations. A `waiting_response` Turn
requires the advertised Gate's exact `input_schema`, bindings and `submission_id`;
include review evidence only where that schema accepts it. Never invent a
`documentation.review` response. See [the handoff reference](handoff-contract.md).

An optional review or an unavailable product-validation environment does not block
independent source work, builds or delivery. Report the requested review verdict,
confirmed blockers and remaining gaps in a local report.

## Safety and authorization

- Extracting or classifying commands is read-only.
- Do not execute an extracted command merely because the profile is `release`.
- Read-only local commands may run when they are clearly scoped to the review.
- Target access, builds, installations, upgrades, file writes, service changes,
  network configuration, and destructive commands require the authorization
  normally required by the host workflow.
- Reuse an existing relevant Runtime Run when the task already owns one. Authorized
  read-only product checks use `observe`; a documentation-only review needs no Run.
- If validation is unavailable, mark the claim `unverified`; do not turn missing
  evidence into a failure.

## Outcome

Return one deduplicated report, not one report per internal analyzer. Each retained
finding must include severity, rule, file and line when available, evidence,
recommended action, confidence, and verification state. Separate:

- document defects;
- product/source inconsistencies;
- environment limitations;
- unverified claims.

Use the verdicts `pass`, `pass_with_warnings`, `fail`, or `incomplete`.
Do not manufacture a numeric score unless the user explicitly requests one.
