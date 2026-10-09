# Interface documentation coverage

When a code change touches Redfish mapping or `mds/ipmi.json`, run the bundled
coverage checker with a prepared JSON input. It performs no network or publishing.

```bash
python3 scripts/interface_coverage.py /path/to/coverage-input.json
```

Minimal input includes `changedFiles`, `headSha`, `fileContents`, `patchText`,
`docsTree`, `docsRevision`, `docsPrFiles` and `prBody`; supply an empty object
for unavailable optional maps and `null` for an unavailable docs tree. The input
contract and examples are in
[the checker](../resources/interface-coverage/scripts/doc-coverage.mjs) and its
adjacent tests. Supply the exact code head, changed filenames/patches and full
JSON content where required, the docs tree at a recorded revision, and any
explicitly linked docs PR files. Obtain missing data through the host's authorized
read-only repository access. Do not silently compare with stale or absent docs.

Keep `coverage`, `manualActions`, `invalidLinks`, `skippedFiles` and
`unmatchedFiles` in the current review evidence. Unavailable input is incomplete,
not proof of absent documentation. Actions and unsupported shapes require manual
review. A matching document proves coverage, not correct semantics; continue
source/product consistency review for changed claims. Findings are advisory unless
the caller's release criteria explicitly make them blocking. Do not automatically
publish a coverage comment or change PR/Issue state.

Include the result and coverage limitations in the source handoff. Supply the
same affected resources to Testing for relevant contract regressions.
