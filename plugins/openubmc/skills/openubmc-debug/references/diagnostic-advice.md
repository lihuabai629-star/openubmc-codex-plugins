# Drive diagnostic advice

Use `diagnostic_advice.py` after a read-only capture when several explanations still fit a missing
Drive. It examines explicitly selected device facts and returns hypotheses plus the next observation
that can separate them. Run the helper locally:

```bash
python "$HOME/.agents/skills/openubmc-debug/scripts/diagnostic_advice.py" \
  --input /tmp/drive-advice-request.json
```

The JSON result contains `facts`, `hypotheses`, and `next_observations`. A hypothesis is `fulfilled`
when all three captured facts match its pattern, `contradicted` when at least one contradicts it,
and otherwise `unknown`. These labels describe the pattern at `snapshot.at`; they do not establish
a root cause or accept a `DiagnosisRecord`.

| Hypothesis | Hardware discovery | MDB object | Northbound representation |
| --- | --- | --- | --- |
| `hardware_not_discovered` | absent | absent | absent |
| `mdb_not_created` | present | absent | absent |
| `northbound_not_published` | present | present | absent |

The patterns are bounded candidates for one missing Drive. If all are contradicted, investigate
outside this set. An empty `next_observations` means no supplied query separates the remaining
candidates; it is not evidence of diagnostic completion.

## Bind captured facts

The following request analyzes a historical example. For a current diagnosis, omit `snapshot_at`
and use the target epochs reported by the current Runtime. Put the original captured documents in
`sources`; do not edit their values or freshness metadata to make a pattern match.

```json
{
  "schema": "openubmc-debug.diagnostic-advice-request.v1",
  "target": "<target-ip>",
  "device": {"Name": "Drive0", "Protocol": "NVMe"},
  "snapshot_at": "2026-09-08T01:00:00+00:00",
  "max_age_seconds": 30,
  "target_epochs": {"<target-ip>": 7},
  "sources": {
    "capture": {
      "ip": "<target-ip>",
      "ok": true,
      "observed_at": "2026-09-08T01:00:00+00:00",
      "target_epoch": 7,
      "result": {
        "freshness": {"status": "fresh", "complete": true},
        "drive": {"Name": "Drive0", "Protocol": "NVMe", "mdb": false}
      }
    }
  },
  "facts": [
    {
      "stage": "mdb",
      "source_id": "capture",
      "device_pointer": "/result/drive",
      "value_pointer": "/result/drive/mdb"
    }
  ],
  "queries": {
    "hardware_discovery": {
      "target": "<target-ip>",
      "selectors": [
        {"id": "scanner-drive0", "kind": "mdb", "queries": ["lsprop ScannerDrive0"]}
      ]
    }
  }
}
```

`device_pointer` identifies an object containing the selected `Name` and `Protocol`, optionally
`ResourceId`. `value_pointer` must point inside that same object to a captured boolean presence
value. Use the actual paths in your capture. This helper does not interpret command text, convert
numeric Presence codes, infer absence from a missing object, or fabricate discovery/northbound
facts. If that surface has no captured boolean fact, omit its binding and keep it unknown.

`queries` uses the existing `ObservationQuery` contract, including its reviewed read-only selector
grammar. The sample scanner name is illustrative: select the actual scanner observation for the
device. The helper returns at most one query with `expected_outcomes.present/absent` candidate IDs.
Passing that query to `observe` is a separate Agent action; the helper itself performs no collection.
Hardware discovery must have its own observation even when it is exposed through an MDB scanner.
The business Drive object's existence cannot stand in for hardware discovery.

Sources require an observation timestamp and a known matching epoch. A normal workflow's epoch
can come from the matching host in `result.runtime.status.targets[].epochs.target_epoch`.
The default maximum age is 30 seconds and can be set from 1 through 900 seconds. Future captures,
expired `freshness.valid_until`, partial/stale content, and unknown or changed epochs remain
unknown. An explicit historical `snapshot_at` only evaluates that historical boundary; Runtime
does not project an attachment whose boundary is older than its window.

For an existing `ObservationRef`, supply the corresponding complete persisted observation document
as the source and add `observation_refs: {"source-id": <original ObservationRef>}`. Fact pointers then
start under `/raw`. The helper checks the existing reference's digest, size, scope, target,
timestamp, fingerprint, and epoch, and also honors the source's `reusable` and `fresh_until` fields.
It preserves the reference without issuing a replacement handle or extending its validity.

Requests are limited to 1 MiB, eight sources and 24 facts, with one fact per target/stage. Output is
limited to 16 KiB. Invalid or ambiguous references produce exit code 2, a diagnostic on stderr, and
no advice JSON. Truncated source content is never a successful negative fact.

## Compare the fault chain

Add `include_fault_chain: true`, `reference_target`, and the original Runtime `comparison_receipt`
to opt in. Supply both targets' original source documents and bind their observed facts to the same
device identity. The source digests must match `ComparisonReceipt.sources` exactly.

`fault_chain.stages` always follows `hardware_discovery`, `mdb`, `northbound`. A first observed
divergence is reported only for a complete, fresh comparison with all stages known on both
targets. Missing hardware remains `unknown`; missing or mismatched stages make the location
inconclusive. `comparison_receipt_id`, `comparison_sources`, and the original `differences` remain
available beside the summary. The helper never changes the underlying comparison's conclusion or
freshness assessment.

## Runtime adapters

An existing Debug adapter can call the public Python function
`attach_diagnostic_advice(capture, request)` before returning its captured payload. The equivalent
local CLI operation is:

```bash
python "$HOME/.agents/skills/openubmc-debug/scripts/diagnostic_advice.py" \
  --input /tmp/drive-advice-request.json \
  --attach-to /tmp/drive-capture.json > /tmp/drive-capture-with-advice.json
```

Every source must be the unannotated capture itself or one of its comparison target results.
Runtime validates those source digests and fact pointers before exposing
`diagnostic_receipt.diagnostic_advice`; each fact receives the current operation's Evidence IDs.
The ordinary results, coverage, comparison, receipt identity and diagnosis acceptance remain
independent of the annotation. The CLI output alone does not create a Runtime receipt or Run.

Advice is optional metadata: invalid attachments are omitted. Projection or persistence budgets
can drop it with `diagnostic_advice_omitted` set to `projection_budget` or `persistence_budget`,
without sacrificing factual results to retain suggestions. Resume and acceptance continue through
the existing `execute` contract.

Fault-chain summaries are available in the standalone helper output. Runtime
projects validated facts, hypotheses and next observations; it omits the helper
fault chain because ComparisonReceipt provenance is validated separately.
