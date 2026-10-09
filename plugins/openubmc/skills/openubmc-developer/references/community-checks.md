# Local specialist checks

Use the checks relevant to the confirmed change, before the source handoff. Keep
results in the current Developer phase; a scan does not introduce a new workflow
stage. Run from this Skill directory. All inputs refer to a local source checkout.

| Change or question | Check | Interpretation |
|---|---|---|
| MDB definitions, message completion codes, Redfish mapping JSON | `compliance` | Inspect findings and skipped rules/files; coverage is limited to implemented rules. |
| Shared containers, callback teardown, borrowed views, Lua numeric/GC lifetime | `concurrency` | Candidates need ownership, lifetime, synchronization or runtime evidence before classification as defects. |
| rackmount web_backend Plugin/Script or its mapping caller | `web-backend` | Trace the full mapping, 1-based ProcessingFlow destinations and consumed return types. The checker inspects the repository web_backend scope. |
| Comparing Redfish interface contracts between revisions | `redfish-diff` | Review semantic changes and supply affected resources to testing and documentation review. |

```bash
python3 scripts/community_checks.py compliance --repo /path/to/repo --file intf/mdb/example.json
python3 scripts/community_checks.py concurrency --repo /path/to/repo --file src/example.cpp
python3 scripts/community_checks.py web-backend --repo /path/to/rackmount --file interface_config/web_backend/example.lua
python3 scripts/community_checks.py redfish-diff --repo /path/to/rackmount --old-ref BASE --new-ref HEAD --output /path/to/report
```

Use actual changed files. Empty or nonmatching scopes are skipped; `incomplete`
means an unavailable dependency, failed invocation or unreadable output, not a
passing check. Compliance uses Node.js 18+; concurrency uses Python and ripgrep.
The Python tools run independently to avoid importing repository code into the
agent's process. None of these wrappers publishes GitCode messages.

For concurrency candidates, follow shared-state access through every reachable
callback and teardown. Establish the object owner, its last valid use, the
synchronization protocol and any asynchronous completion after release. For Lua
numeric/GC candidates, establish the actual runtime representation and reachable
boundary values. Retain confirmed, pending and excluded findings separately,
with revision, actual scope, omitted candidates and the evidence supporting each
classification. Dynamic experiments remain owned by Testing or Debug.

For Web Backend changes, follow mapping input/context/privileges through Lua to
the response field. Prefer an existing declarative operation when it expresses
the behavior. Check null versus empty array/object and error/task return shapes.
Version checks must follow the target repository's actual release contract.

Pass source revisions, affected interface identifiers, report paths and unresolved
coverage to the next requested stage. Node syntax checks and candidate scans do
not prove runtime correctness. Preserve raw reports locally; review/redact them
before sharing outside the workspace.

The pinned source and per-tool licenses are recorded in
[provenance.json](../resources/community/provenance.json).

Interface documentation coverage uses prepared local snapshots. Run
`python3 scripts/interface_coverage.py /path/to/interface-input.json`; see
[interface-coverage.md](interface-coverage.md) for the input contract. Missing
documentation evidence remains unverified. Review advisory findings before handoff.
