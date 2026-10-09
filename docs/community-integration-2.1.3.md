# 2.1.3 candidate

Developer provides local checks for MDB/Redfish JSON compliance, concurrency
candidates, Web Backend contracts, Redfish revision differences, and interface
coverage. Findings remain advisory; missing evidence remains incomplete. Testing
uses the installed `bmcgo test` command contract. The existing log analyzer retains
its collection and analysis entrypoints, including the exact-byte-budget EOF fix.

Trusted Host composition can bind immutable workspace snapshots when starting a
Run and read fresh Run records, Task aggregates and bounded model/time/human-event
measurements. Default v1 behavior remains compatible. Record exports contain
allowlisted metadata and exact Run/repository/commit/command/log references,
with deterministic digests and explicit private retention. See
[Task record export](task-record-export-v1.md).

The candidate keeps the 2.1.2 Skill inventory: 13 full-profile Skills and seven in
the target-runtime profile. Runtime support is separate. Community revisions and
licenses remain in Developer resources. [Release inputs](release-inputs-2.1.3.json)
identify the immutable Skill and Workflow commits.

Local checks are `scripts/check_marketplace.py`, `scripts/check_community.py`,
`scripts/check_records.py` and `scripts/check_behavior.py`. Candidate metadata and
qualification describe the tested payload; a version number or fixture result does
not establish publication, installed Host selection, real provider/device results,
native Windows behavior or hosted CI qualification.
