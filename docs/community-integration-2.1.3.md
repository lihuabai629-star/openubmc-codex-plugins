# 2.1.3 candidate

Developer now provides local checks for MDB/Redfish JSON compliance, concurrency
candidates, Web Backend contracts, Redfish revision differences, and interface
documentation coverage. Checkers consume explicit local scopes and snapshots;
findings remain advisory and missing evidence remains incomplete.

Testing uses `bmcgo test` and checks the installed command contract. The existing
log analyzer retains its Redfish/SSH collection and analysis entrypoints, with an
exact-byte-budget EOF correction for plain and gzip logs.

The plugin retains the 2.1.2 skill inventory (13 full-profile skills, seven in the
target-runtime profile). Runtime support is packaged separately from that list.
Community source revisions and licenses are recorded in Developer resources.

Validation: `python -B scripts/check_community.py` and
`python -B scripts/check_marketplace.py`. Full host qualification is recorded
separately; local checks do not constitute device validation or a published release.
