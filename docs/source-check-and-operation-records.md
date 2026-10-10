# Source checks and operation records

A Run keeps its original Host workspace binding. Before preparing a new Effect,
Runtime reobserves each bound repository through a trusted Host locator. The
current project selection is irrelevant to an existing Run. Commit and dirty
state must match. A missing locator, unreadable repository or unavailable identity
opens `source.context`, as does a mismatch. The Gate accepts a retry after the
original metadata has been restored, or cancellation through the existing cancel
command. A retry cannot replace the Run binding or waive the check. Reconciliation
and reattachment keep the existing Effect identity.

These are Git metadata checks. They do not freeze dirty file contents, prove
machine or firmware identity, or authorize device operations. Legacy Runs without
a repository binding remain readable and executable, with source verification
unavailable. Target identity and freshness remain the device Adapter's preflight
responsibility.

For a newly settled Effect, Runtime records an operation receipt in the same Run
ledger transaction as its terminal result. Exact clean repository provenance
requires matching observations before preparation and after settlement. A drift,
dirty binding, unknown mutation result or unregistered observer produces no exact
receipt. The command digest identifies the redacted operation definition, and the
log digest identifies the redacted structured result receipt, not a raw device
log. Receipts include no command text, path, endpoint, credential or raw output.

Host export reads these receipts from bookmarked Runs. Repeated exports and
restarts do not execute operations or rewrite producer facts. Missing receipts
remain unavailable; an empty receipt set does not imply complete coverage. Test
commands require their own trusted execution producer and are never inferred from
an Agent's phase summary. Evidence from fixture executions retains its synthetic
classification.

The local `host_continuity.py test-record` command executes an explicitly supplied
argv in the registered repository, with a bounded timeout and output budget. It
writes a physical invocation identity before process creation. Passed or failed
requires a completed process and matching clean source observations before and
after execution. Missing executables, timeouts, incomplete output and source
changes stay unavailable. Child commands must observe their normal cleanup
contracts. Test receipts cannot update Run phases or Outcome.

`--test-command` consumes the remaining arguments. Use `--task-id`, `--run-id`,
`--repo-ref`, `--command-ref` and the optional `--timeout` before it. Export uses
ledger operation receipts and local test receipts by default; an explicit
`--evidence` file continues to supply a separately sealed snapshot.
