# Task record export v1

`HostContinuity.export_records(task_id, read_run=..., producer_commit=...,
evidence_reader=None)` reads a fresh handoff and returns a bounded export. It
does not execute a Run or change its Outcome. The optional evidence reader is
injected by the trusted Host and called once with the Task and its sorted unique
Run references. Reader failure affects only operation evidence availability.

`export_task_records(handoff, producer_commit=..., evidence_snapshot=None)` also
accepts an already captured handoff. `verify_export(document)` checks the schema,
field types, bindings and canonical SHA256 digest; the digest establishes content
integrity, while source trust belongs to Host composition.

## Envelope

The schema is `openubmc.task-record-export/v1`. Its allowed fields are `schema`,
`task_ref`, `producer_commit`, `run_records`, `task_aggregate`,
`operation_evidence`, and `content_digest`. The digest covers canonical UTF-8 JSON
with sorted keys, compact separators and no non-finite values, excluding itself.
Run records are sorted by Run ID. v1 and v2 record semantics remain unchanged.
Unknown versions and record fields are rejected; missing values remain null.

Only records and their aggregate are exported. Host notes, terminal-answer text,
commands, paths, endpoint addresses, raw logs, prompts and responses are excluded.
Workspace snapshots retain their existing non-secret references and repository
identity contract. Existing bounded-request budgets apply. File inputs use the
512 KiB reader and reject duplicate JSON object keys.

## Operation and test provenance

`operation_evidence` contains `status` and `snapshot`. Missing, invalid or failed
sources are `unavailable` with a null snapshot. Available means that a supplied
snapshot was validated; it does not imply complete test coverage or Run success.

A snapshot has `schema_version=1`, `task_ref`, `source_ref`, `evidence_kind`
(`observed` or `synthetic`) and at most 256 `entries`. source_ref is the canonical
SHA256 of the snapshot excluding itself. Each entry contains exactly:

| Fields | Semantics |
| --- | --- |
| `event_ref`, `run_ref` | Stable producer event identity and exact bookmarked Run |
| `repo_ref`, `source_commit` | Repository in the persisted workspace snapshot; exact clean commit |
| `command_ref`, `command_digest` | Non-secret command definition reference and SHA256; no command text |
| `kind` | `operation` or `test` |
| `status` | `passed`, `failed`, `skipped`, `not_run` or `unavailable` |
| `execution_status` | `executed`, `not_executed` or `unknown` |
| `evidence_ref`, `log_digest` | Opaque evidence reference and log SHA256, nullable when unobserved |

Passed and failed require executed status, an evidence reference and a log digest.
Skipped and not_run require not_executed. A missing, dirty or different repository
binding makes the source unavailable. The adapter does not inspect repository
files or logs to invent missing facts. Original sealed snapshots remain intact;
identical duplicate events are counted once by event_ref, and conflicts reject
the snapshot. Synthetic identity remains explicit and cannot qualify a release.

## Private files and retention

`RecordExportStore(directory).write(document)` verifies and atomically writes a
content-addressed JSON file with mode 0600 inside a private 0700 directory. It
refuses shared directories, links and changed content at an existing identity.
Repeated writes keep the original file and timestamp. This store supports
Linux/WSL; native Windows storage needs the platform's private-path integration.

No expiration or deletion runs implicitly. `prune(before_timestamp=...,
dry_run=True)` lists verified exports older than an explicit local filesystem
mtime cutoff. `dry_run=False` removes those exports only. Unrecognized, invalid,
linked or mismatched files remain untouched; producer logs, Runtime ledgers,
measurements and evidence retention remain with their original owners.

The offline CLI is `plugins/openubmc/skills/openubmc-target-runtime/tools/record_export.py`:

```bash
python3 plugins/openubmc/skills/openubmc-target-runtime/tools/record_export.py export \
  --handoff handoff.json --producer-commit FULL_SOURCE_COMMIT \
  --output-directory /tmp/private-run-exports
python3 plugins/openubmc/skills/openubmc-target-runtime/tools/record_export.py verify /tmp/private-run-exports/DIGEST.json
python3 plugins/openubmc/skills/openubmc-target-runtime/tools/record_export.py prune \
  --output-directory /tmp/private-run-exports --before-timestamp 1791590400
```

`--apply` is required for CLI deletion. These examples require actual commit and
digest arguments; they do not authorize model, target, repository or network work.
