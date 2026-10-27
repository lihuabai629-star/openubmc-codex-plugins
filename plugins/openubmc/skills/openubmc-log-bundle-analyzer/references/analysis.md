# Analysis and output contract

## Contents

- [Structure validation](#structure-validation)
- [Problem-driven log selection](#problem-driven-log-selection)
- [Paths and rotations](#paths-and-rotations)
- [Bounded scanning and scan status](#bounded-scanning-and-scan-status)
- [Evidence extraction](#evidence-extraction)
- [Time windows](#time-windows)
- [Timeline and temporal correlation](#timeline-and-temporal-correlation)
- [Stable evidence findings](#stable-evidence-findings)
- [Structured summaries](#structured-summaries)
- [Output disclosure](#output-disclosure)
- [JSON result](#json-result)

## Structure validation

The analyzer accepts a local archive or an extracted directory. Archives are rejected when they contain traversal paths, links, device entries, excessive members, or an excessive declared expanded size.

Artifact validation is bounded before log selection begins:

- an archive may be at most 4 GiB and contain at most 200,000 members;
- its declared expanded size may not exceed 16 GiB or the compression-ratio guard of 200 times the archive size, with a 64 MiB minimum allowance;
- extraction preserves at least 256 MiB of free space;
- an already extracted tree may contain at most 200,000 entries, reach at most 64 path components below the supplied root, and contain at most 16 GiB of regular-file data;
- symbolic links and special files are rejected for both archive and directory inputs.
- entry names containing backslashes or ASCII control characters are rejected so every emitted bundle-relative path remains valid under the JSON output contract.

A usable bundle has exactly one root containing `dump_info/` and at least one recognized section:

- `LogDump`
- `AppDump`
- `RTOSDump`
- `OSDump`
- `SpLogDump`
- `BMALogDump`
- `DeviceDump`
- `3rdDump`
- `CoreDump`
- `OptBMC`

Missing `LogDump`, `AppDump`, or `RTOSDump` is a warning rather than an automatic failure because products may emit partial bundles. The validation result records present, missing, and unknown sections plus file counts. For every recognized section it reports at most 200 immediate child-directory records and their recursive file counts. `subdirectory_count` retains the observed count and `subdirectories_truncated` states whether names were omitted from the returned list.

Direct files under `dump_info/` are reported as `root_files` with bundle-relative paths and byte sizes. Their contents are not read during structure validation.

Nested archives are regular bundle artifacts, not automatic extraction targets. Keep core archives, factory backups, configuration archives, and other potentially sensitive payloads opaque unless the user explicitly authorizes deeper inspection and the incident requires it. Recognizing `BMALogDump`, `3rdDump`, `CoreDump`, and `OptBMC` confirms observed structure only; it does not establish identical semantics across products.

## Problem-driven log selection

The analyzer loads `references/logs.json` as its maintained executable catalog. Agents normally consume the selected-log metadata in the result rather than loading this catalog into context.

When the problem clearly names a concrete file or bundle-relative path that exists in the validated bundle, physical-path binding runs first. It selects only those exact paths and inherits the most specific catalog contract. A request that explicitly asks for correlation or comparison keeps ordinary multi-log routing instead. Natural symptom notation such as `Web/HTTPS` is not treated as a bundle path by itself.

If no physical path is bound, only definitions with `route_mode: automatic` participate in ordinary selection. `explicit_only` definitions require a concrete user-named file or path, and `never` definitions are not selectable. Automatic selection order is:

1. rules whose `match_keywords` occur in the problem, with any rule-declared primary artifact ranked first;
2. explicit catalog log names in the problem;
3. a bundle-local `AppDump/<component>/` directory whose normalized name occurs in the problem; this targets only that component's maintained `mdb_info.log`, `sync_property_trace.log`, and `rpc_records.log` contracts;
4. non-generic keywords attached to each known log;
5. a bounded generic rule for broad health or recent-error requests, when a matching rule explicitly enables it.

Generic terms such as `error` and `failed` do not make every known log a candidate. If no rule or specific file keyword matches, the analyzer returns no selected logs instead of scanning the entire artifact.

ASCII routing terms are matched as tokens or complete phrases, not as arbitrary substrings inside other words. Chinese phrases continue to use phrase matching. This prevents short terms such as `sel`, `lan`, `ip`, and `led` from matching unrelated neighboring words.

Each selected log reports:

- `definition_status`: maintained heuristic for repository routing, bundle-local routing for current-bundle component hints, `observed_path` for structure-only artifact definitions, and documented/community-supported only with independently verifiable public provenance;
- `source_type`: normally `repository_maintained` or `bundle_local`; public-source types require an exact stable URL using lowercase `https://`, a public DNS host, and a canonical port, without userinfo or a query string, rather than a local filename, exported discussion name, observed bundle path, or repository homepage;
- `source_reference`: an exact, independently accessible HTTPS URL meeting that boundary when one is available, optionally with a simple fragment anchor, otherwise a neutral value such as `repository-maintained heuristic`;
- `source_revision`: a non-empty document revision, repository commit, or equivalent version required for `component_documentation`, `community_discussion`, and `public_repository` sources; it is omitted for repository-maintained, observed-structure, and bundle-local sources;
- `reliability`: `documented`, `heuristic`, `observed_only`, or `local_only`.
- `routing_basis`: whether selection came from an exact physical bundle path (`explicit_bundle_path`), a problem rule, an explicit catalog filename, a maintained definition keyword, or a current-bundle component name;
- `routing_reliability`: `local_only` when current-bundle structure selected or narrowed a path, otherwise `heuristic`.
- `structured_parser`: the bounded parser used for a supported structured file, otherwise empty.
- `semantic_level`: `path_only`, `purpose`, `structure`, or `diagnostic`, describing how much stable meaning the catalog can claim;
- `artifact_format`: the format class used to enforce safe inspection boundaries;
- `route_mode`: `automatic`, `explicit_only`, or `never`;
- `sensitivity`: `ordinary`, `identifier_sensitive`, `configuration_sensitive`, or `highly_sensitive`;
- `scan_mode`: `text` for bounded content scanning or `metadata_only` for an artifact whose payload must not be read by default.

The catalog mixes community-supported definitions carrying exact public URLs and revisions with repository-maintained heuristics and observed-path coverage. Community discussions support the named file's general purpose, not a stable field-level product protocol. A path observed in one bundle establishes presence only for that artifact and does not establish cross-product semantics. Reliability describes the file contract, not whether a particular evidence line is true; a heuristic route can still contain direct failure evidence, while a documented contract may still contain stale data.

## Paths and rotations

Exact file definitions include numeric rotations in the same directory unless the definition sets `include_rotations: false`, for example:

- `app.log`
- `app.log.1`
- `app.log.2.gz`

Wildcard definitions such as `dump_info/AppDump/*/mdb_info.log` expand across component directories. A numeric rotation inherits a wildcard file contract only when its corresponding base file exists and matches that wildcard. Component words present in the problem increase the ranking of matching component paths.

All returned bundle-relative paths, including `existing_paths`, evidence pointers and root-file entries, use `/` on every operating system. Filesystem access retains the operating system's native paths.

Path discovery is fixed-capacity as well as byte-bounded. One analysis shares a 100,000-entry inspection budget across component hints and catalog path expansion. Component-hint enrichment inspects at most 4,096 `AppDump` entries and retains at most 64 matching component hints. Each wildcard pattern and rotated-file family retains at most 4,096 candidates, and each selected log retains at most 4,096 expanded paths. The public `existing_paths` sample contains at most 10 paths; `existing_path_count` and its completeness fields describe the larger bounded discovery result.

Recursive `**` patterns are rejected. Dynamic component names containing glob metacharacters, backslashes, control characters, padding, or excessive length are skipped rather than converted into executable catalog paths when component hints are collected; a validated bundle tree still rejects backslashes and ASCII control characters before analysis. When a capacity limit is reached, the selected-log record sets `path_discovery_complete: false` and `existing_path_count_is_lower_bound: true`, then emits `path_discovery_limit_reached` with one of `entry_limit`, `glob_match_limit`, `rotation_limit`, or `path_limit` and the applicable numeric limit. An unsafe component name instead emits `component_hint_invalid_name_skipped`; it is not reported as a capacity event. A count from an incomplete discovery pass is not a file total.

## Bounded scanning and scan status

The CLI accepts only positive values up to the following hard ceilings:

| Option | Default | Maximum |
| --- | ---: | ---: |
| `--analysis-max-files` | 8 log types | 64 log types |
| `--analysis-max-lines` | 3 retained lines per log type | 100 retained lines per log type |
| `--analysis-max-paths-per-log` | 12 physical paths | 64 physical paths |
| `--analysis-max-bytes-per-file` | 8 MiB | 64 MiB |
| `--analysis-max-total-bytes` | 64 MiB | 256 MiB |
| `--analysis-max-line-bytes` | 64 KiB | 1 MiB |

A wildcard may discover more paths than the physical-read limit. `existing_path_count` describes paths observed by the bounded discovery pass while `scanned_paths` describes what was actually read. If `path_discovery_complete` is false, that count is a lower bound.

UTF-8 is preferred and GB18030 is accepted as a fallback. Invalid mixed data is decoded with replacement and reported. Embedded or short NUL runs are treated as binary. A complete text line may recover from a run of at least 16 NUL bytes only when the run is confined to the line boundary and the remaining bytes decode strictly as UTF-8 or GB18030; this emits `nul_padding_removed` and marks the assessment as having an evidence gap. Damaged gzip streams, permission failures, overlong lines, and exhausted limits appear under `scan.errors` or `scan.warnings`; they are never silently converted into “no evidence.”

## Evidence extraction

Candidate lines rank in this order:

1. direct failure phrases tied to the problem;
2. lines containing both problem terms and failure terms;
3. lines containing problem terms;
4. generic failure lines within an already selected log.

Catalog `keywords` drive file selection. A file may define narrower
`evidence_keywords` for content matching when its routing words also occur in
routine lifecycle text. When present, that narrower vocabulary replaces the
routing words during content matching. This prevents ordinary registration
records from becoming problem evidence while retaining real event, alarm, and
failure records.

Within the same relevance band, component-path relevance and newer parseable timestamps rank higher. Fixed headers and known low-signal templates are excluded.

Common authorization, cookie, password, token, secret, and device-UID assignments are replaced with `<redacted>` during evidence extraction. An evidence item changed by that scan includes `redacted: true`. Report-wide identifier and location redaction is applied later according to `output_policy` and is not represented by this per-line marker.

Human-readable CLI output escapes terminal control characters from untrusted log text so a bundle cannot forge status lines or terminal sequences. JSON mode uses JSON escaping and remains the preferred machine-consumed interface.

## Time windows

Use `--analysis-since` and `--analysis-until` with ISO-8601-compatible values. A date-only `--analysis-until YYYY-MM-DD` includes that entire calendar day. Use `--analysis-timezone` with `UTC`, a `+/-HH:MM` offset, or an IANA timezone such as `Asia/Shanghai` to interpret timestamps that do not carry their own offset. Without this option, timestamps with unknown timezone remain naive and are not silently treated as UTC.

When either bound is set:

- only lines with a parseable timestamp are eligible;
- out-of-window lines are excluded;
- the normalized bounds appear in `result.analysis.time_window`.

Do not correlate timestamps across incompatible aware/naive time domains. When no
`--analysis-timezone` is supplied and both domains occur, `timeline` is grouped
and ordered only inside each domain: `sequence_scope` is `time_domain`,
`domain_sequence` restarts at one for each domain, and `scan.warnings` contains
`timeline_time_domain_partitioned` (and, when only context evidence introduces
the second domain, `correlation_time_domain_partitioned`). The global
`sequence` is then a serialization position, not a cross-domain chronology.
Provide `--analysis-timezone` when the local-time convention is known so the
domains can be normalized and compared.

Do not use absence inside a narrow window as proof that the event did not occur; the relevant file may lack parseable timestamps or may be missing from the bundle.

## Timeline and temporal correlation

Timestamped evidence is emitted under `analysis.timeline`. It is ascending globally only when `sequence_scope` is `global`; partitioned timelines are ascending within each `time_domain` by `domain_sequence`. `analysis.correlation_windows` groups evidence from at least two log types when adjacent events are within five minutes. These windows are explicitly marked `temporal_proximity_only`: they help the Agent inspect a possible sequence but do not prove a causal relationship.

`analysis.event_correlations` is narrower. During the primary bounded read, the analyzer discovers timestamped `operation.log` failure anchors independently of the small evidence sample retained for display. If anchors exist, it uses the remaining global analysis-byte budget for a second bounded pass over the other selected paths and retains at most eight nearby timestamped candidate pointers per anchor inside the same five-minute window. This lets correlation find a nearby line that `analysis-max-lines` sampling omitted without promoting that line into `evidence`, `evidence_findings`, or the assessment.

Each candidate includes a signed `delta_seconds`; `shared_components` contains only exact component tokens observed on both sides. The result is marked `candidate_context_not_causality`. `candidate_scan_complete` is true only when both anchor discovery and the candidate pass covered their configured bounded inputs without path, byte, line, decoding, or time-domain gaps. Anchors with no candidate are preserved in `unmatched_event_anchors`; their reason distinguishes a complete no-match from an incomplete candidate scan.

`analysis.correlation_scan` makes the second pass auditable. It reports anchor counts, path coverage, primary and second-pass byte use, per-anchor observed/retained candidate counts, configured limits, and phase-specific warnings or errors. Candidate retention is bounded independently of scan completeness: more than eight matches for one anchor can be sampled while the pass itself remains complete, and the observed/retained counts expose that distinction.

## Stable evidence findings

`analysis.evidence_findings` groups repeated log signals under a deterministic `finding_id`. Timestamps, addresses, numeric identifiers, and authentication principals are normalized only for grouping; the representative evidence retains its redacted source line and portable pointer. Each group records an integer finding-contract `revision`, the number of retained evidence samples, whether that number is a lower bound, whether counting was complete, sampled time endpoints, and up to eight evidence pointers. Since schema 2.1 these fields are `sampled_occurrence_count`, `count_is_lower_bound`, `count_complete`, `sampled_first_timestamp`, and `sampled_last_timestamp`. This integer `revision` is separate from an optional catalog `source_revision` carried by evidence pointers.

This is an evidence-deduplication contract, not a root-cause verdict. `reported_severity` reflects wording already present in the log; it is not an incident-impact rating.

## Structured summaries

Supported files can emit `analysis.structured_summaries` during the same bounded read used for evidence extraction:

- `mdb_properties`: object, interface, and property inventories; property values are omitted;
- `delimited_records`: detected delimiter, whether a plausible header was present, observed record count, and malformed-row count; record bodies are omitted;
- `pcie_topology_records`: port/config observed record counts, opaque status-code counts, and bounded line samples; device identifiers and raw labels are omitted (labels are represented only by stable hashes when samples are emitted).

Structured summaries preserve observed shape without inventing semantics. Every summary carries `observed_record_count`, `complete`, `truncated`, `bytes_observed`, and `time_window_applied`. `observed_record_count` is the count observed within the bytes and time window actually processed, not necessarily a file total. A summary with `complete: false` or `truncated: true` must not be treated as a complete inventory. In particular, PCIe topology status codes remain opaque until a public or user-supplied product definition establishes their meaning.

For delimited records, `header_present: false` means the first observed row was counted as data rather than silently promoted to a schema header. Hashes in topology or object samples are correlation handles only; they are not product identifiers and must not be reverse-engineered.

## Output disclosure

Every success and error envelope includes `output_policy`. The default `shareable` profile always redacts credentials and also hides local locations, IP and MAC addresses, UUIDs, authentication principals, browser identifiers, and common keyed asset identifiers such as serial, board, product, card, and part numbers. Contextual `SN(...)` serials and `unit <identifier> linked to connector` asset labels are also redacted. The policy field `common_identifier_redaction` describes this best-effort common-pattern coverage; it does not promise removal of every possible identifier. Portable paths below the validated bundle root remain visible so evidence can still be located inside another copy of the same artifact.

`--include-sensitive-context` selects the `sensitive_context` profile. Exact target, location, and ordinary identifier context is then retained, but credentials remain redacted. Treat this profile as potentially sensitive and review it before forwarding or publishing it. Automated redaction covers common forms; it is not a substitute for reviewing a report before public disclosure.

| `output_policy.profile` | `credential_redaction` | `common_identifier_redaction` | `location_redaction` |
| --- | --- | --- | --- |
| `shareable` | `true` | `true` | `true` |
| `sensitive_context` | `true` | `false` | `false` |

## JSON result

Top-level fields:

- `schema_version`
- `tool`
- `output_policy`
- `ok`
- `code`
- `error`
- `request`
- `result`

Important result fields:

- `source_kind`: `local_archive` or `extracted_directory`.
- `bundle.archive_path`: local archive path when available; the default disclosure profile returns a path placeholder instead of the exact location.
- `bundle.sha256`: archive identity when available.
- `bundle.extract_dir`: extraction directory, hidden by the default disclosure profile.
- `bundle.bundle_root`: validated root containing `dump_info/`, hidden by the default disclosure profile.
- `request.include_sensitive_context`: whether the caller explicitly selected the sensitive-context output profile.
- `validation`: layout, section presence, total and recognized-section file counts, unknown sections, and warnings.
- `analysis.selected_logs`: per-log routing and evidence details.
- `analysis.evidence`: flattened problem evidence with log, purpose, relative path, line number, line, and optional timestamp/redaction marker.
- `analysis.context_evidence`: generic failure or context lines kept separate from problem evidence; these do not by themselves raise the assessment.
- `analysis.assessment`: `evidence_found`, `evidence_found_with_gaps`, `analysis_incomplete`, or `insufficient_bundle_evidence`. Only direct or problem-context evidence can produce `evidence_found`; generic context and structure-only observations do not.
- `analysis.scan`: applied resource limits, actual path/byte counts, read errors, decode warnings, and completion state.
- `analysis.timeline`: timestamped evidence carrying `time_domain`; `sequence_scope: "global"` means timestamps are comparable and globally ordered, while `sequence_scope: "time_domain"` and `domain_sequence` indicate partitioned ordering with an explicit scan warning.
- `analysis.correlation_windows`: bounded multi-log temporal clusters that do not assert causality.
- `analysis.event_correlations`: operation-event anchors and nearby component evidence, with explicit non-causal interpretation.
- `analysis.unmatched_event_anchors`: selected operation events without nearby evidence in other selected logs.
- `analysis.correlation_scan`: bounded two-phase anchor/candidate scan coverage, byte use, retention counts, and warnings.
- `analysis.evidence_findings`: stable, deduplicated log-signal groups with portable evidence pointers.
- `analysis.structured_summaries`: bounded structure and count summaries for supported files.
- `analysis.structured_observation_count`: total observed records recognized by structured parsers within their bounded scans; structure-only observations do not by themselves establish problem evidence.
- `validation.root_files`: direct files under `dump_info/`, summarized by relative path and size without reading their contents.
- `validation.sections.<name>.subdirectories`: bounded immediate-child inventory with recursive file counts; `subdirectory_count` and `subdirectories_truncated` describe completeness.

When a selected-log definition is backed by a public source, `source_revision` is preserved in that selected-log record and propagated to its flattened evidence, context evidence, timeline entries, temporal and operation-event pointers, finding pointers, and structured summaries where those objects are present.

The complete machine-readable version 1.0 contract is [analysis-output.schema.json](analysis-output.schema.json). Removing, renaming, retyping, or changing the meaning of a machine-consumed field requires a schema-version change. Adding a top-level field also requires a schema-version change because the top-level object is closed. Nested optional extensions are compatible only where that object's schema explicitly permits additional properties. The Skill package version in `skill.json` tracks the packaged implementation and documentation independently.

The script extracts candidate evidence; it does not manufacture a root-cause verdict. The Agent must state supporting, contradictory, and missing evidence when turning the result into a hypothesis.
