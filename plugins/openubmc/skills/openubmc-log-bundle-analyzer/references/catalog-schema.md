# Log catalog contract

`logs.json` is the executable catalog used for file selection and handling. A definition describes five independent questions: what is known, what produced that knowledge, how the artifact may be inspected, when it may be selected, and how cautiously its contents must be handled.

## Definition fields

Every entry in `files` requires `name`, `paths`, `component`, `purpose`, and non-empty `keywords`. The loader normalizes these handling dimensions:

| Field | Values | Meaning |
| --- | --- | --- |
| `semantic_level` | `path_only`, `purpose`, `structure`, `diagnostic` | Depth of stable knowledge about the artifact. |
| `artifact_format` | `text`, `csv`, `json`, `sqlite`, `binary`, `archive`, `image`, `video`, `mixed`, `unknown` | Format relevant to safe inspection. |
| `scan_mode` | `text`, `metadata_only` | Whether bounded text inspection is permitted. |
| `route_mode` | `automatic`, `explicit_only`, `never` | Whether an incident description may select the definition. |
| `sensitivity` | `ordinary`, `identifier_sensitive`, `configuration_sensitive`, `highly_sensitive` | Disclosure and inspection risk. |

`coverage_class` remains a compatibility and audit field:

- `semantic`: a specific definition whose content may be inspected or whose presence may be used as evidence;
- `explicit_opaque`: a specific definition with metadata-only handling;
- `generic_fallback`: a section-level handling contract with no file-specific purpose.

Do not use `coverage_class` as a substitute for the five handling dimensions.

## Semantic levels

- `path_only`: the path or file family is known, but its cross-product purpose is not. Report only bundle-local observations.
- `purpose`: a reliable source identifies what the artifact is for.
- `structure`: stable record boundaries or fields are known.
- `diagnostic`: stable states, error meanings, or diagnostic rules are known.

Knowing a purpose does not authorize reading the payload. Configuration, database, binary, archive, image, and video artifacts commonly use `semantic_level: purpose` with `scan_mode: metadata_only`.

## Provenance

The provenance fields are `definition_status`, `source_type`, `source_reference`, optional `source_revision`, and `reliability`.

Public definitions require a specific HTTPS source and a fixed revision. A repository homepage, search result, file name, or single bundle observation is not enough to establish product-wide semantics. `diagnostic` definitions require an independently verifiable public source.

Bundle observations may establish `path_only`. Repository-maintained heuristics may establish a conservative purpose when the boundary is explicit, but they must not be presented as a product protocol.

## Invariants

- `path_only` definitions use `explicit_only` or `never`, not `automatic`.
- `sqlite`, `binary`, `archive`, `image`, and `video` use `metadata_only`.
- `configuration_sensitive` and `highly_sensitive` artifacts use `metadata_only`.
- `metadata_only` cannot be combined with a structured parser.
- `generic_fallback` uses `metadata_only` and never supplies cross-product semantics.
- User-named `explicit_only` artifacts may be selected, but their scan boundary remains unchanged.
- Nested archives, databases, core files, firmware payloads, screenshots, and recordings are not recursively decoded by the catalog.

## Compatibility defaults

Legacy entries remain readable. The loader derives missing dimensions conservatively from `coverage_class`, provenance, parser presence, paths, and `scan_mode`. New or materially revised entries should write the dimensions explicitly so review does not depend on inferred defaults.

## Coverage audit

Run:

```bash
python3 scripts/audit_catalog_coverage.py --bundle /path/to/bundle.tar.gz --json
```

The audit reports handling coverage, semantic-depth coverage, formats, route modes, sensitivity levels, provenance, ambiguity, and conflicting handling contracts. Completion requires every physical path to have a safe handling contract and no unresolved ambiguity. Purpose, structure, and diagnostic percentages remain separate because processing coverage alone does not prove semantic knowledge.
