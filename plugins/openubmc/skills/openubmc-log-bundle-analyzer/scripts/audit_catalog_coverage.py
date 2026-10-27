#!/usr/bin/env python3
"""Audit file-level catalog coverage for an openUBMC one-click log bundle."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import json
import pathlib
import tarfile
import tempfile
from collections import Counter, defaultdict

from log_bundle_analysis import (
    MAX_PATH_DISCOVERY_ENTRIES,
    PathDiscoveryBudget,
    _PathDirectoryIndex,
    _expand_log_paths_bounded,
    load_reference_data,
    normalize_reference_data,
)
from log_bundle_artifact import (
    MAX_DIRECTORY_BYTES,
    MAX_DIRECTORY_DEPTH,
    MAX_DIRECTORY_ENTRIES,
    _bounded_directory_walk,
    extract_archive,
    locate_bundle_root,
    sha256_file,
    validate_bundle_structure,
)
from log_bundle_common import BundleAnalysisError


COVERAGE_CLASSES = ("semantic", "explicit_opaque", "generic_fallback")
COVERAGE_PRECEDENCE = {
    "generic_fallback": 0,
    "explicit_opaque": 1,
    "semantic": 2,
}
SEMANTIC_LEVELS = ("path_only", "purpose", "structure", "diagnostic")
ARTIFACT_FORMATS = ("text", "csv", "json", "sqlite", "binary", "archive", "image", "video", "mixed", "unknown")
ROUTE_MODES = ("automatic", "explicit_only", "never")
SENSITIVITY_LEVELS = ("ordinary", "identifier_sensitive", "configuration_sensitive", "highly_sensitive")
SCAN_MODES = ("text", "metadata_only")
MAX_SAMPLE_LIMIT = 100


def _bundle_file_paths(bundle_root: pathlib.Path) -> tuple[list[str], dict[str, object]]:
    validation = validate_bundle_structure(bundle_root)
    root = pathlib.Path(bundle_root).resolve(strict=True)
    dump_info = root / "dump_info"
    paths: list[str] = []
    for path, _, is_symlink, _, is_file, _ in _bounded_directory_walk(
        dump_info,
        max_entries=MAX_DIRECTORY_ENTRIES,
        max_depth=MAX_DIRECTORY_DEPTH,
        max_bytes=MAX_DIRECTORY_BYTES,
    ):
        if is_symlink:
            raise BundleAnalysisError(
                "bundle_layout_invalid",
                f"Bundle contains symbolic links; first entry: {path}",
            )
        if is_file:
            paths.append(path.relative_to(root).as_posix())
    paths.sort()
    return paths, validation


def _section_for_path(relative_path: str) -> str:
    parts = pathlib.PurePosixPath(relative_path).parts
    if len(parts) >= 3 and parts[0] == "dump_info":
        return parts[1]
    return "dump_info"


def audit_catalog_coverage(
    bundle_root: pathlib.Path,
    *,
    reference_data: dict[str, object] | None = None,
    sample_limit: int = 20,
) -> dict[str, object]:
    """Return deterministic handling, semantic-depth, and provenance coverage."""

    if not 1 <= sample_limit <= MAX_SAMPLE_LIMIT:
        raise BundleAnalysisError(
            "invalid_request",
            f"sample_limit must be between 1 and {MAX_SAMPLE_LIMIT}.",
        )
    root = pathlib.Path(bundle_root).resolve(strict=True)
    bundle_files, validation = _bundle_file_paths(root)
    bundle_file_set = set(bundle_files)
    reference = normalize_reference_data(
        reference_data if reference_data is not None else load_reference_data(),
        source="catalog coverage reference",
    )

    discovery_budget = PathDiscoveryBudget(max_entries=MAX_PATH_DISCOVERY_ENTRIES)
    directory_index = _PathDirectoryIndex(root, discovery_budget)
    path_matches: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in reference["files"]:
        paths = [str(path) for path in item.get("paths", [])]
        if paths and all(path.endswith("/") for path in paths):
            continue
        diagnostics: dict[str, object] = {}
        matched_paths, truncated = _expand_log_paths_bounded(
            root,
            paths,
            diagnostics=diagnostics,
            discovery_budget=discovery_budget,
            directory_index=directory_index,
            include_rotations=bool(item.get("include_rotations", True)),
        )
        if truncated or diagnostics.get("truncated"):
            reasons = diagnostics.get("limit_reasons", [])
            raise BundleAnalysisError(
                "coverage_incomplete",
                "Catalog coverage path discovery reached a bounded limit: "
                + ", ".join(str(reason) for reason in reasons),
            )
        for path in matched_paths:
            relative_path = path.relative_to(root).as_posix()
            if relative_path in bundle_file_set:
                path_matches[relative_path].append(item)

    coverage_counts = Counter({coverage_class: 0 for coverage_class in COVERAGE_CLASSES})
    semantic_level_counts = Counter({level: 0 for level in SEMANTIC_LEVELS})
    artifact_format_counts = Counter({format_name: 0 for format_name in ARTIFACT_FORMATS})
    route_mode_counts = Counter({mode: 0 for mode in ROUTE_MODES})
    sensitivity_counts = Counter({level: 0 for level in SENSITIVITY_LEVELS})
    scan_mode_counts = Counter({mode: 0 for mode in SCAN_MODES})
    provenance_counts: Counter[str] = Counter()
    definition_status_counts: Counter[str] = Counter()
    definition_path_counts: Counter[str] = Counter()
    generic_by_section: Counter[str] = Counter()
    section_counts: dict[str, Counter[str]] = defaultdict(Counter)
    generic_samples: list[str] = []
    uncovered_paths: list[str] = []
    ambiguous_paths: list[dict[str, object]] = []
    conflicting_class_paths: list[dict[str, object]] = []
    conflicting_class_count = 0
    overlap_path_count = 0

    for relative_path in bundle_files:
        section = _section_for_path(relative_path)
        section_counts[section]["total"] += 1
        matches = path_matches.get(relative_path, [])
        if not matches:
            uncovered_paths.append(relative_path)
            section_counts[section]["uncovered"] += 1
            continue
        if len(matches) > 1:
            overlap_path_count += 1
        specific_classes = sorted(
            {
                str(item["coverage_class"])
                for item in matches
                if str(item["coverage_class"]) != "generic_fallback"
            }
        )
        if len(specific_classes) > 1:
            conflicting_class_count += 1
            if len(conflicting_class_paths) < sample_limit:
                conflicting_class_paths.append(
                    {
                        "path": relative_path,
                        "coverage_classes": specific_classes,
                        "definitions": [
                            str(item["name"])
                            for item in matches
                            if str(item["coverage_class"]) in specific_classes
                        ],
                    }
                )
        top_precedence = max(
            COVERAGE_PRECEDENCE[str(item["coverage_class"])] for item in matches
        )
        top_matches = [
            item
            for item in matches
            if COVERAGE_PRECEDENCE[str(item["coverage_class"])] == top_precedence
        ]
        selected = top_matches[0]
        coverage_class = str(selected["coverage_class"])
        coverage_counts[coverage_class] += 1
        section_counts[section][coverage_class] += 1
        semantic_level_counts[str(selected["semantic_level"])] += 1
        artifact_format_counts[str(selected["artifact_format"])] += 1
        route_mode_counts[str(selected["route_mode"])] += 1
        sensitivity_counts[str(selected["sensitivity"])] += 1
        scan_mode_counts[str(selected["scan_mode"])] += 1
        provenance_counts[str(selected["source_type"])] += 1
        definition_status_counts[str(selected["definition_status"])] += 1
        definition_path_counts[str(selected["name"])] += 1
        if coverage_class == "generic_fallback":
            generic_by_section[section] += 1
            if len(generic_samples) < sample_limit:
                generic_samples.append(relative_path)
        if len(top_matches) > 1 and len(ambiguous_paths) < sample_limit:
            ambiguous_paths.append(
                {
                    "path": relative_path,
                    "coverage_class": coverage_class,
                    "definitions": [str(item["name"]) for item in top_matches],
                }
            )

    total = len(bundle_files)
    uncovered_count = len(uncovered_paths)
    ambiguous_count = sum(
        1
        for relative_path in bundle_files
        if path_matches.get(relative_path)
        and len(
            [
                item
                for item in path_matches[relative_path]
                if COVERAGE_PRECEDENCE[str(item["coverage_class"])]
                == max(
                    COVERAGE_PRECEDENCE[str(candidate["coverage_class"])]
                    for candidate in path_matches[relative_path]
                )
            ]
        )
        > 1
    )
    specific_count = coverage_counts["semantic"] + coverage_counts["explicit_opaque"]
    purpose_count = sum(
        semantic_level_counts[level]
        for level in ("purpose", "structure", "diagnostic")
    )
    structure_count = sum(
        semantic_level_counts[level]
        for level in ("structure", "diagnostic")
    )
    diagnostic_count = semantic_level_counts["diagnostic"]

    def percentage(value: int) -> float:
        return round((value * 100.0 / total), 2) if total else 100.0

    return {
        "catalog_version": reference.get("version", ""),
        "complete": True,
        "catalog_covers_all_paths": uncovered_count == 0,
        "has_ambiguous_top_definitions": ambiguous_count > 0,
        "has_conflicting_coverage_classes": conflicting_class_count > 0,
        "total_file_count": total,
        "coverage_counts": dict(coverage_counts),
        "semantic_level_counts": dict(semantic_level_counts),
        "artifact_format_counts": dict(artifact_format_counts),
        "route_mode_counts": dict(route_mode_counts),
        "sensitivity_counts": dict(sensitivity_counts),
        "scan_mode_counts": dict(scan_mode_counts),
        "semantic_coverage_percent": percentage(coverage_counts["semantic"]),
        "specific_definition_coverage_percent": percentage(specific_count),
        "purpose_definition_coverage_percent": percentage(purpose_count),
        "structure_definition_coverage_percent": percentage(structure_count),
        "diagnostic_definition_coverage_percent": percentage(diagnostic_count),
        "processing_coverage_percent": percentage(total - uncovered_count),
        "uncovered_path_count": uncovered_count,
        "ambiguous_path_count": ambiguous_count,
        "conflicting_coverage_class_count": conflicting_class_count,
        "overlap_path_count": overlap_path_count,
        "path_discovery_entries_examined": discovery_budget.entries_examined,
        "provenance_counts": dict(sorted(provenance_counts.items())),
        "definition_status_counts": dict(sorted(definition_status_counts.items())),
        "generic_fallback_by_section": dict(sorted(generic_by_section.items())),
        "section_counts": {
            section: {
                key: counts.get(key, 0)
                for key in ("total", *COVERAGE_CLASSES, "uncovered")
            }
            for section, counts in sorted(section_counts.items())
        },
        "definition_path_counts": dict(
            sorted(definition_path_counts.items(), key=lambda item: (-item[1], item[0]))
        ),
        "generic_fallback_samples": generic_samples,
        "uncovered_path_samples": uncovered_paths[:sample_limit],
        "ambiguous_path_samples": ambiguous_paths,
        "conflicting_coverage_class_samples": conflicting_class_paths,
        "validation_summary": {
            "present_sections": validation["present_sections"],
            "unknown_sections": validation["unknown_sections"],
            "total_file_count": validation["total_file_count"],
        },
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit file handling, semantic depth, provenance, routing, and sensitivity coverage."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle", help="Local .tar or .tar.gz one-click log bundle.")
    source.add_argument("--bundle-dir", help="Extracted bundle directory or dump_info directory.")
    parser.add_argument("--sample-limit", type=int, default=20)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def _resolve_extracted_bundle(input_dir: pathlib.Path) -> pathlib.Path:
    if input_dir.is_symlink():
        raise BundleAnalysisError(
            "bundle_layout_invalid",
            f"Bundle directory must not be a symbolic link: {input_dir}",
        )
    if not input_dir.is_dir():
        raise BundleAnalysisError("bundle_dir_not_found", f"Bundle directory not found: {input_dir}")
    return input_dir.parent if input_dir.name == "dump_info" else locate_bundle_root(input_dir)


def _emit_human(report: dict[str, object]) -> None:
    counts = report["coverage_counts"]
    print(f"TOTAL={report['total_file_count']}")
    print(f"SEMANTIC={counts['semantic']}")
    print(f"EXPLICIT_OPAQUE={counts['explicit_opaque']}")
    print(f"GENERIC_FALLBACK={counts['generic_fallback']}")
    print(f"UNCOVERED={report['uncovered_path_count']}")
    print(f"AMBIGUOUS={report['ambiguous_path_count']}")
    print(f"CONFLICTING_COVERAGE_CLASSES={report['conflicting_coverage_class_count']}")
    print(f"SEMANTIC_COVERAGE_PERCENT={report['semantic_coverage_percent']}")
    print(f"SPECIFIC_DEFINITION_COVERAGE_PERCENT={report['specific_definition_coverage_percent']}")
    print(f"PURPOSE_DEFINITION_COVERAGE_PERCENT={report['purpose_definition_coverage_percent']}")
    print(f"STRUCTURE_DEFINITION_COVERAGE_PERCENT={report['structure_definition_coverage_percent']}")
    print(f"DIAGNOSTIC_DEFINITION_COVERAGE_PERCENT={report['diagnostic_definition_coverage_percent']}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if not 1 <= args.sample_limit <= MAX_SAMPLE_LIMIT:
            raise BundleAnalysisError(
                "invalid_request",
                f"--sample-limit must be between 1 and {MAX_SAMPLE_LIMIT}.",
            )
        source_kind = "extracted_directory"
        archive_sha256 = ""
        if args.bundle:
            archive = pathlib.Path(args.bundle).expanduser()
            if archive.is_symlink():
                raise BundleAnalysisError(
                    "bundle_read_failed",
                    f"Bundle archive must not be a symbolic link: {archive}",
                )
            if not archive.is_file():
                raise BundleAnalysisError("bundle_not_found", f"Bundle archive not found: {archive}")
            if not tarfile.is_tarfile(archive):
                raise BundleAnalysisError("unsupported_bundle", "Bundle must be a readable tar archive.")
            source_kind = "local_archive"
            archive_sha256 = sha256_file(archive)
            with tempfile.TemporaryDirectory(prefix="openubmc-catalog-audit-") as tmp_dir:
                extraction = extract_archive(archive, pathlib.Path(tmp_dir))
                report = audit_catalog_coverage(
                    extraction.bundle_root,
                    sample_limit=args.sample_limit,
                )
            if sha256_file(archive) != archive_sha256:
                raise BundleAnalysisError(
                    "bundle_identity_changed",
                    "The bundle archive changed while it was being audited.",
                )
        else:
            bundle_root = _resolve_extracted_bundle(pathlib.Path(args.bundle_dir).expanduser())
            report = audit_catalog_coverage(bundle_root, sample_limit=args.sample_limit)

        ok = (
            bool(report["catalog_covers_all_paths"])
            and not bool(report["has_ambiguous_top_definitions"])
            and not bool(report["has_conflicting_coverage_classes"])
        )
        payload = {
            "ok": ok,
            "code": "ok" if ok else "catalog_coverage_gaps",
            "source_kind": source_kind,
            "bundle_sha256": archive_sha256,
            "coverage": report,
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else:
            _emit_human(report)
        return 0 if ok else 2
    except BundleAnalysisError as exc:
        payload = {"ok": False, "code": exc.code, "error": exc.message}
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else:
            print(f"ERROR={exc.code}: {exc.message}")
        return 1
    except (OSError, ValueError) as exc:
        payload = {"ok": False, "code": "runtime_error", "error": str(exc) or "Runtime error."}
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else:
            print(f"ERROR=runtime_error: {payload['error']}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
