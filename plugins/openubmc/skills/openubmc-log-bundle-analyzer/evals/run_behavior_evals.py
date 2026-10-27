#!/usr/bin/env python3
"""Execute data-driven, artifact-backed behavioral checks for the Skill."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import io
import json
import pathlib
import sys
import tarfile
import tempfile
from typing import Any


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
FIXTURE_SOURCE_SUFFIX = ".fixture"
sys.path.insert(0, str(SCRIPTS))

import log_bundle_analysis as analysis  # type: ignore  # noqa: E402
import log_bundle_artifact as artifact  # type: ignore  # noqa: E402
import log_bundle_common as common  # type: ignore  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_json(relative_path: str) -> dict[str, Any]:
    path = SKILL_ROOT / relative_path
    document = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(document, dict), f"{relative_path} must contain a JSON object")
    return document


def materialize_analysis_fixture(relative_path: str, destination: pathlib.Path) -> pathlib.Path:
    """Restore checked-in fixture sources to their production-like filenames."""

    source = SKILL_ROOT / relative_path
    require(source.is_dir(), f"analysis fixture must be a directory: {relative_path}")
    for source_path in sorted(source.rglob("*")):
        require(not source_path.is_symlink(), f"analysis fixture must not contain symlinks: {relative_path}")
        if source_path.is_dir():
            continue
        require(source_path.is_file(), f"analysis fixture contains unsupported entry: {source_path}")
        target_relative = source_path.relative_to(source)
        if target_relative.name.endswith(FIXTURE_SOURCE_SUFFIX):
            restored_name = target_relative.name[: -len(FIXTURE_SOURCE_SUFFIX)]
            require(bool(restored_name), f"analysis fixture has an empty restored filename: {source_path}")
            target_relative = target_relative.with_name(restored_name)
        target_path = destination / target_relative
        require(not target_path.exists(), f"analysis fixture restores duplicate path: {target_relative}")
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(source_path.read_bytes())
    return destination


def values_at_path(value: object, path: str) -> list[object]:
    values: list[object] = [value]
    for token in path.split(".") if path else []:
        next_values: list[object] = []
        for current in values:
            if token == "*":
                if isinstance(current, list):
                    next_values.extend(current)
                elif isinstance(current, dict):
                    next_values.extend(current.values())
                continue
            if isinstance(current, dict) and token in current:
                next_values.append(current[token])
                continue
            if isinstance(current, list) and token.isdigit():
                index = int(token)
                if index < len(current):
                    next_values.append(current[index])
        values = next_values
    return values


def apply_check(result: dict[str, object], check: dict[str, object], *, eval_id: object) -> None:
    operation = str(check.get("op", ""))
    path = str(check.get("path", ""))
    values = values_at_path(result, path)
    prefix = f"eval {eval_id} check {operation} at {path!r}"

    if operation == "equals":
        require(len(values) == 1 and values[0] == check.get("value"), f"{prefix} failed: {values!r}")
        return
    if operation == "ends_with":
        expected = str(check.get("value", ""))
        require(
            len(values) == 1 and isinstance(values[0], str) and values[0].endswith(expected),
            f"{prefix} failed: {values!r}",
        )
        return
    if operation == "non_empty":
        require(len(values) == 1 and bool(values[0]), f"{prefix} failed: {values!r}")
        return
    if operation == "contains_text":
        expected = str(check.get("value", ""))
        rendered = json.dumps(values, ensure_ascii=False, sort_keys=True)
        require(expected in rendered, f"{prefix} did not contain expected text")
        return
    if operation == "contains_all":
        expected = set(check.get("values", []))
        require(expected.issubset(set(values)), f"{prefix} missing {sorted(expected - set(values))!r}")
        return
    if operation == "all_contains":
        expected = str(check.get("value", ""))
        require(
            bool(values) and all(isinstance(item, str) and expected in item for item in values),
            f"{prefix} failed: {values!r}",
        )
        return
    if operation == "not_contains_text":
        forbidden = str(check.get("value", ""))
        rendered = json.dumps(values, ensure_ascii=False, sort_keys=True)
        require(forbidden not in rendered, f"{prefix} exposed forbidden text")
        return
    raise AssertionError(f"eval {eval_id} uses unsupported check operation: {operation}")


def run_structure_rejection_fixture(relative_path: str) -> dict[str, object]:
    """Materialize invalid tar archives and verify extraction rejects them."""

    specification = load_json(relative_path)
    cases = specification.get("cases")
    require(isinstance(cases, list) and cases, f"{relative_path} must define non-empty cases")
    rejections: list[dict[str, object]] = []

    with tempfile.TemporaryDirectory() as tmp_dir:
        temporary_root = pathlib.Path(tmp_dir)
        for case in cases:
            require(isinstance(case, dict), f"{relative_path} cases must be objects")
            name = str(case.get("name", ""))
            kind = str(case.get("kind", ""))
            require(name != "", f"{relative_path} case is missing name")
            archive_path = temporary_root / f"{name}.tar.gz"
            extraction_parent = temporary_root / f"{name}-extract"

            with tarfile.open(archive_path, "w:gz") as archive:
                if kind == "multiple_dump_info":
                    for product in ("product-a", "product-b"):
                        payload = b"synthetic fixture\n"
                        member = tarfile.TarInfo(f"{product}/dump_info/LogDump/app.log")
                        member.size = len(payload)
                        archive.addfile(member, io.BytesIO(payload))
                elif kind == "symbolic_link":
                    member = tarfile.TarInfo("bundle/dump_info/LogDump/app.log")
                    member.type = tarfile.SYMTYPE
                    member.linkname = "../../synthetic-target.log"
                    archive.addfile(member)
                else:
                    raise AssertionError(f"{relative_path} uses unsupported structure case: {kind}")

            validator = lambda: artifact.extract_archive(archive_path, extraction_parent)

            try:
                validator()
            except common.BundleAnalysisError as exc:
                rejections.append({"case": name, "code": exc.code})
            else:
                rejections.append({"case": name, "code": "not_rejected"})

    rejected = all(item["code"] != "not_rejected" for item in rejections)
    return {
        "assessment": "artifact_rejected" if rejected else "validation_failed",
        "analysis_attempted": False,
        "rejections": rejections,
    }


def project_result(result: dict[str, object], specifications: list[dict[str, object]]) -> dict[str, object]:
    projection: dict[str, object] = {}
    for specification in specifications:
        target = str(specification.get("target", ""))
        path = str(specification.get("path", ""))
        transform = str(specification.get("transform", ""))
        values = values_at_path(result, path)
        require(target != "", f"Golden projection for {path!r} is missing target")
        require(values, f"Golden projection path did not resolve: {path}")

        if transform == "length":
            require(len(values) == 1 and hasattr(values[0], "__len__"), f"Cannot take length at {path}")
            projected: object = len(values[0])  # type: ignore[arg-type]
        elif transform == "first_where":
            require(len(values) == 1 and isinstance(values[0], list), f"Expected a list at {path}")
            criteria = specification.get("where", {})
            require(isinstance(criteria, dict), f"Invalid where clause at {path}")
            match = next(
                (
                    item
                    for item in values[0]
                    if isinstance(item, dict) and all(item.get(key) == expected for key, expected in criteria.items())
                ),
                None,
            )
            require(match is not None, f"No item at {path} matched {criteria!r}")
            fields = specification.get("fields", [])
            require(isinstance(fields, list), f"Invalid fields projection at {path}")
            projected = {str(field): match[str(field)] for field in fields if str(field) in match}
            require(len(projected) == len(fields), f"Golden projection at {path} is missing fields")
        else:
            projected = values[0] if len(values) == 1 else values
        projection[target] = projected
    return projection


def validate_eval_document(document: dict[str, Any]) -> list[dict[str, Any]]:
    require(document.get("skill_name") == "openubmc-log-bundle-analyzer", "eval skill_name mismatch")
    evals = document.get("evals")
    require(isinstance(evals, list) and evals, "evals.json must define a non-empty evals list")
    ids: set[object] = set()
    executable: list[dict[str, Any]] = []
    for item in evals:
        require(isinstance(item, dict), "each eval must be an object")
        eval_id = item.get("id")
        require(eval_id not in ids, f"duplicate eval id: {eval_id}")
        ids.add(eval_id)
        require(bool(item.get("prompt")), f"eval {eval_id} is missing prompt")
        require(bool(item.get("expectations")), f"eval {eval_id} is missing expectations")
        files = item.get("files", [])
        require(isinstance(files, list), f"eval {eval_id} files must be a list")
        for relative in files:
            require((SKILL_ROOT / str(relative)).exists(), f"eval {eval_id} file does not exist: {relative}")
        execution = item.get("execution")
        if execution is None:
            continue
        require(isinstance(execution, dict), f"eval {eval_id} execution must be an object")
        fixture = str(execution.get("fixture", ""))
        generator = str(execution.get("generator", ""))
        driver = str(execution.get("driver", "analysis"))
        # A structure-rejection generator consumes a checked-in JSON case
        # specification as its fixture; ordinary executions still use exactly
        # one of fixture or generator.
        if generator == "structure_rejection":
            require(bool(fixture), f"eval {eval_id} structure_rejection requires a fixture specification")
        else:
            require(bool(fixture) != bool(generator), f"eval {eval_id} must define exactly one fixture or generator")
        if fixture:
            require(fixture in files, f"eval {eval_id} executable fixture must also appear in files")
            require(driver in {"analysis", "structure_rejection"}, f"eval {eval_id} uses unsupported fixture driver: {driver}")
        else:
            require(driver == "analysis", f"eval {eval_id} generators do not support driver: {driver}")
            require(generator in {"damaged_gzip", "structure_rejection"}, f"eval {eval_id} uses unsupported generator: {generator}")
        if driver == "analysis":
            require(bool(execution.get("problem")), f"eval {eval_id} execution is missing problem")
        require(bool(execution.get("checks") or execution.get("golden")), f"eval {eval_id} has no executable checks")
        executable.append(item)
    return executable


def run_declared_evals(document: dict[str, Any]) -> list[str]:
    completed: list[str] = []
    for item in validate_eval_document(document):
        eval_id = item["id"]
        execution = item["execution"]
        options = execution.get("options", {})
        require(isinstance(options, dict), f"eval {eval_id} options must be an object")
        if execution.get("fixture"):
            relative_fixture = str(execution["fixture"])
            if execution.get("generator") == "structure_rejection" or execution.get("driver", "analysis") == "structure_rejection":
                result = run_structure_rejection_fixture(relative_fixture)
            else:
                with tempfile.TemporaryDirectory(prefix="openubmc-eval-fixture-") as tmp_dir:
                    fixture = materialize_analysis_fixture(relative_fixture, pathlib.Path(tmp_dir) / "bundle")
                    validation = artifact.validate_bundle_structure(fixture)
                    result = analysis.analyze_bundle(fixture, execution["problem"], **options)
                    result["bundle_validation"] = validation
        else:
            with tempfile.TemporaryDirectory() as tmp_dir:
                fixture = pathlib.Path(tmp_dir)
                log_dir = fixture / "dump_info" / "LogDump"
                log_dir.mkdir(parents=True)
                (log_dir / "security.log.1.gz").write_bytes(b"not-a-valid-gzip")
                result = analysis.analyze_bundle(fixture, execution["problem"], **options)
        for check in execution.get("checks", []):
            require(isinstance(check, dict), f"eval {eval_id} check must be an object")
            apply_check(result, check, eval_id=eval_id)
        golden = execution.get("golden")
        if golden is not None:
            require(isinstance(golden, dict), f"eval {eval_id} golden must be an object")
            specifications = golden.get("projection", [])
            require(isinstance(specifications, list) and specifications, f"eval {eval_id} golden projection is empty")
            actual = project_result(result, specifications)
            expected = load_json(str(golden["file"]))
            require(actual == expected, f"eval {eval_id} Golden output changed")
        completed.append(f"eval_{eval_id}")
    return completed


def run_route_benchmark() -> dict[str, float]:
    benchmark = load_json("evals/route_benchmark.json")
    reference = analysis.load_reference_data()
    default_max_files = int(benchmark.get("default_max_files", analysis.DEFAULT_ANALYSIS_MAX_FILES))
    precisions: list[float] = []
    recalls: list[float] = []
    top1_hits: list[float] = []
    top3_precisions: list[float] = []
    negative_cases = 0

    for case in benchmark["cases"]:
        expected = set(case.get("relevant", []))
        selected_order = [
            item["name"]
            for item in analysis.select_logs_for_problem(
                case["problem"],
                reference,
                max_files=int(case.get("max_files", default_max_files)),
            )
        ]
        selected = set(selected_order)
        forbidden = set(case.get("forbidden", []))
        require(not (selected & forbidden), f"route case selected forbidden logs: {case['problem']!r}: {selected & forbidden}")
        if case.get("expected_first"):
            require(bool(selected_order), f"route case selected no logs: {case['problem']!r}")
            require(selected_order[0] == case["expected_first"], f"route first result changed: {case['problem']!r}")

        if not expected:
            negative_cases += 1
            precisions.append(1.0 if not selected else 0.0)
            recalls.append(1.0)
            continue

        true_positive = len(selected & expected)
        precisions.append(true_positive / len(selected) if selected else 0.0)
        recalls.append(true_positive / len(expected))
        top1_hits.append(1.0 if selected_order and selected_order[0] in expected else 0.0)
        top3 = selected_order[:3]
        top3_precisions.append(len(set(top3) & expected) / len(top3) if top3 else 0.0)

    metrics = {
        "macro_precision": sum(precisions) / len(precisions),
        "macro_recall": sum(recalls) / len(recalls),
        "top1_hit_rate": sum(top1_hits) / len(top1_hits),
        "top3_precision": sum(top3_precisions) / len(top3_precisions),
        "negative_case_count": float(negative_cases),
    }
    require(metrics["macro_precision"] >= benchmark["minimum_macro_precision"], "route precision benchmark failed")
    require(metrics["macro_recall"] >= benchmark["minimum_macro_recall"], "route recall benchmark failed")
    require(metrics["top1_hit_rate"] >= benchmark["minimum_top1_hit_rate"], "route Top-1 benchmark failed")
    require(metrics["top3_precision"] >= benchmark["minimum_top3_precision"], "route Top-3 benchmark failed")
    require(negative_cases >= benchmark["minimum_negative_cases"], "route benchmark needs more negative cases")
    return metrics


def run_behavior_evals() -> dict[str, object]:
    document = load_json("evals/evals.json")
    completed = run_declared_evals(document)
    route_metrics = run_route_benchmark()
    completed.append("route_precision_recall")
    return {
        "ok": True,
        "completed": completed,
        "count": len(completed),
        "declared_eval_count": len(document["evals"]),
        "executable_eval_count": len([item for item in document["evals"] if item.get("execution")]),
        "route_macro_precision": route_metrics["macro_precision"],
        "route_macro_recall": route_metrics["macro_recall"],
        "route_top1_hit_rate": route_metrics["top1_hit_rate"],
        "route_top3_precision": route_metrics["top3_precision"],
        "route_negative_case_count": int(route_metrics["negative_case_count"]),
    }


if __name__ == "__main__":
    print(json.dumps(run_behavior_evals(), ensure_ascii=False, indent=2))
