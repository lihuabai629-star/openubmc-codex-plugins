#!/usr/bin/env python3
"""Run bundled document pre-scanners without executing document commands."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../../skills/openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ANALYZER_ROOT = ROOT / "resources" / "analyzers"
PROFILES = {
    "quick": ("security", "links", "typo", "spelling", "punctuation"),
    "full": (
        "security",
        "links",
        "typo",
        "spelling",
        "punctuation",
        "cli",
        "consistency",
    ),
    "release": (
        "security",
        "links",
        "typo",
        "spelling",
        "punctuation",
        "cli",
        "consistency",
    ),
}
MULTI_TARGET = {"security", "links", "cli", "consistency"}
SEMANTIC_REVIEWS = {
    "quick": (),
    "full": ("completeness", "readability", "product_consistency"),
    "release": ("completeness", "readability", "product_consistency", "command_validation"),
}


def markdown_files(targets: list[Path]) -> list[Path]:
    files: list[Path] = []
    for target in targets:
        if target.is_file() and target.suffix.lower() == ".md":
            files.append(target)
        elif target.is_dir():
            files.extend(path for path in target.rglob("*.md") if path.is_file())
    return sorted(dict.fromkeys(path.resolve() for path in files))


def run_process(command: list[str], timeout: int) -> dict[str, Any]:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        return {"status": "timeout", "error": str(error)}
    except OSError as error:
        return {"status": "error", "error": str(error)}
    if result.returncode:
        return {
            "status": "error",
            "returncode": result.returncode,
            "stderr": result.stderr.strip(),
        }
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        return {
            "status": "error",
            "error": f"invalid analyzer JSON: {error}",
            "stderr": result.stderr.strip(),
        }
    return {"status": "ok", "result": payload, "stderr": result.stderr.strip()}


def run_analyzer(
    name: str,
    files: list[Path],
    original_targets: list[Path],
    timeout: int,
) -> dict[str, Any]:
    script = ANALYZER_ROOT / name / "scripts" / "prescan.py"
    if not script.is_file():
        return {"status": "unavailable", "error": f"missing analyzer: {script}"}
    if name in MULTI_TARGET:
        command = [sys.executable, str(script), *(str(path) for path in original_targets)]
        return run_process(command, timeout)

    per_file = []
    status = "ok"
    for path in files:
        result = run_process([sys.executable, str(script), str(path)], timeout)
        per_file.append({"file": str(path), **result})
        if result["status"] != "ok":
            status = "partial"
    return {"status": status, "files": per_file}


def count_findings(value: Any, key: str) -> int:
    if isinstance(value, dict):
        total = len(value.get(key, [])) if isinstance(value.get(key), list) else 0
        return total + sum(count_findings(item, key) for item in value.values())
    if isinstance(value, list):
        return sum(count_findings(item, key) for item in value)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--profile", choices=tuple(PROFILES), default="quick")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 600:
        parser.error("--timeout must be between 1 and 600 seconds")

    targets = [path.expanduser().resolve() for path in args.paths]
    missing = [str(path) for path in targets if not path.exists()]
    files = markdown_files(targets)
    analyzers = {
        name: run_analyzer(name, files, targets, args.timeout)
        for name in PROFILES[args.profile]
    }
    degraded = [name for name, item in analyzers.items() if item["status"] != "ok"]
    document = {
        "schema": "openubmc.doc-review.static.v1",
        "profile": args.profile,
        "targets": [str(path) for path in targets],
        "scanned_files": len(files),
        "missing_targets": missing,
        "command_execution": False,
        "status": "incomplete" if missing or not files or degraded else "ok",
        "semantic_reviews": {
            name: {"status": "not_run", "reason": "Requires contextual review and applicable evidence"}
            for name in SEMANTIC_REVIEWS[args.profile]
        },
        "analyzers": analyzers,
        "summary": {
            "successful": sum(item["status"] == "ok" for item in analyzers.values()),
            "degraded": degraded,
            "confirmed_candidates": count_findings(analyzers, "violations_confirmed"),
            "pending_review": count_findings(analyzers, "violations_pending_review"),
        },
    }
    print(json.dumps(document, ensure_ascii=False, indent=2))
    return 2 if document["status"] == "incomplete" else 0


if __name__ == "__main__":
    raise SystemExit(main())
