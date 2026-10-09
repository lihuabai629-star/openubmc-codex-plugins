#!/usr/bin/env python3
"""Static checks for rackmount web_backend Lua Plugin and Script references."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

PLUGIN_RE = re.compile(r"orchestrator\.([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\s*\(")
SCRIPT_FILE_RE = re.compile(r"^[A-Za-z0-9_./-]+\.lua$")


class Reporter:
    def __init__(self) -> None:
        self.failures = 0
        self.warnings = 0

    def ok(self, message: str) -> None:
        print(f"[OK] {message}")

    def warn(self, message: str) -> None:
        self.warnings += 1
        print(f"[WARN] {message}")

    def fail(self, message: str) -> None:
        self.failures += 1
        print(f"[FAIL] {message}")


def find_web_backend(repo: Path) -> Path:
    candidates = [
        repo / "interface_config" / "web_backend",
        repo / "rackmount" / "interface_config" / "web_backend",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise SystemExit(f"cannot find interface_config/web_backend under {repo}")


def walk_formulas(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "Formula" and isinstance(child, str):
                yield child
            yield from walk_formulas(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_formulas(child)


def mapping_files(web_backend: Path, uri: Optional[str]) -> List[Path]:
    files = sorted((web_backend / "mapping_config").rglob("*.json"))
    if not uri:
        return files

    matched = []
    for file_path in files:
        try:
            if uri in file_path.read_text(encoding="utf-8", errors="ignore"):
                matched.append(file_path)
        except OSError:
            continue
    return matched


def exported_function_exists(module_file: Path, function_name: str) -> bool:
    text = module_file.read_text(encoding="utf-8", errors="ignore")
    patterns = [
        (rf"function\s+[A-Za-z_][A-Za-z0-9_]*\." rf"{re.escape(function_name)}\s*\("),
        (rf"[A-Za-z_][A-Za-z0-9_]*\.{re.escape(function_name)}" rf"\s*=\s*function\s*\("),
    ]
    return any(re.search(pattern, text) for pattern in patterns)


def script_formula_escapes(formula: str) -> bool:
    formula_path = Path(formula)
    return formula_path.is_absolute() or ".." in formula_path.parts


def resolve_script(web_backend: Path, formula: str) -> Tuple[Optional[Path], bool]:
    script_root = web_backend / "script"
    if script_formula_escapes(formula):
        return None, False

    if "/" in formula:
        candidate = script_root / formula
        if candidate.is_file():
            return candidate, False
        matches = list(script_root.rglob(Path(formula).name))
        if len(matches) == 1:
            return matches[0], True
        return None, False

    matches = list(script_root.rglob(formula))
    if len(matches) == 1:
        return matches[0], False
    return None, False


def run_git(repo: Path, args: List[str]) -> List[str]:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def changed_files(repo: Path) -> List[str]:
    if not (repo / ".git").exists():
        return []
    tracked = run_git(repo, ["diff", "--name-only", "HEAD"])
    untracked = run_git(repo, ["ls-files", "--others", "--exclude-standard"])
    return sorted(set(tracked + untracked))


def changed_lua_files(repo: Path, web_backend: Path, names: Iterable[str]) -> Set[Path]:
    result = set()
    for name in names:
        path = repo / name
        if path.suffix == ".lua" and path.is_file() and web_backend in path.parents:
            result.add(path)
    return result


def run_luac(paths: Iterable[Path], reporter: Reporter) -> None:
    paths = sorted(set(paths))
    if not paths:
        reporter.ok("no referenced or changed Lua files require syntax checks")
        return

    luac = shutil.which("luac")
    if not luac:
        reporter.warn("luac not found; skipped Lua syntax checks")
        return

    for path in paths:
        result = subprocess.run(
            [luac, "-p", str(path)],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            reporter.ok(f"luac -p: {path}")
        else:
            detail = result.stderr.strip() or result.stdout.strip()
            reporter.fail(f"luac -p failed: {path}: {detail}")


def check_version_change(
    repo: Path,
    web_backend: Path,
    names: Iterable[str],
    reporter: Reporter,
) -> None:
    relative_web_backend = web_backend.relative_to(repo).as_posix()
    component_root = web_backend.parents[1]
    version_file = component_root / "mds" / "service.json"
    relative_version = version_file.relative_to(repo).as_posix()
    changed = set(names)

    behavior_changed = any(
        name.startswith(f"{relative_web_backend}/") and Path(name).suffix in {".json", ".lua"} for name in changed
    )
    if not behavior_changed:
        reporter.ok("no changed web_backend JSON or Lua behavior detected")
    elif relative_version in changed:
        reporter.ok(f"component version changed: {relative_version}")
    else:
        reporter.fail("web_backend behavior changed but component version is unchanged: " f"{relative_version}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="rackmount repository root")
    parser.add_argument("--uri", help="limit mapping scan to files containing this URI")
    parser.add_argument(
        "--require-version",
        action="store_true",
        help="fail when changed web_backend behavior lacks mds/service.json",
    )
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    web_backend = find_web_backend(repo)
    reporter = Reporter()
    files = mapping_files(web_backend, args.uri)

    if args.uri and not files:
        reporter.fail(f"no mapping_config JSON contains URI: {args.uri}")
    else:
        reporter.ok(f"mapping files scanned: {len(files)}")

    plugin_refs: Dict[Tuple[str, str], Set[Path]] = {}
    script_refs: Dict[str, Set[Path]] = {}

    for file_path in files:
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            reporter.ok(f"valid JSON: {file_path}")
        except (OSError, json.JSONDecodeError) as exc:
            reporter.fail(f"invalid JSON: {file_path}: {exc}")
            continue

        for formula in walk_formulas(data):
            for module_name, function_name in PLUGIN_RE.findall(formula):
                key = (module_name, function_name)
                plugin_refs.setdefault(key, set()).add(file_path)
            if SCRIPT_FILE_RE.fullmatch(formula) and not formula.startswith("orchestrator."):
                script_refs.setdefault(formula, set()).add(file_path)

    lua_to_check: Set[Path] = set()
    plugin_root = web_backend / "plugins" / "orchestrator"

    for (module_name, function_name), callers in sorted(plugin_refs.items()):
        module_file = plugin_root / f"{module_name}.lua"
        caller = sorted(callers)[0]
        if not module_file.is_file():
            reporter.fail(f"missing plugin module {module_file} referenced by {caller}")
            continue
        lua_to_check.add(module_file)
        if exported_function_exists(module_file, function_name):
            reporter.ok(f"plugin export: orchestrator.{module_name}.{function_name}")
        else:
            reporter.fail(
                f"missing export orchestrator.{module_name}.{function_name} "
                f"in {module_file}; referenced by {caller}"
            )

    for formula, callers in sorted(script_refs.items()):
        caller = sorted(callers)[0]
        if script_formula_escapes(formula):
            reporter.fail(f"script formula {formula} escapes the script directory; referenced by {caller}")
            continue

        script_file, basename_fallback = resolve_script(web_backend, formula)
        if not script_file:
            reporter.fail(
                f"script formula {formula} referenced by {caller} was not " f"found under {web_backend / 'script'}"
            )
            continue
        lua_to_check.add(script_file)
        if basename_fallback:
            reporter.warn(f"script formula {formula} resolved by basename fallback: " f"{script_file}")
        else:
            reporter.ok(f"script formula {formula}: {script_file}")

    names = changed_files(repo)
    lua_to_check.update(changed_lua_files(repo, web_backend, names))
    run_luac(lua_to_check, reporter)

    if args.require_version:
        check_version_change(repo, web_backend, names, reporter)

    print(f"Summary: {reporter.failures} failure(s), " f"{reporter.warnings} warning(s)")
    return 1 if reporter.failures else 0


if __name__ == "__main__":
    sys.exit(main())
