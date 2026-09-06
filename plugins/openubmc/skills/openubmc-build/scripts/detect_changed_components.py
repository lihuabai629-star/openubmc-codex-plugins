#!/usr/bin/env python3
"""Detect openUBMC components affected by known paths or git status.

Read-only helper. Prefer --path inputs from the current conversation. Plain
git-status scanning is only a fallback candidate list and can over-report in
dirty worktrees.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def run_git_status(path: Path) -> list[str]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(path), "status", "--short"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return []
    if proc.returncode != 0:
        return []
    return [line for line in proc.stdout.splitlines() if line.strip()]


def is_component(path: Path) -> bool:
    return (path / "mds" / "service.json").is_file() or (path / "conanfile.py").is_file()


def needs_generation(entries: list[str]) -> bool:
    contract_markers = (
        "/mds/",
        "mds/service.json",
        "mds/model.json",
        "mds/types.json",
        "mds/ipmi.json",
        "json/intf/",
        "json/path/",
        "/proto/",
    )
    return any(any(marker in entry for marker in contract_markers) for entry in entries)


def component_dirs(root: Path) -> list[Path]:
    dirs: list[Path] = []
    if is_component(root):
        dirs.append(root)
    for child in sorted(root.iterdir()):
        if child.is_dir() and not child.name.startswith(".") and is_component(child):
            dirs.append(child)
    return dirs


def component_for_path(root: Path, raw_path: str) -> Path | None:
    path = Path(raw_path)
    if not path.is_absolute():
        path = root / path
    path = path.resolve(strict=False)
    for candidate in [path, *path.parents]:
        if candidate == root.parent:
            break
        if is_component(candidate):
            return candidate
    return None


def read_paths(paths: list[str] | None, paths_from: str | None) -> list[str]:
    items = list(paths or [])
    if not paths_from:
        return items
    if paths_from == "-":
        content = sys.stdin.read()
    else:
        content = Path(paths_from).read_text()
    for line in content.splitlines():
        line = line.strip()
        if line:
            items.append(line)
    return items


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect changed openUBMC components")
    parser.add_argument("--root", default=".", help="workspace or component root")
    parser.add_argument("--path", action="append", help="known changed file/dir path; repeatable")
    parser.add_argument("--paths-from", help="file with known changed paths, or '-' for stdin")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    results = []
    known_paths = read_paths(args.path, args.paths_from)
    if known_paths:
        grouped: dict[Path, list[str]] = {}
        unknown: list[str] = []
        for item in known_paths:
            comp = component_for_path(root, item)
            if comp is None:
                unknown.append(item)
                continue
            grouped.setdefault(comp, []).append(item)
        for comp, entries in sorted(grouped.items(), key=lambda pair: pair[0].name):
            service = comp / "mds" / "service.json"
            results.append(
                {
                    "component": comp.name,
                    "path": str(comp),
                    "source": "provided_paths",
                    "has_service_json": service.is_file(),
                    "needs_generation": needs_generation(entries),
                    "changes": entries,
                }
            )
        if unknown:
            results.append(
                {
                    "component": "<unmapped>",
                    "path": str(root),
                    "source": "provided_paths",
                    "has_service_json": False,
                    "needs_generation": needs_generation(unknown),
                    "changes": unknown,
                }
            )
    else:
        for comp in component_dirs(root):
            entries = run_git_status(comp)
            if entries:
                service = comp / "mds" / "service.json"
                results.append(
                    {
                        "component": comp.name,
                        "path": str(comp),
                        "source": "git_status_candidate",
                        "has_service_json": service.is_file(),
                        "needs_generation": needs_generation(entries),
                        "changes": entries,
                    }
                )

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0

    if not results:
        print("No changed openUBMC components detected.")
        return 0

    for item in results:
        gen_hint = "yes" if item["needs_generation"] else "check"
        print(f'{item["component"]}: {item["path"]}')
        print(f'  source: {item["source"]}')
        print(f'  service.json: {"yes" if item["has_service_json"] else "no"}')
        print(f"  bmcgo gen needed: {gen_hint}")
        for change in item["changes"][:20]:
            print(f"  {change}")
        if len(item["changes"]) > 20:
            print(f'  ... {len(item["changes"]) - 20} more')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
