#!/usr/bin/env python3
"""Infer local->remote live patch targets from the current git workspace."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


def run_git(args: list[str], cwd: Path) -> str:
    cp = subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True)
    if cp.returncode != 0:
        raise SystemExit(cp.stderr.strip() or cp.stdout.strip() or f"git {' '.join(args)} failed")
    return cp.stdout.rstrip()


def repo_root(cwd: Path) -> Path:
    return Path(run_git(["rev-parse", "--show-toplevel"], cwd)).resolve()


def changed_files(root: Path, include_untracked: bool) -> list[str]:
    files: list[str] = []
    for line in run_git(["status", "--short"], root).splitlines():
        if not line:
            continue
        status = line[:2]
        path = line[3:].strip()
        if " -> " in path:
            path = path.split(" -> ", 1)[1].strip()
        if status == "??" and not include_untracked:
            continue
        if status.strip() == "D":
            continue
        files.append(path)
    return sorted(set(files))


def infer_target(root: Path, rel: str, app: str | None) -> tuple[str | None, str]:
    p = Path(rel)
    parts = p.parts

    runtime_subpath = ""
    if len(parts) >= 3 and parts[0] == "src" and parts[1] == "lualib":
        runtime_subpath = "lualib/" + "/".join(parts[2:])
    elif len(parts) >= 2 and parts[0] in {"lualib", "service", "json_types", "class", "ipmi"}:
        runtime_subpath = rel

    if runtime_subpath:
        if not app:
            return None, (
                "runtime application mapping requires explicit --app; "
                "the repository name is not a deployment contract"
            )
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", app) or app in {".", ".."}:
            return None, "--app must be one application directory name"
        return f"/opt/bmc/apps/{app}/{runtime_subpath}", ""

    if p.suffix == ".sr":
        return "/opt/bmc/sr/" + p.name, ""
    if "vendor" in parts and "openUBMC" in parts and p.suffix in {".sr", ".csr"}:
        return "/opt/bmc/sr/" + p.name, ""
    return None, "file path does not match a supported live runtime pattern"


def infer_remote(root: Path, rel: str, app: str | None) -> str | None:
    remote, _reason = infer_target(root, rel, app)
    return remote


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cwd", default=".", type=Path)
    ap.add_argument("--app", default="", help="Override /opt/bmc/apps/<app> name")
    ap.add_argument("--include-untracked", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    root = repo_root(args.cwd.resolve())
    candidates = []
    for rel in changed_files(root, args.include_untracked):
        remote, reason = infer_target(root, rel, args.app or None)
        candidates.append({
            "local": str((root / rel).resolve()),
            "relative": rel,
            "remote": remote,
            "supported": remote is not None,
            "reason": reason,
        })

    result = {"repo_root": str(root), "repo_name": root.name, "count": len(candidates), "candidates": candidates}
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        if not candidates:
            print("No changed files found.")
        for i, item in enumerate(candidates, 1):
            remote = item["remote"] or "<cannot infer>"
            print(f"{i}. {item['relative']} -> {remote}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
