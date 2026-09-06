#!/usr/bin/env python3
"""Package one Runtime-consuming Skill with a generated canonical vendor."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile
import uuid


REPO_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_ROOT = REPO_ROOT / "openubmc-target-runtime"
CANONICAL_PACKAGE = RUNTIME_ROOT / "openubmc_target_runtime"
VENDOR_RELATIVE = Path("scripts/_vendor/openubmc_target_runtime")
PACKAGE_MARKER = ".openubmc-runtime-skill-package.json"
PACKAGE_TOOL = "openubmc-target-runtime-package"
LOADER_SOURCE = Path(__file__).resolve().with_name("runtime_loader.py")
LOADER_RELATIVE = Path("scripts/_runtime_loader.py")

import sys

sys.path.insert(0, str(RUNTIME_ROOT))
from openubmc_target_runtime.distribution import (  # noqa: E402
    iter_runtime_source_files,
    runtime_distribution_contract,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args(argv)


def _shareable_files(root: Path):
    manifest_path = root / "skill.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise SystemExit("source Skill is missing a regular skill.json")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("source Skill manifest is invalid") from exc
    declared = manifest.get("files")
    if not isinstance(declared, list) or not declared:
        raise SystemExit("skill.json files must be a non-empty array")
    seen: set[str] = set()
    for raw in declared:
        if not isinstance(raw, str) or not raw or raw in seen:
            raise SystemExit("skill.json files contains an invalid path")
        relative = Path(raw)
        if (
            relative.is_absolute()
            or relative.as_posix() != raw
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise SystemExit(f"skill.json path must stay inside the Skill: {raw}")
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise SystemExit(f"declared package file is unavailable: {raw}")
        seen.add(raw)
        yield path, relative


def _is_our_output(path: Path) -> bool:
    marker = path / PACKAGE_MARKER
    if path.is_symlink() or not marker.is_file() or marker.is_symlink():
        return False
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return payload.get("tool") == PACKAGE_TOOL


def package_skill(source: Path, output: Path, *, force: bool = False) -> list[str]:
    source = source.expanduser().resolve()
    output = output.expanduser().absolute()
    if source.is_symlink() or not source.is_dir():
        raise SystemExit(f"source Skill is unavailable: {source}")
    if output.is_symlink():
        raise SystemExit(f"output must not be a symbolic link: {output}")
    output = output.resolve()
    if output == source or source in output.parents or output in source.parents:
        raise SystemExit("output must be separate from the source tree")
    if output in {Path(output.anchor), Path.home().resolve(), REPO_ROOT.resolve()}:
        raise SystemExit(f"refusing destructive package output: {output}")
    if output.exists() and not force:
        raise SystemExit(f"output already exists: {output}")
    if output.exists() and not _is_our_output(output):
        raise SystemExit("refusing to replace output not created by this packager")

    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.package-", dir=output.parent))
    copied: list[str] = []
    backup: Path | None = None
    try:
        for path, relative in _shareable_files(source):
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
            copied.append(relative.as_posix())
        contract = runtime_distribution_contract(CANONICAL_PACKAGE)
        for path, relative in iter_runtime_source_files(CANONICAL_PACKAGE):
            destination = stage / VENDOR_RELATIVE / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
            copied.append((VENDOR_RELATIVE / relative).as_posix())
        loader_destination = stage / LOADER_RELATIVE
        loader_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(LOADER_SOURCE, loader_destination)
        copied.append(LOADER_RELATIVE.as_posix())
        manifest_path = stage / "skill.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["targetRuntime"] = contract
        manifest["files"] = sorted(set(manifest["files"]) | set(copied))
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        (stage / PACKAGE_MARKER).write_text(
            json.dumps(
                {
                    "tool": PACKAGE_TOOL,
                    "format_version": 1,
                    "source_name": source.name,
                    "target_runtime": contract,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        if output.exists():
            backup = output.parent / f".{output.name}.backup-{uuid.uuid4().hex}"
            os.replace(output, backup)
        os.replace(stage, output)
        if backup is not None:
            shutil.rmtree(backup)
    except BaseException:
        if backup is not None and backup.exists() and not output.exists():
            os.replace(backup, output)
        raise
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return copied


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    copied = package_skill(
        Path(args.source),
        Path(args.output),
        force=args.force,
    )
    print(f"packaged {len(copied)} files into {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
