#!/usr/bin/env python3
"""Create a standalone Log Analyzer package with generated Target Runtime."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile
import uuid

from _runtime_distribution import (
    iter_runtime_source_files,
    read_runtime_api_version,
    runtime_content_digest,
)


SKILL_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SKILL_ROOT.parent
CANONICAL_RUNTIME = REPO_ROOT / "openubmc-target-runtime" / "openubmc_target_runtime"
VENDOR_RELATIVE = Path("scripts/_vendor/openubmc_target_runtime")
PACKAGE_MARKER = ".openubmc-log-analyzer-package.json"
PACKAGE_TOOL = "openubmc-log-analyzer-package"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default=str(SKILL_ROOT))
    parser.add_argument("--output", required=True)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args(argv)


def _shareable_files(root: Path):
    manifest_path = root / "skill.json"
    if not manifest_path.is_file():
        raise SystemExit("source skill is missing skill.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    declared = manifest.get("files")
    if not isinstance(declared, list) or not declared:
        raise SystemExit("skill.json files must be a non-empty array")
    seen: set[str] = set()
    for raw in declared:
        if not isinstance(raw, str) or not raw.strip() or raw in seen:
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


def _runtime_contract() -> dict[str, str]:
    return {
        "apiVersion": read_runtime_api_version(CANONICAL_RUNTIME),
        "contentDigest": runtime_content_digest(CANONICAL_RUNTIME),
        "vendorPath": VENDOR_RELATIVE.as_posix(),
        "source": "generated-from-canonical",
    }


def _is_our_output(path: Path) -> bool:
    marker = path / PACKAGE_MARKER
    if path.is_symlink() or not marker.is_file() or marker.is_symlink():
        return False
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return value.get("tool") == PACKAGE_TOOL


def copy_shareable_tree(
    source: Path,
    output: Path,
    *,
    force: bool = False,
) -> list[str]:
    source = source.expanduser().absolute()
    output = output.expanduser().absolute()
    if source.is_symlink() or not source.is_dir():
        raise SystemExit(f"source skill directory is unavailable: {source}")
    source = source.resolve()
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
    stage = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.package-", dir=output.parent)
    )
    copied: list[str] = []
    backup: Path | None = None
    try:
        for path, relative in _shareable_files(source):
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
            copied.append(relative.as_posix())

        contract = _runtime_contract()
        for path, relative in iter_runtime_source_files(CANONICAL_RUNTIME):
            destination = stage / VENDOR_RELATIVE / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
            copied.append((VENDOR_RELATIVE / relative).as_posix())

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
    copied = copy_shareable_tree(
        Path(args.source),
        Path(args.output),
        force=args.force,
    )
    print(f"packaged {len(copied)} files into {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
