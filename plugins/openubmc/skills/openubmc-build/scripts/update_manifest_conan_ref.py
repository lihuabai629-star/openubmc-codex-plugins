#!/usr/bin/env python3
"""Locate or update component Conan refs under an openUBMC manifest."""

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
import os
import re
import sys
from pathlib import Path
import tempfile


def read_text_preserve_newlines(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def write_text_preserve_newlines(path: Path, text: str) -> None:
    mode = path.stat().st_mode & 0o777
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
        text=False,
    )
    temporary = Path(raw_temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(text.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def iter_manifest_files(manifest_root: Path, stage: str | None) -> list[Path]:
    root = manifest_root / "build" / "subsys"
    if not root.is_dir():
        raise ValueError(f"subsys directory not found: {root}")
    files = []
    for path in sorted(root.rglob("*")):
        if path.suffix not in (".yml", ".yaml"):
            continue
        files.append(path)
    if not stage:
        return files

    staged = [path for path in files if stage in path.relative_to(root).parts]
    if staged:
        return staged
    if stage == "dev":
        return [path for path in files if len(path.relative_to(root).parts) == 1]
    return staged


def conan_ref_pattern(component: str) -> re.Pattern[str]:
    escaped = re.escape(component)
    return re.compile(rf'(?P<quote>["\']?)(?P<ref>{escaped}/[^"\'\s,\]\}}]+)(?P=quote)')


def find_refs(files: list[Path], component: str) -> list[tuple[Path, int, str]]:
    pattern = conan_ref_pattern(component)
    matches: list[tuple[Path, int, str]] = []
    for path in files:
        for index, line in enumerate(read_text_preserve_newlines(path).splitlines(), start=1):
            for match in pattern.finditer(line):
                matches.append((path, index, match.group("ref")))
    return matches


def replace_refs(matches: list[tuple[Path, int, str]], component: str, new_ref: str) -> dict[Path, int]:
    pattern = conan_ref_pattern(component)
    changed: dict[Path, int] = {}
    for path in sorted({item[0] for item in matches}):
        text = read_text_preserve_newlines(path)
        updated, count = pattern.subn(lambda m: f"{m.group('quote')}{new_ref}{m.group('quote')}", text)
        if count:
            write_text_preserve_newlines(path, updated)
            changed[path] = count
    return changed


def exact_target(
    manifest_root: Path,
    exact_file: Path,
    component: str,
    expected_old_ref: str,
    new_ref: str,
    write: bool,
) -> dict[str, object]:
    root = manifest_root.resolve(strict=True)
    path = exact_file.resolve(strict=True)
    subsys_root = (root / "build" / "subsys").resolve(strict=True)
    try:
        path.relative_to(subsys_root)
    except ValueError as exc:
        raise ValueError(f"exact file must be below {subsys_root}: {path}") from exc
    matches = find_refs([path], component)
    if not matches:
        raise ValueError(f"no existing refs for {component} in {path}")
    current_refs = sorted({old_ref for _path, _line, old_ref in matches})
    if current_refs == [new_ref]:
        return {
            "path": str(path),
            "component": component,
            "expected_old_ref": expected_old_ref,
            "new_ref": new_ref,
            "changed": False,
            "written": False,
            "match_count": len(matches),
        }
    unexpected = [ref for ref in current_refs if ref != expected_old_ref]
    if unexpected:
        raise RuntimeError(
            "[manifest_ref_conflict] "
            f"{path}: expected {expected_old_ref} or target {new_ref}; "
            f"found {', '.join(unexpected)}"
        )
    changed = False
    if write:
        replaced = replace_refs(matches, component, new_ref)
        changed = bool(replaced)
    return {
        "path": str(path),
        "component": component,
        "expected_old_ref": expected_old_ref,
        "new_ref": new_ref,
        "changed": True,
        "written": changed,
        "match_count": len(matches),
    }


def product_contains_component(product_manifest: Path, component: str) -> bool:
    if not product_manifest.is_file():
        raise ValueError(f"product manifest not found: {product_manifest}")
    return component in read_text_preserve_newlines(product_manifest)


def main() -> int:
    parser = argparse.ArgumentParser(description="Dry-run or update openUBMC manifest Conan refs")
    parser.add_argument("--manifest-root", required=True, help="manifest workspace root")
    parser.add_argument("--component", required=True, help="component/package name, e.g. general_hardware")
    parser.add_argument("--new-ref", required=True, help="new Conan ref, e.g. component/1.2.3@openubmc/stable")
    parser.add_argument("--expected-old-ref", help="required compare-and-set source ref when writing")
    parser.add_argument("--exact-file", help="single build/subsys file allowed to change")
    parser.add_argument("--stage", help="limit search to build/subsys/<stage>/... path component")
    parser.add_argument("--product-manifest", help="optional product manifest.yml to check dependency presence")
    parser.add_argument("--write", action="store_true", help="write replacements; default is dry-run")
    args = parser.parse_args()

    if not args.new_ref.startswith(f"{args.component}/"):
        print(f"error: --new-ref must start with {args.component}/", file=sys.stderr)
        return 1

    try:
        if args.write and (not args.expected_old_ref or not args.exact_file):
            parser.error("--write requires --expected-old-ref and --exact-file")
        if args.exact_file:
            if not args.expected_old_ref:
                parser.error("--exact-file requires --expected-old-ref")
            result = exact_target(
                Path(args.manifest_root),
                Path(args.exact_file),
                args.component,
                args.expected_old_ref,
                args.new_ref,
                args.write,
            )
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return 0

        files = iter_manifest_files(Path(args.manifest_root), args.stage)
        matches = find_refs(files, args.component)
        if not matches:
            print(f"no existing refs for {args.component} under build/subsys")
            print("if this is a new component, add the correct product/subsystem dependency explicitly")
            return 2

        result: dict[str, object] = {
            "component": args.component,
            "new_ref": args.new_ref,
            "changed": False,
            "written": False,
            "matches": [
                {"path": str(path), "line": line, "current_ref": old_ref}
                for path, line, old_ref in matches
            ],
        }

        if args.product_manifest:
            present = product_contains_component(Path(args.product_manifest), args.component)
            result["product_manifest_contains_component"] = present
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    except Exception as exc:  # noqa: BLE001 - command-line helper should print concise errors.
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
