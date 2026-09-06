#!/usr/bin/env python3
"""Apply an explicit openUBMC version with compare-and-set semantics."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile


class VersionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def read_text(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def component_version(text: str, path: Path) -> str:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise VersionError("invalid_component_json", f"{path}: {exc}") from exc
    value = document.get("version")
    if not isinstance(value, str) or not value:
        raise VersionError(
            "missing_component_version",
            f"{path}: top-level version is missing or not a string",
        )
    return value


def json_string_end(text: str, start: int, path: Path) -> int:
    escaped = False
    for index in range(start + 1, len(text)):
        character = text[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"':
            return index + 1
    raise VersionError(
        "invalid_component_json",
        f"{path}: unterminated JSON string",
    )


def top_level_string_field(
    text: str,
    field: str,
    path: Path,
) -> tuple[int, int, str]:
    depth = 0
    matches: list[tuple[int, int, str]] = []
    index = 0
    while index < len(text):
        character = text[index]
        if character == '"':
            token_end = json_string_end(text, index, path)
            if depth == 1:
                after_key = token_end
                while after_key < len(text) and text[after_key].isspace():
                    after_key += 1
                if (
                    after_key < len(text)
                    and text[after_key] == ":"
                    and json.loads(text[index:token_end]) == field
                ):
                    value_start = after_key + 1
                    while value_start < len(text) and text[value_start].isspace():
                        value_start += 1
                    if value_start >= len(text) or text[value_start] != '"':
                        raise VersionError(
                            "missing_component_version",
                            f"{path}: top-level {field} is not a string",
                        )
                    value_end = json_string_end(text, value_start, path)
                    value = json.loads(text[value_start:value_end])
                    matches.append((value_start, value_end, value))
            index = token_end
            continue
        if character in "[{":
            depth += 1
        elif character in "]}":
            depth -= 1
        index += 1
    if len(matches) != 1:
        raise VersionError(
            "component_version_not_unique",
            f"{path}: expected exactly one top-level {field} field",
        )
    return matches[0]


def replace_component_version(text: str, current: str, target: str, path: Path) -> str:
    start, end, observed = top_level_string_field(text, "version", path)
    if observed != current:
        raise VersionError(
            "component_version_changed",
            f"{path}: top-level version changed while preparing the update",
        )
    replacement = json.dumps(target, ensure_ascii=False)
    return f"{text[:start]}{replacement}{text[end:]}"


def product_version_line(text: str, path: Path) -> tuple[int, str, list[str]]:
    lines = text.splitlines(keepends=True)
    base_indent: int | None = None
    in_base = False
    pattern = re.compile(
        r'^(\s*)version\s*:\s*(["\']?)([^"\'\s#]+)(["\']?)(.*)$'
    )
    for index, line in enumerate(lines):
        if re.match(r"^\s*base\s*:", line):
            base_indent = len(line) - len(line.lstrip(" "))
            in_base = True
            continue
        if not in_base:
            continue
        indent = len(line) - len(line.lstrip(" "))
        if line.strip() and base_indent is not None and indent <= base_indent:
            break
        match = pattern.match(line)
        if match:
            return index, match.group(3), lines
    raise VersionError("missing_product_version", f"{path}: base.version not found")


def replace_product_version(
    lines: list[str],
    index: int,
    current: str,
    target: str,
    path: Path,
) -> str:
    pattern = re.compile(
        r'^(\s*version\s*:\s*)(["\']?)([^"\'\s#]+)(["\']?)(.*)$'
    )
    match = pattern.match(lines[index])
    if not match or match.group(3) != current:
        raise VersionError(
            "product_version_changed",
            f"{path}: base.version changed while preparing the update",
        )
    quote = match.group(2) or match.group(4)
    replacement = f"{match.group(1)}{quote}{target}{quote}{match.group(5)}"
    if lines[index].endswith("\n") and not replacement.endswith("\n"):
        replacement += "\n"
    lines[index] = replacement
    return "".join(lines)


def atomic_write(path: Path, text: str) -> None:
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


def ensure_version(
    path: Path,
    *,
    kind: str,
    expected_current: str,
    target: str,
    write: bool,
) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    text = read_text(resolved)
    if kind == "component":
        current = component_version(text, resolved)
        updated = replace_component_version(text, current, target, resolved)
    else:
        index, current, lines = product_version_line(text, resolved)
        updated = replace_product_version(lines, index, current, target, resolved)

    if current == target:
        return {
            "path": str(resolved),
            "kind": kind,
            "current": current,
            "target": target,
            "changed": False,
            "written": False,
        }
    if current != expected_current:
        raise VersionError(
            "version_conflict",
            f"{resolved}: expected {expected_current} or target {target}, found {current}",
        )
    if write:
        atomic_write(resolved, updated)
    return {
        "path": str(resolved),
        "kind": kind,
        "current": current,
        "target": target,
        "changed": True,
        "written": write,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("component", "product"), required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--expected-current", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    if not args.expected_current or not args.target:
        parser.error("versions must not be empty")
    try:
        result = ensure_version(
            Path(args.path),
            kind=args.kind,
            expected_current=args.expected_current,
            target=args.target,
            write=args.write,
        )
    except VersionError as exc:
        print(f"error: [{exc.code}] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
