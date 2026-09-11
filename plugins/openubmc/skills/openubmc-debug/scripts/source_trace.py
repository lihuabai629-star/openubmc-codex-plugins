#!/usr/bin/env python3
"""Read-only, source-bound Lua call references; never runtime execution proof."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time


_LONG_STRING = re.compile(r"(?:--)?\[(=*)\[")
_SKIP = {".git", ".codegraph", "__pycache__", "node_modules"}
_SOURCE_SUFFIXES = {".lua", ".c", ".h", ".cpp", ".hpp", ".cc", ".py"}


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("source trace time budget exhausted")
    return remaining


def _code_only(text: str, deadline: float) -> str:
    """Mask Lua comments/strings while preserving source line positions."""
    output: list[str] = []
    offset = 0
    while offset < len(text):
        if offset % 1024 == 0:
            _remaining(deadline)
        long_string = _LONG_STRING.match(text, offset)
        end = offset
        if long_string:
            close = "]" + long_string.group(1) + "]"
            found = text.find(close, long_string.end())
            if found < 0:
                raise ValueError("unterminated_long_string_or_comment")
            end = found + len(close)
        elif text.startswith("--", offset):
            found = text.find("\n", offset)
            end = len(text) if found < 0 else found
        elif text[offset] in {"'", '"'}:
            quote = text[offset]
            end = offset + 1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                elif text[end] == quote:
                    end += 1
                    break
                else:
                    end += 1
            else:
                raise ValueError("unterminated_string")
        if end > offset:
            output.append("".join("\n" if char == "\n" else " " for char in text[offset:end]))
            offset = end
        else:
            output.append(text[offset])
            offset += 1
    return "".join(output)


def _file_references(text: str, symbol: str, deadline: float) -> tuple[list[dict[str, object]], bool]:
    code = _code_only(text, deadline)
    tokens: list[tuple[str, int]] = []
    for line_number, line in enumerate(code.splitlines(), 1):
        _remaining(deadline)
        for index, match in enumerate(re.finditer(r"[A-Za-z_]\w*|[^\s]", line)):
            if index % 1024 == 0:
                _remaining(deadline)
            tokens.append((match.group(), line_number))
    references: list[dict[str, object]] = []
    blocks: list[tuple[str, str]] = []
    declared: set[int] = set()
    pending_do = 0
    calls: dict[int, str] = {}
    parentheses: list[str] = []

    def matches(name: str) -> bool:
        return name == symbol if "." in symbol or ":" in symbol else re.split(r"[.:]", name)[-1] == symbol

    for index, (token, line_number) in enumerate(tokens):
        if index % 256 == 0:
            _remaining(deadline)
        if token == "function":
            end = index + 1
            parts = []
            while end < len(tokens) and re.fullmatch(r"[A-Za-z_]\w*|[.:]", tokens[end][0]):
                parts.append(tokens[end][0])
                declared.add(end)
                end += 1
            name = "".join(parts) or "<anonymous>"
            blocks.append(("function", name))
            if matches(name):
                references.append({"kind": "declaration", "line": line_number, "symbol": name})
            continue
        if token in {"if", "for", "while", "repeat"}:
            blocks.append((token, ""))
            pending_do += int(token in {"for", "while"})
        elif token == "do":
            if pending_do:
                pending_do -= 1
            else:
                blocks.append((token, ""))
        elif token in {"end", "until"} and blocks:
            blocks.pop()
        if token == "(":
            parentheses.append(calls.get(index, ""))
        elif token == ")" and parentheses:
            parentheses.pop()
        if not re.fullmatch(r"[A-Za-z_]\w*", token) or index in declared:
            continue
        if index > 0 and tokens[index - 1][0] in {".", ":"}:
            continue
        name, end = token, index + 1
        while end + 1 < len(tokens) and tokens[end][0] in {".", ":"} and re.fullmatch(r"[A-Za-z_]\w*", tokens[end + 1][0]):
            name += tokens[end][0] + tokens[end + 1][0]
            end += 2
        is_call = end < len(tokens) and tokens[end][0] == "("
        if is_call:
            calls[end] = name
        if not matches(name):
            continue
        caller = next((name for kind, name in reversed(blocks) if kind == "function"), "<module>")
        registrar = next((item for item in reversed(parentheses) if re.search(r"(?:^|[.:])(?:register|subscribe|set_handler|add_handler|on)$", item)), "")
        if is_call:
            references.append({"kind": "call_candidate", "line": line_number, "symbol": name,
                               "caller": caller, "resolution": "static_reference"})
        elif registrar:
            references.append({"kind": "registration_candidate", "line": line_number, "symbol": name,
                               "caller": caller, "registrar": registrar, "resolution": "static_reference"})
        else:
            references.append({"kind": "value_reference", "line": line_number, "symbol": name,
                               "caller": caller, "resolution": "unresolved_dispatch"})
    dynamic_dispatch = any(token == "]" and tokens[index + 1][0] == "("
                           for index, (token, _) in enumerate(tokens[:-1]))
    return references, dynamic_dispatch


def inspect_source(source_root: str, symbol: str, *, max_files: int = 256,
                   max_file_bytes: int = 262144, max_matches: int = 80,
                   timeout: float = 5.0) -> dict[str, object]:
    if not re.fullmatch(r"[A-Za-z_]\w*(?:[.:][A-Za-z_]\w*)*", symbol) or len(symbol) > 200:
        raise ValueError("symbol must be a Lua identifier or qualified name")
    if not 1 <= max_files <= 1024 or not 1 <= max_file_bytes <= 1048576 or not 1 <= max_matches <= 200 or not 0 < timeout <= 30:
        raise ValueError("source trace limits are outside the supported range")
    root = Path(source_root).resolve()
    files: list[dict[str, str]] = []
    blob_ids: dict[str, dict[int, str]] = {}
    references: list[dict[str, object]] = []
    gaps: list[dict[str, str]] = []
    deadline = time.monotonic() + timeout
    truncated = False

    def gap(code: str, path: str = "") -> None:
        if len(gaps) < 40:
            item = {"code": code}
            if path:
                item["path"] = path
            if item not in gaps:
                gaps.append(item)

    def candidates():
        count = 0
        if not root.is_dir():
            gap("source_root_missing")
            return
        for directory, names, filenames in os.walk(root, onerror=lambda _: gap("unreadable_directory")):
            if time.monotonic() >= deadline:
                gap("time_limit")
                return
            selected = []
            for name in sorted(names):
                path = Path(directory, name)
                if name in _SKIP:
                    continue
                if path.is_symlink():
                    gap("symlink_skipped", path.relative_to(root).as_posix())
                elif len(path.relative_to(root).parts) > 32:
                    gap("directory_depth_limit")
                else:
                    selected.append(name)
            names[:] = selected
            for name in sorted(filenames):
                if time.monotonic() >= deadline:
                    gap("time_limit")
                    return
                if count >= max_files:
                    gap("file_count_limit")
                    return
                count += 1
                yield Path(directory, name)

    total_bytes = 0
    for path in candidates():
        relative = path.relative_to(root).as_posix()
        try:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                gap("symlink_skipped", relative)
                continue
            if not stat.S_ISREG(metadata.st_mode) or path.suffix not in _SOURCE_SUFFIXES:
                continue
            if path.suffix != ".lua":
                gap("unsupported_source", relative)
                continue
            if metadata.st_size > max_file_bytes:
                gap("file_byte_limit", relative)
                continue
            if total_bytes + metadata.st_size > 8 * 1024 * 1024:
                gap("total_byte_limit")
                break
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    gap("nonregular_source", relative)
                    continue
                raw = stream.read(max_file_bytes + 1)
            if len(raw) > max_file_bytes:
                gap("file_byte_limit", relative)
                continue
            total_bytes += len(raw)
            digest = _digest(raw)
            files.append({"path": relative, "digest": digest})
            blob = b"blob " + str(len(raw)).encode() + b"\0" + raw
            blob_ids[relative] = {40: hashlib.sha1(blob).hexdigest(), 64: hashlib.sha256(blob).hexdigest()}
            found, dynamic_dispatch = _file_references(raw.decode("utf-8"), symbol, deadline)
            if dynamic_dispatch:
                gap("unresolved_dispatch", relative)
            for item in found:
                if len(references) >= max_matches:
                    gap("match_limit")
                    truncated = True
                    break
                references.append({**item, "path": relative, "content_digest": digest,
                                   "generated": bool(set(path.relative_to(root).parts) & {"gen", "generated", "autogen", ".generated"})})
        except TimeoutError:
            gap("time_limit")
            break
        except (OSError, UnicodeError, ValueError):
            gap("unreadable_or_unsupported_source", relative)
    if sum(item["kind"] == "declaration" for item in references) > 1:
        gap("ambiguous_declarations")
    if any(item.get("resolution") == "unresolved_dispatch" for item in references):
        gap("unresolved_dispatch")
    revision = None
    dirty = None
    try:
        commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=_remaining(deadline), check=False)
        if commit.returncode == 0:
            revision = commit.stdout.strip()
            # Compare inspected bytes with raw committed blobs. Git worktree
            # comparison can execute repository-configured clean filters.
            if files:
                tree = subprocess.run(["git", "--literal-pathspecs", "-C", str(root), "ls-tree", "-r", "-z",
                                       revision, "--", *blob_ids], capture_output=True, timeout=_remaining(deadline), check=False)
                if tree.returncode == 0:
                    committed = {}
                    for entry in tree.stdout.split(b"\0"):
                        if not entry:
                            continue
                        identity, path = entry.split(b"\t", 1)
                        committed[os.fsdecode(path)] = identity.split()[2].decode("ascii")
                    dirty = any(path not in committed or blob_ids[path].get(len(committed[path])) != committed[path]
                                for path in blob_ids)
                else:
                    gap("revision_unavailable")
    except (TimeoutError, subprocess.TimeoutExpired):
        gap("time_limit")
    except OSError:
        gap("revision_unavailable")
    incomplete = any(item["code"] != "ambiguous_declarations" for item in gaps)
    return {
        "schema": "openubmc.source-trace.v1",
        "status": "incomplete" if incomplete else ("references_available" if references else "no_references_observed"),
        "symbol": symbol,
        "source": {"root": str(root), "snapshot_digest": _digest(json.dumps(files, sort_keys=True).encode()),
                   "files": files, "revision": revision, "dirty": dirty,
                   "dirty_scope": "inspected_lua_files"},
        "references": references,
        "proves_runtime_execution": False,
        "gaps": gaps,
        "truncated": truncated or any("limit" in item["code"] for item in gaps),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--symbol", required=True)
    parser.add_argument("--max-files", type=int, default=256)
    parser.add_argument("--max-file-bytes", type=int, default=262144)
    parser.add_argument("--max-matches", type=int, default=80)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)
    try:
        result = inspect_source(args.source_root, args.symbol, max_files=args.max_files,
                                max_file_bytes=args.max_file_bytes, max_matches=args.max_matches,
                                timeout=args.timeout)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
