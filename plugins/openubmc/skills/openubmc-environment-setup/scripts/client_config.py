"""Parse Codex and Claude MCP client configuration without writing files."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import json
import re
import tomllib
from typing import Literal, NamedTuple


TOML_KEY_PATTERN = r'(?:[A-Za-z0-9_-]+|"(?:\\.|[^"\\])*"|\'[^\']*\')'
TOML_DOTTED_KEY_PATTERN = rf"{TOML_KEY_PATTERN}(?:\s*\.\s*{TOML_KEY_PATTERN})*"


class ClientConfigError(RuntimeError):
    """The client configuration cannot be interpreted without ambiguity."""


class Migration(NamedTuple):
    text: str
    action: Literal["unchanged", "renamed", "removed"]


def _parse_json_document(text: str) -> dict[str, object]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        raise ClientConfigError("invalid JSON client configuration") from error
    if not isinstance(document, dict):
        raise ClientConfigError("client configuration must be an object")
    return document


def _decode_toml_basic_key(value: str) -> str | None:
    def replace_long_escape(match: re.Match[str]) -> str:
        character = chr(int(match.group(1), 16))
        return json.dumps(character, ensure_ascii=True)[1:-1]

    try:
        normalized = re.sub(r"\\U([0-9a-fA-F]{8})", replace_long_escape, value)
        return json.loads(f'"{normalized}"')
    except (ValueError, json.JSONDecodeError):
        return None


def _toml_dotted_key_path(value: str) -> tuple[str, ...] | None:
    if re.fullmatch(TOML_DOTTED_KEY_PATTERN, value.strip()) is None:
        return None
    parts: list[str] = []
    for token_match in re.finditer(TOML_KEY_PATTERN, value):
        token = token_match.group(0)
        if token.startswith('"'):
            decoded = _decode_toml_basic_key(token[1:-1])
            if decoded is None:
                return None
            parts.append(decoded)
        elif token.startswith("'"):
            parts.append(token[1:-1])
        else:
            parts.append(token)
    return tuple(parts)


def _toml_table_path(
    line: str,
) -> tuple[Literal["table", "array"], tuple[str, ...]] | None:
    match = re.fullmatch(
        rf"(?:\[\s*({TOML_DOTTED_KEY_PATTERN})\s*\]"
        rf"|\[\[\s*({TOML_DOTTED_KEY_PATTERN})\s*\]\])\s*(?:#.*)?",
        line.strip(),
    )
    if match is None:
        return None
    kind: Literal["table", "array"] = "table" if match.group(1) else "array"
    path = _toml_dotted_key_path(match.group(1) or match.group(2))
    return (kind, path) if path is not None else None


def _toml_multiline_string_closes(value: str, delimiter: str) -> bool:
    offset = 0
    while (index := value.find(delimiter, offset)) >= 0:
        if delimiter == "'''":
            return True
        backslashes = 0
        cursor = index - 1
        while cursor >= 0 and value[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        if backslashes % 2 == 0:
            return True
        offset = index + len(delimiter)
    return False


def _toml_multiline_string_opener(line: str) -> tuple[int, str] | None:
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(line):
        character = line[index]
        if quote is not None:
            if quote == '"' and escaped:
                escaped = False
            elif quote == '"' and character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if character == "#":
            return None
        if line.startswith('"""', index) or line.startswith("'''", index):
            return index, line[index : index + 3]
        if character in {'"', "'"}:
            quote = character
        index += 1
    return None


def _toml_structure_lines(lines: list[str]) -> list[str]:
    structural: list[str] = []
    active: str | None = None
    for line in lines:
        if active is not None:
            if _toml_multiline_string_closes(line, active):
                active = None
            structural.append("")
            continue
        opener = _toml_multiline_string_opener(line)
        if opener is None:
            structural.append(line)
            continue
        index, delimiter = opener
        structural.append(line[:index])
        if not _toml_multiline_string_closes(line[index + 3 :], delimiter):
            active = delimiter
    return structural


def _toml_assignment_paths(lines: list[str]) -> list[tuple[int, tuple[str, ...]]]:
    assignments: list[tuple[int, tuple[str, ...]]] = []
    section: tuple[str, ...] = ()
    assignment = re.compile(rf"\s*({TOML_DOTTED_KEY_PATTERN})\s*=")
    for index, line in enumerate(lines):
        header = _toml_table_path(line)
        if header is not None:
            section = header[1]
            continue
        match = assignment.match(line)
        if match is None:
            continue
        path = _toml_dotted_key_path(match.group(1))
        if path is not None:
            assignments.append((index, section + path))
    return assignments


def _toml_section_bounds(
    lines: list[str], path: tuple[str, ...]
) -> tuple[int, int] | None:
    matches = [
        (index, header[0])
        for index, line in enumerate(lines)
        if (header := _toml_table_path(line)) is not None and header[1] == path
    ]
    if len(matches) > 1:
        raise ClientConfigError(f"duplicate TOML section: {'.'.join(path)}")
    if not matches:
        return None
    start, kind = matches[0]
    if kind != "table":
        raise ClientConfigError(f"{'.'.join(path)} must be a TOML table")
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if _toml_table_path(lines[index]) is not None
        ),
        len(lines),
    )
    return start, end


def _toml_section_is_default_http_alias(
    lines: list[str],
    bounds: tuple[int, int],
    name: str,
    url: str,
) -> bool:
    if any(
        len(header[1]) > 2
        and header[1][:2] == ("mcp_servers", name)
        for line in lines
        if (header := _toml_table_path(line)) is not None
    ):
        return False
    start, end = bounds
    meaningful = [
        line
        for line in lines[start + 1 : end]
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if len(meaningful) != 1:
        return False
    match = re.fullmatch(r"\s*url\s*=\s*(['\"])(.*?)\1\s*", meaningful[0])
    return match is not None and match.group(2) == url


def _json_entry_is_default_http_alias(entry: object, url: str) -> bool:
    return (
        isinstance(entry, dict)
        and set(entry).issubset({"type", "url"})
        and entry.get("url") == url
        and entry.get("type", "http") == "http"
    )


def _toml_field(
    lines: list[str], start: int, end: int, name: str
) -> object | None:
    assignment = re.compile(rf"\s*{re.escape(name)}\s*=\s*(.*)")
    matches: list[object] = []
    index = start + 1
    while index < end:
        match = assignment.fullmatch(lines[index])
        if match is None:
            index += 1
            continue
        raw = match.group(1)
        while raw.count("[") > raw.count("]") and index + 1 < end:
            index += 1
            raw += "\n" + lines[index]
        try:
            matches.append(tomllib.loads(f"value = {raw}")["value"])
        except (KeyError, tomllib.TOMLDecodeError) as error:
            raise ClientConfigError(f"TOML {name} has an invalid value") from error
        index += 1
    if len(matches) > 1:
        raise ClientConfigError(f"TOML {name} is assigned more than once")
    return matches[0] if matches else None


def _normalize_mcp_entry(
    url: object,
    command: object,
    args: object,
    name: str,
    *,
    allow_missing_args: bool,
) -> dict[str, object]:
    if isinstance(url, str) and command is None:
        return {"type": "http", "url": url}
    if isinstance(command, str) and url is None:
        if args is None and allow_missing_args:
            args = []
        if not isinstance(args, list) or not all(
            isinstance(item, str) for item in args
        ):
            raise ClientConfigError(f"{name} MCP args must be a string array")
        return {"type": "stdio", "command": command, "args": args}
    raise ClientConfigError(
        f"{name} MCP entry must contain one string URL or one string command"
    )


def parse_toml_mcp_entry(
    text: str,
    name: str,
    *,
    allow_missing_args: bool = False,
) -> dict[str, object] | None:
    """Return one normalized TOML MCP entry without parsing unrelated values."""
    lines = text.splitlines()
    structural = _toml_structure_lines(lines)
    path = ("mcp_servers", name)
    bounds = _toml_section_bounds(structural, path)
    assignments = [
        index
        for index, assignment in _toml_assignment_paths(structural)
        if assignment[:2] == path
    ]
    if bounds is None:
        if assignments:
            raise ClientConfigError(f"{'.'.join(path)} must be a TOML table")
        return None
    start, end = bounds
    if any(index <= start or index >= end for index in assignments):
        raise ClientConfigError(f"ambiguous {name} TOML assignments")
    return _normalize_mcp_entry(
        _toml_field(lines, start, end, "url"),
        _toml_field(lines, start, end, "command"),
        _toml_field(lines, start, end, "args"),
        name,
        allow_missing_args=allow_missing_args,
    )


def toml_section_bounds(
    lines: list[str], path: tuple[str, ...]
) -> tuple[int, int] | None:
    """Locate one semantic TOML table while ignoring multiline string content."""
    return _toml_section_bounds(_toml_structure_lines(lines), path)


def parse_json_mcp_entry(
    text: str,
    name: str,
) -> dict[str, object] | None:
    """Return one JSON MCP entry without discarding client-specific fields."""
    document = _parse_json_document(text)
    servers = document.get("mcpServers", {})
    if not isinstance(servers, dict):
        raise ClientConfigError("mcpServers must be an object")
    entry = servers.get(name)
    if entry is None:
        return None
    if not isinstance(entry, dict):
        raise ClientConfigError(f"{name} MCP entry must be an object")
    return dict(entry)


def migrate_toml_alias(
    text: str,
    *,
    legacy_name: str,
    current_name: str,
    default_url: str,
    current_managed: bool,
) -> Migration:
    lines = text.splitlines()
    structural = _toml_structure_lines(lines)
    assignments = _toml_assignment_paths(structural)
    legacy_path = ("mcp_servers", legacy_name)
    current_path = ("mcp_servers", current_name)
    legacy_assignment_lines = [
        index for index, path in assignments if path[:2] == legacy_path
    ]
    current_assignment_lines = [
        index for index, path in assignments if path[:2] == current_path
    ]
    legacy_bounds = _toml_section_bounds(structural, legacy_path)
    current_bounds = _toml_section_bounds(structural, current_path)
    current_has_external_assignments = bool(current_assignment_lines) and (
        current_bounds is None
        or any(
            index <= current_bounds[0] or index >= current_bounds[1]
            for index in current_assignment_lines
        )
    )
    conflict = f"both {legacy_name} and {current_name} MCP entries exist"
    if legacy_bounds is None:
        if legacy_assignment_lines:
            if current_bounds is not None or current_has_external_assignments:
                raise ClientConfigError(conflict)
            raise ClientConfigError(f"{legacy_name} must be a TOML table")
        return Migration(text, "unchanged")
    start, end = legacy_bounds
    if any(index <= start or index >= end for index in legacy_assignment_lines):
        if current_bounds is not None or current_has_external_assignments:
            raise ClientConfigError(conflict)
        raise ClientConfigError(f"ambiguous {legacy_name} TOML assignments")
    if current_has_external_assignments:
        raise ClientConfigError(conflict)
    if current_bounds is not None:
        if not current_managed or not _toml_section_is_default_http_alias(
            structural,
            legacy_bounds,
            legacy_name,
            default_url,
        ):
            raise ClientConfigError(conflict)
        updated = "\n".join(lines[:start] + lines[end:]).rstrip() + "\n"
        return Migration(updated, "removed")
    lines[start] = f"[mcp_servers.{current_name}]"
    return Migration("\n".join(lines).rstrip() + "\n", "renamed")


def migrate_json_alias(
    text: str,
    *,
    legacy_name: str,
    current_name: str,
    default_url: str,
    current_managed: bool,
) -> Migration:
    document = _parse_json_document(text)
    servers = document.get("mcpServers")
    if not isinstance(servers, dict) or legacy_name not in servers:
        return Migration(text, "unchanged")
    if current_name in servers:
        legacy = servers[legacy_name]
        if not current_managed or not _json_entry_is_default_http_alias(
            legacy, default_url
        ):
            raise ClientConfigError(
                f"both {legacy_name} and {current_name} MCP entries exist"
            )
        servers.pop(legacy_name)
        action: Literal["renamed", "removed"] = "removed"
    else:
        servers[current_name] = servers.pop(legacy_name)
        action = "renamed"
    updated = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    return Migration(updated, action)
