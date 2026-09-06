#!/usr/bin/env python3
"""Create a shareable openubmc-debug skill tree after safety checks."""
from __future__ import annotations

import argparse
import ast
from collections.abc import Mapping
import hashlib
import ipaddress
import json
import os
import re
import shutil
import tempfile
import uuid
from pathlib import Path
from urllib.parse import unquote, urldefrag, urlsplit

from _runtime_distribution import (
    iter_runtime_source_files,
    runtime_distribution_contract,
)

SKILL_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SKILL_ROOT.parent
CANONICAL_RUNTIME_PACKAGE = (
    REPO_ROOT / "openubmc-target-runtime" / "openubmc_target_runtime"
)
VENDORED_RUNTIME_RELATIVE = Path("scripts/_vendor/openubmc_target_runtime")
PACKAGE_MARKER = ".openubmc-debug-package.json"
PACKAGE_TOOL = "openubmc-debug-package"
PACKAGE_FORMAT_VERSION = 1
FORBIDDEN_LITERAL_SHA256 = {
    10: frozenset(
        {
            "aefce6ee3a2102634380dd85acb5d48c33ae6e286f883aa5c707b7835f368ae1",
        }
    ),
}
PASSWORD_ASSIGNMENT_RE = re.compile(r"^(?:export\s+)?OPENUBMC_[A-Z0-9_]*PASSWORD\s*=\s*(.+)$")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)^\s*(?:export\s+)?[A-Z_][A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY)[A-Z0-9_]*\s*=\s*(.+)$"
)
SCALAR_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?i)^\s*(?:[-*+]\s+)?(?:export\s+)?"
    r"(?P<quote>[\"'`]?)"
    r"(?P<key>[a-z_][a-z0-9_.-]*)"
    r"(?P=quote)\s*(?P<operator>[:=])\s*(?P<value>.*?)\s*$"
)
IPV4_LITERAL_RE = re.compile(
    r"(?<![\d.])"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
    r"(?![\d.])"
)
IPV4_PREFIX_LITERAL_RE = re.compile(
    r"(?<![\d.])"
    r"(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){1,2}\."
    r"(?![\d.])"
)
IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f:])[0-9A-Fa-f:]{2,}(?![0-9A-Fa-f:])"
)
RUNTIME_INSTANCE_RE = re.compile(r"\bEvent_[A-Za-z][A-Za-z0-9]*_[0-9A-Fa-f]{8}\b")
EVENT_CODE_LITERAL_RE = re.compile(r"\b0x[0-9A-Fa-f]{8}\b")
CASE_MARKER_RE = re.compile(
    r"(?im)^\s*(?:CASE_"
    + r"ONLY|SINGLE_"
    + r"CASE|INCIDENT_"
    + r"ONLY|DO_"
    + r"NOT_"
    + r"SHIP|单次"
    + r"\s*需求|单"
    + r"\s*案例|仅"
    + r"\s*本次|本次"
    + r"\s*需求)\s*[:：]"
)
HARDWARE_MODEL_RE = re.compile(r"(?im)^\s*(?:HARDWARE_" + r"MODEL|硬件" + r"型号)\s*[:：]\s*\S+")
LABELED_CASE_VALUE_RE = re.compile(
    r"(?im)^\s*(?:Event" + r"Name|Component" + r"Instance|运行时" + r"实例|告警" + r"名称)\s*[:：=]\s*(?![<$\[{])\S+"
)
INLINE_LABELED_CASE_VALUE_RE = re.compile(
    r"(?i)\b(?:EventName|ComponentInstance|AlarmName|HardwareModel)\s*[:=]\s*"
    r"(?![<$\[{])\S+|(?:运行时实例|告警名称|硬件型号)\s*[:：=]\s*(?![<$\[{])\S+"
)
INLINE_ALARM_LITERAL_RE = re.compile(
    r"\b(?:[A-Z][A-Za-z0-9]*[a-z0-9][A-Z][A-Za-z0-9]*|"
    r"[A-Z][A-Z0-9]*(?:[-_][A-Z0-9]+)+)\s+(?:alarm|event)\b|"
    r"\b(?:alarm|event)\s+(?:named\s+|called\s+)"
    r"(?:[A-Z][A-Za-z0-9]*[a-z0-9][A-Z][A-Za-z0-9]*|"
    r"[A-Z][A-Z0-9]*(?:[-_][A-Z0-9]+)+)\b"
)
INLINE_HARDWARE_MODEL_RE = re.compile(
    r"(?i)\b(?:hardware\s+|server\s+|platform\s+|chassis\s+)?model\s+"
    r"(?:is\s+|named\s+|called\s+)?[A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)+\b|"
    r"(?:硬件型号|机型)\s*(?:为|是|[:：=])?\s*"
    r"[A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)+\b"
)
INLINE_RUNTIME_INSTANCE_RE = re.compile(
    r"(?i)\b(?:fan\s+board|power\s+board|pcie\s+(?:board|slot)|"
    r"cpu\s+(?:board|slot)|component\s+(?:slot|instance)|slot|instance)\s*"
    r"(?:#|id\s*)?\d+\b|"
    r"(?:运行时实例|组件实例|槽位)\s*(?:为|是|[:：=#])?\s*\d+\b"
)
INLINE_ONE_OFF_CONDITION_RE = re.compile(
    r"(?i)\b(?:only\s+for\s+(?:this|the)\s+(?:incident|case|request)|"
    r"for\s+(?:this|the)\s+(?:incident|case|request)\s+only|"
    r"this\s+(?:incident|case|request)\s+only)\b|"
    r"(?:仅|只)(?:限|针对)?(?:本次|该次|此次)(?:事件|案例|需求|故障|问题)?"
)
CREDENTIAL_HEADER_RE = re.compile(
    r"(?i)(?:proxy-authorization|authorization|x-api-key|api-key|x-auth-token|"
    r"set-cookie|cookie)[\"']?[ \t]*[:=][ \t]*(?P<value>[^\r\n,}]*)"
)
MULTILINE_CREDENTIAL_HEADER_RE = re.compile(
    r"(?im)^\s*(?:proxy-authorization|authorization|x-api-key|api-key|x-auth-token|"
    r"set-cookie|cookie)[\"']?\s*[:=]\s*$\r?\n[ \t]+(?P<value>[^\r\n]+)"
)
SERIALIZED_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?i)(?P<quote>[\"'])(?P<key>[A-Z_][A-Z0-9_.-]*)(?P=quote)\s*:\s*"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^,}\s]+)"
)
PRIVATE_KEY_MATERIAL_RE = re.compile(
    r"(?is)(-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----)"
    r"(?P<body>.*?)"
    r"(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)"
)
COMMAND_PASSWORD_RE = re.compile(
    r"(?i)(?:\bsshpass\s+-p(?:=|\s+)?|"
    r"--(?:ssh-|telnet-|os-ssh-)?password(?:=|\s+))"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|\S+)"
)
IDENTITY_OPTION_RE = re.compile(
    r"(?i)\b(?:ssh|scp|sftp)\b[^\r\n]*?(?<!\S)-i\s+"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|\S+)"
)
URL_USERINFO_RE = re.compile(
    r"(?i)\b[A-Z][A-Z0-9+.-]*://(?P<user>[^/@\s:]+):(?P<password>[^/@\s]+)@"
)
SECRET_MATERIAL_KEY_RE = re.compile(
    r"(?i)^(?:sk|pk)_(?:live|test)_[A-Za-z0-9_-]{8,}$|"
    r"^(?:ghp_|github_pat_|xox[baprs]-)[A-Za-z0-9_-]{8,}$|"
    r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
)
SENSITIVE_JSON_KEY_SUFFIXES = (
    "pwd",
    "passphrase",
    "password",
    "passwd",
    "secret",
    "client_secret",
    "preshared_key",
    "secret_key",
    "access_key",
    "secret_access_key",
    "aws_secret_access_key",
    "token",
    "access_token",
    "refresh_token",
    "api_token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "private_key",
    "privatekey",
    "identity_file",
    "identityfile",
)
SENSITIVE_JSON_VALUE_SUFFIXES = frozenset(
    (*SENSITIVE_JSON_KEY_SUFFIXES, "credential", "credentials")
)
SAFE_SENSITIVE_CONTAINER_KEYS = frozenset(
    {
        "account",
        "change_remote_state",
        "enabled",
        "format",
        "id",
        "kind",
        "mode",
        "name",
        "provider",
        "source",
        "type",
        "user",
        "username",
    }
)
CANONICAL_CREDENTIAL_ENV_FIELD_NAMES = ("base_url", "username", "password")
EXCLUDED_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}
EXCLUDED_PREFIXES = (
    Path("PROTOTYPE_target_runtime"),
    Path("docs/plans"),
    Path("references/lessons/inbox"),
    Path("scripts/build"),
    Path("tests"),
)
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
ALLOWED_ROOT_FILES = {"SKILL.md", "skill.json"}
ALLOWED_TOP_LEVEL_DIRS = {"agents", "assets", "references", "scripts"}
ALLOWED_SUFFIXES = {
    "agents": {".json", ".yaml", ".yml"},
    "assets": {".gif", ".jpeg", ".jpg", ".json", ".md", ".png", ".svg", ".txt", ".webp", ".yaml", ".yml"},
    "references": {".json", ".md", ".txt", ".yaml", ".yml"},
    "scripts": {".py", ".sh"},
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Package a shareable openubmc-debug skill directory.")
    parser.add_argument("--source", default=str(SKILL_ROOT), help="Skill root to package")
    parser.add_argument("--output", required=True, help="Output directory")
    parser.add_argument("--force", action="store_true", help="Replace output directory if it exists")
    return parser.parse_args(argv)


def should_exclude(relative_path: Path) -> bool:
    if relative_path == Path(PACKAGE_MARKER):
        return True
    if any(part in EXCLUDED_PARTS for part in relative_path.parts):
        return True
    if relative_path.suffix in EXCLUDED_SUFFIXES:
        return True
    return any(relative_path == prefix or prefix in relative_path.parents for prefix in EXCLUDED_PREFIXES)


def validate_source_tree(root: Path) -> None:
    if root.is_symlink():
        raise SystemExit(f"source skill directory must not be a symbolic link: {root}")
    if not root.is_dir():
        raise SystemExit(f"source skill directory does not exist: {root}")
    if not (root / "SKILL.md").is_file():
        raise SystemExit(f"source is not a skill directory (missing SKILL.md): {root}")

    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if path.is_symlink():
            raise SystemExit(f"symbolic link is not allowed in a shareable skill: {relative}")
        if should_exclude(relative):
            continue
        if relative == Path(PACKAGE_MARKER):
            continue
        if any(part.startswith(".") for part in relative.parts):
            raise SystemExit(f"hidden file or directory is not allowed in a shareable skill: {relative}")
        top = relative.parts[0]
        if len(relative.parts) == 1:
            if path.is_file() and top not in ALLOWED_ROOT_FILES:
                raise SystemExit(f"root file is not allowed in a shareable skill: {relative}")
            if path.is_dir() and top not in ALLOWED_TOP_LEVEL_DIRS:
                raise SystemExit(f"top-level directory is not allowed in a shareable skill: {relative}")
            continue
        if top not in ALLOWED_TOP_LEVEL_DIRS:
            raise SystemExit(f"path is not allowed in a shareable skill: {relative}")
        if path.is_file() and path.suffix.lower() not in ALLOWED_SUFFIXES[top]:
            raise SystemExit(f"file type is not allowed in a shareable skill: {relative}")


def iter_shareable_files(root: Path):
    validate_source_tree(root)
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if should_exclude(relative):
            continue
        yield path, relative


def _manifest_file_paths(root: Path) -> list[Path] | None:
    """Return the declared cold-package files when this source has a manifest."""

    manifest_path = root / "skill.json"
    if manifest_path.is_symlink():
        raise SystemExit("skill.json must not be a symbolic link")
    if not manifest_path.exists():
        if root.name == "openubmc-debug":
            raise SystemExit("openubmc-debug source is missing skill.json")
        return None
    if not manifest_path.is_file():
        raise SystemExit("skill.json must be a regular file")
    try:
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except DuplicateJsonKeyError as exc:
        raise SystemExit("skill.json contains a duplicate JSON key") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"skill.json is unavailable or invalid: {type(exc).__name__}") from exc
    raw_files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(raw_files, list) or not raw_files:
        raise SystemExit("skill.json files must be a non-empty array")

    declared: list[Path] = []
    seen: set[str] = set()
    for index, value in enumerate(raw_files):
        if not isinstance(value, str) or not value.strip():
            raise SystemExit(f"skill.json files[{index}] must be a non-empty string")
        if value != value.strip() or "\\" in value:
            raise SystemExit(f"skill.json files[{index}] must use a normalized POSIX path")
        relative = Path(value)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise SystemExit(f"skill.json files[{index}] must stay inside the Skill root")
        normalized = relative.as_posix()
        if normalized != value:
            raise SystemExit(f"skill.json files[{index}] must use a normalized POSIX path")
        if normalized in seen:
            raise SystemExit(f"skill.json files contains a duplicate path: {normalized}")
        if relative == Path(PACKAGE_MARKER) or should_exclude(relative):
            raise SystemExit(f"skill.json files declares an excluded path: {normalized}")
        seen.add(normalized)
        declared.append(relative)
    return declared


def validate_manifest_matches_source(
    root: Path,
    shareable_files: list[tuple[Path, Path]] | None = None,
) -> None:
    """Make the manifest, source scan, and packaged bytes one consistent set."""

    declared = _manifest_file_paths(root)
    if declared is None:
        return
    shareable = shareable_files if shareable_files is not None else list(iter_shareable_files(root))
    actual = {relative.as_posix() for _path, relative in shareable}
    expected = {relative.as_posix() for relative in declared}
    missing = sorted(expected - actual)
    undeclared = sorted(actual - expected)
    if missing or undeclared:
        details: list[str] = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if undeclared:
            details.append("undeclared=" + ",".join(undeclared))
        raise SystemExit("skill.json files does not match the shareable source: " + "; ".join(details))


def iter_scannable_files(root: Path):
    if not root.is_dir():
        raise SystemExit(f"source skill directory does not exist: {root}")
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if path.is_symlink():
            raise SystemExit(f"symbolic link is not allowed in a shareable skill: {relative}")
        if not path.is_file() or should_exclude(relative):
            continue
        yield path, relative


def contains_forbidden_literal(content: str | bytes) -> bool:
    encoded = content.encode("utf-8") if isinstance(content, str) else content
    for length, forbidden_digests in FORBIDDEN_LITERAL_SHA256.items():
        if len(encoded) < length:
            continue
        for start in range(len(encoded) - length + 1):
            candidate = encoded[start : start + length]
            if hashlib.sha256(candidate).hexdigest() in forbidden_digests:
                return True
    return False


def contains_ipv6_literal(text: str) -> bool:
    for match in IPV6_CANDIDATE_RE.finditer(text):
        candidate = match.group(0)
        if ":" not in candidate:
            continue
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.version == 6:
            return True
    return False


def _normalized_name(value: object) -> str:
    raw = str(value)
    raw = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", raw)
    raw = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", raw)
    return re.sub(r"[^a-z0-9]+", "_", raw.casefold()).strip("_")


def _is_sensitive_json_key(value: object) -> bool:
    normalized = _normalized_name(value)
    if normalized.endswith("_env") or normalized.startswith(
        ("has_", "requires_", "supports_")
    ):
        return False
    return any(
        normalized == suffix or normalized.endswith(f"_{suffix}")
        for suffix in SENSITIVE_JSON_KEY_SUFFIXES
    )


def _is_sensitive_json_value_key(value: object) -> bool:
    """Classify JSON value keys without treating prose/variable metadata as secrets."""

    normalized = _normalized_name(value)
    if normalized.endswith("_env") or normalized.startswith(
        ("has_", "requires_", "supports_")
    ):
        return False
    normalized = re.sub(r"_?\d+$", "", normalized)
    if any(
        normalized == form or normalized.endswith(f"_{form}")
        for suffix in SENSITIVE_JSON_VALUE_SUFFIXES
        for form in ({suffix, f"{suffix}s"} if not suffix.endswith("s") else {suffix})
    ):
        return True
    for value_suffix in (
        "value",
        "values",
        "material",
        "data",
        "literal",
        "default",
        "defaults",
        "list",
        "lists",
        "array",
        "map",
        "text",
        "string",
        "plaintext",
        "entry",
        "entries",
        "item",
        "items",
        "pem",
        "raw",
        "blob",
    ):
        marker = f"_{value_suffix}"
        if normalized.endswith(marker):
            return _is_sensitive_json_value_key(normalized[: -len(marker)])
    return False


def _schema_identity_text_is_sensitive(value: object) -> bool:
    normalized = _normalized_name(value)
    return _is_sensitive_json_value_key(normalized) or any(
        _is_sensitive_json_value_key(part)
        for part in normalized.split("_")
        if part
    )


def _schema_property_inherits_sensitive(parent_sensitive: bool, name: object) -> bool:
    if not parent_sensitive:
        return False
    normalized = _normalized_name(name)
    return not (
        normalized in SAFE_SENSITIVE_CONTAINER_KEYS
        or normalized.startswith(("allow_", "has_", "requires_", "supports_"))
    )


def _schema_identity_is_sensitive(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    for key in (
        "title",
        "description",
        "$comment",
        "format",
        "$anchor",
        "$dynamicAnchor",
    ):
        item = value.get(key)
        if isinstance(item, str) and _schema_identity_text_is_sensitive(item):
            return True
    for key in ("$id", "id"):
        item = value.get(key)
        if not isinstance(item, str):
            continue
        parsed = urlsplit(item)
        candidates = [
            unquote(parsed.fragment),
            unquote(parsed.query),
            unquote(parsed.hostname or ""),
        ]
        basename = Path(unquote(parsed.path)).name
        while basename:
            candidates.append(basename)
            if "." not in basename:
                break
            basename = basename.rsplit(".", 1)[0]
        if any(_schema_identity_text_is_sensitive(candidate) for candidate in candidates):
            return True
    return False


def _is_placeholder_secret(value: object) -> bool:
    if value is None or value is False:
        return True
    if not isinstance(value, str):
        return False
    cooked = value.strip().strip("'\"`")
    if not cooked or cooked.casefold() in {"***", "redacted", "redaction"}:
        return True
    if re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", cooked):
        return True
    if re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", cooked):
        return True
    if re.fullmatch(r"<[A-Za-z][A-Za-z0-9_.-]*>", cooked):
        return True
    if re.fullmatch(r"\{\{\s*[A-Za-z_][A-Za-z0-9_.-]*\s*\}\}", cooked):
        return True
    parts = cooked.split(None, 1)
    if len(parts) == 2 and parts[0].casefold() in {"bearer", "basic", "digest"}:
        return _is_placeholder_secret(parts[1])
    return False


def _sensitive_value_has_unsafe_secret(value: object) -> bool:
    """Treat every leaf of a sensitive value as secret-bearing context."""

    if isinstance(value, bool):
        return False
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = _normalized_name(key)
            key_is_field_name = (
                (
                    _is_sensitive_json_value_key(key)
                    and not SECRET_MATERIAL_KEY_RE.match(str(key))
                )
                or normalized in SAFE_SENSITIVE_CONTAINER_KEYS
                or normalized.startswith(("allow_", "has_", "requires_", "supports_"))
            )
            if not key_is_field_name:
                return True
            if _sensitive_value_has_unsafe_secret(item):
                return True
        return False
    if isinstance(value, list):
        return any(_sensitive_value_has_unsafe_secret(item) for item in value)
    return not _is_placeholder_secret(value)


class DuplicateJsonKeyError(ValueError):
    pass


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(key)
        result[key] = value
    return result


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _python_value_has_unsafe_literal(node: ast.AST) -> bool:
    """Detect literals that can become the credential value.

    Lookup keys and resolver labels are metadata. Defaults, transforms, literal
    containers, and call arguments are value-bearing and therefore scanned.
    """
    if isinstance(node, ast.Constant):
        return not _is_placeholder_secret(node.value)
    if isinstance(node, (ast.Name, ast.Attribute)):
        return False
    if isinstance(node, ast.Subscript):
        # The slice is a lookup key. The base still matters so ["secret"][0]
        # cannot hide a literal value.
        return _python_value_has_unsafe_literal(node.value)
    if isinstance(node, ast.Dict):
        return any(
            value is not None and _python_value_has_unsafe_literal(value)
            for value in node.values
        )
    if isinstance(node, ast.Call):
        name = _call_name(node.func)
        short_name = name.rsplit(".", 1)[-1]
        if name == "re.compile":
            return False
        if short_name in {"get", "getenv"}:
            return any(
                _python_value_has_unsafe_literal(item) for item in node.args[1:]
            ) or any(
                _python_value_has_unsafe_literal(keyword.value)
                for keyword in node.keywords
            )
        if short_name == "getattr":
            return any(
                _python_value_has_unsafe_literal(item) for item in node.args[2:]
            ) or any(
                _python_value_has_unsafe_literal(keyword.value)
                for keyword in node.keywords
            )
        if short_name in {"_arg_value", "arg_value"}:
            return any(
                _python_value_has_unsafe_literal(item) for item in node.args[2:]
            ) or any(
                keyword.arg == "default"
                and _python_value_has_unsafe_literal(keyword.value)
                for keyword in node.keywords
            )
        if short_name == "resolve_value":
            direct_value = node.args[0] if node.args else None
            if direct_value is None:
                direct_value = next(
                    (
                        keyword.value
                        for keyword in node.keywords
                        if keyword.arg == "default_value"
                    ),
                    None,
                )
            return direct_value is not None and _python_value_has_unsafe_literal(
                direct_value
            )
        return any(
            _python_value_has_unsafe_literal(item) for item in node.args
        ) or any(
            _python_value_has_unsafe_literal(keyword.value)
            for keyword in node.keywords
        )
    return any(
        _python_value_has_unsafe_literal(child) for child in ast.iter_child_nodes(node)
    )


def _is_safe_code_assignment(value: str) -> bool:
    cooked = value.strip().rstrip(",").strip()
    if _is_placeholder_secret(cooked):
        return True
    try:
        expression = ast.parse(cooked, mode="eval")
    except SyntaxError:
        return False
    return not _python_value_has_unsafe_literal(expression.body)


def _assignment_target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Attribute):
        return [target.attr]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [
            name
            for item in target.elts
            for name in _assignment_target_names(item)
        ]
    return []


def _module_string_constants(tree: ast.Module) -> dict[str, str]:
    constants: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                constants[target.id] = value.value
    return constants


def _function_default_pairs(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
):
    arguments = node.args
    positional = [*arguments.posonlyargs, *arguments.args]
    for argument, default in zip(
        positional[-len(arguments.defaults) :], arguments.defaults
    ):
        yield argument.arg, default
    for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults):
        if default is not None:
            yield argument.arg, default


def _unsafe_python_secret_lines(text: str) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return ["syntax-error"]
    constants = _module_string_constants(tree)
    offenders: set[int] = set()
    for node in ast.walk(tree):
        pairs: list[tuple[str, ast.AST]] = []
        if isinstance(node, ast.Assign):
            for target in node.targets:
                pairs.extend(
                    (name, node.value) for name in _assignment_target_names(target)
                )
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            pairs.extend(
                (name, node.value) for name in _assignment_target_names(node.target)
            )
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    pairs.append((key.value, value))
                elif isinstance(key, ast.Name) and key.id in constants:
                    pairs.append((constants[key.id], value))
        elif isinstance(node, ast.Call):
            pairs.extend(
                (keyword.arg, keyword.value)
                for keyword in node.keywords
                if isinstance(keyword.arg, str)
            )
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            pairs.extend(_function_default_pairs(node))
        for key, value in pairs:
            if not _is_sensitive_json_key(key):
                continue
            if _python_value_has_unsafe_literal(value):
                offenders.add(getattr(value, "lineno", getattr(node, "lineno", 0)))
    return [str(line) for line in sorted(offenders) if line > 0]


def _unsafe_sensitive_assignment_lines(text: str, suffix: str) -> list[str]:
    if suffix.casefold() == ".py":
        return _unsafe_python_secret_lines(text)
    offenders: list[str] = []
    code_file = suffix.casefold() == ".sh"
    for line_number, line in enumerate(text.splitlines(), 1):
        match = SCALAR_CREDENTIAL_ASSIGNMENT_RE.match(line)
        if not match or not _is_sensitive_json_key(match.group("key")):
            continue
        if code_file and match.group("operator") == ":":
            continue
        value = match.group("value").strip().rstrip(",").strip()
        if _is_placeholder_secret(value):
            continue
        if code_file and _is_safe_code_assignment(value):
            continue
        offenders.append(str(line_number))
    return offenders


def _json_secret_paths(value: object, prefix: str = "$") -> list[str]:
    offenders: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}"
            if _is_sensitive_json_value_key(key) and _sensitive_value_has_unsafe_secret(item):
                offenders.append(path)
            offenders.extend(_json_secret_paths(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            offenders.extend(_json_secret_paths(item, f"{prefix}[{index}]"))
    return offenders


def _is_json_schema_document(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    schema_id = value.get("$schema")
    return isinstance(schema_id, str) and "json-schema.org" in schema_id.casefold()


def _schema_value_has_unsafe_secret(value: object) -> bool:
    """Check value-bearing schema keywords without treating schemas as values."""

    return _sensitive_value_has_unsafe_secret(value)


def _canonical_credential_env_selectors(property_name: str) -> frozenset[str]:
    if property_name == "base_url":
        return frozenset({"REDFISH_BASE_URL"})
    if property_name == "username":
        return frozenset({"REDFISH_USERNAME", "OPENUBMC_SSH_USER"})
    if property_name == "password":
        return frozenset({"REDFISH_PASSWORD", "OPENUBMC_SSH_PASSWORD"})
    return frozenset()


def _is_canonical_credential_env_schema(value: object) -> bool:
    """Recognize the exact env-name selector contract, never credential values."""

    if not isinstance(value, dict):
        return False
    if set(value) != {
        "type",
        "required",
        "properties",
        "oneOf",
        "additionalProperties",
    }:
        return False
    if value.get("type") != "object" or value.get("additionalProperties") is not False:
        return False
    if set(value.get("required", [])) != set(CANONICAL_CREDENTIAL_ENV_FIELD_NAMES):
        return False

    properties = value.get("properties")
    if not isinstance(properties, dict):
        return False
    if set(properties) != set(CANONICAL_CREDENTIAL_ENV_FIELD_NAMES):
        return False
    if properties.get("base_url") != {"const": "REDFISH_BASE_URL"}:
        return False
    for property_name in ("username", "password"):
        property_schema = properties.get(property_name)
        if not isinstance(property_schema, dict) or set(property_schema) != {"enum"}:
            return False
        if set(property_schema.get("enum", [])) != set(
            _canonical_credential_env_selectors(property_name)
        ):
            return False

    expected_pairs = {
        ("REDFISH_USERNAME", "OPENUBMC_SSH_PASSWORD"),
        ("REDFISH_USERNAME", "REDFISH_PASSWORD"),
        ("OPENUBMC_SSH_USER", "OPENUBMC_SSH_PASSWORD"),
    }
    actual_pairs: set[tuple[object, object]] = set()
    one_of = value.get("oneOf")
    if not isinstance(one_of, list):
        return False
    for branch in one_of:
        if not isinstance(branch, dict) or set(branch) != {"properties"}:
            return False
        branch_properties = branch.get("properties")
        if not isinstance(branch_properties, dict) or set(branch_properties) != {
            "username",
            "password",
        }:
            return False
        username_schema = branch_properties.get("username")
        password_schema = branch_properties.get("password")
        if (
            not isinstance(username_schema, dict)
            or set(username_schema) != {"const"}
            or not isinstance(password_schema, dict)
            or set(password_schema) != {"const"}
        ):
            return False
        actual_pairs.add((username_schema.get("const"), password_schema.get("const")))
    return actual_pairs == expected_pairs and len(one_of) == len(expected_pairs)


def _is_canonical_env_selector_keyword(
    property_name: str | None,
    keyword: str,
    value: object,
) -> bool:
    if property_name not in CANONICAL_CREDENTIAL_ENV_FIELD_NAMES:
        return False
    if keyword == "const":
        candidates = {value} if isinstance(value, str) else set()
    elif keyword == "enum" and isinstance(value, list):
        candidates = set(value) if all(isinstance(item, str) for item in value) else set()
    else:
        return False
    return bool(candidates) and candidates <= _canonical_credential_env_selectors(
        property_name
    )


UNRESOLVED_SCHEMA_REF = object()


def _find_schema_anchor(value: object, anchor: str) -> object:
    if isinstance(value, dict):
        if value.get("$anchor") == anchor or value.get("$dynamicAnchor") == anchor:
            return value
        for item in value.values():
            found = _find_schema_anchor(item, anchor)
            if found is not UNRESOLVED_SCHEMA_REF:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_schema_anchor(item, anchor)
            if found is not UNRESOLVED_SCHEMA_REF:
                return found
    return UNRESOLVED_SCHEMA_REF


def _resolve_local_schema_ref(root: object, reference: object) -> object:
    """Resolve only same-document refs; external sensitive refs fail closed."""

    if not isinstance(reference, str):
        return UNRESOLVED_SCHEMA_REF
    parsed = urlsplit(reference)
    reference_base = urldefrag(reference).url
    if reference_base:
        root_id = root.get("$id", root.get("id")) if isinstance(root, dict) else None
        if not isinstance(root_id, str) or reference_base != urldefrag(root_id).url:
            return UNRESOLVED_SCHEMA_REF

    fragment = unquote(parsed.fragment)
    if not fragment:
        return root
    if not fragment.startswith("/"):
        return _find_schema_anchor(root, fragment)

    current = root
    for encoded_segment in fragment[1:].split("/"):
        pointer_segment = encoded_segment.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and pointer_segment in current:
            current = current[pointer_segment]
            continue
        if isinstance(current, list) and pointer_segment.isdecimal():
            index = int(pointer_segment)
            if index < len(current):
                current = current[index]
                continue
        return UNRESOLVED_SCHEMA_REF
    return current


def _json_schema_secret_paths(
    value: object,
    prefix: str = "$",
    *,
    sensitive_property: bool = False,
    canonical_credential_env: bool = False,
    schema_property_name: str | None = None,
    root_schema: object | None = None,
    followed_schema_ids: frozenset[int] = frozenset(),
) -> list[str]:
    """Find literal credential defaults/examples while ignoring schema metadata.

    Property schemas named ``authorization`` or ``token`` describe a value; they
    are not themselves that value.  Only value-bearing JSON Schema keywords (or
    nested defaults containing actual sensitive keys) may carry a secret.
    """

    offenders: list[str] = []
    if root_schema is None:
        root_schema = value
    canonical_credential_env = (
        canonical_credential_env or _is_canonical_credential_env_schema(value)
    )
    sensitive_property = sensitive_property or _schema_identity_is_sensitive(value)
    if isinstance(value, list):
        for index, item in enumerate(value):
            offenders.extend(
                _json_schema_secret_paths(
                    item,
                    f"{prefix}[{index}]",
                    sensitive_property=sensitive_property,
                    canonical_credential_env=canonical_credential_env,
                    schema_property_name=schema_property_name,
                    root_schema=root_schema,
                    followed_schema_ids=followed_schema_ids,
                )
            )
        return offenders
    if not isinstance(value, dict):
        return offenders

    for reference_key in ("$ref", "$dynamicRef", "$recursiveRef"):
        reference = value.get(reference_key)
        if not sensitive_property or not isinstance(reference, str):
            continue
        referenced_schema = _resolve_local_schema_ref(root_schema, reference)
        reference_path = f"{prefix}.{reference_key}"
        if referenced_schema is UNRESOLVED_SCHEMA_REF:
            offenders.append(reference_path)
            continue
        if not isinstance(referenced_schema, (dict, bool)):
            if _schema_value_has_unsafe_secret(referenced_schema):
                offenders.append(reference_path)
            continue
        referenced_id = id(referenced_schema)
        if referenced_id not in followed_schema_ids:
            offenders.extend(
                _json_schema_secret_paths(
                    referenced_schema,
                    f"{reference_path}({reference})",
                    sensitive_property=True,
                    canonical_credential_env=canonical_credential_env,
                    schema_property_name=schema_property_name,
                    root_schema=root_schema,
                    followed_schema_ids=followed_schema_ids | {referenced_id},
                )
            )

    for key, item in value.items():
        path = f"{prefix}.{key}"
        if key in {"default", "const", "examples", "enum"}:
            safe_env_selector = canonical_credential_env and (
                _is_canonical_env_selector_keyword(schema_property_name, key, item)
            )
            if (
                sensitive_property
                and not safe_env_selector
                and _schema_value_has_unsafe_secret(item)
            ):
                offenders.append(path)
            offenders.extend(_json_secret_paths(item, path))
            continue
        if key in {"properties", "patternProperties"} and isinstance(item, dict):
            for property_name, property_schema in item.items():
                property_path = f"{path}.{property_name}"
                property_sensitive = (
                    _schema_property_inherits_sensitive(
                        sensitive_property,
                        property_name,
                    )
                    or (
                        _schema_identity_text_is_sensitive(property_name)
                        if key == "patternProperties"
                        else _is_sensitive_json_value_key(property_name)
                    )
                )
                if property_sensitive and not isinstance(property_schema, (dict, bool)):
                    if _schema_value_has_unsafe_secret(property_schema):
                        offenders.append(property_path)
                    continue
                offenders.extend(
                    _json_schema_secret_paths(
                        property_schema,
                        property_path,
                        sensitive_property=property_sensitive,
                        canonical_credential_env=canonical_credential_env,
                        schema_property_name=str(property_name),
                        root_schema=root_schema,
                        followed_schema_ids=followed_schema_ids,
                    )
                )
            continue
        if key in {"$defs", "definitions"} and isinstance(item, dict):
            for definition_name, definition_schema in item.items():
                definition_path = f"{path}.{definition_name}"
                definition_sensitive = (
                    sensitive_property
                    or _is_sensitive_json_value_key(definition_name)
                    or _schema_identity_is_sensitive(definition_schema)
                )
                if definition_sensitive and not isinstance(definition_schema, (dict, bool)):
                    if _schema_value_has_unsafe_secret(definition_schema):
                        offenders.append(definition_path)
                    continue
                offenders.extend(
                    _json_schema_secret_paths(
                        definition_schema,
                        definition_path,
                        sensitive_property=definition_sensitive,
                        canonical_credential_env=canonical_credential_env,
                        schema_property_name=None,
                        root_schema=root_schema,
                        followed_schema_ids=followed_schema_ids,
                    )
                )
            continue
        if key in {"required", "dependentRequired", "$vocabulary"}:
            continue
        if key in {"dependentSchemas", "dependencies"} and isinstance(item, dict):
            for dependency_name, dependency_schema in item.items():
                if isinstance(dependency_schema, dict):
                    offenders.extend(
                        _json_schema_secret_paths(
                            dependency_schema,
                            f"{path}.{dependency_name}",
                            sensitive_property=sensitive_property,
                            canonical_credential_env=canonical_credential_env,
                            schema_property_name=schema_property_name,
                            root_schema=root_schema,
                            followed_schema_ids=followed_schema_ids,
                        )
                    )
            continue
        if _is_sensitive_json_value_key(key) and _sensitive_value_has_unsafe_secret(item):
            offenders.append(path)
        offenders.extend(
            _json_schema_secret_paths(
                item,
                path,
                sensitive_property=sensitive_property,
                canonical_credential_env=canonical_credential_env,
                schema_property_name=schema_property_name,
                root_schema=root_schema,
                followed_schema_ids=followed_schema_ids,
            )
        )
    return offenders


def _json_schema_descriptive_strings(
    value: object, prefix: str = "$"
):
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}"
            if key in {"description", "$comment", "title"} and isinstance(item, str):
                yield path, item
            else:
                yield from _json_schema_descriptive_strings(item, path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _json_schema_descriptive_strings(item, f"{prefix}[{index}]")


def _unsafe_header_values(text: str, source_suffix: str = "") -> list[str]:
    offenders: list[str] = []
    for pattern in (CREDENTIAL_HEADER_RE, MULTILINE_CREDENTIAL_HEADER_RE):
        for match in pattern.finditer(text):
            raw = match.group("value").strip().rstrip(",}").strip().strip("'\"")
            if not raw:
                continue
            if source_suffix.casefold() == ".py":
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                if line_end < 0:
                    line_end = len(text)
                source_line = text[line_start:line_end]
                if re.fullmatch(
                    r"\s*authorization\s*:\s*"
                    r"[A-Za-z_][A-Za-z0-9_.]*(?:\[[^\r\n]+\])?"
                    r"(?:\s*\|\s*[A-Za-z_][A-Za-z0-9_.]*(?:\[[^\r\n]+\])?)*"
                    r"\s*,?\s*",
                    source_line,
                    flags=re.IGNORECASE,
                ):
                    continue
            if _is_placeholder_secret(raw):
                continue
            line_number = text.count("\n", 0, match.start()) + 1
            offenders.append(str(line_number))
    return offenders


def _serialized_text_has_secret(text: str) -> bool:
    try:
        parsed = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        parsed = None
    if _json_secret_paths(parsed):
        return True
    for match in SERIALIZED_CREDENTIAL_ASSIGNMENT_RE.finditer(text):
        if not _is_sensitive_json_key(match.group("key")):
            continue
        raw = match.group("value").strip().strip("'\"")
        if not _is_placeholder_secret(raw):
            return True
    return False


def _unsafe_serialized_assignments(text: str, suffix: str) -> list[str]:
    offenders: list[str] = []
    if suffix.casefold() != ".py":
        for match in SERIALIZED_CREDENTIAL_ASSIGNMENT_RE.finditer(text):
            if not _is_sensitive_json_key(match.group("key")):
                continue
            raw = match.group("value").strip().strip("'\"")
            if _is_placeholder_secret(raw):
                continue
            offenders.append(str(text.count("\n", 0, match.start()) + 1))
    else:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return offenders
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and _serialized_text_has_secret(node.value)
            ):
                offenders.append(str(getattr(node, "lineno", 0)))
    return offenders


def _unsafe_private_key_blocks(text: str) -> list[str]:
    offenders: list[str] = []
    for match in PRIVATE_KEY_MATERIAL_RE.finditer(text):
        body = match.group("body").strip()
        if _is_placeholder_secret(body):
            continue
        offenders.append(str(text.count("\n", 0, match.start()) + 1))
    return offenders


def _unsafe_command_secrets(text: str) -> list[str]:
    offenders: list[str] = []
    for match in COMMAND_PASSWORD_RE.finditer(text):
        # Expanding an environment placeholder still exposes the password in argv.
        offenders.append(str(text.count("\n", 0, match.start()) + 1))
    for match in IDENTITY_OPTION_RE.finditer(text):
        raw = match.group("value").strip().strip("'\"")
        if _is_placeholder_secret(raw):
            continue
        offenders.append(str(text.count("\n", 0, match.start()) + 1))
    for match in URL_USERINFO_RE.finditer(text):
        if _is_placeholder_secret(match.group("user")) and _is_placeholder_secret(
            match.group("password")
        ):
            continue
        offenders.append(str(text.count("\n", 0, match.start()) + 1))
    return offenders


def scan_forbidden_literals(root: Path) -> None:
    offenders: list[str] = []
    for path, relative in iter_scannable_files(root):
        content = path.read_bytes()
        if contains_forbidden_literal(content):
            offenders.append(f"{relative}:forbidden-secret")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            continue
        content_checks = (
            (IPV4_LITERAL_RE, "ip-literal"),
            (IPV4_PREFIX_LITERAL_RE, "ip-prefix-literal"),
            (RUNTIME_INSTANCE_RE, "runtime-instance"),
            (EVENT_CODE_LITERAL_RE, "event-code"),
            (CASE_MARKER_RE, "single-case-marker"),
            (HARDWARE_MODEL_RE, "hardware-model"),
            (LABELED_CASE_VALUE_RE, "labeled-case-value"),
            (INLINE_LABELED_CASE_VALUE_RE, "inline-labeled-case-value"),
            (INLINE_ALARM_LITERAL_RE, "inline-alarm-literal"),
            (INLINE_HARDWARE_MODEL_RE, "inline-hardware-model"),
            (INLINE_RUNTIME_INSTANCE_RE, "inline-runtime-instance"),
            (INLINE_ONE_OFF_CONDITION_RE, "inline-one-off-condition"),
        )
        for pattern, label in content_checks:
            if pattern.search(text):
                offenders.append(f"{relative}:{label}")
        if contains_ipv6_literal(text):
            offenders.append(f"{relative}:ipv6-literal")
        parsed_json: object = None
        is_json_schema = False
        if path.suffix.casefold() == ".json":
            try:
                parsed_json = json.loads(text, object_pairs_hook=_unique_json_object)
            except DuplicateJsonKeyError:
                offenders.append(f"{relative}:duplicate-json-key")
                parsed_json = None
            except json.JSONDecodeError:
                offenders.append(f"{relative}:invalid-json")
                parsed_json = None
            is_json_schema = _is_json_schema_document(parsed_json)
            secret_paths = (
                _json_schema_secret_paths(
                    parsed_json,
                    sensitive_property=_schema_identity_text_is_sensitive(relative),
                )
                if is_json_schema
                else _json_secret_paths(parsed_json)
            )
            for secret_path in secret_paths:
                offenders.append(f"{relative}:json-secret:{secret_path}")
        if is_json_schema:
            for schema_path, schema_text in _json_schema_descriptive_strings(parsed_json):
                if (
                    _unsafe_header_values(schema_text)
                    or _unsafe_serialized_assignments(schema_text, ".txt")
                    or _unsafe_sensitive_assignment_lines(schema_text, ".txt")
                ):
                    offenders.append(
                        f"{relative}:json-schema-text-secret:{schema_path}"
                    )
        else:
            for line_number in _unsafe_header_values(text, path.suffix):
                offenders.append(f"{relative}:credential-header:{line_number}")
            for line_number in _unsafe_serialized_assignments(text, path.suffix):
                offenders.append(f"{relative}:serialized-secret:{line_number}")
        for line_number in _unsafe_private_key_blocks(text):
            offenders.append(f"{relative}:private-key-material:{line_number}")
        for line_number in _unsafe_command_secrets(text):
            offenders.append(f"{relative}:command-secret:{line_number}")
        if not is_json_schema:
            for line_number in _unsafe_sensitive_assignment_lines(text, path.suffix):
                offenders.append(f"{relative}:secret-assignment:{line_number}")
    if offenders:
        raise SystemExit(
            "unsafe content (forbidden literal or case data) found in shareable files: "
            + ", ".join(sorted(set(offenders)))
        )


def _copy_canonical_runtime(root: Path) -> tuple[dict[str, str], list[str]]:
    """Generate the package-only Runtime vendor from the canonical source tree."""

    contract = runtime_distribution_contract(CANONICAL_RUNTIME_PACKAGE)
    copied: list[str] = []
    vendor_root = root / VENDORED_RUNTIME_RELATIVE
    for source_path, runtime_relative in iter_runtime_source_files(
        CANONICAL_RUNTIME_PACKAGE
    ):
        destination = vendor_root / runtime_relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination)
        copied.append((VENDORED_RUNTIME_RELATIVE / runtime_relative).as_posix())
    return contract, copied


def _source_requires_runtime_vendoring(root: Path) -> bool:
    manifest_path = root / "skill.json"
    if not manifest_path.is_file():
        return False
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(manifest, dict) and manifest.get("name") == "openubmc-debug"


def _write_staged_manifest(
    root: Path,
    *,
    runtime_contract: Mapping[str, str],
    generated_files: list[str],
) -> None:
    manifest_path = root / "skill.json"
    try:
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("staged skill.json is unavailable or invalid") from exc
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise SystemExit("staged skill.json files must be an array")
    manifest["targetRuntime"] = dict(runtime_contract)
    manifest["files"] = sorted(
        {str(path) for path in manifest["files"]} | set(generated_files)
    )
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _marker_payload(
    source: Path,
    runtime_contract: Mapping[str, str] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "tool": PACKAGE_TOOL,
        "format_version": PACKAGE_FORMAT_VERSION,
        "source_name": source.name,
    }
    if runtime_contract is not None:
        payload["target_runtime"] = dict(runtime_contract)
    return payload


def _write_package_marker(
    root: Path,
    source: Path,
    runtime_contract: Mapping[str, str] | None = None,
) -> None:
    marker = root / PACKAGE_MARKER
    marker.write_text(
        json.dumps(_marker_payload(source, runtime_contract), indent=2) + "\n",
        encoding="utf-8",
    )


def _normalize_package_permissions(root: Path) -> None:
    root.chmod(0o755)
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
            continue
        relative = path.relative_to(root)
        path.chmod(0o755 if relative.parts and relative.parts[0] == "scripts" else 0o644)


def _is_packager_output(output: Path) -> bool:
    if output.is_symlink() or not output.is_dir():
        return False
    marker = output / PACKAGE_MARKER
    if marker.is_symlink() or not marker.is_file():
        return False
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return (
        payload.get("tool") == PACKAGE_TOOL
        and payload.get("format_version") == PACKAGE_FORMAT_VERSION
    )


def copy_shareable_tree(source: Path, output: Path, *, force: bool = False) -> list[str]:
    raw_source = source.expanduser().absolute()
    if raw_source.is_symlink():
        raise SystemExit(f"source skill directory must not be a symbolic link: {raw_source}")
    source = raw_source.resolve()
    raw_output = output.expanduser().absolute()
    if raw_output.is_symlink():
        raise SystemExit(f"output must not be a symbolic link: {raw_output}")
    output = raw_output.resolve()
    if not source.is_dir():
        raise SystemExit(f"source skill directory does not exist: {source}")
    if output == source or source in output.parents or output in source.parents:
        raise SystemExit("output must be separate from the source skill directory and its ancestors")
    protected_outputs = {Path(output.anchor), Path.home().resolve(), REPO_ROOT.resolve()}
    if output in protected_outputs:
        raise SystemExit(f"refusing destructive package output: {output}")
    validate_source_tree(source)
    shareable_files = list(iter_shareable_files(source))
    validate_manifest_matches_source(source, shareable_files)
    scan_forbidden_literals(source)
    if output.exists():
        if not force:
            raise SystemExit(f"output already exists: {output}")
        if not _is_packager_output(output):
            raise SystemExit(f"refusing to replace output not created by this packager: {output}")

    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.package-", dir=output.parent))
    backup: Path | None = None
    copied: list[str] = []
    try:
        for path, relative in shareable_files:
            dest = stage / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
            copied.append(str(relative))
        runtime_contract: dict[str, str] | None = None
        if _source_requires_runtime_vendoring(source):
            runtime_contract, generated_files = _copy_canonical_runtime(stage)
            copied.extend(generated_files)
            _write_staged_manifest(
                stage,
                runtime_contract=runtime_contract,
                generated_files=generated_files,
            )
        _write_package_marker(stage, source, runtime_contract)
        if runtime_contract is not None:
            scan_forbidden_literals(stage)
        _normalize_package_permissions(stage)

        if output.exists():
            backup = output.parent / f".{output.name}.backup-{uuid.uuid4().hex}"
            os.replace(output, backup)
        try:
            os.replace(stage, output)
        except BaseException:
            if backup is not None and backup.exists() and not output.exists():
                os.replace(backup, output)
            raise
        if backup is not None:
            shutil.rmtree(backup)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return copied


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    source = Path(args.source)
    output = Path(args.output)
    copied = copy_shareable_tree(source, output, force=args.force)
    print(f"packaged {len(copied)} files into {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
