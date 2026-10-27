"""Problem routing, bounded evidence scanning, and timeline construction."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import datetime as dt
import bisect
import fnmatch
import gzip
import heapq
import ipaddress
import json
import os
import pathlib
import re
import zlib
from urllib.parse import urlsplit
from dataclasses import dataclass
from typing import Callable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from log_bundle_findings import (
    MAX_EVENT_CANDIDATES_PER_ANCHOR,
    MAX_EVENT_CORRELATIONS,
    build_event_correlations,
    build_evidence_findings,
    event_candidate_details,
    event_candidate_sort_key,
    is_operation_failure_anchor,
    operation_event_anchor_id,
)
from log_bundle_common import BundleAnalysisError
from log_bundle_structured import SUPPORTED_STRUCTURED_PARSERS, make_structured_collector
from log_bundle_artifact import ensure_bundle_path


DEFAULT_ANALYSIS_MAX_FILES = 8
DEFAULT_ANALYSIS_MAX_LINES = 3
DEFAULT_ANALYSIS_MAX_PATHS = 10
DEFAULT_ANALYSIS_MAX_PATHS_PER_LOG = 12
MAX_PATH_EXPANSION_RESULTS = 4096
MAX_ROTATED_FILE_CANDIDATES = 4096
MAX_GLOB_MATCHES_PER_PATTERN = 4096
MAX_PATH_DISCOVERY_ENTRIES = 100_000
MAX_COMPONENT_HINT_DISCOVERY_ENTRIES = 4096
DEFAULT_ANALYSIS_MAX_BYTES_PER_FILE = 8 * 1024 * 1024
DEFAULT_ANALYSIS_MAX_TOTAL_BYTES = 64 * 1024 * 1024
DEFAULT_ANALYSIS_MAX_LINE_BYTES = 64 * 1024
DEFAULT_CORRELATION_WINDOW_SECONDS = 300
DEFAULT_MAX_BUNDLE_COMPONENT_HINTS = 64
PUBLIC_SOURCE_REFERENCE_RE = re.compile(
    r"^https://"
    r"(?!(?:[a-z0-9-]+\.)*(?:localhost|local|internal|lan|invalid|test|example)(?::|/))"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
    r"\.[a-z]{2,63}"
    r"(?::(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?"
    r"/[^?\s#]+(?:#[A-Za-z0-9._:-]{1,128})?$"
)
SCAN_TRUNCATION_CODES = {
    "file_scan_truncated",
    "scan_byte_limit_reached",
    "total_scan_byte_limit_reached",
    "partial_line_discarded",
}
NUL_PADDING_WARNING_CODE = "nul_padding_removed"
MIN_NUL_PADDING_BYTES = 16
CORRELATION_SCAN_INCOMPLETE_WARNING_CODES = SCAN_TRUNCATION_CODES | {
    "correlation_timezone_domain_mismatch",
    "decode_replacement_used",
    "line_too_long",
    NUL_PADDING_WARNING_CODE,
    "timezone_domain_mismatch",
}
LOG_TIMESTAMP_RE = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
GENERIC_FILE_KEYWORDS = {"error", "errors", "fail", "failed", "failure", "失败", "异常"}
PRIORITY_PHRASE_RULES = (
    (("登录失败", "login"), ("login failed", "login failure", "登录失败"), 16),
    (("同步失败", "sync"), ("sync failed", "sync failure", "failed to sync", "同步失败"), 14),
    (("启动失败", "startup", "boot"), ("startup failed", "start failed", "failed to start", "启动失败"), 14),
)
EVIDENCE_TERM_ALIASES = {
    "auth": ("auth", "authenticate", "authentication", "authorization"),
    "sync": ("sync", "synchronize", "synchronized", "synchronization"),
}
LOW_SIGNAL_LINES = {
    "----------rpc performance statistics----------",
    "----------mdb performance statistics----------",
    ".objectidentifier",
    ".objectname",
}
LOW_SIGNAL_PREFIXES = (
    "类名 对象名 同步属性名:",
    "表达式参数:",
)
LOW_SIGNAL_SUBSTRINGS = (
    "org.freedesktop.dbus.peer ping",
)
APPDUMP_COMPONENT_EVIDENCE_LOGS = (
    "mdb_info.log",
    "sync_property_trace.log",
    "rpc_records.log",
)
# Redaction lives in a small shared module so collection and structured
# summaries cannot accidentally grow a second, weaker implementation.
from log_bundle_redaction import redact_sensitive_text


@dataclass
class ScanBudget:
    max_total_bytes: int
    bytes_read: int = 0

    @property
    def remaining_bytes(self) -> int:
        return max(0, self.max_total_bytes - self.bytes_read)


@dataclass
class PathDiscoveryBudget:
    max_entries: int = MAX_PATH_DISCOVERY_ENTRIES
    entries_examined: int = 0
    truncated: bool = False
    limit_hits: int = 0

    def consume(self) -> bool:
        if self.entries_examined >= self.max_entries:
            self.truncated = True
            self.limit_hits += 1
            return False
        self.entries_examined += 1
        return True

    @property
    def remaining_entries(self) -> int:
        return max(0, self.max_entries - self.entries_examined)


@dataclass(frozen=True)
class _DirectoryEntrySnapshot:
    name: str
    path: pathlib.Path
    is_file: bool
    is_dir: bool


class _PathDirectoryIndex:
    """Charge and cache one bounded scan per directory for one analysis."""

    def __init__(
        self,
        bundle_root: pathlib.Path,
        discovery_budget: PathDiscoveryBudget,
    ) -> None:
        self.bundle_root = pathlib.Path(bundle_root)
        self.discovery_budget = discovery_budget
        self._cache: dict[pathlib.Path, tuple[list[_DirectoryEntrySnapshot], bool]] = {}
        self._names: dict[pathlib.Path, list[str]] = {}

    def scan(self, directory: pathlib.Path) -> tuple[list[_DirectoryEntrySnapshot], bool]:
        directory = pathlib.Path(directory)
        if not os.path.lexists(directory):
            return [], True
        if directory.is_symlink():
            raise BundleAnalysisError(
                "bundle_layout_invalid",
                f"Bundle contains symbolic links; first entry: {directory}",
            )
        safe_directory = ensure_bundle_path(self.bundle_root, directory)
        cached = self._cache.get(safe_directory)
        if cached is not None:
            return cached

        snapshots: list[_DirectoryEntrySnapshot] = []
        complete = True
        try:
            entries = os.scandir(safe_directory)
        except OSError as exc:
            raise BundleAnalysisError(
                "bundle_layout_invalid",
                f"Failed to inspect {safe_directory}: {exc}",
            ) from exc
        with entries:
            for entry in entries:
                if not self.discovery_budget.consume():
                    complete = False
                    break
                candidate = pathlib.Path(entry.path)
                try:
                    is_symlink = entry.is_symlink()
                    is_file = entry.is_file(follow_symlinks=False)
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError as exc:
                    raise BundleAnalysisError(
                        "bundle_layout_invalid",
                        f"Failed to inspect bundle entry {candidate}: {exc}",
                    ) from exc
                if is_symlink:
                    raise BundleAnalysisError(
                        "bundle_layout_invalid",
                        f"Bundle contains symbolic links; first entry: {candidate}",
                    )
                snapshots.append(
                    _DirectoryEntrySnapshot(
                        name=entry.name,
                        path=candidate,
                        is_file=is_file,
                        is_dir=is_dir,
                    )
                )
        snapshots.sort(key=lambda item: item.name)
        result = (snapshots, complete)
        self._cache[safe_directory] = result
        self._names[safe_directory] = [item.name for item in snapshots]
        return result

    def rotation_entries(
        self,
        directory: pathlib.Path,
        target_name: str,
    ) -> tuple[list[_DirectoryEntrySnapshot], bool]:
        snapshots, complete = self.scan(directory)
        if not snapshots:
            return [], complete
        safe_directory = ensure_bundle_path(self.bundle_root, directory)
        names = self._names[safe_directory]
        selected: list[_DirectoryEntrySnapshot] = []

        exact_index = bisect.bisect_left(names, target_name)
        if exact_index < len(names) and names[exact_index] == target_name:
            exact = snapshots[exact_index]
            if exact.is_file:
                selected.append(exact)

        prefix = f"{target_name}."
        prefix_index = bisect.bisect_left(names, prefix)
        while prefix_index < len(names):
            entry = snapshots[prefix_index]
            if not entry.name.startswith(prefix):
                break
            if entry.is_file:
                selected.append(entry)
            prefix_index += 1
        return selected, complete


CATALOG_METADATA_KEYS = ("definition_status", "source_type", "reliability")
CATALOG_SCAN_MODES = frozenset({"text", "metadata_only"})
CATALOG_COVERAGE_CLASSES = frozenset(
    {"semantic", "explicit_opaque", "generic_fallback"}
)
CATALOG_SEMANTIC_LEVELS = frozenset({"path_only", "purpose", "structure", "diagnostic"})
CATALOG_ARTIFACT_FORMATS = frozenset(
    {"text", "csv", "json", "sqlite", "binary", "archive", "image", "video", "mixed", "unknown"}
)
CATALOG_ROUTE_MODES = frozenset({"automatic", "explicit_only", "never"})
CATALOG_SENSITIVITY_LEVELS = frozenset(
    {"ordinary", "identifier_sensitive", "configuration_sensitive", "highly_sensitive"}
)
CATALOG_HIGH_RISK_FORMATS = frozenset({"sqlite", "binary", "archive", "image", "video"})
CATALOG_COVERAGE_PRECEDENCE = {
    "generic_fallback": 0,
    "explicit_opaque": 1,
    "semantic": 2,
}
CATALOG_METADATA_ALLOWED = {
    "definition_status": frozenset(
        {
            "documented",
            "community_supported",
            "observed_path",
            "maintained_heuristic",
            "bundle_local_routing",
        }
    ),
    "source_type": frozenset(
        {
            "component_documentation",
            "community_discussion",
            "public_repository",
            "validated_bundle_structure",
            "repository_maintained",
            "bundle_local",
        }
    ),
    "reliability": frozenset({"documented", "heuristic", "observed_only", "local_only"}),
}
CATALOG_METADATA_PROFILES: dict[str, dict[str, str]] = {
    "component_documentation": {
        "definition_status": "documented",
        "reliability": "documented",
    },
    "community_discussion": {
        "definition_status": "community_supported",
        "reliability": "heuristic",
    },
    "public_repository": {
        "definition_status": "documented",
        "reliability": "documented",
    },
    "validated_bundle_structure": {
        "definition_status": "observed_path",
        "reliability": "observed_only",
        "source_reference": "bundle structure observation",
    },
    "repository_maintained": {
        "definition_status": "maintained_heuristic",
        "reliability": "heuristic",
        "source_reference": "repository-maintained heuristic",
    },
    "bundle_local": {
        "definition_status": "bundle_local_routing",
        "reliability": "local_only",
        "source_reference": "bundle-local observed directory",
    },
}
CATALOG_DEFAULT_METADATA = {
    "definition_status": "maintained_heuristic",
    "source_type": "repository_maintained",
    "reliability": "heuristic",
    "source_reference": "repository-maintained heuristic",
}
PUBLIC_SOURCE_TYPES = frozenset(
    {"component_documentation", "community_discussion", "public_repository"}
)


def _infer_artifact_format(paths: list[str], *, scan_mode: str) -> str:
    """Return a conservative format default for legacy catalog entries."""

    formats: set[str] = set()
    for path in paths:
        name = pathlib.PurePosixPath(path.rstrip("/")).name.casefold()
        if name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
            formats.add("archive")
        elif name.endswith((".tar", ".tgz", ".zip", ".7z", ".gz", ".bz2", ".xz")):
            formats.add("archive")
        elif name.endswith((".jpeg", ".jpg", ".png", ".bmp", ".gif")):
            formats.add("image")
        elif name.endswith((".rep", ".mp4", ".avi", ".mkv", ".webm")):
            formats.add("video")
        elif name.endswith((".db", ".sqlite", ".sqlite3")):
            formats.add("sqlite")
        elif name.endswith((".bin", ".sr", ".core")):
            formats.add("binary")
        elif name.endswith(".json"):
            formats.add("json")
        elif name.endswith(".csv"):
            formats.add("csv")
        elif not path.endswith("/"):
            formats.add("text" if scan_mode == "text" else "unknown")
    if not formats:
        return "unknown"
    if len(formats) == 1:
        return next(iter(formats))
    return "mixed"


def catalog_dimensions(item: dict[str, object]) -> dict[str, str]:
    """Return the normalized handling dimensions for a catalog definition."""

    return {
        "semantic_level": str(item.get("semantic_level", "path_only")),
        "artifact_format": str(item.get("artifact_format", "unknown")),
        "route_mode": str(item.get("route_mode", "explicit_only")),
        "sensitivity": str(item.get("sensitivity", "ordinary")),
    }


def _catalog_error(source: str, message: str) -> BundleAnalysisError:
    return BundleAnalysisError("reference_invalid", f"{source}: {message}")


def _validate_catalog_string(
    value: object,
    *,
    source: str,
    field: str,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise _catalog_error(source, f"{field} must be a string.")
    if not allow_empty and not value.strip():
        raise _catalog_error(source, f"{field} must not be empty.")
    if value != value.strip() or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise _catalog_error(source, f"{field} contains whitespace padding or control characters.")
    return value


def _validate_catalog_string_list(
    value: object,
    *,
    source: str,
    field: str,
    allow_empty: bool,
) -> list[str]:
    if not isinstance(value, list):
        raise _catalog_error(source, f"{field} must be an array of strings.")
    if not allow_empty and not value:
        raise _catalog_error(source, f"{field} must contain at least one item.")
    result: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(value):
        item = _validate_catalog_string(entry, source=source, field=f"{field}[{index}]")
        folded = item.casefold()
        if folded in seen:
            raise _catalog_error(source, f"{field} contains duplicate item: {item}")
        seen.add(folded)
        result.append(item)
    return result


def _validate_catalog_path(value: object, *, source: str, field: str) -> str:
    path = _validate_catalog_string(value, source=source, field=field)
    if "\\" in path or "\x00" in path:
        raise _catalog_error(source, f"{field} must use package-relative POSIX separators: {path!r}")
    if path.startswith("/") or re.match(r"^[A-Za-z]:($|/)", path):
        raise _catalog_error(source, f"{field} must be package-relative: {path!r}")
    if len(path) > 512:
        raise _catalog_error(source, f"{field} exceeds the 512-character safety limit.")
    if "**" in path:
        raise _catalog_error(source, f"{field} must not use recursive '**' globs: {path!r}")
    if "//" in path:
        raise _catalog_error(source, f"{field} contains an empty path component: {path!r}")
    parts = path.split("/")
    if parts[-1] == "":
        # A single trailing slash denotes a directory hint; nothing else may
        # be empty.  The root path and repeated trailing slashes are invalid.
        if len(parts) < 2 or parts[-2] == "":
            raise _catalog_error(source, f"{field} is not a valid relative path: {path!r}")
        parts = parts[:-1]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise _catalog_error(source, f"{field} contains an unsafe path component: {path!r}")
    if sum(any(char in part for char in "*?[") for part in parts) > 4:
        raise _catalog_error(source, f"{field} uses too many wildcard components: {path!r}")
    return path


def _validate_public_source_reference(
    source_reference: str,
    *,
    source: str,
    field: str,
) -> None:
    if len(source_reference) > 2048:
        raise _catalog_error(source, f"{field} exceeds 2048 characters.")
    if not PUBLIC_SOURCE_REFERENCE_RE.fullmatch(source_reference):
        raise _catalog_error(
            source,
            f"{field} must be a lowercase-HTTPS URL with a public DNS host, canonical port, and specific path.",
        )
    try:
        parsed = urlsplit(source_reference)
    except ValueError as exc:
        raise _catalog_error(source, f"{field} is not a valid URL.") from exc
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise _catalog_error(source, f"{field} contains an invalid port.") from exc
    if parsed.scheme != "https" or not parsed.netloc or not parsed.path or parsed.path == "/":
        raise _catalog_error(source, f"{field} must be a specific HTTPS URL.")
    if parsed_port is not None and not 1 <= parsed_port <= 65535:
        raise _catalog_error(source, f"{field} contains an invalid port.")
    if parsed.username or parsed.password or any(char.isspace() for char in source_reference):
        raise _catalog_error(source, f"{field} must not contain credentials or whitespace.")
    if parsed.query:
        raise _catalog_error(source, f"{field} must not contain a query string.")
    if parsed.fragment and not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", parsed.fragment):
        raise _catalog_error(source, f"{field} contains an unsafe fragment identifier.")
    hostname = parsed.hostname or ""
    if not hostname:
        raise _catalog_error(source, f"{field} must contain a public host name.")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        lowered_host = hostname.casefold().rstrip(".")
        if (
            "." not in lowered_host
            or lowered_host == "localhost"
            or lowered_host.endswith(
                (".localhost", ".local", ".internal", ".lan", ".invalid", ".test", ".example")
            )
        ):
            raise _catalog_error(source, f"{field} must use a public host name.")
    else:
        # The canonical public-source syntax deliberately uses DNS names so
        # the machine-readable schema can enforce the same boundary.  IP
        # literals (including global documentation addresses) are not stable
        # public provenance identifiers and are rejected here as well.
        raise _catalog_error(source, f"{field} must use a public DNS host name, not an IP literal.")
    safe_reference, changed = redact_sensitive_text(source_reference)
    if changed or safe_reference != source_reference:
        raise _catalog_error(source, f"{field} must not contain credential-like URL parameters.")


def _catalog_metadata_defaults(
    reference_data: dict[str, object],
    *,
    source: str,
) -> dict[str, str]:
    raw_metadata = reference_data.get("definition_metadata")
    if raw_metadata is None:
        return dict(CATALOG_DEFAULT_METADATA)
    if not isinstance(raw_metadata, dict):
        raise _catalog_error(source, "definition_metadata must be an object.")
    for key, allowed in CATALOG_METADATA_ALLOWED.items():
        raw_values = raw_metadata.get(key)
        if not isinstance(raw_values, list) or not raw_values:
            raise _catalog_error(source, f"definition_metadata.{key} must be a non-empty string array.")
        values = set()
        for index, value in enumerate(raw_values):
            item = _validate_catalog_string(
                value,
                source=source,
                field=f"definition_metadata.{key}[{index}]",
            )
            values.add(item)
        if values != set(allowed):
            raise _catalog_error(
                source,
                f"definition_metadata.{key} must match the supported metadata vocabulary.",
            )
    raw_default = raw_metadata.get("default")
    if not isinstance(raw_default, dict):
        raise _catalog_error(source, "definition_metadata.default must be an object.")
    defaults: dict[str, str] = {}
    for key in CATALOG_METADATA_KEYS:
        value = _validate_catalog_string(
            raw_default.get(key),
            source=source,
            field=f"definition_metadata.default.{key}",
        )
        if value not in CATALOG_METADATA_ALLOWED[key]:
            raise _catalog_error(source, f"definition_metadata.default.{key} is not supported: {value}")
        defaults[key] = value
    source_reference = raw_default.get("source_reference", CATALOG_DEFAULT_METADATA["source_reference"])
    defaults["source_reference"] = _validate_catalog_string(
        source_reference,
        source=source,
        field="definition_metadata.default.source_reference",
    )
    expected_profile = CATALOG_METADATA_PROFILES.get(defaults["source_type"])
    if expected_profile is None or any(
        defaults.get(key) != expected_profile.get(key)
        for key in ("definition_status", "reliability")
    ):
        raise _catalog_error(source, "definition_metadata.default uses an invalid metadata combination.")
    if defaults["source_type"] not in PUBLIC_SOURCE_TYPES and defaults["source_reference"] != expected_profile.get(
        "source_reference", ""
    ):
        raise _catalog_error(source, "definition_metadata.default.source_reference is not neutral.")
    if defaults["source_type"] in PUBLIC_SOURCE_TYPES:
        raise _catalog_error(source, "definition_metadata.default cannot use a public source type.")
    return defaults


def _normalize_item_metadata(
    item: dict[str, object],
    *,
    defaults: dict[str, str],
    source: str,
    name: str,
) -> dict[str, object]:
    raw_source_type = item.get("source_type")
    if raw_source_type is None or (isinstance(raw_source_type, str) and not raw_source_type.strip()):
        source_type = defaults["source_type"]
    else:
        source_type = _validate_catalog_string(
            raw_source_type,
            source=source,
            field=f"files[{name}].source_type",
        )
    if source_type not in CATALOG_METADATA_ALLOWED["source_type"]:
        raise _catalog_error(source, f"files[{name}].source_type is not supported: {source_type}")
    profile = CATALOG_METADATA_PROFILES[source_type]
    normalized: dict[str, object] = {}
    for key in ("definition_status", "reliability"):
        raw_value = item.get(key)
        if raw_value is None or (isinstance(raw_value, str) and not raw_value.strip()):
            value = profile[key]
        else:
            value = _validate_catalog_string(
                raw_value,
                source=source,
                field=f"files[{name}].{key}",
            )
        if value not in CATALOG_METADATA_ALLOWED[key] or value != profile[key]:
            raise _catalog_error(source, f"files[{name}] has an invalid {key}/{source_type} combination.")
        normalized[key] = value

    raw_reference = item.get("source_reference")
    if raw_reference is None or (isinstance(raw_reference, str) and not raw_reference.strip()):
        source_reference = profile.get("source_reference", defaults["source_reference"])
    else:
        source_reference = _validate_catalog_string(
            raw_reference,
            source=source,
            field=f"files[{name}].source_reference",
        )
    if source_type in PUBLIC_SOURCE_TYPES:
        _validate_public_source_reference(
            source_reference,
            source=source,
            field=f"files[{name}].source_reference",
        )
        revision = _validate_catalog_string(
            item.get("source_revision"),
            source=source,
            field=f"files[{name}].source_revision",
        )
        if len(revision) > 256:
            raise _catalog_error(source, f"files[{name}].source_revision exceeds 256 characters.")
        safe_revision, revision_changed = redact_sensitive_text(revision)
        if revision_changed or safe_revision != revision:
            raise _catalog_error(
                source,
                f"files[{name}].source_revision must not contain credential-like assignments.",
            )
        normalized["source_revision"] = revision
    elif source_reference != profile.get("source_reference", defaults["source_reference"]):
        raise _catalog_error(source, f"files[{name}].source_reference must be neutral for {source_type}.")
    if "source_revision" in item and source_type not in PUBLIC_SOURCE_TYPES:
        raise _catalog_error(
            source,
            f"files[{name}].source_revision is only valid for an independently verifiable public source.",
        )
    normalized["source_type"] = source_type
    normalized["source_reference"] = source_reference
    return normalized


def _normalize_reference_data(
    reference_data: dict[str, object],
    *,
    source: str,
) -> dict[str, object]:
    if not isinstance(reference_data, dict):
        raise _catalog_error(source, "catalog root must be an object.")
    if "files" not in reference_data or "rules" not in reference_data:
        raise _catalog_error(source, "catalog must contain files and rules arrays.")
    files = reference_data.get("files")
    rules = reference_data.get("rules")
    if not isinstance(files, list) or not isinstance(rules, list):
        raise _catalog_error(source, "catalog files and rules must be arrays.")
    defaults = _catalog_metadata_defaults(reference_data, source=source)

    names: set[str] = set()
    normalized_files: list[dict[str, object]] = []
    for index, raw_item in enumerate(files):
        if not isinstance(raw_item, dict):
            raise _catalog_error(source, f"files[{index}] must be an object.")
        raw_name = _validate_catalog_string(raw_item.get("name"), source=source, field=f"files[{index}].name")
        if raw_name in names:
            raise _catalog_error(source, f"duplicate log name: {raw_name}")
        names.add(raw_name)
        raw_paths = raw_item.get("paths")
        if not isinstance(raw_paths, list) or not raw_paths:
            raise _catalog_error(source, f"files[{raw_name}].paths must be a non-empty array.")
        normalized_paths = [
            _validate_catalog_path(path, source=source, field=f"files[{raw_name}].paths[{path_index}]")
            for path_index, path in enumerate(raw_paths)
        ]
        if len(set(normalized_paths)) != len(normalized_paths):
            raise _catalog_error(source, f"files[{raw_name}].paths contains duplicates.")
        raw_keywords = raw_item.get("keywords", [])
        normalized_keywords = _validate_catalog_string_list(
            raw_keywords,
            source=source,
            field=f"files[{raw_name}].keywords",
            allow_empty=False,
        )
        normalized_evidence_keywords = _validate_catalog_string_list(
            raw_item.get("evidence_keywords", []),
            source=source,
            field=f"files[{raw_name}].evidence_keywords",
            allow_empty=True,
        )
        purpose = _validate_catalog_string(
            raw_item.get("purpose"),
            source=source,
            field=f"files[{raw_name}].purpose",
        )
        component = _validate_catalog_string(
            raw_item.get("component"),
            source=source,
            field=f"files[{raw_name}].component",
        )
        parser_name = raw_item.get("structured_parser", "")
        if not isinstance(parser_name, str):
            raise _catalog_error(source, f"files[{raw_name}].structured_parser must be a string when present.")
        if parser_name:
            parser_name = _validate_catalog_string(
                parser_name,
                source=source,
                field=f"files[{raw_name}].structured_parser",
            )
            if parser_name not in SUPPORTED_STRUCTURED_PARSERS:
                raise _catalog_error(source, f"files[{raw_name}] uses unknown structured parser: {parser_name}")
        scan_mode = raw_item.get("scan_mode", "text")
        scan_mode = _validate_catalog_string(
            scan_mode,
            source=source,
            field=f"files[{raw_name}].scan_mode",
        )
        if scan_mode not in CATALOG_SCAN_MODES:
            raise _catalog_error(source, f"files[{raw_name}] uses unsupported scan_mode: {scan_mode}")
        if scan_mode == "metadata_only" and parser_name:
            raise _catalog_error(
                source,
                f"files[{raw_name}] cannot combine metadata_only with a structured parser.",
            )
        raw_coverage_class = raw_item.get("coverage_class")
        if raw_coverage_class is None:
            coverage_class = "explicit_opaque" if scan_mode == "metadata_only" else "semantic"
        else:
            coverage_class = _validate_catalog_string(
                raw_coverage_class,
                source=source,
                field=f"files[{raw_name}].coverage_class",
            )
        if coverage_class not in CATALOG_COVERAGE_CLASSES:
            raise _catalog_error(
                source,
                f"files[{raw_name}] uses unsupported coverage_class: {coverage_class}",
            )
        if coverage_class != "semantic" and scan_mode != "metadata_only":
            raise _catalog_error(
                source,
                f"files[{raw_name}] {coverage_class} coverage requires scan_mode metadata_only.",
            )
        include_rotations = raw_item.get("include_rotations", True)
        if not isinstance(include_rotations, bool):
            raise _catalog_error(
                source,
                f"files[{raw_name}].include_rotations must be a boolean.",
            )
        metadata = _normalize_item_metadata(raw_item, defaults=defaults, source=source, name=raw_name)
        raw_semantic_level = raw_item.get("semantic_level")
        if raw_semantic_level is None:
            if coverage_class == "generic_fallback":
                semantic_level = "path_only"
            elif parser_name:
                semantic_level = "structure"
            elif str(metadata.get("source_type", "")) in {"validated_bundle_structure", "bundle_local"}:
                semantic_level = "path_only"
            else:
                semantic_level = "purpose"
        else:
            semantic_level = _validate_catalog_string(
                raw_semantic_level,
                source=source,
                field=f"files[{raw_name}].semantic_level",
            )
        if semantic_level not in CATALOG_SEMANTIC_LEVELS:
            raise _catalog_error(
                source,
                f"files[{raw_name}] uses unsupported semantic_level: {semantic_level}",
            )

        raw_artifact_format = raw_item.get("artifact_format")
        if raw_artifact_format is None:
            artifact_format = _infer_artifact_format(normalized_paths, scan_mode=scan_mode)
        else:
            artifact_format = _validate_catalog_string(
                raw_artifact_format,
                source=source,
                field=f"files[{raw_name}].artifact_format",
            )
        if artifact_format not in CATALOG_ARTIFACT_FORMATS:
            raise _catalog_error(
                source,
                f"files[{raw_name}] uses unsupported artifact_format: {artifact_format}",
            )

        raw_route_mode = raw_item.get("route_mode")
        if raw_route_mode is None:
            route_mode = "automatic" if coverage_class == "semantic" else "explicit_only"
        else:
            route_mode = _validate_catalog_string(
                raw_route_mode,
                source=source,
                field=f"files[{raw_name}].route_mode",
            )
        if route_mode not in CATALOG_ROUTE_MODES:
            raise _catalog_error(source, f"files[{raw_name}] uses unsupported route_mode: {route_mode}")

        raw_sensitivity = raw_item.get("sensitivity", "ordinary")
        sensitivity = _validate_catalog_string(
            raw_sensitivity,
            source=source,
            field=f"files[{raw_name}].sensitivity",
        )
        if sensitivity not in CATALOG_SENSITIVITY_LEVELS:
            raise _catalog_error(source, f"files[{raw_name}] uses unsupported sensitivity: {sensitivity}")

        if semantic_level == "path_only" and route_mode == "automatic":
            raise _catalog_error(source, f"files[{raw_name}] path_only definitions cannot route automatically.")
        if artifact_format in CATALOG_HIGH_RISK_FORMATS and scan_mode != "metadata_only":
            raise _catalog_error(
                source,
                f"files[{raw_name}] {artifact_format} artifacts require scan_mode metadata_only.",
            )
        if sensitivity in {"configuration_sensitive", "highly_sensitive"} and scan_mode != "metadata_only":
            raise _catalog_error(
                source,
                f"files[{raw_name}] {sensitivity} artifacts require scan_mode metadata_only.",
            )
        if semantic_level == "diagnostic" and str(metadata.get("source_type", "")) not in PUBLIC_SOURCE_TYPES:
            raise _catalog_error(
                source,
                f"files[{raw_name}] diagnostic semantics require an independently verifiable public source.",
            )
        normalized_item = dict(raw_item)
        normalized_item.update(metadata)
        normalized_item["name"] = raw_name
        normalized_item["paths"] = normalized_paths
        normalized_item["keywords"] = normalized_keywords
        normalized_item["evidence_keywords"] = normalized_evidence_keywords
        normalized_item["purpose"] = purpose
        normalized_item["component"] = component
        normalized_item["structured_parser"] = parser_name
        normalized_item["scan_mode"] = scan_mode
        normalized_item["coverage_class"] = coverage_class
        normalized_item["semantic_level"] = semantic_level
        normalized_item["artifact_format"] = artifact_format
        normalized_item["route_mode"] = route_mode
        normalized_item["sensitivity"] = sensitivity
        normalized_item["include_rotations"] = include_rotations
        normalized_files.append(normalized_item)

    normalized_rules: list[dict[str, object]] = []
    for index, raw_rule in enumerate(rules):
        if not isinstance(raw_rule, dict):
            raise _catalog_error(source, f"rules[{index}] must be an object.")
        keywords = _validate_catalog_string_list(
            raw_rule.get("match_keywords"),
            source=source,
            field=f"rules[{index}].match_keywords",
            allow_empty=False,
        )
        includes = _validate_catalog_string_list(
            raw_rule.get("include"),
            source=source,
            field=f"rules[{index}].include",
            allow_empty=False,
        )
        primary = _validate_catalog_string_list(
            raw_rule.get("primary", []),
            source=source,
            field=f"rules[{index}].primary",
            allow_empty=True,
        )
        undefined = [name for name in [*includes, *primary] if name not in names]
        if undefined:
            raise _catalog_error(source, f"rules[{index}] references undefined logs: {', '.join(undefined)}")
        if any(name not in includes for name in primary):
            raise _catalog_error(source, f"rules[{index}].primary entries must also appear in include.")
        normalized_rule = dict(raw_rule)
        normalized_rule["match_keywords"] = keywords
        normalized_rule["include"] = includes
        normalized_rule["primary"] = primary
        normalized_rules.append(normalized_rule)
    return {**reference_data, "files": normalized_files, "rules": normalized_rules}


def definition_metadata(
    item: dict[str, object],
    *,
    defaults: dict[str, str] | None = None,
) -> dict[str, str]:
    """Return complete, neutral provenance for a normalized catalog entry."""
    fallback = defaults or CATALOG_DEFAULT_METADATA
    source_type = item.get("source_type")
    if not isinstance(source_type, str) or not source_type:
        source_type = fallback["source_type"]
    profile = CATALOG_METADATA_PROFILES.get(source_type, CATALOG_METADATA_PROFILES[fallback["source_type"]])
    result = {
        "definition_status": str(item.get("definition_status") or profile["definition_status"]),
        "source_type": source_type,
        "source_reference": str(
            item.get("source_reference") or profile.get("source_reference", fallback["source_reference"])
        ),
        "reliability": str(item.get("reliability") or profile["reliability"]),
    }
    if item.get("source_revision"):
        result["source_revision"] = str(item["source_revision"])
    return result

def load_reference_data(reference_path: pathlib.Path | None = None) -> dict[str, object]:
    path = reference_path or pathlib.Path(__file__).resolve().parents[1] / "references" / "logs.json"
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleAnalysisError("reference_load_failed", f"Failed to load log reference {path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise BundleAnalysisError("reference_load_failed", f"Log reference {path} must contain a JSON object.")
    return normalize_reference_data(parsed, source=str(path))


def validate_reference_data(reference_data: dict[str, object], *, source: str = "log reference") -> None:
    """Validate the executable catalog before it influences path selection."""
    _normalize_reference_data(reference_data, source=source)


def normalize_reference_data(
    reference_data: dict[str, object],
    *,
    source: str = "log reference",
) -> dict[str, object]:
    """Validate and return a copy with complete neutral provenance metadata."""
    return _normalize_reference_data(reference_data, source=source)


def add_bundle_component_hints(
    bundle_root: pathlib.Path,
    reference_data: dict[str, object],
    *,
    problem: str = "",
    max_hints: int = DEFAULT_MAX_BUNDLE_COMPONENT_HINTS,
    max_discovery_entries: int = MAX_COMPONENT_HINT_DISCOVERY_ENTRIES,
    discovery_budget: PathDiscoveryBudget | None = None,
) -> dict[str, object]:
    if max_hints < 1:
        raise BundleAnalysisError("invalid_request", "max_hints must be positive.")
    if max_discovery_entries < 1:
        raise BundleAnalysisError("invalid_request", "max_discovery_entries must be positive.")
    # This helper is also used directly by callers and tests.  Do not assume
    # that the caller has already normalized the executable catalog: malformed
    # path/rule metadata must fail closed before it can influence discovery.
    reference_data = normalize_reference_data(reference_data, source="provided log reference")
    files = reference_data["files"]
    if not isinstance(files, list):
        raise _catalog_error("log reference", "catalog files must be an array.")
    copied_files = list(files)
    known_directory_paths = {
        path
        for item in copied_files
        if isinstance(item, dict)
        for path in item.get("paths", [])
        if isinstance(path, str) and path.endswith("/")
    }
    appdump = bundle_root / "dump_info" / "AppDump"
    if os.path.lexists(appdump):
        ensure_bundle_path(bundle_root, appdump)
    matched_component_count = 0
    matched_components: list[pathlib.Path] = []
    retained_components: list[pathlib.Path] = []
    invalid_directory_count = 0
    limit_reasons: set[str] = set()
    budget = discovery_budget or PathDiscoveryBudget()
    starting_entries = budget.entries_examined
    starting_limit_hits = budget.limit_hits
    hint_entries_examined = 0

    def safe_component_name(name: str) -> bool:
        """Return whether *name* can safely become a catalog path/keyword.

        AppDump directory names are untrusted bundle data.  Besides glob
        metacharacters, leading/trailing whitespace and overlong names would
        either alter matching semantics or make the generated catalog fail
        validation on its second normalization pass.
        """
        if not name or name != name.strip() or len(name) > 480:
            return False
        if name in {".", ".."}:
            return False
        if any(char in name for char in ("*", "?", "[", "]", "\\", "\x00")):
            return False
        return not any(ord(char) < 0x20 or ord(char) == 0x7F for char in name)

    if appdump.is_dir():
        try:
            entries = os.scandir(appdump)
        except OSError as exc:
            raise BundleAnalysisError("bundle_layout_invalid", f"Failed to inspect {appdump}: {exc}") from exc
        with entries:
            for entry in entries:
                # Component discovery is enrichment. Keep a small local cap
                # so a huge AppDump cannot consume the entire analysis-level
                # path budget before core LogDump paths are considered.
                if hint_entries_examined >= max_discovery_entries:
                    limit_reasons.add("hint_entry_limit")
                    break
                if not budget.consume():
                    limit_reasons.add("shared_entry_limit")
                    break
                hint_entries_examined += 1
                component = pathlib.Path(entry.path)
                if entry.is_symlink():
                    raise BundleAnalysisError(
                        "bundle_layout_invalid",
                        f"Bundle contains symbolic links; first entry: {component}",
                    )
                if not entry.is_dir(follow_symlinks=False):
                    continue
                component_name = entry.name
                if not safe_component_name(component_name):
                    # Dynamic component paths are catalog globs later. Reject
                    # names that could change that interpretation instead of
                    # broadening the scan.
                    invalid_directory_count += 1
                    limit_reasons.add("invalid_component_name")
                    continue
                component_terms = {
                    component_name,
                    component_name.replace("_", " "),
                    component_name.replace("_", "-"),
                }
                if problem and not any(
                    term_matches(problem, term)
                    or (len(compact_text(term)) >= 4 and compact_text(term) in compact_text(problem))
                    for term in component_terms
                    if term
                ):
                    continue
                matched_component_count += 1
                matched_components.append(component)
        # Keep output deterministic after the bounded directory pass.
        matched_components.sort(key=lambda path: path.name)
        retained_components = matched_components[:max_hints]
        if matched_component_count > max_hints:
            limit_reasons.add("hint_count_limit")
        for component in retained_components:
            component_name = component.name
            directory = f"dump_info/AppDump/{component_name}/"
            if directory in known_directory_paths:
                # Static catalog hints describe a possible product layout.
                # Mark the matching definition only after this exact directory
                # has been observed in the current validated bundle, so a
                # combined rule+component problem can add real component
                # evidence without making catalog-only routing noisy.
                copied_files = [
                    {
                        **item,
                        "bundle_observed": True,
                    }
                    if isinstance(item, dict) and directory in item.get("paths", [])
                    else item
                    for item in copied_files
                ]
                continue
            copied_files.append(
                {
                    "name": f"bundle_component_{component_name}",
                    "paths": [directory],
                    "component": component_name,
                    "purpose": "bundle-local AppDump component routing hint",
                    "definition_status": "bundle_local_routing",
                    "source_type": "bundle_local",
                    "source_reference": "bundle-local observed directory",
                    "reliability": "local_only",
                    "semantic_level": "purpose",
                    "artifact_format": "unknown",
                    "route_mode": "automatic",
                    "sensitivity": "ordinary",
                    "bundle_observed": True,
                    "keywords": list(
                        dict.fromkeys(
                            (
                                component_name,
                                component_name.replace("_", " "),
                                component_name.replace("_", "-"),
                            )
                        )
                    ),
                }
            )
    if budget.limit_hits > starting_limit_hits:
        limit_reasons.add("shared_entry_limit")
    discovery_complete = not limit_reasons
    return {
        **reference_data,
        "files": copied_files,
        "bundle_component_hint_discovery": {
            "matched_directory_count": matched_component_count,
            "retained_directory_count": len(retained_components),
            "entries_examined": hint_entries_examined,
            "complete": discovery_complete,
            "truncated": not discovery_complete,
            "limit": max_hints,
            "entry_limit": max_discovery_entries,
        },
        # Internal diagnostics are consumed by analyze_bundle and omitted
        # from the public output contract.
        "_bundle_component_hint_diagnostics": {
            "limit_reasons": sorted(limit_reasons),
            "invalid_directory_count": invalid_directory_count,
            "shared_entries_examined": budget.entries_examined,
            "shared_entry_limit": budget.max_entries,
            "entries_examined_before": starting_entries,
        },
    }


def normalize_text(value: str) -> str:
    return value.casefold()


ASCII_TERM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/-]*$")


def term_matches(text: str, term: str) -> bool:
    """Match an ASCII word/phrase without matching it inside another word.

    Chinese (and mixed Chinese/English) phrases intentionally retain
    substring matching because word boundaries are not meaningful there.
    """
    normalized_text = normalize_text(text)
    normalized_term = normalize_text(term).strip()
    if not normalized_term:
        return False
    if ASCII_TERM_RE.fullmatch(normalized_term):
        pattern = rf"(?<![A-Za-z0-9_]){re.escape(normalized_term)}(?![A-Za-z0-9_])"
        return re.search(pattern, normalized_text) is not None
    return normalized_term in normalized_text


def explicit_filename_match(name: str, problem: str) -> bool:
    """Return true only when a problem appears to name a concrete file.

    Bare words such as ``login`` are often symptoms, not file names.  They
    must not overpower a rule's ordered/primary log choices.
    """
    if not term_matches(problem, name):
        return False
    return any(char in name for char in (".", "_", "-", "/"))


def evidence_term_matches(text: str, term: str) -> bool:
    aliases = EVIDENCE_TERM_ALIASES.get(normalize_text(term), (term,))
    return any(term_matches(text, alias) for alias in aliases)


def normalize_timestamp_text(value: str) -> str:
    normalized = value.strip().replace(" ", "T", 1)
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    timezone_match = re.search(r"([+-]\d{2})(\d{2})$", normalized)
    if timezone_match and ":" not in timezone_match.group(0):
        normalized = f"{normalized[:-5]}{timezone_match.group(1)}:{timezone_match.group(2)}"
    return normalized


def parse_analysis_timezone(value: str) -> dt.tzinfo | None:
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.casefold() in {"utc", "z"}:
        return dt.timezone.utc
    offset_match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", candidate)
    if offset_match:
        hours = int(offset_match.group(2))
        minutes = int(offset_match.group(3))
        if hours > 23 or minutes > 59:
            raise BundleAnalysisError("invalid_request", f"Invalid analysis timezone offset: {value}")
        delta = dt.timedelta(hours=hours, minutes=minutes)
        if offset_match.group(1) == "-":
            delta = -delta
        return dt.timezone(delta)
    try:
        return ZoneInfo(candidate)
    except ZoneInfoNotFoundError as exc:
        raise BundleAnalysisError(
            "invalid_request",
            f"Unknown analysis timezone '{value}'; use UTC, ±HH:MM, or an IANA timezone.",
        ) from exc


def parse_log_datetime(line: str, *, default_timezone: dt.tzinfo | None = None) -> dt.datetime | None:
    match = LOG_TIMESTAMP_RE.search(line)
    if not match:
        return None
    try:
        parsed = dt.datetime.fromisoformat(normalize_timestamp_text(match.group("timestamp")))
        if parsed.tzinfo is None and default_timezone is not None:
            parsed = parsed.replace(tzinfo=default_timezone)
        return parsed
    except ValueError:
        return None


def parse_log_timestamp(line: str, *, default_timezone: dt.tzinfo | None = None) -> str:
    parsed = parse_log_datetime(line, default_timezone=default_timezone)
    return parsed.isoformat() if parsed else ""


def parse_analysis_time_bound(
    value: str,
    *,
    label: str,
    default_timezone: dt.tzinfo | None = None,
) -> dt.datetime | None:
    candidate = value.strip()
    if not candidate:
        return None
    date_only = re.fullmatch(r"\d{4}-\d{2}-\d{2}", candidate) is not None
    if date_only:
        if "until" in label.casefold():
            candidate = f"{candidate}T23:59:59.999999"
        else:
            candidate = f"{candidate}T00:00:00"
    try:
        parsed = dt.datetime.fromisoformat(normalize_timestamp_text(candidate))
        if parsed.tzinfo is None and default_timezone is not None:
            parsed = parsed.replace(tzinfo=default_timezone)
        return parsed
    except ValueError as exc:
        raise BundleAnalysisError("invalid_request", f"{label} 时间格式无效，请使用 YYYY-MM-DDTHH:MM:SS。") from exc


def comparable_datetime(value: dt.datetime, *, default_timezone: dt.tzinfo | None = None) -> dt.datetime:
    if value.tzinfo is None:
        if default_timezone is None:
            return value
        value = value.replace(tzinfo=default_timezone)
    return value.astimezone(dt.timezone.utc)


def datetimes_share_domain(left: dt.datetime, right: dt.datetime) -> bool:
    return (left.tzinfo is None) == (right.tzinfo is None)


def compare_datetimes(
    left: dt.datetime,
    right: dt.datetime,
    *,
    default_timezone: dt.tzinfo | None = None,
) -> int | None:
    if default_timezone is None and not datetimes_share_domain(left, right):
        return None
    normalized_left = comparable_datetime(left, default_timezone=default_timezone)
    normalized_right = comparable_datetime(right, default_timezone=default_timezone)
    return (normalized_left > normalized_right) - (normalized_left < normalized_right)


def datetime_sort_value(
    value: dt.datetime | None,
    *,
    default_timezone: dt.tzinfo | None = None,
) -> float:
    if value is None:
        return float("-inf")
    if value.tzinfo is None:
        if default_timezone is None:
            # A deterministic pseudo-epoch for ordering within the
            # unspecified local-time domain.  It must not be compared with an
            # aware timestamp unless the caller supplies an analysis timezone.
            return value.replace(tzinfo=dt.timezone.utc).timestamp()
        value = value.replace(tzinfo=default_timezone)
    return comparable_datetime(value, default_timezone=default_timezone).timestamp()


def evidence_timestamp_sort_value(
    evidence_line: dict[str, object],
    *,
    default_timezone: dt.tzinfo | None = None,
) -> float:
    timestamp = evidence_line.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp:
        return float("-inf")
    try:
        parsed = dt.datetime.fromisoformat(normalize_timestamp_text(timestamp))
    except ValueError:
        return float("-inf")
    return datetime_sort_value(parsed, default_timezone=default_timezone)


def evidence_time_domain(evidence_line: dict[str, object]) -> str:
    timestamp = evidence_line.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp:
        return "unknown"
    try:
        parsed = dt.datetime.fromisoformat(normalize_timestamp_text(timestamp))
    except ValueError:
        return "unknown"
    return "timezone_aware" if parsed.tzinfo is not None else "timezone_unspecified"


def compact_text(value: str) -> str:
    return re.sub(r"[\s_\-]+", "", normalize_text(value))


def is_generic_file_keyword(keyword: str) -> bool:
    return normalize_text(keyword) in GENERIC_FILE_KEYWORDS


def build_component_hint_tokens(value: str) -> set[str]:
    normalized = normalize_text(value)
    tokens = {normalized, compact_text(value)}
    for part in re.split(r"[_\-]+", normalized):
        if part:
            tokens.add(part)
    return {token for token in tokens if token}


def score_path_for_problem(path: pathlib.Path, problem: str) -> int:
    parts = path.parts
    normalized_problem = normalize_text(problem)
    compact_problem = compact_text(problem)
    score = 0
    if "AppDump" in parts:
        index = parts.index("AppDump")
        if index + 1 < len(parts) - 1:
            for token in build_component_hint_tokens(parts[index + 1]):
                if term_matches(normalized_problem, token) or (
                    len(token) >= 4 and token in compact_problem
                ):
                    score = max(score, max(8, len(token)))
    return score


def rotation_rank(name: str) -> int:
    match = re.search(r"\.(\d+)(?:\.gz)?$", name)
    if not match:
        return 0
    try:
        return int(match.group(1))
    except ValueError:
        # Python may reject an untrusted filename with an enormous digit
        # string.  Treat it as an out-of-budget rotation instead of letting
        # path discovery fail with a raw ValueError.
        return MAX_ROTATED_FILE_CANDIDATES


def is_low_signal_line(line: str) -> bool:
    stripped_line = line.strip()
    normalized_line = normalize_text(stripped_line)
    if not stripped_line or normalized_line in LOW_SIGNAL_LINES:
        return True
    if any(normalized_line.startswith(prefix) for prefix in LOW_SIGNAL_PREFIXES):
        return True
    return any(substring in normalized_line for substring in LOW_SIGNAL_SUBSTRINGS)


def score_evidence_line(evidence_line: dict[str, object], match_terms: list[str], path: pathlib.Path, problem: str) -> int:
    line = str(evidence_line.get("line", ""))
    normalized_line = normalize_text(line)
    normalized_problem = normalize_text(problem)
    normalized_terms = [normalize_text(term) for term in match_terms if term]
    fallback_terms = ["error", "failed", "exception", "failure", "失败", "告警", "crash"]
    score = score_path_for_problem(path, problem)
    score += sum(10 for term in normalized_terms if term in normalized_line)
    for signals, phrases, bonus in PRIORITY_PHRASE_RULES:
        normalized_signals = [normalize_text(signal) for signal in signals if signal]
        if not (
            any(signal in normalized_problem for signal in normalized_signals)
            or any(signal in term for term in normalized_terms for signal in normalized_signals)
        ):
            continue
        normalized_phrases = [normalize_text(phrase) for phrase in phrases if phrase]
        if any(phrase in normalized_line for phrase in normalized_phrases):
            score += bonus
    if any(term in normalized_line for term in fallback_terms):
        score += 8
    if re.search(r"\d{4}-\d{2}-\d{2}", line):
        score += 4
    if "getmanagedobjects" in normalized_line:
        score -= 2
    return score


def strip_internal_evidence_fields(evidence_lines: list[dict[str, object]]) -> list[dict[str, object]]:
    return [{key: value for key, value in evidence_line.items() if not key.startswith("_")} for evidence_line in evidence_lines]


def sort_evidence_lines(evidence_lines: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(
        evidence_lines,
        key=lambda evidence_line: (
            float(evidence_line.get("_timestamp_sort", float("-inf"))),
            int(evidence_line.get("line_number", 0)),
        ),
        reverse=True,
    )


def select_logs_for_problem(problem: str, reference_data: dict[str, object], *, max_files: int) -> list[dict[str, object]]:
    reference_data = normalize_reference_data(reference_data)
    metadata_defaults = _catalog_metadata_defaults(reference_data, source="log reference")
    normalized_problem = normalize_text(problem)
    files = reference_data.get("files", [])
    rules = reference_data.get("rules", [])
    if not isinstance(files, list):
        files = []
    if not isinstance(rules, list):
        rules = []

    file_map: dict[str, dict[str, object]] = {}
    component_directory_hints: list[dict[str, object]] = []
    component_target_paths: dict[str, list[str]] = {}
    scores: dict[str, int] = {}
    order_rank: dict[str, int] = {}
    matched_keywords: dict[str, set[str]] = {}
    matched_rules: dict[str, list[list[str]]] = {}
    matched_primary: set[str] = set()

    for item in files:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if isinstance(name, str) and name:
            paths = [path for path in item.get("paths", []) if isinstance(path, str) and path]
            if paths and all(path.endswith("/") for path in paths):
                component_directory_hints.append(item)
                continue
            file_map[name] = item

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rule_keywords = [keyword for keyword in rule.get("match_keywords", []) if isinstance(keyword, str) and keyword]
        includes = [name for name in rule.get("include", []) if isinstance(name, str) and name]
        primary = {name for name in rule.get("primary", []) if isinstance(name, str) and name}
        current_matches = [keyword for keyword in rule_keywords if term_matches(normalized_problem, keyword)]
        if not current_matches:
            continue
        for include_index, name in enumerate(includes):
            item = file_map.get(name)
            if item is None or item.get("route_mode") != "automatic":
                continue
            order_rank.setdefault(name, len(order_rank))
            order_bonus = max(0, len(includes) - include_index)
            if name in primary:
                matched_primary.add(name)
            scores[name] = (
                scores.get(name, 0)
                + 100
                + len(current_matches) * 10
                + (100 if name in primary else 0)
                + order_bonus
            )
            matched_keywords.setdefault(name, set()).update(current_matches)
            matched_rules.setdefault(name, []).append(current_matches)

    rule_matched = bool(matched_rules)

    for hint in component_directory_hints:
        hint_keywords = [keyword for keyword in hint.get("keywords", []) if isinstance(keyword, str) and keyword]
        current_matches = [
            keyword
            for keyword in hint_keywords
            if term_matches(normalized_problem, keyword)
            or (len(compact_text(keyword)) >= 4 and compact_text(keyword) in compact_text(problem))
        ]
        if not current_matches:
            continue
        for name in APPDUMP_COMPONENT_EVIDENCE_LOGS:
            if name not in file_map:
                continue
            if file_map[name].get("route_mode") != "automatic":
                continue
            if rule_matched and name not in scores and not hint.get("bundle_observed"):
                continue
            scores[name] = scores.get(name, 0) + 40 + len(current_matches) * 5
            matched_keywords.setdefault(name, set()).update(current_matches)
            targeted = component_target_paths.setdefault(name, [])
            for directory in hint.get("paths", []):
                if not isinstance(directory, str) or not directory.endswith("/"):
                    continue
                candidate = f"{directory}{name}"
                if candidate not in targeted:
                    targeted.append(candidate)

    for name, item in file_map.items():
        route_mode = str(item.get("route_mode", "automatic"))
        if route_mode != "never" and explicit_filename_match(name, normalized_problem):
            scores[name] = scores.get(name, 0) + 200
        keywords = [keyword for keyword in item.get("keywords", []) if isinstance(keyword, str) and keyword]
        current_matches = [
            keyword
            for keyword in keywords
            if route_mode == "automatic"
            and not rule_matched
            and not is_generic_file_keyword(keyword)
            and term_matches(normalized_problem, keyword)
        ]
        if len(current_matches) >= 2:
            scores[name] = scores.get(name, 0) + len(current_matches)
            matched_keywords.setdefault(name, set()).update(current_matches)

    # A rule's ``primary`` declaration is an ordering contract, not just a
    # small relevance hint.  When several broad rules match, non-primary logs
    # can otherwise accumulate a larger numeric score than the primary tier.
    # Raise that tier only as much as needed so the exposed score remains
    # consistent with the returned order.
    primary_scores = [scores[name] for name in matched_primary if name in scores]
    non_primary_scores = [score for name, score in scores.items() if name not in matched_primary]
    if primary_scores and non_primary_scores:
        primary_boost = max(0, max(non_primary_scores) - min(primary_scores) + 1)
        if primary_boost:
            for name in matched_primary:
                if name in scores:
                    scores[name] += primary_boost

    selected: list[dict[str, object]] = []
    for name, score in sorted(
        scores.items(),
        key=lambda entry: (
            entry[0] not in matched_primary,
            -entry[1],
            order_rank.get(entry[0], 10**6),
            entry[0],
        ),
    ):
        item = file_map[name]
        routing_basis: list[str] = []
        if matched_rules.get(name):
            routing_basis.append("problem_rule")
        if name in component_target_paths:
            routing_basis.append("bundle_local_component")
        if explicit_filename_match(name, normalized_problem):
            routing_basis.append("explicit_filename")
        if matched_keywords.get(name) and "problem_rule" not in routing_basis:
            routing_basis.append("definition_keyword")
        selected.append(
            {
                "name": name,
                "score": score,
                "paths": component_target_paths.get(name) or item.get("paths", []),
                "purpose": item.get("purpose", ""),
                "component": item.get("component", ""),
                **definition_metadata(item, defaults=metadata_defaults),
                "keywords": [keyword for keyword in item.get("keywords", []) if isinstance(keyword, str) and keyword],
                "evidence_keywords": [
                    keyword
                    for keyword in item.get("evidence_keywords", [])
                    if isinstance(keyword, str) and keyword
                ],
                "matched_keywords": sorted(matched_keywords.get(name, set())),
                "matched_rules": matched_rules.get(name, []),
                "routing_basis": routing_basis,
                "routing_reliability": "local_only" if "bundle_local_component" in routing_basis else "heuristic",
                "structured_parser": item.get("structured_parser", ""),
                "scan_mode": item.get("scan_mode", "text"),
                **catalog_dimensions(item),
                "_include_rotations": item.get("include_rotations", True),
            }
        )
        if len(selected) >= max_files:
            break
    return selected


EXPLICIT_BUNDLE_PATH_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Za-z0-9][A-Za-z0-9._/-]{1,479})"
)
EXPLICIT_PATH_CORRELATION_TERMS = ("关联", "对照", "结合", "correlat")
EXPLICIT_FILE_QUERY_TERMS = (
    "检查",
    "查看",
    "读取",
    "打开",
    "核对",
    "inspect",
    "check",
    "read",
    "show",
    "open",
)


def _empty_component_hint_discovery() -> dict[str, object]:
    return {
        "matched_directory_count": 0,
        "retained_directory_count": 0,
        "entries_examined": 0,
        "complete": True,
        "truncated": False,
        "limit": DEFAULT_MAX_BUNDLE_COMPONENT_HINTS,
        "entry_limit": MAX_COMPONENT_HINT_DISCOVERY_ENTRIES,
    }


def _explicit_bundle_path_tokens(problem: str) -> set[str]:
    """Return concrete-looking filename/path tokens from a user problem."""
    normalized_problem = problem.casefold()
    if any(term in normalized_problem for term in EXPLICIT_PATH_CORRELATION_TERMS):
        return set()
    has_explicit_file_intent = any(term in normalized_problem for term in EXPLICIT_FILE_QUERY_TERMS)
    tokens: set[str] = set()
    for match in EXPLICIT_BUNDLE_PATH_TOKEN_RE.finditer(problem):
        candidate = match.group(0).strip("./").casefold()
        if not candidate:
            continue
        basename = candidate.rsplit("/", 1)[-1]
        rotationless_basename = re.sub(r"\.\d+(?:\.gz)?$", "", basename)
        suffix = rotationless_basename.rsplit(".", 1)[-1] if "." in rotationless_basename else ""
        has_file_extension = bool(suffix and any("a" <= char <= "z" for char in suffix))
        if candidate.startswith("dump_info/") or has_file_extension:
            tokens.add(candidate)
            continue
        explicit_numeric_rotation = (
            rotationless_basename != basename
            and "." not in rotationless_basename
            and any("a" <= char <= "z" for char in rotationless_basename)
        )
        if has_explicit_file_intent and (
            any(char in basename for char in ("_", "-"))
            or explicit_numeric_rotation
        ):
            tokens.add(candidate)
    return tokens


def _problem_names_bundle_file(relative_path: str, tokens: set[str]) -> bool:
    normalized_path = relative_path.casefold()
    basename = pathlib.PurePosixPath(relative_path).name.casefold()
    for token in tokens:
        if token == basename or token == normalized_path:
            return True
        if "/" in token and normalized_path.endswith(f"/{token}"):
            return True
    return False


def _discover_explicit_bundle_files(
    bundle_root: pathlib.Path,
    problem: str,
    *,
    discovery_budget: PathDiscoveryBudget,
    directory_index: _PathDirectoryIndex,
) -> tuple[list[pathlib.Path], dict[str, object]]:
    """Find physical bundle files explicitly named by the problem, bounded."""
    tokens = _explicit_bundle_path_tokens(problem)
    diagnostics: dict[str, object] = {
        "complete": True,
        "truncated": False,
        "entries_examined": 0,
        "entry_limit": discovery_budget.max_entries,
        "retained_path_count": 0,
        "path_limit": MAX_PATH_EXPANSION_RESULTS,
        "limit_reasons": [],
    }
    if not tokens:
        return [], diagnostics

    start_entries = discovery_budget.entries_examined
    dump_info = bundle_root / "dump_info"
    if not os.path.lexists(dump_info):
        return [], diagnostics
    ensure_bundle_path(bundle_root, dump_info)
    stack = [dump_info]
    matches: list[pathlib.Path] = []
    limit_reasons: set[str] = set()
    while stack:
        directory = stack.pop()
        entries, complete = directory_index.scan(directory)
        if not complete:
            limit_reasons.add("entry_limit")
        child_directories: list[pathlib.Path] = []
        for entry in entries:
            if entry.is_dir:
                child_directories.append(entry.path)
                continue
            if not entry.is_file:
                continue
            relative_path = entry.path.relative_to(bundle_root).as_posix()
            if not _problem_names_bundle_file(relative_path, tokens):
                continue
            if len(matches) >= MAX_PATH_EXPANSION_RESULTS:
                limit_reasons.add("path_limit")
                continue
            matches.append(entry.path)
        # Reverse sorted input so the iterative traversal remains lexical.
        stack.extend(reversed(child_directories))

    matches.sort(key=lambda path: path.relative_to(bundle_root).as_posix())
    diagnostics.update(
        {
            "complete": not limit_reasons,
            "truncated": bool(limit_reasons),
            "entries_examined": discovery_budget.entries_examined - start_entries,
            "retained_path_count": len(matches),
            "limit_reasons": sorted(limit_reasons),
        }
    )
    return matches, diagnostics


def _catalog_pattern_matches_path(
    pattern: str,
    relative_path: str,
    *,
    include_rotations: bool,
    bundle_root: pathlib.Path,
) -> bool:
    pattern_parts = pathlib.PurePosixPath(pattern).parts
    path_parts = pathlib.PurePosixPath(relative_path).parts

    def segment_match(candidate_parts: tuple[str, ...]) -> bool:
        return len(pattern_parts) == len(candidate_parts) and all(
            fnmatch.fnmatchcase(candidate, expected)
            for expected, candidate in zip(pattern_parts, candidate_parts)
        )

    if segment_match(path_parts):
        return True
    if not include_rotations or not path_parts:
        return False
    base_name = re.sub(r"\.\d+(?:\.gz)?$", "", path_parts[-1])
    if base_name == path_parts[-1]:
        return False
    base_parts = (*path_parts[:-1], base_name)
    if not segment_match(base_parts):
        return False
    if any(char in pattern for char in "*?["):
        base_path = bundle_root.joinpath(*base_parts)
        return base_path.is_file() and not base_path.is_symlink()
    return True


def _definition_for_bundle_path(
    bundle_root: pathlib.Path,
    reference_data: dict[str, object],
    relative_path: str,
) -> dict[str, object] | None:
    matches: list[tuple[int, int, dict[str, object]]] = []
    files = reference_data.get("files", [])
    if not isinstance(files, list):
        return None
    for catalog_index, item in enumerate(files):
        if not isinstance(item, dict):
            continue
        patterns = [path for path in item.get("paths", []) if isinstance(path, str)]
        if not patterns or all(path.endswith("/") for path in patterns):
            continue
        if not any(
            _catalog_pattern_matches_path(
                pattern,
                relative_path,
                include_rotations=bool(item.get("include_rotations", True)),
                bundle_root=bundle_root,
            )
            for pattern in patterns
        ):
            continue
        precedence = CATALOG_COVERAGE_PRECEDENCE[str(item.get("coverage_class", "semantic"))]
        matches.append((precedence, -catalog_index, item))
    if not matches:
        return None
    return max(matches, key=lambda match: (match[0], match[1]))[2]


def select_explicit_bundle_files(
    bundle_root: pathlib.Path,
    problem: str,
    reference_data: dict[str, object],
    *,
    max_files: int,
    discovery_budget: PathDiscoveryBudget,
    directory_index: _PathDirectoryIndex,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Bind an explicit filename query to exact physical bundle paths."""
    paths, diagnostics = _discover_explicit_bundle_files(
        bundle_root,
        problem,
        discovery_budget=discovery_budget,
        directory_index=directory_index,
    )
    if not paths:
        return [], diagnostics

    metadata_defaults = _catalog_metadata_defaults(reference_data, source="log reference")
    basename_counts: dict[str, int] = {}
    for path in paths:
        basename_counts[path.name.casefold()] = basename_counts.get(path.name.casefold(), 0) + 1

    selected: list[dict[str, object]] = []
    for path in paths:
        relative_path = path.relative_to(bundle_root).as_posix()
        definition = _definition_for_bundle_path(bundle_root, reference_data, relative_path)
        if definition is None or definition.get("route_mode") == "never":
            continue
        display_name = (
            relative_path
            if basename_counts[path.name.casefold()] > 1
            else path.name
        )
        selected.append(
            {
                "name": display_name,
                "score": 1000,
                "paths": [relative_path],
                "purpose": definition.get("purpose", ""),
                "component": definition.get("component", ""),
                **definition_metadata(definition, defaults=metadata_defaults),
                "keywords": [
                    keyword
                    for keyword in definition.get("keywords", [])
                    if isinstance(keyword, str) and keyword
                ],
                "evidence_keywords": [
                    keyword
                    for keyword in definition.get("evidence_keywords", [])
                    if isinstance(keyword, str) and keyword
                ],
                "matched_keywords": [],
                "matched_rules": [],
                "routing_basis": ["explicit_bundle_path"],
                "routing_reliability": "local_only",
                "structured_parser": definition.get("structured_parser", ""),
                "scan_mode": definition.get("scan_mode", "text"),
                **catalog_dimensions(definition),
                "_include_rotations": False,
            }
        )
        if len(selected) >= max_files:
            break
    return selected, diagnostics


def _iter_rotated_file_candidates_bounded(
    target: pathlib.Path,
    *,
    max_candidates: int = MAX_ROTATED_FILE_CANDIDATES,
    bundle_root: pathlib.Path | None = None,
    discovery_budget: PathDiscoveryBudget | None = None,
    directory_index: _PathDirectoryIndex | None = None,
    limit_reasons: set[str] | None = None,
) -> tuple[list[pathlib.Path], bool]:
    reasons = limit_reasons if limit_reasons is not None else set()
    if max_candidates <= 0:
        reasons.add("rotation_limit")
        return [], True
    parent = target.parent
    if "\x00" in str(target):
        raise BundleAnalysisError("bundle_layout_invalid", "Bundle path contains a NUL character.")
    if bundle_root is not None:
        root = pathlib.Path(bundle_root).resolve(strict=True)
        lexical_parent = parent if parent.is_absolute() else root / parent
        try:
            relative_parent = lexical_parent.relative_to(root)
        except ValueError as exc:
            raise BundleAnalysisError(
                "bundle_layout_invalid",
                f"Bundle path escapes the bundle root: {target}",
            ) from exc
        if ".." in relative_parent.parts:
            raise BundleAnalysisError(
                "bundle_layout_invalid",
                f"Bundle path escapes the bundle root: {target}",
            )
        parent = lexical_parent
    if not os.path.lexists(parent):
        return [], False
    if parent.is_symlink():
        raise BundleAnalysisError(
            "bundle_layout_invalid",
            f"Bundle contains symbolic links; first entry: {parent}",
        )
    if bundle_root is not None:
        parent = ensure_bundle_path(bundle_root, parent)
    if directory_index is not None:
        budget = directory_index.discovery_budget
        if discovery_budget is not None and discovery_budget is not budget:
            raise BundleAnalysisError(
                "invalid_request",
                "directory_index and discovery_budget must share the same budget.",
            )
        index = directory_index
    else:
        budget = discovery_budget or PathDiscoveryBudget()
        # ``rotation_entries`` validates paths relative to the index root.  A
        # direct helper call may provide a relative target; resolve the parent
        # before handing it to the index so ``root/root`` is never constructed.
        if bundle_root is None:
            parent = pathlib.Path(parent).resolve(strict=True)
        index_root = bundle_root or parent
        index = _PathDirectoryIndex(index_root, budget)

    entries, scan_complete = index.rotation_entries(parent, target.name)
    if not scan_complete:
        reasons.add("entry_limit")
    prefix = f"{target.name}."
    candidates: list[tuple[int, str, pathlib.Path]] = []
    for entry in entries:
        if not entry.is_file:
            continue
        name = entry.name
        if name == target.name:
            candidates.append((0, name, entry.path))
            continue
        if not name.startswith(prefix):
            continue
        suffix = name[len(prefix) :]
        if not re.fullmatch(r"\d+(?:\.gz)?", suffix):
            continue
        candidates.append((rotation_rank(name), name, entry.path))

    if len(candidates) > max_candidates:
        reasons.add("rotation_limit")
    selected = heapq.nsmallest(max_candidates, candidates, key=lambda item: (item[0], item[1]))
    truncated = bool(reasons)
    return [path for _, _, path in selected], truncated


def iter_rotated_file_candidates(
    target: pathlib.Path,
    *,
    max_candidates: int = MAX_ROTATED_FILE_CANDIDATES,
) -> list[pathlib.Path]:
    """Return a bounded, newest-first set of a file and numeric rotations."""
    candidates, _ = _iter_rotated_file_candidates_bounded(target, max_candidates=max_candidates)
    return candidates


def _iter_bounded_glob(
    bundle_root: pathlib.Path,
    pattern: str,
    *,
    discovery_budget: PathDiscoveryBudget,
    directory_index: _PathDirectoryIndex | None = None,
    limit_reasons: set[str] | None = None,
):
    """Expand a non-recursive POSIX glob while charging every inspected entry."""
    parts = pattern.rstrip("/").split("/")
    reasons = limit_reasons if limit_reasons is not None else set()
    if directory_index is not None:
        if directory_index.discovery_budget is not discovery_budget:
            raise BundleAnalysisError(
                "invalid_request",
                "directory_index and discovery_budget must share the same budget.",
            )
        directory_cache = directory_index
    else:
        directory_cache = _PathDirectoryIndex(bundle_root, discovery_budget)

    def walk(directory: pathlib.Path, segment_index: int):
        directory = ensure_bundle_path(bundle_root, directory)
        segment = parts[segment_index]
        last = segment_index == len(parts) - 1
        wildcard = any(char in segment for char in "*?[")
        if not wildcard:
            candidate = directory / segment
            if not os.path.lexists(candidate):
                return
            if not discovery_budget.consume():
                reasons.add("entry_limit")
                return
            if candidate.is_symlink():
                raise BundleAnalysisError(
                    "bundle_layout_invalid",
                    f"Bundle contains symbolic links; first entry: {candidate}",
                )
            safe_candidate = ensure_bundle_path(bundle_root, candidate)
            if last:
                yield safe_candidate
            elif safe_candidate.is_dir():
                yield from walk(safe_candidate, segment_index + 1)
            return

        entries, scan_complete = directory_cache.scan(directory)
        if not scan_complete:
            reasons.add("entry_limit")
        for entry in entries:
            if not fnmatch.fnmatchcase(entry.name, segment):
                continue
            candidate = entry.path
            if last:
                yield ensure_bundle_path(bundle_root, candidate)
            elif entry.is_dir:
                yield from walk(candidate, segment_index + 1)

    if not parts or parts == [""]:
        return
    yield from walk(bundle_root, 0)


def _expand_log_paths_bounded(
    bundle_root: pathlib.Path,
    path_patterns: list[object],
    *,
    max_paths: int = MAX_PATH_EXPANSION_RESULTS,
    max_entries: int = MAX_PATH_DISCOVERY_ENTRIES,
    diagnostics: dict[str, object] | None = None,
    discovery_budget: PathDiscoveryBudget | None = None,
    directory_index: _PathDirectoryIndex | None = None,
    include_rotations: bool = True,
) -> tuple[list[pathlib.Path], bool]:
    status = diagnostics if diagnostics is not None else {}
    limit_reasons: set[str] = set()
    if max_paths <= 0:
        truncated = bool(path_patterns)
        if truncated:
            limit_reasons.add("path_limit")
        status.update(
            {
                "complete": not truncated,
                "truncated": truncated,
                "entries_examined": 0,
                "entry_limit": max_entries,
                "retained_path_count": 0,
                "path_limit": max_paths,
                "limit_reasons": sorted(limit_reasons),
            }
        )
        return [], truncated
    if max_entries <= 0:
        if path_patterns:
            limit_reasons.add("entry_limit")
        status.update(
            {
                "complete": not bool(path_patterns),
                "truncated": bool(path_patterns),
                "entries_examined": 0,
                "entry_limit": max_entries,
                "retained_path_count": 0,
                "path_limit": max_paths,
                "limit_reasons": sorted(limit_reasons),
            }
        )
        return [], bool(path_patterns)
    matches: list[pathlib.Path] = []
    seen: set[pathlib.Path] = set()
    if directory_index is not None:
        budget = directory_index.discovery_budget
        if discovery_budget is not None and discovery_budget is not budget:
            raise BundleAnalysisError(
                "invalid_request",
                "directory_index and discovery_budget must share the same budget.",
            )
        index = directory_index
    else:
        budget = discovery_budget or PathDiscoveryBudget(max_entries=max_entries)
        index = _PathDirectoryIndex(bundle_root, budget)
    starting_entries = budget.entries_examined
    starting_limit_hits = budget.limit_hits

    def add_candidate(candidate: pathlib.Path) -> bool:
        try:
            safe_candidate = ensure_bundle_path(bundle_root, candidate)
        except BundleAnalysisError:
            raise
        if safe_candidate in seen:
            return True
        if len(matches) >= max_paths:
            limit_reasons.add("path_limit")
            return False
        matches.append(safe_candidate)
        seen.add(safe_candidate)
        return True

    for raw_pattern in path_patterns:
        if not isinstance(raw_pattern, str) or not raw_pattern:
            continue
        if include_rotations and not any(char in raw_pattern for char in "*?["):
            exact_target = bundle_root / raw_pattern
            candidates, _ = _iter_rotated_file_candidates_bounded(
                exact_target,
                bundle_root=bundle_root,
                discovery_budget=budget,
                directory_index=index,
                limit_reasons=limit_reasons,
            )
            for candidate in candidates:
                if not add_candidate(candidate):
                    break
            continue

        glob_candidates: list[pathlib.Path] = []
        glob_count = 0
        for candidate in _iter_bounded_glob(
            bundle_root,
            raw_pattern,
            discovery_budget=budget,
            directory_index=index,
            limit_reasons=limit_reasons,
        ):
            glob_count += 1
            if glob_count > MAX_GLOB_MATCHES_PER_PATTERN:
                limit_reasons.add("glob_match_limit")
                break
            glob_candidates.append(candidate)
        glob_candidates.sort(key=lambda path: str(path))
        for candidate in glob_candidates:
            if not candidate.is_file():
                continue
            if include_rotations:
                rotated, _ = _iter_rotated_file_candidates_bounded(
                    candidate,
                    bundle_root=bundle_root,
                    discovery_budget=budget,
                    directory_index=index,
                    limit_reasons=limit_reasons,
                )
            else:
                rotated = []
            for path in rotated or [candidate]:
                if not add_candidate(path):
                    break
            if "path_limit" in limit_reasons:
                break
        if "path_limit" in limit_reasons:
            break
    if budget.limit_hits > starting_limit_hits:
        limit_reasons.add("entry_limit")
    truncated = bool(limit_reasons)
    status.update(
        {
            "complete": not truncated,
            "truncated": truncated,
            "entries_examined": budget.entries_examined - starting_entries,
            "total_entries_examined": budget.entries_examined,
            "entry_limit": budget.max_entries,
            "retained_path_count": len(matches),
            "path_limit": max_paths,
            "limit_reasons": sorted(limit_reasons),
        }
    )
    return matches, truncated


def expand_log_paths(bundle_root: pathlib.Path, path_patterns: list[object]) -> list[pathlib.Path]:
    matches, _ = _expand_log_paths_bounded(bundle_root, path_patterns)
    return matches


def _append_diagnostic(diagnostics: dict[str, object], key: str, value: dict[str, object]) -> None:
    bucket = diagnostics.setdefault(key, [])
    if isinstance(bucket, list):
        bucket.append(value)


def _decode_log_line(raw_line: bytes, diagnostics: dict[str, object], line_number: int) -> str:
    try:
        return raw_line.decode("utf-8")
    except UnicodeDecodeError:
        try:
            decoded = raw_line.decode("gb18030")
        except UnicodeDecodeError:
            decoded = raw_line.decode("utf-8", errors="replace")
            _append_diagnostic(
                diagnostics,
                "warnings",
                {
                    "code": "decode_replacement_used",
                    "line_number": line_number,
                    "message": "Line was not valid UTF-8 or GB18030; replacement characters were used.",
                },
            )
            return decoded
        encodings = diagnostics.setdefault("fallback_encodings", [])
        if isinstance(encodings, list) and "gb18030" not in encodings:
            encodings.append("gb18030")
            _append_diagnostic(
                diagnostics,
                "warnings",
                {
                    "code": "encoding_fallback_used",
                    "line_number": line_number,
                    "message": "GB18030 decoding was used for non-UTF-8 log content.",
                },
            )
        return decoded


def _remove_boundary_nul_padding(raw_line: bytes) -> tuple[bytes, int] | None:
    """Remove a bounded, line-boundary NUL padding gap from a text line.

    Some rotated logs are fixed-size records with zero-filled gaps between
    otherwise valid text records.  A NUL run is recoverable only when it is a
    sufficiently long prefix or suffix of one complete logical line (or the
    whole line) and the remaining bytes decode as UTF-8/GB18030.  Embedded or
    short NUL runs remain a fail-closed binary signal.
    """
    newline = b""
    body = raw_line
    if body.endswith(b"\n"):
        newline = b"\n"
        body = body[:-1]
        if body.endswith(b"\r"):
            newline = b"\r\n"
            body = body[:-1]
    if b"\x00" not in body:
        return raw_line, 0
    if not body:
        return raw_line, 0

    first_text = next((index for index, value in enumerate(body) if value != 0), None)
    if first_text is None:
        if len(body) >= MIN_NUL_PADDING_BYTES:
            return newline, len(body)
        return None
    last_text = len(body) - 1
    while last_text >= 0 and body[last_text] == 0:
        last_text -= 1
    prefix_count = first_text
    suffix_count = len(body) - last_text - 1
    if (
        max(prefix_count, suffix_count) < MIN_NUL_PADDING_BYTES
        or 0 < prefix_count < MIN_NUL_PADDING_BYTES
        or 0 < suffix_count < MIN_NUL_PADDING_BYTES
    ):
        return None
    core = body[first_text : last_text + 1]
    if b"\x00" in core or any(value < 0x20 and value != 0x09 or value == 0x7F for value in core):
        return None
    try:
        core.decode("utf-8")
    except UnicodeDecodeError:
        try:
            core.decode("gb18030")
        except UnicodeDecodeError:
            return None
    return core + newline, prefix_count + suffix_count


def iter_text_lines(
    path: pathlib.Path,
    *,
    max_bytes: int = DEFAULT_ANALYSIS_MAX_BYTES_PER_FILE,
    max_line_bytes: int = DEFAULT_ANALYSIS_MAX_LINE_BYTES,
    diagnostics: dict[str, object] | None = None,
):
    status = diagnostics if diagnostics is not None else {}
    status.setdefault("path", str(path))
    status.setdefault("bytes_read", 0)
    status.setdefault("lines_read", 0)
    status.setdefault("errors", [])
    status.setdefault("warnings", [])
    if max_bytes <= 0:
        _append_diagnostic(
            status,
            "warnings",
            {"code": "scan_byte_limit_reached", "message": "No scan-byte budget remained for this file."},
        )
        return
    if max_line_bytes <= 0:
        _append_diagnostic(
            status,
            "errors",
            {"code": "invalid_line_limit", "message": "Maximum line size must be positive."},
        )
        return

    opener = gzip.open if path.suffix == ".gz" else open
    bytes_read = 0
    logical_line_number = 0
    scan_truncated = False
    truncation_reported = False

    def mark_partial_line() -> None:
        nonlocal scan_truncated, truncation_reported
        scan_truncated = True
        if not truncation_reported:
            _append_diagnostic(
                status,
                "warnings",
                {
                    "code": "partial_line_discarded",
                    "line_number": logical_line_number,
                    "message": "The byte limit ended inside a log line; the partial line was discarded.",
                },
            )
            truncation_reported = True

    try:
        with opener(path, "rb") as handle:
            while bytes_read < max_bytes:
                remaining = max_bytes - bytes_read
                raw_line = handle.readline(min(max_line_bytes + 1, remaining))
                if not raw_line:
                    break
                logical_line_number += 1
                bytes_read += len(raw_line)
                line_complete = raw_line.endswith(b"\n")
                contains_nul = b"\x00" in raw_line

                # A bounded read can end in the middle of a line. Probe one
                # byte to distinguish an exact EOF from content that remains
                # beyond the scan budget; the probe is deliberately not
                # counted against the budget.
                if not line_complete and bytes_read >= max_bytes:
                    continuation = handle.read(1)
                    if continuation:
                        mark_partial_line()
                        break

                if contains_nul and line_complete:
                    sanitized_line = _remove_boundary_nul_padding(raw_line)
                    if sanitized_line is not None and sanitized_line[1] > 0:
                        raw_line, removed_bytes = sanitized_line
                        contains_nul = False
                        padding_only = not raw_line.rstrip(b"\r\n")
                        _append_diagnostic(
                            status,
                            "warnings",
                            {
                                "code": NUL_PADDING_WARNING_CODE,
                                "line_number": logical_line_number,
                                "bytes_removed": removed_bytes,
                                "message": (
                                    "A zero-filled padding line was skipped while retaining surrounding text."
                                    if padding_only
                                    else (
                                        "A complete text line contained a bounded NUL padding gap at its boundary; "
                                        "the padding was removed and the line was retained."
                                    )
                                ),
                            },
                        )
                        if padding_only:
                            continue
                    if contains_nul:
                        _append_diagnostic(
                            status,
                            "errors",
                            {
                                "code": "binary_content_detected",
                                "line_number": logical_line_number,
                                "message": "NUL bytes indicate that this candidate is not a text log.",
                            },
                        )
                        break

                if len(raw_line) > max_line_bytes:
                    # Discard the rest of an overlong logical line in bounded
                    # chunks. If the byte budget cuts it off, never expose the
                    # partial fragment as evidence.
                    while not line_complete and bytes_read < max_bytes:
                        remaining = max_bytes - bytes_read
                        continuation = handle.readline(min(max_line_bytes + 1, remaining))
                        if not continuation:
                            line_complete = True
                            break
                        bytes_read += len(continuation)
                        contains_nul = contains_nul or b"\x00" in continuation
                        line_complete = continuation.endswith(b"\n")
                    if not line_complete and bytes_read >= max_bytes:
                        continuation = handle.read(1)
                        if continuation:
                            mark_partial_line()
                    if contains_nul:
                        _append_diagnostic(
                            status,
                            "errors",
                            {
                                "code": "binary_content_detected",
                                "line_number": logical_line_number,
                                "message": "NUL bytes indicate that this candidate is not a text log.",
                            },
                        )
                        break
                    _append_diagnostic(
                        status,
                        "warnings",
                        {
                            "code": "line_too_long",
                            "line_number": logical_line_number,
                            "message": f"Line exceeded the {max_line_bytes}-byte scan limit and was skipped.",
                        },
                    )
                    if scan_truncated:
                        break
                    continue

                yield logical_line_number, _decode_log_line(raw_line, status, logical_line_number).rstrip("\r\n")

            # readline() can stop exactly at the byte boundary after a
            # complete line. Check whether another byte exists so regular
            # files receive the same truncation signal as gzip streams.
            if bytes_read >= max_bytes and not scan_truncated:
                continuation = handle.read(1)
                if continuation:
                    scan_truncated = True
            if scan_truncated:
                _append_diagnostic(
                    status,
                    "warnings",
                    {
                        "code": "file_scan_truncated",
                        "message": f"File scan stopped after {max_bytes} decompressed bytes.",
                    },
                )
    except (OSError, EOFError, zlib.error) as exc:
        _append_diagnostic(
            status,
            "errors",
            {
                "code": "log_read_failed",
                "message": f"Failed to read candidate log: {exc}",
            },
        )
    finally:
        status["bytes_read"] = bytes_read
        status["lines_read"] = logical_line_number


def collect_evidence_lines(
    file_path: pathlib.Path,
    *,
    match_terms: list[str],
    max_lines: int,
    since: dt.datetime | None = None,
    until: dt.datetime | None = None,
    diagnostics: dict[str, object] | None = None,
    max_bytes: int = DEFAULT_ANALYSIS_MAX_BYTES_PER_FILE,
    max_line_bytes: int = DEFAULT_ANALYSIS_MAX_LINE_BYTES,
    budget: ScanBudget | None = None,
    line_observer: Callable[..., None] | None = None,
    default_timezone: dt.tzinfo | None = None,
) -> list[dict[str, object]]:
    if max_lines <= 0:
        return []
    status = diagnostics if diagnostics is not None else {}
    effective_max_bytes = max_bytes
    if budget is not None:
        effective_max_bytes = min(effective_max_bytes, budget.remaining_bytes)
    normalized_terms = [normalize_text(term) for term in match_terms if term]
    fallback_terms = ["error", "failed", "exception", "failure", "失败", "告警", "crash"]
    strong_matches: list[dict[str, object]] = []
    keyword_matches: list[dict[str, object]] = []
    fallback_matches: list[dict[str, object]] = []
    match_counts = status.setdefault(
        "match_counts",
        {"direct_failure": 0, "problem_context": 0, "generic_failure": 0},
    )

    def retain_best(bucket: list[dict[str, object]], item: dict[str, object]) -> None:
        bucket.append(item)
        bucket.sort(
            key=lambda candidate: (
                float(candidate.get("_timestamp_sort", float("-inf"))),
                int(candidate.get("line_number", 0)),
            ),
            reverse=True,
        )
        if len(bucket) > max_lines:
            del bucket[max_lines:]

    for line_number, line in iter_text_lines(
        file_path,
        max_bytes=effective_max_bytes,
        max_line_bytes=max_line_bytes,
        diagnostics=status,
    ):
        safe_line, was_redacted = redact_sensitive_text(line)
        if is_low_signal_line(line):
            if line_observer is not None:
                line_observer(line_number, safe_line, False if (since or until) else True)
            continue
        stripped_line = line.strip()
        parsed_datetime = parse_log_datetime(stripped_line, default_timezone=default_timezone)
        in_time_window = True
        if since or until:
            in_time_window = parsed_datetime is not None
        if parsed_datetime is not None:
            if since is not None:
                comparison = compare_datetimes(parsed_datetime, since, default_timezone=default_timezone)
                if comparison is None:
                    in_time_window = False
                    _append_diagnostic(
                        status,
                        "warnings",
                        {
                            "code": "timezone_domain_mismatch",
                            "line_number": line_number,
                            "message": "Log timestamp and analysis window use different/unknown time domains.",
                        },
                    )
                elif comparison < 0:
                    in_time_window = False
            if until is not None and in_time_window:
                comparison = compare_datetimes(parsed_datetime, until, default_timezone=default_timezone)
                if comparison is None:
                    in_time_window = False
                    _append_diagnostic(
                        status,
                        "warnings",
                        {
                            "code": "timezone_domain_mismatch",
                            "line_number": line_number,
                            "message": "Log timestamp and analysis window use different/unknown time domains.",
                        },
                    )
                elif comparison > 0:
                    in_time_window = False
        if line_observer is not None:
            # Structured collectors need to retain a header, but must ignore
            # records outside an explicit incident window.
            line_observer(line_number, safe_line, in_time_window)
        if (since or until) and not in_time_window:
            continue
        normalized_line = normalize_text(stripped_line)
        has_keyword_match = any(evidence_term_matches(normalized_line, term) for term in normalized_terms)
        has_fallback_match = any(term_matches(normalized_line, term) for term in fallback_terms)
        safe_line = safe_line.strip()
        evidence_line = {
            "path": str(file_path),
            "line_number": line_number,
            "line": safe_line,
            "_timestamp_sort": datetime_sort_value(parsed_datetime),
        }
        if was_redacted:
            evidence_line["redacted"] = True
        if parsed_datetime is not None:
            evidence_line["timestamp"] = parsed_datetime.isoformat()

        if normalized_terms and has_keyword_match and has_fallback_match:
            evidence_line["match_class"] = "direct_failure"
            if isinstance(match_counts, dict):
                match_counts["direct_failure"] = int(match_counts.get("direct_failure", 0)) + 1
            retain_best(strong_matches, evidence_line)
            continue
        if normalized_terms and has_keyword_match:
            evidence_line["match_class"] = "problem_context"
            if isinstance(match_counts, dict):
                match_counts["problem_context"] = int(match_counts.get("problem_context", 0)) + 1
            retain_best(keyword_matches, evidence_line)
            continue
        if has_fallback_match:
            evidence_line["match_class"] = "generic_failure"
            if isinstance(match_counts, dict):
                match_counts["generic_failure"] = int(match_counts.get("generic_failure", 0)) + 1
            retain_best(fallback_matches, evidence_line)

    if budget is not None:
        budget.bytes_read += int(status.get("bytes_read", 0))
    if strong_matches:
        selected_class = "direct_failure"
        selected_matches = strong_matches
    elif keyword_matches:
        selected_class = "problem_context"
        selected_matches = keyword_matches
    else:
        selected_class = "generic_failure"
        selected_matches = fallback_matches
    observed_count = int(match_counts.get(selected_class, 0)) if isinstance(match_counts, dict) else len(selected_matches)
    if observed_count > len(selected_matches):
        for item in selected_matches:
            item["sampled_from_larger_set"] = True
    status["matched_line_count"] = sum(int(value) for value in match_counts.values()) if isinstance(match_counts, dict) else 0
    return strip_internal_evidence_fields(selected_matches)


def _line_in_analysis_window(
    parsed_datetime: dt.datetime,
    *,
    since: dt.datetime | None,
    until: dt.datetime | None,
    default_timezone: dt.tzinfo | None,
    diagnostics: dict[str, object],
    line_number: int,
) -> bool:
    """Apply the same explicit time-domain rules as primary evidence scans."""
    for bound, comparison_operator in ((since, "since"), (until, "until")):
        if bound is None:
            continue
        comparison = compare_datetimes(parsed_datetime, bound, default_timezone=default_timezone)
        if comparison is None:
            # Keep one bounded diagnostic per path rather than allowing a
            # mixed-timezone file to consume unbounded memory.
            marker = f"_correlation_{comparison_operator}_timezone_warning"
            if not diagnostics.get(marker):
                _append_diagnostic(
                    diagnostics,
                    "warnings",
                    {
                        "code": "timezone_domain_mismatch",
                        "line_number": line_number,
                        "message": "Log timestamp and analysis window use different/unknown time domains.",
                    },
                )
                diagnostics[marker] = True
            return False
        outside_window = comparison < 0 if comparison_operator == "since" else comparison > 0
        if outside_window:
            return False
    return True


def scan_correlation_candidates(
    bundle_root: pathlib.Path,
    anchors: list[dict[str, object]],
    paths: list[dict[str, object]],
    *,
    window_seconds: int,
    since: dt.datetime | None = None,
    until: dt.datetime | None = None,
    analysis_timezone: dt.tzinfo | None = None,
    budget: ScanBudget,
    max_bytes_per_file: int,
    max_line_bytes: int,
) -> tuple[dict[str, list[dict[str, object]]], dict[str, object]]:
    """Perform the bounded second pass used only for operation-event context.

    The pass deliberately returns candidate pointers separately from primary
    evidence.  This keeps candidate-only lines out of assessment and finding
    aggregation while still allowing a low ``max_lines`` primary sample to be
    supplemented around each operation anchor.
    """
    candidate_details: dict[str, list[dict[str, object]]] = {
        operation_event_anchor_id(anchor): [] for anchor in anchors[:MAX_EVENT_CORRELATIONS]
    }
    observed_by_anchor: dict[str, int] = {anchor_id: 0 for anchor_id in candidate_details}
    metadata: dict[str, object] = {
        "attempted": bool(anchors),
        "complete": True,
        "candidate_scan_complete": True,
        "window_seconds": window_seconds,
        "anchor_count_observed": len(anchors),
        "anchor_count_scanned": min(len(anchors), MAX_EVENT_CORRELATIONS),
        "candidate_count_observed": 0,
        "candidate_count_retained": 0,
        "max_candidates_per_anchor": MAX_EVENT_CANDIDATES_PER_ANCHOR,
        "eligible_path_count": 0,
        "scanned_path_count": 0,
        "scanned_bytes": 0,
        "truncated": False,
        "errors": [],
        "warnings": [],
    }
    if not anchors:
        metadata["reason"] = "no_operation_failure_anchor"
        return candidate_details, metadata

    # De-duplicate path records before the second pass.  ``expand_log_paths``
    # already enforces lexical/symlink boundaries; re-check immediately before
    # opening because an extracted tree may have changed between passes.
    unique_paths: list[dict[str, object]] = []
    seen_paths: set[pathlib.Path] = set()
    for record in paths:
        raw_path = record.get("path")
        if not isinstance(raw_path, pathlib.Path):
            continue
        if raw_path in seen_paths or record.get("log") == "operation.log":
            continue
        seen_paths.add(raw_path)
        unique_paths.append(record)

    metadata["eligible_path_count"] = len(unique_paths)
    if not unique_paths:
        metadata["reason"] = "no_other_selected_paths"
        return candidate_details, metadata

    anchors_to_scan = anchors[:MAX_EVENT_CORRELATIONS]
    for record in unique_paths:
        raw_path = record["path"]
        display_path = _portable_path(raw_path, bundle_root)
        try:
            file_path = ensure_bundle_path(bundle_root, raw_path)
        except BundleAnalysisError as exc:
            metadata["complete"] = False
            metadata["candidate_scan_complete"] = False
            metadata["truncated"] = True
            issue = {
                "path": display_path,
                "code": exc.code,
                "message": exc.redacted_message,
                "phase": "correlation_candidate_scan",
                "log": record.get("log", ""),
            }
            cast_errors = metadata["errors"]
            if isinstance(cast_errors, list):
                cast_errors.append(issue)
            continue

        if budget.remaining_bytes <= 0:
            metadata["complete"] = False
            metadata["candidate_scan_complete"] = False
            metadata["truncated"] = True
            issue = {
                "path": file_path.relative_to(bundle_root).as_posix(),
                "code": "correlation_scan_byte_limit_reached",
                "message": "No analysis byte budget remained for the correlation candidate pass.",
                "phase": "correlation_candidate_scan",
                "log": record.get("log", ""),
            }
            cast_warnings = metadata["warnings"]
            if isinstance(cast_warnings, list):
                cast_warnings.append(issue)
            # All subsequent paths would observe the same exhausted budget.
            break

        diagnostics: dict[str, object] = {}
        effective_max_bytes = min(max_bytes_per_file, budget.remaining_bytes)
        for line_number, line in iter_text_lines(
            file_path,
            max_bytes=effective_max_bytes,
            max_line_bytes=max_line_bytes,
            diagnostics=diagnostics,
        ):
            if is_low_signal_line(line):
                continue
            parsed_datetime = parse_log_datetime(line, default_timezone=analysis_timezone)
            if parsed_datetime is None:
                continue
            if not _line_in_analysis_window(
                parsed_datetime,
                since=since,
                until=until,
                default_timezone=analysis_timezone,
                diagnostics=diagnostics,
                line_number=line_number,
            ):
                continue
            safe_line, was_redacted = redact_sensitive_text(line)
            candidate = {
                "log": record.get("log", ""),
                "component": record.get("component", ""),
                "path": file_path.relative_to(bundle_root).as_posix(),
                "line_number": line_number,
                "line": safe_line.strip(),
                "timestamp": parsed_datetime.isoformat(),
                **(
                    {"source_revision": record["source_revision"]}
                    if record.get("source_revision")
                    else {}
                ),
            }
            if was_redacted:
                candidate["redacted"] = True
            for anchor in anchors_to_scan:
                anchor_id = operation_event_anchor_id(anchor)
                details = event_candidate_details(
                    anchor,
                    candidate,
                    window_seconds=window_seconds,
                )
                if details is None:
                    anchor_timestamp = str(anchor.get("timestamp", ""))
                    candidate_timestamp = str(candidate.get("timestamp", ""))
                    anchor_aware = bool(re.search(r"(?:Z|[+-]\d{2}:?\d{2})$", anchor_timestamp))
                    candidate_aware = bool(re.search(r"(?:Z|[+-]\d{2}:?\d{2})$", candidate_timestamp))
                    if anchor_aware != candidate_aware:
                        diagnostics["_correlation_domain_mismatch"] = True
                    continue
                observed_by_anchor[anchor_id] += 1
                bucket = candidate_details[anchor_id]
                bucket.append(details)
                bucket.sort(key=event_candidate_sort_key)
                if len(bucket) > MAX_EVENT_CANDIDATES_PER_ANCHOR:
                    del bucket[MAX_EVENT_CANDIDATES_PER_ANCHOR:]

        budget.bytes_read += int(diagnostics.get("bytes_read", 0) or 0)
        metadata["scanned_path_count"] = int(metadata["scanned_path_count"]) + 1
        metadata["scanned_bytes"] = int(metadata["scanned_bytes"]) + int(diagnostics.get("bytes_read", 0) or 0)
        for key in ("errors", "warnings"):
            entries = diagnostics.get(key, [])
            if not isinstance(entries, list):
                continue
            destination = metadata[key]
            if not isinstance(destination, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                issue = {
                    "path": file_path.relative_to(bundle_root).as_posix(),
                    **entry,
                    "phase": "correlation_candidate_scan",
                    "log": record.get("log", ""),
                }
                destination.append(issue)
                code = str(entry.get("code", ""))
                if key == "errors" or code in CORRELATION_SCAN_INCOMPLETE_WARNING_CODES:
                    metadata["complete"] = False
                    metadata["candidate_scan_complete"] = False
                    metadata["truncated"] = True
        if diagnostics.get("_correlation_domain_mismatch"):
            metadata["complete"] = False
            metadata["candidate_scan_complete"] = False
            metadata["truncated"] = True
            warnings = metadata["warnings"]
            if isinstance(warnings, list):
                warnings.append(
                    {
                        "path": file_path.relative_to(bundle_root).as_posix(),
                        "code": "correlation_timezone_domain_mismatch",
                        "message": "Timestamped candidate lines in an incompatible timezone domain were excluded.",
                        "phase": "correlation_candidate_scan",
                        "log": record.get("log", ""),
                    }
                )

    if int(metadata["scanned_path_count"]) < len(unique_paths):
        metadata["complete"] = False
        metadata["candidate_scan_complete"] = False
        metadata["truncated"] = True
    metadata["candidate_count_observed"] = sum(observed_by_anchor.values())
    metadata["candidate_count_retained"] = sum(len(bucket) for bucket in candidate_details.values())
    metadata["observed_by_anchor"] = observed_by_anchor
    metadata["retained_by_anchor"] = {
        anchor_id: len(bucket) for anchor_id, bucket in candidate_details.items()
    }
    return candidate_details, metadata


def _portable_path(path: object, bundle_root: pathlib.Path) -> str:
    candidate = pathlib.Path(str(path))
    try:
        return candidate.relative_to(bundle_root).as_posix()
    except ValueError:
        return str(candidate)


def timeline_time_domains(evidence: list[dict[str, object]]) -> set[str]:
    return {
        evidence_time_domain(item)
        for item in evidence
        if isinstance(item.get("timestamp"), str) and item.get("timestamp")
    }


def build_timeline(
    evidence: list[dict[str, object]],
    *,
    default_timezone: dt.tzinfo | None = None,
) -> list[dict[str, object]]:
    timestamped = [
        {**item, "time_domain": evidence_time_domain(item)}
        for item in evidence
        if isinstance(item.get("timestamp"), str) and item.get("timestamp")
    ]
    time_domains = {str(item.get("time_domain", "unknown")) for item in timestamped}
    domain_partitioned = default_timezone is None and len(time_domains) > 1
    domain_rank = {
        "timezone_aware": 0,
        "timezone_unspecified": 1,
        "unknown": 2,
    }
    timestamped.sort(
        key=lambda item: (
            (
                domain_rank.get(str(item.get("time_domain", "unknown")), 3)
                if domain_partitioned
                else 0
            ),
            evidence_timestamp_sort_value(item, default_timezone=default_timezone),
            str(item.get("path", "")),
            int(item.get("line_number", 0)),
        )
    )
    domain_sequences: dict[str, int] = {}
    result: list[dict[str, object]] = []
    for index, item in enumerate(timestamped, start=1):
        time_domain = str(item.get("time_domain", "unknown"))
        domain_sequences[time_domain] = domain_sequences.get(time_domain, 0) + 1
        result.append(
            {
                "sequence": index,
                "sequence_scope": "time_domain" if domain_partitioned else "global",
                "domain_sequence": domain_sequences[time_domain],
                **item,
            }
        )
    return result


def build_correlation_windows(
    timeline: list[dict[str, object]],
    *,
    window_seconds: int = DEFAULT_CORRELATION_WINDOW_SECONDS,
    default_timezone: dt.tzinfo | None = None,
) -> list[dict[str, object]]:
    if window_seconds <= 0:
        return []
    clusters: list[list[dict[str, object]]] = []
    current: list[dict[str, object]] = []
    previous_time: float | None = None
    previous_domain = ""
    for item in timeline:
        current_time = evidence_timestamp_sort_value(
            item,
            default_timezone=default_timezone,
        )
        current_domain = str(item.get("time_domain", evidence_time_domain(item)))
        comparable_domain = "normalized" if default_timezone is not None else current_domain
        if previous_time is None or (
            comparable_domain == previous_domain and current_time - previous_time <= window_seconds
        ):
            current.append(item)
        else:
            clusters.append(current)
            current = [item]
        previous_time = current_time
        previous_domain = comparable_domain
    if current:
        clusters.append(current)

    windows: list[dict[str, object]] = []
    for cluster in clusters:
        logs = sorted({str(item.get("log", "")) for item in cluster if item.get("log")})
        if len(logs) < 2:
            continue
        windows.append(
            {
                "start_timestamp": cluster[0].get("timestamp", ""),
                "end_timestamp": cluster[-1].get("timestamp", ""),
                "logs": logs,
                "evidence": [
                    {
                        "log": item.get("log", ""),
                        "path": item.get("path", ""),
                        "line_number": item.get("line_number", 0),
                        "timestamp": item.get("timestamp", ""),
                        **(
                            {"source_revision": item["source_revision"]}
                            if item.get("source_revision")
                            else {}
                        ),
                    }
                    for item in cluster[:8]
                ],
                "interpretation": "temporal_proximity_only",
                "time_domain": cluster[0].get("time_domain", "unknown"),
                "candidate_scan_complete": False,
            }
        )
    return windows[:20]


def analyze_bundle(
    bundle_root: pathlib.Path,
    problem: str,
    *,
    reference_data: dict[str, object] | None = None,
    max_files: int = DEFAULT_ANALYSIS_MAX_FILES,
    max_lines: int = DEFAULT_ANALYSIS_MAX_LINES,
    max_paths_per_log: int = DEFAULT_ANALYSIS_MAX_PATHS_PER_LOG,
    max_total_bytes: int = DEFAULT_ANALYSIS_MAX_TOTAL_BYTES,
    max_bytes_per_file: int = DEFAULT_ANALYSIS_MAX_BYTES_PER_FILE,
    max_line_bytes: int = DEFAULT_ANALYSIS_MAX_LINE_BYTES,
    max_scan_files: int = 512,
    max_discovery_entries: int = MAX_PATH_DISCOVERY_ENTRIES,
    since: dt.datetime | None = None,
    until: dt.datetime | None = None,
    analysis_timezone: dt.tzinfo | None = None,
) -> dict[str, object]:
    if min(max_files, max_lines, max_paths_per_log, max_total_bytes, max_bytes_per_file,
           max_line_bytes, max_scan_files, max_discovery_entries) < 1:
        raise BundleAnalysisError("invalid_request", "Analysis resource limits must be positive.")
    discovery_budget = PathDiscoveryBudget(max_entries=max_discovery_entries)
    # One index is shared by all selected log definitions.  This keeps a
    # repeated exact path or wildcard parent from being rescanned (and
    # charged) once per definition while preserving one analysis-wide budget.
    directory_index = _PathDirectoryIndex(bundle_root, discovery_budget)
    base_reference = (
        load_reference_data()
        if reference_data is None
        else normalize_reference_data(reference_data, source="provided log reference")
    )
    selected_logs, explicit_path_discovery = select_explicit_bundle_files(
        bundle_root,
        problem,
        base_reference,
        max_files=max_files,
        discovery_budget=discovery_budget,
        directory_index=directory_index,
    )
    if selected_logs:
        reference = base_reference
        component_hint_discovery = _empty_component_hint_discovery()
    else:
        reference = add_bundle_component_hints(
            bundle_root,
            base_reference,
            problem=problem,
            discovery_budget=discovery_budget,
        )
        reference = normalize_reference_data(reference, source="log reference with bundle-local hints")
        component_hint_discovery = reference.get("bundle_component_hint_discovery", {})
        selected_logs = select_logs_for_problem(problem, reference, max_files=max_files)
    analyzed_logs: list[dict[str, object]] = []
    total_existing_paths = 0
    total_evidence_lines = 0
    scanned_path_count = 0
    scan_errors: list[dict[str, object]] = []
    scan_warnings: list[dict[str, object]] = []
    scan_truncated = False
    budget = ScanBudget(max_total_bytes=max_total_bytes)
    structured_summaries: list[dict[str, object]] = []
    operation_anchors: list[dict[str, object]] = []
    observed_operation_anchor_count = 0
    unparseable_operation_anchor_count = 0
    operation_anchor_discovery_complete = True
    operation_log_selected = False
    correlation_candidate_paths: list[dict[str, object]] = []
    correlation_available_path_count = 0
    correlation_expected_path_count = 0
    correlation_paths_limited = False
    operation_anchor_scan_truncated = False
    primary_scanned_correlation_path_count = 0
    any_path_discovery_truncated = bool(explicit_path_discovery.get("truncated", False))

    component_hint_diagnostics = reference.get("_bundle_component_hint_diagnostics", {})
    hint_limit_reasons: set[str] = set()
    if isinstance(component_hint_diagnostics, dict):
        raw_reasons = component_hint_diagnostics.get("limit_reasons", [])
        if isinstance(raw_reasons, list):
            hint_limit_reasons = {
                str(reason)
                for reason in raw_reasons
                if str(reason)
                in {
                    "hint_entry_limit",
                    "hint_count_limit",
                    "shared_entry_limit",
                    "invalid_component_name",
                }
            }
    if isinstance(component_hint_discovery, dict) and not component_hint_discovery.get("complete", True):
        scan_truncated = True
        any_path_discovery_truncated = True
        # Keep capacity warnings machine-compatible with the previous code,
        # but make the triggering reason and its actual limit explicit.  An
        # unsafe component name is reported separately: it is not a capacity
        # problem and must not be presented as one.
        if not hint_limit_reasons:
            hint_limit_reasons.add("hint_count_limit")
        hint_limit_values = {
            "hint_entry_limit": int(component_hint_discovery.get("entry_limit", 0) or 0),
            "hint_count_limit": int(component_hint_discovery.get("limit", 0) or 0),
            "shared_entry_limit": int(
                component_hint_diagnostics.get("shared_entry_limit", discovery_budget.max_entries)
                if isinstance(component_hint_diagnostics, dict)
                else discovery_budget.max_entries
            ),
        }
        for reason in sorted(hint_limit_reasons):
            if reason == "invalid_component_name":
                scan_warnings.append(
                    {
                        "log": "bundle_component_hints",
                        "path": "dump_info/AppDump",
                        "code": "component_hint_invalid_name_skipped",
                        "message": (
                            "One or more AppDump component directories used characters that cannot be safely "
                            "turned into a routing path; those hints were skipped."
                        ),
                        "reason": reason,
                        "invalid_directory_count": int(
                            component_hint_diagnostics.get("invalid_directory_count", 0) or 0
                        )
                        if isinstance(component_hint_diagnostics, dict)
                        else 0,
                    }
                )
                continue
            scan_warnings.append(
                {
                    "log": "bundle_component_hints",
                    "path": "dump_info/AppDump",
                    "code": "component_hint_limit_reached",
                    "message": (
                        "Bundle-local AppDump component routing hints reached a bounded discovery limit."
                    ),
                    "reason": reason,
                    "matched_directory_count": int(component_hint_discovery.get("matched_directory_count", 0) or 0),
                    "retained_directory_count": int(component_hint_discovery.get("retained_directory_count", 0) or 0),
                    "entries_examined": int(component_hint_discovery.get("entries_examined", 0) or 0),
                    "limit": hint_limit_values.get(reason, int(component_hint_discovery.get("limit", 0) or 0)),
                    "entry_limit": int(component_hint_discovery.get("entry_limit", 0) or 0),
                }
            )

    if explicit_path_discovery.get("truncated", False):
        scan_truncated = True
        raw_reasons = explicit_path_discovery.get("limit_reasons", [])
        reasons = (
            [str(reason) for reason in raw_reasons if isinstance(reason, str)]
            if isinstance(raw_reasons, list)
            else []
        )
        scan_warnings.append(
            {
                "log": "explicit_bundle_path",
                "path": "dump_info",
                "code": "explicit_bundle_path_discovery_limit_reached",
                "message": "Explicit filename discovery reached a bounded limit; matching paths may be incomplete.",
                "reason": ",".join(reasons) or "bounded_limit",
                "entries_examined": int(explicit_path_discovery.get("entries_examined", 0) or 0),
                "limit": int(explicit_path_discovery.get("entry_limit", discovery_budget.max_entries) or 0),
            }
        )

    for item in selected_logs:
        path_discovery_diagnostics: dict[str, object] = {}
        existing_paths, log_path_discovery_truncated = _expand_log_paths_bounded(
            bundle_root,
            list(item.get("paths", [])),
            diagnostics=path_discovery_diagnostics,
            discovery_budget=discovery_budget,
            directory_index=directory_index,
            include_rotations=bool(item.get("_include_rotations", True)),
        )
        log_path_discovery_truncated = log_path_discovery_truncated or bool(
            path_discovery_diagnostics.get("truncated", False)
        )
        any_path_discovery_truncated = any_path_discovery_truncated or log_path_discovery_truncated
        existing_paths = sorted(
            existing_paths,
            key=lambda path: (-score_path_for_problem(path, problem), rotation_rank(path.name), str(path)),
        )
        matched_terms = [
            term for term in item.get("matched_keywords", []) if isinstance(term, str) and term
        ]
        configured_evidence_terms = [
            term for term in item.get("evidence_keywords", []) if isinstance(term, str) and term
        ]
        routing_terms = [
            term for term in item.get("keywords", []) if isinstance(term, str) and term
        ]
        # A definition may use broad routing words (for example ``sensor``)
        # that also occur in routine initialization lines.  When a narrower
        # evidence vocabulary is supplied, use it as the content signal
        # exclusively.  Legacy definitions without that field keep their
        # established fallback to the file keywords, which is important for
        # broad overview rules whose route phrase is not expected to appear in
        # the log body.
        candidate_terms = list(
            dict.fromkeys(
                [
                    *(
                        configured_evidence_terms
                        if configured_evidence_terms
                        else [*matched_terms, *routing_terms]
                    ),
                ]
            )
        )
        specific_terms = [term for term in candidate_terms if not is_generic_file_keyword(term)]
        evidence_terms = specific_terms or candidate_terms
        candidate_evidence: list[dict[str, object]] = []
        log_errors: list[dict[str, object]] = []
        log_warnings: list[dict[str, object]] = []
        scanned_paths: list[pathlib.Path] = []
        metadata_only = str(item.get("scan_mode", "text")) == "metadata_only"
        log_scan_truncated = log_path_discovery_truncated or (
            not metadata_only and len(existing_paths) > max_paths_per_log
        )
        if log_path_discovery_truncated:
            scan_truncated = True
            raw_reasons = path_discovery_diagnostics.get("limit_reasons", [])
            path_limit_reasons = (
                {str(reason) for reason in raw_reasons if isinstance(reason, str)}
                if isinstance(raw_reasons, list)
                else set()
            )
            if not path_limit_reasons:
                # Preserve a useful warning even if a caller supplied a
                # legacy diagnostics object without the reason field.
                path_limit_reasons = {"path_limit"}
            path_limit_values = {
                "entry_limit": int(
                    path_discovery_diagnostics.get("entry_limit", MAX_PATH_DISCOVERY_ENTRIES) or 0
                ),
                "glob_match_limit": MAX_GLOB_MATCHES_PER_PATTERN,
                "rotation_limit": MAX_ROTATED_FILE_CANDIDATES,
                "path_limit": int(
                    path_discovery_diagnostics.get("path_limit", MAX_PATH_EXPANSION_RESULTS) or 0
                ),
            }
            path_reason_messages = {
                "entry_limit": "Directory-entry inspection reached its bounded limit.",
                "glob_match_limit": "Wildcard expansion reached its per-pattern match limit.",
                "rotation_limit": "Rotated-file expansion reached its candidate limit.",
                "path_limit": "Path expansion reached its retained-path limit.",
            }
            for reason in sorted(path_limit_reasons):
                if reason not in path_limit_values:
                    continue
                log_warnings.append(
                    {
                        "path": str(next(iter(item.get("paths", [])), "dump_info")),
                        "code": "path_discovery_limit_reached",
                        "message": (
                            f"{path_reason_messages[reason]} Reported path counts are lower bounds."
                        ),
                        "reason": reason,
                        "retained_path_count": len(existing_paths),
                        "limit": path_limit_values[reason],
                    }
                )

        scan_paths = [] if metadata_only else existing_paths[:max_paths_per_log]
        remaining_files = max(0, max_scan_files - scanned_path_count)
        if len(scan_paths) > remaining_files:
            scan_paths = scan_paths[:remaining_files]
            log_scan_truncated = True
            scan_truncated = True
            log_warnings.append({"code": "scan_file_limit_reached",
                                 "path": str(item["paths"][0]),
                                 "message": "The shared file scan limit was reached.",
                                 "limit": max_scan_files})
        is_operation_log = str(item.get("name", "")) == "operation.log"
        if is_operation_log:
            operation_log_selected = True
            if log_path_discovery_truncated or len(scan_paths) < len(existing_paths):
                operation_anchor_discovery_complete = False
        else:
            correlation_available_path_count += len(existing_paths)
            correlation_expected_path_count += len(scan_paths)
            correlation_paths_limited = correlation_paths_limited or (
                not metadata_only
                and (
                    log_path_discovery_truncated
                    or len(scan_paths) < len(existing_paths)
                )
            )
            correlation_candidate_paths.extend(
                {
                    "log": item["name"],
                    "component": item.get("component", ""),
                    "path": file_path,
                    **(
                        {"source_revision": item["source_revision"]}
                        if item.get("source_revision")
                        else {}
                    ),
                }
                for file_path in scan_paths
            )
        if log_path_discovery_truncated or (
            not metadata_only and len(scan_paths) < len(existing_paths)
        ):
            scan_truncated = True
        for file_path in scan_paths:
            if budget.remaining_bytes <= 0:
                scan_truncated = True
                log_scan_truncated = True
                if is_operation_log:
                    operation_anchor_discovery_complete = False
                log_warnings.append(
                    {
                        "path": file_path.relative_to(bundle_root).as_posix(),
                        "code": "total_scan_byte_limit_reached",
                        "message": f"Total scan stopped after {max_total_bytes} decompressed bytes.",
                    }
                )
                break
            diagnostics: dict[str, object] = {}
            structured_collector = make_structured_collector(item.get("structured_parser"), file_path)

            def observe_primary_line(
                line_number: int,
                safe_line: str,
                in_time_window: bool,
            ) -> None:
                nonlocal observed_operation_anchor_count, unparseable_operation_anchor_count
                if structured_collector is not None:
                    structured_collector.observe(line_number, safe_line, in_time_window)
                if not is_operation_log or not in_time_window:
                    return
                anchor_probe = {
                    "log": "operation.log",
                    "component": item.get("component", ""),
                    "line": safe_line.strip(),
                }
                if not is_operation_failure_anchor(anchor_probe):
                    return
                parsed_datetime = parse_log_datetime(safe_line.strip(), default_timezone=analysis_timezone)
                if parsed_datetime is None:
                    unparseable_operation_anchor_count += 1
                    return
                anchor = {
                    "log": "operation.log",
                    "component": item.get("component", ""),
                    "path": file_path.relative_to(bundle_root).as_posix(),
                    "line_number": line_number,
                    "line": safe_line.strip(),
                    "timestamp": parsed_datetime.isoformat(),
                    **(
                        {"source_revision": item["source_revision"]}
                        if item.get("source_revision")
                        else {}
                    ),
                }
                observed_operation_anchor_count += 1
                operation_anchors.append(anchor)
                operation_anchors.sort(
                    key=lambda candidate: (
                        -evidence_timestamp_sort_value(
                            candidate,
                            default_timezone=analysis_timezone,
                        ),
                        str(candidate.get("path", "")),
                        -int(candidate.get("line_number", 0)),
                    )
                )
                if len(operation_anchors) > MAX_EVENT_CORRELATIONS:
                    del operation_anchors[MAX_EVENT_CORRELATIONS:]
                    operation_anchor_scan_truncated = True

            evidence_for_path = collect_evidence_lines(
                file_path,
                match_terms=evidence_terms,
                max_lines=max_lines,
                since=since,
                until=until,
                diagnostics=diagnostics,
                max_bytes=max_bytes_per_file,
                max_line_bytes=max_line_bytes,
                budget=budget,
                line_observer=(
                    observe_primary_line
                    if structured_collector is not None or is_operation_log
                    else None
                ),
                default_timezone=analysis_timezone,
            )
            if structured_collector is not None:
                structured_summary = structured_collector.finish(file_path.relative_to(bundle_root).as_posix())
                if structured_summary is not None:
                    file_warnings = diagnostics.get("warnings", [])
                    file_errors = diagnostics.get("errors", [])
                    warning_codes = {
                        str(entry.get("code", ""))
                        for entry in file_warnings
                        if isinstance(entry, dict)
                    }
                    error_codes = {
                        str(entry.get("code", ""))
                        for entry in file_errors
                        if isinstance(entry, dict)
                    }
                    observed_count = structured_summary.get("observed_record_count", 0)
                    structured_summary["observed_record_count"] = int(observed_count or 0)
                    structured_summary["bytes_observed"] = int(diagnostics.get("bytes_read", 0) or 0)
                    structured_summary["truncated"] = bool(
                        warning_codes
                        & {
                            "file_scan_truncated",
                            "scan_byte_limit_reached",
                            "total_scan_byte_limit_reached",
                            "partial_line_discarded",
                        }
                    )
                    structured_summary["complete"] = not bool(file_errors or structured_summary["truncated"])
                    if NUL_PADDING_WARNING_CODE in warning_codes:
                        structured_summary["complete"] = False
                    structured_summary["time_window_applied"] = bool(since or until)
                    structured_summaries.append(
                        {
                            "log": item["name"],
                            "component": item.get("component", ""),
                            **(
                                {"source_revision": item["source_revision"]}
                                if item.get("source_revision")
                                else {}
                            ),
                            **structured_summary,
                        }
                    )
            scanned_paths.append(file_path)
            scanned_path_count += 1
            if not is_operation_log:
                primary_scanned_correlation_path_count += 1
            for key, destination in (("errors", log_errors), ("warnings", log_warnings)):
                entries = diagnostics.get(key, [])
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    entry_code = str(entry.get("code", ""))
                    if entry_code in SCAN_TRUNCATION_CODES:
                        log_scan_truncated = True
                        scan_truncated = True
                    if is_operation_log and (
                        key == "errors" or entry_code in CORRELATION_SCAN_INCOMPLETE_WARNING_CODES
                    ):
                        operation_anchor_discovery_complete = False
                    destination.append(
                        {
                            "path": file_path.relative_to(bundle_root).as_posix(),
                            **entry,
                        }
                    )
            for evidence_line in evidence_for_path:
                candidate_evidence.append(
                    {
                        **evidence_line,
                        "_score": score_evidence_line(evidence_line, evidence_terms, file_path, problem),
                        "_timestamp_sort": evidence_timestamp_sort_value(
                            evidence_line,
                            default_timezone=analysis_timezone,
                        ),
                    }
                )
            # Retain only the best output-sized candidates plus one sentinel
            # for sampling. Rotated logs must not retain one full line per file.
            candidate_evidence.sort(key=lambda line: (
                -int(line.get("_score", 0)),
                -float(line.get("_timestamp_sort", float("-inf"))),
                str(line.get("path", "")), -int(line.get("line_number", 0))))
            del candidate_evidence[max_lines + 1:]

        candidate_evidence.sort(
            key=lambda evidence_line: (
                -int(evidence_line.get("_score", 0)),
                -float(evidence_line.get("_timestamp_sort", float("-inf"))),
                str(evidence_line.get("path", "")),
                -int(evidence_line.get("line_number", 0)),
            )
        )
        ranked_lines = [
            {
                **{key: value for key, value in evidence_line.items() if not key.startswith("_")},
                "path": _portable_path(evidence_line["path"], bundle_root),
                **(
                    {"source_revision": item["source_revision"]}
                    if item.get("source_revision")
                    else {}
                ),
            }
            for evidence_line in candidate_evidence[:max_lines]
        ]
        if len(candidate_evidence) > max_lines:
            for line in ranked_lines:
                line["sampled_from_larger_set"] = True
        evidence_lines = [
            line for line in ranked_lines if line.get("match_class") != "generic_failure"
        ]
        context_lines = [
            line for line in ranked_lines if line.get("match_class") == "generic_failure"
        ]
        total_existing_paths += len(existing_paths)
        total_evidence_lines += len(evidence_lines)
        scan_errors.extend({"log": item["name"], **entry} for entry in log_errors)
        scan_warnings.extend({"log": item["name"], **entry} for entry in log_warnings)
        analyzed_logs.append(
            {
                "name": item["name"],
                "purpose": item.get("purpose", ""),
                "component": item.get("component", ""),
                "definition_status": item.get("definition_status", "maintained_heuristic"),
                "source_type": item.get("source_type", "repository_maintained"),
                "source_reference": item.get("source_reference", ""),
                "reliability": item.get("reliability", "heuristic"),
                **(
                    {"source_revision": item["source_revision"]}
                    if item.get("source_revision")
                    else {}
                ),
                "matched_keywords": item.get("matched_keywords", []),
                "routing_basis": item.get("routing_basis", []),
                "routing_reliability": item.get("routing_reliability", "heuristic"),
                "structured_parser": item.get("structured_parser", ""),
                "scan_mode": item.get("scan_mode", "text"),
                **catalog_dimensions(item),
                "existing_paths": [
                    path.relative_to(bundle_root).as_posix()
                    for path in existing_paths[:DEFAULT_ANALYSIS_MAX_PATHS]
                ],
                "existing_path_count": len(existing_paths),
                "existing_path_count_is_lower_bound": log_path_discovery_truncated,
                "path_discovery_complete": not log_path_discovery_truncated,
                "path_discovery_entries_examined": int(
                    path_discovery_diagnostics.get("entries_examined", 0) or 0
                ),
                "path_discovery_entry_limit": int(
                    path_discovery_diagnostics.get("entry_limit", MAX_PATH_DISCOVERY_ENTRIES) or 0
                ),
                "existing_paths_truncated": (
                    log_path_discovery_truncated or len(existing_paths) > DEFAULT_ANALYSIS_MAX_PATHS
                ),
                "scanned_paths": [path.relative_to(bundle_root).as_posix() for path in scanned_paths],
                "scanned_path_count": len(scanned_paths),
                "scan_truncated": log_scan_truncated,
                "scan_errors": log_errors,
                "scan_warnings": log_warnings,
                "evidence_lines": evidence_lines,
                "context_lines": context_lines,
            }
        )

    primary_scanned_bytes = budget.bytes_read
    candidate_details_by_anchor, correlation_scan = scan_correlation_candidates(
        bundle_root,
        operation_anchors,
        correlation_candidate_paths,
        window_seconds=DEFAULT_CORRELATION_WINDOW_SECONDS,
        since=since,
        until=until,
        analysis_timezone=analysis_timezone,
        budget=budget,
        max_bytes_per_file=max_bytes_per_file,
        max_line_bytes=max_line_bytes,
    )
    correlation_scan.update(
        {
            "operation_log_selected": operation_log_selected,
            "anchor_discovery_complete": operation_anchor_discovery_complete,
            "anchor_count_observed": observed_operation_anchor_count,
            "anchor_count_retained": len(operation_anchors),
            "unparseable_anchor_count": unparseable_operation_anchor_count,
            "anchors_truncated": operation_anchor_scan_truncated,
            "available_path_count": correlation_available_path_count,
            "bounded_path_record_count": correlation_expected_path_count,
            "primary_scanned_candidate_path_count": primary_scanned_correlation_path_count,
            "max_paths_per_log": max_paths_per_log,
            "max_total_bytes": max_total_bytes,
            "max_bytes_per_file": max_bytes_per_file,
            "max_line_bytes": max_line_bytes,
            "max_scan_files": max_scan_files,
            "primary_scanned_bytes": primary_scanned_bytes,
            "remaining_bytes_before_scan": max(0, max_total_bytes - primary_scanned_bytes),
            "remaining_bytes_after_scan": budget.remaining_bytes,
        }
    )
    correlation_warnings = correlation_scan.get("warnings", [])
    if not isinstance(correlation_warnings, list):
        correlation_warnings = []
        correlation_scan["warnings"] = correlation_warnings

    if observed_operation_anchor_count > MAX_EVENT_CORRELATIONS:
        operation_anchor_scan_truncated = True
        correlation_scan["anchors_truncated"] = True
        correlation_warnings.append(
            {
                "log": "operation.log",
                "code": "operation_anchor_limit_reached",
                "message": (
                    f"Retained {MAX_EVENT_CORRELATIONS} of {observed_operation_anchor_count} "
                    "observed operation failure anchors for bounded correlation."
                ),
                "phase": "operation_anchor_discovery",
            }
        )
    if operation_log_selected and not operation_anchor_discovery_complete:
        correlation_warnings.append(
            {
                "log": "operation.log",
                "code": "operation_anchor_discovery_incomplete",
                "message": "The bounded primary read could not fully inspect all selected operation.log content.",
                "phase": "operation_anchor_discovery",
            }
        )
    if unparseable_operation_anchor_count:
        operation_anchor_discovery_complete = False
        correlation_scan["anchor_discovery_complete"] = False
        correlation_scan["complete"] = False
        correlation_scan["candidate_scan_complete"] = False
        correlation_scan["truncated"] = True
        correlation_warnings.append(
            {
                "log": "operation.log",
                "code": "operation_anchor_timestamp_unparseable",
                "message": (
                    f"{unparseable_operation_anchor_count} operation failure line(s) had no parseable timestamp "
                    "and could not be correlated."
                ),
                "phase": "operation_anchor_discovery",
            }
        )
    if operation_anchors and correlation_paths_limited:
        correlation_scan["candidate_scan_complete"] = False
        correlation_scan["truncated"] = True
        correlation_warnings.append(
            {
                "code": "correlation_path_limit_reached",
                "message": (
                    f"The candidate pass was limited to {max_paths_per_log} physical paths per selected log."
                ),
                "phase": "correlation_candidate_scan",
            }
        )
    if operation_anchors and int(correlation_scan.get("scanned_path_count", 0)) < int(
        correlation_scan.get("eligible_path_count", 0)
    ):
        correlation_scan["candidate_scan_complete"] = False
        correlation_scan["truncated"] = True
        correlation_warnings.append(
            {
                "code": "correlation_paths_not_scanned",
                "message": (
                    "Some bounded candidate paths were not reached by the correlation candidate pass."
                ),
                "phase": "correlation_candidate_scan",
            }
        )
    correlation_scan["complete"] = bool(
        operation_anchor_discovery_complete
        and not operation_anchor_scan_truncated
        and correlation_scan.get("candidate_scan_complete", False)
    )
    correlation_errors = correlation_scan.get("errors", [])
    if isinstance(correlation_errors, list):
        scan_errors.extend(
            item
            for item in correlation_errors
            if isinstance(item, dict) and item.get("path") and item.get("log")
        )
    if isinstance(correlation_warnings, list):
        scan_warnings.extend(
            item
            for item in correlation_warnings
            if isinstance(item, dict) and item.get("path") and item.get("log")
        )
    if operation_anchors and not correlation_scan.get("complete", False):
        scan_truncated = True

    evidence: list[dict[str, object]] = []
    context_evidence: list[dict[str, object]] = []
    for log_result in analyzed_logs:
        for field_name, destination in (
            ("evidence_lines", evidence),
            ("context_lines", context_evidence),
        ):
            for line in log_result[field_name]:
                destination.append(
                {
                    "log": log_result["name"],
                    "purpose": log_result["purpose"],
                    "component": log_result["component"],
                    "definition_status": log_result["definition_status"],
                    "source_type": log_result["source_type"],
                    "source_reference": log_result["source_reference"],
                    "reliability": log_result["reliability"],
                    "semantic_level": log_result["semantic_level"],
                    "artifact_format": log_result["artifact_format"],
                    "route_mode": log_result["route_mode"],
                    "sensitivity": log_result["sensitivity"],
                    **(
                        {"source_revision": log_result["source_revision"]}
                        if log_result.get("source_revision")
                        else {}
                    ),
                    "routing_basis": log_result["routing_basis"],
                    "routing_reliability": log_result["routing_reliability"],
                    **line,
                    **(
                        {"source_revision": log_result["source_revision"]}
                        if log_result.get("source_revision")
                        else {}
                    ),
                }
            )

    timeline = build_timeline(evidence, default_timezone=analysis_timezone)
    correlation_timeline = build_timeline(
        [*evidence, *context_evidence],
        default_timezone=analysis_timezone,
    )
    correlation_windows = build_correlation_windows(
        correlation_timeline,
        default_timezone=analysis_timezone,
    )
    timeline_domains = timeline_time_domains(timeline)
    correlation_domains = timeline_time_domains(correlation_timeline)

    def append_time_domain_warning(
        code: str,
        items: list[dict[str, object]],
        domains: set[str],
        scope: str,
    ) -> None:
        if analysis_timezone is not None or len(domains) <= 1 or not items:
            return
        warning_item = next(
            (
                item
                for item in items
                if str(item.get("time_domain", "unknown")) != str(items[0].get("time_domain", "unknown"))
            ),
            items[0],
        )
        scan_warnings.append(
            {
                "log": str(warning_item.get("log", scope)),
                "path": str(warning_item.get("path", "dump_info")),
                "code": code,
                "message": (
                    f"{scope.capitalize()} entries use incompatible timestamp domains. They are ordered only "
                    "within each time domain; cross-domain sequence values are not chronological. Provide "
                    "--analysis-timezone to normalize timestamps without offsets."
                ),
                "time_domains": sorted(domains),
            }
        )

    append_time_domain_warning(
        "timeline_time_domain_partitioned",
        timeline,
        timeline_domains,
        "timeline",
    )
    if correlation_domains != timeline_domains:
        append_time_domain_warning(
            "correlation_time_domain_partitioned",
            correlation_timeline,
            correlation_domains,
            "correlation timeline",
        )
    for anchor in operation_anchors:
        anchor_id = operation_event_anchor_id(anchor)
        bucket = candidate_details_by_anchor.setdefault(anchor_id, [])
        seen = {
            (str(item.get("path", "")), int(item.get("line_number", 0)))
            for item in bucket
        }
        for candidate in correlation_timeline:
            details = event_candidate_details(
                anchor,
                candidate,
                window_seconds=DEFAULT_CORRELATION_WINDOW_SECONDS,
            )
            if details is None:
                continue
            key = (str(details.get("path", "")), int(details.get("line_number", 0)))
            if key in seen:
                continue
            seen.add(key)
            bucket.append(details)
        bucket.sort(key=event_candidate_sort_key)
        if len(bucket) > MAX_EVENT_CANDIDATES_PER_ANCHOR:
            del bucket[MAX_EVENT_CANDIDATES_PER_ANCHOR:]
    event_correlations, unmatched_event_anchors = build_event_correlations(
        [],
        window_seconds=DEFAULT_CORRELATION_WINDOW_SECONDS,
        scan_complete=bool(correlation_scan.get("complete", False)),
        candidate_details_by_anchor=candidate_details_by_anchor,
        anchors=operation_anchors,
    )
    evidence_findings = build_evidence_findings(evidence)
    gap_warning_codes = {
        "decode_replacement_used",
        "file_scan_truncated",
        "line_too_long",
        "scan_byte_limit_reached",
        "total_scan_byte_limit_reached",
        "partial_line_discarded",
        "timezone_domain_mismatch",
        "timeline_time_domain_partitioned",
        "correlation_time_domain_partitioned",
        "path_discovery_limit_reached",
        "component_hint_limit_reached",
        "component_hint_invalid_name_skipped",
        NUL_PADDING_WARNING_CODE,
    }
    has_analysis_gaps = bool(
        scan_errors
        or scan_truncated
        or any(str(item.get("code", "")) in gap_warning_codes for item in scan_warnings)
    )
    structured_observation_count = sum(
        int(item.get("observed_record_count", 0))
        for item in structured_summaries
        if isinstance(item.get("observed_record_count", 0), int)
    )
    problem_evidence = [
        item
        for item in evidence
        if str(item.get("match_class", "")) in {"direct_failure", "problem_context"}
    ]
    if problem_evidence:
        assessment = "evidence_found_with_gaps" if has_analysis_gaps else "evidence_found"
    elif has_analysis_gaps:
        assessment = "analysis_incomplete"
    else:
        assessment = "insufficient_bundle_evidence"
    path_count_verb = "found at least" if any_path_discovery_truncated else "found"
    summary = (
        f"Selected {len(analyzed_logs)} log types for problem '{problem}', "
        f"{path_count_verb} {total_existing_paths} existing paths, scanned {scanned_path_count}, "
        f"extracted {total_evidence_lines} evidence lines, and observed "
        f"{structured_observation_count} structured records."
    )
    result = {
        "problem": problem,
        "selected_logs": analyzed_logs,
        "evidence": evidence,
        "evidence_count": len(evidence),
        "context_evidence": context_evidence,
        "context_evidence_count": len(context_evidence),
        "timeline": timeline,
        "timeline_count": len(timeline),
        "correlation_windows": correlation_windows,
        "event_correlations": event_correlations,
        "unmatched_event_anchors": unmatched_event_anchors,
        "correlation_scan": correlation_scan,
        "evidence_findings": evidence_findings,
        "structured_summaries": structured_summaries,
        "structured_observation_count": structured_observation_count,
        "assessment": assessment,
        "scan": {
            "complete": not has_analysis_gaps,
            "scanned_path_count": scanned_path_count,
            "scanned_bytes": budget.bytes_read,
            "primary_scanned_bytes": primary_scanned_bytes,
            "correlation_scanned_bytes": correlation_scan.get("scanned_bytes", 0),
            "max_paths_per_log": max_paths_per_log,
            "max_total_bytes": max_total_bytes,
            "max_bytes_per_file": max_bytes_per_file,
            "max_line_bytes": max_line_bytes,
            "truncated": scan_truncated,
            "path_discovery": {
                "entries_examined": discovery_budget.entries_examined,
                "entry_limit": discovery_budget.max_entries,
                "complete": not any_path_discovery_truncated,
                "truncated": any_path_discovery_truncated,
                "path_limit": MAX_PATH_EXPANSION_RESULTS,
                "glob_match_limit": MAX_GLOB_MATCHES_PER_PATTERN,
                "rotation_limit": MAX_ROTATED_FILE_CANDIDATES,
                "component_hint_discovery": component_hint_discovery,
            },
            "errors": scan_errors,
            "warnings": scan_warnings,
        },
        "summary": summary,
    }
    if since or until:
        result["time_window"] = {
            "since": since.isoformat() if since else "",
            "until": until.isoformat() if until else "",
        }
    return result
