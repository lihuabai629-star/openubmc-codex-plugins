"""Shell-free offline tools shared by native hosts and the Codex MCP adapter."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import sys
import uuid

# Python's Windows main-module path can drop the long-path prefix used by sibling imports.
if os.name == "nt":
    sys.path.insert(0, str(Path(__file__).parent))

from analyze_bundle import (
    _collect_disclosure_literals,
    _validate_numeric_options,
    parse_args,
    redact_payload_strings,
    run_request,
    safe_terminal_text,
)
from log_bundle_analysis import iter_text_lines
from log_bundle_artifact import ensure_bundle_path, locate_bundle_root
from log_bundle_common import BundleAnalysisError
from log_bundle_redaction import redact_public_text


SCHEMA = "openubmc.offline-tools.v1"
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
DEFINITIONS = json.loads((Path(__file__).resolve().parents[1] / "references/offline-tools.json").read_text(encoding="utf-8"))


class _Diagnostics(list):
    """Retain a bounded sample while counting every scanner diagnostic."""
    def __init__(self):
        super().__init__()
        self.total = 0

    def append(self, value):
        self.total += 1
        if len(self) < 32:
            super().append(value)


def _validate(value: object, schema: dict, field: str = "arguments"):
    """Validate the scalar/object JSON subset used by the shipped tool schemas."""
    kind = schema["type"]
    valid_type = {
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
        "integer": type(value) is int,
    }[kind]
    if not valid_type:
        raise BundleAnalysisError("invalid_request", f"{field} must be {kind}.")
    if kind == "object":
        properties = schema["properties"]
        if set(value) - set(properties) or set(schema.get("required", [])) - set(value):
            raise BundleAnalysisError("invalid_request", f"{field} contains unknown fields or omits required fields.")
        return {key: _validate(item, properties[key], f"{field}.{key}") for key, item in value.items()}
    if kind == "string" and not schema.get("minLength", 0) <= len(value) <= schema["maxLength"]:
        raise BundleAnalysisError("invalid_request", f"{field} has an invalid length.")
    if kind == "integer" and not schema["minimum"] <= value <= schema["maximum"]:
        raise BundleAnalysisError("invalid_request", f"{field} is outside the supported range.")
    return value


def _path(value: str, cwd: Path) -> Path:
    candidate = Path(value).expanduser()
    return candidate if candidate.is_absolute() else cwd / candidate


def _public(payload: dict) -> dict:
    locations, hosts = _collect_disclosure_literals(payload)
    return redact_payload_strings(payload, location_literals=tuple(sorted(locations, key=len, reverse=True)),
                                  host_literals=tuple(sorted(hosts, key=len, reverse=True)))


def _window(items: list, limit: int) -> dict:
    return {"items": items[:limit], "total": len(items), "truncated": len(items) > limit}


def _brief(value: object):
    """Bound nested diagnostic text in the model response; the artifact retains it."""
    if isinstance(value, str):
        return value[:512]
    if isinstance(value, dict):
        return {key: _brief(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_brief(item) for item in value[:32]]
    return value


def _diagnostics(scan: dict, limit: int) -> dict:
    return {**{key: scan[key] for key in ("complete", "truncated", "scanned_path_count", "scanned_bytes",
                                         "max_paths_per_log", "max_total_bytes", "max_bytes_per_file", "max_line_bytes") if key in scan},
            "errors": _window([_brief(item) for item in scan.get("errors", [])], limit),
            "warnings": _window([_brief(item) for item in scan.get("warnings", [])], limit)}


def _compact_response(response: dict) -> dict:
    """Keep model responses below the wire limit while retaining honest window totals."""
    response["response_truncated"] = False
    windows = []
    def collect(value):
        if isinstance(value, dict):
            if {"items", "total", "truncated"}.issubset(value):
                windows.append(value)
            for item in value.values():
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)
    collect(response)
    while len(json.dumps(response, ensure_ascii=False).encode("utf-8")) > MAX_RESPONSE_BYTES:
        candidates = [window for window in windows if window["items"]]
        if not candidates:
            raise BundleAnalysisError("response_limit", "Read the full local artifact; compact metadata exceeded its limit.")
        largest = max(candidates, key=lambda window: len(json.dumps(window["items"], ensure_ascii=False)))
        largest["items"].pop()
        largest["truncated"] = True
        response["response_truncated"] = True
    return response


def _private_directory(directory: Path) -> None:
    # Reject existing link components before mkdir; never chmod a caller's directory.
    for parent in [*reversed(directory.parents), directory]:
        if parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction()):
            raise BundleAnalysisError("output_path_invalid", "Output directories must not contain links.")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)


def analyze(arguments: dict, *, cwd: Path, artifact_dir: Path) -> dict:
    """Save the full redacted payload and return bounded findings and read pointers."""
    source = _path(arguments["source"], cwd)
    if not arguments["problem"].strip():
        raise BundleAnalysisError("missing_problem", "Provide a non-empty problem statement.")
    output = _path(arguments["output_dir"], cwd) if "output_dir" in arguments else artifact_dir
    output = output.absolute()
    if source.is_dir():
        root = source.parent if source.name == "dump_info" else locate_bundle_root(source)
        if output.resolve().is_relative_to(root.resolve()):
            raise BundleAnalysisError("output_path_invalid", "Choose an output directory outside the input bundle.")
    _private_directory(output)
    identity = uuid.uuid4().hex
    destination = output / f"analysis-{identity}.json"
    argv = ["--bundle-dir" if source.is_dir() else "--bundle", str(source),
            "--problem", arguments["problem"], "--extract-dir", str(output / f"extract-{identity}"),
            "--output-json", str(destination)]
    for key in ("since", "until", "timezone"):
        if key in arguments:
            argv += [f"--analysis-{key}", arguments[key]]
    for key, value in arguments.get("limits", {}).items():
        argv += ["--analysis-" + key.replace("_", "-"), str(value)]
    options = parse_args(argv)
    _validate_numeric_options(options)
    payload = run_request(options)
    safe = _public(payload)
    if not payload["ok"]:
        return {"schema": SCHEMA, "ok": False, "code": payload["code"], "error": safe["error"],
                "validation": safe["result"].get("validation", {})}
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(safe, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    analysis = safe["result"].get("analysis", {})
    limit = arguments.get("summary_limit", 12)
    evidence = [{**{key: item[key] for key in ("path", "line_number", "timestamp", "match_class") if key in item},
                 "line": str(item.get("line", ""))[:512],
                 "line_truncated": len(str(item.get("line", ""))) > 512} for item in analysis.get("evidence", [])]
    return _compact_response({"schema": SCHEMA, "ok": True, "code": "ok", "artifact": str(destination),
            "summary_limits": {"max_items": limit, "max_text_characters": 512, "max_response_bytes": MAX_RESPONSE_BYTES},
            "bundle_dir": payload["result"]["bundle"]["bundle_root"],
            "source_sha256": payload["result"]["bundle"]["sha256"],
            "validation": _brief(safe["result"]["validation"]),
            "summary": analysis.get("summary", "")[:1024], "assessment": analysis.get("assessment", ""),
            "scan": _diagnostics(analysis.get("scan", {}), limit),
            "correlation_scan": _diagnostics(analysis.get("correlation_scan", {}), limit),
            "selected_logs": _window([{"name": item.get("name", ""), "scanned_paths": _window(item.get("scanned_paths", []), limit)}
                                      for item in analysis.get("selected_logs", [])], limit),
            "evidence": _window(evidence, limit),
            "findings": _window([_brief(item) for item in analysis.get("evidence_findings", [])], limit),
            "structured_summary_count": len(analysis.get("structured_summaries", [])),
            "event_correlation_count": len(analysis.get("event_correlations", []))})


def read_evidence(arguments: dict, *, cwd: Path) -> dict:
    """Read a bounded, redacted line window from a regular bundle member."""
    directory = _path(arguments["bundle_dir"], cwd)
    if directory.is_symlink():
        raise BundleAnalysisError("bundle_layout_invalid", "Bundle directory must not be a symbolic link.")
    root = directory.parent if directory.name == "dump_info" else directory
    relative = arguments["path"]
    parts = PurePosixPath(relative).parts
    if (not parts or parts[0] != "dump_info" or any(part in {"..", "."} for part in relative.split("/"))
            or "\\" in relative or ":" in relative or "\0" in relative or PureWindowsPath(relative).drive):
        raise BundleAnalysisError("evidence_path_invalid", "Use a bundle-relative dump_info/... path with forward slashes.")
    path = ensure_bundle_path(root, relative)
    if not stat.S_ISREG(path.stat().st_mode):
        raise BundleAnalysisError("evidence_path_invalid", "Evidence must be a regular text or gzip log file.")
    start = arguments.get("start_line", 1)
    count = arguments.get("line_count", 40)
    output_limit = arguments.get("max_output_bytes", 32768)
    error_sample, warning_sample = _Diagnostics(), _Diagnostics()
    diagnostics: dict = {"errors": error_sample, "warnings": warning_sample}
    lines = []
    used = 0
    output_truncated = False
    redacted = False
    last_scanned_line = 0
    private_key = False
    iterator = iter_text_lines(path, max_bytes=arguments.get("max_scan_bytes", 8 * 1024 * 1024),
                               max_line_bytes=arguments.get("max_line_bytes", 64 * 1024), diagnostics=diagnostics)
    try:
        for number, text in iterator:
            last_scanned_line = number
            if "-----BEGIN " in text and "PRIVATE KEY-----" in text:
                private_key = True
            protected = private_key
            if "-----END " in text and "PRIVATE KEY-----" in text:
                private_key = False
            if number < start:
                continue
            if number >= start + count:
                break
            safe, changed = ("<redacted-private-key>", True) if protected else redact_public_text(text)
            redacted |= changed
            safe = safe_terminal_text(safe)
            size = len(safe.encode("utf-8"))
            if used + size > output_limit:
                output_truncated = True
                break
            lines.append({"line_number": number, "text": safe})
            used += size
    finally:
        iterator.close()
    safe_diagnostics = _public({**diagnostics, "bundle_dir": str(root)})
    warnings = safe_diagnostics.get("warnings", [])
    errors = safe_diagnostics.get("errors", [])
    complete = not (output_truncated or warnings or errors)
    return {"schema": SCHEMA, "ok": not errors, "code": "ok" if not errors else "evidence_read_failed",
            "path": relative, "start_line": start, "line_count": len(lines), "lines": lines,
            "redacted": redacted, "complete": complete,
            "output_truncated": output_truncated, "bytes_read": diagnostics.get("bytes_read", 0),
            "last_scanned_line": last_scanned_line, "errors": errors, "warnings": warnings,
            "diagnostic_counts": {"errors": error_sample.total, "warnings": warning_sample.total},
            "diagnostics_truncated": error_sample.total > len(errors) or warning_sample.total > len(warnings)}


def call_tool(name: str, arguments: object, *, cwd: Path, artifact_dir: Path) -> dict:
    """Dispatch only shipped offline operations; return stable, redacted failures."""
    try:
        definition = next((tool for tool in DEFINITIONS if tool["name"] == name), None)
        if definition is None:
            raise BundleAnalysisError("unknown_tool", "Unknown offline tool.")
        selected = _validate(arguments, definition["inputSchema"])
        if name == "openubmc_analyze_bundle":
            return analyze(selected, cwd=cwd, artifact_dir=artifact_dir)
        return read_evidence(selected, cwd=cwd)
    except BundleAnalysisError as exc:
        return {"schema": SCHEMA, "ok": False, "code": exc.code,
                "error": redact_public_text(exc.redacted_message)[0]}
    except (OSError, ValueError):
        return {"schema": SCHEMA, "ok": False, "code": "local_io_failed",
                "error": "Could not read the local input or create a new result file. Check paths and permissions."}


def main() -> None:
    """Accept one Host-owned JSON request on stdin; never consume shell syntax."""
    sys.stdout.reconfigure(encoding="utf-8")
    try:
        raw = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("request too large")
        request = json.loads(raw)
        if not isinstance(request, dict) or set(request) != {"tool", "arguments", "cwd", "artifact_dir"}:
            raise ValueError("invalid worker request")
        result = call_tool(request["tool"], request["arguments"], cwd=Path(request["cwd"]), artifact_dir=Path(request["artifact_dir"]))
    except (TypeError, ValueError, KeyError):
        result = {"schema": SCHEMA, "ok": False, "code": "invalid_request", "error": "Invalid offline worker request."}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
