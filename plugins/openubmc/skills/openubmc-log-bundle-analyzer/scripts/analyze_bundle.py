#!/usr/bin/env python3
"""Validate and analyze a local openUBMC one-click log bundle."""
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
import pathlib
import re
import sys
import tarfile
import tempfile

from log_bundle_analysis import (
    DEFAULT_ANALYSIS_MAX_BYTES_PER_FILE,
    DEFAULT_ANALYSIS_MAX_LINE_BYTES,
    DEFAULT_ANALYSIS_MAX_PATHS_PER_LOG,
    DEFAULT_ANALYSIS_MAX_TOTAL_BYTES,
    analyze_bundle,
    compare_datetimes,
    parse_analysis_time_bound,
    parse_analysis_timezone,
    redact_sensitive_text,
)
from log_bundle_redaction import redact_public_text
from log_bundle_artifact import (
    extract_archive,
    locate_bundle_root,
    sha256_file,
    validate_bundle_structure,
)
from log_bundle_common import (
    BundleAnalysisError,
    ExtractionResult,
)


SCHEMA_VERSION = "1.0"
DEFAULT_ANALYSIS_MAX_FILES = 8
DEFAULT_ANALYSIS_MAX_LINES = 3

# CLI resource knobs are deliberately bounded independently from the lower
# defaults.  A caller may widen a scan for a large bundle, but cannot turn a
# typo or an untrusted request into an effectively unbounded traversal or
# output operation.
MAX_ANALYSIS_MAX_FILES = 64
MAX_ANALYSIS_MAX_LINES = 100
MAX_ANALYSIS_MAX_PATHS_PER_LOG = 64
MAX_ANALYSIS_MAX_BYTES_PER_FILE = 64 * 1024 * 1024
MAX_ANALYSIS_MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ANALYSIS_MAX_LINE_BYTES = 1024 * 1024


def safe_terminal_text(value: object) -> str:
    """Render untrusted bundle text without terminal control injection."""
    text = str(value)
    rendered: list[str] = []
    bidi_controls = {
        *range(0x202A, 0x202F),
        *range(0x2066, 0x206A),
        0x200B,
        0x200C,
        0x200D,
        0x2060,
        0xFEFF,
    }
    for character in text:
        codepoint = ord(character)
        if codepoint == 0x1B:
            rendered.append("\\x1b")
        elif codepoint in {0x0A, 0x0D, 0x09}:
            rendered.append({0x0A: "\\n", 0x0D: "\\r", 0x09: "\\t"}[codepoint])
        elif codepoint < 0x20 or codepoint == 0x7F:
            rendered.append(f"\\x{codepoint:02x}")
        elif 0x80 <= codepoint <= 0x9F or codepoint in bidi_controls:
            rendered.append(f"\\u{codepoint:04x}")
        else:
            rendered.append(character)
    return "".join(rendered)


LOCATION_FIELDS = {
    "archive_path",
    "bundle",
    "bundle_dir",
    "bundle_root",
    "extract_dir",
}
LOCATION_LIST_FIELDS: set[str] = set()
HOST_FIELDS: set[str] = set()
PUBLIC_PROVENANCE_FIELDS = {"source_reference", "source_revision"}


def _collect_disclosure_literals(
    value: object,
    *,
    field_name: str = "",
    locations: set[str] | None = None,
    hosts: set[str] | None = None,
) -> tuple[set[str], set[str]]:
    """Collect exact caller- or runtime-supplied locations and target hosts.

    Generic free-text redaction is necessarily pattern based.  Exact values
    already present in structured location/host fields provide a stronger
    boundary for error strings, including custom POSIX mount roots.
    """

    location_values = locations if locations is not None else set()
    host_values = hosts if hosts is not None else set()
    if isinstance(value, str):
        if value and field_name in LOCATION_FIELDS:
            location_values.add(value)
        if value and field_name in HOST_FIELDS:
            host_values.add(value)
        return location_values, host_values
    if isinstance(value, list):
        if field_name in LOCATION_LIST_FIELDS:
            location_values.update(str(item) for item in value if isinstance(item, str) and item)
        for item in value:
            _collect_disclosure_literals(
                item,
                field_name=field_name,
                locations=location_values,
                hosts=host_values,
            )
        return location_values, host_values
    if isinstance(value, dict):
        for key, item in value.items():
            _collect_disclosure_literals(
                item,
                field_name=str(key),
                locations=location_values,
                hosts=host_values,
            )
    return location_values, host_values


def _redact_exact_context(
    value: str,
    *,
    location_literals: tuple[str, ...],
    host_literals: tuple[str, ...],
) -> str:
    redacted = value
    path_component = r"A-Za-z0-9._+@=%-"
    # A caller-supplied root such as ``/tmp`` is a prefix of many ordinary
    # tokens (``/tmpfiles``) and of other paths (``/usr/lib/tmpfiles.d``).
    # Replace a complete path token, including descendants, while keeping
    # component boundaries so exact-context redaction cannot damage evidence.
    for literal in location_literals:
        if not literal:
            continue
        normalized_literal = literal
        if literal.startswith("/") and literal != "/":
            normalized_literal = literal.rstrip("/")
        elif re.match(r"^[A-Za-z]:\\", literal) and not re.fullmatch(r"[A-Za-z]:\\", literal):
            normalized_literal = literal.rstrip("\\")
        if normalized_literal.startswith("/"):
            pattern = (
                rf"(?<![{path_component}\\]){re.escape(normalized_literal)}"
                rf"(?:/[{path_component}]+)*(?![{path_component}])"
            )
        elif re.match(r"^(?:[A-Za-z]:\\|\\\\)", normalized_literal):
            pattern = (
                rf"(?<![{path_component}]){re.escape(normalized_literal)}"
                rf"(?:\\[{path_component}]+)*(?![{path_component}])"
            )
        else:
            pattern = rf"(?<![{path_component}]){re.escape(normalized_literal)}(?![{path_component}])"
        redacted = re.sub(pattern, "<redacted-path>", redacted)
    for literal in host_literals:
        if not literal:
            continue
        redacted = re.sub(
            rf"(?<![A-Za-z0-9_.-]){re.escape(literal)}(?![A-Za-z0-9_.-])",
            "<redacted-host>",
            redacted,
            flags=re.IGNORECASE,
        )
    return redacted


def redact_payload_strings(
    value: object,
    *,
    include_sensitive_context: bool = False,
    field_name: str = "",
    location_literals: tuple[str, ...] = (),
    host_literals: tuple[str, ...] = (),
) -> object:
    """Apply the selected disclosure boundary to every emitted string.

    Credentials are always redacted.  The default shareable profile also
    removes local locations and common host, account, browser, and
    asset identifiers.  Exact public source references remain reproducible.
    """

    if isinstance(value, str):
        if field_name in PUBLIC_PROVENANCE_FIELDS:
            redacted, _ = redact_sensitive_text(value)
            return redacted
        if include_sensitive_context:
            redacted, _ = redact_sensitive_text(value)
            return redacted
        if field_name in LOCATION_FIELDS and value:
            return "<redacted-path>"
        if field_name in HOST_FIELDS and value:
            return "<redacted-host>"
        exact_redacted = _redact_exact_context(
            value,
            location_literals=location_literals,
            host_literals=host_literals,
        )
        redacted, _ = redact_public_text(exact_redacted)
        return redacted
    if isinstance(value, list):
        if not include_sensitive_context and field_name in LOCATION_LIST_FIELDS:
            return ["<redacted-path>" for _ in value]
        return [
            redact_payload_strings(
                item,
                include_sensitive_context=include_sensitive_context,
                field_name=field_name,
                location_literals=location_literals,
                host_literals=host_literals,
            )
            for item in value
        ]
    if isinstance(value, dict):
        return {
            key: redact_payload_strings(
                item,
                include_sensitive_context=include_sensitive_context,
                field_name=str(key),
                location_literals=location_literals,
                host_literals=host_literals,
            )
            for key, item in value.items()
        }
    return value


def emit_result(
    payload: dict[str, object],
    *,
    json_mode: bool,
    include_sensitive_context: bool = False,
    output_json: str = "",
) -> None:
    location_values, host_values = _collect_disclosure_literals(payload)
    payload = redact_payload_strings(  # type: ignore[assignment]
        payload,
        include_sensitive_context=include_sensitive_context,
        location_literals=tuple(sorted(location_values, key=len, reverse=True)),
        host_literals=tuple(sorted(host_values, key=len, reverse=True)),
    )
    if output_json:
        try:
            with pathlib.Path(output_json).expanduser().open("x", encoding="utf-8", newline="\n") as output:
                json.dump(payload, output, ensure_ascii=False, indent=2)
                output.write("\n")
        except OSError as exc:
            raise BundleAnalysisError(
                "output_write_failed",
                "Could not create JSON output; choose a new file in an existing writable directory.",
            ) from exc
    if json_mode:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    result = payload["result"]
    print(f"STATUS={'ok' if payload['ok'] else 'error'}")
    if payload["error"]:
        print(f"ERROR={safe_terminal_text(payload['error'])}")
    print(f"SOURCE_KIND={safe_terminal_text(result.get('source_kind', ''))}")
    bundle = result.get("bundle", {})
    if isinstance(bundle, dict):
        if bundle.get("archive_path"):
            print(f"LOCAL_BUNDLE_PATH={safe_terminal_text(bundle['archive_path'])}")
        if bundle.get("bundle_root"):
            print(f"BUNDLE_ROOT={safe_terminal_text(bundle['bundle_root'])}")
        if bundle.get("sha256"):
            print(f"BUNDLE_SHA256={safe_terminal_text(bundle['sha256'])}")
    validation = result.get("validation", {})
    if isinstance(validation, dict) and validation:
        print(f"BUNDLE_VALID={str(bool(validation.get('valid'))).lower()}")
        sections = validation.get("present_sections", [])
        if isinstance(sections, list):
            print(f"PRESENT_SECTIONS={safe_terminal_text(','.join(str(item) for item in sections))}")
    analysis = payload["result"].get("analysis")
    if isinstance(analysis, dict):
        summary = analysis.get("summary")
        if summary:
            print(f"ANALYSIS_SUMMARY={safe_terminal_text(summary)}")
        if analysis.get("assessment"):
            print(f"ANALYSIS_ASSESSMENT={safe_terminal_text(analysis['assessment'])}")
        scan = analysis.get("scan", {})
        if isinstance(scan, dict):
            print(f"ANALYSIS_SCAN_COMPLETE={str(bool(scan.get('complete'))).lower()}")
            print(f"ANALYSIS_SCANNED_PATHS={scan.get('scanned_path_count', 0)}")
            print(f"ANALYSIS_SCANNED_BYTES={scan.get('scanned_bytes', 0)}")
        correlation_scan = analysis.get("correlation_scan", {})
        if isinstance(correlation_scan, dict):
            print(
                "ANALYSIS_CORRELATION_SCAN_COMPLETE="
                f"{str(bool(correlation_scan.get('complete'))).lower()}"
            )
            print(
                "ANALYSIS_CORRELATION_SCANNED_BYTES="
                f"{correlation_scan.get('scanned_bytes', 0)}"
            )
        selected_logs = analysis.get("selected_logs", [])
        if isinstance(selected_logs, list) and selected_logs:
            names = [item.get("name", "") for item in selected_logs if isinstance(item, dict) and item.get("name")]
            if names:
                print(f"ANALYSIS_SELECTED_LOGS={safe_terminal_text(','.join(names))}")
        evidence = analysis.get("evidence", [])
        if isinstance(evidence, list):
            for item in evidence:
                if not isinstance(item, dict):
                    continue
                print(
                    "EVIDENCE="
                    f"{safe_terminal_text(item.get('path', ''))}:{safe_terminal_text(item.get('line_number', ''))}: "
                    f"{safe_terminal_text(item.get('line', ''))}"
                )
        timeline = analysis.get("timeline", [])
        if isinstance(timeline, list):
            for item in timeline:
                if not isinstance(item, dict):
                    continue
                print(
                    "TIMELINE="
                    f"{safe_terminal_text(item.get('timestamp', ''))} "
                    f"{safe_terminal_text(item.get('path', ''))}:{safe_terminal_text(item.get('line_number', ''))}"
                )
        findings = analysis.get("evidence_findings", [])
        if isinstance(findings, list):
            print(f"ANALYSIS_FINDINGS={len(findings)}")
        structured = analysis.get("structured_summaries", [])
        if isinstance(structured, list):
            print(f"ANALYSIS_STRUCTURED_SUMMARIES={len(structured)}")
        event_correlations = analysis.get("event_correlations", [])
        if isinstance(event_correlations, list):
            print(f"ANALYSIS_EVENT_CORRELATIONS={len(event_correlations)}")


def build_payload(
    *,
    ok: bool,
    code: str,
    error: str,
    request: dict[str, object],
    result: dict[str, object],
    include_sensitive_context: bool = False,
) -> dict[str, object]:
    normalized_error = error
    if not ok and not str(error).strip():
        normalized_error = "Unexpected analyzer failure."
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "openubmc_log_bundle_analyzer",
        "output_policy": {
            "profile": "sensitive_context" if include_sensitive_context else "shareable",
            "credential_redaction": True,
            "common_identifier_redaction": not include_sensitive_context,
            "location_redaction": not include_sensitive_context,
        },
        "ok": ok,
        "code": code,
        "error": normalized_error,
        "request": request,
        "result": result,
    }


class _JsonFriendlyArgumentParser(argparse.ArgumentParser):
    """Raise a catchable error instead of writing an unstructured traceback."""

    def error(self, message: str) -> None:
        raise argparse.ArgumentError(None, message)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = _JsonFriendlyArgumentParser(
        description="校验并按问题分析本地 openUBMC 一键日志包。",
        add_help=False,
        exit_on_error=False,
    )
    parser._positionals.title = "位置参数"
    parser._optionals.title = "选项"
    parser.add_argument("-h", "--help", action="help", help="显示帮助信息并退出。")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--bundle", default="", help="本地 .tar 或 .tar.gz 一键日志包。")
    source.add_argument("--bundle-dir", default="", help="已解压的一键日志包目录。")
    parser.add_argument("--extract-dir", default="", help="本地解压目录的父目录。")
    parser.add_argument("--problem", default="", help="解压后用于问题驱动选日志的问题描述。")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="只校验日志包结构；不进行问题驱动分析。",
    )
    parser.add_argument("--analysis-max-files", type=int, default=DEFAULT_ANALYSIS_MAX_FILES, help="最多分析的日志类型数量。")
    parser.add_argument("--analysis-max-lines", type=int, default=DEFAULT_ANALYSIS_MAX_LINES, help="每类日志最多抽取的证据行数。")
    parser.add_argument(
        "--analysis-max-paths-per-log",
        type=int,
        default=DEFAULT_ANALYSIS_MAX_PATHS_PER_LOG,
        help="每类日志最多扫描的实际文件数。",
    )
    parser.add_argument(
        "--analysis-max-bytes-per-file",
        type=int,
        default=DEFAULT_ANALYSIS_MAX_BYTES_PER_FILE,
        help="每个日志文件最多扫描的解压后字节数。",
    )
    parser.add_argument(
        "--analysis-max-total-bytes",
        type=int,
        default=DEFAULT_ANALYSIS_MAX_TOTAL_BYTES,
        help="本次分析最多扫描的解压后总字节数。",
    )
    parser.add_argument(
        "--analysis-max-line-bytes",
        type=int,
        default=DEFAULT_ANALYSIS_MAX_LINE_BYTES,
        help="单行日志允许扫描的最大字节数，超长行会被跳过并记录。",
    )
    parser.add_argument("--analysis-since", default="", help="只保留不早于该时间的分析证据，格式 YYYY-MM-DDTHH:MM:SS。")
    parser.add_argument("--analysis-until", default="", help="只保留不晚于该时间的分析证据，格式 YYYY-MM-DDTHH:MM:SS。")
    parser.add_argument(
        "--analysis-timezone",
        default="",
        help="解释无时区日志时间的时区（UTC、±HH:MM 或 IANA 名称）；未指定时不跨时区关联。",
    )
    parser.add_argument("--json", action="store_true", help="输出 JSON 结构化结果。")
    parser.add_argument(
        "--output-json", default="",
        help="将成功结果另存为 UTF-8 JSON（无 BOM）；目标须为日志目录之外、已有目录内的新文件。",
    )
    parser.add_argument(
        "--include-sensitive-context",
        action="store_true",
        help=(
            "保留本地路径及普通资产标识；凭据仍会脱敏。"
            "此输出不应未经检查直接公开。"
        ),
    )
    return parser.parse_args(argv)


def _empty_request(*, include_sensitive_context: bool = False) -> dict[str, object]:
    return {
        "bundle": "",
        "bundle_dir": "",
        "problem": "",
        "validate_only": False,
        "analysis_since": "",
        "analysis_until": "",
        "analysis_timezone": "",
        "include_sensitive_context": include_sensitive_context,
        "analysis_limits": {
            "max_files": DEFAULT_ANALYSIS_MAX_FILES,
            "max_lines": DEFAULT_ANALYSIS_MAX_LINES,
            "max_paths_per_log": DEFAULT_ANALYSIS_MAX_PATHS_PER_LOG,
            "max_bytes_per_file": DEFAULT_ANALYSIS_MAX_BYTES_PER_FILE,
            "max_total_bytes": DEFAULT_ANALYSIS_MAX_TOTAL_BYTES,
            "max_line_bytes": DEFAULT_ANALYSIS_MAX_LINE_BYTES,
        },
    }


def _validate_numeric_options(args: argparse.Namespace) -> None:
    """Reject non-positive or resource-amplifying CLI values early."""

    bounded_options = {
        "--analysis-max-files": (args.analysis_max_files, MAX_ANALYSIS_MAX_FILES),
        "--analysis-max-lines": (args.analysis_max_lines, MAX_ANALYSIS_MAX_LINES),
        "--analysis-max-paths-per-log": (args.analysis_max_paths_per_log, MAX_ANALYSIS_MAX_PATHS_PER_LOG),
        "--analysis-max-bytes-per-file": (args.analysis_max_bytes_per_file, MAX_ANALYSIS_MAX_BYTES_PER_FILE),
        "--analysis-max-total-bytes": (args.analysis_max_total_bytes, MAX_ANALYSIS_MAX_TOTAL_BYTES),
        "--analysis-max-line-bytes": (args.analysis_max_line_bytes, MAX_ANALYSIS_MAX_LINE_BYTES),
    }
    invalid_options: list[str] = []
    for name, (value, upper_bound) in bounded_options.items():
        if value < 1 or value > upper_bound:
            invalid_options.append(f"{name} (1..{upper_bound})")
    if invalid_options:
        raise BundleAnalysisError(
            "invalid_request",
            "Invalid numeric option(s): " + ", ".join(invalid_options),
        )


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    json_requested = "--json" in raw_argv
    sensitive_context_requested = "--include-sensitive-context" in raw_argv
    try:
        args = parse_args(raw_argv)
    except argparse.ArgumentError as exc:
        message, _ = redact_sensitive_text(f"Invalid command-line arguments: {exc}")
        if json_requested:
            emit_result(
                build_payload(
                    ok=False,
                    code="argument_error",
                    error=message,
                    request=_empty_request(
                        include_sensitive_context=sensitive_context_requested,
                    ),
                    result={
                        "source_kind": "",
                        "bundle": {},
                        "validation": {},
                    },
                    include_sensitive_context=sensitive_context_requested,
                ),
                json_mode=True,
                include_sensitive_context=sensitive_context_requested,
            )
        else:
            print(message, file=sys.stderr)
        return 2
    try:
        _validate_numeric_options(args)
    except BundleAnalysisError as exc:
        emit_result(
            build_payload(
                ok=False,
                code=exc.code,
                error=exc.redacted_message,
                request=_empty_request(
                    include_sensitive_context=args.include_sensitive_context,
                ),
                result={
                    "source_kind": "",
                    "bundle": {},
                    "validation": {},
                },
                include_sensitive_context=args.include_sensitive_context,
            ),
            json_mode=args.json,
            include_sensitive_context=args.include_sensitive_context,
        )
        return 1
    payload = run_request(args)
    try:
        emit_result(
            payload,
            json_mode=args.json,
            include_sensitive_context=args.include_sensitive_context,
            output_json=args.output_json if payload["ok"] else "",
        )
    except BundleAnalysisError as exc:
        payload = {**payload, "ok": False, "code": exc.code, "error": exc.redacted_message}
        emit_result(payload, json_mode=args.json, include_sensitive_context=args.include_sensitive_context)
    return 0 if payload["ok"] else 1


def run_request(args: argparse.Namespace) -> dict[str, object]:
    """Analyze validated options without printing or writing the result payload."""
    request = {
        "bundle": args.bundle,
        "bundle_dir": args.bundle_dir,
        "problem": args.problem,
        "validate_only": args.validate_only,
        "analysis_since": args.analysis_since,
        "analysis_until": args.analysis_until,
        "analysis_timezone": args.analysis_timezone,
        "include_sensitive_context": args.include_sensitive_context,
        "analysis_limits": {
            "max_files": args.analysis_max_files,
            "max_lines": args.analysis_max_lines,
            "max_paths_per_log": args.analysis_max_paths_per_log,
            "max_bytes_per_file": args.analysis_max_bytes_per_file,
            "max_total_bytes": args.analysis_max_total_bytes,
            "max_line_bytes": args.analysis_max_line_bytes,
        },
        "extract_dir": args.extract_dir,
    }

    source_kind = ""
    archive_path: pathlib.Path | None = None
    archive_sha256 = ""
    extract_result: ExtractionResult | None = None
    validation: dict[str, object] = {}
    analysis: dict[str, object] | None = None
    try:
        if not any((args.bundle, args.bundle_dir)):
            raise BundleAnalysisError(
                "missing_source",
                "Provide one of --bundle or --bundle-dir.",
            )
        if not args.problem.strip() and not args.validate_only:
            raise BundleAnalysisError(
                "missing_problem",
                "Provide --problem for analysis, or use --validate-only for structure validation only.",
            )
        if args.problem.strip() and args.validate_only:
            raise BundleAnalysisError(
                "invalid_request",
                "Use either --problem or --validate-only, not both.",
            )
        if args.bundle:
            archive_path = pathlib.Path(args.bundle).expanduser().resolve()
            if not archive_path.is_file():
                raise BundleAnalysisError("bundle_not_found", f"Bundle file not found: {archive_path}")
            if not tarfile.is_tarfile(archive_path):
                raise BundleAnalysisError("bundle_format_invalid", f"Not a readable tar archive: {archive_path}")
            source_kind = "local_archive"
            archive_sha256 = sha256_file(archive_path)
            extract_parent = pathlib.Path(
                args.extract_dir or pathlib.Path(tempfile.gettempdir()) / "openubmc-log-bundle-analyzer/extract"
            )
            request["extract_dir"] = str(extract_parent)
            extract_result = extract_archive(archive_path, extract_parent)
        else:
            input_dir = pathlib.Path(args.bundle_dir).expanduser()
            if not input_dir.is_dir():
                raise BundleAnalysisError("bundle_dir_not_found", f"Bundle directory not found: {input_dir}")
            if input_dir.is_symlink():
                raise BundleAnalysisError(
                    "bundle_layout_invalid",
                    f"Bundle directory must not be a symbolic link: {input_dir}",
                )
            source_kind = "extracted_directory"
            if input_dir.name == "dump_info":
                bundle_root = input_dir.parent
            else:
                bundle_root = locate_bundle_root(input_dir)
            extract_result = ExtractionResult(
                extract_dir=input_dir,
                bundle_root=bundle_root,
            )

        if extract_result is None:
            raise BundleAnalysisError("runtime_error", "Bundle extraction did not produce a bundle root.")
        validation = validate_bundle_structure(extract_result.bundle_root)

        if args.problem.strip() and not args.validate_only:
            analysis_timezone = parse_analysis_timezone(args.analysis_timezone)
            analysis_since = parse_analysis_time_bound(
                args.analysis_since,
                label="--analysis-since",
                default_timezone=analysis_timezone,
            )
            analysis_until = parse_analysis_time_bound(
                args.analysis_until,
                label="--analysis-until",
                default_timezone=analysis_timezone,
            )
            if analysis_since and analysis_until:
                comparison = compare_datetimes(
                    analysis_since,
                    analysis_until,
                    default_timezone=analysis_timezone,
                )
                if comparison is None:
                    raise BundleAnalysisError(
                        "invalid_request",
                        "Analysis bounds use mixed timezone domains; provide --analysis-timezone or matching offsets.",
                    )
                if comparison > 0:
                    raise BundleAnalysisError("invalid_request", "--analysis-since 不能晚于 --analysis-until。")
            analysis = analyze_bundle(
                extract_result.bundle_root,
                args.problem.strip(),
                max_files=args.analysis_max_files,
                max_lines=args.analysis_max_lines,
                max_paths_per_log=args.analysis_max_paths_per_log,
                max_bytes_per_file=args.analysis_max_bytes_per_file,
                max_total_bytes=args.analysis_max_total_bytes,
                max_line_bytes=args.analysis_max_line_bytes,
                since=analysis_since,
                until=analysis_until,
                analysis_timezone=analysis_timezone,
            )

        if archive_path and sha256_file(archive_path) != archive_sha256:
            raise BundleAnalysisError(
                "bundle_identity_changed",
                "The bundle archive changed while it was being validated or analyzed.",
            )

        if args.output_json and pathlib.Path(args.output_json).expanduser().resolve().is_relative_to(
            extract_result.bundle_root.resolve()
        ):
            raise BundleAnalysisError(
                "output_path_invalid", "JSON output must be outside the input bundle directory.",
            )

        result = {
            "source_kind": source_kind,
            "bundle": {
                "archive_path": str(archive_path) if archive_path else "",
                "sha256": archive_sha256,
                "extract_dir": str(extract_result.extract_dir),
                "bundle_root": str(extract_result.bundle_root.resolve()),
            },
            "validation": validation,
        }
        if analysis is not None:
            result["analysis"] = analysis
        return build_payload(
            ok=True,
            code="ok",
            error="",
            request=request,
            result=result,
            include_sensitive_context=args.include_sensitive_context,
        )
    except BundleAnalysisError as exc:
        partial_result: dict[str, object] = {
            "source_kind": source_kind,
            "bundle": {
                "archive_path": str(archive_path) if archive_path else "",
                "sha256": archive_sha256,
                "extract_dir": str(extract_result.extract_dir) if extract_result else "",
                "bundle_root": str(extract_result.bundle_root.resolve()) if extract_result else "",
            },
            "validation": validation,
        }
        if analysis is not None:
            partial_result["analysis"] = analysis
        return build_payload(
            ok=False,
            code=exc.code,
            error=exc.redacted_message,
            request=request,
            result=partial_result,
            include_sensitive_context=args.include_sensitive_context,
        )
    except Exception as exc:
        # This is the final CLI boundary.  Library helpers still raise precise
        # exceptions, but an unexpected defect must not escape as a traceback
        # that violates the JSON contract or exposes raw bundle data.
        safe_error, _ = redact_sensitive_text(str(exc))
        return build_payload(
            ok=False,
            code="runtime_error",
            error=safe_error,
            request=request,
            result={
                "source_kind": source_kind,
                "bundle": {
                    "archive_path": str(archive_path) if archive_path else "",
                    "sha256": archive_sha256,
                    "extract_dir": str(extract_result.extract_dir) if extract_result else "",
                    "bundle_root": str(extract_result.bundle_root.resolve()) if extract_result else "",
                },
                "validation": validation,
            },
            include_sensitive_context=args.include_sensitive_context,
        )


if __name__ == "__main__":
    sys.exit(main())
