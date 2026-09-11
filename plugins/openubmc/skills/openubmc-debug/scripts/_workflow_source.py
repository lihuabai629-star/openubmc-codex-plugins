#!/usr/bin/env python3
"""Bounded exact-term source search for the openUBMC debug workflow."""
from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import re
import shutil
import stat
import subprocess
import threading
import time


_SOURCE_LINE_LIMIT = 2000
_SOURCE_READ_CHUNK = 64 * 1024
_SOURCE_INCOMPLETE_PATH_LIMIT = 20
_SKIP_DIRECTORIES = {".git", ".codegraph", "__pycache__", "node_modules"}
_EMIT_RE = re.compile(
    r"\b(?:emit|raise|report|publish|create|add|send|set)[A-Za-z0-9_]*(?:alarm|event)"
    r"|\b(?:alarm|event)[A-Za-z0-9_]*(?:emit|raise|report|publish|create|add|send|set)",
    re.IGNORECASE,
)
_TRIGGER_RE = re.compile(
    r"\b(?:if|when|unless|condition|compare|predicate|trigger)\b|(?:<=|>=|==|!=|<|>)",
    re.IGNORECASE,
)
_SAMPLE_SOURCE_RE = re.compile(
    r"\b(?:sample|sampled|reading|measured|measurement|current_value|sensor_value)\b",
    re.IGNORECASE,
)
_THRESHOLD_SOURCE_RE = re.compile(
    r"\b(?:threshold|limit|lower_limit|upper_limit|min_value|max_value)\b",
    re.IGNORECASE,
)


def source_search_tool_available() -> bool:
    return bool(shutil.which("rg"))


def _literal_token_matches(text: str, term: str) -> bool:
    if not term:
        return False
    return bool(
        re.search(
            rf"(?<!\w){re.escape(term)}(?!\w)",
            text,
        )
    )


def codegraph_available(root: Path) -> bool:
    return (root / ".codegraph").is_dir() and bool(shutil.which("codegraph"))


def source_dimensions(text: str, path: str) -> set[str]:
    dimensions: set[str] = set()
    lowered_path = path.casefold()
    if (
        Path(path).suffix.casefold() in {".json", ".yaml", ".yml", ".xml"}
        or any(token in lowered_path for token in ("event", "alarm", "schema", "model"))
    ):
        dimensions.add("definition")
    if _EMIT_RE.search(text):
        dimensions.add("emit")
    if _TRIGGER_RE.search(text):
        dimensions.add("trigger")
    if _SAMPLE_SOURCE_RE.search(text):
        dimensions.add("sample")
    if _THRESHOLD_SOURCE_RE.search(text):
        dimensions.add("threshold")
    return dimensions


def _term_quotas(terms: list[str], max_matches: int) -> dict[str, int]:
    if not terms:
        return {}
    budget = max(0, max_matches)
    base, remainder = divmod(budget, len(terms))
    return {
        term: base + (1 if index < remainder else 0)
        for index, term in enumerate(terms)
    }


def _source_match(
    term: str,
    path: str,
    line_number: int,
    text: str,
) -> dict[str, object]:
    clean_text = text.rstrip("\r\n")
    line_truncated = len(clean_text) > _SOURCE_LINE_LIMIT
    if line_truncated:
        clean_text = clean_text[: _SOURCE_LINE_LIMIT - 3] + "..."
    return {
        "term": term,
        "path": path,
        "line": line_number,
        "text": clean_text,
        "line_truncated": line_truncated,
    }


def _read_process_lines(
    process: subprocess.Popen[str],
    *,
    timeout: float,
):
    output_queue: queue.Queue[str | None] = queue.Queue(maxsize=128)

    def reader() -> None:
        assert process.stdout is not None
        try:
            for line in process.stdout:
                output_queue.put(line)
        finally:
            output_queue.put(None)

    threading.Thread(target=reader, daemon=True).start()
    end = time.monotonic() + timeout
    while True:
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, timeout)
        try:
            item = output_queue.get(timeout=min(0.1, remaining))
        except queue.Empty:
            if process.poll() is not None and output_queue.empty():
                return
            continue
        if item is None:
            return
        yield item


def _search_term_with_rg(
    rg: str,
    root: Path,
    term: str,
    quota: int,
    timeout: float,
) -> tuple[list[dict[str, object]], bool, str, bool]:
    command = [rg, "--json", "--no-messages", "-F", "-e", term, str(root)]
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        return [], False, str(exc), False
    matches: list[dict[str, object]] = []
    truncated = False
    timed_out = False
    error = ""
    try:
        for raw_line in _read_process_lines(process, timeout=timeout):
            try:
                event = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            if truncated or event.get("type") != "match":
                continue
            data = event.get("data", {})
            path_data = data.get("path", {}) if isinstance(data, dict) else {}
            line_data = data.get("lines", {}) if isinstance(data, dict) else {}
            path_text = str(path_data.get("text", ""))
            line_text = str(line_data.get("text", ""))
            if not _literal_token_matches(line_text, term):
                continue
            try:
                path_text = str(Path(path_text).relative_to(root))
            except (ValueError, OSError):
                pass
            match = _source_match(
                term,
                path_text,
                int(data.get("line_number", 0) or 0),
                line_text,
            )
            if len(matches) < quota:
                matches.append(match)
            else:
                truncated = True
                process.terminate()
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
    finally:
        try:
            returncode = process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            returncode = process.wait()
        if process.stderr is not None:
            error = process.stderr.read().strip()
            process.stderr.close()
        if process.stdout is not None:
            process.stdout.close()
    if not timed_out and returncode not in {0, 1, -15} and not truncated:
        error = error or f"rg exited with status {returncode}"
    return matches, truncated, error, timed_out


def _python_source_search(
    root: Path,
    terms: list[str],
    quotas: dict[str, int],
    timeout: float,
) -> tuple[
    dict[str, list[dict[str, object]]],
    dict[str, bool],
    bool,
    int,
    str,
    list[str],
]:
    found = {term: [] for term in terms}
    overflow = {term: False for term in terms}
    started = time.monotonic()
    scanned_files = 0
    incomplete_paths: list[str] = []

    def relative_path(path: Path) -> str:
        try:
            return str(path.relative_to(root))
        except ValueError:
            return str(path)

    def mark_incomplete(path: Path) -> None:
        relative = relative_path(path)
        if relative not in incomplete_paths:
            incomplete_paths.append(relative)

    def walk_error(error: OSError) -> None:
        filename = getattr(error, "filename", None)
        mark_incomplete(Path(filename) if filename else root)

    def incomplete_error() -> str:
        if not incomplete_paths:
            return ""
        preview = incomplete_paths[:_SOURCE_INCOMPLETE_PATH_LIMIT]
        suffix = "..." if len(incomplete_paths) > len(preview) else ""
        return (
            "source search incomplete; unreadable or unscanned paths="
            f"{len(incomplete_paths)} ({', '.join(preview)}{suffix})"
        )

    for directory, names, filenames in os.walk(root, onerror=walk_error):
        names[:] = sorted(
            name
            for name in names
            if name not in _SKIP_DIRECTORIES
            and not Path(directory, name).is_symlink()
        )
        for filename in sorted(filenames):
            if time.monotonic() - started >= timeout:
                return (
                    found,
                    overflow,
                    True,
                    scanned_files,
                    "source search timed out",
                    incomplete_paths,
                )
            path = Path(directory, filename)
            try:
                path_stat = path.lstat()
            except OSError:
                mark_incomplete(path)
                continue
            if not stat.S_ISREG(path_stat.st_mode):
                continue
            try:
                stream = path.open("r", encoding="utf-8", errors="ignore")
            except OSError:
                mark_incomplete(path)
                continue
            scanned_files += 1
            try:
                line_number = 1
                line_preview = ""
                line_matches: set[str] = set()
                pending = ""
                maximum_term_length = max(len(term) for term in terms)

                def scan_text(text: str) -> None:
                    for term in terms:
                        if term not in line_matches and _literal_token_matches(text, term):
                            line_matches.add(term)

                def finish_line() -> bool:
                    for term in terms:
                        if term not in line_matches:
                            continue
                        if len(found[term]) < quotas[term]:
                            found[term].append(
                                _source_match(
                                    term,
                                    relative_path(path),
                                    line_number,
                                    line_preview,
                                )
                            )
                        else:
                            overflow[term] = True
                    return bool(overflow) and all(overflow.values())

                while True:
                    if time.monotonic() - started >= timeout:
                        return (
                            found,
                            overflow,
                            True,
                            scanned_files,
                            "source search timed out",
                            incomplete_paths,
                        )
                    chunk = stream.readline(_SOURCE_READ_CHUNK)
                    if not chunk:
                        if pending or line_preview or line_matches:
                            scan_text(pending)
                            if finish_line():
                                return (
                                    found,
                                    overflow,
                                    False,
                                    scanned_files,
                                    incomplete_error(),
                                    incomplete_paths,
                                )
                        break
                    if "\x00" in chunk:
                        pending = ""
                        line_preview = ""
                        line_matches.clear()
                        break
                    if len(line_preview) <= _SOURCE_LINE_LIMIT:
                        remaining_preview = _SOURCE_LINE_LIMIT + 1 - len(line_preview)
                        line_preview += chunk[:remaining_preview]
                    combined = pending + chunk
                    if chunk.endswith(("\n", "\r")):
                        scan_text(combined)
                        pending = ""
                        if finish_line():
                            return (
                                found,
                                overflow,
                                False,
                                scanned_files,
                                incomplete_error(),
                                incomplete_paths,
                            )
                        line_number += 1
                        line_preview = ""
                        line_matches.clear()
                    else:
                        retained = maximum_term_length + 1
                        split_at = max(0, len(combined) - retained)
                        scan_text(combined[:split_at])
                        pending = combined[split_at:]
            finally:
                stream.close()
    return (
        found,
        overflow,
        False,
        scanned_files,
        incomplete_error(),
        incomplete_paths,
    )


def _merge_source_matches(
    terms: list[str],
    per_term_matches: dict[str, list[dict[str, object]]],
) -> list[dict[str, object]]:
    merged: dict[tuple[str, int, str], dict[str, object]] = {}
    for term in terms:
        for match in per_term_matches.get(term, []):
            key = (
                str(match["path"]),
                int(match["line"]),
                str(match["text"]),
            )
            if key not in merged:
                merged[key] = {
                    "id": -1,
                    "terms": [],
                    "path": match["path"],
                    "line": match["line"],
                    "text": match["text"],
                    "line_truncated": match["line_truncated"],
                }
            merged[key]["terms"].append(term)
    matches = list(merged.values())
    for index, match in enumerate(matches):
        match["id"] = index
    return matches


def search_source_terms(
    source_root: str,
    terms: list[str],
    max_matches: int,
    timeout: int | float,
) -> dict[str, object]:
    root = Path(source_root)
    rg = shutil.which("rg")
    has_codegraph = codegraph_available(root)
    if not root.is_dir():
        return {
            "ok": False,
            "code": "source_root_missing",
            "method": "none",
            "rg_available": bool(rg),
            "codegraph_available": has_codegraph,
            "matches": [],
            "hits": [],
            "per_term": {},
            "truncated": False,
            "timed_out": False,
            "error": f"Source root does not exist: {source_root}",
        }
    unique_terms = list(dict.fromkeys(term for term in terms if term))
    if not unique_terms:
        return {
            "ok": False,
            "code": "skipped",
            "method": "none",
            "rg_available": bool(rg),
            "codegraph_available": has_codegraph,
            "matches": [],
            "hits": [],
            "per_term": {},
            "truncated": False,
            "timed_out": False,
            "error": "No source search terms were available",
        }
    quotas = _term_quotas(unique_terms, max_matches)
    per_term_matches: dict[str, list[dict[str, object]]] = {}
    overflow: dict[str, bool] = {}
    errors: list[str] = []
    timed_out = False
    scanned_files: int | None = None
    incomplete_paths: list[str] = []
    started = time.monotonic()
    if rg:
        method = "rg"
        for term in unique_terms:
            remaining = max(
                0.001,
                min(float(timeout), 60.0) - (time.monotonic() - started),
            )
            if remaining <= 0.001:
                timed_out = True
                per_term_matches[term] = []
                overflow[term] = True
                continue
            matches, truncated, error, term_timed_out = _search_term_with_rg(
                rg, root, term, quotas[term], remaining
            )
            per_term_matches[term] = matches
            overflow[term] = truncated or term_timed_out
            timed_out = timed_out or term_timed_out
            if error:
                errors.append(f"{term}: {error}")
    else:
        method = "python"
        (
            per_term_matches,
            overflow,
            timed_out,
            scanned_files,
            error,
            incomplete_paths,
        ) = _python_source_search(
            root,
            unique_terms,
            quotas,
            min(float(timeout), 60.0),
        )
        if error:
            errors.append(error)
    if timed_out:
        # A timed-out search cannot prove that any term had no additional
        # matches. Mark every per-term result as truncated instead of exposing
        # an incomplete search as a successful negative finding.
        overflow.update({term: True for term in unique_terms})
    if errors:
        overflow.update({term: True for term in unique_terms})
    matches = _merge_source_matches(unique_terms, per_term_matches)
    per_term = {
        term: {
            "quota": quotas[term],
            "returned": len(per_term_matches.get(term, [])),
            "truncated": bool(overflow.get(term)),
        }
        for term in unique_terms
    }
    rendered_hits = [
        f"{match['path']}:{match['line']}:{match['text']}" for match in matches
    ]
    failed = timed_out or bool(errors)
    return {
        "ok": not failed,
        "code": (
            "source_search_timeout"
            if timed_out
            else (
                "source_search_incomplete"
                if errors and method == "python"
                else ("source_search_failed" if errors else "ok")
            )
        ),
        "method": method,
        "rg_available": bool(rg),
        "codegraph_available": has_codegraph,
        "matches": matches,
        "hits": rendered_hits,
        "per_term": per_term,
        "requested_limit": max_matches,
        "effective_limit": sum(quotas.values()),
        "truncated": any(overflow.values()),
        "timed_out": timed_out,
        "scanned_files": scanned_files,
        "incomplete_path_count": len(incomplete_paths),
        "incomplete_paths": incomplete_paths[:_SOURCE_INCOMPLETE_PATH_LIMIT],
        "trace_candidates": [
            {"symbol": term, "helper": "source_trace.py"}
            for term in unique_terms[:20]
            if len(term) <= 200
            and re.fullmatch(r"[A-Za-z_]\w*(?:[.:][A-Za-z_]\w*)*", term)
            and per_term[term]["returned"]
        ],
        "error": "; ".join(errors),
    }
