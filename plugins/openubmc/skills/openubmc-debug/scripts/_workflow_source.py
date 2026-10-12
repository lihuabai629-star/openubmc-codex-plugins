#!/usr/bin/env python3
"""Bounded exact-term source search for the openUBMC debug workflow."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import queue
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from _source_catalog import SourceCatalog


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
                path_text = Path(path_text).relative_to(root).as_posix()
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
            return path.relative_to(root).as_posix()
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
    provenance = SourceCatalog(root, timeout=max(0.0, min(float(timeout), 60.0) -
                                                (time.monotonic() - started))).annotate(matches)
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
        "provenance": provenance,
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


# The index is a disposable local cache. SourceCatalog is deliberately consulted
# after every query: branch, commit, catalog selection and matched-file dirty
# state must describe the current checkout, not the last indexing pass.
_INDEX_VERSION = "2"
_INDEX_SUFFIXES = {
    ".lua", ".c", ".cc", ".cpp", ".h", ".hpp", ".json", ".yaml",
    ".yml", ".xml", ".ini", ".conf", ".toml",
}
_INDEX_TOKEN_RE = re.compile(
    r"0x[0-9a-fA-F]+|/[A-Za-z_][A-Za-z0-9_./-]*|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:(?:::|[.:])[A-Za-z_][A-Za-z0-9_]*)*"
)
_QUERY_STOP_WORDS = {
    "a", "an", "and", "are", "by", "does", "for", "from", "how", "in",
    "is", "of", "on", "or", "the", "to", "what", "where", "which", "with",
}


class SourceIndexUnavailable(Exception):
    """A local cache failed; callers should use bounded text search."""


def _windows_private_storage():
    """Find the Runtime sibling when this source helper runs alone."""
    sibling = Path(__file__).resolve().parents[2] / "openubmc-target-runtime"
    if str(sibling) not in sys.path:
        sys.path.insert(0, str(sibling))
    from openubmc_target_runtime import windows_private
    return windows_private


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _default_index_path(root: Path) -> Path:
    cache_root = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache").expanduser().absolute()
    identity = hashlib.sha256(os.fsencode(str(root))).hexdigest()[:24]
    return cache_root / "openubmc" / "source-index" / (identity + ".sqlite3")


def _index_connection(root: Path, index_path: Path) -> sqlite3.Connection:
    if index_path.is_symlink():
        raise SourceIndexUnavailable("index_path_symlink")
    if os.name == "nt":
        _windows_private_storage().ensure_private_directory(index_path.parent)
    else:
        index_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    created = not index_path.exists()
    if not index_path.exists():
        try:
            fd = os.open(index_path, os.O_CREAT | os.O_EXCL | os.O_RDWR |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.close(fd)
        except FileExistsError:
            pass
    fd = os.open(index_path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise SourceIndexUnavailable("index_not_regular")
        if os.name == "nt":
            private = _windows_private_storage()
            if created:
                private.harden_new_file(index_path)
            else:
                private.verify_private_path(index_path)
        else:
            os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    connection = sqlite3.connect(index_path, timeout=0.5)
    connection.execute("PRAGMA busy_timeout=500")
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS index_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS index_files (
            path TEXT PRIMARY KEY, digest TEXT NOT NULL, indexed_at TEXT NOT NULL,
            warnings TEXT NOT NULL DEFAULT '[]'
        );
        CREATE TABLE IF NOT EXISTS index_lines (
            path TEXT NOT NULL, line INTEGER NOT NULL, text TEXT NOT NULL,
            PRIMARY KEY (path, line)
        );
        CREATE TABLE IF NOT EXISTS index_tokens (
            token TEXT NOT NULL, path TEXT NOT NULL, line INTEGER NOT NULL,
            PRIMARY KEY (token, path, line)
        );
        CREATE INDEX IF NOT EXISTS index_tokens_path ON index_tokens(path);
    """)
    metadata = dict(connection.execute("SELECT key, value FROM index_meta"))
    if metadata and (metadata.get("root") != str(root)
                     or metadata.get("version") not in {"1", _INDEX_VERSION}):
        connection.close()
        raise SourceIndexUnavailable("index_identity_mismatch")
    columns = {row[1] for row in connection.execute("PRAGMA table_info(index_files)")}
    with connection:
        if "warnings" not in columns:
            connection.execute("ALTER TABLE index_files ADD COLUMN warnings TEXT NOT NULL DEFAULT '[]'")
        if metadata.get("version") == "1":
            # A v1 cache did not retain its incomplete-file warnings. Reindex
            # those files before it can claim a complete result again.
            connection.execute("UPDATE index_files SET digest='' ")
            connection.execute("UPDATE index_meta SET value=? WHERE key='version'", (_INDEX_VERSION,))
        if not metadata:
            connection.executemany("INSERT INTO index_meta(key, value) VALUES (?, ?)",
                                   [("version", _INDEX_VERSION), ("root", str(root))])
    return connection


def _remove_index_file(connection: sqlite3.Connection, relative: str) -> None:
    connection.execute("DELETE FROM index_tokens WHERE path=?", (relative,))
    connection.execute("DELETE FROM index_lines WHERE path=?", (relative,))
    connection.execute("DELETE FROM index_files WHERE path=?", (relative,))


def _sync_source_index(
    root: Path, index_path: Path, *, max_files: int, deadline: float,
) -> tuple[sqlite3.Connection, dict[str, object]]:
    connection = _index_connection(root, index_path)
    seen: set[str] = set()
    scanned = updated = unchanged = removed = 0
    bytes_read = 0
    warnings: set[str] = set()
    try:
        with connection:
            for directory, names, filenames in os.walk(root, onerror=lambda _: warnings.add("unreadable_directory")):
                if time.monotonic() >= deadline:
                    raise SourceIndexUnavailable("index_time_limit")
                names[:] = [name for name in sorted(names)
                            if name not in _SKIP_DIRECTORIES | {".openubmc"}
                            and not Path(directory, name).is_symlink()]
                for name in sorted(filenames):
                    path = Path(directory, name)
                    if path.absolute() == index_path:
                        continue
                    if path.suffix.casefold() not in _INDEX_SUFFIXES:
                        continue
                    if time.monotonic() >= deadline:
                        raise SourceIndexUnavailable("index_time_limit")
                    scanned += 1
                    if scanned > max_files:
                        raise SourceIndexUnavailable("index_file_limit")
                    relative = path.relative_to(root).as_posix()
                    seen.add(relative)
                    try:
                        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                                     getattr(os, "O_NONBLOCK", 0))
                        with os.fdopen(fd, "rb") as stream:
                            info = os.fstat(stream.fileno())
                            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                                raise ValueError("unsupported source size or type")
                            raw = stream.read(1024 * 1024 + 1)
                        if len(raw) > 1024 * 1024:
                            raise ValueError("source byte limit")
                    except (OSError, ValueError):
                        warnings.add("unreadable_or_oversize_file")
                        _remove_index_file(connection, relative)
                        continue
                    bytes_read += len(raw)
                    if bytes_read > 64 * 1024 * 1024:
                        raise SourceIndexUnavailable("index_total_byte_limit")
                    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
                    previous = connection.execute(
                        "SELECT digest, warnings FROM index_files WHERE path=?", (relative,)
                    ).fetchone()
                    if previous and previous[0] == digest:
                        try:
                            cached_warnings = json.loads(previous[1])
                        except (TypeError, ValueError) as exc:
                            raise SourceIndexUnavailable("invalid_cached_warnings") from exc
                        if (not isinstance(cached_warnings, list)
                                or not all(isinstance(value, str) for value in cached_warnings)):
                            raise SourceIndexUnavailable("invalid_cached_warnings")
                        warnings.update(cached_warnings)
                        unchanged += 1
                        continue
                    _remove_index_file(connection, relative)
                    text = raw.decode("utf-8", errors="replace")
                    lines = []
                    tokens = []
                    file_warnings: set[str] = set()
                    for number, line in enumerate(text.splitlines(), 1):
                        if number % 1024 == 0 and time.monotonic() >= deadline:
                            raise SourceIndexUnavailable("index_time_limit")
                        if number > 20000:
                            file_warnings.add("file_line_limit")
                            break
                        lines.append((relative, number, line[:_SOURCE_LINE_LIMIT]))
                        unique = set()
                        for match in _INDEX_TOKEN_RE.finditer(line):
                            token = match.group().casefold()
                            unique.add(token)
                            # Preserve exact qualified identifiers and their
                            # parts so prose can still locate Drive.update.
                            unique.update(part for part in re.split(r":{2}|[.:/]", token)
                                          if len(part) >= 3)
                        if len(unique) > 256:
                            file_warnings.add("line_token_limit")
                        tokens.extend((token, relative, number) for token in sorted(unique)[:256])
                    connection.executemany("INSERT INTO index_lines(path, line, text) VALUES (?, ?, ?)", lines)
                    connection.executemany("INSERT INTO index_tokens(token, path, line) VALUES (?, ?, ?)", tokens)
                    connection.execute(
                        "INSERT INTO index_files(path, digest, indexed_at, warnings) VALUES (?, ?, ?, ?)",
                        (relative, digest, _utc_now(), json.dumps(sorted(file_warnings))),
                    )
                    warnings.update(file_warnings)
                    updated += 1
            for (relative,) in connection.execute("SELECT path FROM index_files").fetchall():
                if relative not in seen:
                    _remove_index_file(connection, relative)
                    removed += 1
    except Exception:
        connection.close()
        raise
    return connection, {
        "path": str(index_path), "status": "partial" if warnings else "ready",
        "scanned_files": scanned, "hashed_bytes": bytes_read,
        "updated_files": updated, "unchanged_files": unchanged,
        "removed_files": removed, "warnings": sorted(warnings),
    }


def _query_tokens(query: str) -> tuple[list[str], bool]:
    exact = bool(query.isascii() and len(query) <= 200
                 and re.fullmatch(r"[A-Za-z0-9_./:-]+", query))
    if exact:
        return [query.casefold()], True
    tokens = [match.group().casefold() for match in _INDEX_TOKEN_RE.finditer(query)]
    return list(dict.fromkeys(token for token in tokens if len(token) >= 3
                              and token not in _QUERY_STOP_WORDS))[:8], False


def _index_candidates(
    connection: sqlite3.Connection, query: str, *, max_candidates: int,
    deadline: float,
) -> tuple[list[dict[str, object]], bool]:
    terms, exact = _query_tokens(query)
    candidates: dict[tuple[str, int], dict[str, object]] = {}
    truncated = False
    for term in terms:
        if time.monotonic() >= deadline:
            raise SourceIndexUnavailable("index_query_time_limit")
        rows = connection.execute("""
            SELECT t.path, t.line, l.text, f.digest, f.indexed_at
            FROM index_tokens AS t JOIN index_lines AS l
              ON l.path=t.path AND l.line=t.line
            JOIN index_files AS f ON f.path=t.path
            WHERE t.token=? ORDER BY t.path, t.line LIMIT ?
        """, (term, max_candidates + 1)).fetchall()
        if len(rows) > max_candidates:
            truncated = True
        for path, line, text, digest, indexed_at in rows[:max_candidates]:
            key = path, line
            item = candidates.setdefault(key, {"kind": "source", "path": path,
                                               "line": line, "text": text,
                                               "content_digest": digest,
                                               "indexed_at": indexed_at,
                                               "matched_terms": []})
            if term not in item["matched_terms"]:
                item["matched_terms"].append(term)
    if exact:
        # A filename or model/config path can be useful without a token on line 1.
        for path, digest, indexed_at in connection.execute(
            "SELECT path, digest, indexed_at FROM index_files ORDER BY path"
        ):
            if path.casefold() != query.casefold() and not path.casefold().endswith("/" + query.casefold()):
                continue
            key = path, 1
            if key not in candidates:
                row = connection.execute("SELECT text FROM index_lines WHERE path=? AND line=1", (path,)).fetchone()
                candidates[key] = {"kind": "source", "path": path, "line": 1,
                                   "text": row[0] if row else "", "content_digest": digest,
                                   "indexed_at": indexed_at, "matched_terms": [query.casefold()],
                                   "path_match": True}
            else:
                candidates[key]["path_match"] = True
    values = list(candidates.values())
    if len(values) > max_candidates:
        truncated = True
        values = values[:max_candidates]
    for item in values:
        item["match_type"] = (
            "exact_path" if item.get("path_match") else
            "exact_identifier" if exact else "query_terms"
        )
    return values, truncated


def _knowledge_candidates(receipt: object) -> tuple[list[dict[str, object]], dict[str, object]]:
    if receipt is None:
        return [], {"status": "not_requested"}
    if not isinstance(receipt, dict):
        return [], {"status": "unavailable", "code": "invalid_receipt"}
    payload = receipt.get("structuredContent", receipt)
    if not isinstance(payload, dict):
        return [], {"status": "unavailable", "code": "invalid_receipt"}
    if payload.get("ok") is False:
        error = payload.get("error")
        return [], {"status": "unavailable", "code": str(error.get("code", "kb_failed"))[:80]
                    if isinstance(error, dict) else "kb_failed"}
    result = payload.get("result", payload)
    if not isinstance(result, dict):
        return [], {"status": "unavailable", "code": "invalid_receipt"}
    references = result.get("references", [])
    if not isinstance(references, list):
        return [], {"status": "unavailable", "code": "invalid_references"}
    items = []
    seen = set()
    for reference in references[:16]:
        if not isinstance(reference, dict):
            continue
        identifier = reference.get("reference_id")
        path = reference.get("file_path")
        if not isinstance(identifier, (str, int)) or not isinstance(path, str):
            continue
        identifier = str(identifier)[:128]
        path = path[:512]
        if not identifier or not path or (identifier, path) in seen:
            continue
        seen.add((identifier, path))
        items.append({"kind": "knowledge_candidate", "reference_id": identifier,
                      "file_path": path, "evidence_ref": "kb:" + identifier,
                      "applicability": "unverified", "score": 5})
    status = "available" if items else "no_citable_references"
    return items, {"status": status, "returned": len(items),
                   "truncated": bool(result.get("truncated")) or len(references) > 16}


def _rank_source_matches(matches: list[dict[str, object]], query: str) -> list[dict[str, object]]:
    exact = _query_tokens(query)[1]
    for item in matches:
        source = item.get("source", {})
        if not isinstance(source, dict):
            source = {}
            item["source"] = source
        applicability = source.get("applicability")
        base = 150 if item.get("match_type") == "exact_path" else (120 if exact else 30)
        score = base + 12 * len(item.get("matched_terms", []))
        if applicability == "product_source_candidate":
            score += 40
        elif source.get("product_match") is False:
            score -= 20
        if source.get("modified"):
            score += 2  # visibly current dirty bytes, never a claim of deployment
        item["score"] = score
        item["evidence_ref"] = (f"source:{item['path']}:{item['line']}@{item['content_digest']}"
                                if item.get("content_digest") else None)
        source["dirty"] = source.get("modified")
        source["dirty_scope"] = "matched_file"
        item["freshness"] = {"indexed_at": item.pop("indexed_at", None),
                             "checked_at": _utc_now(), "scope": "local_source_bytes",
                             "identity_checked": bool(item.get("content_digest") and
                                                      source.get("content_digest") == item["content_digest"])}
    return sorted(matches, key=lambda item: (-item["score"], item["path"], item["line"]))


def navigate_source(
    source_root: str, query: str, *, index_path: str | None = None,
    kb_receipt: object = None, max_results: int = 12, max_files: int = 4096,
    timeout: float = 8.0,
) -> dict[str, object]:
    """Incremental local lookup with an optional already-fetched KB receipt.

    This function never contacts a device or KB service. A failed index uses
    the pre-existing bounded text search and preserves its provenance.
    """
    if not isinstance(query, str) or not query.strip() or len(query) > 2000:
        raise ValueError("query must contain 1-2000 characters")
    if not 1 <= max_results <= 40 or not 1 <= max_files <= 16384 or not 0 < timeout <= 30:
        raise ValueError("source navigation limits are outside the supported range")
    root = Path(source_root).resolve()
    if not root.is_dir():
        raise ValueError("source root does not exist")
    query = query.strip()
    index_file = Path(index_path).expanduser().absolute() if index_path else _default_index_path(root)
    started = time.monotonic()
    deadline = started + timeout
    knowledge, kb_status = _knowledge_candidates(kb_receipt)
    index_status: dict[str, object]
    truncated = False
    fallback = False
    try:
        if not _query_tokens(query)[0]:
            raise SourceIndexUnavailable("query_not_indexable")
        connection, index_status = _sync_source_index(root, index_file, max_files=max_files,
                                                       deadline=started + timeout * 0.65)
        try:
            matches, truncated = _index_candidates(connection, query,
                                                   max_candidates=min(256, max_results * 12),
                                                   deadline=deadline)
        finally:
            connection.close()
        provenance = SourceCatalog(root, timeout=max(0.0, deadline - time.monotonic())).annotate(matches)
        if any(item.get("source", {}).get("content_digest") not in
               {None, item["content_digest"]} for item in matches):
            raise SourceIndexUnavailable("source_changed_during_query")
    except (SourceIndexUnavailable, OSError, sqlite3.Error) as error:
        fallback = True
        index_status = {"path": str(index_file), "status": "unavailable",
                        "code": str(error)[:100] if isinstance(error, SourceIndexUnavailable)
                        else type(error).__name__}
        terms, exact = _query_tokens(query)
        search_terms = [query] if exact or not terms else terms[:3]
        search = search_source_terms(str(root), search_terms, min(80, max_results * 4),
                                     max(0.1, min(3.0, deadline - time.monotonic())))
        provenance = search.get("provenance", {})
        matches = [{**match, "kind": "source", "content_digest":
                    match.get("source", {}).get("content_digest"),
                    "matched_terms": match.get("terms", []),
                    "match_type": "exact_identifier" if exact else "query_terms",
                    "indexed_at": None} for match in search.get("matches", [])]
        truncated = bool(search.get("truncated"))
        index_status["fallback_method"] = search.get("method")
        index_status["fallback_code"] = search.get("code")
    ranked = _rank_source_matches(matches, query)
    reserve_kb = (min(2, len(knowledge), max_results - (1 if ranked else 0))
                  if not _query_tokens(query)[1] else 0)
    selected = ranked[:max_results - reserve_kb]
    remaining = max_results - len(selected)
    selected.extend(knowledge[:remaining])
    truncated = truncated or len(ranked) > max_results - reserve_kb or len(knowledge) > remaining
    partial = (fallback or index_status["status"] != "ready" or
               kb_status["status"] == "unavailable" or truncated or
               bool(provenance.get("warnings")) or
               any(not item["freshness"]["identity_checked"] for item in selected
                   if item["kind"] == "source"))
    return {
        "schema": "openubmc.source-navigation.v1",
        "status": "partial" if partial else "complete",
        "query": query, "source_root": str(root), "index": index_status,
        "provenance": provenance, "kb": kb_status,
        "results": selected, "source_count": sum(item["kind"] == "source" for item in selected),
        "knowledge_count": sum(item["kind"] == "knowledge_candidate" for item in selected),
        "truncated": truncated, "fallback": fallback,
        "proves_runtime_execution": False,
    }
