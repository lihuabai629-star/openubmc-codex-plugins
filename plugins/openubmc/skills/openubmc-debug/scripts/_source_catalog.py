"""Bounded per-hit provenance for mixed community and product source trees.

The optional local catalog classifies repositories; it neither authorizes a
device operation nor proves that a checkout was built into deployed firmware.
Missing metadata degrades to reference-only results, never blocks searching.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
from urllib.parse import urlsplit


CATALOG_PATH = ".openubmc/source-catalog.json"


def _is_reparse_path(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _read_regular_file(path: Path, limit: int) -> bytes:
    """Read only the same regular file inspected at this path before and after open.

    Windows has no O_NOFOLLOW. Comparing the opened file with both path
    identities also rejects a link or replacement inserted around os.open.
    """
    before = path.lstat()
    if _is_reparse_path(path) or not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError("unsupported source file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > limit:
            raise ValueError("unsupported source file")
        content = stream.read(limit + 1)
        after = path.lstat()
        if (not before.st_ino or not opened.st_ino or not after.st_ino
                or not os.path.samestat(before, opened)
                or not os.path.samestat(opened, after)
                or _is_reparse_path(path)):
            raise ValueError("source file changed during read")
    if len(content) > limit:
        raise ValueError("source file limit")
    return content


def _contains_reparse_path(root: Path, path: Path) -> bool:
    relative = path.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        if _is_reparse_path(current):
            return True
    return False


def _remote_identity(raw: str) -> str | None:
    # Never return URL credentials, queries or local filesystem remote paths.
    if "://" not in raw and ":" in raw and not raw.startswith(("/", ".")):
        host, path = raw.split(":", 1)
        raw = "ssh://" + host + "/" + path
    try:
        url = urlsplit(raw)
        if url.scheme not in {"http", "https", "ssh", "git"} or not url.hostname:
            return None
        return url.hostname.lower() + "/" + url.path.strip("/").removesuffix(".git")
    except ValueError:
        return None


class SourceCatalog:
    def __init__(self, root: Path, *, timeout: float = 1.0):
        self.root = root.resolve()
        self.deadline = time.monotonic() + max(0.0, min(timeout, 2.0))
        self.entries = {}
        self.product = ""
        self.warnings = []
        self.catalog_present = False
        self._repositories = {}
        self._paths = {}
        self._files = {}
        self._load_catalog()

    def _warn(self, code):
        if code not in self.warnings:
            self.warnings.append(code)

    def _load_catalog(self):
        path = self.root / CATALOG_PATH
        if not path.exists() and not path.is_symlink():
            return
        self.catalog_present = True
        try:
            if _is_reparse_path(path) or _is_reparse_path(path.parent):
                raise ValueError("unsupported catalog file")
            raw = _read_regular_file(path, 262144)
            data = json.loads(raw)
            if (not isinstance(data, dict) or type(data.get("schema_version")) is not int or data["schema_version"] != 1
                    or not isinstance(data.get("repositories"), list)
                    or len(data["repositories"]) > 128):
                raise ValueError("unsupported catalog")
            product = data.get("product", "")
            if not isinstance(product, str) or len(product) > 128:
                raise ValueError("invalid product")
            entries = {}
            for entry in data["repositories"]:
                if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                    raise ValueError("invalid repository")
                relative = Path(entry["path"])
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("repository outside source root")
                resolved = (self.root / relative).resolve()
                resolved.relative_to(self.root)
                if resolved in entries:
                    raise ValueError("duplicate repository")
                if entry.get("origin", "unknown") not in {"community", "internal", "third_party", "unknown"}:
                    raise ValueError("invalid source origin")
                if entry.get("role", "reference") not in {"implementation", "reference"}:
                    raise ValueError("invalid source role")
                if (not isinstance(entry.get("component", ""), str)
                        or len(entry.get("component", "")) > 128):
                    raise ValueError("invalid component")
                products = entry.get("products", [])
                if (not isinstance(products, list) or len(products) > 64
                        or any(not isinstance(p, str) or not p or len(p) > 128 for p in products)):
                    raise ValueError("invalid products")
                revision = entry.get("commit")
                if revision is not None and (not isinstance(revision, str) or len(revision) not in {40, 64}
                        or any(c not in "0123456789abcdef" for c in revision)):
                    raise ValueError("catalog commit must be an immutable hash")
                entries[resolved] = {k: entry[k] for k in (
                    "origin", "role", "component", "products", "commit") if k in entry}
            self.product, self.entries = product, entries
            counts = Counter(e.get("component") for e in entries.values()
                             if e.get("role") == "implementation" and product in e.get("products", []))
            for entry in self.entries.values():
                if counts[entry.get("component")] > 1:
                    entry["ambiguous"] = True
                    self._warn("multiple_implementations_for_component")
        except (OSError, ValueError, TypeError, RecursionError, UnicodeError):
            self.entries = {}
            self.product = ""
            self._warn("catalog_unavailable_or_invalid")

    def _git(self, root, *args):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            self._warn("provenance_time_limit")
            return None
        try:
            completed = subprocess.run(
                ["git", "--no-optional-locks", "--literal-pathspecs", "-c", "core.fsmonitor=false",
                 "-C", str(root), *args], capture_output=True, timeout=remaining, check=False,
            )
            return completed.stdout if completed.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            self._warn("repository_metadata_unavailable")
            return None

    def _repository(self, path):
        directory = path.parent
        if directory in self._paths:
            return self._paths[directory]
        candidate = directory
        while candidate != self.root and not (candidate / ".git").exists():
            candidate = candidate.parent
        if candidate not in self._repositories:
            if len(self._repositories) >= 32:
                self._warn("repository_count_limit")
                return None, {}
            raw = self._git(candidate, "rev-parse", "--show-toplevel")
            repo = Path(os.fsdecode(raw).strip()).resolve() if raw else None
            metadata = {}
            if repo is not None:
                commit = self._git(repo, "rev-parse", "HEAD")
                branch = self._git(repo, "symbolic-ref", "--quiet", "--short", "HEAD")
                remote = self._git(repo, "config", "--get", "remote.origin.url")
                metadata = {"repository": str(repo),
                            "commit": os.fsdecode(commit).strip() if commit else None,
                            "branch": os.fsdecode(branch).strip() if branch else None,
                            "remote": _remote_identity(os.fsdecode(remote).strip()) if remote else None}
            self._repositories[candidate] = repo, metadata
        result = self._repositories[candidate]
        self._paths[directory] = result
        return result

    def _file_identity(self, path, repo, commit):
        if path in self._files:
            return self._files[path]
        result = {"content_digest": None, "modified": None}
        if time.monotonic() >= self.deadline:
            self._warn("provenance_time_limit")
            return result
        try:
            content = _read_regular_file(path, 1024 * 1024)
            result["content_digest"] = "sha256:" + hashlib.sha256(content).hexdigest()
            if repo and commit:
                relative = path.relative_to(repo).as_posix()
                tree = self._git(repo, "ls-tree", "-z", commit, "--", relative)
                if tree is not None:
                    blob = b"blob " + str(len(content)).encode() + b"\0" + content
                    identity = tree.split(b"\t", 1)[0].split()
                    oid = identity[2].decode() if len(identity) == 3 else ""
                    digest = hashlib.sha256(blob).hexdigest() if len(oid) == 64 else hashlib.sha1(blob).hexdigest()
                    result["modified"] = oid != digest
        except (OSError, ValueError):
            self._warn("file_identity_unavailable")
        self._files[path] = result
        return result

    def annotate(self, matches):
        for match in matches:
            try:
                relative = Path(str(match["path"]))
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("source path is outside root")
                path = self.root / relative
                if _contains_reparse_path(self.root, path):
                    match["source"] = {"applicability": "unknown", "reason": "source_reparse_path"}
                    continue
                path.resolve().relative_to(self.root)
            except (KeyError, ValueError, OSError):
                match["source"] = {"applicability": "unknown", "reason": "path_outside_source_root"}
                continue
            repo, metadata = self._repository(path)
            entry = self.entries.get(repo, {})
            if repo is None:
                # An explicitly catalogued non-Git tree remains reference only.
                entry = next((e for p, e in self.entries.items() if path.is_relative_to(p)), {})
            identity = self._file_identity(path, repo, metadata.get("commit"))
            selected = bool(self.product and self.product in entry.get("products", []))
            revision_matches = entry.get("commit") in {None, metadata.get("commit")}
            candidate = bool(selected and entry.get("role") == "implementation" and repo
                             and metadata.get("commit") and revision_matches and not entry.get("ambiguous"))
            match["source"] = {
                **metadata, **identity,
                "origin": entry.get("origin", "unknown"), "origin_basis": "catalog" if entry else "unclassified",
                "component": entry.get("component"), "products": entry.get("products", []),
                "selected_product": self.product or None, "product_match": selected,
                "revision_match": revision_matches if entry.get("commit") else None,
                "applicability": "product_source_candidate" if candidate else ("reference" if entry else "unknown"),
                "ambiguous": bool(entry.get("ambiguous")),
                "proves_deployed_source": False,
            }
        return {"schema": "openubmc.source-provenance.v1", "catalog_present": self.catalog_present,
                "product": self.product or None, "warnings": list(self.warnings),
                "proves_deployed_source": False}
