#!/usr/bin/env python3
"""Re-hash one stable upgrade artifact without following symlinks."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


_PRODUCT_VERSION_RE = re.compile(r"(?<![\d.])(\d+(?:\.\d+){3})(?!\d|\.\d)")
_STABLE_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
_MAX_METADATA_BYTES = 1024 * 1024


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    return all(getattr(left, item) == getattr(right, item) for item in _STABLE_FIELDS)


def _read_stable_metadata(path: Path) -> dict[str, object]:
    before_path = os.lstat(path)
    if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
        raise ValueError(f"artifact metadata sidecar must be a regular file: {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (before_path.st_dev, before_path.st_ino):
            raise ValueError(f"artifact metadata sidecar changed while opening: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, 64 * 1024)
            if not block:
                break
            total += len(block)
            if total > _MAX_METADATA_BYTES:
                raise ValueError(f"artifact metadata sidecar is too large: {path}")
            chunks.append(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = os.lstat(path)
    if not _same_file_state(before, after) or not _same_file_state(after, after_path):
        raise ValueError(f"artifact metadata sidecar changed while reading: {path}")
    try:
        document = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"artifact metadata sidecar is invalid: {path}") from exc
    if not isinstance(document, dict):
        raise ValueError(f"artifact metadata sidecar must contain an object: {path}")
    return document


def stable_sha256(path: Path) -> dict[str, object]:
    path = path.absolute()
    before_path = os.lstat(path)
    if not stat.S_ISREG(before_path.st_mode) or stat.S_ISLNK(before_path.st_mode):
        raise ValueError(f"artifact must be a regular file: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (before_path.st_dev, before_path.st_ino):
            raise ValueError(f"artifact changed while opening: {path}")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = os.lstat(path)
    if not _same_file_state(before, after):
        raise ValueError(f"artifact changed while hashing: {path}")
    if not _same_file_state(after, after_path):
        raise ValueError(f"artifact path changed while hashing: {path}")
    return {"path": str(path), "sha256": digest.hexdigest(), "size": after.st_size}


def validate_artifact_metadata(
    path: Path,
    *,
    expected_sha256: str,
    product_version: str,
    actual_size: int | None = None,
) -> dict[str, object]:
    """Fail closed when a build sidecar or versioned filename disagrees.

    Build emits ``<artifact>.metadata.json`` with the artifact digest, size, and
    product version.  A version embedded in the HPM filename is also checked
    when the name contains exactly one dotted four-part version.  Generic HPM
    names without a version remain supported, but an existing malformed or
    stale sidecar is never ignored.
    """

    normalized_sha = expected_sha256.strip().lower()
    expected_version = product_version.strip()
    if not expected_version:
        raise ValueError("product version must not be empty")
    versions = sorted(set(_PRODUCT_VERSION_RE.findall(path.name)))
    if len(versions) == 1 and versions[0] != expected_version:
        raise ValueError(
            "artifact filename product version does not match: "
            f"filename {versions[0]}, expected {expected_version}"
        )

    sidecar = Path(f"{path}.metadata.json")
    if not os.path.lexists(sidecar):
        return {
            "sidecar_path": "",
            "filename_product_version": versions[0] if len(versions) == 1 else "",
        }
    document = _read_stable_metadata(sidecar)
    if not isinstance(document, dict) or not isinstance(document.get("artifact"), dict):
        raise ValueError(f"artifact metadata sidecar is missing artifact identity: {sidecar}")
    identity = document["artifact"]
    sidecar_sha = identity.get("sha256")
    sidecar_size = identity.get("size")
    sidecar_version = document.get("product_version")
    if "upgrade_eligible" in document and document.get("upgrade_eligible") is not True:
        raise ValueError("build artifact is not eligible for Upgrade")
    if "package_binding" in document and document.get("package_binding") != "package_binding_verified":
        raise ValueError("build artifact package binding is not verified")
    if not isinstance(sidecar_sha, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sidecar_sha):
        raise ValueError(f"artifact metadata sidecar has invalid SHA-256: {sidecar}")
    if isinstance(sidecar_size, bool) or not isinstance(sidecar_size, int) or sidecar_size < 0:
        raise ValueError(f"artifact metadata sidecar has invalid size: {sidecar}")
    if not isinstance(sidecar_version, str) or not sidecar_version.strip():
        raise ValueError(f"artifact metadata sidecar has invalid product version: {sidecar}")
    if sidecar_sha.lower() != normalized_sha:
        raise ValueError(
            "artifact metadata SHA-256 does not match: "
            f"sidecar {sidecar_sha.lower()}, expected {normalized_sha}"
        )
    if sidecar_version.strip() != expected_version:
        raise ValueError(
            "artifact metadata product version does not match: "
            f"sidecar {sidecar_version.strip()}, expected {expected_version}"
        )
    if actual_size is not None and sidecar_size != actual_size:
        raise ValueError(
            "artifact metadata size does not match: "
            f"sidecar {sidecar_size}, actual {actual_size}"
        )
    return {
        "sidecar_path": str(sidecar),
        "filename_product_version": versions[0] if len(versions) == 1 else "",
        "sidecar_sha256": sidecar_sha.lower(),
        "sidecar_size": sidecar_size,
        "sidecar_product_version": sidecar_version.strip(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--product-version", default="")
    args = parser.parse_args()
    try:
        result = stable_sha256(Path(args.path))
        if result["sha256"] != args.expected_sha256.lower():
            raise ValueError("artifact SHA-256 does not match the expected value")
        if args.product_version:
            result["metadata"] = validate_artifact_metadata(
                Path(args.path).absolute(),
                expected_sha256=args.expected_sha256,
                product_version=args.product_version,
                actual_size=int(result["size"]),
            )
        print(json.dumps(result, sort_keys=True))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
