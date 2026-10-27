"""Safe archive extraction and one-click bundle structure validation."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import hashlib
import os
import pathlib
import shutil
import tarfile
import tempfile

from log_bundle_common import BundleAnalysisError, ExtractionResult


MAX_SECTION_SUBDIRECTORIES = 200
MAX_ARCHIVE_MEMBERS = 200_000
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
MAX_EXTRACTED_BYTES = 16 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MIN_EXPANDED_ALLOWANCE = 64 * 1024 * 1024
MIN_FREE_SPACE_RESERVE = 256 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = MAX_ARCHIVE_MEMBERS
MAX_DIRECTORY_DEPTH = 64
MAX_DIRECTORY_BYTES = MAX_EXTRACTED_BYTES
KNOWN_BUNDLE_SECTIONS = (
    "LogDump",
    "AppDump",
    "RTOSDump",
    "OSDump",
    "SpLogDump",
    "BMALogDump",
    "DeviceDump",
    "3rdDump",
    "CoreDump",
    "OptBMC",
)


def _ensure_portable_path_parts(
    parts: tuple[str, ...],
    *,
    error_code: str,
    subject: str,
) -> None:
    """Reject names that cannot satisfy the public relative-path contract."""
    if any(
        "\\" in part or any(ord(char) < 0x20 or ord(char) == 0x7F for char in part)
        for part in parts
    ):
        raise BundleAnalysisError(
            error_code,
            f"{subject} contains a name that cannot be represented in portable result paths.",
        )


def _symbolic_link_error(path: pathlib.Path) -> BundleAnalysisError:
    return BundleAnalysisError(
        "bundle_layout_invalid",
        f"Bundle contains symbolic links; first entry: {path}",
    )


def ensure_bundle_path(
    bundle_root: pathlib.Path | str,
    candidate: pathlib.Path | str,
) -> pathlib.Path:
    """Resolve a bundle member without allowing a symlink or root escape.

    The returned path is safe to use only for the current filesystem state.
    Callers that accept a user-managed extracted directory should validate the
    tree immediately before scanning it and must not follow a path that fails
    this check.
    """

    bundle_root = pathlib.Path(bundle_root)
    candidate = pathlib.Path(candidate)
    if bundle_root.is_symlink():
        raise _symbolic_link_error(bundle_root)
    try:
        root = bundle_root.resolve(strict=True)
    except OSError as exc:
        raise BundleAnalysisError(
            "bundle_layout_invalid",
            f"Unable to resolve bundle root {bundle_root}: {exc}",
        ) from exc

    lexical_path = candidate if candidate.is_absolute() else root / candidate
    try:
        relative = lexical_path.relative_to(root)
    except ValueError as exc:
        raise BundleAnalysisError(
            "bundle_layout_invalid",
            f"Bundle path escapes the bundle root: {candidate}",
        ) from exc
    if ".." in relative.parts:
        raise BundleAnalysisError(
            "bundle_layout_invalid",
            f"Bundle path escapes the bundle root: {candidate}",
        )
    _ensure_portable_path_parts(
        relative.parts,
        error_code="bundle_layout_invalid",
        subject="Bundle path",
    )

    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise _symbolic_link_error(current)

    try:
        resolved = lexical_path.resolve(strict=True)
    except OSError as exc:
        raise BundleAnalysisError(
            "bundle_layout_invalid",
            f"Unable to resolve bundle path {candidate}: {exc}",
        ) from exc
    if not resolved.is_relative_to(root):
        raise BundleAnalysisError(
            "bundle_layout_invalid",
            f"Bundle path escapes the bundle root: {candidate}",
        )
    return resolved


def ensure_safe_member_path(destination: pathlib.Path, member_name: str) -> None:
    _ensure_portable_path_parts(
        tuple(part for part in member_name.split("/") if part not in {"", "."}),
        error_code="extract_failed",
        subject="Archive member path",
    )
    target_path = (destination / member_name).resolve()
    destination_root = destination.resolve()
    if not target_path.is_relative_to(destination_root):
        raise BundleAnalysisError("extract_failed", f"Unsafe archive member path: {member_name}")


def _mkdir_private(path: pathlib.Path) -> None:
    """Create an extraction directory and keep it private regardless of umask."""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError as exc:
        raise BundleAnalysisError(
            "extract_failed",
            f"Unable to set private permissions on extraction directory {path}: {exc}",
        ) from exc


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise BundleAnalysisError("bundle_read_failed", f"Failed to read {path}: {exc}") from exc
    return digest.hexdigest()


def _bounded_directory_walk(
    root: pathlib.Path,
    *,
    max_entries: int,
    max_depth: int,
    max_bytes: int | None = None,
):
    """Yield directory entries once without following links or exceeding limits."""

    stack: list[tuple[pathlib.Path, tuple[str, ...]]] = [(root, ())]
    entry_count = 0
    total_bytes = 0
    while stack:
        directory, parent_parts = stack.pop()
        try:
            iterator = os.scandir(directory)
        except OSError as exc:
            raise BundleAnalysisError(
                "bundle_layout_invalid",
                f"Failed to inspect bundle directory {directory}: {exc}",
            ) from exc
        try:
            with iterator:
                for entry in iterator:
                    entry_count += 1
                    if entry_count > max_entries:
                        raise BundleAnalysisError(
                            "bundle_limits_exceeded",
                            f"Directory tree contains more than {max_entries} entries.",
                        )
                    relative_parts = (*parent_parts, entry.name)
                    _ensure_portable_path_parts(
                        (entry.name,),
                        error_code="bundle_layout_invalid",
                        subject="Bundle entry",
                    )
                    if len(relative_parts) > max_depth:
                        raise BundleAnalysisError(
                            "bundle_limits_exceeded",
                            f"Directory tree exceeds the maximum depth of {max_depth}.",
                        )
                    try:
                        is_symlink = entry.is_symlink()
                        is_directory = entry.is_dir(follow_symlinks=False)
                        is_file = entry.is_file(follow_symlinks=False)
                        file_size = (
                            entry.stat(follow_symlinks=False).st_size
                            if is_file and max_bytes is not None
                            else 0
                        )
                    except OSError as exc:
                        raise BundleAnalysisError(
                            "bundle_layout_invalid",
                            f"Failed to inspect bundle entry {entry.path}: {exc}",
                        ) from exc
                    if not is_symlink and not is_directory and not is_file:
                        raise BundleAnalysisError(
                            "bundle_layout_invalid",
                            f"Unsupported special file in bundle: {entry.path}",
                        )
                    if max_bytes is not None and is_file:
                        total_bytes += max(0, file_size)
                        if total_bytes > max_bytes:
                            raise BundleAnalysisError(
                                "bundle_limits_exceeded",
                                f"Directory tree contains more than {max_bytes} bytes of files.",
                            )
                    path = pathlib.Path(entry.path)
                    yield path, relative_parts, is_symlink, is_directory, is_file, file_size
                    if is_directory:
                        stack.append((path, relative_parts))
        except BundleAnalysisError:
            raise
        except OSError as exc:
            raise BundleAnalysisError(
                "bundle_layout_invalid",
                f"Failed to inspect bundle directory {directory}: {exc}",
            ) from exc


def locate_bundle_root(extract_dir: pathlib.Path) -> pathlib.Path:
    extract_dir = pathlib.Path(extract_dir)
    if extract_dir.is_symlink():
        raise _symbolic_link_error(extract_dir)
    try:
        search_root = extract_dir.resolve(strict=True)
    except OSError as exc:
        raise BundleAnalysisError(
            "bundle_layout_invalid",
            f"Unable to resolve extracted bundle directory {extract_dir}: {exc}",
        ) from exc

    candidate_count = 0
    candidate_root: pathlib.Path | None = None
    for path, _, is_symlink, is_directory, _, _ in _bounded_directory_walk(
        search_root,
        max_entries=MAX_DIRECTORY_ENTRIES,
        max_depth=MAX_DIRECTORY_DEPTH,
    ):
        if path.name != "dump_info":
            continue
        if is_symlink:
            raise _symbolic_link_error(path)
        if is_directory:
            candidate_count += 1
            if candidate_root is None:
                candidate_root = path.parent
    if candidate_count == 1 and candidate_root is not None:
        return candidate_root
    if candidate_count > 1:
        raise BundleAnalysisError(
            "bundle_layout_ambiguous",
            f"Found multiple dump_info/ directories under {extract_dir}",
        )
    raise BundleAnalysisError("bundle_layout_invalid", "Extracted bundle does not contain dump_info/")


def extract_archive(archive_path: pathlib.Path, extract_parent: pathlib.Path) -> ExtractionResult:
    try:
        archive_size = archive_path.stat().st_size
    except OSError as exc:
        raise BundleAnalysisError("bundle_read_failed", f"Failed to stat {archive_path}: {exc}") from exc
    if archive_size > MAX_ARCHIVE_BYTES:
        raise BundleAnalysisError(
            "bundle_limits_exceeded",
            f"Archive is {archive_size} bytes, exceeding the {MAX_ARCHIVE_BYTES}-byte safety limit.",
        )
    ratio_limit = max(MIN_EXPANDED_ALLOWANCE, archive_size * MAX_COMPRESSION_RATIO)
    effective_expanded_limit = min(MAX_EXTRACTED_BYTES, ratio_limit)
    bundle_name = archive_path.name
    if bundle_name.endswith(".tar.gz"):
        bundle_name = bundle_name[: -len(".tar.gz")]
    elif bundle_name.endswith(".tar"):
        bundle_name = bundle_name[: -len(".tar")]
    if extract_parent.is_symlink():
        raise _symbolic_link_error(extract_parent)
    extract_parent_preexisting = extract_parent.exists()
    if extract_parent_preexisting:
        if not extract_parent.is_dir():
            raise BundleAnalysisError(
                "extract_failed",
                f"Extraction parent is not a directory: {extract_parent}",
            )
    else:
        _mkdir_private(extract_parent)
    extract_dir = pathlib.Path(
        tempfile.mkdtemp(prefix=f"{bundle_name}-", dir=extract_parent)
    )
    try:
        with tarfile.open(archive_path, "r|*") as archive:
            member_count = 0
            total_size = 0
            extracted_files: set[pathlib.Path] = set()
            for member in archive:
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise BundleAnalysisError(
                        "bundle_limits_exceeded",
                        f"Archive contains more than {MAX_ARCHIVE_MEMBERS} members.",
                    )
                total_size += max(0, member.size)
                if total_size > effective_expanded_limit:
                    raise BundleAnalysisError(
                        "bundle_limits_exceeded",
                        "Archive exceeds the expanded-size or compression-ratio safety limit.",
                    )
                ensure_safe_member_path(extract_dir, member.name)
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise BundleAnalysisError(
                        "extract_failed",
                        f"Unsupported archive member type: {member.name}",
                    )
                target = (extract_dir / member.name).resolve()
                if member.isdir():
                    _mkdir_private(target)
                    continue
                if not member.isfile():
                    raise BundleAnalysisError(
                        "extract_failed",
                        f"Unsupported archive member type: {member.name}",
                    )
                if target in extracted_files or target.exists():
                    raise BundleAnalysisError(
                        "extract_failed",
                        f"Duplicate archive member path: {member.name}",
                    )
                extracted_files.add(target)
                _mkdir_private(target.parent)
                free_bytes = shutil.disk_usage(extract_dir).free
                if free_bytes - max(0, member.size) < MIN_FREE_SPACE_RESERVE:
                    raise BundleAnalysisError(
                        "bundle_limits_exceeded",
                        "Insufficient free space to extract the archive while preserving the safety reserve.",
                    )
                source = archive.extractfile(member)
                if source is None:
                    raise BundleAnalysisError(
                        "extract_failed",
                        f"Unable to read archive member: {member.name}",
                    )
                with source, target.open("xb") as output:
                    target.chmod(0o600)
                    shutil.copyfileobj(source, output)
        bundle_root = locate_bundle_root(extract_dir)
    except BundleAnalysisError:
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise
    except (tarfile.TarError, OSError) as exc:
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise BundleAnalysisError("extract_failed", f"Failed to extract {archive_path}: {exc}") from exc
    return ExtractionResult(extract_dir=extract_dir, bundle_root=bundle_root)


def validate_bundle_structure(bundle_root: pathlib.Path) -> dict[str, object]:
    bundle_root = pathlib.Path(bundle_root)
    if bundle_root.is_symlink():
        raise _symbolic_link_error(bundle_root)
    try:
        root = bundle_root.resolve(strict=True)
    except OSError as exc:
        raise BundleAnalysisError(
            "bundle_layout_invalid",
            f"Unable to resolve bundle root {bundle_root}: {exc}",
        ) from exc
    dump_info = root / "dump_info"
    if dump_info.is_symlink():
        raise _symbolic_link_error(dump_info)
    if not dump_info.is_dir():
        raise BundleAnalysisError(
            "bundle_layout_invalid",
            f"Bundle root does not contain dump_info/: {root}",
        )
    ensure_bundle_path(root, dump_info)
    section_present = {name: False for name in KNOWN_BUNDLE_SECTIONS}
    section_file_counts = {name: 0 for name in KNOWN_BUNDLE_SECTIONS}
    section_child_file_counts: dict[str, dict[str, int]] = {
        name: {} for name in KNOWN_BUNDLE_SECTIONS
    }
    unknown_sections: list[str] = []
    root_files: list[dict[str, object]] = []
    total_file_count = 0

    for path, parts, is_symlink, is_directory, is_file, file_size in _bounded_directory_walk(
        dump_info,
        max_entries=MAX_DIRECTORY_ENTRIES,
        max_depth=MAX_DIRECTORY_DEPTH,
        max_bytes=MAX_DIRECTORY_BYTES,
    ):
        if is_symlink:
            raise _symbolic_link_error(path)
        if is_file:
            total_file_count += 1
        section_name = parts[0]
        if len(parts) == 1:
            if is_directory:
                if section_name in section_present:
                    section_present[section_name] = True
                else:
                    unknown_sections.append(section_name)
            elif is_file:
                root_files.append(
                    {
                        "path": path.relative_to(root).as_posix(),
                        "size_bytes": file_size,
                    }
                )
            continue
        if section_name not in section_present or not section_present[section_name]:
            continue
        if len(parts) == 2 and is_directory:
            section_child_file_counts[section_name].setdefault(parts[1], 0)
        if is_file:
            section_file_counts[section_name] += 1
            if len(parts) >= 3:
                child_name = parts[1]
                section_child_file_counts[section_name][child_name] = (
                    section_child_file_counts[section_name].get(child_name, 0) + 1
                )

    sections: dict[str, dict[str, object]] = {}
    for name in KNOWN_BUNDLE_SECTIONS:
        child_counts = section_child_file_counts[name]
        child_names = sorted(child_counts)
        sections[name] = {
            "present": section_present[name],
            "file_count": section_file_counts[name],
            "subdirectory_count": len(child_names),
            "subdirectories": [
                {"name": child_name, "file_count": child_counts[child_name]}
                for child_name in child_names[:MAX_SECTION_SUBDIRECTORIES]
            ],
            "subdirectories_truncated": len(child_names) > MAX_SECTION_SUBDIRECTORIES,
        }

    total_files = sum(section_file_counts.values())

    present_sections = [
        name for name, detail in sections.items() if detail["present"]
    ]
    if not present_sections:
        raise BundleAnalysisError(
            "bundle_layout_invalid",
            "dump_info/ exists but none of the recognized log sections are present.",
        )

    warnings = [
        f"missing_section:{name}"
        for name in ("LogDump", "AppDump", "RTOSDump")
        if not sections[name]["present"]
    ]
    unknown_sections.sort()
    root_files.sort(key=lambda item: str(item["path"]))
    return {
        "valid": True,
        "layout": "openubmc-one-click-log-bundle",
        "bundle_root": str(root),
        "present_sections": present_sections,
        "sections": sections,
        "total_file_count": total_file_count,
        "total_files_in_known_sections": total_files,
        "root_files": root_files,
        "unknown_sections": unknown_sections,
        "warnings": warnings,
    }
