#!/usr/bin/env python3
"""Create an immutable openUBMC build plan without changing a checkout."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile


SCHEMA = "openubmc-build/plan-v1"
MODES = (
    "validate",
    "component-package",
    "product-artifact",
    "diagnose",
    "publish",
)
DEFAULT_ROOTFS_PATHS = ("/opt/bmc/apps", "/opt/bmc/drivers")
RESOLVED_LOCK_ROLES = (
    "requires",
    "build_requires",
    "python_requires",
    "config_requires",
)
LOCAL_LOCK_ROOT = Path("/tmp") / f"openubmc-build-{os.getuid()}"
EXECUTION_CONTRACT_FILES = (
    "scripts/check_dependency_delta.py",
    "scripts/check_rootfs_access.py",
    "scripts/create_build_plan.py",
    "scripts/finalize_product_attempt.py",
    "scripts/run_bmcgo_checked.py",
    "scripts/run_build_attempt.py",
    "scripts/verify_product_artifact.py",
    "scripts/verify_hpm_containment.py",
    "scripts/write_artifact_metadata.py",
)


class BuildPlanError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def run_git(root: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"{root}: git {' '.join(args)} failed: {message}")
    return result.stdout


def current_umask() -> str:
    value = os.umask(0)
    os.umask(value)
    return f"{value:03o}"


def exclusion_pathspecs(paths: tuple[str, ...]) -> list[str]:
    result = ["."]
    for path in paths:
        result.extend(
            (
                f":(top,exclude){path}",
                f":(top,exclude){path}/**",
            )
        )
    return result


def workspace_identity(
    root: Path,
    mutable_paths: tuple[str, ...] = (),
) -> dict[str, object]:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"workspace is not a directory: {resolved}")
    top_level = Path(
        run_git(resolved, "rev-parse", "--show-toplevel")
        .decode("utf-8")
        .strip()
    ).resolve()
    if top_level != resolved:
        raise ValueError(
            f"workspace must be the Git checkout root: {resolved}; found {top_level}"
        )
    head = run_git(resolved, "rev-parse", "HEAD").decode("ascii").strip()
    git_dir_raw = run_git(resolved, "rev-parse", "--git-dir").decode().strip()
    git_dir = Path(git_dir_raw)
    if not git_dir.is_absolute():
        git_dir = (resolved / git_dir).resolve()
    common_dir_raw = run_git(resolved, "rev-parse", "--git-common-dir").decode().strip()
    common_dir = Path(common_dir_raw)
    if not common_dir.is_absolute():
        common_dir = (resolved / common_dir).resolve()
    pathspecs = exclusion_pathspecs(mutable_paths)
    status = run_git(
        resolved,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--",
        *pathspecs,
    )
    diff = run_git(
        resolved,
        "diff",
        "--binary",
        "--no-ext-diff",
        "HEAD",
        "--",
        *pathspecs,
    )
    index = run_git(
        resolved,
        "diff",
        "--cached",
        "--binary",
        "--no-ext-diff",
        "HEAD",
        "--",
        *pathspecs,
    )
    untracked = run_git(
        resolved,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        *pathspecs,
    )
    dirty_digest = hashlib.sha256()
    dirty_digest.update(status)
    dirty_digest.update(b"\0")
    dirty_digest.update(diff)
    dirty_digest.update(b"\0index\0")
    dirty_digest.update(index)
    for raw_relative in sorted(item for item in untracked.split(b"\0") if item):
        relative = raw_relative.decode("utf-8", errors="surrogateescape")
        path = top_level / relative
        dirty_digest.update(b"\0untracked\0")
        dirty_digest.update(raw_relative)
        dirty_digest.update(b"\0")
        if path.is_symlink():
            dirty_digest.update(b"symlink\0")
            dirty_digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
        elif path.is_file():
            dirty_digest.update(b"file\0")
            with path.open("rb") as handle:
                while block := handle.read(1024 * 1024):
                    dirty_digest.update(block)
        else:
            dirty_digest.update(b"other\0")
    branch_result = subprocess.run(
        ["git", "-C", str(resolved), "symbolic-ref", "--short", "-q", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    branch = branch_result.stdout.decode("utf-8", errors="replace").strip()
    return {
        "root": str(resolved),
        "git_toplevel": str(top_level),
        "git_dir": str(git_dir),
        "git_common_dir": str(common_dir),
        "git_head": head,
        "git_branch": branch,
        "dirty": bool(status),
        "scoped_diff_sha256": dirty_digest.hexdigest(),
        "mutable_paths": list(mutable_paths),
    }


def parse_workspace(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if not separator or not name or not raw_path:
        raise argparse.ArgumentTypeError("--workspace must be NAME=PATH")
    if not all(ch.isalnum() or ch in "._-" for ch in name):
        raise argparse.ArgumentTypeError(f"invalid workspace name: {name}")
    return name, Path(raw_path)


def parse_named_relative_path(value: str) -> tuple[str, str]:
    name, separator, raw_path = value.partition("=")
    if not separator or not name or not raw_path:
        raise argparse.ArgumentTypeError("--mutable-path must be NAME=RELATIVE_PATH")
    path = PurePosixPath(raw_path)
    if path.is_absolute() or ".." in path.parts or raw_path in {"", "."}:
        raise argparse.ArgumentTypeError(
            "--mutable-path must stay below the named workspace"
        )
    return name, str(path)


def parse_rootfs_path(value: str) -> str:
    path = PurePosixPath(value)
    if not path.is_absolute() or path == PurePosixPath("/") or ".." in path.parts:
        raise argparse.ArgumentTypeError(
            "rootfs service paths must be absolute below / without .."
        )
    return str(path)


def parse_rootfs_service(value: str) -> dict[str, object]:
    parts = value.split("=", 2)
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(
            "--rootfs-service must be "
            "NAME=UID:GID[:SUPPLEMENTARY_GID...]=/PATH[,/PATH...]"
        )
    name, raw_identity, raw_paths = parts
    if not name or not all(ch.isalnum() or ch in "._-" for ch in name):
        raise argparse.ArgumentTypeError(f"invalid rootfs service name: {name}")
    identity_parts = raw_identity.split(":")
    if len(identity_parts) < 2 or any(
        not part.isdigit() for part in identity_parts
    ):
        raise argparse.ArgumentTypeError(
            "--rootfs-service identity must be UID:GID[:SUPPLEMENTARY_GID...]"
        )
    paths = [parse_rootfs_path(item) for item in raw_paths.split(",") if item]
    if not paths:
        raise argparse.ArgumentTypeError(
            "--rootfs-service requires at least one absolute service path"
        )
    return {
        "name": name,
        "uid": int(identity_parts[0]),
        "gid": int(identity_parts[1]),
        "supplementary_gids": sorted(
            {int(part) for part in identity_parts[2:]}
        ),
        "paths": sorted(set(DEFAULT_ROOTFS_PATHS).union(paths)),
    }


def resolved_lock_identity(path: Path) -> dict[str, object]:
    identity = file_identity(path)
    document = json.loads(
        Path(str(identity["path"])).read_text(encoding="utf-8")
    )
    if not isinstance(document, dict):
        raise BuildPlanError(
            "incomplete_resolved_lock",
            f"resolved lock must be a JSON object: {identity['path']}",
        )
    missing = [role for role in RESOLVED_LOCK_ROLES if role not in document]
    invalid = [
        role
        for role in RESOLVED_LOCK_ROLES
        if role in document
        and (
            not isinstance(document[role], list)
            or any(not isinstance(item, str) for item in document[role])
        )
    ]
    if missing or invalid:
        detail = ", ".join((*missing, *invalid))
        raise BuildPlanError(
            "incomplete_resolved_lock",
            "resolved lock must preserve requires, build_requires, "
            f"python_requires, and config_requires lists; invalid: {detail}",
        )
    return identity


def skill_digest(
    skill_root: Path,
    relative_paths: tuple[str, ...] | None = None,
) -> str:
    digest = hashlib.sha256()
    paths = (
        [skill_root / relative for relative in relative_paths]
        if relative_paths is not None
        else sorted(skill_root.rglob("*"))
    )
    for path in paths:
        if not path.is_file():
            if relative_paths is None:
                continue
            raise ValueError(f"Skill contract file is missing: {path}")
        relative = path.relative_to(skill_root)
        if "__pycache__" in relative.parts or path.suffix == ".pyc":
            continue
        digest.update(str(relative).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def file_identity(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"expected a regular file: {resolved}")
    metadata = resolved.stat()
    return {
        "path": str(resolved),
        "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
        "size": metadata.st_size,
        "mode": metadata.st_mode & 0o7777,
    }


def output_resource_lock(role: str, path: Path) -> dict[str, str]:
    canonical = path.resolve()
    lock_id = hashlib.sha256(
        str(canonical).encode("utf-8", errors="surrogateescape")
    ).hexdigest()
    return {
        "role": role,
        "path": str(canonical),
        "lock_id": lock_id,
        "lock_path": str(
            LOCAL_LOCK_ROOT / "output-locks" / f"{lock_id}.lock"
        ),
    }


def is_product_build_command(command: list[str]) -> bool:
    if len(command) < 2:
        return False
    if Path(command[0]).name != "bmcgo" or command[1] != "build":
        return False
    return any(
        argument in {"-b", "--board"} or argument.startswith("--board=")
        for argument in command[2:]
    )


def command_executable_identity(argv: list[str], cwd: Path) -> dict[str, object]:
    if not argv:
        return {}
    raw = argv[0]
    if os.sep in raw:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = cwd / candidate
        resolved = candidate.resolve(strict=True)
    else:
        found = shutil.which(raw)
        if not found:
            raise ValueError(f"command executable not found on PATH: {raw}")
        resolved = Path(found).resolve(strict=True)
    identity = file_identity(resolved)
    identity["argv0"] = raw
    return identity


def product_lock_identity(manifest_root: Path, community: str) -> dict[str, object]:
    root = manifest_root.resolve(strict=True)
    expected = root / "build" / f"{community}.lock"
    if not expected.is_file():
        alternatives = sorted((root / "build").glob("*.lock")) if (root / "build").is_dir() else []
        found = ", ".join(str(path) for path in alternatives) or "none"
        raise BuildPlanError(
            "community_lock_mismatch",
            f"expected {expected}; available product locks: {found}",
        )
    return file_identity(expected)


def semantic_plan_id(plan: dict[str, object]) -> str:
    semantic = {key: value for key, value in plan.items() if key not in {"created_at", "plan_id"}}
    payload = json.dumps(
        semantic,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def atomic_write_json(path: Path, document: dict[str, object]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
        text=True,
    )
    temporary = Path(raw_temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def write_plan_immutable(
    path: Path,
    document: dict[str, object],
) -> tuple[dict[str, object], bool]:
    resolved = path.resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)

    def existing_plan() -> dict[str, object]:
        existing = json.loads(resolved.read_text(encoding="utf-8"))
        if (
            existing.get("plan_id") == document.get("plan_id")
            and semantic_plan_id(existing) == semantic_plan_id(document)
        ):
            return existing
        raise BuildPlanError(
            "plan_path_conflict",
            f"refusing to replace a different Plan at {resolved}",
        )

    if resolved.exists():
        return existing_plan(), True

    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=f".{resolved.name}.",
        dir=resolved.parent,
        text=True,
    )
    temporary = Path(raw_temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        try:
            os.link(temporary, resolved)
        except FileExistsError:
            return existing_plan(), True
        return document, False
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    plan_argv = (
        raw_argv[: raw_argv.index("--")]
        if "--" in raw_argv
        else raw_argv
    )
    retired_staged_rootfs_flags = {
        "--rootfs",
        "--rootfs-identity",
        "--rootfs-path",
        "--product-version-file",
    }
    retired = next(
        (
            token.split("=", 1)[0]
            for token in plan_argv
            if token.split("=", 1)[0] in retired_staged_rootfs_flags
        ),
        None,
    )
    if retired:
        print(
            "error: [staged_rootfs_evidence_retired] "
            f"{retired} is retired; bind the final ext4 with --rootfs-image "
            "and declare service identities with --rootfs-service",
            file=sys.stderr,
        )
        return 1

    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--mode", required=True, choices=MODES)
    parser.add_argument(
        "--workspace",
        action="append",
        default=[],
        type=parse_workspace,
        metavar="NAME=PATH",
    )
    parser.add_argument(
        "--mutable-path",
        action="append",
        default=[],
        type=parse_named_relative_path,
        metavar="NAME=RELATIVE_PATH",
        help="workspace subtree the planned command may change",
    )
    parser.add_argument("--cwd", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--run-root",
        help="Attempt evidence root; defaults to the Plan file parent",
    )
    parser.add_argument("--manifest-root")
    parser.add_argument("--community")
    parser.add_argument("--artifact-path")
    parser.add_argument("--product-version")
    parser.add_argument("--baseline-resolved-lock")
    parser.add_argument("--resolved-lock-path")
    parser.add_argument("--rootfs-image")
    parser.add_argument(
        "--hpm-key-file",
        help="Explicit local package-decryption key for required HPM containment verification",
    )
    parser.add_argument(
        "--rootfs-service",
        action="append",
        default=[],
        type=parse_rootfs_service,
        metavar="NAME=UID:GID[:SUP...]=/PATH[,/PATH...]",
    )
    parser.add_argument("--conan-home")
    parser.add_argument(
        "--allowed-dependency-change",
        action="append",
        default=[],
        metavar="COMPONENT",
    )
    parser.add_argument(
        "--command-source",
        choices=("user", "handoff", "generated"),
        default="user",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(raw_argv)

    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command and args.mode not in {"diagnose"}:
        parser.error("provide the exact command after --")
    if not args.workspace:
        parser.error("provide at least one --workspace NAME=PATH")

    try:
        output_path = Path(args.output).resolve()
        if args.hpm_key_file and args.mode != "product-artifact":
            raise BuildPlanError("hpm_key_requires_product_mode", "--hpm-key-file requires product-artifact mode")
        run_root = Path(args.run_root).resolve() if args.run_root else output_path.parent
        mutable_by_workspace: dict[str, list[str]] = {}
        for name, relative in args.mutable_path:
            mutable_by_workspace.setdefault(name, []).append(relative)

        workspace_roots_by_name: dict[str, Path] = {}
        for name, root in args.workspace:
            if name in workspace_roots_by_name:
                raise ValueError(f"duplicate workspace name: {name}")
            workspace_roots_by_name[name] = root.resolve(strict=True)

        manifest_root: Path | None = None
        artifact_path: Path | None = None
        rootfs_image: Path | None = None
        baseline_resolved_lock: Path | None = None
        resolved_lock: Path | None = None
        metadata_path: Path | None = None
        if args.mode == "product-artifact":
            if (
                not args.manifest_root
                or not args.community
                or not args.artifact_path
                or not args.product_version
                or not args.rootfs_image
                or not args.baseline_resolved_lock
                or not args.rootfs_service
            ):
                raise BuildPlanError(
                    "missing_product_inputs",
                    "product-artifact requires --manifest-root, --community, "
                    "--artifact-path, --rootfs-image, --product-version, "
                    "--baseline-resolved-lock, and at least one "
                    "--rootfs-service",
                )
            if "manifest" not in workspace_roots_by_name:
                raise BuildPlanError(
                    "missing_manifest_workspace",
                    "product-artifact requires --workspace manifest=<manifest-root>",
                )
            manifest_root = Path(args.manifest_root).resolve(strict=True)
            if workspace_roots_by_name["manifest"] != manifest_root:
                raise BuildPlanError(
                    "manifest_workspace_mismatch",
                    "--manifest-root does not match --workspace manifest=PATH",
                )

            raw_artifact_path = Path(args.artifact_path).expanduser()
            if not raw_artifact_path.is_absolute():
                raise BuildPlanError(
                    "artifact_path_not_absolute",
                    "--artifact-path must be an absolute HPM output path",
                )
            artifact_path = raw_artifact_path.resolve()

            raw_rootfs_image = Path(args.rootfs_image).expanduser()
            if not raw_rootfs_image.is_absolute():
                raise BuildPlanError(
                    "rootfs_image_not_absolute",
                    "--rootfs-image must be an absolute final ext4 output path",
                )
            rootfs_image = raw_rootfs_image.resolve()

            baseline_resolved_lock = Path(
                args.baseline_resolved_lock
            ).resolve(strict=True)
            if args.resolved_lock_path:
                raw_resolved_lock = Path(args.resolved_lock_path).expanduser()
                if not raw_resolved_lock.is_absolute():
                    raise BuildPlanError(
                        "resolved_lock_path_not_absolute",
                        "--resolved-lock-path must be an absolute output path",
                    )
                resolved_lock = raw_resolved_lock.resolve()
            else:
                resolved_lock = (manifest_root / "output" / "package.lock").resolve()
            metadata_path = Path(f"{artifact_path}.metadata.json").resolve()

            mutable_by_workspace.setdefault("manifest", []).extend(
                ("output", "temp")
            )
            managed_outputs = (
                artifact_path,
                metadata_path,
                rootfs_image,
                resolved_lock,
            )
            for managed_output in managed_outputs:
                if managed_output.is_relative_to(manifest_root):
                    relative = managed_output.relative_to(manifest_root)
                    if relative.parts:
                        mutable_by_workspace["manifest"].append(
                            relative.as_posix()
                        )

        workspaces: dict[str, object] = {}
        for name, root in workspace_roots_by_name.items():
            mutable_paths = tuple(sorted(set(mutable_by_workspace.pop(name, []))))
            workspaces[name] = workspace_identity(root, mutable_paths)
        if mutable_by_workspace:
            unknown = ", ".join(sorted(mutable_by_workspace))
            raise ValueError(f"mutable path names unknown workspace(s): {unknown}")
        cwd = Path(args.cwd).resolve(strict=True)
        workspace_roots = [Path(item["root"]) for item in workspaces.values()]
        if not any(cwd == root or cwd.is_relative_to(root) for root in workspace_roots):
            raise BuildPlanError(
                "cwd_outside_workspace",
                f"command cwd is not below a bound workspace: {cwd}",
            )
        if any(
            output_path.is_relative_to(root) or run_root.is_relative_to(root)
            for root in workspace_roots
        ):
            raise BuildPlanError(
                "evidence_inside_workspace",
                "Plan output and run root must be outside bound workspaces: "
                f"{output_path}, {run_root}",
            )
        if args.mode != "product-artifact" and is_product_build_command(command):
            raise BuildPlanError(
                "product_command_requires_product_artifact",
                "a Manifest bmcgo build with a board target must use "
                "product-artifact mode",
            )
        locks: dict[str, object] = {}
        expectations: dict[str, object] = {}
        output_resources: list[dict[str, str]] = []
        environment: dict[str, object] = {
            "umask": "022" if args.mode == "product-artifact" else current_umask(),
            "PATH": os.environ.get("PATH", ""),
        }
        if args.mode == "product-artifact":
            assert manifest_root is not None
            assert artifact_path is not None
            assert rootfs_image is not None
            assert baseline_resolved_lock is not None
            assert resolved_lock is not None
            assert metadata_path is not None
            manifest_workspace = workspaces.get("manifest")
            assert manifest_workspace is not None
            if not (cwd == manifest_root or cwd.is_relative_to(manifest_root)):
                raise BuildPlanError(
                    "product_cwd_outside_manifest",
                    f"product command cwd is outside the Manifest checkout: {cwd}",
                )
            environment["community"] = args.community
            conan_home = Path(
                args.conan_home
                or os.environ.get("CONAN_HOME", str(Path.home() / ".conan2"))
            ).expanduser().resolve()
            environment["conan_home"] = str(conan_home)
            locks["product"] = product_lock_identity(manifest_root, args.community)
            if rootfs_image.exists() and not rootfs_image.is_file():
                raise BuildPlanError(
                    "rootfs_image_not_regular",
                    f"--rootfs-image is not a regular file output: {rootfs_image}",
                )
            locks["dependency_baseline"] = resolved_lock_identity(
                baseline_resolved_lock
            )
            if args.hpm_key_file:
                key_path = Path(args.hpm_key_file).expanduser().absolute()
                if key_path.is_symlink() or not key_path.is_file():
                    raise BuildPlanError("invalid_hpm_key_file", "HPM key must be a regular file")
                if key_path in {artifact_path, metadata_path, rootfs_image, resolved_lock}:
                    raise BuildPlanError("product_output_input_collision", "HPM key is a planned output")
                # Private Plan/Attempt records bind this input. Public
                # containment and artifact evidence never includes it.
                locks["hpm_key"] = file_identity(key_path)
                if locks["hpm_key"]["size"] != 16:
                    raise BuildPlanError("invalid_hpm_key_length", "HPM AES key must contain exactly 16 bytes")
            if baseline_resolved_lock == resolved_lock:
                raise BuildPlanError(
                    "dependency_baseline_is_output",
                    "--baseline-resolved-lock must be a frozen pre-build file, "
                    "not the planned resolved-lock output",
                )
            output_paths = (
                artifact_path,
                metadata_path,
                rootfs_image,
                resolved_lock,
            )
            if len(set(output_paths)) != len(output_paths):
                raise BuildPlanError(
                    "product_output_path_collision",
                    "HPM, metadata sidecar, final rootfs image, and resolved lock "
                    "require distinct paths",
                )
            evidence_namespaces = (
                output_path,
                run_root / "plans",
                run_root / "locks",
            )
            collision = next(
                (
                    (managed, reserved)
                    for managed in output_paths
                    for reserved in evidence_namespaces
                    if managed == reserved
                    or (
                        reserved != output_path
                        and managed.is_relative_to(reserved)
                    )
                ),
                None,
            )
            if collision is not None:
                managed, reserved = collision
                raise BuildPlanError(
                    "product_output_evidence_collision",
                    f"product output {managed} collides with evidence namespace "
                    f"{reserved}",
                )
            input_paths = {
                baseline_resolved_lock,
                Path(str(locks["product"]["path"])),
            }
            input_collision = next(
                (path for path in output_paths if path in input_paths),
                None,
            )
            if input_collision is not None:
                raise BuildPlanError(
                    "product_output_input_collision",
                    f"product output collides with a frozen input: {input_collision}",
                )
            services: list[dict[str, object]] = []
            service_names: set[str] = set()
            for service in args.rootfs_service:
                name = str(service["name"])
                if name in service_names:
                    raise BuildPlanError(
                        "duplicate_rootfs_service",
                        f"duplicate rootfs service: {name}",
                    )
                service_names.add(name)
                services.append(service)
            services.sort(key=lambda item: str(item["name"]))
            debugfs_path = shutil.which("debugfs")
            if not debugfs_path:
                raise BuildPlanError(
                    "debugfs_not_found",
                    "debugfs is required to inspect the final ext4 rootfs image",
                )
            debugfs_identity = file_identity(Path(debugfs_path))
            if Path(str(debugfs_identity["path"])) in set(output_paths):
                raise BuildPlanError(
                    "product_output_input_collision",
                    "product output collides with the planned debugfs executable",
                )
            output_resources.extend(
                sorted(
                    (
                        output_resource_lock("artifact", artifact_path),
                        output_resource_lock("metadata", metadata_path),
                        output_resource_lock("rootfs", rootfs_image),
                        output_resource_lock("dependency_lock", resolved_lock),
                        output_resource_lock("product_version", rootfs_image),
                    ),
                    key=lambda item: (item["role"], item["path"]),
                )
            )
            expectations = {
                "versions": {
                    "product": {
                        "expected": args.product_version,
                        "evidence_path": str(rootfs_image),
                        "inside_image_path": "/etc/version.json",
                    },
                },
                "allowed_dependency_changes": sorted(
                    set(args.allowed_dependency_change)
                ),
                "artifact": {
                    "kind": "openubmc-hpm",
                    "path": str(artifact_path),
                    "expected_version": args.product_version,
                },
                "metadata": {
                    "path": str(metadata_path),
                },
                "dependency_delta": {
                    "baseline": locks["dependency_baseline"],
                    "actual_path": str(resolved_lock),
                    "roles": list(RESOLVED_LOCK_ROLES),
                },
                "rootfs_access": {
                    "root": str(rootfs_image),
                    "image_path": str(rootfs_image),
                    "image_format": "ext4",
                    "debugfs": debugfs_identity,
                    "services": services,
                },
                "outputs": {
                    "artifact": str(artifact_path),
                    "dependency_lock": str(resolved_lock),
                    "rootfs_image": str(rootfs_image),
                },
                "package_binding": {
                    "status": "package_binding_unverified",
                    "upgrade_eligible": False,
                },
                "required_gates": [
                    "dependency-delta",
                    "rootfs-access",
                ],
            }
            if args.hpm_key_file:
                expectations["package_binding"] = {
                    "method": "openubmc-picmg-ext4-aes128cbc-gzip-tar",
                    "required": True,
                }
        plan: dict[str, object] = {
            "schema": SCHEMA,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "mode": args.mode,
            "workspaces": workspaces,
            "command": {
                "source": args.command_source,
                "cwd": str(cwd),
                "argv": command,
            },
            "environment": environment,
            "locks": locks,
            "expectations": expectations,
            "execution": {
                "plan_path": str(output_path),
                "run_root": str(run_root),
                "checkout_locks": sorted(
                    {
                        str(Path(item["git_dir"]) / "openubmc-build.lock")
                        for item in workspaces.values()
                    }
                ),
                "output_resources": output_resources,
            },
            "runner": {
                "skill_sha256": skill_digest(Path(__file__).resolve().parents[1]),
                "execution_contract_sha256": skill_digest(
                    Path(__file__).resolve().parents[1],
                    EXECUTION_CONTRACT_FILES,
                ),
                "executable": command_executable_identity(command, cwd),
            },
        }
        plan["plan_id"] = semantic_plan_id(plan)
        plan, reused = write_plan_immutable(output_path, plan)
    except BuildPlanError as exc:
        print(f"error: [{exc.code}] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "plan_id": plan["plan_id"],
                "plan_path": str(output_path),
                "reused": reused,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
