"""Immutable repository release identity and compatibility verification."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import ast
from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


RELEASE_LOCK_SCHEMA = "openubmc-agent-workflow.release-lock.v1"
RELEASE_LOCK_VERSION = 1
RELEASE_COMMIT_POLICY = "lock-finalization-parent-v1"
_FULL_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_RUNTIME_DIGEST_DOMAIN = b"openubmc-target-runtime-content-v1\0"
_SKILL_DIGEST_DOMAIN = b"openubmc-skill-package-v1\0"
_DEPENDENCY_DIGEST_DOMAIN = b"openubmc-release-dependency-lock-v1\0"


class ReleaseLockError(ValueError):
    """Raised when immutable release facts do not match the repository."""


def is_full_commit(value: object) -> bool:
    """Return whether value is a complete Git commit identity."""

    return _FULL_COMMIT.fullmatch(str(value).lower()) is not None


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _fingerprint(value: object) -> str:
    return "sha256:" + hashlib.sha256(_json_bytes(value)).hexdigest()


def _file_set_digest(
    root: Path,
    files: Sequence[PurePosixPath],
    *,
    domain: bytes,
) -> str:
    digest = hashlib.sha256(domain)
    for relative in sorted(files, key=lambda item: item.as_posix()):
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ReleaseLockError(f"release file is unavailable: {relative}")
        content = path.read_bytes()
        encoded = relative.as_posix().encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return "sha256:" + digest.hexdigest()


def _json_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseLockError(f"invalid JSON document: {path}") from exc
    if not isinstance(value, dict):
        raise ReleaseLockError(f"JSON document must be an object: {path}")
    return value


def _expression_value(node: ast.expr, values: Mapping[str, object]) -> object:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name) and node.id in values:
        return values[node.id]
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                parts.append(part.value)
            elif isinstance(part, ast.FormattedValue):
                parts.append(str(_expression_value(part.value, values)))
            else:
                raise ValueError("unsupported formatted constant")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _expression_value(node.left, values) + _expression_value(
            node.right, values
        )
    return ast.literal_eval(node)


def _constant(
    path: Path,
    name: str,
    *,
    seed: Mapping[str, object] | None = None,
) -> object:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError) as exc:
        raise ReleaseLockError(f"cannot read release constant {name}: {path}") from exc
    values: dict[str, object] = dict(seed or {})
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = [target.id for target in targets if isinstance(target, ast.Name)]
        if not names:
            continue
        try:
            value = _expression_value(node.value, values)
        except (ValueError, TypeError) as exc:
            if name in names:
                raise ReleaseLockError(
                    f"release constant {name} must be statically evaluable: {path}"
                ) from exc
            continue
        for assigned in names:
            values[assigned] = value
        if name in names:
            return value
    raise ReleaseLockError(f"release constant {name} is missing: {path}")


def _skill_records(root: Path, workflow: Mapping[str, object]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    raw_skills = workflow.get("skills")
    if not isinstance(raw_skills, list) or not raw_skills:
        raise ReleaseLockError("workflow.json has no Skills")
    for item in raw_skills:
        if not isinstance(item, Mapping):
            raise ReleaseLockError("workflow.json contains an invalid Skill")
        name = str(item.get("name", ""))
        relative_root = PurePosixPath(str(item.get("path", "")))
        if (
            not name
            or relative_root.is_absolute()
            or any(part in {"", ".", ".."} for part in relative_root.parts)
        ):
            raise ReleaseLockError(f"invalid Skill path for {name or '<unnamed>'}")
        skill_root = root / relative_root
        manifest = _json_object(skill_root / "skill.json")
        if manifest.get("name") != name:
            raise ReleaseLockError(f"Skill manifest name mismatch: {name}")
        raw_files = manifest.get("files")
        if not isinstance(raw_files, list) or not raw_files:
            raise ReleaseLockError(f"Skill manifest files are missing: {name}")
        files: list[PurePosixPath] = []
        for raw in raw_files:
            relative = PurePosixPath(str(raw))
            if (
                relative.is_absolute()
                or any(part in {"", ".", ".."} for part in relative.parts)
            ):
                raise ReleaseLockError(f"invalid Skill package path: {name}/{raw}")
            files.append(relative)
        records.append(
            {
                "name": name,
                "path": relative_root.as_posix(),
                "version": str(manifest.get("version", "")),
                "manifest_version": int(manifest.get("manifestVersion", 0)),
                "digest": _file_set_digest(
                    skill_root,
                    files,
                    domain=_SKILL_DIGEST_DOMAIN,
                ),
            }
        )
    return records


def _runtime_record(root: Path) -> dict[str, object]:
    package = root / "openubmc-target-runtime" / "openubmc_target_runtime"
    files = [
        path.relative_to(package)
        for path in package.rglob("*.py")
        if path.is_file() and "__pycache__" not in path.parts
    ]
    if not files:
        raise ReleaseLockError("Target Runtime package contains no Python sources")
    return {
        "api_version": str(_constant(package / "contracts.py", "RUNTIME_API_VERSION")),
        "content_digest": _file_set_digest(
            package,
            tuple(PurePosixPath(path.as_posix()) for path in files),
            domain=_RUNTIME_DIGEST_DOMAIN,
        ),
    }


def _dependency_records(root: Path) -> dict[str, dict[str, str]]:
    dependencies = {
        "python_validation": PurePosixPath("requirements-ci.lock"),
        "knowledge_mcp": PurePosixPath("openubmc-kb-mcp/package-lock.json"),
    }
    return {
        name: {
            "path": relative.as_posix(),
            "digest": _file_set_digest(
                root,
                (relative,),
                domain=_DEPENDENCY_DIGEST_DOMAIN,
            ),
        }
        for name, relative in dependencies.items()
    }


def _schema_record(root: Path, workflow: Mapping[str, object]) -> dict[str, object]:
    package = root / "openubmc-target-runtime" / "openubmc_target_runtime"
    runtime_api = str(_constant(package / "contracts.py", "RUNTIME_API_VERSION"))
    seed = {"RUNTIME_API_VERSION": runtime_api}
    return {
        "workflow_schema": str(workflow.get("schema_version", "")),
        "workflow_definition_schema": str(
            _constant(
                package / "workflow.py",
                "WORKFLOW_DEFINITION_SCHEMA",
                seed=seed,
            )
        ),
        "workflow_definition_version": int(
            _constant(package / "workflow.py", "WORKFLOW_DEFINITION_VERSION")
        ),
        "case_replay_bundle_schema": str(
            _constant(
                package / "replay.py",
                "CASE_REPLAY_BUNDLE_SCHEMA",
                seed=seed,
            )
        ),
        "case_replay_bundle_version": int(
            _constant(package / "replay.py", "CASE_REPLAY_BUNDLE_VERSION")
        ),
        "operation_contract_schema": str(
            _constant(
                package / "operation_contracts.py",
                "OPERATION_CONTRACT_SCHEMA",
                seed=seed,
            )
        ),
        "session_outcome_schema": str(
            _constant(
                package / "session_outcome.py",
                "SESSION_OUTCOME_SCHEMA",
                seed=seed,
            )
        ),
        "session_outcome_artifact_schema": str(
            _constant(
                package / "session_outcome.py",
                "SESSION_OUTCOME_ARTIFACT_SCHEMA",
                seed=seed,
            )
        ),
        "context_storage_version": int(
            _constant(package / "context_runtime.py", "CONTEXT_RUNTIME_STORAGE_VERSION")
        ),
    }


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise ReleaseLockError(result.stderr.strip() or "git command failed")
    return result.stdout.strip()


def repository_commit(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD^{commit}")


def build_release_lock(root: Path, *, source_commit: str) -> dict[str, object]:
    root = root.resolve()
    if not is_full_commit(source_commit):
        raise ReleaseLockError("source_commit must be a full Git commit")
    workflow = _json_object(root / "workflow.json")
    skills = _skill_records(root, workflow)
    runtime = _runtime_record(root)
    schemas = _schema_record(root, workflow)
    dependencies = _dependency_records(root)
    evaluation_harnesses = workflow.get("evaluation_harnesses", {})
    if not isinstance(evaluation_harnesses, Mapping):
        raise ReleaseLockError("workflow.json evaluation_harnesses must be an object")
    compatibility = {
        "runtime_api": runtime["api_version"],
        "profiles": workflow.get("profiles", {}),
        "clients": workflow.get("clients", {}),
        "target_runtime_skills": list(
            dict(workflow.get("profiles", {})).get("target-runtime", [])
        ),
    }
    source_identity = {
        "workflow_digest": _fingerprint(workflow),
        "skills": skills,
        "runtime": runtime,
        "schemas": schemas,
        "dependencies": dependencies,
        "evaluation_harnesses": dict(evaluation_harnesses),
        "compatibility": compatibility,
    }
    lock = {
        "schema": RELEASE_LOCK_SCHEMA,
        "lock_version": RELEASE_LOCK_VERSION,
        "release_version": str(workflow.get("version", "")),
        "source_commit": source_commit.lower(),
        "source_commit_policy": RELEASE_COMMIT_POLICY,
        **source_identity,
        "source_tree_digest": _fingerprint(source_identity),
    }
    lock["lock_digest"] = _fingerprint(lock)
    return lock


def _validate_release_commit_topology(root: Path, source_commit: str) -> None:
    current = repository_commit(root).lower()
    if current == source_commit:
        return
    topology = _git(root, "rev-list", "--parents", "-n", "1", "HEAD").split()
    parents = tuple(value.lower() for value in topology[1:])
    changed = tuple(
        line
        for line in _git(root, "diff", "--name-only", source_commit, current).splitlines()
        if line
    )
    if parents != (source_commit,) or changed != ("release-lock.json",):
        raise ReleaseLockError(
            "release commit must equal source_commit or be a lock-only child"
        )


def verify_release_lock(
    root: Path,
    lock: Mapping[str, object] | None = None,
    *,
    verify_git_topology: bool = True,
) -> dict[str, object]:
    root = root.resolve()
    document = dict(lock) if lock is not None else _json_object(root / "release-lock.json")
    if document.get("schema") != RELEASE_LOCK_SCHEMA:
        raise ReleaseLockError("unsupported release lock schema")
    if document.get("lock_version") != RELEASE_LOCK_VERSION:
        raise ReleaseLockError("unsupported release lock version")
    if document.get("source_commit_policy") != RELEASE_COMMIT_POLICY:
        raise ReleaseLockError("unsupported release commit policy")
    source_commit = str(document.get("source_commit", "")).lower()
    expected = build_release_lock(root, source_commit=source_commit)
    if document != expected:
        mismatched = sorted(
            key
            for key in set(document) | set(expected)
            if document.get(key) != expected.get(key)
        )
        raise ReleaseLockError(
            "release lock does not match repository: " + ", ".join(mismatched)
        )
    if verify_git_topology:
        _validate_release_commit_topology(root, source_commit)
    return {
        "schema": RELEASE_LOCK_SCHEMA,
        "release_version": document["release_version"],
        "source_commit": source_commit,
        "source_tree_digest": document["source_tree_digest"],
        "workflow_digest": document["workflow_digest"],
        "lock_digest": document["lock_digest"],
        "runtime": dict(document["runtime"]),
        "schemas": dict(document["schemas"]),
        "dependencies": dict(document["dependencies"]),
        "evaluation_harnesses": dict(document["evaluation_harnesses"]),
        "skill_digests": {
            str(item["name"]): str(item["digest"])
            for item in document["skills"]
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "verify", "show"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--source-commit")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--no-git-topology", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            source_commit = args.source_commit or repository_commit(args.root)
            document = build_release_lock(args.root, source_commit=source_commit)
            output = args.output or (args.root / "release-lock.json")
            output.write_text(
                json.dumps(document, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            print(json.dumps(document, ensure_ascii=False, sort_keys=True))
            return 0
        identity = verify_release_lock(
            args.root,
            verify_git_topology=not args.no_git_topology,
        )
        print(json.dumps(identity, ensure_ascii=False, sort_keys=True))
        return 0
    except ReleaseLockError as exc:
        print(f"release lock error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
