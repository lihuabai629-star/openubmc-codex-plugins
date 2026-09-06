"""Deterministic metadata for canonical and generated Runtime packages."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path


RUNTIME_API_NAME = "RUNTIME_API_VERSION"
RUNTIME_DIGEST_ALGORITHM = "sha256"
_DIGEST_DOMAIN = b"openubmc-target-runtime-content-v1\0"


def iter_runtime_source_files(package_root: Path):
    root = package_root.resolve()
    if not root.is_dir() or not (root / "__init__.py").is_file():
        raise ValueError(f"Target Runtime package is unavailable: {root}")
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if "__pycache__" in relative.parts:
            continue
        if path.is_symlink():
            raise ValueError(
                f"Target Runtime source must not contain symbolic links: {relative}"
            )
        if path.is_file():
            yield path, relative


def runtime_content_digest(package_root: Path) -> str:
    digest = hashlib.sha256(_DIGEST_DOMAIN)
    files = list(iter_runtime_source_files(package_root))
    if not files:
        raise ValueError("Target Runtime package contains no Python sources")
    for path, relative in files:
        content = path.read_bytes()
        encoded_path = relative.as_posix().encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"{RUNTIME_DIGEST_ALGORITHM}:{digest.hexdigest()}"


def read_runtime_api_version(package_root: Path) -> str:
    contracts_path = package_root.resolve() / "contracts.py"
    try:
        tree = ast.parse(contracts_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, SyntaxError) as exc:
        raise ValueError(
            f"Target Runtime API metadata is unavailable: {contracts_path}"
        ) from exc
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(
            isinstance(target, ast.Name) and target.id == RUNTIME_API_NAME
            for target in targets
        ):
            return value.value
    raise ValueError(f"Target Runtime API constant is missing: {contracts_path}")


def runtime_distribution_contract(package_root: Path) -> dict[str, str]:
    return {
        "apiVersion": read_runtime_api_version(package_root),
        "contentDigest": runtime_content_digest(package_root),
        "vendorPath": "scripts/_vendor/openubmc_target_runtime",
        "source": "generated-from-canonical",
    }
