"""Load an installed, generated-vendor, or repository Target Runtime safely."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import importlib
import importlib.util
import json
from pathlib import Path
import sys


def _load_distribution(package_root: Path):
    path = package_root / "distribution.py"
    spec = importlib.util.spec_from_file_location(
        f"_openubmc_runtime_distribution_{abs(hash(str(path)))}",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Target Runtime distribution metadata is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _validated_vendor(
    script_path: Path,
    expected_api: str,
) -> tuple[Path, dict[str, str]] | None:
    skill_root = script_path.resolve().parents[1]
    manifest_path = skill_root / "skill.json"
    if not manifest_path.is_file():
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Skill manifest is unavailable or invalid") from exc
    contract = manifest.get("targetRuntime")
    if not isinstance(contract, dict):
        return None
    required = ("apiVersion", "contentDigest", "vendorPath", "source")
    if any(not isinstance(contract.get(key), str) or not contract[key] for key in required):
        raise RuntimeError("Skill Target Runtime contract is incomplete")
    vendor_relative = Path(contract["vendorPath"])
    if vendor_relative.is_absolute() or ".." in vendor_relative.parts:
        raise RuntimeError("Skill Target Runtime vendor path is invalid")
    package_root = skill_root / vendor_relative
    if not package_root.is_dir():
        raise RuntimeError("generated Target Runtime vendor is missing")
    distribution = _load_distribution(package_root)
    actual_api = distribution.read_runtime_api_version(package_root)
    actual_digest = distribution.runtime_content_digest(package_root)
    if contract["apiVersion"] != expected_api or actual_api != expected_api:
        raise RuntimeError("generated Target Runtime API version is incompatible")
    if contract["contentDigest"] != actual_digest:
        raise RuntimeError("generated Target Runtime content digest is incompatible")
    if contract["source"] != "generated-from-canonical":
        raise RuntimeError("generated Target Runtime source marker is invalid")
    return package_root, {key: str(contract[key]) for key in required}


def _installed_runtime_matches_contract(
    installed,
    contract: dict[str, str],
) -> bool:
    module_path = getattr(installed, "__file__", "")
    if not isinstance(module_path, str) or not module_path:
        raise RuntimeError("installed Target Runtime package path is unavailable")
    package_root = Path(module_path).resolve().parent
    distribution = _load_distribution(package_root)
    actual_api = distribution.read_runtime_api_version(package_root)
    actual_digest = distribution.runtime_content_digest(package_root)
    if actual_api != contract["apiVersion"]:
        raise RuntimeError("installed Target Runtime API version is incompatible")
    if actual_digest != contract["contentDigest"]:
        raise RuntimeError("installed Target Runtime content digest is incompatible")
    return True


def _repository_package(script_path: Path, expected_api: str) -> Path | None:
    root = script_path.resolve().parents[2] / "openubmc-target-runtime"
    package = root / "openubmc_target_runtime"
    if not package.is_dir():
        return None
    distribution = _load_distribution(package)
    if distribution.read_runtime_api_version(package) != expected_api:
        raise RuntimeError("repository Target Runtime API version is incompatible")
    return package


def load_runtime_module(script_path: Path, *, expected_api: str):
    vendor = _validated_vendor(script_path, expected_api)
    try:
        installed = importlib.import_module("openubmc_target_runtime")
    except ModuleNotFoundError:
        installed = None
    if vendor is not None:
        package_root, contract = vendor
        if (
            installed is not None
            and getattr(installed, "RUNTIME_API_VERSION", "") == expected_api
            and _installed_runtime_matches_contract(installed, contract)
        ):
            return installed
    elif (
        installed is not None
        and getattr(installed, "RUNTIME_API_VERSION", "") == expected_api
    ):
        return installed

    if vendor is None:
        package_root = _repository_package(script_path, expected_api)
    else:
        package_root = vendor[0]
    if package_root is None:
        raise RuntimeError(
            "Target Runtime is unavailable; repair the installed Runtime/MCP environment"
        )
    parent = str(package_root.parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    if installed is not None:
        for name in tuple(sys.modules):
            if name == "openubmc_target_runtime" or name.startswith(
                "openubmc_target_runtime."
            ):
                sys.modules.pop(name, None)
    module = importlib.import_module("openubmc_target_runtime")
    if getattr(module, "RUNTIME_API_VERSION", "") != expected_api:
        raise RuntimeError("selected Target Runtime API version is incompatible")
    return module
