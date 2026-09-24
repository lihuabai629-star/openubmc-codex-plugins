#!/usr/bin/env python3
"""Resolve build ownership before a tool is selected.

The receipt is deliberately transport-neutral so the packaged Skill and a
Runtime build plan can apply the same routing decision.
"""

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
from pathlib import Path
import re
from typing import Mapping


ROUTE_SCHEMA = "openubmc.build-route/receipt-v1"
EQUIVALENCE_SCHEMA = "openubmc.build-route/equivalence-claim-v2"


def _text(value: object) -> str:
    return str(value).strip() if value is not None else ""


def _executable_name(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _digest(value: Mapping[str, object]) -> str:
    body = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(body.encode()).hexdigest()


def classify_request(request: str, argv: list[str] | None = None) -> tuple[str, str, str]:
    """Return (owner, mode, reason) using mutually exclusive positive signals."""

    text = _text(request).lower()
    arguments = list(argv or [])
    command = " ".join(arguments).lower()
    executable = _executable_name(arguments[0]) if arguments else ""
    combined = f"{text} {command}"
    if (
        any(token in combined for token in (
            "安装构建环境", "配置构建环境", "setup build environment", "install build environment",
        ))
        or re.search(r"\b(?:install|setup|configure)\b.*\b(?:build\s+)?environment\b", combined)
        or re.search(r"(?:安装|配置).{0,20}(?:构建)?环境", combined)
    ):
        return "openubmc-environment-setup", "handoff", "environment setup owns installation and repair"
    # A raw Conan invocation is the historically observed escape hatch.  Keep
    # ownership visible, but fail closed until the caller supplies an
    # equivalence receipt for the selected build tool.
    if re.search(r"\bconan\s+create\b", combined):
        return "openubmc-build", "validate", "raw conan create requires an equivalence receipt"
    if re.search(r"bingo[-_ ]?(?:cli|tool|开发|开发工具)", combined) or (
        "bingo" in combined and "开发" in combined and "工具" in combined
    ):
        return "openubmc-bingo-development", "handoff", "Bingo CLI development owns the request"
    if executable in {"bingo", "bingo.exe"} or re.search(r"(?:^|\s)bingo(?:\.exe)?(?:\s|$)", combined):
        return "openubmc-bingo-build", "handoff", "explicit Bingo build command owns the request"
    if any(token in combined for token in ("发布 conan", "上传 conan", "publish package", "upload package")):
        return "openubmc-publish", "handoff", "package publication is outside local Build ownership"
    if any(token in combined for token in ("hpm", "固件包", "product image", "rootfs", "产品固件")):
        return "openubmc-build", "product-artifact", "requested output is a product artifact"
    if "bmcgo build" in combined or "--board" in combined or " -b " in f" {combined} ":
        return "openubmc-build", "product-artifact", "bmcgo board build produces a product artifact"
    if any(token in combined for token in ("conan package", "conan 包", "组件包", "component package")):
        return "openubmc-build", "component-package", "explicit component package output"
    if any(token in combined for token in ("compile", "编译", "生成代码", "gen", "unit test", "单元测试", "test")):
        return "openubmc-build", "validate", "local validation has no product artifact signal"
    return "openubmc-build", "validate", "default local build validation"


def _argument_values(argv: list[str], *names: str) -> list[str]:
    result: list[str] = []
    for index, value in enumerate(argv):
        if value in names and index + 1 < len(argv):
            candidate = argv[index + 1]
            result.append(candidate if candidate and not candidate.startswith("-") else "")
            continue
        for name in names:
            prefix = name + "="
            if value.startswith(prefix):
                candidate = value.removeprefix(prefix)
                result.append(candidate if candidate and not candidate.startswith("-") else "")
                break
    return result


def _manifest_board_entry(root: Path, board: str) -> Path | None:
    if board != board.strip() or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", board):
        return None
    product_root = root / "build" / "product"
    if product_root.is_symlink() or not product_root.is_dir():
        return None
    resolved_root = product_root.resolve()
    if not resolved_root.is_relative_to(root.resolve()):
        return None
    for entry in product_root.iterdir():
        if entry.is_symlink():
            continue
        if entry.resolve().parent != resolved_root:
            continue
        if entry.name == board or (entry.is_file() and entry.stem == board):
            return entry
    return None


def _bingo_preconditions(
    owner: str,
    request: str,
    argv: list[str] | None,
    workspace: Path | None,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    root = workspace.resolve() if workspace else None
    if root is None:
        return ([{
            "name": "workspace",
            "status": "required",
            "detail": "select the Bingo source, component, or Manifest checkout owned by this route",
        }], {"kind": "", "status": "required"})

    if owner == "openubmc-bingo-development":
        pyproject = root / "pyproject.toml"
        project_text = ""
        if pyproject.is_file():
            project_text = pyproject.read_text(encoding="utf-8", errors="replace").lower()
        source_markers = (
            root / "src" / "bingo",
            root / "bingo",
            root / "tests" / "test_cli.py",
        )
        valid = "openubmc-bingo" in project_text or any(path.exists() for path in source_markers)
        precondition = {
            "name": "bingo_source_repository",
            "status": "passed" if valid else "failed",
            "path": str(root),
            "detail": "recognized Bingo CLI source" if valid else "missing Bingo CLI source markers",
        }
        artifact = {
            "kind": "bingo-source-change",
            "status": "passed" if valid else "failed",
        }
        return [precondition, {"name": "requested_artifact", **artifact}], artifact

    component = (root / "mds" / "service.json").is_file()
    manifest = any(
        path.exists()
        for path in (root / ".bingo" / "config", root / "build" / "frame.py", root / "build" / "product")
    )
    workspace_ok = component or manifest
    preconditions: list[dict[str, object]] = [{
        "name": "bingo_workspace",
        "status": "passed" if workspace_ok else "failed",
        "path": str(root),
        "detail": (
            "component workspace" if component else
            "Manifest workspace" if manifest else
            "missing component or Manifest markers"
        ),
    }]
    command = list(argv or [])
    combined = (request + " " + " ".join(command)).lower()
    board_values = _argument_values(command, "-b", "--board")
    duplicate_board = len(board_values) > 1
    board = board_values[0] if len(board_values) == 1 else ""
    bingo_build = (
        len(command) > 1
        and _executable_name(command[0]) in {"bingo", "bingo.exe"}
        and command[1].lower() == "build"
    )
    product = (
        any(token in combined for token in ("-t publish", "product", "hpm", "固件"))
        or bool(board_values)
        or (manifest and bingo_build)
    )
    if product:
        board_entry = _manifest_board_entry(root, board) if board else None
        status = (
            "failed" if duplicate_board else
            "passed" if manifest and board_entry is not None else
            "required" if manifest and not board else
            "failed"
        )
        detail = (
            "board option must appear exactly once" if duplicate_board else
            "Manifest product release target is explicit" if status == "passed" else
            "select an explicit board with -b or --board" if status == "required" else
            "product publication requires a Manifest workspace" if not manifest else
            "board does not resolve to a build/product entry"
        )
        artifact: dict[str, object] = {
            "kind": "product-release",
            "status": status,
            "board": board,
            "detail": detail,
        }
        if board_entry is not None:
            artifact["board_entry"] = str(board_entry)
    elif component:
        artifact = {"kind": "component-build", "status": "passed"}
    elif manifest:
        artifact = {"kind": "manifest-operation", "status": "passed"}
    else:
        artifact = {"kind": "", "status": "failed", "detail": "requested artifact cannot be resolved"}
    preconditions.append({"name": "requested_artifact", **artifact})
    return preconditions, artifact


def _workspace_preconditions(owner: str, mode: str, workspace: Path | None) -> list[dict[str, object]]:
    if owner != "openubmc-build" or mode == "handoff":
        return []
    root = workspace.resolve() if workspace else None
    if root is None:
        return [{"name": "workspace", "status": "required", "detail": "select a component or manifest checkout"}]
    component = (root / "mds" / "service.json").is_file()
    manifest = any((root / marker).exists() for marker in (".bmcgo/config", ".bingo/config", "build/frame.py"))
    if mode == "component-package":
        return [{"name": "component_workspace", "status": "passed" if component else "failed", "path": str(root / "mds" / "service.json")}]
    if mode == "product-artifact":
        return [{"name": "manifest_workspace", "status": "passed" if manifest else "failed", "path": str(root)}]
    # Validation must still be tied to a recognizable component checkout.  A
    # random directory is not a valid build workspace merely because it exists.
    component_markers = (
        root / "mds" / "service.json",
        root / "conanfile.py",
        root / "CMakeLists.txt",
        root / "src",
    )
    valid_component = component or any(path.exists() for path in component_markers[1:])
    return [{
        "name": "component_workspace",
        "status": "passed" if valid_component else "failed",
        "path": str(root),
        "detail": "recognized component checkout" if valid_component else "missing component markers",
    }]


def _tool_substitution_precondition(
    owner: str,
    mode: str,
    argv: list[str] | None,
    equivalence: Mapping[str, object] | None,
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    """Return (precondition, normalized receipt) for a non-default tool.

    Routing is advisory unless the receipt is attached to the same decision.
    This helper makes the receipt a build-plan input rather than documentation
    that can be forgotten after the route was selected.
    """
    supported_owners = {"openubmc-build", "openubmc-bingo-build"}
    if owner not in supported_owners:
        return None, None
    command = list(argv or [])
    if not command:
        return None, None
    executable = _executable_name(command[0])
    expected_executables = (
        {"bmcgo", "bmcgo.exe"}
        if owner == "openubmc-build"
        else {"bingo", "bingo.exe"}
    )
    if executable in expected_executables:
        return {"name": "tool_boundary", "status": "passed", "tool": executable}, None
    if re.search(r"\bconan\s+create\b", " ".join(command).lower()):
        if equivalence is None:
            return {
                "name": "tool_equivalence",
                "status": "failed",
                "detail": "raw conan create requires an equivalence receipt",
            }, None
    if equivalence is None:
        return {
            "name": "tool_equivalence",
            "status": "failed",
            "detail": f"substituted tool {executable} requires an equivalence receipt",
        }, None
    try:
        normalized = equivalence_receipt(equivalence)
    except (TypeError, ValueError) as exc:
        return {
            "name": "tool_equivalence",
            "status": "failed",
            "detail": str(exc),
        }, None
    return {
        "name": "tool_equivalence",
        "status": "pending_plan_binding",
        "tool": executable,
        "receipt_digest": normalized["digest"],
    }, normalized


def route_receipt(
    request: str,
    *,
    argv: list[str] | None = None,
    workspace: Path | None = None,
    equivalence: Mapping[str, object] | None = None,
) -> dict[str, object]:
    owner, mode, reason = classify_request(request, argv)
    artifact: dict[str, object] | None = None
    if owner in {"openubmc-bingo-build", "openubmc-bingo-development"}:
        preconditions, artifact = _bingo_preconditions(owner, request, argv, workspace)
    else:
        preconditions = _workspace_preconditions(owner, mode, workspace)
    tool_precondition, normalized_equivalence = _tool_substitution_precondition(
        owner, mode, argv, equivalence
    )
    if tool_precondition is not None:
        preconditions.append(tool_precondition)
    ready = all(item.get("status") in {"passed", "not_required"} for item in preconditions)
    selected_tool = (
        "bmcgo" if owner == "openubmc-build" and not argv else
        _executable_name(argv[0]) if argv and owner in {"openubmc-build", "openubmc-bingo-build"} else
        ""
    )
    receipt: dict[str, object] = {
        "schema": ROUTE_SCHEMA,
        "owner": owner,
        "mode": mode,
        "reason": reason,
        "preconditions": preconditions,
        "ready": ready,
        "handoff": owner if owner != "openubmc-build" else "",
        "tool": selected_tool if ready else "",
        "plan_binding_required": normalized_equivalence is not None,
    }
    if artifact is not None:
        receipt["artifact"] = artifact
    if normalized_equivalence is not None:
        receipt["equivalence"] = normalized_equivalence
    receipt["digest"] = _digest(receipt)
    return receipt


def equivalence_receipt(value: Mapping[str, object]) -> dict[str, object]:
    required = ("source", "profile", "options", "dependency_graph", "expected_artifact", "release_gates")
    missing = [name for name in required if not value.get(name)]
    if missing:
        raise ValueError("tool substitution equivalence is missing: " + ", ".join(missing))
    for name in ("source", "dependency_graph"):
        identity = value[name]
        if isinstance(identity, str):
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", identity):
                raise ValueError(f"{name} must be a sha256 identity")
        elif isinstance(identity, Mapping):
            digest = _text(identity.get("sha256"))
            if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", digest):
                raise ValueError(f"{name} must contain a sha256 identity")
        else:
            raise ValueError(f"{name} must be an identity")
    if not isinstance(value["profile"], str) or not _text(value["profile"]):
        raise ValueError("profile must be a non-empty string")
    if not isinstance(value["options"], (list, Mapping)):
        raise ValueError("options must be an array or object")
    artifact = value["expected_artifact"]
    if not isinstance(artifact, Mapping) or not _text(artifact.get("kind")) or not _text(artifact.get("version")):
        raise ValueError("expected_artifact requires kind and version")
    gates = value["release_gates"]
    if not isinstance(gates, list) or not gates or any(not isinstance(gate, str) or not gate.strip() for gate in gates):
        raise ValueError("release_gates must be a non-empty list of names")
    receipt = {
        "schema": EQUIVALENCE_SCHEMA,
        "claim_complete": True,
        **{name: value[name] for name in required},
    }
    receipt["digest"] = _digest(receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--argv", nargs="*")
    parser.add_argument("--equivalence", type=Path)
    args = parser.parse_args()
    if args.equivalence:
        value = json.loads(args.equivalence.read_text(encoding="utf-8"))
        print(json.dumps(equivalence_receipt(value), ensure_ascii=False, sort_keys=True))
    else:
        receipt = route_receipt(args.request, argv=args.argv, workspace=args.workspace)
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
        return 0 if receipt["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
