#!/usr/bin/env python3
"""Case-aware CLI transport for the openUBMC Target Runtime catalog."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
from contextlib import contextmanager
import json
import os
import sys
import uuid
from collections.abc import Iterator, Mapping

from _cli_common import add_context_runtime_arguments
import target_runtime_mcp
import workflow_remote


_CLI_SSH_PASSWORD_ENV = "OPENUBMC_TARGET_RUNTIME_CLI_SSH_PASSWORD"
_CLI_TELNET_PASSWORD_ENV = "OPENUBMC_TARGET_RUNTIME_CLI_TELNET_PASSWORD"


def _transport_identity(args: argparse.Namespace, *, prefix: str) -> tuple[str, str]:
    task_id = str(getattr(args, "task_id", "") or os.environ.get("CODEX_TASK_ID", "")).strip()
    if not task_id:
        task_id = f"{prefix}-task-{uuid.uuid4().hex}"
    operation_id = str(getattr(args, "operation_id", "")).strip()
    if not operation_id:
        operation_id = str(getattr(args, "idempotency_key", "")).strip()
    if not operation_id:
        operation_id = f"{prefix}-operation-{uuid.uuid4().hex}"
    return task_id, operation_id


def _with_case_controls(
    arguments: Mapping[str, object], args: argparse.Namespace
) -> dict[str, object]:
    result = dict(arguments)
    for name in ("case_id", "idempotency_key"):
        value = str(getattr(args, name, "")).strip()
        if value:
            result[name] = value
    expected_revision = getattr(args, "expected_revision", None)
    if expected_revision is not None:
        result["expected_revision"] = expected_revision
    return result


def _generic_arguments(
    arguments: Mapping[str, object],
    args: argparse.Namespace,
    *,
    operation: str,
    interface_profile: str,
) -> dict[str, object]:
    if interface_profile != "agent":
        return _with_case_controls(arguments, args)
    result = dict(arguments)
    legacy_run_id = str(getattr(args, "case_id", "")).strip()
    if operation == "execute" and legacy_run_id and "run_id" not in result:
        result["run_id"] = legacy_run_id
    return result


@contextmanager
def _direct_password_environment(
    args: argparse.Namespace, arguments: dict[str, object]
) -> Iterator[None]:
    changes: list[tuple[str, str | None]] = []
    for attribute, selector, env_name in (
        ("ssh_password", "ssh_password_env", _CLI_SSH_PASSWORD_ENV),
        ("telnet_password", "telnet_password_env", _CLI_TELNET_PASSWORD_ENV),
    ):
        value = str(getattr(args, attribute, ""))
        if not value:
            continue
        changes.append((env_name, os.environ.get(env_name)))
        os.environ[env_name] = value
        arguments[selector] = env_name
    try:
        yield
    finally:
        for env_name, previous in reversed(changes):
            if previous is None:
                os.environ.pop(env_name, None)
            else:
                os.environ[env_name] = previous


def _emit(envelope: Mapping[str, object], *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True))
        return
    print(str(envelope.get("summary", "openUBMC operation completed")))
    case_id = str(envelope.get("case_id", ""))
    if case_id:
        print(f"case_id={case_id} revision={envelope.get('revision', 0)}")
    error = envelope.get("canonical_error")
    if isinstance(error, Mapping):
        print(f"error={error.get('code', 'internal_error')}: {error.get('message', '')}")


def _legacy_returncode(result: Mapping[str, object], envelope: Mapping[str, object]) -> int:
    value = result.get("returncode")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if result.get("ok") is False or envelope.get("status") == "failed":
        return 1
    return 0


def _call(
    operation: str,
    arguments: Mapping[str, object],
    args: argparse.Namespace,
    *,
    json_output: bool,
    prefix: str,
    service=None,
) -> int:
    task_id, operation_id = _transport_identity(args, prefix=prefix)
    owns_service = service is None
    if service is None:
        service = target_runtime_mcp.create_service()
    try:
        try:
            result = service.call_tool(
                operation,
                arguments,
                task_id=task_id,
                operation_id=operation_id,
            )
            envelope = getattr(result, "envelope", result)
            if not isinstance(envelope, Mapping):
                raise TypeError("Context Runtime returned a non-object envelope")
            _emit(envelope, json_output=json_output)
            return _legacy_returncode(result, envelope)
        except Exception as exc:
            error = service.error_result(
                exc,
                name=operation,
                arguments=arguments,
                task_id=task_id,
                operation_id=operation_id,
            )
            _emit(error.envelope, json_output=json_output)
            return 1
        finally:
            service.complete_task(task_id)
    finally:
        if owns_service:
            service.close()


def run_legacy(argv: list[str] | None = None) -> int:
    args = workflow_remote.build_parser().parse_args(argv)
    arguments = target_runtime_mcp.workflow_arguments_from_namespace(args)
    arguments = _with_case_controls(arguments, args)
    with _direct_password_environment(args, arguments):
        return _call(
            "debug_run",
            arguments,
            args,
            json_output=bool(args.json),
            prefix="debug-cli",
        )


def run_compare_legacy(argv: list[str] | None = None) -> int:
    import compare_remote

    args = compare_remote.build_parser().parse_args(argv)
    arguments = _with_case_controls(compare_remote.build_request(args), args)
    with _direct_password_environment(args, arguments):
        return _call(
            "debug_run",
            arguments,
            args,
            json_output=bool(args.json),
            prefix="compare-cli",
        )


def _generic_parser(operation_names: tuple[str, ...]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Call an openUBMC Target Runtime operation through its active Interface.",
        epilog="Interface operations: " + ", ".join(operation_names),
    )
    parser.add_argument("--operation", choices=operation_names)
    parser.add_argument(
        "--arguments-json",
        default="{}",
        help="JSON object passed to the selected Catalog operation",
    )
    parser.add_argument(
        "--list-operations",
        action="store_true",
        help="Print the operations exposed by the same Catalog as MCP tools/list",
    )
    add_context_runtime_arguments(parser)
    return parser


def _generic_main(argv: list[str]) -> int:
    service = target_runtime_mcp.create_service()
    try:
        operation_names = service.interface_catalog.names()
        args = _generic_parser(operation_names).parse_args(argv)
        if args.list_operations:
            print(json.dumps(list(operation_names), ensure_ascii=False, indent=2))
            return 0
        if not args.operation:
            raise SystemExit("--operation is required unless --list-operations is used")
        try:
            raw = json.loads(args.arguments_json)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"--arguments-json is not valid JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise SystemExit("--arguments-json must decode to an object")
        arguments = _generic_arguments(
            raw,
            args,
            operation=args.operation,
            interface_profile=service.interface_profile,
        )
        task_id, operation_id = _transport_identity(args, prefix="catalog-cli")
        try:
            value = service.call_exposed_tool(
                args.operation,
                arguments,
                task_id=task_id,
                operation_id=operation_id,
            )
            envelope = getattr(value, "envelope", value)
            if not isinstance(envelope, Mapping):
                raise TypeError("Target Runtime returned a non-object result")
            _emit(envelope, json_output=True)
            return _legacy_returncode(value, envelope)
        except Exception as exc:
            error = service.error_result(
                exc,
                name=args.operation,
                arguments=arguments,
                task_id=task_id,
                operation_id=operation_id,
            )
            envelope = getattr(error, "envelope", error)
            _emit(envelope, json_output=True)
            return 1
        finally:
            service.complete_task(task_id)
    finally:
        service.close()


def main(argv: list[str] | None = None) -> int:
    selected = list(sys.argv[1:] if argv is None else argv)
    generic_markers = {"--operation", "--arguments-json", "--list-operations"}
    if "--help" in selected or generic_markers.intersection(selected):
        return _generic_main(selected)
    return run_legacy(selected)


if __name__ == "__main__":
    raise SystemExit(main())
