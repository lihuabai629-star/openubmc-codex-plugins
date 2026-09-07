#!/usr/bin/env python3
"""Run and aggregate the read-only openUBMC debug acceptance workflow."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess  # compatibility seam: callers patch subprocess.run at the CLI boundary
import sys
import threading
import uuid

from _cli_common import (
    add_context_runtime_arguments,
    resolve_ssh_credentials,
    resolve_telnet_credentials,
)
import active_alarms
import busctl_remote
import collect_logs
from collect_logs import (
    DEFAULT_LOG_MAX_BYTES,
    HARD_MAX_LOG_BYTES,
    MAX_ROTATED_LIMIT,
    validate_log_names,
)
import mdbctl_remote
import preflight_remote
import read_remote_file
from _json_common import build_json_payload
from _source_root import resolve_source_root
from _workflow_correlation import (
    alarm_epoch,
    build_correlation,
    instance_alarm_terms,
    line_matches_alarm_instance,
    log_epoch,
    log_lines,
    search_source_terms,
    stable_alarm_terms,
)
from _workflow_freshness import (
    alarm_identity,
    alarm_records,
    alarm_summary,
    compare_alarm_snapshots,
    compare_bmc_time_snapshots,
    compare_file_snapshots,
    compare_preflight,
    compare_uptime_snapshots,
    file_lines,
    payload_result,
    preflight_capabilities,
    snapshot_available,
)
from _workflow_runtime import (
    WorkflowDeadline,
    compact_workflow_payload,
    run_json_tool,
    run_python_json_tool,
    skipped_result,
    utc_now,
)


SCRIPT_DIR = Path(__file__).resolve().parent
VERSION_PATH = "/etc/version.json"
UPTIME_PATH = "/proc/uptime"
DEFAULT_FILES = [VERSION_PATH, UPTIME_PATH]


def _command_argv(command: list[str]) -> list[str]:
    for index, item in enumerate(command):
        if str(item).endswith(".py"):
            return list(command[index + 1 :])
    raise ValueError("collector command does not contain a Python entry point")


class CapabilityReadyPreflightRun:
    """Expose capability gates while the complete typed preflight is still running."""

    _DEPENDENCIES = {
        "mdbctl": ("SSH", "MDBCTL"),
        "busctl": ("SSH", "DBUS_ENV", "BUSCTL"),
        "active_alarm_transport": ("SSH", "DBUS_ENV", "BUSCTL"),
        "remote_log_file": ("TELNET",),
    }

    def __init__(
        self,
        runner,
        *,
        args: argparse.Namespace,
        command: list[str],
        timeout: int | float,
        deadline: WorkflowDeadline | None,
        refresh_checks: dict[str, dict[str, object]] | None,
        release_cached_mdb: bool,
    ) -> None:
        self.runner = runner
        self.args = args
        self.command = list(command)
        self.timeout = timeout
        self.deadline = deadline
        self.refresh_checks = refresh_checks
        self.release_cached_mdb = release_cached_mdb
        self._condition = threading.Condition()
        self._check_states: dict[str, bool] = {}
        self._cached_check_states: dict[str, bool] = {}
        if refresh_checks is not None:
            self._cached_check_states.update(
                {
                    name: bool(check.get("ok"))
                    for name, check in refresh_checks.items()
                }
            )
            self._check_states.update(
                {
                    name: bool(check.get("ok"))
                    for name, check in refresh_checks.items()
                    if name not in {"SSH", "TELNET"}
                }
            )
        self._completed = False
        self._result: dict[str, object] | None = None
        self._error: BaseException | None = None
        self._thread = threading.Thread(
            target=self._run,
            name="openubmc-debug-preflight",
            daemon=True,
        )
        self._thread.start()

    def _selected(self, capability: str) -> bool:
        if capability in {"busctl", "active_alarm_transport"}:
            return not bool(getattr(self.args, "mdb_only", False))
        if capability == "remote_log_file":
            return not bool(getattr(self.args, "skip_telnet", False)) and not bool(
                getattr(self.args, "mdb_only", False)
            )
        return True

    def _observe_check(self, name: str, raw_result) -> None:
        ok = bool(raw_result[0]) if isinstance(raw_result, tuple) and raw_result else False
        with self._condition:
            self._check_states[name] = ok
            self._condition.notify_all()

    def _run(self) -> None:
        def invoke(executed_command: list[str]) -> int:
            args = preflight_remote.parse_args(_command_argv(executed_command))
            return self.runner._invoke_preflight_main(
                args,
                refresh_checks=self.refresh_checks,
                check_observer=self._observe_check,
            )

        try:
            result = run_python_json_tool(
                "preflight_start",
                self.command,
                invoke,
                self.timeout,
                deadline=self.deadline,
            )
            result = self.runner._finalize_tool_result("preflight_start", result)
        except BaseException as exc:
            with self._condition:
                self._error = exc
                self._completed = True
                self._condition.notify_all()
            return
        with self._condition:
            self._result = result
            self._completed = True
            self._condition.notify_all()

    def wait_capability(
        self,
        capability: str,
        *,
        deadline: WorkflowDeadline | None = None,
    ) -> bool:
        dependencies = self._DEPENDENCIES.get(capability)
        if dependencies is None:
            raise ValueError(f"unsupported preflight capability gate: {capability}")
        if not self._selected(capability):
            return False
        if (
            capability == "mdbctl"
            and self.release_cached_mdb
            and all(
                self._cached_check_states.get(name) is True
                for name in dependencies
            )
        ):
            return True
        with self._condition:
            while True:
                if any(
                    name in self._check_states and not self._check_states[name]
                    for name in dependencies
                ):
                    return False
                if all(name in self._check_states for name in dependencies):
                    return all(self._check_states[name] for name in dependencies)
                if self._completed:
                    return False
                if deadline is None:
                    self._condition.wait()
                    continue
                remaining = deadline.remaining()
                if remaining <= 0:
                    return False
                self._condition.wait(timeout=remaining)

    def result(self) -> dict[str, object]:
        with self._condition:
            while not self._completed:
                self._condition.wait()
            if self._error is not None:
                raise self._error
            if self._result is None:
                raise RuntimeError("typed preflight completed without a result")
            return self._result


class TypedDebugToolRunner:
    """Dispatch existing collector CLIs inside one DebugRun process."""

    def __init__(self, runtime_lease) -> None:
        self.runtime_lease = runtime_lease
        self._preflight_checks: dict[str, dict[str, object]] = {}
        self._preflight_args = None
        self._preflight_start_mode = "full"

    def _prepare_preflight_start(
        self,
        args: argparse.Namespace,
    ) -> dict[str, dict[str, object]] | None:
        self._preflight_args = args
        cache_reader = getattr(
            self.runtime_lease,
            "cached_preflight_checks",
            None,
        )
        refresh_checks = cache_reader(args) if callable(cache_reader) else None
        self._preflight_start_mode = (
            "refresh" if refresh_checks is not None else "full"
        )
        return refresh_checks

    def prepare_assurance_refresh(self, args: argparse.Namespace) -> bool:
        """Restore epoch-valid capability truth for a refresh-only assured pass."""

        cache_reader = self.runtime_lease.cached_preflight_checks
        checks = cache_reader(args)
        if not checks:
            return False
        self._preflight_args = args
        self._preflight_checks = checks
        return True

    def _invoke_preflight_main(
        self,
        args: argparse.Namespace,
        *,
        refresh_checks: dict[str, dict[str, object]] | None,
        check_observer=None,
    ) -> int:
        return preflight_remote.main(
            _args=args,
            _ssh=self.runtime_lease.ssh_credentials_mapping(),
            _telnet=self.runtime_lease.telnet_credentials_mapping(),
            object_alarm_lease=self.runtime_lease.object_alarm_lease,
            telnet_session=self.runtime_lease.telnet_session,
            _refresh_checks=refresh_checks,
            _check_observer=check_observer,
        )

    def _invoke_preflight(self, name: str, command: list[str]) -> int:
        args = preflight_remote.parse_args(_command_argv(command))
        refresh_checks = (
            self._prepare_preflight_start(args)
            if name == "preflight_start"
            else self._preflight_checks
        )
        return self._invoke_preflight_main(
            args,
            refresh_checks=refresh_checks,
        )

    def start_capability_preflight(
        self,
        command: list[str],
        env: dict[str, str],
        timeout: int | float,
        *,
        deadline: WorkflowDeadline | None = None,
        release_cached_mdb: bool = False,
    ) -> CapabilityReadyPreflightRun:
        del env
        args = preflight_remote.parse_args(_command_argv(command))
        refresh_checks = self._prepare_preflight_start(args)
        return CapabilityReadyPreflightRun(
            self,
            args=args,
            command=command,
            timeout=timeout,
            deadline=deadline,
            refresh_checks=refresh_checks,
            release_cached_mdb=release_cached_mdb,
        )

    @staticmethod
    def _result_checks(
        result: dict[str, object],
    ) -> dict[str, dict[str, object]]:
        payload = result.get("payload")
        payload_result = payload.get("result") if isinstance(payload, dict) else None
        checks = payload_result.get("checks") if isinstance(payload_result, dict) else None
        if not isinstance(checks, dict):
            return {}
        return {
            str(key): value
            for key, value in checks.items()
            if isinstance(value, dict)
        }

    @staticmethod
    def _preflight_cache_anchors_ok(
        args: argparse.Namespace,
        checks: dict[str, dict[str, object]],
    ) -> bool:
        selected = preflight_remote._selected_preflight_checks(args)
        required = [name for name in ("SSH", "TELNET") if name in selected]
        return all(bool(checks.get(name, {}).get("ok")) for name in required)

    def _record_phase(self, name: str) -> None:
        if name in {"preflight_start", "preflight_end"}:
            mode = (
                self._preflight_start_mode
                if name == "preflight_start"
                else "refresh"
            )
            recorder = getattr(
                self.runtime_lease,
                "record_preflight_phase",
                None,
            )
            if callable(recorder):
                recorder(mode)
                return
        self.runtime_lease.record_phase(name)

    def _finalize_tool_result(
        self,
        name: str,
        result: dict[str, object],
    ) -> dict[str, object]:
        self._record_phase(name)
        self.runtime_lease.record_tool_result(name, result)
        if name == "preflight_start":
            self._preflight_checks = self._result_checks(result)
            cache_writer = getattr(
                self.runtime_lease,
                "store_preflight_checks",
                None,
            )
            cache_invalidator = getattr(
                self.runtime_lease,
                "invalidate_preflight_checks",
                None,
            )
            if (
                bool(result.get("ok"))
                and self._preflight_checks
                and self._preflight_args is not None
                and self._preflight_cache_anchors_ok(
                    self._preflight_args,
                    self._preflight_checks,
                )
                and callable(cache_writer)
            ):
                cache_writer(self._preflight_args, self._preflight_checks)
            elif self._preflight_args is not None and callable(cache_invalidator):
                cache_invalidator(self._preflight_args)
        elif name == "preflight_end":
            end_checks = self._result_checks(result)
            cache_invalidator = getattr(
                self.runtime_lease,
                "invalidate_preflight_checks",
                None,
            )
            if (
                self._preflight_args is not None
                and callable(cache_invalidator)
                and (
                    not bool(result.get("ok"))
                    or not end_checks
                    or not self._preflight_cache_anchors_ok(
                        self._preflight_args,
                        end_checks,
                    )
                )
            ):
                cache_invalidator(self._preflight_args)
        return result

    def _invoke_ssh_collector(
        self,
        *,
        name: str,
        command: list[str],
        module,
    ) -> int:
        args = module.parse_args(_command_argv(command))
        ssh = self.runtime_lease.ssh_credentials_mapping()

        def collect() -> int:
            kwargs = {
                "ssh_runner": self.runtime_lease.ssh_runner,
                "_args": args,
                "_ssh": ssh,
            }
            if module in {busctl_remote, active_alarms}:
                kwargs["runtime_lease"] = self.runtime_lease.object_alarm_lease
            return module.main(**kwargs)

        return self.runtime_lease.run_ssh_read(
            request_id=f"debug-{uuid.uuid4().hex}",
            collector_name=name,
            operation={"command": list(command)},
            collect=collect,
        )

    def _invoke_telnet_collector(
        self,
        *,
        command: list[str],
        module,
    ) -> int:
        lease = self.runtime_lease.telnet_lease
        if lease is None:
            raise RuntimeError("Debug Telnet lane is not available")
        args = module.parse_args(_command_argv(command))
        return module.main(
            runtime_lease=lease,
            _args=args,
            _telnet=self.runtime_lease.telnet_credentials_mapping(),
            _session=lease.session_proxy,
        )

    def __call__(
        self,
        name: str,
        command: list[str],
        env: dict[str, str],
        timeout: int | float,
        *,
        deadline: WorkflowDeadline | None = None,
    ) -> dict[str, object]:
        del env
        tool = next(
            (Path(item).stem for item in command if str(item).endswith(".py")),
            "",
        )

        def invoke(executed_command: list[str]) -> int:
            if tool == "preflight_remote":
                return self._invoke_preflight(name, executed_command)
            if tool == "mdbctl_remote":
                return self._invoke_ssh_collector(
                    name=name,
                    command=executed_command,
                    module=mdbctl_remote,
                )
            if tool == "busctl_remote":
                return self._invoke_ssh_collector(
                    name=name,
                    command=executed_command,
                    module=busctl_remote,
                )
            if tool == "active_alarms":
                return self._invoke_ssh_collector(
                    name=name,
                    command=executed_command,
                    module=active_alarms,
                )
            if tool == "collect_logs":
                return self._invoke_telnet_collector(
                    command=executed_command,
                    module=collect_logs,
                )
            if tool == "read_remote_file":
                return self._invoke_telnet_collector(
                    command=executed_command,
                    module=read_remote_file,
                )
            raise ValueError(f"unsupported typed Debug collector: {tool or name}")

        result = run_python_json_tool(
            name,
            command,
            invoke,
            timeout,
            deadline=deadline,
        )
        return self._finalize_tool_result(name, result)


def build_typed_debug_tool_runner(runtime_lease) -> TypedDebugToolRunner:
    return TypedDebugToolRunner(runtime_lease)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Execute the read-only openUBMC debug workflow and compare final freshness."
    )
    parser.add_argument("--ip", required=True, help="BMC IP")
    parser.add_argument("--keyword", default="", help="Optional literal log keyword")
    parser.add_argument(
        "--mdb-query",
        action="append",
        dest="mdb_queries",
        default=[],
        help=(
            "Repeatable reviewed read-only mdbctl query, for example "
            "'lsobj BusinessConnector'; specific queries replace the default lsclass"
        ),
    )
    parser.add_argument(
        "--mdb-expand-class",
        action="append",
        dest="mdb_expand_classes",
        default=[],
        help=(
            "Repeatable MDB class whose current objects are discovered with lsobj "
            "and then read with lsprop inside the same TargetRun"
        ),
    )
    parser.add_argument(
        "--mdb-concurrency",
        default="auto",
        help=(
            "Concurrent MDB reads: auto, unbounded, or a positive integer "
            "(default: auto)"
        ),
    )
    parser.add_argument(
        "--mdb-only",
        action="store_true",
        help=(
            "Collect only reviewed MDB queries plus lightweight preflight freshness; "
            "skip bus tree, active alarms, logs, and files"
        ),
    )
    parser.add_argument("--logs", default="app.log,framework.log")
    parser.add_argument("--lines", type=int, default=200)
    parser.add_argument("--include-rotated", action="store_true")
    parser.add_argument(
        "--rotated-limit",
        type=int,
        default=3,
        help=(
            "Maximum rotated files per log when --include-rotated "
            f"(default: 3; hard max: {MAX_ROTATED_LIMIT})"
        ),
    )
    parser.add_argument(
        "--log-max-bytes",
        type=int,
        default=DEFAULT_LOG_MAX_BYTES,
        help=(
            "Maximum bytes returned per selected log "
            f"(default: {DEFAULT_LOG_MAX_BYTES}; hard max: {HARD_MAX_LOG_BYTES})"
        ),
    )
    parser.add_argument(
        "--file",
        action="append",
        dest="files",
        default=[],
        help="Additional live file; version and uptime are always collected",
    )
    parser.add_argument(
        "--tree-service",
        default="",
        help="Optional exact service for a bounded tree; default uses busctl list",
    )
    parser.add_argument("--tree-head", type=int, default=20)
    parser.add_argument(
        "--alarm-service",
        default="",
        help="Optional exact current-alarm service override",
    )
    parser.add_argument(
        "--alarm-path",
        default="",
        help="Optional exact current-alarm object-path override",
    )
    parser.add_argument("--alarm-discovery-service-limit", type=int, default=16)
    parser.add_argument("--alarm-discovery-path-limit", type=int, default=64)
    parser.add_argument("--alarm-limit", type=int, default=100)
    parser.add_argument("--alarm-call-signature", default="")
    parser.add_argument("--alarm-call-arg", action="append", default=[])
    parser.add_argument("--no-freshness", action="store_true")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument(
        "--deadline",
        type=int,
        default=600,
        help="End-to-end workflow budget in seconds (default: 600)",
    )
    parser.add_argument(
        "--source-root",
        default="",
        help=(
            "Local source root. Resolution order: argument, "
            "OPENUBMC_SOURCE_ROOT, then the git repository containing cwd."
        ),
    )
    parser.add_argument(
        "--source-max-matches",
        type=int,
        default=40,
        help="Global source-match cap; use 0 to collect no source matches",
    )
    parser.add_argument("--correlate-alarm-limit", type=int, default=20)
    parser.add_argument("--correlation-time-window", type=int, default=300)
    parser.add_argument("--no-source-correlation", action="store_true")

    parser.add_argument("--ssh-user", default="")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--ssh-user-env", default="")
    parser.add_argument("--ssh-password-env", default="")
    parser.add_argument("--ssh-password", default="")
    parser.add_argument("--ssh-identity-file", default="")
    parser.add_argument("--telnet-user", default="")
    parser.add_argument("--telnet-port", type=int, default=23)
    parser.add_argument("--telnet-user-env", default="")
    parser.add_argument("--telnet-password-env", default="")
    parser.add_argument("--telnet-password", default="")
    parser.add_argument(
        "--skip-telnet",
        action="store_true",
        help="Keep the workflow on SSH/source evidence and skip Telnet log/file collection",
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--compact-json",
        action="store_true",
        help="With --json, omit duplicated child envelopes and evidence arrays",
    )
    add_context_runtime_arguments(parser)
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def requested_files(args: argparse.Namespace) -> list[str]:
    return list(dict.fromkeys([*DEFAULT_FILES, *getattr(args, "files", [])]))


def validate_workflow_inputs(args: argparse.Namespace) -> None:
    if getattr(args, "mdb_only", False):
        args.skip_telnet = True
    logs = validate_log_names(
        [item.strip() for item in args.logs.split(",") if item.strip()]
    )
    if not logs:
        raise SystemExit("--logs must name at least one log file")
    args.logs = ",".join(logs)
    parsed_mdb_queries: list[list[str]] = []
    for index, query in enumerate(getattr(args, "mdb_queries", []), start=1):
        if not isinstance(query, str):
            raise SystemExit(f"--mdb-query #{index} must be a string")
        parts = query.split()
        if not mdbctl_remote.is_read_only_command(parts):
            raise SystemExit(
                f"--mdb-query #{index} does not match the reviewed read-only grammar"
            )
        parsed_mdb_queries.append(parts)
    args.mdb_queries = parsed_mdb_queries
    parsed_expand_classes: list[str] = []
    for index, class_name in enumerate(
        getattr(args, "mdb_expand_classes", []),
        start=1,
    ):
        if not isinstance(class_name, str) or not mdbctl_remote.is_read_only_command(
            ["lsobj", class_name]
        ):
            raise SystemExit(
                f"--mdb-expand-class #{index} is not a valid MDB class token"
            )
        if class_name not in parsed_expand_classes:
            parsed_expand_classes.append(class_name)
    args.mdb_expand_classes = parsed_expand_classes
    selected_concurrency = str(getattr(args, "mdb_concurrency", "auto")).strip().lower()
    if selected_concurrency not in {"auto", "unbounded"}:
        if not selected_concurrency.isdecimal() or int(selected_concurrency) < 1:
            raise SystemExit(
                "--mdb-concurrency must be auto, unbounded, or a positive integer"
            )
        selected_concurrency = str(int(selected_concurrency))
    args.mdb_concurrency = selected_concurrency
    try:
        args.files = [
            read_remote_file.normalize_remote_path(path)
            for path in getattr(args, "files", [])
        ]
    except ValueError as exc:
        raise SystemExit(f"--file {exc}") from exc


def requested_mdb_queries(args: argparse.Namespace) -> list[list[str]]:
    queries = getattr(args, "mdb_queries", [])
    if not queries and not getattr(args, "mdb_expand_classes", []):
        return [["lsclass"]]
    return [query.split() if isinstance(query, str) else list(query) for query in queries]


def requested_mdb_expand_classes(args: argparse.Namespace) -> list[str]:
    return list(getattr(args, "mdb_expand_classes", []))


def mdb_concurrency_budget(args: argparse.Namespace, query_count: int) -> int:
    if query_count < 1:
        return 0
    policy = str(getattr(args, "mdb_concurrency", "auto"))
    if policy == "unbounded":
        return query_count
    if policy == "auto":
        return min(query_count, 4)
    return min(query_count, int(policy))


def child_environment(args: argparse.Namespace) -> dict[str, str]:
    ssh = resolve_ssh_credentials(args)
    telnet = (
        {"user": "", "password": ""}
        if getattr(args, "skip_telnet", False)
        else resolve_telnet_credentials(args)
    )
    env = os.environ.copy()
    mappings = {
        "OPENUBMC_SSH_USER": ssh["user"],
        "OPENUBMC_SSH_PASSWORD": ssh["password"],
        "OPENUBMC_TELNET_USER": telnet["user"],
        "OPENUBMC_TELNET_PASSWORD": telnet["password"],
    }
    for name, value in mappings.items():
        if value:
            env[name] = str(value)
    return env


def base_script_command(script: str, args: argparse.Namespace) -> list[str]:
    return [sys.executable, "-B", str(SCRIPT_DIR / script), "--ip", args.ip]


def ssh_flags(args: argparse.Namespace) -> list[str]:
    flags: list[str] = []
    if getattr(args, "ssh_port", 22) != 22:
        flags.extend(["--ssh-port", str(args.ssh_port)])
    if getattr(args, "ssh_identity_file", ""):
        flags.extend(["--ssh-identity-file", args.ssh_identity_file])
    return flags


def telnet_flags(args: argparse.Namespace) -> list[str]:
    if getattr(args, "telnet_port", 23) == 23:
        return []
    return ["--telnet-port", str(args.telnet_port)]


def child_timeout_flags(script: str, args: argparse.Namespace) -> list[str]:
    """Translate the workflow tool timeout to each child CLI's public flags."""

    timeout = str(getattr(args, "timeout", 180))
    if script == "preflight_remote.py":
        return [
            "--ssh-timeout",
            timeout,
            "--telnet-connect-timeout",
            timeout,
            "--telnet-prompt-timeout",
            timeout,
        ]
    if script in {"mdbctl_remote.py", "busctl_remote.py", "active_alarms.py"}:
        return ["--timeout", timeout]
    if script in {"collect_logs.py", "read_remote_file.py"}:
        return [
            "--connect-timeout",
            timeout,
            "--prompt-timeout",
            timeout,
            "--command-timeout",
            timeout,
        ]
    return []


def _preflight_command(args: argparse.Namespace) -> list[str]:
    return base_script_command("preflight_remote.py", args) + [
        *ssh_flags(args),
        *telnet_flags(args),
        *(["--skip-telnet"] if getattr(args, "skip_telnet", False) else []),
        *(["--mdb-only"] if getattr(args, "mdb_only", False) else []),
        *(
            item
            for name in getattr(args, "preflight_checks", [])
            for item in ("--check", str(name))
        ),
        *child_timeout_flags("preflight_remote.py", args),
        "--json",
        "--compact-json",
    ]


def _active_alarm_command(
    args: argparse.Namespace,
    *,
    service_override: str = "",
    path_override: str = "",
) -> list[str]:
    command = (
        base_script_command("active_alarms.py", args)
        + ssh_flags(args)
        + child_timeout_flags("active_alarms.py", args)
    )
    command.extend(["--deadline", str(getattr(args, "timeout", 180))])
    service = service_override or getattr(args, "alarm_service", "")
    path = path_override or getattr(args, "alarm_path", "")
    if service:
        command.extend(["--service", service])
    if path:
        command.extend(["--path", path])
    command.extend(
        [
            "--discovery-service-limit",
            str(getattr(args, "alarm_discovery_service_limit", 16)),
            "--discovery-path-limit",
            str(getattr(args, "alarm_discovery_path_limit", 64)),
            "--limit",
            str(getattr(args, "alarm_limit", 100)),
            "--json",
            "--compact-json",
        ]
    )
    signature = getattr(args, "alarm_call_signature", "")
    if signature:
        command.extend(["--call-signature", signature])
        for value in getattr(args, "alarm_call_arg", []):
            command.extend(["--call-arg", value])
    return command


def _freshness_alarm_command(
    args: argparse.Namespace,
    active_before: dict[str, object],
) -> tuple[list[str], str]:
    """Re-introspect the exact start endpoint when automatic discovery succeeded."""

    if getattr(args, "alarm_service", "") or getattr(args, "alarm_path", ""):
        return _active_alarm_command(args), "explicit_request"
    if active_before.get("ok"):
        payload = active_before.get("payload")
        result = payload.get("result") if isinstance(payload, dict) else None
        if isinstance(result, dict):
            service = result.get("service")
            path = result.get("path")
            if isinstance(service, str) and service and isinstance(path, str) and path:
                return (
                    _active_alarm_command(
                        args,
                        service_override=service,
                        path_override=path,
                    ),
                    "start_snapshot",
                )
    return _active_alarm_command(args), "automatic"


def _read_file_command(args: argparse.Namespace, path: str) -> list[str]:
    return (
        base_script_command("read_remote_file.py", args)
        + telnet_flags(args)
        + child_timeout_flags("read_remote_file.py", args)
        + [
            "--path",
            path,
            "--json",
            "--compact-json",
        ]
    )


def _object_capabilities(enabled: bool | dict[str, bool]) -> dict[str, bool]:
    if isinstance(enabled, dict):
        remote_object = bool(enabled.get("remote_object"))
        mdbctl = bool(enabled.get("mdbctl", remote_object))
        busctl = bool(enabled.get("busctl", remote_object))
        active_alarms = bool(
            enabled.get(
                "active_alarm_transport",
                enabled.get("active_alarms", busctl),
            )
        )
    else:
        remote_object = bool(enabled)
        mdbctl = remote_object
        busctl = remote_object
        active_alarms = remote_object
    return {
        "mdbctl": mdbctl,
        "busctl": busctl,
        "active_alarms": active_alarms,
    }


def _mdb_command(args: argparse.Namespace, query: list[str]) -> list[str]:
    return (
        base_script_command("mdbctl_remote.py", args)
        + ssh_flags(args)
        + child_timeout_flags("mdbctl_remote.py", args)
        + ["--json", "--compact-json", *query]
    )


def _run_command_batch(
    commands: dict[str, list[str]],
    *,
    tool_runner,
    env: dict[str, str],
    timeout: int,
    deadline: WorkflowDeadline | None,
    max_workers: int,
) -> dict[str, dict[str, object]]:
    if not commands:
        return {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            name: executor.submit(
                tool_runner,
                name,
                command,
                env,
                timeout,
                deadline=deadline,
            )
            for name, command in commands.items()
        }
        return {name: futures[name].result() for name in commands}


def _expansion_objects(result: dict[str, object]) -> tuple[list[str], int]:
    if not bool(result.get("ok")):
        return [], 0
    payload = result.get("payload")
    payload_result = payload.get("result") if isinstance(payload, dict) else None
    lines = (
        payload_result.get("stdout_lines")
        if isinstance(payload_result, dict)
        else None
    )
    objects: list[str] = []
    invalid_count = 0
    for raw_line in lines if isinstance(lines, list) else []:
        object_name = str(raw_line).strip()
        if not object_name:
            continue
        if not mdbctl_remote.is_read_only_command(["lsprop", object_name]):
            invalid_count += 1
            continue
        if object_name not in objects:
            objects.append(object_name)
    return objects, invalid_count


def _local_workflow_failure(name: str, code: str, error: str) -> dict[str, object]:
    observed_at = utc_now()
    return {
        "name": name,
        "ok": False,
        "code": code,
        "returncode": 2,
        "started_at": observed_at,
        "completed_at": observed_at,
        "command": [],
        "payload": None,
        "error": error,
    }


def _mdb_expansion_result_name(discovery_name: str, object_name: str) -> str:
    digest = hashlib.sha256(object_name.encode("utf-8")).hexdigest()[:12]
    return f"{discovery_name}_object_{digest}"


def _run_mdb_plan(
    args: argparse.Namespace,
    env: dict[str, str],
    deadline: WorkflowDeadline | None,
    *,
    tool_runner,
) -> dict[str, dict[str, object]]:
    initial_commands: dict[str, list[str]] = {}
    for index, query in enumerate(requested_mdb_queries(args), start=1):
        name = "mdbctl" if index == 1 else f"mdbctl_{index}"
        initial_commands[name] = _mdb_command(args, query)
    discoveries: list[tuple[str, str]] = []
    for index, class_name in enumerate(
        requested_mdb_expand_classes(args),
        start=1,
    ):
        name = f"mdbctl_expand_{index}"
        discoveries.append((name, class_name))
        initial_commands[name] = _mdb_command(args, ["lsobj", class_name])

    results = _run_command_batch(
        initial_commands,
        tool_runner=tool_runner,
        env=env,
        timeout=getattr(args, "timeout", 180),
        deadline=deadline,
        max_workers=mdb_concurrency_budget(args, len(initial_commands)),
    )
    expanded_commands: dict[str, list[str]] = {}
    validation_failures: dict[str, dict[str, object]] = {}
    for discovery_name, _class_name in discoveries:
        objects, invalid_count = _expansion_objects(results[discovery_name])
        if invalid_count:
            validation_name = f"{discovery_name}_validation"
            validation_failures[validation_name] = _local_workflow_failure(
                validation_name,
                "invalid_mdb_expansion_output",
                "MDB class discovery returned one or more invalid object tokens",
            )
            continue
        for object_name in objects:
            name = _mdb_expansion_result_name(discovery_name, object_name)
            expanded_commands[name] = _mdb_command(
                args,
                ["lsprop", object_name],
            )
    expanded_results = _run_command_batch(
        expanded_commands,
        tool_runner=tool_runner,
        env=env,
        timeout=getattr(args, "timeout", 180),
        deadline=deadline,
        max_workers=mdb_concurrency_budget(args, len(expanded_commands)),
    )
    results.update(validation_failures)
    results.update(expanded_results)
    return results


def run_ssh_lane(
    args: argparse.Namespace,
    env: dict[str, str],
    enabled: bool | dict[str, bool],
    deadline: WorkflowDeadline | None = None,
    *,
    tool_runner=None,
) -> dict[str, dict[str, object]]:
    selected_tool_runner = tool_runner or run_json_tool
    capabilities = _object_capabilities(enabled)
    selected = {
        "mdbctl": True,
        "busctl": not bool(getattr(args, "mdb_only", False)),
        "active_alarms": not bool(getattr(args, "mdb_only", False)),
    }
    tree_service = getattr(args, "tree_service", "")
    busctl_command = (
        base_script_command("busctl_remote.py", args)
        + ssh_flags(args)
        + child_timeout_flags("busctl_remote.py", args)
    )
    busctl_command.extend(
        [
            "--action",
            "tree" if tree_service else "list",
        ]
    )
    if tree_service:
        busctl_command.extend(["--service", tree_service])
    busctl_command.extend(
        [
            "--head",
            str(getattr(args, "tree_head", 20)),
            "--json",
            "--compact-json",
        ]
    )
    mdb_initial_names: list[str] = []
    for index, query in enumerate(requested_mdb_queries(args), start=1):
        name = "mdbctl" if index == 1 else f"mdbctl_{index}"
        mdb_initial_names.append(name)
    mdb_initial_names.extend(
        f"mdbctl_expand_{index}"
        for index, _class_name in enumerate(
            requested_mdb_expand_classes(args),
            start=1,
        )
    )
    if capabilities["mdbctl"]:
        mdb_results: dict[str, dict[str, object]] | None = None
    else:
        reason = "mdbctl capability was not available after preflight"
        mdb_results = {
            name: skipped_result(name, reason) for name in mdb_initial_names
        }

    other_commands = {
        "busctl": busctl_command,
        "active_alarms": _active_alarm_command(args),
    }
    other_results: dict[str, dict[str, object]] = {}
    pending_other: dict[str, list[str]] = {}
    for name, command in other_commands.items():
        if not selected[name]:
            other_results[name] = skipped_result(
                name,
                f"{name} was not selected by the MDB-only workflow",
            )
        elif not capabilities[name]:
            other_results[name] = skipped_result(
                name,
                f"{name} capability was not available after preflight",
            )
        else:
            pending_other[name] = command

    if mdb_results is None and pending_other:
        with ThreadPoolExecutor(max_workers=1) as executor:
            other_future = executor.submit(
                _run_command_batch,
                pending_other,
                tool_runner=selected_tool_runner,
                env=env,
                timeout=getattr(args, "timeout", 180),
                deadline=deadline,
                max_workers=len(pending_other),
            )
            mdb_results = _run_mdb_plan(
                args,
                env,
                deadline,
                tool_runner=selected_tool_runner,
            )
            other_results.update(other_future.result())
    else:
        if mdb_results is None:
            mdb_results = _run_mdb_plan(
                args,
                env,
                deadline,
                tool_runner=selected_tool_runner,
            )
        if pending_other:
            other_results.update(
                _run_command_batch(
                    pending_other,
                    tool_runner=selected_tool_runner,
                    env=env,
                    timeout=getattr(args, "timeout", 180),
                    deadline=deadline,
                    max_workers=len(pending_other),
                )
            )
    return {
        **mdb_results,
        "busctl": other_results["busctl"],
        "active_alarms": other_results["active_alarms"],
    }


def run_capability_ready_mdb_lane(
    args: argparse.Namespace,
    env: dict[str, str],
    preflight_run,
    deadline: WorkflowDeadline,
    *,
    tool_runner,
) -> dict[str, dict[str, object]]:
    enabled = preflight_run.wait_capability("mdbctl", deadline=deadline)
    mdb_args = copy.copy(args)
    mdb_args.mdb_only = True
    mdb_args.skip_telnet = True
    lane = run_ssh_lane(
        mdb_args,
        env,
        {
            "remote_object": enabled,
            "mdbctl": enabled,
            "busctl": False,
            "active_alarm_transport": False,
        },
        deadline,
        tool_runner=tool_runner,
    )
    return {
        name: result
        for name, result in lane.items()
        if name not in {"busctl", "active_alarms"}
    }


def run_capability_ready_bus_lane(
    args: argparse.Namespace,
    env: dict[str, str],
    preflight_run,
    deadline: WorkflowDeadline,
    *,
    tool_runner,
) -> dict[str, dict[str, object]]:
    enabled = preflight_run.wait_capability("busctl", deadline=deadline)
    lane = run_ssh_lane(
        args,
        env,
        {
            "remote_object": enabled,
            "mdbctl": False,
            "busctl": enabled,
            "active_alarm_transport": enabled,
        },
        deadline,
        tool_runner=tool_runner,
    )
    return {
        "busctl": lane["busctl"],
        "active_alarms": lane["active_alarms"],
    }


def run_capability_ready_telnet_lane(
    args: argparse.Namespace,
    env: dict[str, str],
    preflight_run,
    deadline: WorkflowDeadline,
    *,
    tool_runner,
) -> dict[str, object]:
    enabled = preflight_run.wait_capability(
        "remote_log_file",
        deadline=deadline,
    )
    return run_telnet_lane(
        args,
        env,
        enabled,
        deadline,
        tool_runner=tool_runner,
    )


def run_telnet_lane(
    args: argparse.Namespace,
    env: dict[str, str],
    enabled: bool,
    deadline: WorkflowDeadline | None = None,
    *,
    tool_runner=None,
) -> dict[str, object]:
    selected_tool_runner = tool_runner or run_json_tool
    files = requested_files(args)
    if not enabled:
        reason = "Remote log/file capability was not available after preflight"
        return {
            "logs": skipped_result("logs", reason),
            "files": {path: skipped_result(f"file:{path}", reason) for path in files},
        }
    log_command = (
        base_script_command("collect_logs.py", args)
        + telnet_flags(args)
        + child_timeout_flags("collect_logs.py", args)
        + [
            "--logs",
            getattr(args, "logs", "app.log,framework.log"),
            "--lines",
            str(getattr(args, "lines", 200)),
            "--rotated-limit",
            str(getattr(args, "rotated_limit", 3)),
            "--max-bytes",
            str(getattr(args, "log_max_bytes", DEFAULT_LOG_MAX_BYTES)),
            "--json",
            "--compact-json",
        ]
    )
    if getattr(args, "keyword", ""):
        log_command.extend(["--grep", args.keyword, "--since-boot"])
    if getattr(args, "include_rotated", False):
        log_command.append("--include-rotated")
    logs = selected_tool_runner(
        "logs",
        log_command,
        env,
        getattr(args, "timeout", 180),
        deadline=deadline,
    )
    file_results: dict[str, dict[str, object]] = {}
    for path in files:
        file_results[path] = selected_tool_runner(
            f"file:{path}",
            _read_file_command(args, path),
            env,
            getattr(args, "timeout", 180),
            deadline=deadline,
        )
    return {"logs": logs, "files": file_results}


def alarm_search_terms(active_result: dict[str, object]) -> list[str]:
    terms: list[str] = []
    for record in alarm_records(active_result):
        for term in stable_alarm_terms(record):
            if term not in terms:
                terms.append(term)
    return terms


def run_alarm_log_lane(
    args: argparse.Namespace,
    env: dict[str, str],
    enabled: bool,
    active_result: dict[str, object],
    deadline: WorkflowDeadline | None = None,
    *,
    tool_runner=None,
) -> dict[str, object]:
    if not enabled:
        return skipped_result(
            "alarm_logs", "Remote log/file capability was not available after preflight"
        )
    terms = alarm_search_terms(active_result)
    if not terms:
        return skipped_result(
            "alarm_logs", "No stable EventName/EventCode terms were available"
        )
    command = (
        base_script_command("collect_logs.py", args)
        + telnet_flags(args)
        + child_timeout_flags("collect_logs.py", args)
        + [
            "--logs",
            getattr(args, "logs", "app.log,framework.log"),
            "--lines",
            str(getattr(args, "lines", 200)),
            "--rotated-limit",
            str(getattr(args, "rotated_limit", 3)),
            "--max-bytes",
            str(getattr(args, "log_max_bytes", DEFAULT_LOG_MAX_BYTES)),
            "--grep",
            ",".join(terms),
            "--since-boot",
            "--json",
            "--compact-json",
        ]
    )
    if getattr(args, "include_rotated", False):
        command.append("--include-rotated")
    return (tool_runner or run_json_tool)(
        "alarm_logs",
        command,
        env,
        getattr(args, "timeout", 180),
        deadline=deadline,
    )


def flatten_results(lanes: dict[str, object]) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for value in lanes.values():
        if isinstance(value, dict) and "code" in value:
            results.append(value)
        elif isinstance(value, dict):
            results.extend(flatten_results(value))
    return results


def build_summary(
    preflight_start: dict[str, object], lanes: dict[str, object]
) -> dict[str, object]:
    all_results = [preflight_start, *flatten_results(lanes)]
    return {
        "executed": [item["name"] for item in all_results if item["code"] != "skipped"],
        "failed": [
            item["name"]
            for item in all_results
            if item["code"] != "skipped" and not item["ok"]
        ],
        "skipped": [item["name"] for item in all_results if item["code"] == "skipped"],
    }


def _append_summary_results(
    summary: dict[str, object], results: list[dict[str, object]]
) -> None:
    summary["executed"].extend(
        item["name"] for item in results if item["code"] != "skipped"
    )
    summary["failed"].extend(
        item["name"]
        for item in results
        if item["code"] != "skipped" and not item["ok"]
    )
    summary["skipped"].extend(
        item["name"] for item in results if item["code"] == "skipped"
    )


def _source_search_result(correlation: dict[str, object]) -> dict[str, object]:
    search = correlation.get("source_search")
    if not isinstance(search, dict):
        return {
            "name": "source_search",
            "ok": False,
            "code": "source_search_failed",
            "returncode": 1,
            "error": "Source search result was missing",
        }
    code = str(search.get("code", "source_search_failed"))
    if code == "skipped":
        return skipped_result(
            "source_search", str(search.get("error", "Source correlation disabled"))
        )
    ok = bool(search.get("ok"))
    return {
        "name": "source_search",
        "ok": ok,
        "code": code,
        "returncode": 0 if ok else (124 if search.get("timed_out") else 1),
        "error": str(search.get("error", "")),
    }


def _collect_freshness(
    args: argparse.Namespace,
    env: dict[str, str],
    deadline: WorkflowDeadline,
    preflight_start: dict[str, object],
    preflight_command: list[str],
    lanes: dict[str, object],
    *,
    tool_runner=None,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    selected_tool_runner = tool_runner or run_json_tool
    preflight_end = selected_tool_runner(
        "preflight_end",
        preflight_command,
        env,
        args.timeout,
        deadline=deadline,
    )
    end_capabilities = preflight_capabilities(preflight_end)
    active_before = lanes["ssh"]["active_alarms"]
    active_alarm_end_enabled = (
        end_capabilities["active_alarms"] and snapshot_available(active_before)
    )
    telnet_end_enabled = end_capabilities["remote_log_file"]
    active_end_command, active_endpoint_source = _freshness_alarm_command(
        args, active_before
    )
    active_end = (
        selected_tool_runner(
            "active_alarms_end",
            active_end_command,
            env,
            args.timeout,
            deadline=deadline,
        )
        if active_alarm_end_enabled
        else skipped_result(
            "active_alarms_end", "Final active_alarms capability was unavailable"
        )
    )
    files = lanes["telnet"]["files"]
    version_before = files.get(
        VERSION_PATH, skipped_result("version_start", "fixed version snapshot missing")
    )
    uptime_before = files.get(
        UPTIME_PATH, skipped_result("uptime_start", "fixed uptime snapshot missing")
    )
    if telnet_end_enabled:
        version_end = selected_tool_runner(
            "version_end",
            _read_file_command(args, VERSION_PATH),
            env,
            args.timeout,
            deadline=deadline,
        )
        uptime_end = selected_tool_runner(
            "uptime_end",
            _read_file_command(args, UPTIME_PATH),
            env,
            args.timeout,
            deadline=deadline,
        )
    else:
        version_end = skipped_result(
            "version_end", "Final remote log/file capability was unavailable"
        )
        uptime_end = skipped_result(
            "uptime_end", "Final remote log/file capability was unavailable"
        )
    bmc_time_delta = compare_bmc_time_snapshots(preflight_start, preflight_end)
    bmc_elapsed_seconds = (
        bmc_time_delta.get("elapsed_seconds")
        if bmc_time_delta.get("comparable")
        and not bmc_time_delta.get("clock_moved_backwards")
        else None
    )
    preflight_delta = compare_preflight(preflight_start, preflight_end)
    alarm_delta = compare_alarm_snapshots(active_before, active_end)
    version_delta = compare_file_snapshots(version_before, version_end)
    uptime_delta = compare_uptime_snapshots(
        uptime_before,
        uptime_end,
        bmc_elapsed_seconds=bmc_elapsed_seconds,
    )
    freshness = {
        "captured_at": utc_now(),
        "preflight_end": preflight_end,
        "active_alarms_end": active_end,
        "active_alarm_endpoint_source": active_endpoint_source,
        "version_end": version_end,
        "uptime_end": uptime_end,
        "preflight_delta": preflight_delta,
        "alarm_delta": alarm_delta,
        "version_delta": version_delta,
        "uptime_delta": uptime_delta,
        "bmc_time_delta": bmc_time_delta,
    }
    assessment = _assess_freshness(
        preflight_start=preflight_start,
        preflight_end=preflight_end,
        active_before=active_before,
        active_end=active_end,
        version_before=version_before,
        version_end=version_end,
        uptime_before=uptime_before,
        uptime_end=uptime_end,
        preflight_delta=preflight_delta,
        alarm_delta=alarm_delta,
        version_delta=version_delta,
        uptime_delta=uptime_delta,
        bmc_time_delta=bmc_time_delta,
        required_dimensions={
            "preflight",
            "bmc_time",
            *(
                ()
                if bool(getattr(args, "mdb_only", False))
                else ("active_alarms",)
            ),
            *(
                ()
                if bool(getattr(args, "skip_telnet", False))
                else ("version", "uptime")
            ),
        },
    )
    freshness.update(assessment)
    freshness_ok = not assessment["lost_dimensions"] and not assessment["stale_evidence"]
    freshness_code = (
        "ok"
        if freshness_ok
        else (
            "freshness_changed_during_capture"
            if assessment["stale_evidence"]
            else "freshness_incomplete"
        )
    )
    freshness_result = {
        "name": "freshness",
        "ok": freshness_ok,
        "code": freshness_code,
        "returncode": 0 if freshness_ok else 1,
        "error": (
            ""
            if freshness_ok
            else "Freshness evidence changed or became unavailable during capture"
        ),
    }
    return freshness, [
        preflight_end,
        active_end,
        version_end,
        uptime_end,
        freshness_result,
    ]


def _assess_freshness(
    *,
    preflight_start: dict[str, object],
    preflight_end: dict[str, object],
    active_before: dict[str, object],
    active_end: dict[str, object],
    version_before: dict[str, object],
    version_end: dict[str, object],
    uptime_before: dict[str, object],
    uptime_end: dict[str, object],
    preflight_delta: dict[str, object],
    alarm_delta: dict[str, object],
    version_delta: dict[str, object],
    uptime_delta: dict[str, object],
    bmc_time_delta: dict[str, object],
    required_dimensions: set[str] | None = None,
) -> dict[str, object]:
    """Aggregate freshness completeness without hiding changed or lost lanes."""

    deltas = {
        "preflight": preflight_delta,
        "active_alarms": alarm_delta,
        "version": version_delta,
        "uptime": uptime_delta,
        "bmc_time": bmc_time_delta,
    }
    selected_dimensions = set(deltas) if required_dimensions is None else set(
        required_dimensions
    )
    comparable_dimensions = [
        name
        for name, delta in deltas.items()
        if name in selected_dimensions and bool(delta.get("comparable"))
    ]
    unavailable_dimensions = [
        name
        for name in deltas
        if name in selected_dimensions and name not in comparable_dimensions
    ]
    not_requested_dimensions = [
        name for name in deltas if name not in selected_dimensions
    ]
    availability_pairs = {
        "preflight": (
            snapshot_available(preflight_start),
            snapshot_available(preflight_end),
        ),
        "active_alarms": (
            snapshot_available(active_before),
            snapshot_available(active_end),
        ),
        "version": (
            snapshot_available(version_before),
            snapshot_available(version_end),
        ),
        "uptime": (
            snapshot_available(uptime_before),
            snapshot_available(uptime_end),
        ),
    }
    lost_dimensions = [
        name
        for name, (before, after) in availability_pairs.items()
        if name in selected_dimensions and before and not after
    ]
    stale_evidence: list[str] = []

    def mark_stale(*names: str) -> None:
        for name in names:
            if name not in stale_evidence:
                stale_evidence.append(name)

    if bool(preflight_delta.get("changed")):
        mark_stale("preflight_start")
    if "active_alarms" in selected_dimensions and bool(alarm_delta.get("changed")):
        mark_stale("active_alarms_start")
    if "version" in selected_dimensions and bool(version_delta.get("changed")):
        mark_stale("version_start")
    if "uptime" in selected_dimensions and bool(uptime_delta.get("reboot_detected")):
        mark_stale(
            "preflight_start",
            "active_alarms_start",
            "logs_start",
            "version_start",
            "uptime_start",
        )
    if bool(bmc_time_delta.get("clock_moved_backwards")):
        mark_stale("preflight_start", "active_alarms_start", "logs_start")

    status = (
        "complete"
        if not unavailable_dimensions
        else "partial"
        if comparable_dimensions
        else "unavailable"
    )
    after_last_change: bool | str = (
        False
        if stale_evidence
        else True
        if status == "complete"
        else "unknown"
    )
    return {
        "status": status,
        "complete": status == "complete",
        "comparable_dimensions": comparable_dimensions,
        "unavailable_dimensions": unavailable_dimensions,
        "not_requested_dimensions": not_requested_dimensions,
        "lost_dimensions": lost_dimensions,
        "after_last_reboot_or_change": after_last_change,
        "stale_evidence": stale_evidence,
    }


def emit_text(payload: dict[str, object]) -> None:
    result = payload["result"]
    summary = result["summary"]
    print(f"workflow_ok={payload['ok']} code={payload['code']}")
    print(f"executed={','.join(summary['executed'])}")
    print(f"failed={','.join(summary['failed']) or '-'}")
    print(f"skipped={','.join(summary['skipped']) or '-'}")
    freshness = result.get("freshness", {})
    if freshness:
        alarm_delta = freshness.get("alarm_delta", {})
        print(
            "alarm_count="
            f"{alarm_delta.get('before_count')}->{alarm_delta.get('after_count')} "
            f"comparable={alarm_delta.get('comparable')} "
            f"changed={alarm_delta.get('changed')} "
            f"identity_changed={alarm_delta.get('identity_changed')} "
            f"payload_changed={alarm_delta.get('payload_changed')}"
        )


def _validate_numeric_args(args: argparse.Namespace) -> None:
    for value, label in (
        (args.lines, "--lines"),
        (args.rotated_limit, "--rotated-limit"),
        (args.log_max_bytes, "--log-max-bytes"),
        (args.tree_head, "--tree-head"),
        (args.alarm_discovery_service_limit, "--alarm-discovery-service-limit"),
        (args.alarm_discovery_path_limit, "--alarm-discovery-path-limit"),
        (args.correlate_alarm_limit, "--correlate-alarm-limit"),
        (args.correlation_time_window, "--correlation-time-window"),
        (args.timeout, "--timeout"),
        (args.deadline, "--deadline"),
    ):
        if value < 1:
            raise SystemExit(f"{label} must be positive")
    if args.source_max_matches < 0:
        raise SystemExit("--source-max-matches must be non-negative")
    if args.rotated_limit > MAX_ROTATED_LIMIT:
        raise SystemExit(f"--rotated-limit must be at most {MAX_ROTATED_LIMIT}")
    if args.log_max_bytes > HARD_MAX_LOG_BYTES:
        raise SystemExit(f"--log-max-bytes must be at most {HARD_MAX_LOG_BYTES}")


def _execute_workflow(
    args: argparse.Namespace,
    *,
    source_root_source: str,
    engine: str,
    env: dict[str, str],
    tool_runner,
    runtime_status=None,
    parallel_lanes: bool,
    emit_output: bool = True,
    output_handler=None,
) -> int:
    started_at = utc_now()
    deadline = WorkflowDeadline(args.deadline)
    preflight_command = _preflight_command(args)
    preflight_starter = getattr(tool_runner, "start_capability_preflight", None)
    if parallel_lanes and callable(preflight_starter):
        preflight_run = preflight_starter(
            preflight_command,
            env,
            args.timeout,
            deadline=deadline,
            release_cached_mdb=bool(
                getattr(args, "fast_snapshot", False)
            ),
        )
        with ThreadPoolExecutor(max_workers=3) as executor:
            mdb_future = executor.submit(
                run_capability_ready_mdb_lane,
                args,
                env,
                preflight_run,
                deadline,
                tool_runner=tool_runner,
            )
            bus_future = executor.submit(
                run_capability_ready_bus_lane,
                args,
                env,
                preflight_run,
                deadline,
                tool_runner=tool_runner,
            )
            telnet_future = executor.submit(
                run_capability_ready_telnet_lane,
                args,
                env,
                preflight_run,
                deadline,
                tool_runner=tool_runner,
            )
            preflight_start = preflight_run.result()
            capabilities = preflight_capabilities(preflight_start)
            lanes = {
                "ssh": {
                    **mdb_future.result(),
                    **bus_future.result(),
                },
                "telnet": telnet_future.result(),
            }
    else:
        preflight_start = tool_runner(
            "preflight_start",
            preflight_command,
            env,
            args.timeout,
            deadline=deadline,
        )
        capabilities = preflight_capabilities(preflight_start)
        telnet_enabled = capabilities["remote_log_file"]

    if parallel_lanes and not callable(preflight_starter):
        with ThreadPoolExecutor(max_workers=2) as executor:
            ssh_future = executor.submit(
                run_ssh_lane,
                args,
                env,
                capabilities,
                deadline,
                tool_runner=tool_runner,
            )
            telnet_future = executor.submit(
                run_telnet_lane,
                args,
                env,
                telnet_enabled,
                deadline,
                tool_runner=tool_runner,
            )
            lanes: dict[str, object] = {
                "ssh": ssh_future.result(),
                "telnet": telnet_future.result(),
            }
    elif not parallel_lanes:
        lanes = {
            "ssh": run_ssh_lane(
                args,
                env,
                capabilities,
                deadline,
                tool_runner=tool_runner,
            ),
            "telnet": run_telnet_lane(
                args,
                env,
                telnet_enabled,
                deadline,
                tool_runner=tool_runner,
            ),
        }

    telnet_enabled = capabilities["remote_log_file"]

    lanes["telnet"]["alarm_logs"] = run_alarm_log_lane(
        args,
        env,
        telnet_enabled,
        lanes["ssh"]["active_alarms"],
        deadline,
        tool_runner=tool_runner,
    )
    summary = build_summary(preflight_start, lanes)
    source_correlation_requested = (
        bool(args.source_root) and not args.no_source_correlation
    )
    correlation = build_correlation(
        lanes["ssh"]["active_alarms"],
        lanes["telnet"]["alarm_logs"],
        source_root=args.source_root,
        max_matches=args.source_max_matches,
        alarm_limit=args.correlate_alarm_limit,
        timeout=min(float(args.timeout), deadline.remaining()),
        workflow_keyword=args.keyword,
        enabled=source_correlation_requested and not deadline.exhausted(),
        workflow_logs_result=lanes["telnet"]["logs"],
        time_window=args.correlation_time_window,
    )
    source_search_result = _source_search_result(correlation)
    _append_summary_results(summary, [source_search_result])

    freshness: dict[str, object] = {}
    if not args.no_freshness:
        freshness, freshness_results = _collect_freshness(
            args,
            env,
            deadline,
            preflight_start,
            preflight_command,
            lanes,
            tool_runner=tool_runner,
        )
        _append_summary_results(summary, freshness_results)

    all_results = [preflight_start, *flatten_results(lanes), source_search_result]
    if freshness:
        all_results.extend(
            freshness[name]
            for name in (
                "preflight_end",
                "active_alarms_end",
                "version_end",
                "uptime_end",
            )
            if isinstance(freshness.get(name), dict)
        )
    deadline_failed = any(
        result.get("code") == "workflow_deadline_exceeded" for result in all_results
    )
    ok = bool(preflight_start["ok"]) and not summary["failed"]
    code = (
        "ok"
        if ok
        else (
            "workflow_deadline_exceeded"
            if deadline_failed or deadline.exhausted()
            else "workflow_partial_failure"
        )
    )
    payload = build_json_payload(
        tool="workflow_remote",
        ip=args.ip,
        ok=ok,
        code=code,
        returncode=0 if ok else 1,
        request={
            "keyword": args.keyword,
            "mdb_queries": [" ".join(query) for query in requested_mdb_queries(args)],
            "mdb_expand_classes": requested_mdb_expand_classes(args),
            "mdb_concurrency": args.mdb_concurrency,
            "mdb_only": bool(args.mdb_only),
            "logs": args.logs,
            "lines": args.lines,
            "include_rotated": args.include_rotated,
            "rotated_limit": args.rotated_limit,
            "log_max_bytes": args.log_max_bytes,
            "files": requested_files(args),
            "tree_service": args.tree_service,
            "tree_head": args.tree_head,
            "alarm_service": args.alarm_service,
            "alarm_path": args.alarm_path,
            "alarm_discovery_service_limit": args.alarm_discovery_service_limit,
            "alarm_discovery_path_limit": args.alarm_discovery_path_limit,
            "alarm_limit": args.alarm_limit,
            "alarm_call_signature": args.alarm_call_signature,
            "alarm_call_args": args.alarm_call_arg,
            "freshness_requested": not args.no_freshness,
            "source_root": args.source_root,
            "source_root_source": source_root_source,
            "source_correlation_requested": source_correlation_requested,
            "source_max_matches": args.source_max_matches,
            "correlate_alarm_limit": args.correlate_alarm_limit,
            "correlation_time_window": args.correlation_time_window,
            "tool_timeout": args.timeout,
            "deadline": args.deadline,
        },
        result={
            "started_at": started_at,
            "completed_at": utc_now(),
            "deadline": deadline.as_result(),
            "preflight_start": preflight_start,
            "capabilities": capabilities,
            "source_root_resolution": {
                "root": args.source_root or None,
                "source": source_root_source,
            },
            "lanes": lanes,
            "freshness": freshness,
            "correlation": correlation,
            "summary": summary,
            "runtime": {
                "engine": engine,
                "status": runtime_status() if runtime_status is not None else {},
            },
        },
    )
    output_candidate = (
        compact_workflow_payload(payload) if args.compact_json else payload
    )
    output_payload = output_candidate
    if output_handler is not None:
        output_handler(output_payload)
    if emit_output:
        if args.json:
            print(json.dumps(output_payload, indent=2, ensure_ascii=False))
        else:
            emit_text(payload)
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    """Enter the shared Context Runtime while preserving legacy CLI inputs."""

    import target_runtime_cli

    return target_runtime_cli.run_legacy(argv)


if __name__ == "__main__":
    raise SystemExit(main())
