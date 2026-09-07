#!/usr/bin/env python3
"""Execute one checked attempt from an immutable openUBMC build plan."""

from __future__ import annotations

import argparse
from collections import deque
import ctypes
from datetime import datetime, timezone
import fcntl
import hashlib
import json
from multiprocessing import Pipe
from multiprocessing.connection import Connection
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
from typing import Callable, TextIO
import uuid

from create_build_plan import (
    EXECUTION_CONTRACT_FILES,
    LOCAL_LOCK_ROOT,
    atomic_write_json,
    file_identity,
    output_resource_lock,
    semantic_plan_id,
    skill_digest,
    workspace_identity,
)
from run_bmcgo_checked import (
    DEFAULT_FAILURE_PATTERNS,
    DEFAULT_IGNORE_PATTERNS,
    compile_patterns,
    is_failure_line,
)
from write_artifact_metadata import artifact_identity


TERMINAL_STATES = {"succeeded", "failed", "cancelled", "interrupted"}
SIGNAL_GRACE_SECONDS = 5.0
DESCENDANT_CLEAR_OBSERVATIONS = 3
PROCESS_OBSERVATION_INTERVAL = 0.05
PR_SET_CHILD_SUBREAPER = 36
TRUSTED_BOOTSTRAP = """
import ctypes
import os
import signal
import sys

PR_SET_PDEATHSIG = 1
expected_parent = int(sys.argv[1])
gate_fd = int(sys.argv[2])
executable = sys.argv[3]
command = sys.argv[4:]
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
    error = ctypes.get_errno()
    print(f"ERROR guardian bootstrap prctl failed: errno={error}", file=sys.stderr, flush=True)
    raise SystemExit(126)
if os.getppid() != expected_parent:
    raise SystemExit(125)
try:
    token = os.read(gate_fd, 1)
finally:
    os.close(gate_fd)
if token != b"1":
    raise SystemExit(125)
try:
    os.execve(executable, command, os.environ)
except BaseException as exc:
    print(
        f"ERROR guardian bootstrap exec failed: {type(exc).__name__}: {exc}",
        file=sys.stderr,
        flush=True,
    )
    raise SystemExit(126)
"""
WORKSPACE_BINDING_FIELDS = (
    "root",
    "git_dir",
    "git_common_dir",
    "git_head",
    "scoped_diff_sha256",
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_plan(path: Path) -> tuple[Path, dict[str, object], str]:
    resolved = path.resolve(strict=True)
    document_bytes = resolved.read_bytes()
    document = json.loads(document_bytes.decode("utf-8"))
    expected = document.get("plan_id")
    actual = semantic_plan_id(document)
    if expected != actual:
        raise ValueError(
            f"plan_digest_mismatch: recorded {expected}, calculated {actual}"
        )
    execution = document.get("execution", {})
    if Path(str(execution.get("plan_path", ""))).resolve() != resolved:
        raise ValueError("plan_path_mismatch")
    skill_root = Path(__file__).resolve().parents[1]
    current_contract = skill_digest(skill_root, EXECUTION_CONTRACT_FILES)
    planned_contract = document.get("runner", {}).get("execution_contract_sha256")
    if current_contract != planned_contract:
        raise ValueError(
            "execution_contract_digest_mismatch: executable Skill code changed "
            "after Plan creation"
        )
    executable = document.get("runner", {}).get("executable", {})
    if executable:
        current_executable = file_identity(Path(str(executable["path"])))
        for field in ("path", "sha256", "size", "mode"):
            if current_executable[field] != executable.get(field):
                raise ValueError(f"command_executable_drift: {field}")
    return resolved, document, hashlib.sha256(document_bytes).hexdigest()


def compare_workspace_identity(
    planned: dict[str, object],
    current: dict[str, object],
) -> dict[str, dict[str, object]]:
    return {
        field: {
            "planned": planned.get(field),
            "current": current.get(field),
        }
        for field in WORKSPACE_BINDING_FIELDS
        if current.get(field) != planned.get(field)
    }


def verify_workspaces(plan: dict[str, object]) -> dict[str, dict[str, object]]:
    current_identities: dict[str, dict[str, object]] = {}
    for name, planned in plan.get("workspaces", {}).items():
        mutable_paths = tuple(str(item) for item in planned.get("mutable_paths", []))
        current = workspace_identity(Path(planned["root"]), mutable_paths)
        drift = compare_workspace_identity(planned, current)
        if drift:
            field = next(iter(drift))
            values = drift[field]
            raise ValueError(
                f"workspace_drift: {name}.{field}: "
                f"planned {values['planned']}, current {values['current']}"
            )
        current_identities[name] = current
    return current_identities


def compare_file_identity(
    planned: dict[str, object],
    current: dict[str, object],
) -> dict[str, dict[str, object]]:
    return {
        field: {
            "planned": planned.get(field),
            "current": current.get(field),
        }
        for field in ("path", "sha256", "size", "mode")
        if current.get(field) != planned.get(field)
    }


def verify_input_locks(plan: dict[str, object]) -> dict[str, dict[str, object]]:
    current_locks: dict[str, dict[str, object]] = {}
    for name, planned in plan.get("locks", {}).items():
        current = file_identity(Path(str(planned["path"])))
        drift = compare_file_identity(planned, current)
        if drift:
            field = next(iter(drift))
            raise ValueError(f"input_lock_drift: {name}.{field}")
        current_locks[name] = current
    return current_locks


def snapshot_file(path: Path) -> dict[str, object]:
    absolute = path.absolute()
    try:
        identity = artifact_identity(absolute)
    except FileNotFoundError:
        return {"path": str(absolute), "status": "missing"}
    metadata = os.lstat(absolute)
    return {
        **identity,
        "status": "present",
        "device": int(metadata.st_dev),
        "inode": int(metadata.st_ino),
        "mtime_ns": int(metadata.st_mtime_ns),
        "ctime_ns": int(metadata.st_ctime_ns),
    }


def snapshot_outputs(plan: dict[str, object]) -> dict[str, dict[str, object]]:
    return {
        str(role): snapshot_file(Path(str(path)))
        for role, path in plan.get("expectations", {}).get("outputs", {}).items()
    }


def release_locks(handles: list[TextIO]) -> None:
    for handle in reversed(handles):
        try:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except (OSError, ValueError):
                pass
        finally:
            try:
                handle.close()
            except (OSError, ValueError):
                pass


def acquire_locks(specs: list[tuple[Path, str]]) -> list[TextIO]:
    handles: list[TextIO] = []
    try:
        unique: dict[Path, str] = {}
        for raw_path, contention in specs:
            unique.setdefault(raw_path.resolve(), contention)
        for path, contention in sorted(unique.items(), key=lambda item: str(item[0])):
            path.parent.mkdir(parents=True, exist_ok=True)
            handle = path.open("a+", encoding="utf-8")
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                handle.close()
                raise ValueError(f"{contention}: {path}") from exc
            handles.append(handle)
        return handles
    except Exception:
        release_locks(handles)
        raise


def prepare_local_lock_root() -> None:
    LOCAL_LOCK_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = os.lstat(LOCAL_LOCK_ROOT)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ValueError(f"unsafe_local_lock_root: {LOCAL_LOCK_ROOT}")
    os.chmod(LOCAL_LOCK_ROOT, 0o700)
    output_root = LOCAL_LOCK_ROOT / "output-locks"
    output_root.mkdir(mode=0o700, exist_ok=True)
    output_metadata = os.lstat(output_root)
    if not stat.S_ISDIR(output_metadata.st_mode) or output_metadata.st_uid != os.getuid():
        raise ValueError(f"unsafe_output_lock_root: {output_root}")
    os.chmod(output_root, 0o700)


def expected_output_resources(plan: dict[str, object]) -> list[dict[str, str]]:
    if plan.get("mode") != "product-artifact":
        return []
    expectations = plan.get("expectations", {})
    resources = (
        (
            "artifact",
            expectations.get("artifact", {}).get("path", ""),
        ),
        (
            "dependency_lock",
            expectations.get("dependency_delta", {}).get("actual_path", ""),
        ),
        (
            "metadata",
            expectations.get("metadata", {}).get("path", ""),
        ),
        (
            "product_version",
            expectations.get("versions", {})
            .get("product", {})
            .get("evidence_path", ""),
        ),
        (
            "rootfs",
            expectations.get("rootfs_access", {}).get("root", ""),
        ),
    )
    if any(not path for _role, path in resources):
        raise ValueError("plan_missing_output_resource")
    return sorted(
        (
            output_resource_lock(role, Path(str(path)))
            for role, path in resources
        ),
        key=lambda item: (item["role"], item["path"]),
    )


def recover_stale_attempts(attempts_root: Path) -> None:
    if not attempts_root.is_dir():
        return
    for state_path in attempts_root.glob("*/state.json"):
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if state.get("status") in TERMINAL_STATES:
                continue
            state.update(
                {
                    "status": "interrupted",
                    "rc": 1,
                    "finished_at": now(),
                    "recovered_at": now(),
                    "runner_error": "stale_nonterminal_attempt_recovered",
                }
            )
            atomic_write_json(state_path, state)
        except Exception:
            continue


def scan_failure_log(path: Path) -> tuple[int, list[str]]:
    patterns = compile_patterns(DEFAULT_FAILURE_PATTERNS)
    ignore_patterns = compile_patterns(DEFAULT_IGNORE_PATTERNS)
    matches: deque[str] = deque(maxlen=80)
    count = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle, start=1):
            if is_failure_line(line, patterns, ignore_patterns):
                count += 1
                matches.append(f"{index}: {line.rstrip()}")
    return count, list(matches)


class CleanupUnproven(RuntimeError):
    pass


def read_process_identity(pid: int) -> dict[str, object] | None:
    try:
        raw = (Path("/proc") / str(pid) / "stat").read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CleanupUnproven(f"cannot inspect process {pid}") from exc
    closing = raw.rfind(")")
    if closing < 0:
        raise CleanupUnproven(f"invalid /proc stat for process {pid}")
    fields = raw[closing + 2 :].split()
    try:
        return {
            "pid": pid,
            "state": fields[0],
            "ppid": int(fields[1]),
            "pgid": int(fields[2]),
            "session_id": int(fields[3]),
            "starttime": int(fields[19]),
        }
    except (IndexError, ValueError) as exc:
        raise CleanupUnproven(f"invalid /proc stat for process {pid}") from exc


def same_process(
    current: dict[str, object] | None,
    expected: dict[str, object],
) -> bool:
    return bool(
        current
        and current.get("state") != "Z"
        and all(
            current.get(field) == expected.get(field)
            for field in ("pid", "pgid", "session_id", "starttime")
        )
    )


def set_child_subreaper() -> dict[str, object]:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    identity = read_process_identity(os.getpid())
    if identity is None:
        raise CleanupUnproven("cannot establish subreaper identity")
    return identity


def observe_descendant_scope(
    supervisor_identity: dict[str, object],
) -> tuple[str, list[dict[str, object]]]:
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return "unknown", []
    identities: dict[int, dict[str, object]] = {}
    try:
        process_dirs = list(proc_root.iterdir())
    except OSError:
        return "unknown", []
    unknown = False
    for process_dir in process_dirs:
        if not process_dir.name.isdigit():
            continue
        try:
            current = read_process_identity(int(process_dir.name))
        except CleanupUnproven:
            unknown = True
            continue
        if current is None:
            continue
        identities[int(current["pid"])] = current

    supervisor_pid = int(supervisor_identity["pid"])
    if not same_process(identities.get(supervisor_pid), supervisor_identity):
        return "unknown", []

    children: dict[int, list[dict[str, object]]] = {}
    for current in identities.values():
        if current.get("state") == "Z":
            continue
        children.setdefault(int(current["ppid"]), []).append(current)

    members: list[dict[str, object]] = []
    queue = deque([supervisor_pid])
    seen = {supervisor_pid}
    while queue:
        parent_pid = queue.popleft()
        for current in children.get(parent_pid, []):
            pid = int(current["pid"])
            if pid in seen:
                continue
            seen.add(pid)
            members.append(current)
            queue.append(pid)

    if unknown:
        return "unknown", members
    if members:
        return "live", members
    return "clear", []


def signal_process(pid: int, signum: int, expected_starttime: int) -> None:
    try:
        pidfd = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return
    try:
        current = read_process_identity(pid)
        if current is None or current.get("starttime") != expected_starttime:
            return
        try:
            signal.pidfd_send_signal(pidfd, signum)
        except ProcessLookupError:
            pass
    finally:
        os.close(pidfd)


def signal_descendant_scope(
    supervisor_identity: dict[str, object],
    signum: int,
) -> tuple[str, bool]:
    status, members = observe_descendant_scope(supervisor_identity)
    for member in members:
        signal_process(
            int(member["pid"]),
            signum,
            int(member["starttime"]),
        )
    return status, bool(members)


def signal_descendant_scope_when_observable(
    supervisor_identity: dict[str, object],
    signum: int,
) -> bool:
    signaled = False
    while True:
        status, found = signal_descendant_scope(supervisor_identity, signum)
        signaled = signaled or found
        if status == "clear":
            return signaled
        if status == "live":
            return signaled
        time.sleep(PROCESS_OBSERVATION_INTERVAL)


def reap_adopted_children() -> None:
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def prove_descendant_scope_clear(
    supervisor_identity: dict[str, object],
    *,
    reap_children: bool,
) -> bool:
    clear_observations = 0
    escalated = False
    while clear_observations < DESCENDANT_CLEAR_OBSERVATIONS:
        if reap_children:
            reap_adopted_children()
        status, _members = observe_descendant_scope(supervisor_identity)
        if status == "clear":
            clear_observations += 1
        else:
            clear_observations = 0
            escalated = (
                signal_descendant_scope_when_observable(
                    supervisor_identity,
                    signal.SIGKILL,
                )
                or escalated
            )
        if clear_observations < DESCENDANT_CLEAR_OBSERVATIONS:
            time.sleep(PROCESS_OBSERVATION_INTERVAL)
    if reap_children:
        reap_adopted_children()
    return escalated


def cleanup_descendant_scope(
    supervisor_identity: dict[str, object],
    *,
    reap_children: bool,
) -> bool:
    escalated = signal_descendant_scope_when_observable(
        supervisor_identity,
        signal.SIGKILL,
    )
    escalated = (
        prove_descendant_scope_clear(
            supervisor_identity,
            reap_children=reap_children,
        )
        or escalated
    )
    return escalated


def send_guardian_message(
    connection: Connection,
    message: dict[str, object],
) -> bool:
    try:
        connection.send(message)
    except (BrokenPipeError, EOFError, OSError):
        return False
    return True


def recover_attempt_after_runner_loss(
    state_path: str,
    process_rc: int | None,
    signal_escalated: bool,
) -> None:
    path = Path(state_path)
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        if state.get("status") in TERMINAL_STATES:
            return
        rc = normalized_rc(process_rc)
        state.update(
            {
                "status": "interrupted",
                "rc": rc or 1,
                "process_rc": process_rc,
                "finished_at": now(),
                "signal_escalated": signal_escalated,
                "runner_error": "runner_connection_lost_guardian_recovered",
            }
        )
        atomic_write_json(path, state)
    except Exception:
        pass


def lock_guardian_main(
    connection: Connection,
    command: list[str],
    executable: str,
    cwd: str,
    environment: dict[str, str],
    child_umask: int,
    log_path: str,
    state_path: str,
) -> int:
    os.setsid()
    guardian_identity: dict[str, object] | None = None
    child: subprocess.Popen[bytes] | None = None
    child_identity: dict[str, object] | None = None
    gate_write: int | None = None
    armed = False
    parent_connected = True
    escalated = False
    termination_requested = False
    signal_deadline: float | None = None
    try:
        guardian_identity = set_child_subreaper()
        with Path(log_path).open("wb") as log:
            gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
            try:
                child = subprocess.Popen(
                    [
                        sys.executable,
                        "-I",
                        "-c",
                        TRUSTED_BOOTSTRAP,
                        str(os.getpid()),
                        str(gate_read),
                        executable,
                        *command,
                    ],
                    cwd=cwd,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    shell=False,
                    close_fds=True,
                    pass_fds=(gate_read,),
                    process_group=0,
                    umask=child_umask,
                )
            except Exception as exc:
                os.close(gate_read)
                os.close(gate_write)
                gate_write = None
                send_guardian_message(
                    connection,
                    {
                        "event": "launch_error",
                        "error": f"{type(exc).__name__}: {exc}",
                    },
                )
                return 1
            os.close(gate_read)
            current = read_process_identity(child.pid)
            expected_session = os.getpid()
            if (
                current is None
                or current.get("pgid") != child.pid
                or current.get("session_id") != expected_session
            ):
                raise RuntimeError("trusted bootstrap identity mismatch")
            child_identity = {
                "pid": child.pid,
                "pgid": child.pid,
                "session_id": expected_session,
                "starttime": current["starttime"],
            }
            for signum in (signal.SIGINT, signal.SIGTERM):
                signal.signal(signum, signal.SIG_IGN)
            if not send_guardian_message(
                connection,
                {
                    "event": "prepared",
                    **child_identity,
                    "prepared_at": now(),
                },
            ):
                parent_connected = False
                os.close(gate_write)
                gate_write = None

            while child.poll() is None:
                if parent_connected and connection.poll(0.05):
                    try:
                        message = connection.recv()
                    except (EOFError, OSError):
                        parent_connected = False
                        message = {"action": "abort"}
                    action = message.get("action")
                    if action == "arm" and not armed:
                        try:
                            os.write(gate_write, b"1")
                        finally:
                            os.close(gate_write)
                            gate_write = None
                        armed = True
                        if not send_guardian_message(
                            connection,
                            {
                                "event": "started",
                                **child_identity,
                                "started_at": now(),
                            },
                        ):
                            parent_connected = False
                            signal_descendant_scope_when_observable(
                                guardian_identity,
                                signal.SIGTERM,
                            )
                            termination_requested = True
                            signal_deadline = (
                                time.monotonic() + SIGNAL_GRACE_SECONDS
                            )
                    elif action == "signal" and armed:
                        signum = int(message["signum"])
                        signal_descendant_scope_when_observable(
                            guardian_identity,
                            signum,
                        )
                        termination_requested = True
                        signal_deadline = (
                            time.monotonic() + SIGNAL_GRACE_SECONDS
                        )
                    elif action == "abort":
                        if not armed:
                            if gate_write is not None:
                                os.close(gate_write)
                                gate_write = None
                        else:
                            signal_descendant_scope_when_observable(
                                guardian_identity,
                                signal.SIGTERM,
                            )
                            termination_requested = True
                            signal_deadline = (
                                time.monotonic() + SIGNAL_GRACE_SECONDS
                            )
                elif not parent_connected and not termination_requested:
                    if not armed:
                        if gate_write is not None:
                            os.close(gate_write)
                            gate_write = None
                    else:
                        signal_descendant_scope_when_observable(
                            guardian_identity,
                            signal.SIGTERM,
                        )
                        termination_requested = True
                        signal_deadline = (
                            time.monotonic() + SIGNAL_GRACE_SECONDS
                        )

                if (
                    armed
                    and termination_requested
                    and signal_deadline is not None
                    and time.monotonic() >= signal_deadline
                ):
                    signal_descendant_scope_when_observable(
                        guardian_identity,
                        signal.SIGKILL,
                    )
                    escalated = True
                    signal_deadline = None

            process_rc = child.wait()
            reap_adopted_children()
            status, _members = observe_descendant_scope(guardian_identity)
            if status != "clear":
                escalated = (
                    signal_descendant_scope_when_observable(
                        guardian_identity,
                        signal.SIGKILL,
                    )
                    or escalated
                )
            escalated = (
                prove_descendant_scope_clear(
                    guardian_identity,
                    reap_children=True,
                )
                or escalated
            )
            if not parent_connected:
                recover_attempt_after_runner_loss(
                    state_path,
                    process_rc,
                    escalated,
                )
                return 0
            if not send_guardian_message(
                connection,
                {
                    "event": "finished",
                    "process_rc": process_rc,
                    "signal_escalated": escalated,
                },
            ):
                recover_attempt_after_runner_loss(
                    state_path,
                    process_rc,
                    escalated,
                )
                return 0
            while True:
                if not connection.poll(0.05):
                    continue
                try:
                    message = connection.recv()
                except (EOFError, OSError):
                    recover_attempt_after_runner_loss(
                        state_path,
                        process_rc,
                        escalated,
                    )
                    return 0
                action = message.get("action")
                if action == "release":
                    return 0
                if action == "abort":
                    recover_attempt_after_runner_loss(
                        state_path,
                        process_rc,
                        escalated,
                    )
                    return 0
    except Exception as exc:
        if gate_write is not None:
            try:
                os.close(gate_write)
            except OSError:
                pass
        if guardian_identity is not None:
            signal_descendant_scope_when_observable(
                guardian_identity,
                signal.SIGKILL,
            )
        if child is not None:
            try:
                child.wait(timeout=SIGNAL_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                pass
        if guardian_identity is not None:
            prove_descendant_scope_clear(
                guardian_identity,
                reap_children=True,
            )
        if parent_connected:
            send_guardian_message(
                connection,
                {
                    "event": "guardian_error",
                    "error": f"{type(exc).__name__}: {exc}",
                },
            )
        return 1
    finally:
        connection.close()


def spawn_lock_guardian(
    command: list[str],
    executable: str,
    cwd: str,
    environment: dict[str, str],
    child_umask: int,
    log_path: Path,
    state_path: Path,
) -> tuple[int, Connection]:
    parent_connection, guardian_connection = Pipe(duplex=True)
    guardian_pid = os.fork()
    if guardian_pid == 0:
        parent_connection.close()
        exit_code = lock_guardian_main(
            guardian_connection,
            command,
            executable,
            cwd,
            environment,
            child_umask,
            str(log_path),
            str(state_path),
        )
        os._exit(exit_code)
    guardian_connection.close()
    return guardian_pid, parent_connection


def guardian_has_exited(guardian_pid: int) -> tuple[bool, int | None]:
    waited_pid, status = os.waitpid(guardian_pid, os.WNOHANG)
    if waited_pid == 0:
        return False, None
    return True, os.waitstatus_to_exitcode(status)


def receive_guardian_message(
    connection: Connection,
    guardian_pid: int,
) -> dict[str, object]:
    while True:
        if connection.poll(0.05):
            try:
                message = connection.recv()
            except EOFError as exc:
                raise RuntimeError("lock_guardian_closed_without_result") from exc
            if not isinstance(message, dict):
                raise RuntimeError("lock_guardian_sent_invalid_message")
            return message
        exited, exit_code = guardian_has_exited(guardian_pid)
        if exited:
            raise RuntimeError(
                f"lock_guardian_exited_without_result: rc={exit_code}"
            )


def wait_for_guardian(
    connection: Connection,
    guardian_pid: int,
    interrupted: Callable[[], int | None],
) -> tuple[int, bool]:
    forwarded_signal: int | None = None
    while True:
        signum = interrupted()
        if signum is not None and signum != forwarded_signal:
            if not send_guardian_message(
                connection,
                {"action": "signal", "signum": signum},
            ):
                raise RuntimeError("lock_guardian_control_channel_closed")
            forwarded_signal = signum
        if connection.poll(0.05):
            try:
                message = connection.recv()
            except EOFError as exc:
                raise RuntimeError("lock_guardian_closed_without_result") from exc
            event = message.get("event")
            if event == "finished":
                return (
                    int(message["process_rc"]),
                    bool(message.get("signal_escalated")),
                )
            if event in {"launch_error", "guardian_error"}:
                _pid, status = os.waitpid(guardian_pid, 0)
                guardian_rc = os.waitstatus_to_exitcode(status)
                raise RuntimeError(
                    f"{message.get('error')}; lock_guardian_rc={guardian_rc}"
                )
            raise RuntimeError(f"unexpected_lock_guardian_event: {event}")
        exited, exit_code = guardian_has_exited(guardian_pid)
        if exited:
            raise RuntimeError(
                f"lock_guardian_exited_without_result: rc={exit_code}"
            )


def release_guardian(
    connection: Connection,
    guardian_pid: int,
) -> None:
    if not send_guardian_message(connection, {"action": "release"}):
        raise RuntimeError("lock_guardian_release_channel_closed")
    connection.close()
    _pid, status = os.waitpid(guardian_pid, 0)
    guardian_rc = os.waitstatus_to_exitcode(status)
    if guardian_rc != 0:
        raise RuntimeError(f"lock_guardian_release_failed: rc={guardian_rc}")


def stop_guardian(
    connection: Connection | None,
    guardian_pid: int | None,
    runner_identity: dict[str, object] | None,
) -> None:
    if connection is not None:
        send_guardian_message(connection, {"action": "abort"})
        connection.close()
    guardian_alive = guardian_pid is not None
    if guardian_pid is not None:
        deadline = time.monotonic() + (SIGNAL_GRACE_SECONDS * 2) + 1
        while time.monotonic() < deadline:
            try:
                exited, _exit_code = guardian_has_exited(guardian_pid)
            except ChildProcessError:
                guardian_alive = False
                break
            if exited:
                guardian_alive = False
                break
            time.sleep(0.05)
    if guardian_alive and guardian_pid is not None:
        try:
            os.kill(guardian_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(guardian_pid, 0)
        except ChildProcessError:
            pass
    if runner_identity is not None:
        cleanup_descendant_scope(
            runner_identity,
            reap_children=True,
        )


def normalized_rc(process_rc: int | None, failure_count: int = 0) -> int:
    if process_rc is None:
        return 1
    if process_rc < 0:
        return min(255, 128 + abs(process_rc))
    if process_rc == 0 and failure_count:
        return 1
    return min(255, process_rc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument(
        "--run-root",
        help="compatibility assertion; must equal the run root frozen in the Plan",
    )
    args = parser.parse_args(argv)

    state: dict[str, object] | None = None
    state_path: Path | None = None
    lock_handles: list[TextIO] = []
    previous_handlers: dict[int, object] = {}
    guardian_pid: int | None = None
    guardian_connection: Connection | None = None
    runner_identity: dict[str, object] | None = None
    child_identity: dict[str, object] | None = None
    child_pidfd: int | None = None
    process_rc: int | None = None
    signal_escalated = False
    interrupted_signal: int | None = None
    try:
        plan_path, plan, plan_sha256 = load_plan(Path(args.plan))
        plan_id = str(plan["plan_id"])
        execution = plan.get("execution", {})
        run_root = Path(str(execution.get("run_root", ""))).resolve()
        if args.run_root and Path(args.run_root).resolve() != run_root:
            raise ValueError("run_root_mismatch")
        for planned in plan.get("workspaces", {}).values():
            workspace_root = Path(str(planned["root"]))
            if run_root == workspace_root or run_root.is_relative_to(workspace_root):
                raise ValueError("evidence_inside_workspace")

        plan_root = run_root / "plans" / plan_id
        attempts_root = plan_root / "attempts"
        attempts_root.mkdir(parents=True, exist_ok=True)
        prepare_local_lock_root()
        lock_specs = [
            (
                Path(str(path)),
                "workspace_or_plan_already_running",
            )
            for path in execution.get("checkout_locks", [])
        ]
        lock_specs.append(
            (
                run_root / "locks" / f"plan-{plan_id}.lock",
                "workspace_or_plan_already_running",
            )
        )
        planned_output_resources = execution.get("output_resources", [])
        required_output_resources = expected_output_resources(plan)
        if planned_output_resources != required_output_resources:
            raise ValueError(
                "output_resource_lock_mismatch: "
                f"planned={planned_output_resources} "
                f"expected={required_output_resources}"
            )
        for expected_resource in required_output_resources:
            lock_specs.append(
                (
                    Path(expected_resource["lock_path"]),
                    "output_resource_already_running: "
                    f"{expected_resource['role']}={expected_resource['path']}",
                )
            )
        lock_handles = acquire_locks(lock_specs)
        recover_stale_attempts(attempts_root)
        workspaces_before = verify_workspaces(plan)
        input_locks_before = verify_input_locks(plan)

        attempt_id = uuid.uuid4().hex
        attempt_root = attempts_root / attempt_id
        attempt_root.mkdir(mode=0o700)
        state_path = attempt_root / "state.json"
        command_path = attempt_root / "command.json"
        log_path = attempt_root / "build.log"
        command = plan["command"]
        command_document = {
            "plan_id": plan_id,
            "plan_sha256": plan_sha256,
            "attempt_id": attempt_id,
            "cwd": command["cwd"],
            "argv": command["argv"],
            "source": command["source"],
            "executable": plan.get("runner", {}).get("executable", {}),
        }
        atomic_write_json(command_path, command_document)
        state = {
            "schema": "openubmc-build/attempt-v1",
            "plan_id": plan_id,
            "plan_path": str(plan_path),
            "plan_sha256": plan_sha256,
            "attempt_id": attempt_id,
            "status": "prepared",
            "prepared_at": now(),
            "command_path": str(command_path),
            "log_path": str(log_path),
            "rc": None,
            "process_rc": None,
            "workspaces_before": workspaces_before,
            "input_locks_before": input_locks_before,
            "outputs_before": snapshot_outputs(plan),
        }
        atomic_write_json(state_path, state)

        def handle_signal(signum: int, _frame: object) -> None:
            nonlocal interrupted_signal
            if interrupted_signal is None:
                interrupted_signal = signum

        previous_handlers = {
            signum: signal.signal(signum, handle_signal)
            for signum in (signal.SIGINT, signal.SIGTERM)
        }

        environment = os.environ.copy()
        planned_environment = plan.get("environment", {})
        environment["PATH"] = str(
            planned_environment.get("PATH", environment.get("PATH", ""))
        )
        if planned_environment.get("community"):
            environment["OPENUBMC_COMMUNITY_NAME"] = str(
                planned_environment["community"]
            )
        if planned_environment.get("conan_home"):
            environment["CONAN_HOME"] = str(planned_environment["conan_home"])

        state["launch_requested_at"] = now()
        atomic_write_json(state_path, state)
        runner_identity = set_child_subreaper()
        guardian_pid, guardian_connection = spawn_lock_guardian(
            list(command["argv"]),
            str(plan.get("runner", {}).get("executable", {}).get("path")),
            str(command["cwd"]),
            environment,
            int(str(planned_environment.get("umask", "022")), 8),
            log_path,
            state_path,
        )
        prepared = receive_guardian_message(guardian_connection, guardian_pid)
        if prepared.get("event") != "prepared":
            try:
                _pid, guardian_status = os.waitpid(guardian_pid, 0)
                guardian_rc = os.waitstatus_to_exitcode(guardian_status)
            except ChildProcessError:
                guardian_rc = 1
            guardian_pid = None
            raise RuntimeError(
                f"{prepared.get('error', 'lock guardian failed before prepare')}; "
                f"lock_guardian_rc={guardian_rc}"
            )
        child_identity = {
            field: int(prepared[field])
            for field in ("pid", "pgid", "session_id", "starttime")
        }
        current_child = read_process_identity(int(child_identity["pid"]))
        if not same_process(current_child, child_identity):
            raise RuntimeError("trusted bootstrap identity drift before arm")
        child_pidfd = os.pidfd_open(int(child_identity["pid"]), 0)
        state.update(
            {
                "launch_prepared_at": prepared["prepared_at"],
                "cleanup_identity": child_identity,
                "lock_guardian_pid": guardian_pid,
            }
        )
        atomic_write_json(state_path, state)
        if interrupted_signal is not None:
            send_guardian_message(guardian_connection, {"action": "abort"})
            raise RuntimeError("attempt interrupted before command arm")
        if not send_guardian_message(guardian_connection, {"action": "arm"}):
            raise RuntimeError("lock_guardian_arm_channel_closed")
        started = receive_guardian_message(guardian_connection, guardian_pid)
        if started.get("event") != "started":
            raise RuntimeError(
                str(started.get("error", "lock guardian failed during arm"))
            )
        if any(
            int(started[field]) != int(child_identity[field])
            for field in ("pid", "pgid", "session_id", "starttime")
        ):
            raise RuntimeError("trusted bootstrap identity drift at start")
        state.update(
            {
                "status": "running",
                "started_at": started["started_at"],
                "pid": int(child_identity["pid"]),
                "pgid": int(child_identity["pgid"]),
                "session_id": int(child_identity["session_id"]),
                "starttime": int(child_identity["starttime"]),
            }
        )
        atomic_write_json(state_path, state)
        process_rc, signal_escalated = wait_for_guardian(
            guardian_connection,
            guardian_pid,
            lambda: interrupted_signal,
        )
        if process_rc == 126:
            launch_error = log_path.read_text(
                encoding="utf-8",
                errors="replace",
            ).strip()
            if launch_error.startswith("ERROR guardian bootstrap"):
                process_rc = None
                raise RuntimeError(launch_error)

        failure_count, failure_log_lines = scan_failure_log(log_path)
        outputs_after = snapshot_outputs(plan)
        input_locks_after: dict[str, dict[str, object]] = {}
        input_lock_drift: dict[str, dict[str, object]] = {}
        for name, planned in plan.get("locks", {}).items():
            try:
                current_lock = file_identity(Path(str(planned["path"])))
            except Exception as exc:
                current_lock = {"error": f"{type(exc).__name__}: {exc}"}
                lock_drift = {
                    "identity": {
                        "planned": "frozen input file identity",
                        "current": current_lock["error"],
                    }
                }
            else:
                lock_drift = compare_file_identity(planned, current_lock)
            input_locks_after[name] = current_lock
            if lock_drift:
                input_lock_drift[name] = lock_drift
        workspaces_after: dict[str, dict[str, object]] = {}
        workspace_drift: dict[str, dict[str, object]] = {}
        for name, planned in plan.get("workspaces", {}).items():
            mutable_paths = tuple(str(item) for item in planned.get("mutable_paths", []))
            try:
                current = workspace_identity(Path(planned["root"]), mutable_paths)
            except Exception as exc:
                current = {"error": f"{type(exc).__name__}: {exc}"}
                drift = {
                    "identity": {
                        "planned": "bound workspace identity",
                        "current": current["error"],
                    }
                }
            else:
                drift = compare_workspace_identity(planned, current)
            workspaces_after[name] = current
            if drift:
                workspace_drift[name] = drift
        contamination = sorted(workspace_drift)
        rc = normalized_rc(process_rc, failure_count)
        if interrupted_signal is not None:
            status = (
                "cancelled"
                if interrupted_signal == signal.SIGINT
                else "interrupted"
            )
        elif contamination or input_lock_drift or signal_escalated:
            status = "failed"
            rc = rc or 1
        else:
            status = "succeeded" if rc == 0 else "failed"
        state.update(
            {
                "status": status,
                "rc": rc,
                "process_rc": process_rc,
                "failure_log_count": failure_count,
                "failure_log_lines": failure_log_lines,
                "workspace_contamination": contamination,
                "workspace_drift": workspace_drift,
                "workspaces_after": workspaces_after,
                "input_lock_drift": input_lock_drift,
                "input_locks_after": input_locks_after,
                "outputs_after": outputs_after,
                "finished_at": now(),
                "signal": interrupted_signal,
                "signal_escalated": signal_escalated,
            }
        )
        atomic_write_json(state_path, state)
        release_guardian(guardian_connection, guardian_pid)
        guardian_connection = None
        guardian_pid = None
        child_identity = None
        runner_identity = None
        if child_pidfd is not None:
            os.close(child_pidfd)
            child_pidfd = None

        result = {
            "plan_id": plan_id,
            "attempt_id": attempt_id,
            "status": state["status"],
            "rc": state["rc"],
            "attempt_root": str(attempt_root),
            "state_path": str(state_path),
            "command_path": str(command_path),
            "log_path": str(log_path),
        }
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if state["status"] == "succeeded" else int(state["rc"] or 1)
    except Exception as exc:
        if (
            state is not None
            and state_path is not None
            and state.get("status") not in TERMINAL_STATES
        ):
            state.update(
                {
                    "status": "interrupted" if interrupted_signal else "failed",
                    "rc": normalized_rc(process_rc),
                    "process_rc": process_rc,
                    "finished_at": now(),
                    "signal": interrupted_signal,
                    "runner_error": f"{type(exc).__name__}: {exc}",
                }
            )
            try:
                atomic_write_json(state_path, state)
            except Exception:
                pass
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        stop_guardian(guardian_connection, guardian_pid, runner_identity)
        if child_pidfd is not None:
            os.close(child_pidfd)
        release_locks(lock_handles)
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
