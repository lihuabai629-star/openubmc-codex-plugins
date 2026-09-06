#!/usr/bin/env python3
"""Shared SSH helpers for openUBMC remote scripts."""
from __future__ import annotations

import locale
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, List

ENV_RE = re.compile(r"^(DBUS_SESSION_BUS_ADDRESS|XDG_RUNTIME_DIR)=(.*)$")
HOST_KEY_RE = re.compile(
    r"Warning: Permanently added '.*?' \([^)]+\) to the list of known hosts\.\s*",
    re.DOTALL,
)
LEGAL_BANNER_RE = re.compile(
    r"WARNING! This system is PRIVATE and PROPRIETARY.*?law enforcement and other purposes\.\s*",
    re.DOTALL,
)
DEBUG_SHELL_RE = re.compile(
    r"\*{10,}\s*Debug Shell\s*Copyright\(C\) 2023\s*\*{10,}\s*",
    re.DOTALL,
)
NOISE_MARKERS = (
    "bash: can't access tty; job control turned off",
)
SSH_HOST_KEY_POLICY_ENV = "OPENUBMC_SSH_HOST_KEY_POLICY"
SSH_KNOWN_HOSTS_FILE_ENV = "OPENUBMC_SSH_KNOWN_HOSTS_FILE"
DEFAULT_SSH_HOST_KEY_POLICY = "insecure"
SSH_OUTPUT_LIMIT_RETURN_CODE = 125
SSH_OUTPUT_LIMIT_CODE = "ssh_output_limit_exceeded"
SSH_CAPTURE_ERROR_RETURN_CODE = 126
SSH_CAPTURE_ERROR_CODE = "ssh_transport_capture_failed"
SSH_CLIENT_MISSING_RETURN_CODE = 127
SSH_CLIENT_MISSING_CODE = "ssh_client_missing"
SSH_HOST_KEY_POLICY_ERROR_RETURN_CODE = 126
SSH_HOST_KEY_POLICY_ERROR_CODE = "ssh_host_key_policy_invalid"
SSH_HOST_KEY_FAILURE_CODE = "ssh_host_key_verification_failed"
SSH_INSECURE_HOST_KEY_WARNING = "ssh_host_key_verification_disabled"
DBUS_ENV_STDOUT_LIMIT_BYTES = 64 * 1024
DBUS_ENV_STDERR_LIMIT_BYTES = 64 * 1024
_CAPTURE_CHUNK_BYTES = 64 * 1024
_HOST_KEY_FAILURE_MARKERS = (
    "host key verification failed",
    "remote host identification has changed",
    "no ed25519 host key is known for",
    "no ecdsa host key is known for",
    "no rsa host key is known for",
    "offending ",
)


class SshHostKeyPolicyError(ValueError):
    """A host-key policy request was invalid."""

    def __init__(
        self,
        message: str,
        *,
        audit: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = SSH_HOST_KEY_POLICY_ERROR_CODE
        self.audit = audit or {}


class DbusEnvironment(dict[str, str]):
    """Dictionary-compatible D-Bus environment with safe transport metadata."""

    def __init__(
        self,
        *args,
        transport: dict[str, object] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.transport = transport or {}


def ssh_output_limit_exceeded(completed: subprocess.CompletedProcess[str]) -> bool:
    return bool(
        getattr(completed, "output_limit_exceeded", False)
        or getattr(completed, "stdout_limit_exceeded", False)
        or getattr(completed, "stderr_limit_exceeded", False)
    )


def ssh_capture_failed(completed: subprocess.CompletedProcess[str]) -> bool:
    return bool(getattr(completed, "capture_failed", False))


def ssh_transport_failure_code(
    completed: subprocess.CompletedProcess[str],
) -> str:
    if bool(getattr(completed, "ssh_client_missing", False)):
        return SSH_CLIENT_MISSING_CODE
    if bool(getattr(completed, "host_key_policy_invalid", False)):
        return SSH_HOST_KEY_POLICY_ERROR_CODE
    if bool(getattr(completed, "host_key_verification_failed", False)):
        return SSH_HOST_KEY_FAILURE_CODE
    if ssh_output_limit_exceeded(completed):
        return SSH_OUTPUT_LIMIT_CODE
    if ssh_capture_failed(completed):
        return SSH_CAPTURE_ERROR_CODE
    return ""


def ssh_transport_details(
    completed: subprocess.CompletedProcess[str],
) -> dict[str, object]:
    return {
        "failure_code": ssh_transport_failure_code(completed),
        "returncode": completed.returncode,
        "timed_out": bool(getattr(completed, "timed_out", False)),
        "ssh_client_missing": bool(
            getattr(completed, "ssh_client_missing", False)
        ),
        "host_key_verification_failed": bool(
            getattr(completed, "host_key_verification_failed", False)
        ),
        "host_key_policy_invalid": bool(
            getattr(completed, "host_key_policy_invalid", False)
        ),
        "host_key_policy": str(
            getattr(completed, "ssh_host_key_policy", DEFAULT_SSH_HOST_KEY_POLICY)
        ),
        "host_key_policy_source": str(
            getattr(completed, "ssh_host_key_policy_source", "default")
        ),
        "known_hosts_source": str(
            getattr(completed, "ssh_known_hosts_source", "ssh_default")
        ),
        "warnings": list(getattr(completed, "ssh_transport_warnings", [])),
        "output_limit_exceeded": ssh_output_limit_exceeded(completed),
        "capture_failed": ssh_capture_failed(completed),
        "stdout": {
            "limit_bytes": getattr(completed, "stdout_limit_bytes", None),
            "limit_exceeded": bool(
                getattr(completed, "stdout_limit_exceeded", False)
            ),
            "bytes_read": int(getattr(completed, "stdout_bytes_read", 0)),
            "bytes_captured": int(
                getattr(completed, "stdout_bytes_captured", 0)
            ),
            "read_error": bool(getattr(completed, "stdout_read_error", False)),
        },
        "stderr": {
            "limit_bytes": getattr(completed, "stderr_limit_bytes", None),
            "limit_exceeded": bool(
                getattr(completed, "stderr_limit_exceeded", False)
            ),
            "bytes_read": int(getattr(completed, "stderr_bytes_read", 0)),
            "bytes_captured": int(
                getattr(completed, "stderr_bytes_captured", 0)
            ),
            "read_error": bool(getattr(completed, "stderr_read_error", False)),
        },
    }


def ssh_transport_failure_message(code: str, context: str = "SSH command") -> str:
    messages = {
        SSH_CLIENT_MISSING_CODE: (
            "The required local ssh executable is unavailable; route environment "
            "preparation to openubmc-environment-setup"
        ),
        SSH_HOST_KEY_FAILURE_CODE: (
            "SSH host-key verification failed; verify the target key and the "
            "configured known-hosts source before retrying"
        ),
        SSH_HOST_KEY_POLICY_ERROR_CODE: (
            "SSH host-key policy is invalid or insecure verification was not "
            "explicitly authorized"
        ),
        SSH_OUTPUT_LIMIT_CODE: (
            f"SSH output exceeded the configured byte limit during {context}"
        ),
        SSH_CAPTURE_ERROR_CODE: f"SSH output capture failed during {context}",
    }
    return messages.get(code, f"{context} failed")


def _validate_output_limit(name: str, value: int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer or None")
    return value


def _bounded_utf8_text(text: str, limit_bytes: int | None) -> str:
    if limit_bytes is None:
        return text
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit_bytes:
        return text
    return encoded[:limit_bytes].decode("utf-8", errors="ignore")


def _attach_capture_metadata(
    completed: subprocess.CompletedProcess[str],
    *,
    stdout_limit_bytes: int | None,
    stderr_limit_bytes: int | None,
    stdout_limit_exceeded: bool = False,
    stderr_limit_exceeded: bool = False,
    stdout_bytes_read: int = 0,
    stderr_bytes_read: int = 0,
    stdout_bytes_captured: int = 0,
    stderr_bytes_captured: int = 0,
    stdout_read_error: bool = False,
    stderr_read_error: bool = False,
    timed_out: bool = False,
) -> subprocess.CompletedProcess[str]:
    completed.stdout_limit_bytes = stdout_limit_bytes
    completed.stderr_limit_bytes = stderr_limit_bytes
    completed.stdout_limit_exceeded = stdout_limit_exceeded
    completed.stderr_limit_exceeded = stderr_limit_exceeded
    completed.output_limit_exceeded = bool(
        stdout_limit_exceeded or stderr_limit_exceeded
    )
    completed.stdout_bytes_read = stdout_bytes_read
    completed.stderr_bytes_read = stderr_bytes_read
    completed.stdout_bytes_captured = stdout_bytes_captured
    completed.stderr_bytes_captured = stderr_bytes_captured
    completed.stdout_read_error = stdout_read_error
    completed.stderr_read_error = stderr_read_error
    completed.capture_failed = bool(stdout_read_error or stderr_read_error)
    completed.timed_out = timed_out
    return completed


def _read_bounded_stream(
    stream: BinaryIO,
    limit_bytes: int | None,
    state: dict[str, object],
    process: subprocess.Popen[bytes],
    kill_lock: threading.Lock,
) -> None:
    chunks: list[bytes] = []
    bytes_read = 0
    bytes_captured = 0
    try:
        read_chunk = getattr(stream, "read1", stream.read)
        while True:
            chunk = read_chunk(_CAPTURE_CHUNK_BYTES)
            if not chunk:
                break
            bytes_read += len(chunk)
            if limit_bytes is None:
                chunks.append(chunk)
                bytes_captured += len(chunk)
                continue
            remaining = max(0, limit_bytes - bytes_captured)
            if remaining:
                kept = chunk[:remaining]
                chunks.append(kept)
                bytes_captured += len(kept)
            if len(chunk) > remaining:
                state["limit_exceeded"] = True
                with kill_lock:
                    if process.poll() is None:
                        process.kill()
                break
    except (OSError, ValueError) as exc:
        state["read_error"] = str(exc)
    finally:
        try:
            stream.close()
        except OSError:
            pass
        state["content"] = b"".join(chunks)
        state["bytes_read"] = bytes_read
        state["bytes_captured"] = bytes_captured


def _run_bounded_process(
    cmd: list[str],
    *,
    timeout: float,
    env: dict[str, str] | None,
    stdout_limit_bytes: int | None,
    stderr_limit_bytes: int | None,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    stdout_state: dict[str, object] = {"limit_exceeded": False}
    stderr_state: dict[str, object] = {"limit_exceeded": False}
    kill_lock = threading.Lock()
    readers = [
        threading.Thread(
            target=_read_bounded_stream,
            args=(
                process.stdout,
                stdout_limit_bytes,
                stdout_state,
                process,
                kill_lock,
            ),
            daemon=True,
        ),
        threading.Thread(
            target=_read_bounded_stream,
            args=(
                process.stderr,
                stderr_limit_bytes,
                stderr_state,
                process,
                kill_lock,
            ),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()

    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        with kill_lock:
            if process.poll() is None:
                process.kill()
        process.wait()
    for reader in readers:
        reader.join()

    encoding = locale.getpreferredencoding(False) or "utf-8"
    stdout_bytes = bytes(stdout_state.get("content", b""))
    stderr_bytes = bytes(stderr_state.get("content", b""))
    stdout = stdout_bytes.decode(encoding, errors="replace")
    stderr = stderr_bytes.decode(encoding, errors="replace")
    stdout_limit_exceeded = bool(stdout_state.get("limit_exceeded", False))
    stderr_limit_exceeded = bool(stderr_state.get("limit_exceeded", False))
    stdout_read_error = bool(stdout_state.get("read_error"))
    stderr_read_error = bool(stderr_state.get("read_error"))
    if stdout_limit_exceeded or stderr_limit_exceeded:
        returncode = SSH_OUTPUT_LIMIT_RETURN_CODE
    elif timed_out:
        returncode = 124
        timeout_message = f"SSH command timed out after {timeout}s"
        stderr = f"{stderr}\n{timeout_message}".strip()
    elif stdout_read_error or stderr_read_error:
        returncode = SSH_CAPTURE_ERROR_RETURN_CODE
    else:
        returncode = int(process.returncode or 0)

    completed = subprocess.CompletedProcess(
        args=cmd,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )
    return _attach_capture_metadata(
        completed,
        stdout_limit_bytes=stdout_limit_bytes,
        stderr_limit_bytes=stderr_limit_bytes,
        stdout_limit_exceeded=stdout_limit_exceeded,
        stderr_limit_exceeded=stderr_limit_exceeded,
        stdout_bytes_read=int(stdout_state.get("bytes_read", 0)),
        stderr_bytes_read=int(stderr_state.get("bytes_read", 0)),
        stdout_bytes_captured=int(stdout_state.get("bytes_captured", 0)),
        stderr_bytes_captured=int(stderr_state.get("bytes_captured", 0)),
        stdout_read_error=stdout_read_error,
        stderr_read_error=stderr_read_error,
        timed_out=timed_out,
    )


def resolve_ssh_host_key_config(
    policy: str = "",
    known_hosts_file: str = "",
    *,
    allow_insecure: bool = False,
) -> dict[str, object]:
    del allow_insecure
    explicit_policy = bool(policy.strip())
    environment_policy = os.environ.get(SSH_HOST_KEY_POLICY_ENV, "").strip()
    selected = (
        policy
        or environment_policy
        or DEFAULT_SSH_HOST_KEY_POLICY
    ).strip().lower()
    policy_source = (
        "explicit_argument"
        if explicit_policy
        else "environment"
        if environment_policy
        else "default"
    )
    explicit_known_hosts = bool(known_hosts_file.strip())
    environment_known_hosts = os.environ.get(
        SSH_KNOWN_HOSTS_FILE_ENV, ""
    ).strip()
    known_hosts = (known_hosts_file or environment_known_hosts).strip()
    known_hosts_source = (
        "explicit_argument"
        if explicit_known_hosts
        else "environment"
        if environment_known_hosts
        else "ssh_default"
    )
    warnings: list[str] = []
    if selected == "strict":
        options = ["-o", "StrictHostKeyChecking=yes"]
    elif selected == "accept-new":
        options = ["-o", "StrictHostKeyChecking=accept-new"]
    elif selected == "insecure":
        options = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
        known_hosts_source = "disabled"
        warnings.append(SSH_INSECURE_HOST_KEY_WARNING)
    else:
        raise SshHostKeyPolicyError(
            f"invalid SSH host key policy {selected!r}; expected strict, accept-new, or insecure",
            audit={
                "policy": selected,
                "policy_source": policy_source,
                "known_hosts_source": known_hosts_source,
                "warnings": [],
            },
        )
    if known_hosts and selected != "insecure":
        options += ["-o", f"UserKnownHostsFile={known_hosts}"]
    return {
        "policy": selected,
        "policy_source": policy_source,
        "known_hosts_source": known_hosts_source,
        "_known_hosts_file": known_hosts,
        "options": options,
        "warnings": warnings,
    }


def build_ssh_host_key_options(
    policy: str = "",
    known_hosts_file: str = "",
    *,
    allow_insecure: bool = False,
) -> list[str]:
    config = resolve_ssh_host_key_config(
        policy,
        known_hosts_file,
        allow_insecure=allow_insecure,
    )
    return list(config["options"])


def _attach_ssh_transport_metadata(
    completed: subprocess.CompletedProcess[str],
    *,
    host_key_config: dict[str, object] | None = None,
    ssh_client_missing: bool = False,
    host_key_policy_invalid: bool = False,
) -> subprocess.CompletedProcess[str]:
    config = host_key_config or {
        "policy": DEFAULT_SSH_HOST_KEY_POLICY,
        "policy_source": "default",
        "known_hosts_source": "ssh_default",
        "warnings": [],
    }
    completed.ssh_client_missing = ssh_client_missing
    completed.host_key_policy_invalid = host_key_policy_invalid
    completed.ssh_host_key_policy = str(config.get("policy", DEFAULT_SSH_HOST_KEY_POLICY))
    completed.ssh_host_key_policy_source = str(
        config.get("policy_source", "default")
    )
    completed.ssh_known_hosts_source = str(
        config.get("known_hosts_source", "ssh_default")
    )
    completed.ssh_transport_warnings = list(config.get("warnings", []))
    lowered = f"{completed.stderr or ''}\n{completed.stdout or ''}".lower()
    completed.host_key_verification_failed = any(
        marker in lowered for marker in _HOST_KEY_FAILURE_MARKERS
    )
    return completed


class SshControlMasterOpenError(RuntimeError):
    """Raised when the task-owned OpenSSH master cannot be established."""

    def __init__(self, completed: subprocess.CompletedProcess[str]) -> None:
        message = sanitize_remote_text(completed.stderr or completed.stdout or "")
        super().__init__(message or "OpenSSH ControlMaster could not be established")
        self.completed = completed


@dataclass
class SshControlMasterHandle:
    """Private process handle; local paths and credentials are never serialized."""

    host: str
    user: str
    port: int
    control_path: str = field(repr=False)
    host_key_config: dict[str, object] = field(repr=False)
    tempdir: tempfile.TemporaryDirectory[str] = field(repr=False)
    closed: bool = False

    @property
    def destination(self) -> str:
        return f"{self.user}@{self.host}"


class OpenSshControlMasterTransport:
    """OpenSSH ControlMaster adapter for the canonical Runtime SSH lane."""

    def __init__(
        self,
        *,
        host_key_policy: str = "",
        known_hosts_file: str = "",
        allow_insecure_host_key: bool = False,
        persist_seconds: int = 60,
        connect_timeout: float = 15.0,
        debug_dumper=None,
        debug_label_prefix: str = "ssh_master",
    ) -> None:
        if persist_seconds < 1:
            raise ValueError("persist_seconds must be positive")
        if connect_timeout <= 0:
            raise ValueError("connect_timeout must be positive")
        self.host_key_policy = host_key_policy
        self.known_hosts_file = known_hosts_file
        self.allow_insecure_host_key = allow_insecure_host_key
        self.persist_seconds = persist_seconds
        self.connect_timeout = connect_timeout
        self.debug_dumper = debug_dumper
        self.debug_label_prefix = debug_label_prefix

    @staticmethod
    def _policy_from_target(target) -> str:
        policy = getattr(target, "policy", None)
        return str(getattr(policy, "ssh_host_key_policy", "") or "")

    def _bound_host_key_config(self, target) -> dict[str, object]:
        return resolve_ssh_host_key_config(
            self.host_key_policy or self._policy_from_target(target),
            self.known_hosts_file,
            allow_insecure=self.allow_insecure_host_key,
        )

    def validate_channel_options(
        self,
        *,
        target,
        host_key_policy: str,
        known_hosts_file: str,
        allow_insecure_host_key: bool,
    ) -> None:
        configured = self._bound_host_key_config(target)
        requested = resolve_ssh_host_key_config(
            host_key_policy
            or self.host_key_policy
            or self._policy_from_target(target),
            known_hosts_file or self.known_hosts_file,
            allow_insecure=(
                allow_insecure_host_key or self.allow_insecure_host_key
            ),
        )
        comparable_fields = (
            "policy",
            "known_hosts_source",
            "_known_hosts_file",
            "options",
        )
        if any(
            requested.get(field_name) != configured.get(field_name)
            for field_name in comparable_fields
        ):
            raise ValueError(
                "SSH channel host-key options do not match the bound SSH lease"
            )

    @staticmethod
    def _connection_prefix(
        *,
        port: int,
        host_key_config: dict[str, object],
    ) -> list[str]:
        return [
            "ssh",
            "-p",
            str(port),
            *list(host_key_config["options"]),
            "-o",
            "LogLevel=ERROR",
        ]

    @staticmethod
    def _attach_mode(
        completed: subprocess.CompletedProcess[str],
        mode: str,
    ) -> subprocess.CompletedProcess[str]:
        completed.ssh_connection_mode = mode
        return completed

    def _write_debug_command(
        self,
        dumper,
        label: str,
        command: list[str],
        *,
        remote_command: str,
        stdout_limit_bytes: int | None,
        stderr_limit_bytes: int | None,
        host_key_config: dict[str, object],
    ) -> None:
        if dumper is None:
            return
        dumper.write_text(
            label,
            "command",
            " ".join(shlex.quote(part) for part in command),
            metadata={
                "stage": label,
                "artifact": "command",
                "transport": "ssh",
                "connection_mode": "control-master-channel",
                "command_summary": remote_command,
                "stdout_limit_bytes": stdout_limit_bytes,
                "stderr_limit_bytes": stderr_limit_bytes,
                "host_key_policy": host_key_config["policy"],
                "host_key_policy_source": host_key_config["policy_source"],
                "known_hosts_source": host_key_config["known_hosts_source"],
                "warnings": host_key_config["warnings"],
            },
        )

    def open_master(self, *, target, credentials) -> SshControlMasterHandle:
        try:
            host_key_config = self._bound_host_key_config(target)
        except SshHostKeyPolicyError as exc:
            completed = subprocess.CompletedProcess(
                args=[],
                returncode=SSH_HOST_KEY_POLICY_ERROR_RETURN_CODE,
                stdout="",
                stderr=str(exc),
            )
            completed = _attach_capture_metadata(
                completed,
                stdout_limit_bytes=None,
                stderr_limit_bytes=None,
            )
            completed = _attach_ssh_transport_metadata(
                completed,
                host_key_config=exc.audit,
                host_key_policy_invalid=True,
            )
            raise SshControlMasterOpenError(completed) from exc

        tempdir = tempfile.TemporaryDirectory(prefix="openubmc-ssh-master-")
        handle = SshControlMasterHandle(
            host=str(target.host),
            user=str(credentials.user),
            port=int(target.ssh_port),
            control_path=str(Path(tempdir.name) / "master.sock"),
            host_key_config=host_key_config,
            tempdir=tempdir,
        )
        command: list[str] = []
        password = str(credentials.password)
        if password:
            command += ["sshpass", "-e"]
        command += self._connection_prefix(
            port=handle.port,
            host_key_config=host_key_config,
        )
        identity_file = str(credentials.identity_file)
        if identity_file:
            command += ["-i", identity_file, "-o", "IdentitiesOnly=yes"]
        elif not password:
            command += ["-o", "BatchMode=yes"]
        command += [
            "-M",
            "-N",
            "-f",
            "-o",
            "ControlMaster=yes",
            "-o",
            f"ControlPersist={self.persist_seconds}",
            "-o",
            f"ControlPath={handle.control_path}",
            handle.destination,
        ]
        run_env = None
        if password:
            run_env = dict(os.environ)
            run_env["SSHPASS"] = password
        if not shutil.which("ssh"):
            completed = subprocess.CompletedProcess(
                args=command,
                returncode=SSH_CLIENT_MISSING_RETURN_CODE,
                stdout="",
                stderr=(
                    "ssh executable is unavailable; route environment preparation "
                    "to openubmc-environment-setup"
                ),
            )
            completed = _attach_capture_metadata(
                completed,
                stdout_limit_bytes=None,
                stderr_limit_bytes=None,
            )
            completed = _attach_ssh_transport_metadata(
                completed,
                host_key_config=host_key_config,
                ssh_client_missing=True,
            )
            tempdir.cleanup()
            raise SshControlMasterOpenError(completed)
        if password and not shutil.which("sshpass"):
            completed = subprocess.CompletedProcess(
                args=command,
                returncode=127,
                stdout="",
                stderr="sshpass not found; install it or use key-based authentication",
            )
            completed = _attach_capture_metadata(
                completed,
                stdout_limit_bytes=None,
                stderr_limit_bytes=None,
            )
            completed = _attach_ssh_transport_metadata(
                completed,
                host_key_config=host_key_config,
            )
            tempdir.cleanup()
            raise SshControlMasterOpenError(completed)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.connect_timeout,
                env=run_env,
            )
            completed = _attach_capture_metadata(
                completed,
                stdout_limit_bytes=None,
                stderr_limit_bytes=None,
                stdout_bytes_read=len((completed.stdout or "").encode("utf-8")),
                stderr_bytes_read=len((completed.stderr or "").encode("utf-8")),
                stdout_bytes_captured=len((completed.stdout or "").encode("utf-8")),
                stderr_bytes_captured=len((completed.stderr or "").encode("utf-8")),
            )
        except subprocess.TimeoutExpired:
            completed = subprocess.CompletedProcess(
                args=command,
                returncode=124,
                stdout="",
                stderr=(
                    "SSH ControlMaster authentication timed out after "
                    f"{self.connect_timeout}s"
                ),
            )
            completed = _attach_capture_metadata(
                completed,
                stdout_limit_bytes=None,
                stderr_limit_bytes=None,
                timed_out=True,
            )
        completed = _attach_ssh_transport_metadata(
            completed,
            host_key_config=host_key_config,
        )
        completed = self._attach_mode(completed, "control-master-authentication")
        if completed.returncode != 0 or not self.check_master(handle):
            self.close_master(handle)
            raise SshControlMasterOpenError(completed)
        return handle

    def _control_command(
        self,
        handle: SshControlMasterHandle,
        operation: str,
    ) -> list[str]:
        return [
            *self._connection_prefix(
                port=handle.port,
                host_key_config=handle.host_key_config,
            ),
            "-o",
            f"ControlPath={handle.control_path}",
            "-O",
            operation,
            handle.destination,
        ]

    def check_master(self, master: SshControlMasterHandle) -> bool:
        if master.closed or not Path(master.control_path).exists():
            return False
        try:
            completed = subprocess.run(
                self._control_command(master, "check"),
                capture_output=True,
                text=True,
                timeout=min(self.connect_timeout, 2.0),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        return completed.returncode == 0

    def run_channel(
        self,
        master: SshControlMasterHandle,
        remote_command: str,
        *,
        timeout: float,
        tty: bool = False,
        stdout_limit_bytes: int | None = None,
        stderr_limit_bytes: int | None = None,
        debug_dumper=None,
        debug_label: str = "ssh",
    ) -> subprocess.CompletedProcess[str]:
        stdout_limit_bytes = _validate_output_limit(
            "stdout_limit_bytes", stdout_limit_bytes
        )
        stderr_limit_bytes = _validate_output_limit(
            "stderr_limit_bytes", stderr_limit_bytes
        )
        command = [
            *self._connection_prefix(
                port=master.port,
                host_key_config=master.host_key_config,
            ),
            "-o",
            f"ControlPath={master.control_path}",
            "-o",
            "ControlMaster=no",
            "-o",
            "BatchMode=yes",
            "-o",
            "NumberOfPasswordPrompts=0",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "HostbasedAuthentication=no",
            "-o",
            "GSSAPIAuthentication=no",
        ]
        if tty:
            command.append("-tt")
        command += [master.destination, remote_command]
        dumper = debug_dumper if debug_dumper is not None else self.debug_dumper
        label = debug_label or self.debug_label_prefix
        self._write_debug_command(
            dumper,
            label,
            command,
            remote_command=remote_command,
            stdout_limit_bytes=stdout_limit_bytes,
            stderr_limit_bytes=stderr_limit_bytes,
            host_key_config=master.host_key_config,
        )
        if not shutil.which("ssh"):
            completed = subprocess.CompletedProcess(
                args=command,
                returncode=SSH_CLIENT_MISSING_RETURN_CODE,
                stdout="",
                stderr=(
                    "ssh executable is unavailable; route environment preparation "
                    "to openubmc-environment-setup"
                ),
            )
            completed = _attach_capture_metadata(
                completed,
                stdout_limit_bytes=stdout_limit_bytes,
                stderr_limit_bytes=stderr_limit_bytes,
            )
            completed = _attach_ssh_transport_metadata(
                completed,
                host_key_config=master.host_key_config,
                ssh_client_missing=True,
            )
        else:
            try:
                completed = _run_bounded_process(
                    command,
                    timeout=timeout,
                    env=None,
                    stdout_limit_bytes=stdout_limit_bytes,
                    stderr_limit_bytes=stderr_limit_bytes,
                )
            except FileNotFoundError:
                completed = subprocess.CompletedProcess(
                    args=command,
                    returncode=SSH_CLIENT_MISSING_RETURN_CODE,
                    stdout="",
                    stderr=(
                        "ssh executable is unavailable; route environment preparation "
                        "to openubmc-environment-setup"
                    ),
                )
                completed = _attach_capture_metadata(
                    completed,
                    stdout_limit_bytes=stdout_limit_bytes,
                    stderr_limit_bytes=stderr_limit_bytes,
                )
                completed = _attach_ssh_transport_metadata(
                    completed,
                    host_key_config=master.host_key_config,
                    ssh_client_missing=True,
                )
        completed = _attach_ssh_transport_metadata(
            completed,
            host_key_config=master.host_key_config,
            ssh_client_missing=bool(getattr(completed, "ssh_client_missing", False)),
        )
        completed = self._attach_mode(completed, "control-master-channel")
        completed.stdout = _bounded_utf8_text(completed.stdout, stdout_limit_bytes)
        completed.stderr = _bounded_utf8_text(completed.stderr, stderr_limit_bytes)
        if dumper is not None:
            metadata = {
                "stage": label,
                "transport": "ssh",
                "connection_mode": "control-master-channel",
                "returncode": completed.returncode,
                "command_summary": remote_command,
                "stdout_limit_bytes": stdout_limit_bytes,
                "stderr_limit_bytes": stderr_limit_bytes,
                "failure_code": ssh_transport_failure_code(completed),
            }
            dumper.write_text(
                label,
                "stdout",
                completed.stdout or "",
                metadata={**metadata, "artifact": "stdout"},
            )
            dumper.write_text(
                label,
                "stderr",
                completed.stderr or "",
                metadata={**metadata, "artifact": "stderr"},
            )
        return completed

    def channel_lost_master(
        self,
        master: SshControlMasterHandle,
        result: subprocess.CompletedProcess[str],
    ) -> bool:
        if master.closed:
            return True
        if result.returncode != 255:
            return False
        return not self.check_master(master)

    def close_master(self, master: SshControlMasterHandle) -> None:
        if master.closed:
            return
        try:
            if Path(master.control_path).exists() and shutil.which("ssh"):
                subprocess.run(
                    self._control_command(master, "exit"),
                    capture_output=True,
                    text=True,
                    timeout=min(self.connect_timeout, 2.0),
                )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        finally:
            master.closed = True
            master.tempdir.cleanup()


def sanitize_remote_text(text: str) -> str:
    if not text:
        return ""
    text = HOST_KEY_RE.sub("", text)
    text = LEGAL_BANNER_RE.sub("", text)
    text = DEBUG_SHELL_RE.sub("", text)

    cleaned: list[str] = []
    for raw in text.replace("\r", "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            if cleaned and cleaned[-1] != "":
                cleaned.append("")
            continue
        if any(marker in line for marker in NOISE_MARKERS):
            continue
        cleaned.append(line)
    return "\n".join(cleaned).rstrip()


def run_ssh(
    ip: str,
    user: str,
    password: str,
    remote_cmd: str,
    timeout: float,
    tty: bool = False,
    port: int = 22,
    identity_file: str = "",
    debug_dumper=None,
    debug_label: str = "ssh",
    host_key_policy: str = "",
    known_hosts_file: str = "",
    allow_insecure_host_key: bool = False,
    stdout_limit_bytes: int | None = None,
    stderr_limit_bytes: int | None = None,
) -> subprocess.CompletedProcess[str]:
    stdout_limit_bytes = _validate_output_limit(
        "stdout_limit_bytes", stdout_limit_bytes
    )
    stderr_limit_bytes = _validate_output_limit(
        "stderr_limit_bytes", stderr_limit_bytes
    )
    try:
        host_key_config = resolve_ssh_host_key_config(
            host_key_policy,
            known_hosts_file,
            allow_insecure=allow_insecure_host_key,
        )
    except SshHostKeyPolicyError as exc:
        cp = subprocess.CompletedProcess(
            args=[],
            returncode=SSH_HOST_KEY_POLICY_ERROR_RETURN_CODE,
            stdout="",
            stderr=str(exc),
        )
        cp = _attach_capture_metadata(
            cp,
            stdout_limit_bytes=stdout_limit_bytes,
            stderr_limit_bytes=stderr_limit_bytes,
        )
        return _attach_ssh_transport_metadata(
            cp,
            host_key_config=exc.audit,
            host_key_policy_invalid=True,
        )

    cmd: List[str] = []
    if password:
        cmd += ["sshpass", "-e"]
    cmd += [
        "ssh",
        "-p",
        str(port),
    ]
    cmd += list(host_key_config["options"])
    cmd += ["-o", "LogLevel=ERROR"]
    if identity_file:
        cmd += ["-i", identity_file, "-o", "IdentitiesOnly=yes"]
    if tty:
        cmd.append("-tt")
    cmd.append(f"{user}@{ip}")
    cmd.append(remote_cmd)
    if debug_dumper is not None:
        debug_dumper.write_text(
            debug_label,
            "command",
            " ".join(
                shlex.quote(part) for part in cmd
            ),
            metadata={
                "stage": debug_label,
                "artifact": "command",
                "transport": "ssh",
                "command_summary": remote_cmd,
                "stdout_limit_bytes": stdout_limit_bytes,
                "stderr_limit_bytes": stderr_limit_bytes,
                "host_key_policy": host_key_config["policy"],
                "host_key_policy_source": host_key_config["policy_source"],
                "known_hosts_source": host_key_config["known_hosts_source"],
                "warnings": host_key_config["warnings"],
            },
        )
    if not shutil.which("ssh"):
        cp = subprocess.CompletedProcess(
            args=cmd,
            returncode=SSH_CLIENT_MISSING_RETURN_CODE,
            stdout="",
            stderr=(
                "ssh executable is unavailable; route environment preparation "
                "to openubmc-environment-setup"
            ),
        )
        cp = _attach_capture_metadata(
            cp,
            stdout_limit_bytes=stdout_limit_bytes,
            stderr_limit_bytes=stderr_limit_bytes,
        )
        cp = _attach_ssh_transport_metadata(
            cp,
            host_key_config=host_key_config,
            ssh_client_missing=True,
        )
    elif password and not shutil.which("sshpass"):
        cp = subprocess.CompletedProcess(
            args=cmd,
            returncode=127,
            stdout="",
            stderr="sshpass not found; install it or use key-based authentication",
        )
        cp = _attach_capture_metadata(
            cp,
            stdout_limit_bytes=stdout_limit_bytes,
            stderr_limit_bytes=stderr_limit_bytes,
        )
    else:
        run_env = None
        if password:
            run_env = dict(os.environ)
            run_env["SSHPASS"] = password
        try:
            if stdout_limit_bytes is not None or stderr_limit_bytes is not None:
                cp = _run_bounded_process(
                    cmd,
                    timeout=timeout,
                    env=run_env,
                    stdout_limit_bytes=stdout_limit_bytes,
                    stderr_limit_bytes=stderr_limit_bytes,
                )
            else:
                timed_out = False
                try:
                    cp = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        env=run_env,
                    )
                except subprocess.TimeoutExpired:
                    timed_out = True
                    cp = subprocess.CompletedProcess(
                        args=cmd,
                        returncode=124,
                        stdout="",
                        stderr=f"SSH command timed out after {timeout}s",
                    )
                cp = _attach_capture_metadata(
                    cp,
                    stdout_limit_bytes=None,
                    stderr_limit_bytes=None,
                    stdout_bytes_read=len((cp.stdout or "").encode("utf-8")),
                    stderr_bytes_read=len((cp.stderr or "").encode("utf-8")),
                    stdout_bytes_captured=len((cp.stdout or "").encode("utf-8")),
                    stderr_bytes_captured=len((cp.stderr or "").encode("utf-8")),
                    timed_out=timed_out,
                )
        except FileNotFoundError:
            cp = subprocess.CompletedProcess(
                args=cmd,
                returncode=SSH_CLIENT_MISSING_RETURN_CODE,
                stdout="",
                stderr=(
                    "ssh executable is unavailable; route environment preparation "
                    "to openubmc-environment-setup"
                ),
            )
            cp = _attach_capture_metadata(
                cp,
                stdout_limit_bytes=stdout_limit_bytes,
                stderr_limit_bytes=stderr_limit_bytes,
            )
            cp = _attach_ssh_transport_metadata(
                cp,
                host_key_config=host_key_config,
                ssh_client_missing=True,
            )
    cp = _attach_ssh_transport_metadata(
        cp,
        host_key_config=host_key_config,
        ssh_client_missing=bool(getattr(cp, "ssh_client_missing", False)),
        host_key_policy_invalid=bool(
            getattr(cp, "host_key_policy_invalid", False)
        ),
    )
    cp.stdout = _bounded_utf8_text(cp.stdout or "", stdout_limit_bytes)
    cp.stderr = _bounded_utf8_text(cp.stderr or "", stderr_limit_bytes)
    if debug_dumper is not None:
        metadata = {
            "stage": debug_label,
            "transport": "ssh",
            "returncode": cp.returncode,
            "command_summary": remote_cmd,
            "stdout_limit_bytes": stdout_limit_bytes,
            "stderr_limit_bytes": stderr_limit_bytes,
            "stdout_limit_exceeded": bool(
                getattr(cp, "stdout_limit_exceeded", False)
            ),
            "stderr_limit_exceeded": bool(
                getattr(cp, "stderr_limit_exceeded", False)
            ),
            "output_limit_exceeded": bool(
                getattr(cp, "output_limit_exceeded", False)
            ),
            "capture_failed": bool(getattr(cp, "capture_failed", False)),
            "stdout_read_error": bool(
                getattr(cp, "stdout_read_error", False)
            ),
            "stderr_read_error": bool(
                getattr(cp, "stderr_read_error", False)
            ),
            "stdout_bytes_read": int(getattr(cp, "stdout_bytes_read", 0)),
            "stderr_bytes_read": int(getattr(cp, "stderr_bytes_read", 0)),
            "stdout_bytes_captured": int(
                getattr(cp, "stdout_bytes_captured", 0)
            ),
            "stderr_bytes_captured": int(
                getattr(cp, "stderr_bytes_captured", 0)
            ),
            "failure_code": ssh_transport_failure_code(cp),
            "ssh_client_missing": bool(
                getattr(cp, "ssh_client_missing", False)
            ),
            "host_key_verification_failed": bool(
                getattr(cp, "host_key_verification_failed", False)
            ),
            "host_key_policy": str(
                getattr(cp, "ssh_host_key_policy", DEFAULT_SSH_HOST_KEY_POLICY)
            ),
            "host_key_policy_source": str(
                getattr(cp, "ssh_host_key_policy_source", "default")
            ),
            "known_hosts_source": str(
                getattr(cp, "ssh_known_hosts_source", "ssh_default")
            ),
            "warnings": list(
                getattr(cp, "ssh_transport_warnings", [])
            ),
        }
        debug_dumper.write_text(
            debug_label,
            "stdout",
            cp.stdout or "",
            metadata={**metadata, "artifact": "stdout"},
        )
        debug_dumper.write_text(
            debug_label,
            "stderr",
            cp.stderr or "",
            metadata={**metadata, "artifact": "stderr"},
        )
    return cp


def build_posix_shell_command(inner: str, *, load_profile: bool = False) -> str:
    commands: list[str] = []
    if load_profile:
        commands.append(". /etc/profile >/dev/null 2>&1")
    commands.append(inner)
    return "sh -lc " + shlex.quote("; ".join(commands))


def detect_dbus_env(
    ip: str,
    user: str,
    password: str,
    timeout: float,
    port: int = 22,
    identity_file: str = "",
    debug_dumper=None,
    debug_label: str = "dbus_env",
    ssh_runner=None,
) -> DbusEnvironment:
    if ssh_runner is None:
        ssh_runner = run_ssh
    cmd = build_posix_shell_command('printenv | grep -E "DBUS_SESSION_BUS_ADDRESS|XDG_RUNTIME_DIR"')
    cp = ssh_runner(
        ip,
        user,
        password,
        cmd,
        timeout,
        tty=True,
        port=port,
        identity_file=identity_file,
        debug_dumper=debug_dumper,
        debug_label=debug_label,
        stdout_limit_bytes=DBUS_ENV_STDOUT_LIMIT_BYTES,
        stderr_limit_bytes=DBUS_ENV_STDERR_LIMIT_BYTES,
    )
    transport = ssh_transport_details(cp)
    if ssh_transport_failure_code(cp):
        return DbusEnvironment(transport=transport)
    combined = sanitize_remote_text((cp.stdout or "") + "\n" + (cp.stderr or ""))
    found = DbusEnvironment(transport=transport)
    for line in combined.splitlines():
        match = ENV_RE.match(line.strip())
        if match:
            found[match.group(1)] = match.group(2)
    return found


def filter_text_output(
    text: str,
    grep_keywords: list[str],
    head: int | None = None,
    tail: int | None = None,
) -> str:
    if not text:
        return ""
    lines = text.splitlines()
    if grep_keywords:
        lowered = [item.lower() for item in grep_keywords]
        lines = [line for line in lines if any(keyword in line.lower() for keyword in lowered)]
    if head is not None:
        lines = lines[:head]
    if tail is not None:
        lines = lines[-tail:]
    return "\n".join(lines).strip()


def build_filter_notice(grep_keywords: list[str], head: int | None, tail: int | None) -> str:
    parts: list[str] = []
    if grep_keywords:
        parts.append(f"grep={','.join(grep_keywords)}")
    if head is not None:
        parts.append(f"head={head}")
    if tail is not None:
        parts.append(f"tail={tail}")
    if not parts:
        return "[INFO] 0 matching lines after filters"
    return f"[INFO] 0 matching lines after filters ({'; '.join(parts)})"


def preview_lines(text: str, limit: int = 5, width: int = 180) -> list[str]:
    preview: list[str] = []
    for raw in text.splitlines()[:limit]:
        line = raw.strip()
        if not line:
            continue
        if len(line) > width:
            line = line[: width - 3] + "..."
        preview.append(line)
    return preview
