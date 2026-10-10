"""In-process SSH transport for native Windows device work."""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import time

from .contracts import TargetSpec
from .redaction import SecretMaterialError, redact_text, require_secret_free
from .runtime import ResolvedSshCredentials


class ParamikoOpenError(RuntimeError):
    def __init__(self, completed: subprocess.CompletedProcess[str]):
        super().__init__(completed.stderr or "SSH connection failed")
        self.completed = completed
        self.result = completed


@dataclass
class ParamikoMaster:
    target: TargetSpec
    credentials: ResolvedSshCredentials = field(repr=False)
    client: object = field(repr=False)
    closed: bool = False

    @property
    def destination(self) -> str:
        return f"{self.credentials.user}@{self.target.host}"


class ParamikoSshTransport:
    """The same task-scoped SSH lane contract without sshpass or POSIX sockets."""

    def __init__(self, *, host_key_policy: str = "", known_hosts_file: str = "",
                 allow_insecure_host_key: bool = False, persist_seconds: int = 60,
                 connect_timeout: float = 15.0, debug_dumper=None,
                 debug_label_prefix: str = "ssh", open_error_type=ParamikoOpenError):
        if connect_timeout <= 0 or persist_seconds < 1:
            raise ValueError("SSH timeouts must be positive")
        self.host_key_policy = host_key_policy
        self.known_hosts_file = known_hosts_file
        self.allow_insecure_host_key = allow_insecure_host_key
        self.connect_timeout = connect_timeout
        self.debug_dumper = debug_dumper
        self.debug_label_prefix = debug_label_prefix
        self.open_error_type = open_error_type

    def _policy(self, target: TargetSpec) -> str:
        value = (self.host_key_policy or target.policy.ssh_host_key_policy or "insecure").strip().lower()
        if value == "default":
            value = "insecure"
        if value not in {"strict", "accept-new", "insecure"}:
            raise ValueError("SSH host key policy must be strict, accept-new, or insecure")
        return value

    def validate_channel_options(self, *, target: TargetSpec, host_key_policy: str,
                                 known_hosts_file: str, allow_insecure_host_key: bool) -> None:
        requested = (host_key_policy or self.host_key_policy or target.policy.ssh_host_key_policy).strip().lower()
        if requested == "default":
            requested = "insecure"
        if requested != self._policy(target) or (known_hosts_file or self.known_hosts_file) != self.known_hosts_file:
            raise ValueError("SSH channel host-key options do not match the bound SSH lease")
        if allow_insecure_host_key and not self.allow_insecure_host_key and requested != "insecure":
            raise ValueError("SSH channel host-key options do not match the bound SSH lease")

    def _known_hosts(self, policy: str) -> Path | None:
        if policy == "insecure":
            return None
        path = Path(self.known_hosts_file).expanduser() if self.known_hosts_file else Path.home()/".ssh/known_hosts"
        if policy == "accept-new" and not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if os.name == "nt":
                from .windows_private import ensure_private_directory, harden_new_file
                ensure_private_directory(path.parent)
            path.touch(mode=0o600)
            if os.name == "nt":
                harden_new_file(path)
        if not path.is_file() or path.is_symlink():
            raise ValueError("SSH known-hosts file is unavailable")
        if os.name == "nt":
            from .windows_private import verify_private_path
            verify_private_path(path)
        return path

    def open_master(self, *, target: TargetSpec, credentials: ResolvedSshCredentials) -> ParamikoMaster:
        try:
            import paramiko
        except ImportError:
            raise ParamikoOpenError(subprocess.CompletedProcess([], 127, "", "Native SSH dependency is unavailable")) from None
        policy = self._policy(target)
        client = paramiko.SSHClient()
        try:
            known_hosts = self._known_hosts(policy)
            if known_hosts is not None:
                client.load_host_keys(str(known_hosts))
            if policy == "strict":
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
            elif policy == "accept-new":
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            else:
                class AcceptWithoutPersistence(paramiko.MissingHostKeyPolicy):
                    def missing_host_key(self, _client, _hostname, _key):
                        return None
                client.set_missing_host_key_policy(AcceptWithoutPersistence())
            client.connect(
                hostname=target.host, port=target.ssh_port, username=credentials.user,
                password=credentials.password or None,
                key_filename=credentials.identity_file or None,
                timeout=self.connect_timeout, auth_timeout=self.connect_timeout,
                banner_timeout=self.connect_timeout,
                allow_agent=not bool(credentials.password),
                look_for_keys=not bool(credentials.password or credentials.identity_file),
            )
            return ParamikoMaster(target=target, credentials=credentials, client=client)
        except Exception as exc:
            client.close()
            if isinstance(exc, paramiko.BadHostKeyException) or "not found in known_hosts" in str(exc):
                message = "SSH host key verification failed"
            elif isinstance(exc, paramiko.AuthenticationException):
                message = "SSH authentication failed"
            elif isinstance(exc, (socket.timeout, TimeoutError)):
                message = "SSH connection timed out"
            else:
                message = "SSH connection failed"
            completed = subprocess.CompletedProcess(["ssh", target.host], 255, "", message)
            raise self.open_error_type(completed) from None

    @staticmethod
    def check_master(master: ParamikoMaster) -> bool:
        transport = master.client.get_transport() if not master.closed else None
        return bool(transport and transport.is_active())

    @staticmethod
    def _safe_command(master: ParamikoMaster, remote_command: str) -> list[str]:
        if master.credentials.password and master.credentials.password in remote_command:
            raise SecretMaterialError("credential value is not accepted in a remote command")
        require_secret_free(remote_command, boundary="remote command")
        return ["ssh", master.destination, remote_command]

    @staticmethod
    def _completed(master: ParamikoMaster, args: list[str], returncode: int,
                   stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
        secrets = (master.credentials.password,) if master.credentials.password else ()
        result = subprocess.CompletedProcess(
            args, returncode,
            redact_text(stdout, secret_values=secrets),
            redact_text(stderr, secret_values=secrets),
        )
        result.ssh_connection_mode = "in-process-channel"
        return result

    def run_channel(self, master: ParamikoMaster, remote_command: str, **kwargs: object) -> subprocess.CompletedProcess[str]:
        args = self._safe_command(master, remote_command)
        timeout = float(kwargs.get("timeout", 60))
        if timeout <= 0:
            return self._completed(master, args, 124, stderr="SSH command timed out")
        stdout_limit = kwargs.get("stdout_limit_bytes")
        stderr_limit = kwargs.get("stderr_limit_bytes")
        stdout_limit = 1024 * 1024 if stdout_limit is None else int(stdout_limit)
        stderr_limit = 1024 * 1024 if stderr_limit is None else int(stderr_limit)
        if stdout_limit < 0 or stderr_limit < 0:
            raise ValueError("SSH output limit cannot be negative")
        channel = None
        try:
            transport = master.client.get_transport()
            if transport is None or not transport.is_active():
                return self._completed(master, args, 255, stderr="SSH connection lost")
            channel = transport.open_session(timeout=timeout)
            if kwargs.get("tty"):
                channel.get_pty()
            channel.exec_command(remote_command)
            chunks = [[], []]
            counts = [0, 0]
            limits = [stdout_limit, stderr_limit]
            deadline = time.monotonic() + timeout
            while True:
                for index, ready, receive in ((0, channel.recv_ready, channel.recv),
                                              (1, channel.recv_stderr_ready, channel.recv_stderr)):
                    while ready():
                        data = receive(65536)
                        counts[index] += len(data)
                        if counts[index] > limits[index]:
                            return self._completed(master, args, 125, stderr="SSH output limit exceeded")
                        chunks[index].append(data)
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    code = channel.recv_exit_status()
                    out = b"".join(chunks[0]).decode("utf-8", errors="replace")
                    err = b"".join(chunks[1]).decode("utf-8", errors="replace")
                    result = self._completed(master, args, code, out, err)
                    dumper = kwargs.get("debug_dumper") or self.debug_dumper
                    if dumper is not None:
                        label = str(kwargs.get("debug_label") or self.debug_label_prefix)
                        dumper.write_text(label, "stdout", result.stdout or "", metadata={"transport": "ssh", "artifact": "stdout"})
                        dumper.write_text(label, "stderr", result.stderr or "", metadata={"transport": "ssh", "artifact": "stderr"})
                    return result
                if time.monotonic() >= deadline:
                    return self._completed(master, args, 124, stderr="SSH command timed out")
                time.sleep(0.01)
        except (OSError, EOFError, socket.timeout):
            return self._completed(master, args, 255, stderr="SSH connection lost")
        finally:
            if channel is not None:
                channel.close()

    def download_file(self, master: ParamikoMaster, remote_path: str, local_path: str,
                      **kwargs: object) -> subprocess.CompletedProcess[str]:
        args = ["sftp", master.destination, remote_path, local_path]
        timeout = float(kwargs.get("timeout", 1800))
        try:
            sftp = master.client.open_sftp()
        except Exception:
            return self._scp_download_file(master, remote_path, local_path, timeout=timeout)
        try:
            sftp.get_channel().settimeout(timeout)
            sftp.get(remote_path, local_path)
            return self._completed(master, args, 0)
        except (OSError, EOFError, socket.timeout):
            return self._completed(master, args, 255, stderr="SSH download failed")
        finally:
            sftp.close()

    def _scp_download_file(self, master: ParamikoMaster, remote_path: str,
                           local_path: str, *, timeout: float) -> subprocess.CompletedProcess[str]:
        command = f"scp -f -- {shlex.quote(remote_path)}"
        args = self._safe_command(master, command)
        channel = None
        temporary = None
        try:
            transport = master.client.get_transport()
            if transport is None or not transport.is_active():
                return self._completed(master, args, 255, stderr="SSH connection lost")
            channel = transport.open_session(timeout=timeout)
            channel.settimeout(timeout)
            channel.exec_command(command)
            channel.sendall(b"\0")

            def line() -> bytes:
                value = bytearray()
                while len(value) < 4096:
                    byte = channel.recv(1)
                    if not byte:
                        raise EOFError("SCP stream ended")
                    if byte == b"\n":
                        return bytes(value)
                    value.extend(byte)
                raise ValueError("SCP header is too large")

            marker = channel.recv(1)
            while marker == b"T":
                line()
                channel.sendall(b"\0")
                marker = channel.recv(1)
            if marker in {b"\1", b"\2"}:
                line()
                return self._completed(master, args, 1, stderr="SCP source rejected the download")
            if marker != b"C":
                raise ValueError("Invalid SCP file header")
            fields = line().split(b" ", 2)
            if len(fields) != 3 or not fields[0].isdigit() or not fields[1].isdigit():
                raise ValueError("Invalid SCP file header")
            size = int(fields[1])
            if size > 1 << 40:
                raise ValueError("SCP file is too large")
            destination = Path(local_path)
            with tempfile.NamedTemporaryFile(mode="wb", prefix=".openubmc-download-",
                                             dir=destination.parent, delete=False) as stream:
                temporary = Path(stream.name)
                channel.sendall(b"\0")
                remaining = size
                while remaining:
                    chunk = channel.recv(min(65536, remaining))
                    if not chunk:
                        raise EOFError("SCP file is incomplete")
                    stream.write(chunk)
                    remaining -= len(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            if channel.recv(1) != b"\0":
                raise ValueError("SCP source did not complete the file")
            channel.sendall(b"\0")
            if channel.recv_exit_status() != 0:
                raise ValueError("SCP source failed")
            os.replace(temporary, destination)
            temporary = None
            return self._completed(master, args, 0)
        except (OSError, EOFError, socket.timeout, ValueError):
            return self._completed(master, args, 255, stderr="SSH download failed")
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            if channel is not None:
                try:
                    channel.close()
                except EOFError:
                    # A disconnected peer cannot acknowledge channel shutdown.
                    # Preserve the transfer result or the original exception.
                    pass

    def upload_file(self, master: ParamikoMaster, local_path: str, remote_path: str,
                    **kwargs: object) -> subprocess.CompletedProcess[str]:
        timeout = float(kwargs.get("timeout", 1800))
        command = f"umask 077 && cat > {shlex.quote(remote_path)}"
        args = self._safe_command(master, command)
        channel = None
        try:
            transport = master.client.get_transport()
            if transport is None or not transport.is_active():
                return self._completed(master, args, 255, stderr="SSH connection lost")
            channel = transport.open_session(timeout=timeout)
            channel.settimeout(timeout)
            channel.exec_command(command)
            with Path(local_path).open("rb") as stream:
                while chunk := stream.read(65536):
                    channel.sendall(chunk)
            channel.shutdown_write()
            code = channel.recv_exit_status()
            return self._completed(master, args, code,
                                   stderr=channel.makefile_stderr("r").read(8192))
        except (OSError, EOFError, socket.timeout):
            return self._completed(master, args, 255, stderr="SSH upload failed")
        finally:
            if channel is not None:
                channel.close()

    def channel_lost_master(self, master: ParamikoMaster,
                            result: subprocess.CompletedProcess[str]) -> bool:
        return result.returncode == 255 and not self.check_master(master)

    @staticmethod
    def close_master(master: ParamikoMaster) -> None:
        if not master.closed:
            master.closed = True
            master.client.close()
