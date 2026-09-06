"""Dependency-free system OpenSSH transport for task-scoped Runtime lanes."""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

from .contracts import TargetSpec
from .runtime import ResolvedSshCredentials


class OpenSshUnavailable(RuntimeError):
    pass


class OpenSshMasterError(RuntimeError):
    def __init__(self, result: subprocess.CompletedProcess[str]) -> None:
        message = (result.stderr or result.stdout or "").strip()
        super().__init__(message or "OpenSSH ControlMaster could not be established")
        self.result = result


@dataclass
class OpenSshMaster:
    target: TargetSpec
    credentials: ResolvedSshCredentials = field(repr=False)
    control_path: str = field(repr=False)
    tempdir: tempfile.TemporaryDirectory[str] = field(repr=False)
    closed: bool = False

    @property
    def destination(self) -> str:
        return f"{self.credentials.user}@{self.target.host}"


class OpenSshControlMasterTransport:
    """Small canonical OpenSSH ControlMaster transport shared by Skills."""

    def __init__(
        self,
        *,
        host_key_policy: str = "",
        known_hosts_file: str = "",
        persist_seconds: int = 60,
        connect_timeout: float = 15.0,
    ) -> None:
        if persist_seconds < 1:
            raise ValueError("persist_seconds must be positive")
        if connect_timeout <= 0:
            raise ValueError("connect_timeout must be positive")
        self.host_key_policy = host_key_policy
        self.known_hosts_file = known_hosts_file
        self.persist_seconds = persist_seconds
        self.connect_timeout = connect_timeout

    def _host_key_options(self, target: TargetSpec) -> list[str]:
        policy = (
            self.host_key_policy
            or target.policy.ssh_host_key_policy
            or "insecure"
        ).strip().lower()
        if policy == "default":
            policy = "insecure"
        if policy == "strict":
            options = ["-o", "StrictHostKeyChecking=yes"]
        elif policy == "accept-new":
            options = ["-o", "StrictHostKeyChecking=accept-new"]
        elif policy == "insecure":
            options = [
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
            ]
        else:
            raise ValueError(
                "SSH host key policy must be strict, accept-new, or insecure"
            )
        if self.known_hosts_file and policy != "insecure":
            options.extend(["-o", f"UserKnownHostsFile={self.known_hosts_file}"])
        return options

    @staticmethod
    def _password_prefix(credentials: ResolvedSshCredentials) -> list[str]:
        if not credentials.password:
            return []
        if not shutil.which("sshpass"):
            raise OpenSshUnavailable(
                "sshpass not found; install it or use key-based authentication"
            )
        return ["sshpass", "-e"]

    @staticmethod
    def _sanitized_environment() -> dict[str, str]:
        environment = dict(os.environ)
        for name in (
            "OPENUBMC_SSH_PASSWORD",
            "OPENUBMC_TELNET_PASSWORD",
            "OPENUBMC_OS_SSH_PASSWORD",
            "OPENUBMC_REDFISH_PASSWORD",
            "REDFISH_PASSWORD",
            "SSHPASS",
        ):
            environment.pop(name, None)
        return environment

    @classmethod
    def _environment(
        cls,
        credentials: ResolvedSshCredentials,
    ) -> dict[str, str]:
        environment = cls._sanitized_environment()
        if credentials.password:
            environment["SSHPASS"] = credentials.password
        return environment

    def _connection_options(self, master: OpenSshMaster) -> list[str]:
        options = [
            "-p",
            str(master.target.ssh_port),
            *self._host_key_options(master.target),
            "-o",
            "LogLevel=ERROR",
        ]
        if master.credentials.identity_file:
            options.extend(
                [
                    "-i",
                    master.credentials.identity_file,
                    "-o",
                    "IdentitiesOnly=yes",
                ]
            )
        return options

    def open_master(
        self,
        *,
        target: TargetSpec,
        credentials: ResolvedSshCredentials,
    ) -> OpenSshMaster:
        if not shutil.which("ssh"):
            raise OpenSshUnavailable("ssh executable is unavailable")
        tempdir = tempfile.TemporaryDirectory(prefix="openubmc-target-runtime-ssh-")
        master = OpenSshMaster(
            target=target,
            credentials=credentials,
            control_path=str(Path(tempdir.name) / "master.sock"),
            tempdir=tempdir,
        )
        command = [
            *self._password_prefix(credentials),
            "ssh",
            *self._connection_options(master),
            "-M",
            "-N",
            "-f",
            "-o",
            "ControlMaster=yes",
            "-o",
            f"ControlPersist={self.persist_seconds}",
            "-o",
            f"ControlPath={master.control_path}",
            master.destination,
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.connect_timeout,
                env=self._environment(credentials),
            )
        except subprocess.TimeoutExpired:
            result = subprocess.CompletedProcess(
                command,
                124,
                "",
                f"SSH authentication timed out after {self.connect_timeout}s",
            )
        if result.returncode != 0 or not self.check_master(master):
            self.close_master(master)
            raise OpenSshMasterError(result)
        return master

    def _control_command(self, master: OpenSshMaster, operation: str) -> list[str]:
        return [
            "ssh",
            *self._connection_options(master),
            "-o",
            f"ControlPath={master.control_path}",
            "-O",
            operation,
            master.destination,
        ]

    def check_master(self, master: OpenSshMaster) -> bool:
        if master.closed or not Path(master.control_path).exists():
            return False
        try:
            result = subprocess.run(
                self._control_command(master, "check"),
                capture_output=True,
                text=True,
                timeout=min(self.connect_timeout, 2.0),
                env=self._sanitized_environment(),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0

    def run_channel(
        self,
        master: OpenSshMaster,
        remote_command: str,
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        timeout = float(kwargs.get("timeout", 60))
        command = [
            "ssh",
            *self._connection_options(master),
            "-o",
            f"ControlPath={master.control_path}",
            "-o",
            "ControlMaster=no",
            "-o",
            "BatchMode=yes",
            master.destination,
            remote_command,
        ]
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=self._sanitized_environment(),
            )
        except subprocess.TimeoutExpired as exc:
            return subprocess.CompletedProcess(
                command,
                124,
                exc.stdout or "",
                (exc.stderr or "") + f"\nSSH command timed out after {timeout}s",
            )

    def download_file(
        self,
        master: OpenSshMaster,
        remote_path: str,
        local_path: str,
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        timeout = float(kwargs.get("timeout", 1800))
        command = [
            "scp",
            "-P",
            str(master.target.ssh_port),
            *self._host_key_options(master.target),
            "-o",
            f"ControlPath={master.control_path}",
            "-o",
            "ControlMaster=no",
            f"{master.destination}:{remote_path}",
            local_path,
        ]
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=self._sanitized_environment(),
            )
        except subprocess.TimeoutExpired as exc:
            return subprocess.CompletedProcess(
                command,
                124,
                exc.stdout or "",
                (exc.stderr or "") + f"\nSCP timed out after {timeout}s",
            )

    def upload_file(
        self,
        master: OpenSshMaster,
        local_path: str,
        remote_path: str,
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        timeout = float(kwargs.get("timeout", 1800))
        command = [
            "ssh",
            *self._connection_options(master),
            "-o",
            f"ControlPath={master.control_path}",
            "-o",
            "ControlMaster=no",
            "-o",
            "BatchMode=yes",
            master.destination,
            f"umask 077 && cat > {shlex.quote(remote_path)}",
        ]
        try:
            with Path(local_path).open("rb") as stream:
                return subprocess.run(
                    command,
                    stdin=stream,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=self._sanitized_environment(),
                )
        except subprocess.TimeoutExpired as exc:
            return subprocess.CompletedProcess(
                command,
                124,
                exc.stdout or "",
                (exc.stderr or "") + f"\nSSH upload timed out after {timeout}s",
            )

    def channel_lost_master(
        self,
        master: OpenSshMaster,
        result: subprocess.CompletedProcess[str],
    ) -> bool:
        return result.returncode == 255 and not self.check_master(master)

    def close_master(self, master: OpenSshMaster) -> None:
        if master.closed:
            return
        try:
            if Path(master.control_path).exists() and shutil.which("ssh"):
                subprocess.run(
                    self._control_command(master, "exit"),
                    capture_output=True,
                    text=True,
                    timeout=min(self.connect_timeout, 2.0),
                    env=self._sanitized_environment(),
                )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        finally:
            master.closed = True
            master.tempdir.cleanup()
