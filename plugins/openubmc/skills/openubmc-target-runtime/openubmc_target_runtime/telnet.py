"""Canonical Telnet client, login, and command-framing primitives."""
from __future__ import annotations

from dataclasses import dataclass
import re
import secrets
import socket
import time


IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
SE = 240
DEFAULT_MAX_BUFFER_BYTES = 8 * 1024 * 1024
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
LOGIN_RE = re.compile(br"(login:|username:)", re.IGNORECASE)
PASSWORD_RE = re.compile(br"password:", re.IGNORECASE)
SHELL_PROMPT_RE = re.compile(br"(?m)[^\n]*[#$] ?$")
MAX_TELNET_INPUT_BYTES = 960
MAX_TELNET_EXPECT_BYTES = 64 * 1024
MAX_TELNET_COMMAND_OUTPUT_BYTES = 8 * 1024 * 1024
TELNET_OUTPUT_LIMIT_RETURN_CODE = 125
TELNET_OUTPUT_LIMIT_CODE = "telnet_output_limit_exceeded"
FRAME_TOKEN_BYTES = 16
FRAME_TOKEN_HEX_LENGTH = FRAME_TOKEN_BYTES * 2


class TelnetOutputLimitExceeded(RuntimeError):
    """Raised after a Telnet receive exceeds its configured hard ceiling."""

    def __init__(
        self,
        limit_bytes: int,
        bytes_received: int,
        *,
        captured: bytes = b"",
        stage: str = "telnet_receive",
    ) -> None:
        super().__init__(TELNET_OUTPUT_LIMIT_CODE)
        self.code = TELNET_OUTPUT_LIMIT_CODE
        self.limit_bytes = limit_bytes
        self.bytes_received = bytes_received
        self.captured = captured[:limit_bytes]
        self.stage = stage


class TelnetClient:
    """Minimal Telnet client with bounded negotiation and receive buffers."""

    def __init__(
        self,
        host: str,
        port: int,
        timeout: int = 10,
        *,
        max_buffer_bytes: int = DEFAULT_MAX_BUFFER_BYTES,
    ) -> None:
        if max_buffer_bytes < 1:
            raise ValueError("max_buffer_bytes must be positive")
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._buffer = bytearray()
        self.max_buffer_bytes = max_buffer_bytes
        self._iac_pending = False
        self._iac_cmd: int | None = None
        self._subnegotiation = False
        self._subnegotiation_iac = False
        self.last_read_status = "idle"

    def _respond_to_negotiation(self, command: int, option: int) -> None:
        if command in (DO, DONT):
            self.sock.sendall(bytes([IAC, WONT, option]))
        elif command in (WILL, WONT):
            self.sock.sendall(bytes([IAC, DONT, option]))

    def _feed(self, data: bytes) -> bytes:
        cooked = bytearray()
        for byte in data:
            if self._subnegotiation:
                if self._subnegotiation_iac:
                    self._subnegotiation_iac = False
                    if byte == SE:
                        self._subnegotiation = False
                    elif byte == IAC:
                        continue
                    continue
                if byte == IAC:
                    self._subnegotiation_iac = True
                continue

            if self._iac_cmd is not None:
                self._respond_to_negotiation(self._iac_cmd, byte)
                self._iac_cmd = None
                continue

            if self._iac_pending:
                self._iac_pending = False
                if byte == IAC:
                    cooked.append(IAC)
                elif byte in (DO, DONT, WILL, WONT):
                    self._iac_cmd = byte
                elif byte == SB:
                    self._subnegotiation = True
                    self._subnegotiation_iac = False
                continue

            if byte == IAC:
                self._iac_pending = True
            else:
                cooked.append(byte)
        return bytes(cooked)

    def _close_after_limit(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def _raise_output_limit(
        self,
        limit_bytes: int,
        bytes_received: int,
        *,
        stage: str,
    ) -> None:
        captured = bytes(self._buffer[:limit_bytes])
        self._buffer.clear()
        self.last_read_status = "output_limit_exceeded"
        self._close_after_limit()
        raise TelnetOutputLimitExceeded(
            limit_bytes,
            bytes_received,
            captured=captured,
            stage=stage,
        )

    def _recv_into_buffer(
        self,
        timeout: float,
        *,
        max_bytes: int | None = None,
        stage: str = "telnet_receive",
    ) -> str:
        buffer_limit = getattr(self, "max_buffer_bytes", DEFAULT_MAX_BUFFER_BYTES)
        limit_bytes = min(
            buffer_limit,
            max_bytes if max_bytes is not None else buffer_limit,
        )
        if limit_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self.sock.settimeout(max(timeout, 0.05))
        try:
            chunk = self.sock.recv(4096)
        except (TimeoutError, socket.timeout):
            self.last_read_status = "timeout"
            return "timeout"
        if not chunk:
            self.last_read_status = "closed"
            return "closed"
        cooked = self._feed(chunk)
        prospective_size = len(self._buffer) + len(cooked)
        if prospective_size > limit_bytes:
            remaining = max(0, limit_bytes - len(self._buffer))
            if remaining:
                self._buffer.extend(cooked[:remaining])
            self._raise_output_limit(
                limit_bytes,
                prospective_size,
                stage=stage,
            )
        self._buffer.extend(cooked)
        self.last_read_status = "data"
        return "data"

    def write(self, data: bytes) -> None:
        self.sock.sendall(data.replace(bytes([IAC]), bytes([IAC, IAC])))

    def read_until(
        self,
        expected: bytes,
        timeout: float = 20,
        *,
        max_bytes: int | None = None,
    ) -> bytes:
        deadline = time.monotonic() + timeout
        buffer_limit = getattr(self, "max_buffer_bytes", DEFAULT_MAX_BUFFER_BYTES)
        limit_bytes = min(
            buffer_limit,
            max_bytes if max_bytes is not None else buffer_limit,
        )
        while True:
            if len(self._buffer) > limit_bytes:
                self._raise_output_limit(
                    limit_bytes,
                    len(self._buffer),
                    stage="telnet_command_receive",
                )
            index = bytes(self._buffer).find(expected)
            if index != -1:
                end = index + len(expected)
                data = bytes(self._buffer[:end])
                del self._buffer[:end]
                self.last_read_status = "matched"
                return data
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.last_read_status = "timeout"
                data = bytes(self._buffer)
                self._buffer.clear()
                return data
            if self._recv_into_buffer(
                remaining,
                max_bytes=limit_bytes,
                stage="telnet_command_receive",
            ) != "data":
                data = bytes(self._buffer)
                self._buffer.clear()
                return data

    def expect(
        self,
        patterns: list[re.Pattern[bytes]],
        timeout: float = 5,
        *,
        max_bytes: int | None = None,
    ) -> tuple[int, re.Match[bytes] | None, bytes]:
        deadline = time.monotonic() + timeout
        buffer_limit = getattr(self, "max_buffer_bytes", DEFAULT_MAX_BUFFER_BYTES)
        limit_bytes = min(
            buffer_limit,
            max_bytes if max_bytes is not None else buffer_limit,
        )
        while True:
            current = bytes(self._buffer)
            if len(current) > limit_bytes:
                self._raise_output_limit(
                    limit_bytes,
                    len(current),
                    stage="telnet_expect",
                )
            for index, pattern in enumerate(patterns):
                match = pattern.search(current)
                if match:
                    end = match.end()
                    data = current[:end]
                    del self._buffer[:end]
                    return index, match, data
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.last_read_status = "timeout"
                data = bytes(self._buffer)
                self._buffer.clear()
                return -1, None, data
            if self._recv_into_buffer(
                remaining,
                max_bytes=limit_bytes,
                stage="telnet_expect",
            ) != "data":
                data = bytes(self._buffer)
                self._buffer.clear()
                return -1, None, data

    def close(self) -> None:
        self.sock.close()


@dataclass(frozen=True)
class TelnetCommandResult:
    stdout: str
    returncode: int | None
    framing_complete: bool
    timed_out: bool
    connection_closed: bool
    raw: bytes

    @property
    def ok(self) -> bool:
        return self.framing_complete and self.returncode == 0


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def _frame_markers(token: str) -> tuple[bytes, bytes, bytes]:
    if not re.fullmatch(rf"[0-9a-f]{{{FRAME_TOKEN_HEX_LENGTH}}}", token):
        raise ValueError("invalid Telnet frame token")
    token_bytes = token.encode("ascii")
    return (
        b"\x1e__OPENUBMC_" + token_bytes + b"_START__\x1e",
        b"\x1d__OPENUBMC_" + token_bytes + b"_RC__=",
        b"\x1f__OPENUBMC_" + token_bytes + b"_END__\x1f",
    )


def telnet_command_markers(token: str) -> tuple[bytes, bytes, bytes]:
    """Return the validated start, return-code, and end markers for a frame."""

    return _frame_markers(token)


def framed_command(cmd: str, *, frame_token: str | None = None) -> str:
    token = frame_token or secrets.token_hex(FRAME_TOKEN_BYTES)
    _frame_markers(token)
    return (
        f"printf '\\036__OPENUBMC_{token}_START__\\036'; "
        f"{cmd}; __openubmc_telnet_rc=$?; "
        f"printf '\\n\\035__OPENUBMC_{token}_RC__=%s\\n' "
        f"\"$__openubmc_telnet_rc\"; "
        f"printf '\\037__OPENUBMC_{token}_END__\\037'"
    )


def framed_telnet_command(cmd: str, *, frame_token: str | None = None) -> str:
    """Public spelling for a shell command wrapped in an unforgeable frame."""

    return framed_command(cmd, frame_token=frame_token)


def framed_command_size(cmd: str) -> int:
    placeholder = "0" * FRAME_TOKEN_HEX_LENGTH
    return len(framed_command(cmd, frame_token=placeholder).encode("utf-8"))


def _expect(
    tn: TelnetClient,
    patterns: list[re.Pattern[bytes]],
    timeout: int,
    debug_dumper=None,
    debug_name: str = "telnet_expect",
) -> tuple[int, bytes]:
    try:
        index, _match, data = tn.expect(
            patterns,
            timeout=timeout,
            max_bytes=MAX_TELNET_EXPECT_BYTES,
        )
    except TelnetOutputLimitExceeded as exc:
        _write_bounded_telnet_dump(
            debug_dumper,
            debug_name,
            exc.captured,
            limit_bytes=MAX_TELNET_EXPECT_BYTES,
            metadata={
                "stage": debug_name,
                "artifact": "raw",
                "transport": "telnet",
                "output_limit_exceeded": True,
                "output_limit_bytes": exc.limit_bytes,
                "bytes_received": exc.bytes_received,
            },
        )
        _close_after_output_limit(tn)
        raise
    if len(data) > MAX_TELNET_EXPECT_BYTES:
        exc = TelnetOutputLimitExceeded(
            MAX_TELNET_EXPECT_BYTES,
            len(data),
            captured=data[:MAX_TELNET_EXPECT_BYTES],
            stage="telnet_expect",
        )
        _write_bounded_telnet_dump(
            debug_dumper,
            debug_name,
            exc.captured,
            limit_bytes=MAX_TELNET_EXPECT_BYTES,
            metadata={
                "stage": debug_name,
                "artifact": "raw",
                "transport": "telnet",
                "output_limit_exceeded": True,
                "output_limit_bytes": exc.limit_bytes,
                "bytes_received": exc.bytes_received,
            },
        )
        _close_after_output_limit(tn)
        raise exc
    if debug_dumper is not None:
        _write_bounded_telnet_dump(
            debug_dumper,
            debug_name,
            data,
            limit_bytes=MAX_TELNET_EXPECT_BYTES,
            metadata={
                "stage": debug_name,
                "artifact": "raw",
                "transport": "telnet",
            },
        )
    return index, data


def _write_bounded_telnet_dump(
    debug_dumper,
    label: str,
    content: bytes,
    *,
    limit_bytes: int,
    metadata: dict[str, object],
) -> None:
    if debug_dumper is None:
        return
    bounded = content[:limit_bytes]
    debug_dumper.write_bytes(
        label,
        "raw",
        bounded,
        metadata={
            **metadata,
            "debug_capture_limit_bytes": limit_bytes,
            "debug_capture_truncated": len(content) > limit_bytes,
        },
    )


def _close_after_output_limit(tn: TelnetClient) -> None:
    try:
        tn.close()
    except Exception:
        pass


def telnet_output_limit_details(
    exc: TelnetOutputLimitExceeded,
) -> dict[str, object]:
    return {
        "output_limit_exceeded": True,
        "output_limit_bytes": exc.limit_bytes,
        "bytes_received": exc.bytes_received,
        "stage": exc.stage,
    }


def telnet_connect(
    ip: str,
    port: int,
    user: str,
    password: str,
    connect_timeout: int = 10,
    prompt_timeout: int = 5,
    debug_dumper=None,
    debug_label: str = "telnet_connect",
) -> TelnetClient:
    try:
        tn = TelnetClient(
            ip,
            port,
            timeout=connect_timeout,
            max_buffer_bytes=MAX_TELNET_COMMAND_OUTPUT_BYTES,
        )
    except OSError as exc:
        raise RuntimeError(str(exc)) from exc

    def fail(message: str):
        try:
            tn.close()
        finally:
            raise RuntimeError(message)

    index, _data = _expect(
        tn,
        [LOGIN_RE, SHELL_PROMPT_RE],
        timeout=prompt_timeout,
        debug_dumper=debug_dumper,
        debug_name=f"{debug_label}_initial",
    )
    if index == -1:
        tn.write(b"\n")
        index, _data = _expect(
            tn,
            [LOGIN_RE, SHELL_PROMPT_RE],
            timeout=prompt_timeout,
            debug_dumper=debug_dumper,
            debug_name=f"{debug_label}_retry",
        )

    if index == 1:
        return tn
    if index != 0:
        fail("Telnet did not reach a login prompt or shell prompt")
    if not user:
        fail("Telnet login prompt detected but no username was provided")

    tn.write(user.encode("utf-8") + b"\n")
    index, _data = _expect(
        tn,
        [PASSWORD_RE, SHELL_PROMPT_RE, LOGIN_RE],
        timeout=prompt_timeout,
        debug_dumper=debug_dumper,
        debug_name=f"{debug_label}_username",
    )
    if index == 0:
        tn.write(password.encode("utf-8") + b"\n")
        index, _data = _expect(
            tn,
            [SHELL_PROMPT_RE, LOGIN_RE, PASSWORD_RE],
            timeout=prompt_timeout,
            debug_dumper=debug_dumper,
            debug_name=f"{debug_label}_password",
        )
        if index != 0:
            fail("Telnet login failed; shell prompt was not reached after password entry")
        return tn
    if index == 1:
        return tn
    fail("Telnet login failed; username was not accepted")


def parse_telnet_command_output(
    data: bytes,
    *,
    frame_token: str,
    last_read_status: str = "",
) -> TelnetCommandResult:
    """Parse one bounded command response using the caller's frame token."""

    start_b, rc_b, end_b = _frame_markers(frame_token)
    payload = data
    returncode: int | None = None
    framing_complete = False
    start_index = data.find(start_b)
    if start_index >= 0:
        framed = data[start_index + len(start_b) :]
        trailer = re.search(
            rb"\r?\n"
            + re.escape(rc_b)
            + rb"([0-9]{1,3})\r?\n"
            + re.escape(end_b)
            + rb"$",
            framed,
        )
        if trailer is not None:
            candidate_returncode = int(trailer.group(1))
            if candidate_returncode <= 255:
                framing_complete = True
                returncode = candidate_returncode
                payload = framed[: trailer.start()]

    text = strip_ansi(payload.decode("utf-8", errors="replace"))
    status = str(last_read_status)
    return TelnetCommandResult(
        stdout=text.strip("\r\n"),
        returncode=returncode if framing_complete else None,
        framing_complete=framing_complete,
        timed_out=not framing_complete and status != "closed",
        connection_closed=not framing_complete and status == "closed",
        raw=payload,
    )


def run_telnet_command(
    tn: TelnetClient,
    cmd: str,
    timeout: int = 20,
    debug_dumper=None,
    debug_name: str = "telnet",
) -> TelnetCommandResult:
    lane_runner = getattr(tn, "run_telnet_command", None)
    if callable(lane_runner):
        return lane_runner(
            cmd,
            timeout=timeout,
            debug_dumper=debug_dumper,
            debug_name=debug_name,
        )
    frame_token = secrets.token_hex(FRAME_TOKEN_BYTES)
    _start_b, _rc_b, end_b = _frame_markers(frame_token)
    full_cmd = framed_command(cmd, frame_token=frame_token)
    if debug_dumper is not None:
        debug_dumper.write_text(
            debug_name,
            "command",
            cmd,
            metadata={
                "stage": debug_name,
                "artifact": "command",
                "transport": "telnet",
                "command_summary": cmd,
            },
        )
    tn.write(full_cmd.encode("utf-8") + b"\n")

    deadline = time.monotonic() + timeout
    data = b""
    try:
        while time.monotonic() < deadline:
            remaining_bytes = MAX_TELNET_COMMAND_OUTPUT_BYTES - len(data)
            if remaining_bytes < 1:
                raise TelnetOutputLimitExceeded(
                    MAX_TELNET_COMMAND_OUTPUT_BYTES,
                    len(data) + 1,
                    captured=data,
                    stage="telnet_command_receive",
                )
            chunk = tn.read_until(
                end_b,
                timeout=max(0.1, deadline - time.monotonic()),
                max_bytes=remaining_bytes,
            )
            if not chunk:
                break
            prospective_size = len(data) + len(chunk)
            if prospective_size > MAX_TELNET_COMMAND_OUTPUT_BYTES:
                raise TelnetOutputLimitExceeded(
                    MAX_TELNET_COMMAND_OUTPUT_BYTES,
                    prospective_size,
                    captured=(data + chunk)[:MAX_TELNET_COMMAND_OUTPUT_BYTES],
                    stage="telnet_command_receive",
                )
            data += chunk
            if end_b in data:
                break
    except TelnetOutputLimitExceeded as exc:
        captured = exc.captured or data[:MAX_TELNET_COMMAND_OUTPUT_BYTES]
        _write_bounded_telnet_dump(
            debug_dumper,
            debug_name,
            captured,
            limit_bytes=MAX_TELNET_COMMAND_OUTPUT_BYTES,
            metadata={
                "stage": debug_name,
                "artifact": "raw",
                "transport": "telnet",
                "command_summary": cmd,
                "output_limit_exceeded": True,
                "output_limit_bytes": exc.limit_bytes,
                "bytes_received": exc.bytes_received,
            },
        )
        _close_after_output_limit(tn)
        raise TelnetOutputLimitExceeded(
            exc.limit_bytes,
            exc.bytes_received,
            captured=captured,
            stage="telnet_command_receive",
        ) from None

    if debug_dumper is not None:
        _write_bounded_telnet_dump(
            debug_dumper,
            debug_name,
            data,
            limit_bytes=MAX_TELNET_COMMAND_OUTPUT_BYTES,
            metadata={
                "stage": debug_name,
                "artifact": "raw",
                "transport": "telnet",
                "command_summary": cmd,
            },
        )
    result = parse_telnet_command_output(
        data,
        frame_token=frame_token,
        last_read_status=str(getattr(tn, "last_read_status", "")),
    )
    if debug_dumper is not None:
        debug_dumper.write_text(
            debug_name,
            "text",
            result.stdout,
            metadata={
                "stage": debug_name,
                "artifact": "text",
                "transport": "telnet",
                "command_summary": cmd,
            },
        )
    return result


def run_telnet_command_text(
    tn: TelnetClient,
    cmd: str,
    timeout: int = 20,
    debug_dumper=None,
    debug_name: str = "telnet",
) -> str:
    """Compatibility text view over :func:`run_telnet_command`."""

    return run_telnet_command(
        tn,
        cmd,
        timeout=timeout,
        debug_dumper=debug_dumper,
        debug_name=debug_name,
    ).stdout


def close_telnet(tn: TelnetClient) -> None:
    release = getattr(tn, "release_telnet_client", None)
    if callable(release):
        release()
        return
    try:
        tn.write(b"exit\n")
        time.sleep(0.2)
    except Exception:
        pass
    try:
        tn.close()
    except Exception:
        pass


# Compatibility names retained for existing public helper scripts.
run_cmd_result = run_telnet_command
run_cmd = run_telnet_command_text


__all__ = [
    "ANSI_RE",
    "DEFAULT_MAX_BUFFER_BYTES",
    "FRAME_TOKEN_BYTES",
    "FRAME_TOKEN_HEX_LENGTH",
    "LOGIN_RE",
    "MAX_TELNET_COMMAND_OUTPUT_BYTES",
    "MAX_TELNET_EXPECT_BYTES",
    "MAX_TELNET_INPUT_BYTES",
    "PASSWORD_RE",
    "SHELL_PROMPT_RE",
    "TELNET_OUTPUT_LIMIT_CODE",
    "TELNET_OUTPUT_LIMIT_RETURN_CODE",
    "TelnetClient",
    "TelnetCommandResult",
    "TelnetOutputLimitExceeded",
    "close_telnet",
    "framed_command",
    "framed_command_size",
    "framed_telnet_command",
    "parse_telnet_command_output",
    "run_cmd",
    "run_cmd_result",
    "run_telnet_command",
    "run_telnet_command_text",
    "strip_ansi",
    "telnet_command_markers",
    "telnet_connect",
    "telnet_output_limit_details",
]
