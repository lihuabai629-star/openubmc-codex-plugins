#!/usr/bin/env python3
"""Shared CLI helpers for openUBMC remote scripts."""
from __future__ import annotations

from collections.abc import Mapping
import argparse
import os
import stat
from pathlib import Path


SSH_USER_ENV = "OPENUBMC_SSH_USER"
SSH_PASSWORD_ENV = "OPENUBMC_SSH_PASSWORD"
TELNET_USER_ENV = "OPENUBMC_TELNET_USER"
TELNET_PASSWORD_ENV = "OPENUBMC_TELNET_PASSWORD"
OS_IP_ENV = "OPENUBMC_OS_IP"
OS_SSH_USER_ENV = "OPENUBMC_OS_SSH_USER"
OS_SSH_PASSWORD_ENV = "OPENUBMC_OS_SSH_PASSWORD"
OS_SSH_PORT_ENV = "OPENUBMC_OS_SSH_PORT"
REDFISH_USERNAME_ENV = "REDFISH_USERNAME"
REDFISH_PASSWORD_ENV = "REDFISH_PASSWORD"
GENERAL_CREDENTIALS_FILE_ENV = "OPENUBMC_CREDENTIALS_FILE"
CREDENTIALS_FILE_ENV = "OPENUBMC_DEBUG_CREDENTIALS_FILE"
CREDENTIALS_FILE_ENVS = (
    GENERAL_CREDENTIALS_FILE_ENV,
    CREDENTIALS_FILE_ENV,
)
CREDENTIALS_FILE_MAX_BYTES = 64 * 1024
DEVELOPMENT_MODE_ENV = "OPENUBMC_DEBUG_DEVELOPMENT_MODE"
PASSWORD_KEY = "password"
IDENTITY_FILE_KEY = "identity_file"
ALLOWED_CREDENTIAL_KEYS = frozenset(
    {
        SSH_USER_ENV,
        SSH_PASSWORD_ENV,
        TELNET_USER_ENV,
        TELNET_PASSWORD_ENV,
        OS_IP_ENV,
        OS_SSH_USER_ENV,
        OS_SSH_PASSWORD_ENV,
        OS_SSH_PORT_ENV,
        REDFISH_USERNAME_ENV,
        REDFISH_PASSWORD_ENV,
    }
)


def add_context_runtime_arguments(parser: argparse.ArgumentParser) -> None:
    """Add transport-only Case controls shared by compatibility CLIs."""

    group = parser.add_argument_group("Context Runtime")
    group.add_argument(
        "--case-id",
        default="",
        help="Resume an existing persistent Case instead of opening a new one",
    )
    group.add_argument(
        "--expected-revision",
        type=int,
        default=None,
        help="Optional optimistic Case revision check",
    )
    group.add_argument(
        "--idempotency-key",
        default="",
        help="Replay the same completed operation without recollecting evidence",
    )
    group.add_argument(
        "--task-id",
        default="",
        help="Transport task identity; defaults to CODEX_TASK_ID or a generated value",
    )
    group.add_argument(
        "--operation-id",
        default="",
        help="Operation identity; defaults to the idempotency key or a generated value",
    )


def development_mode_enabled() -> bool:
    return True


def _parse_credentials_value(value: str, *, line_number: int) -> str:
    cooked = value.strip()
    if "\x00" in cooked:
        raise SystemExit(
            f"credentials file contains an invalid value on line {line_number}"
        )
    if not cooked:
        return ""
    if cooked[0] in {"'", '"'}:
        if len(cooked) < 2 or cooked[-1] != cooked[0]:
            raise SystemExit(
                "credentials file contains a malformed quoted value "
                f"on line {line_number}"
            )
        return cooked[1:-1]
    if cooked[-1] in {"'", '"'}:
        raise SystemExit(
            "credentials file contains a malformed quoted value "
            f"on line {line_number}"
        )
    return cooked


def _selected_credentials_file() -> Path | None:
    selected: list[tuple[str, Path]] = []
    for env_name in CREDENTIALS_FILE_ENVS:
        if env_name not in os.environ:
            continue
        raw_path = os.environ[env_name]
        if not raw_path.strip():
            raise SystemExit(f"{env_name} must not be empty")
        expanded = Path(raw_path).expanduser()
        normalized = Path(os.path.abspath(os.fspath(expanded)))
        selected.append((env_name, normalized))

    if not selected:
        return None
    if len({path for _, path in selected}) != 1:
        raise SystemExit(
            "OPENUBMC_CREDENTIALS_FILE and OPENUBMC_DEBUG_CREDENTIALS_FILE "
            "must reference the same file when both are set"
        )
    return selected[0][1]


def load_credentials_file() -> dict[str, str]:
    """Parse an explicitly selected credentials file without mutating the environment."""
    path = _selected_credentials_file()
    if path is None:
        return {}
    if path.is_symlink():
        raise SystemExit(f"credentials file must not be a symbolic link: {path}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        file_descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise SystemExit(f"credentials file does not exist: {path}") from None
    except OSError:
        raise SystemExit(f"credentials file could not be opened safely: {path}") from None

    try:
        file_stat = os.fstat(file_descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise SystemExit(f"credentials path is not a regular file: {path}")
        if file_stat.st_size > CREDENTIALS_FILE_MAX_BYTES:
            raise SystemExit(
                "credentials file exceeds the maximum supported size: "
                f"{path}"
            )
        if hasattr(os, "getuid") and file_stat.st_uid != os.getuid():
            raise SystemExit(
                f"credentials file must be owned by the current user: {path}"
            )
        mode = stat.S_IMODE(file_stat.st_mode)
        if mode & 0o077:
            raise SystemExit(
                "credentials file permissions must be 0600 or stricter: "
                f"{path} (mode {mode:04o})"
            )
        with os.fdopen(file_descriptor, "rb", closefd=False) as stream:
            raw_content = stream.read(CREDENTIALS_FILE_MAX_BYTES + 1)
        if len(raw_content) > CREDENTIALS_FILE_MAX_BYTES:
            raise SystemExit(
                "credentials file exceeds the maximum supported size: "
                f"{path}"
            )
    except OSError:
        raise SystemExit(f"credentials file could not be read safely: {path}") from None
    finally:
        os.close(file_descriptor)

    try:
        content = raw_content.decode("utf-8")
    except UnicodeDecodeError:
        raise SystemExit("credentials file must contain valid UTF-8 text") from None

    parsed: dict[str, str] = {}
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            raise SystemExit(
                "credentials file entries must use KEY=VALUE syntax "
                f"(line {line_number})"
            )
        key, value = stripped.split("=", 1)
        key = key.strip()
        if key not in ALLOWED_CREDENTIAL_KEYS:
            raise SystemExit(
                f"credentials file contains an unsupported key on line {line_number}"
            )
        parsed_value = _parse_credentials_value(value, line_number=line_number)
        if key in parsed and parsed[key] != parsed_value:
            raise SystemExit(
                "credentials file contains a conflicting duplicate key "
                f"on line {line_number}"
            )
        parsed[key] = parsed_value

    return parsed


def _value_from_sources(
    env_name: str,
    credentials: Mapping[str, str],
) -> tuple[bool, str]:
    if env_name in os.environ:
        return True, os.environ[env_name]
    if env_name in credentials:
        return True, credentials[env_name]
    return False, ""


def resolve_value(
    default_value: str,
    env_name: str,
    label: str,
    fallback_env_names: tuple[str, ...] = (),
    *,
    credentials: Mapping[str, str] | None = None,
) -> str:
    file_values = load_credentials_file() if credentials is None else credentials
    if file_values.get("__runtime_selected__") == "1":
        from _target_runtime_adapter import _load_runtime_module
        _load_runtime_module()
        from openubmc_target_runtime.credential_file import selected_credential_value
        if not env_name and default_value:
            return default_value
        selected = selected_credential_value(file_values, (env_name,) if env_name else fallback_env_names)
        if selected is not None:
            return selected
    if env_name:
        found, value = _value_from_sources(env_name, file_values)
        if not found:
            raise SystemExit(f"{label} environment variable {env_name} is not set")
        return value
    if default_value:
        return default_value
    for fallback_env_name in fallback_env_names:
        if fallback_env_name in os.environ:
            return os.environ[fallback_env_name]
    for fallback_env_name in fallback_env_names:
        if fallback_env_name in file_values:
            return file_values[fallback_env_name]
    return default_value


def _arg_value(args, name: str, default=""):
    if args is None:
        return default
    return getattr(args, name, default)


def resolve_int_value(
    default_value: str | int,
    env_name: str,
    label: str,
    fallback_env_names: tuple[str, ...] = (),
    fallback_default: int = 22,
    *,
    credentials: Mapping[str, str] | None = None,
) -> int:
    raw = resolve_value(
        str(default_value) if default_value not in ("", None) else "",
        env_name,
        label,
        fallback_env_names,
        credentials=credentials,
    )
    if raw == "":
        return fallback_default
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(f"{label} must be an integer: {raw}") from exc
    if value < 1 or value > 65535:
        raise SystemExit(f"{label} must be between 1 and 65535: {raw}")
    return value


def resolve_ssh_credentials(args) -> dict[str, str | int]:
    credentials = load_credentials_file()
    return {
        "user": resolve_value(
            _arg_value(args, "ssh_user"),
            _arg_value(args, "ssh_user_env"),
            "SSH user",
            (SSH_USER_ENV,),
            credentials=credentials,
        ),
        PASSWORD_KEY: resolve_value(
            _arg_value(args, "ssh_password") if development_mode_enabled() else "",
            _arg_value(args, "ssh_password_env"),
            "SSH password",
            (SSH_PASSWORD_ENV,),
            credentials=credentials,
        ),
        "port": _arg_value(args, "ssh_port", 22),
        IDENTITY_FILE_KEY: _arg_value(args, "ssh_identity_file"),
    }

def resolve_telnet_credentials(args) -> dict[str, str | int]:
    credentials = load_credentials_file()
    return {
        "user": resolve_value(
            _arg_value(args, "telnet_user"),
            _arg_value(args, "telnet_user_env"),
            "Telnet user",
            (TELNET_USER_ENV,),
            credentials=credentials,
        ),
        PASSWORD_KEY: resolve_value(
            _arg_value(args, "telnet_password") if development_mode_enabled() else "",
            _arg_value(args, "telnet_password_env"),
            "Telnet password",
            (TELNET_PASSWORD_ENV,),
            credentials=credentials,
        ),
        "port": _arg_value(args, "telnet_port", 23),
    }


def resolve_debug_credentials(
    args,
    *,
    include_telnet: bool = True,
    credentials: Mapping[str, str] | None = None,
) -> dict[str, dict[str, str | int]]:
    """Resolve the combined Debug credential source exactly once."""

    credential_values = (
        load_credentials_file() if credentials is None else dict(credentials)
    )
    ssh = {
        "user": resolve_value(
            _arg_value(args, "ssh_user"),
            _arg_value(args, "ssh_user_env"),
            "SSH user",
            (SSH_USER_ENV,),
            credentials=credential_values,
        ),
        PASSWORD_KEY: resolve_value(
            _arg_value(args, "ssh_password") if development_mode_enabled() else "",
            _arg_value(args, "ssh_password_env"),
            "SSH password",
            (SSH_PASSWORD_ENV,),
            credentials=credential_values,
        ),
        "port": _arg_value(args, "ssh_port", 22),
        IDENTITY_FILE_KEY: _arg_value(args, "ssh_identity_file") or credential_values.get("OPENUBMC_SSH_IDENTITY_FILE", ""),
    }
    telnet = {
        "user": "",
        PASSWORD_KEY: "",
        "port": _arg_value(args, "telnet_port", 23),
    }
    if include_telnet:
        telnet = {
            "user": resolve_value(
                _arg_value(args, "telnet_user"),
                _arg_value(args, "telnet_user_env"),
                "Telnet user",
                (TELNET_USER_ENV,),
                credentials=credential_values,
            ),
            PASSWORD_KEY: resolve_value(
                _arg_value(args, "telnet_password") if development_mode_enabled() else "",
                _arg_value(args, "telnet_password_env"),
                "Telnet password",
                (TELNET_PASSWORD_ENV,),
                credentials=credential_values,
            ),
            "port": _arg_value(args, "telnet_port", 23),
        }
    return {"ssh": ssh, "telnet": telnet}


def resolve_os_access(args=None) -> dict[str, str | int]:
    credentials = load_credentials_file()
    return {
        "ip": resolve_value(
            _arg_value(args, "os_ip"),
            _arg_value(args, "os_ip_env"),
            "OS IP",
            (OS_IP_ENV,),
            credentials=credentials,
        ),
        "user": resolve_value(
            _arg_value(args, "os_ssh_user"),
            _arg_value(args, "os_ssh_user_env"),
            "OS SSH user",
            (OS_SSH_USER_ENV,),
            credentials=credentials,
        ),
        PASSWORD_KEY: resolve_value(
            _arg_value(args, "os_ssh_password") if development_mode_enabled() else "",
            _arg_value(args, "os_ssh_password_env"),
            "OS SSH password",
            (OS_SSH_PASSWORD_ENV,),
            credentials=credentials,
        ),
        "port": resolve_int_value(
            _arg_value(args, "os_ssh_port"),
            _arg_value(args, "os_ssh_port_env"),
            "OS SSH port",
            (OS_SSH_PORT_ENV,),
            fallback_default=22,
            credentials=credentials,
        ),
    }
