"""Canonical mode-bounded credential-file parsing for openUBMC domain tools."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import os
from pathlib import Path
import stat


GENERAL_CREDENTIALS_FILE_ENV = "OPENUBMC_CREDENTIALS_FILE"
DEBUG_CREDENTIALS_FILE_ENV = "OPENUBMC_DEBUG_CREDENTIALS_FILE"
CREDENTIALS_FILE_MAX_BYTES = 64 * 1024
ALLOWED_CREDENTIAL_KEYS = frozenset(
    {
        "OPENUBMC_SSH_USER",
        "OPENUBMC_SSH_PASSWORD",
        "OPENUBMC_TELNET_USER",
        "OPENUBMC_TELNET_PASSWORD",
        "OPENUBMC_OS_IP",
        "OPENUBMC_OS_SSH_USER",
        "OPENUBMC_OS_SSH_PASSWORD",
        "OPENUBMC_OS_SSH_PORT",
        "REDFISH_USERNAME",
        "REDFISH_PASSWORD",
    }
)


class CredentialFileError(ValueError):
    """Credential source could not be read without weakening its local boundary."""


def _parse_value(value: str, *, line_number: int) -> str:
    cooked = value.strip()
    if "\x00" in cooked:
        raise CredentialFileError(
            f"credentials file contains an invalid value on line {line_number}"
        )
    if not cooked:
        return ""
    if cooked[0] in {"'", '"'}:
        if len(cooked) < 2 or cooked[-1] != cooked[0]:
            raise CredentialFileError(
                "credentials file contains a malformed quoted value "
                f"on line {line_number}"
            )
        return cooked[1:-1]
    if cooked[-1] in {"'", '"'}:
        raise CredentialFileError(
            "credentials file contains a malformed quoted value "
            f"on line {line_number}"
        )
    return cooked


def read_credentials_file(
    path: Path,
    *,
    allowed_keys: frozenset[str] = ALLOWED_CREDENTIAL_KEYS,
    max_bytes: int = CREDENTIALS_FILE_MAX_BYTES,
) -> dict[str, str]:
    """Read one regular, current-user credential file without following links."""

    normalized = Path(os.path.abspath(os.fspath(path.expanduser())))
    if normalized.is_symlink():
        raise CredentialFileError(
            f"credentials file must not be a symbolic link: {normalized}"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(normalized, flags)
    except FileNotFoundError:
        raise CredentialFileError(
            f"credentials file does not exist: {normalized}"
        ) from None
    except OSError:
        raise CredentialFileError(
            f"credentials file could not be opened safely: {normalized}"
        ) from None

    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise CredentialFileError(
                f"credentials path is not a regular file: {normalized}"
            )
        if info.st_size > max_bytes:
            raise CredentialFileError(
                "credentials file exceeds the maximum supported size: "
                f"{normalized}"
            )
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise CredentialFileError(
                f"credentials file must be owned by the current user: {normalized}"
            )
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o077:
            raise CredentialFileError(
                "credentials file permissions must be 0600 or stricter: "
                f"{normalized} (mode {mode:04o})"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise CredentialFileError(
                "credentials file exceeds the maximum supported size: "
                f"{normalized}"
            )
    except OSError:
        raise CredentialFileError(
            f"credentials file could not be read safely: {normalized}"
        ) from None
    finally:
        os.close(descriptor)

    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise CredentialFileError(
            "credentials file must contain valid UTF-8 text"
        ) from None

    parsed: dict[str, str] = {}
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise CredentialFileError(
                "credentials file entries must use KEY=VALUE syntax "
                f"(line {line_number})"
            )
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in allowed_keys:
            raise CredentialFileError(
                f"credentials file contains an unsupported key on line {line_number}"
            )
        parsed_value = _parse_value(value, line_number=line_number)
        if key in parsed and parsed[key] != parsed_value:
            raise CredentialFileError(
                "credentials file contains a conflicting duplicate key "
                f"on line {line_number}"
            )
        parsed[key] = parsed_value
    return parsed


def selected_credentials_path(
    environ: Mapping[str, str] | None = None,
    *,
    env_names: Sequence[str] = (
        GENERAL_CREDENTIALS_FILE_ENV,
        DEBUG_CREDENTIALS_FILE_ENV,
    ),
) -> Path | None:
    source = os.environ if environ is None else environ
    selected: list[tuple[str, Path]] = []
    for env_name in env_names:
        if env_name not in source:
            continue
        raw_path = source[env_name]
        if not raw_path.strip():
            raise CredentialFileError(f"{env_name} must not be empty")
        selected.append(
            (
                env_name,
                Path(os.path.abspath(os.fspath(Path(raw_path).expanduser()))),
            )
        )
    if not selected:
        return None
    if len({path for _, path in selected}) != 1:
        names = " and ".join(name for name, _ in selected)
        raise CredentialFileError(
            f"{names} must reference the same file when both are set"
        )
    return selected[0][1]


def load_selected_credentials_file(
    environ: Mapping[str, str] | None = None,
    *,
    env_names: Sequence[str] = (
        GENERAL_CREDENTIALS_FILE_ENV,
        DEBUG_CREDENTIALS_FILE_ENV,
    ),
    allowed_keys: frozenset[str] = ALLOWED_CREDENTIAL_KEYS,
) -> dict[str, str]:
    path = selected_credentials_path(environ, env_names=env_names)
    if path is None:
        return {}
    return read_credentials_file(path, allowed_keys=allowed_keys)
