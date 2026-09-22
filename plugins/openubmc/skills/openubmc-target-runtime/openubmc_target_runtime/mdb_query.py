"""Reviewed read-only MDB query grammar shared by Runtime and adapters."""

from __future__ import annotations

from collections.abc import Sequence
import re


_MDB_READ_ONLY_COMMAND_ARITY = {
    "lsclass": (0, 0),
    "lsobj": (1, 1),
    "lsprop": (1, 2),
    "getprop": (3, 3),
    "lsmethod": (1, 2),
    "lsmc": (0, 0),
}
_MDB_SAFE_ARGUMENT_RE = re.compile(
    r"\A[A-Za-z0-9_/][A-Za-z0-9_./:@+-]*\Z", re.ASCII
)
_UINT32_MAX = (1 << 32) - 1
_MAX_ARGUMENT_BYTES = 256
_DECIMAL_ARGUMENT_RE = re.compile(r"\A[0-9]{1,10}\Z", re.ASCII)
MDB_QUERY_CORRECTION = (
    "use reviewed read-only grammar: lsclass | lsobj <class> | "
    "lsprop <object> [interface] | getprop <object> <interface> <property> | "
    "lsmethod <object> [interface] | lsmc | "
    "call <object> <*.BlockIO> Read <offset-high> <offset-low> <length>"
)


def _is_safe_argument(value: str) -> bool:
    return (
        len(value.encode("utf-8")) <= _MAX_ARGUMENT_BYTES
        and _MDB_SAFE_ARGUMENT_RE.fullmatch(value) is not None
    )


def is_read_only_mdb_query(parts: Sequence[str]) -> bool:
    """Return whether command parts match the single Runtime-owned grammar."""

    if parts and parts[0] == "call":
        if len(parts) != 7:
            return False
        _command, object_name, interface, method, *raw_numbers = parts
        if (
            not _is_safe_argument(object_name)
            or not _is_safe_argument(interface)
            or not interface.endswith(".BlockIO")
            or method != "Read"
            or any(
                _DECIMAL_ARGUMENT_RE.fullmatch(value) is None
                for value in raw_numbers
            )
        ):
            return False
        offset_high, offset_low, length = (int(value) for value in raw_numbers)
        return (
            0 <= offset_high <= _UINT32_MAX
            and 0 <= offset_low <= _UINT32_MAX
            and 1 <= length <= 4096
        )
    if not parts or parts[0] not in _MDB_READ_ONLY_COMMAND_ARITY:
        return False
    minimum, maximum = _MDB_READ_ONLY_COMMAND_ARITY[parts[0]]
    arguments = parts[1:]
    return minimum <= len(arguments) <= maximum and all(
        _MDB_SAFE_ARGUMENT_RE.fullmatch(token) is not None for token in arguments
    )
