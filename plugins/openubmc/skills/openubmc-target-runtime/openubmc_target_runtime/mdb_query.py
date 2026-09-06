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
MDB_QUERY_CORRECTION = (
    "use reviewed read-only grammar: lsclass | lsobj <class> | "
    "lsprop <object> [interface] | getprop <object> <interface> <property> | "
    "lsmethod <object> [interface] | lsmc"
)


def is_read_only_mdb_query(parts: Sequence[str]) -> bool:
    """Return whether command parts match the single Runtime-owned grammar."""

    if not parts or parts[0] not in _MDB_READ_ONLY_COMMAND_ARITY:
        return False
    minimum, maximum = _MDB_READ_ONLY_COMMAND_ARITY[parts[0]]
    arguments = parts[1:]
    return minimum <= len(arguments) <= maximum and all(
        _MDB_SAFE_ARGUMENT_RE.fullmatch(token) is not None for token in arguments
    )
