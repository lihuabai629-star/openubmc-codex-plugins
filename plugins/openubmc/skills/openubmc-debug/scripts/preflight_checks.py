#!/usr/bin/env python3
"""Compatibility entrypoint for the typed preflight checks implementation."""
from __future__ import annotations

import functools
import importlib.util
import inspect
from pathlib import Path
import sys


_IMPL_PATH = Path(__file__).resolve().with_name("_preflight_checks.py")
_IMPL_NAME = "_openubmc_debug_preflight_checks"
_INTERNAL_NAMES = {
    "_impl",
    "_spec",
    "_IMPL_PATH",
    "_IMPL_NAME",
    "_INTERNAL_NAMES",
    "_make_proxy",
    "_sync_patched_globals",
    "functools",
    "importlib",
    "inspect",
    "Path",
    "sys",
}

if str(_IMPL_PATH.parent) not in sys.path:
    sys.path.insert(0, str(_IMPL_PATH.parent))
_spec = importlib.util.spec_from_file_location(_IMPL_NAME, _IMPL_PATH)
if _spec is None or _spec.loader is None:
    raise ImportError(f"cannot load implementation: {_IMPL_PATH}")
_impl = importlib.util.module_from_spec(_spec)
sys.modules[_IMPL_NAME] = _impl
_spec.loader.exec_module(_impl)


def _sync_patched_globals() -> None:
    for _name, _value in list(globals().items()):
        if _name in _INTERNAL_NAMES or _name.startswith("__"):
            continue
        if getattr(_value, "__openubmc_proxy_name__", None) == _name:
            continue
        if hasattr(_impl, _name):
            setattr(_impl, _name, _value)


def _make_proxy(_name: str):
    _target = getattr(_impl, _name)

    @functools.wraps(_target)
    def _proxy(*args, **kwargs):
        _sync_patched_globals()
        return getattr(_impl, _name)(*args, **kwargs)

    _proxy.__openubmc_proxy_name__ = _name
    return _proxy


for _name in dir(_impl):
    if _name.startswith("__"):
        continue
    _value = getattr(_impl, _name)
    globals()[_name] = _make_proxy(_name) if inspect.isfunction(_value) else _value


def main() -> int:
    """Validate that the legacy import entrypoint can still be executed."""

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
