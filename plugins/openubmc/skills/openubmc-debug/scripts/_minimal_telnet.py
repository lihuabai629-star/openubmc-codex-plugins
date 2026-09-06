#!/usr/bin/env python3
"""Compatibility import for the canonical Target Runtime Telnet client."""
from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path
import sys


_MODULE_NAME = "_openubmc_target_runtime_telnet_primitives"


def _load_runtime_telnet_module():
    cached = sys.modules.get(_MODULE_NAME)
    if cached is not None:
        return cached

    scripts = Path(__file__).resolve().parent
    candidates = (
        scripts / "_vendor" / "openubmc_target_runtime" / "telnet.py",
        scripts.parents[1]
        / "openubmc-target-runtime"
        / "openubmc_target_runtime"
        / "telnet.py",
    )
    for path in candidates:
        if not path.is_file():
            continue
        spec = importlib.util.spec_from_file_location(_MODULE_NAME, path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[_MODULE_NAME] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(_MODULE_NAME, None)
            raise
        return module

    return importlib.import_module("openubmc_target_runtime.telnet")


_RUNTIME_TELNET_MODULE = _load_runtime_telnet_module()
globals().update(
    {
        name: getattr(_RUNTIME_TELNET_MODULE, name)
        for name in dir(_RUNTIME_TELNET_MODULE)
        if not name.startswith("__")
    }
)
