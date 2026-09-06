#!/usr/bin/env python3
"""Compatibility import for canonical Target Runtime Telnet primitives."""
from __future__ import annotations

import sys

from _minimal_telnet import _RUNTIME_TELNET_MODULE


globals().update(
    {
        name: getattr(_RUNTIME_TELNET_MODULE, name)
        for name in dir(_RUNTIME_TELNET_MODULE)
        if not name.startswith("__")
    }
)
sys.modules[__name__] = _RUNTIME_TELNET_MODULE
