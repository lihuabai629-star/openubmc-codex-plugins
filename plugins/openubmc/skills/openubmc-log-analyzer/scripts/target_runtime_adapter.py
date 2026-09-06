#!/usr/bin/env python3
"""Compatibility import for the public Log Analyzer Runtime backend."""
from __future__ import annotations

from pathlib import Path
import sys


_SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))

from openubmc_log_analyzer import runtime_backend as _runtime_backend


# Preserve module-level monkeypatching and private compatibility names for callers
# that still import ``scripts/target_runtime_adapter.py`` directly.
globals().update(
    {
        name: getattr(_runtime_backend, name)
        for name in dir(_runtime_backend)
        if not name.startswith("__")
    }
)
sys.modules[__name__] = _runtime_backend
