#!/usr/bin/env python3
"""Narrow Win32 filesystem and process probes for the packaged KB process.

Only paths and process IDs cross this boundary. Credential and token bytes stay
in the Node process that owns them.
"""
from __future__ import annotations

import json
from pathlib import Path
import runpy
import sys

PACKAGE = Path(__file__).resolve().parents[1]/"openubmc_target_runtime"
_private = runpy.run_path(str(PACKAGE/"windows_private.py"))
_lifecycle = runpy.run_path(str(PACKAGE/"mcp_lifecycle.py"))
ensure_private_directory = _private["ensure_private_directory"]
harden_new_file = _private["harden_new_file"]
verify_private_path = _private["verify_private_path"]
_windows_process_state = _lifecycle["_windows_process_state"]


def main() -> int:
    if sys.platform != "win32" or len(sys.argv) != 3:
        return 2
    action, argument = sys.argv[1:]
    try:
        if action == "ensure-directory":
            ensure_private_directory(Path(argument))
        elif action == "verify-path":
            verify_private_path(Path(argument))
        elif action == "harden-file":
            harden_new_file(Path(argument))
        elif action == "process-state":
            pid = int(argument)
            alive, identity = _windows_process_state(pid)
            print(json.dumps({"alive": alive, "identity": identity}))
            return 0
        else:
            return 2
    except (OSError, ValueError):
        return 2
    print('{"ok":true}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
