#!/usr/bin/env python3
"""Check authentication for one required Conan remote without exposing secrets."""

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)

import argparse
import json
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", args.remote):
        parser.error("select one existing remote alias")
    try:
        completed = subprocess.run(
            ["conan", "remote", "auth", args.remote, "-cc", "core:non_interactive=True"],
            capture_output=True, text=True, timeout=120)
        failed = bool(completed.returncode) or bool(re.search(
            r"(?:^|\s)error:|wrong user|wrong password|authentication (?:error|failed)|interactive mode disabled",
            completed.stdout + "\n" + completed.stderr, flags=re.IGNORECASE))
    except (OSError, subprocess.TimeoutExpired):
        failed = True
    print(json.dumps({"status": "failed" if failed else "passed", "remote": args.remote}))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
