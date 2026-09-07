#!/usr/bin/env python3
"""Validate a Redfish target and mode-0600 credential file without secrets."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit

TARGET_RUNTIME_API_VERSION = "openubmc.target-runtime.v1"
local_loader = Path(__file__).resolve().with_name("_runtime_loader.py")
loader_path = (
    local_loader
    if local_loader.is_file()
    else Path(__file__).resolve().parents[2]
    / "openubmc-target-runtime"
    / "tools"
    / "runtime_loader.py"
)
spec = importlib.util.spec_from_file_location(
    "_openubmc_upgrade_credentials_runtime_loader",
    loader_path,
)
if spec is None or spec.loader is None:
    raise ImportError("Target Runtime loader is unavailable")
loader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loader)
try:
    _runtime = loader.load_runtime_module(
        Path(__file__), expected_api=TARGET_RUNTIME_API_VERSION
    )
except RuntimeError as exc:
    raise SystemExit(str(exc)) from None
ALLOWED_CREDENTIAL_KEYS = _runtime.ALLOWED_CREDENTIAL_KEYS
ResolvedRedfishCredentials = _runtime.ResolvedRedfishCredentials
read_credentials_file = _runtime.read_credentials_file


Credentials = ResolvedRedfishCredentials


def target_origin(raw: str) -> str:
    parsed = urlsplit(raw)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("target must be an HTTPS URL with a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("target URL must not contain credentials")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("target must be an HTTPS origin without a path or query")
    try:
        host = str(ipaddress.ip_address(parsed.hostname))
    except ValueError:
        host = parsed.hostname.rstrip(".").lower()
    port = parsed.port or 443
    rendered = f"[{host}]" if ":" in host else host
    return f"https://{rendered}:{port}"


def load_credentials(path: Path) -> Credentials:
    values = read_credentials_file(path, allowed_keys=ALLOWED_CREDENTIAL_KEYS)
    if not values.get("REDFISH_USERNAME") or not values.get("REDFISH_PASSWORD"):
        raise ValueError("credentials file requires non-empty REDFISH_USERNAME and REDFISH_PASSWORD")
    return Credentials(
        user=values["REDFISH_USERNAME"],
        password=values["REDFISH_PASSWORD"],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--credentials-file", default=os.environ.get("OPENUBMC_CREDENTIALS_FILE", ""))
    args = parser.parse_args()
    try:
        if not args.credentials_file:
            raise ValueError("OPENUBMC_CREDENTIALS_FILE is not configured")
        origin = target_origin(args.target)
        credentials = load_credentials(Path(args.credentials_file))
        print(
            json.dumps(
                {
                    "ok": True,
                    "target": origin,
                    "credentials_file": str(Path(args.credentials_file).absolute()),
                    "username_present": bool(credentials.username),
                    "password_present": bool(credentials.password),
                },
                sort_keys=True,
            )
        )
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
