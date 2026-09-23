#!/usr/bin/env python3
"""Record a conversation-confirmed BMC-to-OS address association locally."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import ipaddress
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "openubmc-target-runtime"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from openubmc_target_runtime.configuration import (
    ConfigurationConflict,
    ConfigurationError,
    LocalConfigurationStore,
    device_associations,
)
from openubmc_target_runtime.credential_file import CredentialFileError, read_private_text
from openubmc_target_runtime.credentials import CredentialConfigurationError, LocalCredentialSource
from config_page import import_legacy_targets


class ExistingAssociationConflict(ConfigurationConflict):
    def __init__(self, existing_os_ip: str):
        super().__init__("BMC already has a different OS association")
        self.existing_os_ip = existing_os_ip


def associate_device(*, bmc_ip: str, os_ip: str,
                     replace_existing: bool = False,
                     expected_os_ip: str | None = None,
                     source_path: Path | None = None) -> dict[str, object]:
    try:
        bmc = str(ipaddress.ip_address(bmc_ip))
        os_host = str(ipaddress.ip_address(os_ip))
    except ValueError:
        raise ConfigurationError("Both targets must be literal IP addresses") from None
    if bmc == os_host:
        raise ConfigurationError("BMC and OS addresses must differ")
    if replace_existing != (expected_os_ip is not None):
        raise ConfigurationError("Replacement requires the confirmed old OS IP")
    if expected_os_ip is not None:
        try:
            expected_os_ip = str(ipaddress.ip_address(expected_os_ip))
        except ValueError:
            raise ConfigurationError("The old OS address must be a literal IP") from None

    source = LocalCredentialSource(config_path=source_path).select_path()
    if source is None:
        config_home = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        source = config_home / "openubmc" / "credentials.json"
    store = LocalConfigurationStore(source, kind="targets")
    status = store.status()
    if status["revision"] != status["active_revision"]:
        raise ConfigurationConflict("A saved draft is pending activation")
    source_text = None
    if status["active_revision"] is not None:
        config = store.read_active()
    elif source.exists() or source.is_symlink():
        source_text = read_private_text(source, max_bytes=1024 * 1024)
        config = (json.loads(source_text) if source_text.lstrip().startswith("{")
                  else import_legacy_targets(source_text))
    else:
        config = {"schema_version": 1}
    associations = device_associations(config)
    if replace_existing and bmc not in associations:
        raise ConfigurationConflict("The confirmed old association is no longer present")
    if bmc in associations:
        if replace_existing and associations[bmc] != expected_os_ip:
            raise ExistingAssociationConflict(associations[bmc])
        if associations[bmc] != os_host:
            if not replace_existing:
                raise ExistingAssociationConflict(associations[bmc])
        else:
            return {"associated": True, "changed": False, "bmc_ip": bmc,
                    "os_ip": os_host, "revision": status["active_revision"]}
    device_key = next((key for key in config.get("devices", {})
                       if str(ipaddress.ip_address(key)) == bmc), bmc)
    config.setdefault("devices", {})[device_key] = {"os_ip": os_host}
    committed = store.save_and_activate(
        config, expected_revision=status["revision"],
        expected_active_revision=status["active_revision"],
        expected_source_text=source_text,
    )
    return {"associated": True, "changed": True, "bmc_ip": bmc,
            "os_ip": os_host, "revision": committed["active_revision"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bmc-ip", required=True)
    parser.add_argument("--os-ip", required=True)
    parser.add_argument("--confirm-same-device", action="store_true")
    parser.add_argument("--replace-existing", action="store_true")
    parser.add_argument("--expected-os-ip")
    parser.add_argument("--source", type=Path)
    args = parser.parse_args(argv)
    if not args.confirm_same_device:
        print(json.dumps({"associated": False, "code": "confirmation_required"}))
        return 2
    try:
        result = associate_device(bmc_ip=args.bmc_ip, os_ip=args.os_ip,
                                  replace_existing=args.replace_existing,
                                  expected_os_ip=args.expected_os_ip,
                                  source_path=args.source)
    except ExistingAssociationConflict as conflict:
        result = {"associated": False, "code": "association_conflict",
                  "existing_os_ip": conflict.existing_os_ip}
    except ConfigurationConflict:
        result = {"associated": False, "code": "configuration_conflict"}
    except CredentialConfigurationError as error:
        result = {"associated": False, "code": error.code}
    except CredentialFileError:
        result = {"associated": False, "code": "configuration_invalid"}
    except (ConfigurationError, ValueError, TypeError):
        result = {"associated": False, "code": "configuration_invalid"}
    except Exception:
        result = {"associated": False, "code": "local_operation_failed"}
    print(json.dumps(result, ensure_ascii=True))
    return 0 if result["associated"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
