#!/usr/bin/env python3
"""Current-user local configuration page for Linux and WSL."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)

import argparse
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import shutil
import subprocess
import socket
import sys
import threading
import time
from urllib.parse import urlsplit
import webbrowser

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "openubmc-target-runtime"))
from openubmc_target_runtime.configuration import (
    LocalConfigurationStore,
    ConfigurationError,
    ConfigurationConflict,
)
from openubmc_target_runtime.credential_file import (
    read_private_text,
    parse_credentials_text,
    selected_credential_value,
)


def _masked(config):
    value = copy.deepcopy(config)
    records = [value, *value.get("credentials", {}).values()]
    for record in records:
        for name in ("password", "clientSecret"):
            if name in record:
                record[name + "_set"] = bool(record.pop(name))
    return value


def _secret_edits(config, previous):
    value = copy.deepcopy(config)
    pairs = [(value, previous)]
    pairs += [
        (record, previous.get("credentials", {}).get(name, {}))
        for name, record in value.get("credentials", {}).items()
    ]
    for record, old in pairs:
        for name in ("password", "clientSecret"):
            record.pop(name + "_set", None)
            if name not in record and name not in old:
                continue
            edit = record.get(name, {"action": "keep"})
            if not isinstance(edit, dict) or edit.get("action") not in {
                "keep",
                "replace",
                "remove",
            }:
                raise ConfigurationError(
                    "Choose keep, replace or remove for secret fields"
                )
            if edit["action"] == "replace":
                if not isinstance(edit.get("value"), str):
                    raise ConfigurationError("A replacement secret must be text")
                record[name] = edit["value"]
            elif edit["action"] == "keep":
                selected = old
                if "source" in edit:
                    source = edit["source"]
                    if not isinstance(source, str) or source not in previous.get(
                        "credentials", {}
                    ):
                        raise ConfigurationConflict(
                            "Original credential record is unavailable"
                        )
                    selected = previous["credentials"][source]
                record[name] = selected.get(name, "")
            else:
                record[name] = ""
    return value


def import_legacy_targets(text):
    values = parse_credentials_text(text)
    config = {"schema_version": 1, "credentials": {}, "defaults": {}}
    for purpose, transport in (("bmc", "ssh"), ("bmc", "redfish"), ("os", "ssh")):
        prefix = "OPENUBMC_" + ("OS_" if purpose == "os" else "") + transport.upper()
        record = {}
        for field in ("user", "password", "identity_file"):
            names = [prefix + "_" + field.upper()]
            if (
                purpose == "bmc"
                and transport == "redfish"
                and field in {"user", "password"}
            ):
                names.append(
                    "REDFISH_" + ("USERNAME" if field == "user" else "PASSWORD")
                )
            record[field] = selected_credential_value(values, names, environ={}) or ""
        if any(record.values()):
            name = purpose + "-" + transport
            config["credentials"][name] = record
            config["defaults"].setdefault(purpose, {})[transport] = name
    return config


class PluginMaintenance:
    """Bounded local operations through the immutable plugin CLI."""

    def __init__(self, plugin_root, *, environment=None, timeout=660):
        self.root = Path(plugin_root)
        self.timeout = timeout
        self.environment = dict(os.environ if environment is None else environment)
        self.home = Path(self.environment.get("HOME", str(Path.home())))
        self.codex = Path(self.environment.get("CODEX_HOME", str(self.home/".codex")))
        self.preview_id = None
        self.preview_config = None
        self.transaction = None

    def command(self, *arguments):
        process = subprocess.Popen(
            [sys.executable, "-I", "-B", str(self.root/"scripts/pluginctl.py"),
             *arguments, "--home", str(self.home), "--codex-home", str(self.codex)],
            env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=self.timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            finally:
                process.stdout.close()
                process.stderr.close()
            raise
        try:
            value = json.loads(stdout or stderr)
        except ValueError:
            raise ValueError("plugin_operation_failed") from None
        if process.returncode not in (0, 2) or not isinstance(value, dict):
            raise ValueError("plugin_operation_failed")
        return value

    def config_bytes(self):
        path = self.codex/"config.toml"
        if path.is_symlink():
            raise ConfigurationConflict("configuration_conflict")
        return path.read_bytes() if path.exists() else b""

    def dispatch(self, data):
        action = data.get("action")
        if action == "status":
            report = self.command("doctor")
            config = report.get("codex_configuration", {})
            return {
                "version": report.get("version"),
                "integrity": report.get("package_integrity", False),
                "runtime": report.get("capabilities", {}).get("runtime", {}).get("startup_ready", False),
                "kb": report.get("capabilities", {}).get("kb", {}).get("startup_ready", False),
                "configuration": {"ready": config.get("ready", False),
                    "conflict": bool(config.get("conflicts")),
                    "servers": config.get("changes", {}).get("mcp_servers", [])},
            }
        if action == "preview":
            before = self.config_bytes()
            report = self.command("repair-overrides", "--preview")
            if not report.get("ok") or before != self.config_bytes():
                raise ConfigurationConflict("configuration_conflict")
            self.preview_id = secrets.token_urlsafe(24)
            self.preview_config = before
            return {"preview_id": self.preview_id,
                    "servers": report["changes"]["mcp_servers"],
                    "would_change": report["would_change"]}
        if action == "apply":
            if not self.preview_id or data.get("preview_id") != self.preview_id or self.config_bytes() != self.preview_config:
                raise ConfigurationConflict("configuration_conflict")
            self.preview_id = None
            report = self.command("repair-overrides", "--expected-config-digest", hashlib.sha256(self.preview_config).hexdigest())
            if not report.get("ok"):
                raise ConfigurationConflict("configuration_conflict")
            self.transaction = report.get("transaction")
            return {"changed": report["changed"], "transaction": self.transaction}
        if action == "undo":
            if not self.transaction or data.get("transaction") != self.transaction:
                raise ConfigurationConflict("configuration_conflict")
            report = self.command("restore-legacy", "--transaction", self.transaction)
            if not report.get("ok"):
                raise ConfigurationConflict("configuration_conflict")
            self.transaction = None
            return {"restored": True}
        if action == "dependencies":
            capability = data.get("capability")
            if capability not in ("runtime", "kb"):
                raise ValueError("invalid_capability")
            result = self.command("prepare", "--repair", "--capability", capability)
            return {"repaired": result.get("ok") is True, "capability": capability}
        raise ValueError("invalid_plugin_action")


class LocalConfigurationServer:
    def __init__(
        self, config_home: Path, *, checker=None, authorized_targets=(), sources=None, maintenance=None
    ):
        self.config_home = Path(config_home).expanduser().resolve()
        self.stores = {
            "targets": LocalConfigurationStore(
                self.config_home / "openubmc" / "credentials.json", kind="targets"
            ),
            "conan": LocalConfigurationStore(
                self.config_home / "openubmc" / "conan.json", kind="conan"
            ),
            "kb": LocalConfigurationStore(
                self.config_home / "openubmc" / "kb-mcp.json", kind="kb"
            ),
        }
        for kind, path in (sources or {}).items():
            self.stores[kind] = LocalConfigurationStore(path, kind=kind)
        self.maintenance = maintenance
        self.checker = checker
        self.authorized_targets = tuple(authorized_targets)
        self.session_token = secrets.token_urlsafe(32)
        self.verifications = {}
        self.last_activity = time.monotonic()
        self._lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(5)

            def log_message(self, *_args):
                pass

            def send_body(self, status, value, kind="application/json"):
                body = (
                    json.dumps(value, ensure_ascii=True).encode()
                    if kind == "application/json"
                    else value
                )
                self.send_response(status)
                self.send_header("Content-Type", kind + "; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
                )
                self.end_headers()
                self.wfile.write(body)

            def allowed(self, write=False):
                return (
                    ipaddress.ip_address(self.client_address[0]).is_loopback
                    and self.headers.get_all("Host", []) == [owner.host]
                    and secrets.compare_digest(
                        self.headers.get("X-OpenUBMC-Session", ""), owner.session_token
                    )
                    and (
                        not write
                        or self.headers.get_all("Origin", []) == [owner.origin]
                    )
                )

            def do_GET(self):
                if self.headers.get_all("Host", []) != [owner.host]:
                    return self.send_body(403, {"error": "invalid_host"})
                if self.path == "/favicon.ico":
                    return self.send_body(204, b"", "image/x-icon")
                if self.path == "/api/state":
                    if not self.allowed():
                        return self.send_body(403, {"error": "invalid_session"})
                    return self.respond(lambda: owner.state())
                assets = {
                    "/": ("index.html", "text/html"),
                    "/page.js": ("page.js", "text/javascript"),
                    "/page.css": ("page.css", "text/css"),
                }
                if self.path not in assets:
                    return self.send_body(404, {"error": "not_found"})
                name, kind = assets[self.path]
                path = (
                    Path(__file__).resolve().parents[1]
                    / "assets"
                    / "config-page"
                    / name
                )
                if not path.is_file():
                    return self.send_body(404, {"error": "not_found"})
                self.send_body(200, path.read_bytes(), kind)

            def do_POST(self):
                if not self.allowed(write=True):
                    return self.send_body(403, {"error": "invalid_session_or_origin"})
                try:
                    if (
                        self.headers.get("Transfer-Encoding")
                        or self.headers.get_content_type() != "application/json"
                    ):
                        raise ValueError()
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 1024 * 1024:
                        raise ValueError()
                    data = json.loads(self.rfile.read(length))
                    if not isinstance(data, dict):
                        raise ValueError()
                except (ValueError, OSError, RecursionError):
                    return self.send_body(400, {"error": "invalid_request"})
                self.respond(lambda: owner.dispatch(self.path, data))

            def respond(self, callback):
                try:
                    owner.last_activity = time.monotonic()
                    result = callback()
                except ConfigurationConflict:
                    return self.send_body(
                        409,
                        {
                            "error": "configuration_conflict",
                            "message": "配置已被更新，请刷新页面后重试。",
                        },
                    )
                except (ConfigurationError, ValueError, TypeError, KeyError):
                    return self.send_body(
                        400,
                        {
                            "error": "configuration_invalid",
                            "message": "配置格式无效，请检查字段与凭据引用。",
                        },
                    )
                except Exception:
                    return self.send_body(
                        500,
                        {
                            "error": "local_operation_failed",
                            "message": "本地操作未完成，原有配置仍可通过状态页检查。",
                        },
                    )
                self.send_body(200, result)

        self.http = ThreadingHTTPServer(
            (str(ipaddress.ip_address(socket.INADDR_LOOPBACK)), 0), Handler
        )
        self.http.daemon_threads = False
        self.host = f"{self.http.server_address[0]}:{self.http.server_address[1]}"
        self.origin = "http://" + self.host
        self.url = self.origin + "/#" + self.session_token
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(timeout=2)

    def view(self, kind):
        store = self.stores[kind]
        status = store.status()
        config = store.read_active() if status["active_revision"] else {}
        readiness = []
        if kind == "targets":
            for scope, overrides in [
                ("default", {}),
                *config.get("targets", {}).items(),
            ]:
                for purpose in ("bmc", "os"):
                    references = {
                        **config.get("defaults", {}).get(purpose, {}),
                        **overrides.get(purpose, {}),
                    }
                    for transport, name in references.items():
                        record = config.get("credentials", {}).get(name, {})
                        readiness.append(
                            {
                                "scope": scope,
                                "purpose": purpose,
                                "transport": transport,
                                "configured": bool(
                                    record.get("user")
                                    and (
                                        record.get("password")
                                        or transport == "ssh"
                                        and record.get("identity_file")
                                    )
                                ),
                            }
                        )
        elif kind == "conan":
            readiness = [
                {
                    "scope": name,
                    "configured": bool(record.get("user") and record.get("password")),
                }
                for name, record in config.get("credentials", {}).items()
            ]
        else:
            readiness = [
                {
                    "scope": "KB",
                    "configured": all(
                        config.get(name)
                        for name in ("username", "password", "clientSecret")
                    ),
                }
            ]
        return {
            **status,
            "readiness": readiness,
            "config": _masked(store.read_saved()),
            "legacy_available": store.source.is_file(),
            "source": str(store.source),
            "checks": [
                value
                for (selected, _), value in self.verifications.items()
                if selected == kind and value["revision"] == status["active_revision"]
            ],
        }

    def state(self):
        with self._lock:
            return {
                **{kind: self.view(kind) for kind in self.stores},
                "environment": {
                    "platform": "WSL"
                    if "microsoft" in os.uname().release.lower()
                    else "Linux",
                    "hostname": socket.gethostname(),
                    "config_home": str(self.config_home),
                },
                "authorized_targets": list(self.authorized_targets),
            }

    def dispatch(self, path, data):
        with self._lock:
            if path == "/api/close":
                threading.Timer(0.1, self.http.shutdown).start()
                return {"closed": True}
            if path == "/api/plugin":
                if self.maintenance is None:
                    return {"available": False}
                return self.maintenance.dispatch(data)
            kind = data["kind"]
            store = self.stores[kind]
            if path == "/api/save":
                config = _secret_edits(data["config"], store.read_saved())
                store.save(config, expected_revision=data["expected_revision"])
            elif path == "/api/import":
                text = read_private_text(store.source, max_bytes=1024 * 1024)
                config = (
                    json.loads(text)
                    if kind != "targets" or text.lstrip().startswith("{")
                    else import_legacy_targets(text)
                )
                store.save(config, expected_revision=data["expected_revision"])
            elif path == "/api/activate":
                store.activate(
                    data["revision"],
                    expected_active_revision=data["expected_active_revision"],
                )
                for target in self.authorized_targets:
                    if kind == "targets":
                        self.check(kind, target)
            elif path == "/api/check":
                target = data.get("target")
                if kind == "targets" and not target:
                    return {"verified": False, "code": "target_required"}
                if (
                    target not in self.authorized_targets
                    and data.get("confirm") is not True
                ):
                    return {"verified": False, "code": "confirmation_required"}
                return self.check(kind, target)
            else:
                raise ConfigurationError("Unknown local action")
            return self.view(kind)

    def check(self, kind, target):
        store = self.stores[kind]
        revision = store.status()["active_revision"]
        if revision is None:
            return {"verified": False, "code": "activation_required"}
        if kind == "targets":
            if not isinstance(target, dict) or set(target) != {
                "ip",
                "purpose",
                "transport",
            }:
                raise ConfigurationError("Select the complete target scope")
            target = {**target, "ip": str(ipaddress.ip_address(target["ip"]))}
            if target["purpose"] not in {"bmc", "os"} or target["transport"] not in {
                "ssh",
                "redfish",
            }:
                raise ConfigurationError("Invalid target purpose or transport")
        if kind == "conan" and (
            not isinstance(target, dict)
            or set(target) != {"remote"}
            or target["remote"] not in store.read_active().get("credentials", {})
        ):
            raise ConfigurationError("Select a configured Conan remote")
        try:
            result = (
                self.checker(
                    kind,
                    store.read_active(),
                    target,
                    revision=revision,
                    source=store.source,
                )
                if self.checker
                else {"verified": False, "code": "check_unavailable"}
            )
        except Exception:
            result = {"verified": False, "code": "connection_failed"}
        allowed = {
            "connected",
            "remote_missing",
            "credentials_missing",
            "authentication_failed",
            "network_error",
            "host_identity_failed",
            "tls_error",
            "interaction_required",
            "permission_denied",
            "timeout",
            "check_unavailable",
            "connection_failed",
        }
        code = (
            result.get("code") if result.get("code") in allowed else "connection_failed"
        )
        if store.status()["active_revision"] != revision:
            return {"verified": False, "code": "configuration_changed"}
        receipt = {
            "verified": result.get("verified") is True and code == "connected",
            "code": code,
            "target": target,
            "revision": revision,
            "checked_at": int(time.time()),
        }
        self.verifications[(kind, json.dumps(target, sort_keys=True))] = receipt
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-home", type=Path)
    parser.add_argument("--home", type=Path)
    parser.add_argument("--codex-home", type=Path)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--purpose", choices=["bmc", "os"], default="bmc")
    parser.add_argument("--transport", choices=["ssh", "redfish"], default="ssh")
    args = parser.parse_args()
    if args.home is not None:
        os.environ["HOME"] = str(args.home)
    if args.codex_home is not None:
        os.environ["CODEX_HOME"] = str(args.codex_home)

    def stop(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from config_checks import BoundedConfigurationChecker
    from openubmc_target_runtime.credentials import LocalCredentialSource

    selected = (
        LocalCredentialSource().select_path() if args.config_home is None else None
    )
    sources = {}
    if selected is not None:
        sources["targets"] = selected
    kb_source = os.environ.get("OPENUBMC_KB_CONFIG") or os.environ.get(
        "OPENUBMC_MCP_CONFIG"
    )
    if kb_source and args.config_home is None:
        sources["kb"] = Path(kb_source)
    config_home = args.config_home or Path(
        os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    )
    targets = [
        {
            "ip": str(ipaddress.ip_address(host)),
            "purpose": args.purpose,
            "transport": args.transport,
        }
        for host in args.target
    ]
    with LocalConfigurationServer(
        config_home,
        checker=BoundedConfigurationChecker(),
        sources=sources,
        authorized_targets=targets,
        maintenance=PluginMaintenance(Path(__file__).resolve().parents[3])
        if (Path(__file__).resolve().parents[3]/"plugin-lock.json").is_file() else None,
    ) as server:
        print(server.url, flush=True)
        if not args.no_browser:
            if "microsoft" in os.uname().release.lower() and shutil.which("wslview"):
                subprocess.Popen(
                    ["wslview", server.url],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                webbrowser.open(server.url)
        try:
            while server.thread.is_alive():
                server.thread.join(timeout=1)
                if time.monotonic() - server.last_activity > 900:
                    break
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
