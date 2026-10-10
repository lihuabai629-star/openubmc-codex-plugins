"""Best-effort remembering after authentication, never a connection prerequisite.

Production composition enables this local policy. The Runtime library remains
side-effect free unless a caller supplies it; a failed save cannot fail a lane.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import replace
from functools import wraps
import hashlib
import ipaddress
import json
from pathlib import Path
import threading
import uuid

from .configuration import ConfigurationConflict, LocalConfigurationStore
from .credential_file import configuration_home
from .credentials import CredentialConfigurationError, LocalCredentialSource, read_private_credentials
from .credential_file import (CREDENTIALS_FILE_MAX_BYTES, CredentialFileError,
                              parse_credentials_text, selected_credential_value)


def import_legacy_targets(text: str) -> dict:
    """Preserve legacy defaults when adding an IP-specific remembered account."""
    values = parse_credentials_text(text)
    config = {"schema_version": 1, "credentials": {}, "defaults": {}}
    for purpose, transport in (("bmc", "ssh"), ("bmc", "redfish"), ("os", "ssh")):
        prefix = "OPENUBMC_" + ("OS_" if purpose == "os" else "") + transport.upper()
        record = {}
        for field in ("user", "password", "identity_file"):
            names = [prefix + "_" + field.upper()]
            if purpose == "bmc" and transport == "redfish" and field in {"user", "password"}:
                names.append("REDFISH_" + ("USERNAME" if field == "user" else "PASSWORD"))
            record[field] = selected_credential_value(values, names, environ={}) or ""
        if any(record.values()):
            name = next((name for name, existing in config["credentials"].items()
                         if existing == record), purpose + "-" + transport)
            config["credentials"][name] = record
            config["defaults"].setdefault(purpose, {})[transport] = name
    return config


def _legacy_overlay_is_equivalent(source: LocalCredentialSource, text: str) -> bool:
    """Check the legacy parser and ambiguous inputs before activating an overlay."""
    if len(text.encode("utf-8")) > CREDENTIALS_FILE_MAX_BYTES or text.lstrip().startswith("{"):
        return False
    try:
        values = parse_credentials_text(text)
        for purpose, transport in (("bmc", "ssh"), ("bmc", "redfish"), ("os", "ssh")):
            source._legacy_record(text, purpose=purpose, transport=transport)
        for name in ("OPENUBMC_TELNET_USER", "OPENUBMC_TELNET_PASSWORD", "OPENUBMC_OS_IP"):
            selected_credential_value(values, (name,), environ=source.environ)
        port = selected_credential_value(values, ("OPENUBMC_OS_SSH_PORT",),
                                         environ=source.environ)
        if port not in (None, "") and not 1 <= int(port) <= 65535:
            return False
    except (CredentialFileError, CredentialConfigurationError, ValueError):
        return False
    return True


class VerifiedCredentialMemory:
    """Merge only the authenticated IP/purpose/transport into the chosen store.

    No authentication, discovery of other accounts, or device operation occurs
    here. Pending edits and concurrent changes are preserved, not overwritten.
    """

    def __init__(self, *, config_path=None, environ=None):
        self.source = LocalCredentialSource(config_path=config_path, environ=environ)
        self._lock = threading.RLock()
        self._expected = None

    def _path(self):
        path = self.source.select_path()
        if path is None:
            path = configuration_home(self.source.environ) / "openubmc" / "credentials.json"
        return path

    @staticmethod
    def _generation(path):
        store = LocalConfigurationStore(path, kind="targets")
        status = store.status()
        original = None
        overlay = (status["active_revision"] is not None
                   and store.read_active().get("legacy_source_overlay") is True)
        if (status["active_revision"] is None or overlay) and (path.exists() or path.is_symlink()):
            original = hashlib.sha256(read_private_credentials(path).encode()).hexdigest()
        return status["revision"], status["active_revision"], original

    def for_connection(self):
        """Bind the destination before authentication so later edits win."""
        path = self._path()
        bound = VerifiedCredentialMemory(config_path=path, environ=self.source.environ)
        bound._expected = self._generation(path)
        return bound

    def remember(self, *, host: str, purpose: str, transport: str, credentials) -> dict:
        try:
            with self._lock:
                return self._remember(host, purpose, transport, credentials)
        except Exception:
            # A connection already succeeded. Keep its in-memory credentials;
            # never include storage exceptions (which may contain secrets).
            return {"remembered": False, "code": "storage_unavailable"}

    def _remember(self, host, purpose, transport, credentials):
        try:
            host = str(ipaddress.ip_address(host.strip()))
        except ValueError:
            return {"remembered": False, "code": "unsupported_scope"}
        selected_port = credentials.port
        if (purpose not in {"bmc", "os"} or transport not in {"ssh", "redfish"}
                or type(selected_port) is not int or not 1 <= selected_port <= 65535):
            return {"remembered": False, "code": "unsupported_scope"}
        default_port = {"ssh": 22, "redfish": 443}[transport]
        record = {"user": credentials.user, "password": credentials.password}
        if transport == "ssh" and credentials.identity_file:
            record["identity_file"] = credentials.identity_file
        if not record["user"] or not (record["password"] or record.get("identity_file")):
            return {"remembered": False, "code": "incomplete_account"}
        path = self._path()
        store = LocalConfigurationStore(path, kind="targets")
        status = store.status()
        if self._expected is not None and self._generation(path) != self._expected:
            return {"remembered": False, "code": "configuration_changed"}
        if status["revision"] != status["active_revision"]:
            return {"remembered": False, "code": "pending_configuration_edit"}
        source_text = None
        legacy_source = False
        if status["active_revision"]:
            # Persistence reads the current saved==active generation, not the
            # request's intentionally pinned credential-read snapshot.
            config = store.read_saved()
            if config.get("legacy_source_overlay") is True:
                source_text = read_private_credentials(path)
                if not _legacy_overlay_is_equivalent(self.source, source_text):
                    return {"remembered": False, "code": "legacy_equivalence_unproven"}
        elif path.exists() or path.is_symlink():
            source_text = read_private_credentials(path)
            if not source_text.lstrip().startswith("{"):
                legacy_source = True
            if legacy_source:
                if not _legacy_overlay_is_equivalent(self.source, source_text):
                    return {"remembered": False, "code": "legacy_equivalence_unproven"}
                config = {"schema_version": 1, "credentials": {}, "target_ports": {},
                          "legacy_source_overlay": True}
            else:
                config = json.loads(source_text)
        else:
            config = {"schema_version": 1, "legacy_environment_fallback": True}
        store._validate(config)
        records = config.setdefault("credentials", {})
        group_name = "targets" if selected_port == default_port else "target_ports"
        targets = config.setdefault(group_name, {})
        address = next((key for key in targets
                        if str(ipaddress.ip_address(key.strip())) == host), host)
        references = targets.get(address, {}).get(purpose, {})
        port_references = references.get(transport, {}) if group_name == "target_ports" else None
        previous = (port_references.get(str(selected_port)) if port_references is not None
                    else references.get(transport))
        selected = previous or (config.get("defaults", {}).get(purpose, {}).get(transport)
                                if group_name == "targets" else None)
        if selected and all(records[selected].get(k, "") == record.get(k, "")
                            for k in ("user", "password", "identity_file")):
            return {"remembered": True, "code": "already_available"}
        name = next((name for name, value in records.items() if value == record), None)
        if name is None:
            name = "remembered-" + uuid.uuid4().hex
            records[name] = record
        references = targets.setdefault(address, {}).setdefault(purpose, {})
        if group_name == "target_ports":
            references.setdefault(transport, {})[str(selected_port)] = name
        else:
            references[transport] = name
        if previous and previous.startswith("remembered-"):
            used = [config.get("defaults", {}), *config.get("targets", {}).values()]
            referenced = any(previous in refs.values() for item in used for refs in item.values())
            referenced |= any(previous in ports.values()
                              for item in config.get("target_ports", {}).values()
                              for transports in item.values() for ports in transports.values())
            if not referenced:
                records.pop(previous, None)
        try:
            store.save_and_activate(config, expected_revision=status["revision"],
                                    expected_active_revision=status["active_revision"],
                                    expected_source_text=source_text, blocking=False)
        except ConfigurationConflict:
            return {"remembered": False, "code": "configuration_changed"}
        except Exception:
            return {"remembered": False, "code": "storage_unavailable"}
        return {"remembered": True, "code": "saved"}


_memory = ContextVar("verified_credential_memory", default=None)


@contextmanager
def credential_memory_scope(memory):
    token = _memory.set(memory)
    try:
        yield
    finally:
        _memory.reset(token)


def credential_memory_request(function):
    """Apply the production policy in the actual request worker, not its parent."""
    @wraps(function)
    def wrapped(self, *args, **kwargs):
        with credential_memory_scope(self.credential_memory):
            return function(self, *args, **kwargs)
    return wrapped


class AuthenticationMemory:
    """A lane-local, single-attempt sink captured at construction time."""

    def __init__(self):
        self.memory = _memory.get()
        self.status = {"remembered": False, "code": "not_attempted"}
        if self.memory is not None:
            try:
                self.memory = self.memory.for_connection()
            except Exception:
                self.memory = None
                self.status = {"remembered": False, "code": "storage_unavailable"}

    def authenticated(self, *, host, transport, credentials, purpose="bmc", port=None):
        if self.memory is None or self.status["code"] != "not_attempted":
            return
        try:
            if port is not None and port != credentials.port:
                credentials = replace(credentials, port=port)
            self.status = self.memory.remember(host=host, transport=transport,
                                               credentials=credentials, purpose=purpose)
        except Exception:
            self.status = {"remembered": False, "code": "storage_unavailable"}
