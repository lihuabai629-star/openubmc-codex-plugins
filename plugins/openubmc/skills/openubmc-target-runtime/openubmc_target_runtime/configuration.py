"""Current-user configuration snapshots and explicit atomic activation."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import fcntl
import ipaddress
import json
import math
from urllib.parse import urlsplit
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

from .credential_file import CredentialFileError, read_private_text


class ConfigurationError(ValueError):
    code = 'configuration_invalid'


class ConfigurationConflict(ConfigurationError):
    code = 'configuration_conflict'


def _sidecar(source: Path, role: str) -> Path:
    return source.with_name('.' + source.name + '.' + role + '.json')


def _snapshot(source: Path, revision: str) -> Path:
    if not isinstance(revision, str) or re.fullmatch(r'[a-f0-9]{32}', revision) is None:
        raise ConfigurationError('Invalid configuration revision')
    return source.parent / ('.' + source.name + '.revisions') / (revision + '.json')


def _read(path: Path, *, missing: bool = False):
    if missing and not path.exists() and not path.is_symlink():
        return None
    try:
        return json.loads(read_private_text(path, max_bytes=1024 * 1024))
    except (CredentialFileError, ValueError, RecursionError):
        raise ConfigurationError('Configuration must be valid private local JSON') from None


def _revision(source: Path, role: str) -> str | None:
    marker = _read(_sidecar(source, role), missing=True)
    if marker is None:
        return None
    if not isinstance(marker, dict) or marker.get('schema') != 'openubmc.configuration.v1':
        raise ConfigurationError('Unsupported configuration marker')
    revision = marker.get('revision')
    _snapshot(source, revision)
    return revision


_request_snapshots: ContextVar[dict | None] = ContextVar('configuration_request_snapshots', default=None)


@contextmanager
def configuration_request():
    """Pin local revisions across all partitions and retries of one public call."""
    if _request_snapshots.get() is not None:
        yield
        return
    token = _request_snapshots.set({})
    try:
        yield
    finally:
        _request_snapshots.reset(token)


def activated_source(source: Path) -> tuple[Path, str | None]:
    """Return the immutable explicitly activated snapshot, or the legacy source."""
    source = Path(source)
    pinned = _request_snapshots.get()
    if pinned is not None and source in pinned:
        return pinned[source]
    revision = _revision(source, 'active')
    selected = (_snapshot(source, revision), revision) if revision is not None else (source, None)
    if pinned is not None:
        pinned[source] = selected
    return selected


def has_activation(source: Path) -> bool:
    marker = _sidecar(source, 'active')
    return marker.exists() or marker.is_symlink()


def _atomic_write(path: Path, content: bytes) -> None:
    if path.is_symlink():
        raise ConfigurationError('Configuration markers must not be symbolic links')
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _validate_targets(config: object) -> None:
    if not isinstance(config, dict) or type(config.get('schema_version')) is not int or config['schema_version'] != 1:
        raise ConfigurationError('Unsupported target configuration schema')
    for name in ('credentials', 'defaults', 'targets'):
        if not isinstance(config.get(name, {}), dict):
            raise ConfigurationError('Credential records and target defaults must be objects')
    if set(config) - {'schema_version', 'credentials', 'defaults', 'targets'}:
        raise ConfigurationError('Unknown target configuration field')
    for record in config.get('credentials', {}).values():
        if not isinstance(record, dict) or set(record) - {'user', 'password', 'identity_file'} or any(not isinstance(value, str) or '\0' in value for value in record.values()):
            raise ConfigurationError('Credential fields must be strings')
    normalized_addresses = set()
    for address in config.get('targets', {}):
        try:
            normalized = str(ipaddress.ip_address(address.strip()))
            if normalized in normalized_addresses:
                raise ConfigurationError('Duplicate normalized target address')
            normalized_addresses.add(normalized)
        except ValueError:
            raise ConfigurationError('Target overrides require a literal IP address') from None
    for purposes in [config.get('defaults', {}), *config.get('targets', {}).values()]:
        if not isinstance(purposes, dict):
            raise ConfigurationError('Target purposes must be objects')
        for purpose, references in purposes.items():
            if purpose not in {'bmc', 'os'} or not isinstance(references, dict) or any(transport not in {'ssh', 'redfish'} or not isinstance(reference, str) for transport, reference in references.items()):
                raise ConfigurationError('Invalid purpose or transport reference')
            if any(reference not in config.get('credentials', {}) for reference in references.values()):
                raise ConfigurationError('Credential reference has no corresponding record')


def _validate_kb(config: object) -> None:
    if not isinstance(config, dict):
        raise ConfigurationError('KB configuration must be an object')
    strings = {'username', 'password', 'clientSecret', 'clientId', 'redirectUri',
               'lightragUrl', 'userCenterUrl', 'oauthBaseUrl', 'tokenCachePath'}
    if set(config) - strings - {'scopes', 'requestTimeoutMs'}:
        raise ConfigurationError('Unknown KB configuration field')
    for name in strings & config.keys():
        if not isinstance(config[name], str) or '\0' in config[name]:
            raise ConfigurationError('KB configuration fields must be strings')
    for name in ('lightragUrl', 'userCenterUrl', 'oauthBaseUrl'):
        if name not in config:
            continue
        try:
            url = urlsplit(config[name])
            valid = url.hostname and not url.username and not url.password and not url.query and not url.fragment
            loopback = url.hostname == 'localhost'
            if not loopback:
                try:
                    loopback = ipaddress.ip_address(url.hostname).is_loopback
                except ValueError:
                    pass
            valid = valid and (url.scheme == 'https' or (url.scheme == 'http' and loopback))
        except ValueError:
            valid = False
        if not valid:
            raise ConfigurationError('KB endpoints require HTTPS or loopback HTTP without URL credentials')
    if 'scopes' in config and (not isinstance(config['scopes'], list) or not config['scopes'] or any(not isinstance(item, str) or not item.strip() for item in config['scopes'])):
        raise ConfigurationError('KB scopes must be nonempty strings')
    if 'requestTimeoutMs' in config:
        value = config['requestTimeoutMs']
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ConfigurationError('KB request timeout must be finite and positive')


def _validate_conan(config: object) -> None:
    if not isinstance(config, dict) or set(config) - {'credentials'} or not isinstance(config.get('credentials', {}), dict):
        raise ConfigurationError('Conan configuration must contain credential records')
    for remote, record in config.get('credentials', {}).items():
        if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', remote) is None:
            raise ConfigurationError('Invalid Conan remote name')
        if not isinstance(record, dict) or set(record) - {'user', 'password'} or any(not isinstance(v, str) or '\0' in v for v in record.values()):
            raise ConfigurationError('Conan credentials must contain text fields')


class LocalConfigurationStore:
    def __init__(self, source: Path, *, kind: str):
        self.source = Path(os.path.abspath(Path(source).expanduser()))
        if kind not in {'targets', 'kb', 'conan'}:
            raise ConfigurationError('Unsupported configuration kind')
        self.kind = kind

    def _validate(self, config: object) -> None:
        {'targets': _validate_targets, 'kb': _validate_kb, 'conan': _validate_conan}[self.kind](config)

    @contextmanager
    def _locked(self):
        self.source.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock = self.source.with_name('.' + self.source.name + '.lock')
        descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ConfigurationError('Configuration lock must be a private current-user file')
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def status(self) -> dict[str, object]:
        revision = _revision(self.source, 'saved')
        active = _revision(self.source, 'active')
        return {'saved': revision is not None, 'revision': revision, 'active_revision': active, 'verified': False}

    def read_active(self) -> dict:
        """Local operator-only active bytes, never a model-facing projection."""
        path, _revision_id = activated_source(self.source)
        return _read(path)

    def read_saved(self) -> dict:
        """Local operator-only data; callers must remove secrets before display."""
        revision = _revision(self.source, 'saved')
        if revision is None:
            return {'schema_version': 1} if self.kind == 'targets' else {}
        return _read(_snapshot(self.source, revision))

    def save(self, config: dict, *, expected_revision: str | None) -> dict[str, object]:
        self._validate(config)
        try:
            content = (json.dumps(config, ensure_ascii=True) + '\n').encode()
        except (TypeError, ValueError, RecursionError):
            raise ConfigurationError('Configuration must be JSON data') from None
        if len(content) > 1024 * 1024:
            raise ConfigurationError('Configuration exceeds the supported byte limit')
        with self._locked():
            if _revision(self.source, 'saved') != expected_revision:
                raise ConfigurationConflict('Configuration changed; refresh before saving')
            revision = uuid.uuid4().hex
            snapshot = _snapshot(self.source, revision)
            if snapshot.parent.is_symlink():
                raise ConfigurationError('Configuration snapshots must remain local')
            snapshot.parent.mkdir(mode=0o700, exist_ok=True)
            info = snapshot.parent.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ConfigurationError('Configuration snapshot directory must be private and current-user owned')
            _atomic_write(snapshot, content)
            _atomic_write(_sidecar(self.source, 'saved'), json.dumps({'schema': 'openubmc.configuration.v1', 'revision': revision}).encode())
            return self.status()

    def activate(self, revision: str, *, expected_active_revision: str | None) -> dict[str, object]:
        with self._locked():
            if _revision(self.source, 'active') != expected_active_revision:
                raise ConfigurationConflict('Active configuration changed; refresh before activating')
            if _revision(self.source, 'saved') != revision:
                raise ConfigurationConflict('Only the latest saved configuration can be activated')
            self._validate(_read(_snapshot(self.source, revision)))
            _atomic_write(_sidecar(self.source, 'active'), json.dumps({'schema': 'openubmc.configuration.v1', 'revision': revision}).encode())
            return self.status()
