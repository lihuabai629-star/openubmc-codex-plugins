"""Current-user local credential sources; secret values never form public identities."""
from __future__ import annotations

from collections.abc import Mapping
import ipaddress
import json
import os
from pathlib import Path
from .credential_file import CredentialFileError, read_private_text, parse_credentials_text, selected_credential_value, selected_credentials_path


class CredentialConfigurationError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def normalize_credential_host(host: str) -> str:
    text = host.strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.lower()


def read_private_credentials(path: Path) -> str:
    try:
        return read_private_text(path, max_bytes=1024 * 1024)
    except CredentialFileError as exc:
        code = 'credentials_missing' if 'does not exist' in str(exc) else 'credentials_invalid'
        raise CredentialConfigurationError(code, 'Check the selected current-user credential source and its permissions') from None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result and result[key] != value:
            raise CredentialConfigurationError('credentials_conflict', 'Credential configuration contains conflicting duplicate fields')
        result[key] = value
    return result


class LocalCredentialSource:
    def __init__(self, *, config_path: Path | str | None = None, environ: Mapping[str, str] | None = None):
        self.config_path = Path(config_path) if config_path is not None else None
        self.environ = os.environ if environ is None else environ

    def is_structured(self, path: Path | None) -> bool:
        return path is not None and (path.suffix.lower() == '.json' or read_private_credentials(path).lstrip().startswith('{'))

    def select_path(self) -> Path | None:
        if self.config_path is not None:
            return Path(os.path.abspath(self.config_path.expanduser()))
        try:
            selected = selected_credentials_path(self.environ, env_names=(
                'OPENUBMC_CREDENTIALS_CONFIG', 'OPENUBMC_CREDENTIALS_FILE', 'OPENUBMC_DEBUG_CREDENTIALS_FILE'))
        except CredentialFileError as exc:
            code = 'credentials_conflict' if 'same file' in str(exc) else 'credentials_invalid'
            raise CredentialConfigurationError(code, 'Check the explicit local credential source selectors') from None
        if selected is not None:
            return selected
        config_home = self.environ.get('XDG_CONFIG_HOME') or str(Path.home() / '.config')
        from .configuration import has_activation
        for name in ('credentials.json', 'credentials.env'):
            path = Path(config_home) / 'openubmc' / name
            if path.exists() or path.is_symlink() or has_activation(path):
                return path
        return None

    def status(self) -> dict[str, object]:
        """Describe selected local capabilities without claiming a remote connection."""
        from .configuration import activated_source, ConfigurationError
        result = {'configured': False, 'status': 'missing', 'reason': 'No local credential capability is configured',
                  'remote_authentication': 'not_checked', 'capabilities': {}, 'active_revision': None}
        try:
            path = self.select_path()
            selected, revision = activated_source(path) if path is not None else (None, None)
            result['active_revision'] = revision
            content = read_private_credentials(selected) if selected is not None else ''
            structured = selected is not None and (selected.suffix.lower() == '.json' or content.lstrip().startswith('{'))
            hosts = ['default-credential-readiness.invalid']
            if structured:
                config = json.loads(content, object_pairs_hook=_unique_object)
                if not isinstance(config, dict) or not isinstance(config.get('targets', {}), dict):
                    raise CredentialConfigurationError('credentials_invalid', 'Invalid local target configuration')
                hosts.extend(config.get('targets', {}))
            capabilities = {'bmc_ssh': False, 'redfish': False, 'os_ssh': False, 'os_redfish': False}
            for host in hosts:
                for purpose, transport, name in [('bmc', 'ssh', 'bmc_ssh'), ('bmc', 'redfish', 'redfish'),
                                                 ('os', 'ssh', 'os_ssh'), ('os', 'redfish', 'os_redfish')]:
                    record = self.resolve(selected, host=host, purpose=purpose, transport=transport, required=False)
                    capabilities[name] = capabilities[name] or record is not None
            legacy_incomplete = False
            if not structured:
                # Telnet and the legacy OS-port completeness rule remain separate
                # from the Runtime's SSH/Redfish record interface.
                values = parse_credentials_text(content)
                telnet = [selected_credential_value(values, (key,), environ=self.environ) or ''
                          for key in ('OPENUBMC_TELNET_USER', 'OPENUBMC_TELNET_PASSWORD')]
                capabilities['telnet'] = all(telnet)
                legacy_incomplete = any(telnet) and not all(telnet)
                if selected_credential_value(values, ('OPENUBMC_OS_SSH_PORT',), environ=self.environ) and not capabilities['os_ssh']:
                    legacy_incomplete = True
            result.update(configured=any(capabilities.values()) and not legacy_incomplete, capabilities=capabilities)
            result['status'] = 'configured' if result['configured'] else 'incomplete' if selected is not None else 'missing'
            result['reason'] = ('Local credentials are complete; remote authentication was not checked'
                                if result['configured'] else 'Complete the selected local credential capabilities')
        except CredentialConfigurationError as error:
            result.update(status=error.code.removeprefix('credentials_'), reason=str(error), code=error.code)
        except (CredentialFileError, ConfigurationError, ValueError, TypeError, RecursionError, OSError):
            result.update(status='invalid', reason='Check the selected current-user credential configuration and permissions',
                          code='credentials_invalid')
        return result

    def _legacy_record(self, content: str, *, purpose: str, transport: str) -> dict[str, str]:
        try:
            values = parse_credentials_text(content)
        except CredentialFileError as exc:
            code = 'credentials_conflict' if 'conflicting' in str(exc) else 'credentials_invalid'
            raise CredentialConfigurationError(code, 'Check the legacy credential file format and duplicate fields') from None
        prefix = 'OPENUBMC_' + ('OS_' if purpose == 'os' else '') + transport.upper()
        aliases = {field: [prefix + '_' + field.upper()] for field in ('user', 'password', 'identity_file')}
        if purpose == 'bmc' and transport == 'redfish':
            aliases['user'].append('REDFISH_USERNAME')
            aliases['password'].append('REDFISH_PASSWORD')
        record = {}
        for field, names in aliases.items():
            record[field] = selected_credential_value(values, names, environ=self.environ) or ''
        return record

    def resolve(self, path: Path | None, *, host: str, purpose: str, transport: str, required: bool = True) -> dict[str, str] | None:
        content = read_private_credentials(path) if path is not None else ''
        if path is None or (path.suffix.lower() != '.json' and not content.lstrip().startswith('{')):
            record = self._legacy_record(content, purpose=purpose, transport=transport)
            if not required and not any(record.values()):
                return None
            self._validate_record(record, purpose=purpose, transport=transport)
            return record
        try:
            config = json.loads(content, object_pairs_hook=_unique_object)
        except (ValueError, RecursionError):
            raise CredentialConfigurationError('credentials_invalid', 'Credential source must contain valid JSON') from None
        if not isinstance(config, dict) or config.get('schema_version') != 1:
            raise CredentialConfigurationError('credentials_invalid', 'Unsupported local credential configuration schema')
        defaults, targets, records = (config.get(key, {}) for key in ('defaults', 'targets', 'credentials'))
        if not all(isinstance(value, dict) for value in (defaults, targets, records)):
            raise CredentialConfigurationError('credentials_invalid', 'Credential defaults, targets and records must be objects')
        normalized_targets = {}
        for address, entries in targets.items():
            try:
                normalized = str(ipaddress.ip_address(address.strip()))
            except ValueError:
                raise CredentialConfigurationError('credentials_invalid', 'Target overrides require literal IPv4 or IPv6 addresses') from None
            if normalized in normalized_targets and normalized_targets[normalized] != entries:
                raise CredentialConfigurationError('credentials_conflict', 'Multiple overrides select the same normalized IP')
            normalized_targets[normalized] = entries
        target = normalized_targets.get(normalize_credential_host(host), {})
        if not isinstance(target, dict) or not isinstance(defaults.get(purpose, {}), dict) or not isinstance(target.get(purpose, {}), dict):
            raise CredentialConfigurationError('credentials_invalid', 'Credential purposes must contain transport references')
        reference = target.get(purpose, {}).get(transport, defaults.get(purpose, {}).get(transport))
        if reference is None and not required:
            return None
        if not isinstance(reference, str) or not reference or reference not in records:
            raise CredentialConfigurationError('credentials_missing', f'Configure a complete local {purpose} {transport} credential record')
        record = records[reference]
        if not isinstance(record, dict) or any(not isinstance(value, str) or '\x00' in value for value in record.values()):
            raise CredentialConfigurationError('credentials_invalid', 'Credential record fields must be strings')
        self._validate_record(record, purpose=purpose, transport=transport)
        return {key: record.get(key, '') for key in ('user', 'password', 'identity_file')}

    @staticmethod
    def _validate_record(record: Mapping[str, str], *, purpose: str, transport: str) -> None:
        if not record.get('user', '').strip() or not (record.get('password') or transport == 'ssh' and record.get('identity_file')):
            raise CredentialConfigurationError('credentials_missing', f'Complete the selected local {purpose} {transport} record; defaults are not combined with overrides')
