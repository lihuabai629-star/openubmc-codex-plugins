"""Current-user local credential sources; secret values never form public identities."""
from __future__ import annotations

from collections.abc import Mapping
import ipaddress
import json
import os
from pathlib import Path
from .credential_file import (CREDENTIALS_FILE_MAX_BYTES, CredentialFileError, configuration_home, read_private_text,
                              parse_credentials_text, selected_credential_value, selected_credentials_path)


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


def read_private_credentials(path: Path, *, max_bytes: int = 1024 * 1024) -> str:
    try:
        return read_private_text(path, max_bytes=max_bytes)
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
        from .configuration import has_activation
        for name in ('credentials.json', 'credentials.env'):
            path = configuration_home(self.environ) / 'openubmc' / name
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
            legacy_content = content
            if structured:
                config = json.loads(content, object_pairs_hook=_unique_object)
                if not isinstance(config, dict) or not isinstance(config.get('targets', {}), dict):
                    raise CredentialConfigurationError('credentials_invalid', 'Invalid local target configuration')
                from .configuration import _validate_targets
                _validate_targets(config)
                hosts.extend(config.get('targets', {}))
                hosts.extend(config.get('target_ports', {}))
                if config.get('legacy_source_overlay') is True:
                    legacy_content = read_private_credentials(path, max_bytes=CREDENTIALS_FILE_MAX_BYTES)
            capabilities = {'bmc_ssh': False, 'redfish': False, 'os_ssh': False, 'os_redfish': False}
            for host in hosts:
                for purpose, transport, name in [('bmc', 'ssh', 'bmc_ssh'), ('bmc', 'redfish', 'redfish'),
                                                 ('os', 'ssh', 'os_ssh'), ('os', 'redfish', 'os_redfish')]:
                    ports = [None]
                    if structured:
                        qualified = config.get('target_ports', {}).get(host, {}).get(purpose, {}).get(transport, {})
                        if isinstance(qualified, dict):
                            ports.extend(int(port) for port in qualified)
                    for port in ports:
                        record = self.resolve(selected, host=host, purpose=purpose, transport=transport,
                                              port=port, required=False, legacy_path=path)
                        capabilities[name] = capabilities[name] or record is not None
            legacy_incomplete = False
            if not structured or config.get('legacy_source_overlay') is True:
                # Telnet and the legacy OS-port completeness rule remain separate
                # from the Runtime's SSH/Redfish record interface.
                values = parse_credentials_text(legacy_content)
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

    def resolve(self, path: Path | None, *, host: str, purpose: str, transport: str,
                port: int | None = None, required: bool = True,
                legacy_path: Path | None = None) -> dict[str, str] | None:
        default_port = {'ssh': 22, 'redfish': 443}[transport]
        port = default_port if port is None else port
        if type(port) is not int or not 1 <= port <= 65535:
            raise CredentialConfigurationError('credentials_invalid', 'Credential port must be between 1 and 65535')
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
        defaults, targets, records, target_ports = (config.get(key, {}) for key in (
            'defaults', 'targets', 'credentials', 'target_ports'))
        if not all(isinstance(value, dict) for value in (defaults, targets, records, target_ports)):
            raise CredentialConfigurationError('credentials_invalid', 'Credential defaults, targets and records must be objects')
        def normalize_targets(entries):
            normalized_targets = {}
            for address, selected in entries.items():
                try:
                    normalized = str(ipaddress.ip_address(address.strip()))
                except (AttributeError, ValueError):
                    raise CredentialConfigurationError('credentials_invalid', 'Target overrides require literal IPv4 or IPv6 addresses') from None
                if normalized in normalized_targets and normalized_targets[normalized] != selected:
                    raise CredentialConfigurationError('credentials_conflict', 'Multiple overrides select the same normalized IP')
                normalized_targets[normalized] = selected
            return normalized_targets
        normalized_targets = normalize_targets(targets)
        normalized_port_targets = normalize_targets(target_ports)
        from .configuration import ConfigurationError, _validate_targets
        try:
            _validate_targets(config)
        except ConfigurationError:
            raise CredentialConfigurationError('credentials_invalid', 'Invalid local target configuration') from None
        target = normalized_targets.get(normalize_credential_host(host), {})
        port_target = normalized_port_targets.get(normalize_credential_host(host), {})
        if (not isinstance(target, dict) or not isinstance(port_target, dict)
                or not isinstance(defaults.get(purpose, {}), dict)
                or not isinstance(target.get(purpose, {}), dict)
                or not isinstance(port_target.get(purpose, {}), dict)):
            raise CredentialConfigurationError('credentials_invalid', 'Credential purposes must contain transport references')
        if port == default_port:
            reference = target.get(purpose, {}).get(transport, defaults.get(purpose, {}).get(transport))
        else:
            ports = port_target.get(purpose, {}).get(transport, {})
            if not isinstance(ports, dict):
                raise CredentialConfigurationError('credentials_invalid', 'Port-qualified references must be objects')
            reference = ports.get(str(port), defaults.get(purpose, {}).get(transport))
        if reference is None and config.get('legacy_source_overlay') is True:
            if legacy_path is None:
                raise CredentialConfigurationError('credentials_invalid', 'Legacy overlay requires its original private source')
            legacy_content = read_private_credentials(legacy_path, max_bytes=CREDENTIALS_FILE_MAX_BYTES)
            if legacy_content.lstrip().startswith('{'):
                raise CredentialConfigurationError('credentials_invalid', 'Legacy overlay source changed format')
            record = self._legacy_record(legacy_content, purpose=purpose, transport=transport)
            if not required and not any(record.values()):
                return None
            self._validate_record(record, purpose=purpose, transport=transport)
            return record
        if reference is None and config.get('legacy_environment_fallback') is True:
            # An automatically created IP-only store must not disable existing
            # process-environment access to other IPs or protocols. A configured
            # reference (even incomplete) still wins and is never field-merged.
            record = self._legacy_record('', purpose=purpose, transport=transport)
            if any(record.values()):
                self._validate_record(record, purpose=purpose, transport=transport)
                return record
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
