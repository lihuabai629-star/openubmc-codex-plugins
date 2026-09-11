"""Bounded system-manager service observations through a read-only SSH lane."""

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)

from datetime import datetime, timezone
import json
import re
import shlex
import subprocess
import time

from _target_runtime_adapter import _load_runtime_module

_RUNTIME = _load_runtime_module()
UNIT = _RUNTIME.SYSTEMD_UNIT
validate_names = _RUNTIME.validate_systemd_names
PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'Result',
              'ExecMainCode', 'ExecMainStatus', 'InvocationID')
JOURNAL_FIELDS = ('_BOOT_ID', '_SYSTEMD_INVOCATION_ID', '_SYSTEMD_UNIT',
                  '__REALTIME_TIMESTAMP', 'MESSAGE', 'PRIORITY', 'UNIT', 'INVOCATION_ID', '_PID')
BOOT_COMMAND = 'cat /proc/sys/kernel/random/boot_id'


class CollectionGap(ValueError):
    """Fixed collector reason, never remote output or exception text."""


def parse_properties(output, name):
    lines = output.splitlines()
    if len(lines) != len(PROPERTIES) or any('=' not in line for line in lines):
        raise CollectionGap('malformed_properties')
    properties = dict(line.split('=', 1) for line in lines)
    if properties.get('Id') != name or set(properties) != set(PROPERTIES):
        raise CollectionGap('malformed_properties')
    if (properties['LoadState'] not in {'stub', 'loaded', 'not-found', 'bad-setting', 'error', 'merged', 'masked'}
            or properties['ActiveState'] not in {'active', 'reloading', 'inactive', 'failed', 'activating', 'deactivating', 'maintenance', 'refreshing'}
            or any(not re.fullmatch(r'[a-z][a-z-]{0,63}', properties[key]) for key in ('SubState', 'Result'))
            or any(not re.fullmatch(r'[0-9]{1,10}', properties[key]) for key in ('ExecMainCode', 'ExecMainStatus'))):
        raise CollectionGap('malformed_properties')
    if properties['LoadState'] == 'not-found':
        raise CollectionGap('unit_not_found')
    if not re.fullmatch(r'[0-9a-f]{32}', properties['InvocationID']) or properties['InvocationID'] == '0' * 32:
        raise CollectionGap('invocation_identity_unavailable')
    return properties


def parse_journal(output, boot, name, invocation):
    try:
        logs = [json.loads(line) for line in output.splitlines() if line]
    except (ValueError, RecursionError):
        raise CollectionGap('malformed_journal') from None
    if len(logs) > 100:
        raise CollectionGap('journal_line_limit')
    for row in logs:
        if (not isinstance(row, dict) or not {'_BOOT_ID', '__REALTIME_TIMESTAMP', 'MESSAGE', 'PRIORITY'} <= set(row)
                or any(not isinstance(row[key], str) for key in JOURNAL_FIELDS if key in row)
                or not row['__REALTIME_TIMESTAMP'].isdigit()
                or row['PRIORITY'] not in '01234567' or len(row['PRIORITY']) != 1
):
            raise CollectionGap('malformed_journal')
        if row['_BOOT_ID'] != boot.replace('-', ''):
            raise CollectionGap('journal_boot_mismatch')
        manager = row.get('_PID') == '1' and row.get('UNIT') == name
        row_invocation = row.get('INVOCATION_ID') if manager else row.get('_SYSTEMD_INVOCATION_ID')
        if not isinstance(row_invocation, str) or not re.fullmatch(r'[0-9a-f]{32}', row_invocation):
            raise CollectionGap('malformed_journal')
        if row_invocation != invocation:
            raise CollectionGap('journal_invocation_mismatch')
        if not manager and row.get('_SYSTEMD_UNIT') != name:
            raise CollectionGap('journal_unit_mismatch')
    return logs


def collect_systemd(names, run_ssh, *, deadline, secret_values=()):
    """Collect only fixed commands; run_ssh is the bound transport, never Agent input."""
    validate_names(names)
    result = {'requested': list(names), 'units': [], 'complete': False, 'gaps': [],
              'started_at': datetime.now(timezone.utc).isoformat()}
    remaining_bytes = 256 * 1024

    def command(text):
        nonlocal remaining_bytes
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CollectionGap('deadline_exceeded')
        reply = run_ssh(text, timeout=remaining, stdout_limit_bytes=remaining_bytes + 1,
                        stderr_limit_bytes=min(8192, remaining_bytes + 1))
        if getattr(reply, 'output_limit_exceeded', False):
            raise CollectionGap('output_limit')
        if getattr(reply, 'timed_out', False) or time.monotonic() > deadline:
            raise CollectionGap('deadline_exceeded')
        if getattr(reply, 'stdout_read_error', False) or getattr(reply, 'stderr_read_error', False):
            raise CollectionGap('transport_failed')
        remaining_bytes -= len(reply.stdout.encode()) + len(reply.stderr.encode())
        if remaining_bytes < 0:
            raise CollectionGap('output_limit')
        if reply.returncode == 255:
            raise CollectionGap('transport_failed')
        if reply.returncode == 127 or 'not been booted with systemd' in reply.stderr.lower():
            raise CollectionGap('unsupported')
        if any(reason in reply.stderr.lower() for reason in ('permission denied', 'access denied', 'insufficient permissions')):
            raise CollectionGap('permission_denied')
        if (reply.returncode == 4 and text.startswith('LC_ALL=C systemctl --system show ')
                and 'LoadState=not-found' in reply.stdout.splitlines()):
            raise CollectionGap('unit_not_found')
        if reply.returncode:
            raise CollectionGap('command_failed')
        return reply.stdout

    try:
        boot = command(BOOT_COMMAND).strip()
        if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot):
            raise CollectionGap('boot_identity_unavailable')
        result['boot_id'] = boot
        if list(names) == ['failed']:
            listing = command('LC_ALL=C systemctl --system list-units --failed --type=service --all --no-legend --no-pager --plain')
            names = []
            for line in listing.splitlines():
                fields = line.split()
                if len(fields) < 4 or not UNIT.fullmatch(fields[0]) or fields[2] != 'failed':
                    raise CollectionGap('malformed_discovery')
                names.append(fields[0])
            if len(names) > 16:
                raise CollectionGap('unit_limit')
            if len(set(names)) != len(names):
                raise CollectionGap('malformed_discovery')
        for name in names:
            show = 'LC_ALL=C systemctl --system show --no-pager --property=' + ','.join(PROPERTIES) + ' -- ' + shlex.quote(name)
            before = parse_properties(command(show), name)
            journal_command = ('LC_ALL=C journalctl --system --no-pager --quiet --output=json --output-fields='
                               + ','.join(JOURNAL_FIELDS) + ' --boot=' + boot + ' --lines=100 '
                               + '_SYSTEMD_UNIT=' + shlex.quote(name)
                               + ' _SYSTEMD_INVOCATION_ID=' + before['InvocationID']
                               + ' + _BOOT_ID=' + boot.replace('-', '')
                               + ' UNIT=' + shlex.quote(name) + ' INVOCATION_ID=' + before['InvocationID']
                               + ' _PID=1')
            logs = parse_journal(command(journal_command), boot, name, before['InvocationID'])
            after = parse_properties(command(show), name)
            if before != after:
                raise CollectionGap('invocation_or_state_changed')
            if any(line.get('_BOOT_ID') != boot.replace('-', '') for line in logs):
                raise CollectionGap('journal_boot_mismatch')
            if len(logs) == 100 and 'journal_truncated' not in result['gaps']:
                result['gaps'].append('journal_truncated')
            for row in logs:
                row['MESSAGE'] = _RUNTIME.redact_text(row['MESSAGE'], secret_values=secret_values)
            result['units'].append({'unit': name, 'properties': before,
                                    'journal': [{k: row[k] for k in JOURNAL_FIELDS if k in row} for row in logs]})
        if command(BOOT_COMMAND).strip() != boot:
            raise CollectionGap('boot_changed')
        result['complete'] = not result['gaps']
    except (TimeoutError, subprocess.TimeoutExpired):
        result['gaps'].append('deadline_exceeded')
    except CollectionGap as error:
        result['gaps'].append(str(error))
    except (OSError, ValueError, RuntimeError):
        result['gaps'].append('transport_failed')
    result['completed_at'] = datetime.now(timezone.utc).isoformat()
    return result
