"""Bounded read-only OS probes through BMC SSH and its native SOL command."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


from datetime import datetime, timezone
import codecs
import ipaddress
import json
import re
import shlex
import socket
import threading
import time
import uuid

from _target_runtime_adapter import _load_runtime_module

_RUNTIME = _load_runtime_module()
validate_os_console_names = _RUNTIME.validate_os_console_names

OUTPUT_LIMIT = 256 * 1024
LOGIN = re.compile(r'(?:^|[\r\n])[^\r\n]{0,128}(?:login|登录)\s*[:：]\s*$', re.I)
PASSWORD = re.compile(r'(?:password|密码)\s*[:：]\s*$', re.I)
SHELL = re.compile(r'(?:^|[\r\n])[^\r\n]{0,160}[$#]\s*$')
AUTH_FAILED = re.compile(r'login incorrect|authentication fail|incorrect password|登录不正确|认证失败', re.I)
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
BOOT = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
IDENTITY_COMMAND = 'id -u && tty && uname -srmo && hostname && cat /proc/sys/kernel/random/boot_id'
NETWORK_COMMAND = 'LC_ALL=C ip -j address show && LC_ALL=C ip -j route show'
BOOT_COMMAND = 'cat /proc/sys/kernel/random/boot_id'
BMC_PROMPT = re.compile(r'(?:^|[\r\n])(?:openUBMC|iBMC):[^\r\n]{0,128}->[ \t]*$', re.I)
SOL_CONNECTED = re.compile(r"\[Connect SOL successfully! Use 'Esc\(' to exit\.\]", re.I)
SHARED_NOTICE = re.compile(r'(?:^|[\r\n])Warning! The SOL session is in shared mode,[^\r\n]*(?:[\r\n]|$)', re.I)
HELP_COMMAND = 'ipmcset -t sol -d activate -h'
SESSIONS_COMMAND = 'ipmcget -t sol -d session'


def _sys_com_option(output):
    options = []
    shared = False
    for line in output.splitlines():
        match = re.fullmatch(r'\s*([1-9][0-9]?)\s+SYS\s+COM\s*', line, re.I)
        if match:
            options.append(match.group(1))
        shared |= bool(re.fullmatch(r'\s*0\s+Shared mode\s*', line, re.I))
    if len(options) != 1 or not shared:
        raise CollectionGap('sol_unavailable')
    return options[0]


def _require_idle_sessions(output):
    lines = [line.split() for line in output.splitlines()]
    if ['Index', 'Type', 'Mode', 'LoginTime', 'IP', 'Name'] not in lines:
        raise CollectionGap('sol_session_state_unverified')
    rows = [line for line in lines if line and line[0] in {'1', '2'}]
    if len(rows) != 2 or {line[0] for line in rows} != {'1', '2'}:
        raise CollectionGap('sol_session_state_unverified')
    if any(line[1:] != ['N/A'] * 5 for line in rows):
        raise CollectionGap('sol_busy')


class CollectionGap(ValueError):
    """A fixed local reason, never raw terminal output or exception text."""


def _now():
    return datetime.now(timezone.utc).isoformat()


class SolSession:
    """One owned SSH channel and OS login; no force-deactivation or replay."""

    def __init__(self, target, user, password, *, deadline, port=22, identity_file='',
                 check_cancelled=lambda: None):
        self.deadline = deadline
        self.check_cancelled = check_cancelled
        self.client = None
        self.channel = None
        self.socket = None
        self.buffer = ''
        self.bytes_read = 0
        self.owned_login = False
        self.login_attempted = False
        self.password_sent = False
        self.probe_running = False
        self.active = False
        self.activation_attempted = False
        self.bmc_prompt = BMC_PROMPT
        self.decoder = codecs.getincrementaldecoder('utf-8')('replace')
        try:
            import paramiko
        except ImportError:
            raise CollectionGap('ssh_transport_unavailable') from None
        self.check_cancelled()
        self.client = paramiko.SSHClient()
        # Match Debug's read-only SSH policy without persisting host keys.
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        timed_out = threading.Event()
        def abort_connect():
            timed_out.set()
            self._disconnect()
        timer = threading.Timer(self._remaining(), abort_connect)
        timer.daemon = True
        timer.start()
        try:
            self.socket = socket.create_connection((target, port), timeout=self._remaining())
            remaining = self._remaining()
            self.client.connect(hostname=target, port=port, sock=self.socket, username=user,
                password=password or None, key_filename=identity_file or None,
                timeout=remaining, banner_timeout=remaining, auth_timeout=remaining,
                allow_agent=False, look_for_keys=False)
            self.channel = self.client.get_transport().open_session(timeout=self._remaining())
            self.channel.settimeout(self._remaining())
            self.channel.get_pty(term='vt100', width=160, height=48)
            self.channel.invoke_shell()
            self._remaining()
        except Exception as error:
            self._disconnect()
            if timed_out.is_set() or time.monotonic() >= self.deadline:
                raise CollectionGap('deadline_exceeded') from None
            if isinstance(error, paramiko.AuthenticationException):
                raise CollectionGap('bmc_authentication_failed') from None
            raise CollectionGap('bmc_ssh_failed') from None
        except BaseException:
            self._disconnect()
            raise
        finally:
            timer.cancel()

    def _remaining(self, deadline=None):
        remaining = (self.deadline if deadline is None else deadline) - time.monotonic()
        if remaining <= 0:
            raise CollectionGap('deadline_exceeded')
        return remaining

    def _disconnect(self):
        if self.channel is not None:
            self.channel.close()
        if self.client is not None:
            self.client.close()
        if self.socket is not None:
            self.socket.close()

    def send(self, value, *, deadline=None, cleanup=False):
        data = value.encode('utf-8') if isinstance(value, str) else value
        while data:
            if not cleanup:
                self.check_cancelled()
            self.channel.settimeout(self._remaining(deadline))
            written = self.channel.send(data)
            if not written:
                raise CollectionGap('sol_disconnected')
            data = data[written:]

    def read(self, *, until=None, cleanup=False):
        bound = self.deadline if until is None else until
        while time.monotonic() < bound:
            if not cleanup:
                self.check_cancelled()
            if not self.channel.recv_ready():
                if self.channel.closed or self.channel.exit_status_ready():
                    raise CollectionGap('sol_disconnected')
                time.sleep(min(.02, max(0, bound - time.monotonic())))
                continue
            data = self.channel.recv(4096)
            if not data:
                raise CollectionGap('sol_disconnected')
            self.bytes_read += len(data)
            if self.bytes_read > OUTPUT_LIMIT and not cleanup:
                raise CollectionGap('output_limit')
            self.buffer = ANSI.sub('', self.buffer + self.decoder.decode(data))
            if cleanup:
                self.buffer = self.buffer[-8192:]
            return
        raise CollectionGap('deadline_exceeded')

    def wait(self, patterns, *, until=None, cleanup=False):
        while True:
            for reason, pattern in patterns:
                match = pattern.search(self.buffer)
                if match:
                    text = self.buffer[:match.start()]
                    self.buffer = self.buffer[match.end():]
                    return reason, match, text
            self.read(until=until, cleanup=cleanup)

    def bmc_command(self, command):
        self.buffer = ''
        self.send(command + '\r')
        _, match, output = self.wait([('bmc', self.bmc_prompt)])
        if self.bmc_prompt is SHELL:
            # Login banners can share the first shell-prompt line. Learn its
            # stable form from the completed, fixed BMC help command instead.
            literal = match.group().strip('\r\n').rstrip()
            self.bmc_prompt = re.compile(r'(?:^|[\r\n])' + re.escape(literal) + r'[ \t]*$')
        return output

    def login(self, user, password):
        reason, match, _ = self.wait([('bmc', BMC_PROMPT), ('shell', SHELL),
                                      ('login', LOGIN), ('password', PASSWORD)])
        if reason not in {'bmc', 'shell'}:
            raise CollectionGap('bmc_console_unavailable')
        if reason == 'shell':
            # Generic matching is restricted to the first BMC help read; its
            # exact prompt is pinned before activation or any OS credentials.
            self.bmc_prompt = SHELL
        option = _sys_com_option(self.bmc_command(HELP_COMMAND))
        _require_idle_sessions(self.bmc_command(SESSIONS_COMMAND))
        self.activation_attempted = True
        self.send('ipmcset -t sol -d activate -v ' + option + ' 0\r')
        reason, _, _ = self.wait([
            ('busy', re.compile(r'payload already active|SOL.*(?:in use|already active)', re.I)),
            ('denied', re.compile(r'permission denied|insufficient privilege|unauthorized', re.I)),
            ('unsupported', re.compile(r'SOL.*(?:disabled|not supported|unavailable)', re.I)),
            ('rejected', self.bmc_prompt),
            ('active', SOL_CONNECTED),
        ])
        if reason != 'active':
            self.activation_attempted = False
            raise CollectionGap({'busy': 'sol_busy', 'denied': 'sol_permission_denied',
                'unsupported': 'sol_unavailable', 'rejected': 'sol_activation_failed'}[reason])
        self.active = True
        # A newline reveals a login prompt. Never send commands into an
        # existing authenticated shell, firmware menu or password challenge.
        prompts = [('login', LOGIN), ('shell', SHELL), ('password', PASSWORD)]
        try:
            reason, _, _ = self.wait(prompts, until=min(self.deadline, time.monotonic() + 1))
        except CollectionGap as error:
            if str(error) != 'deadline_exceeded' or time.monotonic() >= self.deadline:
                raise
            if SHARED_NOTICE.sub('', self.buffer).strip():
                raise CollectionGap('console_not_at_login') from None
            self.buffer = ''
            self.send('\r')
            reason, _, _ = self.wait(prompts)
        if reason != 'login':
            raise CollectionGap('console_not_at_login')
        self.login_attempted = True
        self.send(user + '\r')
        reason, _, _ = self.wait([('failed', AUTH_FAILED), ('login', LOGIN), ('password', PASSWORD)])
        if reason != 'password':
            raise CollectionGap('os_authentication_failed')
        # The native escape starts with ESC; credential controls are rejected
        # before connecting, while printable leading tildes remain literal.
        self.password_sent = True
        self.send(password + '\r')
        reason, _, _ = self.wait([('failed', AUTH_FAILED), ('login', LOGIN),
                                 ('password', PASSWORD), ('shell', SHELL)])
        if reason != 'shell':
            raise CollectionGap('os_authentication_failed')
        self.owned_login = True

    def command(self, command):
        self.check_cancelled()
        if time.monotonic() >= self.deadline:
            raise CollectionGap('deadline_exceeded')
        token = uuid.uuid4().hex
        # Literal control characters occur only in printf output, not its
        # terminal echo. A prompt or echoed command cannot complete a probe.
        begin = '\x1e' + token + ':begin\x1f'
        end = re.compile('\x1e' + token + r':end:([0-9]{1,3})\x1f')
        self.buffer = ''
        self.probe_running = True
        self.send("printf '\\036%s\\037\\n' " + shlex.quote(token + ':begin')
                  + '; ' + command + "; printf '\\036%s:%s\\037\\n' "
                  + shlex.quote(token + ':end') + ' "$?"\r')
        self.wait([('begin', re.compile(re.escape(begin)))])
        _, match, output = self.wait([('end', end)])
        self.probe_running = False
        if match.group(1) != '0':
            raise CollectionGap('os_probe_failed')
        return output.replace('\r', '').strip()

    def close(self, *, deadline):
        logged_out = not self.password_sent
        closed = not self.activation_attempted
        try:
            if self.channel is not None and not self.channel.closed:
                if self.owned_login:
                    if self.probe_running:
                        self.buffer = ''
                        self.send(b'\x03', deadline=deadline, cleanup=True)
                        self.wait([('shell', SHELL)], until=min(deadline - .5, time.monotonic() + 1.5), cleanup=True)
                    self.buffer = ''
                    # A terminal's interrupt flush can discard bytes following
                    # Ctrl-C in the same write. Send exit only at an idle shell.
                    self.send('exit\r', deadline=deadline, cleanup=True)
                    self.wait([('login', LOGIN)], until=min(deadline - .5, time.monotonic() + 4), cleanup=True)
                    logged_out = True
                elif self.login_attempted:
                    # Cancel only our unfinished login input, with no account retry.
                    self.buffer = ''
                    self.send(b'\x03\x04', deadline=deadline, cleanup=True)
                    self.wait([('login', LOGIN)], until=min(deadline, time.monotonic() + 1.5), cleanup=True)
                    logged_out = True
        except (OSError, CollectionGap):
            pass
        finally:
            if self.active:
                try:
                    self.buffer = ''
                    self.send(b'\x1b(', deadline=deadline, cleanup=True)
                    self.wait([('bmc', self.bmc_prompt)], until=deadline, cleanup=True)
                    closed = True
                except (OSError, CollectionGap):
                    pass
            self._disconnect()
        return (["os_logout_unconfirmed"] if not logged_out else []) + (["sol_close_unconfirmed"] if not closed else [])


def _identity(output):
    lines = output.splitlines()
    if (len(lines) != 5 or not re.fullmatch(r'[0-9]{1,10}', lines[0])
            or not re.fullmatch(r'/dev/(?:tty[A-Za-z0-9]+|hvc[0-9]+)', lines[1])
            or not lines[2].startswith('Linux ') or len(lines[2]) > 256
            or not re.fullmatch(r'[A-Za-z0-9_.-]{1,253}', lines[3])
            or not BOOT.fullmatch(lines[4])):
        raise CollectionGap('os_identity_unverified')
    return dict(zip(('uid', 'tty', 'kernel', 'hostname', 'boot_id'), lines))


def _network(output):
    try:
        decoder = json.JSONDecoder()
        addresses, end = decoder.raw_decode(output.lstrip())
        routes, end2 = decoder.raw_decode(output.lstrip()[end:].lstrip())
        if output.lstrip()[end:].lstrip()[end2:].strip():
            raise ValueError
        if (not isinstance(addresses, list) or not isinstance(routes, list)
                or len(addresses) > 64 or len(routes) > 128):
            raise ValueError
        interfaces = []
        for row in addresses:
            name = row['ifname']
            if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,64}', name):
                raise ValueError
            entries = row['addr_info']
            if not isinstance(entries, list) or len(entries) > 32:
                raise ValueError
            cidrs = []
            for item in entries:
                cidrs.append(str(ipaddress.ip_interface(str(item['local']) + '/' + str(item['prefixlen']))))
            state = row.get('operstate', 'UNKNOWN')
            if state not in {'UNKNOWN', 'NOTPRESENT', 'DOWN', 'LOWERLAYERDOWN', 'TESTING', 'DORMANT', 'UP'}:
                raise ValueError
            interfaces.append({'name': name, 'state': state, 'addresses': cidrs})
        selected_routes = []
        for row in routes:
            if not isinstance(row, dict) or not isinstance(row.get('dst'), str):
                raise ValueError
            entry = {}
            for key in ('dst', 'gateway', 'dev', 'prefsrc', 'type'):
                if key in row:
                    if not isinstance(row[key], str) or len(row[key]) > 128:
                        raise ValueError
                    entry[key] = row[key]
            if entry['dst'] != 'default':
                ipaddress.ip_network(entry['dst'], strict=False)
            for key in ('gateway', 'prefsrc'):
                if key in entry:
                    ipaddress.ip_address(entry[key])
            if 'dev' in entry and not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,64}', entry['dev']):
                raise ValueError
            selected_routes.append(entry)
        return {'interfaces': interfaces, 'routes': selected_routes}
    except (ValueError, KeyError, TypeError, RecursionError):
        raise CollectionGap('malformed_network') from None


def collect_os_console(names, target, values, *, deadline, check_cancelled=lambda: None,
                       ssh_port=22, session_factory=SolSession):
    """No OS IP, shell command or credentials enter through the Agent schema."""
    validate_os_console_names(names)
    result = {'requested': list(names), 'transport': 'bmc-ssh-sol', 'complete': False,
              'gaps': [], 'started_at': _now()}
    session = None
    try:
        target = str(ipaddress.ip_address(target))
        gap = values.get('__console_gap__')
        if gap in {'bmc_ssh_credentials_missing', 'os_password_credentials_missing'}:
            raise CollectionGap(gap)
        if type(ssh_port) is not int or not 1 <= ssh_port <= 65535:
            raise CollectionGap('bmc_ssh_port_invalid')
        credentials = []
        for prefix in ('OPENUBMC_SSH', 'OPENUBMC_OS_SSH'):
            user = values.get(prefix + '_USER', '')
            password = values.get(prefix + '_PASSWORD', '')
            identity_file = values.get('OPENUBMC_SSH_IDENTITY_FILE', '') if not credentials else ''
            if not user or not (password or identity_file):
                raise CollectionGap('os_password_credentials_missing' if credentials else 'bmc_ssh_credentials_missing')
            if (any(ord(char) < 32 or ord(char) == 127 for char in user + password + identity_file)
                    or len(user) > 256 or len(password) > 1024 or len(identity_file) > 4096):
                raise CollectionGap('console_credentials_invalid')
            credentials.append((user, password))
        remaining = deadline - time.monotonic()
        if remaining <= 2:
            raise CollectionGap('deadline_exceeded')
        cleanup_seconds = min(5, max(2, remaining * .2))
        session = session_factory(target, *credentials[0], deadline=deadline - cleanup_seconds,
                                  port=ssh_port, identity_file=values.get('OPENUBMC_SSH_IDENTITY_FILE', ''),
                                  check_cancelled=check_cancelled)
        session.login(*credentials[1])
        identity = _identity(session.command(IDENTITY_COMMAND))
        result['identity'] = identity
        if 'network' in names:
            result['network'] = _network(session.command(NETWORK_COMMAND))
        if session.command(BOOT_COMMAND) != identity['boot_id']:
            raise CollectionGap('os_boot_changed')
        result['complete'] = True
    except CollectionGap as error:
        result['gaps'].append(str(error))
    except TimeoutError:
        result['gaps'].append('deadline_exceeded')
    except (OSError, ValueError, RuntimeError):
        result['gaps'].append('sol_transport_failed')
    finally:
        if session is not None:
            cleanup_gaps = session.close(deadline=deadline)
            if cleanup_gaps:
                result['complete'] = False
                result['gaps'].extend(cleanup_gaps)
    result['completed_at'] = _now()
    # Terminal input/output is deliberately absent; redact even typed facts.
    secrets = tuple(values.get(prefix + '_PASSWORD', '') for prefix in ('OPENUBMC_SSH', 'OPENUBMC_OS_SSH'))
    def redact(value):
        if isinstance(value, dict):
            return {key: redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, str):
            return _RUNTIME.redact_text(value, secret_values=secrets)
        return value
    return redact(result)
