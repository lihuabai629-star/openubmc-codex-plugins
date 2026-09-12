#!/usr/bin/env python3
"""Verify and operate an installed OpenUBMC Codex plugin."""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import os
import fcntl
import platform
import shutil
import signal
import tempfile
import subprocess
import sys
import time
import threading

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


class DependencyCancelled(ValueError):
    pass


def _cancel_dependency_process(_signum, _frame):
    raise DependencyCancelled('Dependency preparation cancelled')


def prepare_for_start(content: dict[str, bytes], capability: str) -> None:
    """Keep first-use downloads owned by the MCP client's lifetime on Linux."""
    parent = os.getppid()
    if sys.platform != 'linux' or parent <= 1:
        raise ValueError('First-start dependency preparation requires a live Linux parent')
    signal.signal(signal.SIGTERM, _cancel_dependency_process)
    signal.signal(signal.SIGINT, _cancel_dependency_process)
    stopped = threading.Event()
    def watch_parent():
        # Linux parent-death signals follow the spawning thread's lifetime.
        # Codex uses worker threads, so watch process reparenting instead.
        while not stopped.wait(.1):
            if os.getppid() != parent:
                os.kill(os.getpid(), signal.SIGTERM)
                return
    watcher = threading.Thread(target=watch_parent, daemon=True)
    watcher.start()
    try:
        if os.getppid() != parent:
            raise DependencyCancelled('MCP client exited before dependency preparation')
        prepare_dependencies(content, False, capability=capability, lock_timeout=540)
    finally:
        stopped.set()
        watcher.join(timeout=1)
    if os.getppid() != parent:
        raise DependencyCancelled('MCP client exited during dependency preparation')


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode()


def verify(root: Path = ROOT) -> tuple[dict, dict[str, bytes]]:
    lock_path = root/'plugin-lock.json'
    if root.is_symlink() or lock_path.is_symlink():
        raise ValueError('plugin root and lock must not be symbolic links')
    lock = json.loads(lock_path.read_bytes())
    unsigned = dict(lock)
    digest = unsigned.pop('content_digest', None)
    if digest != hashlib.sha256(canonical(unsigned)).hexdigest():
        raise ValueError('plugin lock digest mismatch')
    if lock.get('schema') != 'openubmc.codex-plugin.v1':
        raise ValueError('unsupported plugin lock schema')
    content = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('plugin contains symbolic link: ' + str(path.relative_to(root)))
        if path.is_file() and path != lock_path:
            relative = path.relative_to(root)
            # Python may create runtime bytecode beside packaged scripts. These
            # caches are derived files and must never change package identity.
            if (path.suffix == '.pyc' and '__pycache__' in relative.parts
                    and relative.as_posix() not in lock['files']):
                continue
            content[relative.as_posix()] = path.read_bytes()
    if {name: hashlib.sha256(data).hexdigest() for name, data in content.items()} != lock['files']:
        raise ValueError('plugin file inventory mismatch; reinstall the verified archive')
    for name in content:
        if PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts:
            raise ValueError('invalid plugin member')
    manifest = json.loads(content['.codex-plugin/plugin.json'])
    if manifest['version'] != lock['version'] or manifest['name'] != lock['name']:
        raise ValueError('plugin manifest identity mismatch')
    if lock.get('manifest_digest') != hashlib.sha256(content['.codex-plugin/plugin.json']).hexdigest():
        raise ValueError('plugin manifest digest mismatch')
    return lock, content


def dependency_root(content: dict[str, bytes], capability: str) -> Path:
    identity = {'schema': 'capability-target.v2', 'capability': capability,
                'machine': platform.machine(), 'platform': sys.platform}
    if capability == 'runtime':
        identity.update(python=sys.version, lock=hashlib.sha256(content['requirements.lock']).hexdigest())
    elif capability == 'kb':
        node = subprocess.run(['node', '--version'], env=node_environment(), timeout=10, check=True, capture_output=True, text=True).stdout.strip()
        if int(node.removeprefix('v').split('.')[0]) < 20:
            raise ValueError('KB requires Node 20 or newer')
        identity.update(node=node, lock=hashlib.sha256(content['openubmc-kb-mcp/package-lock.json']).hexdigest())
    else:
        raise ValueError('Unknown dependency capability')
    key = hashlib.sha256(canonical(identity)).hexdigest()
    data = Path(os.environ.get('XDG_DATA_HOME') or Path.home()/'.local/share')
    return data/'openubmc/plugin-dependencies'/capability/key


def dependency_inventory(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root).as_posix()
        if relative == 'receipt.json':
            continue
        if path.is_symlink():
            if not path.resolve().is_relative_to(root.resolve()):
                raise ValueError('dependency symlink escapes its cache')
            result[relative] = {'link': os.readlink(path)}
        elif path.is_file():
            result[relative] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'mode': path.stat().st_mode & 0o777}
    return result


def check_dependencies(root: Path) -> dict:
    receipt = root/'receipt.json'
    if not receipt.is_file():
        raise ValueError('Dependencies are not prepared; run pluginctl.py prepare')
    if root.is_symlink() or receipt.is_symlink():
        raise ValueError('Dependency cache must not be a symbolic link')
    record = json.loads(receipt.read_bytes())
    if not isinstance(record, dict) or record.get('schema') != 'openubmc.plugin-dependencies.v2' or record.get('files') != dependency_inventory(root):
        raise ValueError('Dependency cache drift; run pluginctl.py prepare --repair')
    return record


def _prepare_timeout(command: list[str]) -> float:
    default = 300.0 if command and command[0] == sys.executable else 180.0
    raw = os.environ.get('OPENUBMC_PLUGIN_PREPARE_TIMEOUT_SEC', '')
    try:
        value = float(raw) if raw else default
    except ValueError:
        value = default
    if not math.isfinite(value) or value <= 0:
        raise ValueError('Dependency timeout must be finite and positive')
    return value


def _run_dependency_command(command: list[str], env: dict[str, str], *, timeout: float, stage: str, mutex_fd: int) -> None:
    """Stop the complete owned process group before cache cleanup or retry."""
    started=time.monotonic()
    process = subprocess.Popen(command, env=env, stdout=sys.stderr, stderr=sys.stderr,
                               start_new_session=True, pass_fds=(mutex_fd,))
    print(json.dumps({'stage':stage,'status':'started','pid':process.pid,'timeout_seconds':timeout}),file=sys.stderr,flush=True)
    try:
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            print(json.dumps({'stage': stage, 'status': 'timeout'}, sort_keys=True), file=sys.stderr, flush=True)
            raise ValueError('Dependency preparation timed out: ' + command[0]) from exc
        if return_code:
            print(json.dumps({'stage': stage, 'status': 'failed', 'exit_code': return_code}, sort_keys=True), file=sys.stderr, flush=True)
            raise ValueError('Dependency preparation failed in ' + command[0] + ' (exit ' + str(return_code) + ')')
        print(json.dumps({'stage': stage, 'status': 'completed', 'pid':process.pid, 'elapsed_seconds':time.monotonic()-started}, sort_keys=True), file=sys.stderr, flush=True)
    finally:
        # Even a successfully reaped parent can leave descendants holding pipes.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def prepare_dependencies(content: dict[str, bytes], repair: bool, *, capability: str, offline: bool = False, retries: int = 0,
                          pip_timeout: float | None = None, npm_timeout: float | None = None,
                          lock_timeout: float = 30.0) -> Path:
    root = dependency_root(content, capability)
    root.parent.mkdir(parents=True, exist_ok=True)
    with (root.parent/(root.name+'.lock')).open('a') as mutex:
        deadline = time.monotonic() + max(0.1, lock_timeout)
        while True:
            try:
                fcntl.flock(mutex, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno != errno.EWOULDBLOCK or time.monotonic() >= deadline:
                    raise ValueError('Dependency cache lock timed out') from exc
                time.sleep(0.05)
        staging = root.parent / (root.name + '.staging')
        backup = root.parent / (root.name + '.previous')
        for path in (root, staging, backup):
            if path.is_symlink():
                raise ValueError('Dependency cache must not be a symbolic link')
        # A worker inherits the lock, so abandoned stages cannot be removed
        # while an installer from a killed prepare process is still writing.
        if backup.exists() and not root.exists():
            backup.rename(root)
        if staging.exists():
            shutil.rmtree(staging)
        if (root/'receipt.json').exists() and not repair:
            check_dependencies(root)
            if backup.exists():
                shutil.rmtree(backup)
            return root
        if root.exists() and root.is_symlink():
            raise ValueError('Dependency cache must not be a symbolic link')
        staging.mkdir(mode=0o700)
        knowledge = staging/'knowledge'
        env = node_environment()
        if capability == 'runtime':
            (staging/'requirements.lock').write_bytes(content['requirements.lock'])
            command = [sys.executable, '-I', '-B', '-m', 'pip', 'install', '--disable-pip-version-check', '--no-compile', '--only-binary=:all:', '--require-hashes', '--target', str(staging/'python-packages'), '-r', str(staging/'requirements.lock')]
            if offline:
                command.append('--no-index')
        else:
            knowledge.mkdir()
            for name in ('package.json', 'package-lock.json'):
                (knowledge/name).write_bytes(content['openubmc-kb-mcp/'+name])
            command = ['npm', 'ci', '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund', '--prefix', str(knowledge)]
            if offline:
                command.append('--offline')
        commands = [command]
        try:
            for command in commands:
                stage = 'pip' if command[0] == sys.executable else 'npm'
                timeout = pip_timeout if stage == 'pip' and pip_timeout is not None else npm_timeout if stage == 'npm' and npm_timeout is not None else _prepare_timeout(command)
                for attempt in range(retries + 1):
                    if attempt:
                        partial = staging/'python-packages' if stage == 'pip' else knowledge/'node_modules'
                        if partial.exists():
                            shutil.rmtree(partial)
                    try:
                        _run_dependency_command(command, env, timeout=timeout, stage=stage, mutex_fd=mutex.fileno())
                        break
                    except DependencyCancelled:
                        raise
                    except ValueError:
                        if attempt == retries:
                            raise
            # Dependency identity covers the complete installed content, including
            # Node production dependencies; no package writes occur during startup.
            record = {'schema': 'openubmc.plugin-dependencies.v2', 'capability': capability, 'files': dependency_inventory(staging)}
            (staging/'receipt.json').write_bytes(canonical(record))
            check_dependencies(staging)
            if backup.exists():
                shutil.rmtree(backup)
            if root.exists():
                root.rename(backup)
            try:
                staging.rename(root)
            except Exception:
                if backup.exists() and not root.exists():
                    backup.rename(root)
                raise
            if backup.exists():
                shutil.rmtree(backup)
            print(json.dumps({'stage': 'publish', 'status': 'completed'}, sort_keys=True), file=sys.stderr, flush=True)
        except Exception:
            if staging.exists():
                shutil.rmtree(staging)
            raise
    return root


def execution_snapshot(content: dict[str, bytes], lock: dict, dependencies: Path) -> Path:
    record = check_dependencies(dependencies)
    expected = {name: {'sha256': hashlib.sha256(data).hexdigest(), 'mode': 0o500 if name.endswith('.sh') else 0o400}
                for name, data in content.items()}
    dependency_paths = {}
    for name, identity in record['files'].items():
        if name.startswith('python-packages/'):
            destination = name
        elif name.startswith('knowledge/node_modules/'):
            destination = 'openubmc-kb-mcp/'+name.removeprefix('knowledge/')
        else:
            continue
        expected[destination] = identity
        dependency_paths[destination] = name
    key = hashlib.sha256(canonical({'plugin': lock['content_digest'], 'files': expected})).hexdigest()
    cache = Path(os.environ.get('XDG_CACHE_HOME') or Path.home()/'.cache')/'openubmc/plugin-executions'
    cache.mkdir(parents=True, exist_ok=True)
    snapshot = cache/key
    with (cache/(key+'.lock')).open('a') as mutex:
        fcntl.flock(mutex, fcntl.LOCK_EX)
        if not snapshot.exists():
            with tempfile.TemporaryDirectory(prefix='.prepare-', dir=cache) as temporary:
                stage = Path(temporary)/'snapshot'
                stage.mkdir()
                for name, identity in expected.items():
                    path = stage/name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if 'link' in identity:
                        path.symlink_to(identity['link'])
                    else:
                        data = content[name] if name in content else (dependencies/dependency_paths[name]).read_bytes()
                        if hashlib.sha256(data).hexdigest() != identity['sha256']:
                            raise ValueError('Dependency cache changed during snapshot creation')
                        path.write_bytes(data)
                        path.chmod(identity['mode'])
                if dependency_inventory(stage) != expected:
                    raise ValueError('Execution snapshot inventory mismatch')
                stage.rename(snapshot)
        if snapshot.is_symlink() or dependency_inventory(snapshot) != expected:
            raise ValueError('Execution snapshot drift; remove the damaged execution cache and retry')
    return snapshot


def node_environment() -> dict[str, str]:
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    for key in tuple(env):
        if key.upper() in {'NODE_OPTIONS', 'NODE_PATH', 'NPM_CONFIG_NODE_OPTIONS'}:
            env.pop(key)
    return env


def local_credentials_status(content: dict[str, bytes]) -> dict[str, object]:
    """Inspect local sources using verified Runtime modules, without dependencies."""
    import sys
    import types
    prefix = '_verified_openubmc_credentials'
    package = types.ModuleType(prefix)
    package.__path__ = []
    loaded = {prefix: package}
    sys.modules[prefix] = package
    try:
        for name in ('credential_file', 'configuration', 'credentials'):
            module = types.ModuleType(prefix + '.' + name)
            module.__package__ = prefix
            sys.modules[module.__name__] = loaded[module.__name__] = module
            path = 'skills/openubmc-target-runtime/openubmc_target_runtime/' + name + '.py'
            exec(compile(content[path], '<verified-' + name + '>', 'exec'), module.__dict__)
        return module.LocalCredentialSource().status()
    finally:
        for name in loaded:
            sys.modules.pop(name, None)


def probe_server(command: str, content: dict[str, bytes], lock: dict) -> dict[str, object]:
    """Perform a bounded MCP initialize/tools/list probe through the public launcher."""
    request = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                          'params': {'protocolVersion': '2024-11-05', 'capabilities': {},
                                     'clientInfo': {'name': 'openubmc-plugin-doctor', 'version': lock['version']}}}) + '\n'
    request += json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'})+'\n'
    request += json.dumps({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})+'\n'
    probe_env = node_environment()
    probe_env['OPENUBMC_MCP_FORMAL_RUN'] = '0'
    probe_env['OPENUBMC_MCP_PARENT_PID'] = str(os.getpid())
    process = subprocess.Popen([sys.executable, "-B", '-I', str(ROOT/'scripts/pluginctl.py'), command],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, env=probe_env)
    try:
        stdout, stderr = process.communicate(request, timeout=12)
    except subprocess.TimeoutExpired:
        process.kill(); stdout, stderr = process.communicate()
    messages = []
    for line in stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict): messages.append(value)
    initialized = any(value.get('id') == 1 and isinstance(value.get('result'), dict) for value in messages)
    server = next((value['result'].get('serverInfo') for value in messages if value.get('id') == 1 and isinstance(value.get('result'), dict)), {})
    names = {tool.get('name') for value in messages if value.get('id') == 2
             for tool in value.get('result', {}).get('tools', [])}
    expected = {'observe', 'execute'} if command == 'runtime' else {'openubmc_kb_query', 'openubmc_kb_status', 'openubmc_kb_list'}
    ok = initialized and names == expected and process.returncode == 0
    return {'ok': ok, 'server': server, 'tools': sorted(names), 'stderr': stderr[-1000:] if not ok else ''}


def write_timing(path: Path | None, stage: str, started: float) -> None:
    if path is not None:
        with path.open('a') as stream:
            stream.write(json.dumps({'stage': stage, 'elapsed_seconds': time.monotonic()-started})+'\n')


def launch(command: str, content: dict[str, bytes], lock: dict, timings: Path | None = None, page_args: list[str] | None = None) -> int:
    if command == 'configure':
        # Recovery must remain accessible when either dependency cache is broken.
        # The guarded page and configuration store use only the standard library.
        argv = [sys.executable, '-I', '-B', str(ROOT/'skills/openubmc-environment-setup/scripts/config_page.py'), *(page_args or [])]
        os.execvpe(argv[0], argv, node_environment())
        return 0
    started = time.monotonic()
    dependencies = dependency_root(content, "runtime" if command == "configure" else command)
    write_timing(timings, 'dependency_identity', started)
    if not (dependencies/'receipt.json').is_file():
        raise ValueError('Dependencies are not prepared; run pluginctl.py prepare')
    started = time.monotonic()
    with (dependencies.parent/(dependencies.name+'.lock')).open('a') as mutex:
        fcntl.flock(mutex, fcntl.LOCK_SH)
        write_timing(timings, 'dependency_lock', started)
        started = time.monotonic()
        snapshot = execution_snapshot(content, lock, dependencies)
        write_timing(timings, 'execution_snapshot', started)
    env = node_environment()
    env['OPENUBMC_MCP_SOURCE_COMMIT'] = lock['source_commit']
    env['OPENUBMC_PLUGIN_CONTENT_DIGEST'] = lock['content_digest']
    if command == 'runtime':
        argv = [sys.executable, '-I', '-B', '-c',
                'import sys,runpy;sys.path.insert(0,sys.argv[1]);runpy.run_path(sys.argv[2],run_name="__main__")',
                str(snapshot/'python-packages'), str(snapshot/'scripts/launch_runtime.py')]
    else:
        argv = ['node', str(snapshot/'openubmc-kb-mcp/src/server.js')]
    # Preserve the direct Codex parent across launch. Execution caches contain
    # only verified release/dependency bytes and persist independently of state.
    os.execvpe(argv[0], argv, env)
    return 0


def positive_timeout(value: str) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('timeout must be a number') from exc
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError('timeout must be finite and positive')
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['verify', 'prepare', 'doctor', 'runtime', 'kb', 'configure', 'migrate', 'repair-overrides', 'restore-legacy'])
    parser.add_argument('--home', type=Path, default=Path.home())
    parser.add_argument('--codex-home', type=Path, default=Path(os.environ['CODEX_HOME']) if os.environ.get('CODEX_HOME') else None)
    parser.add_argument('--transaction', default='')
    parser.add_argument('--expected-config-digest')
    migration_mode = parser.add_mutually_exclusive_group()
    migration_mode.add_argument('--disable-only', dest='migration_mode', action='store_const', const='disable-only', default='disable-only', help='Disable legacy registrations while retaining files (default)')
    migration_mode.add_argument('--remove', dest='migration_mode', action='store_const', const='remove', help='Remove owned legacy registrations and Skill links')
    parser.add_argument('--preview', action='store_true', help='Inspect migration without changing files')
    parser.add_argument('--target-plugin', default='openubmc@openubmc-public', help='Plugin registration to preserve during migration')
    parser.add_argument('--no-browser', action='store_true')
    parser.add_argument('--target', action='append', default=[])
    parser.add_argument('--purpose', choices=['bmc','os'], default='bmc')
    parser.add_argument('--transport', choices=['ssh','redfish'], default='ssh')
    parser.add_argument('--capability', choices=['runtime', 'kb', 'all'], default='all', help='Capability to prepare or diagnose')
    parser.add_argument('--repair', action='store_true', help='Recreate a damaged dependency cache')
    parser.add_argument('--prepare-on-start', action='store_true', help='Prepare locked dependencies before the first MCP startup')
    parser.add_argument('--offline', action='store_true', help='Disable package index access')
    parser.add_argument('--retries', type=int, choices=range(4), default=0, help='Additional bounded attempts per stage')
    parser.add_argument('--pip-timeout', type=positive_timeout, help='pip stage deadline in seconds (default 300)')
    parser.add_argument('--npm-timeout', type=positive_timeout, help='npm stage deadline in seconds (default 180)')
    parser.add_argument('--lock-timeout', type=positive_timeout, default=30, help='Dependency lock wait in seconds')
    parser.add_argument('--timings', type=Path, help='Write startup phase durations to a new external JSONL file')
    args = parser.parse_args()
    try:
        if args.timings is not None:
            if args.timings.resolve().is_relative_to(ROOT.resolve()):
                raise ValueError('Timing output must be outside the immutable plugin')
            args.timings.open('x').close()
        started = time.monotonic()
        lock, content = verify()
        write_timing(args.timings, 'verify', started)
        report = {'ok': True, 'source_commit': lock['source_commit'], 'version': lock['version'],
                  'content_digest': lock['content_digest'], 'skills': lock['skills']}
        if args.command in ('migrate', 'repair-overrides', 'restore-legacy'):
            import types
            module = types.ModuleType('openubmc_plugin_install')
            exec(compile(content['scripts/plugin_install.py'], '<verified-plugin-install>', 'exec'), module.__dict__)
            skill_paths = [item['path'] for item in json.loads(content['workflow.json'])['skills']]
            if args.command in ('migrate', 'repair-overrides'):
                operation = module.preview if args.preview else module.migrate
                binding = {'expected_before_digest': args.expected_config_digest} if not args.preview else {}
                result = operation(args.home, skill_paths, args.codex_home, mode='repair-overrides' if args.command == 'repair-overrides' else args.migration_mode, target_plugin=args.target_plugin, **binding)
            else:
                result = module.restore(args.home, args.transaction, args.codex_home)
            print(json.dumps(result, sort_keys=True)); return 0 if result['ok'] else 2
        if args.command == 'prepare':
            signal.signal(signal.SIGTERM, _cancel_dependency_process)
            signal.signal(signal.SIGINT, _cancel_dependency_process)
            capabilities = ('runtime', 'kb') if args.capability == 'all' else (args.capability,)
            roots = {}
            for capability in capabilities:
                roots[capability] = str(prepare_dependencies(content, args.repair, capability=capability, offline=args.offline, retries=args.retries, pip_timeout=args.pip_timeout, npm_timeout=args.npm_timeout, lock_timeout=args.lock_timeout))
            report['capability_dependencies'] = roots
            report['dependencies'] = roots.get('runtime', roots.get('kb'))
        elif args.command == 'configure':
            page_args=['--purpose',args.purpose,'--transport',args.transport,'--home',str(args.home)]
            if args.codex_home: page_args.extend(['--codex-home',str(args.codex_home)])
            if args.no_browser: page_args.append('--no-browser')
            for target in args.target: page_args.extend(['--target',target])
            return launch('configure',content,lock,page_args=page_args)
        elif args.command in ('runtime', 'kb'):
            if args.prepare_on_start and not (dependency_root(content, args.command)/'receipt.json').is_file():
                prepare_for_start(content, args.command)
            return launch(args.command, content, lock, args.timings)
        elif args.command == 'doctor':
            report['package_integrity'] = True
            capabilities = ('runtime', 'kb') if args.capability == 'all' else (args.capability,)
            report['capabilities'] = {}
            report['mcp_health'] = {}
            for capability in capabilities:
                status = {'dependencies_ready': False, 'startup_ready': False}
                try:
                    root = dependency_root(content, capability)
                    check_dependencies(root)
                    status.update(dependencies_ready=True, dependencies=str(root))
                    health = probe_server(capability, content, lock)
                    status['startup_ready'] = health['ok']
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    status['error'] = str(error)
                    health = {'ok': False, 'error': 'dependencies unavailable'}
                report['capabilities'][capability] = status
                report['mcp_health'][capability] = health
            report['dependencies_ready'] = all(item['dependencies_ready'] for item in report['capabilities'].values())
            report['credentials'] = local_credentials_status(content)
            report['credentials_configured'] = report['credentials']['configured']
            report['startup_ready'] = report['dependencies_ready'] and all(item.get('ok') for item in report['mcp_health'].values())
            import types
            module = types.ModuleType('openubmc_plugin_install')
            exec(compile(content['scripts/plugin_install.py'], '<verified-plugin-install>', 'exec'), module.__dict__)
            configuration = module.preview(args.home, [], args.codex_home,
                                           mode='repair-overrides', target_plugin=args.target_plugin)
            configuration['ready'] = configuration['ok'] and not configuration['would_change']
            if not configuration['ready']:
                configuration['repair_action'] = ('pluginctl.py repair-overrides --preview; '
                    'reconcile custom settings if reported, then pluginctl.py repair-overrides')
            report['codex_configuration'] = configuration
            report['ok'] = report['startup_ready'] and configuration['ready']
        print(json.dumps(report, sort_keys=True))
        return 0 if report['ok'] else 2
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({'ok': False, 'error': str(error)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
