"""Exercise Python entrypoints against a final immutable plugin copy."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import select
import shutil
import subprocess
import sys
import tempfile
import unittest

if __package__:
    from .plugin_fixture import package_fixture
else:
    from plugin_fixture import package_fixture


MODULE_IMPORT = '''
from pathlib import Path
import runpy, sys
root = Path(sys.argv[1])
entry = root/'skills/openubmc-debug/scripts/target_runtime_cli.py'
guard = runpy.run_path(str(entry.with_name('_plugin_entrypoint.py')))
cache = guard['initialize'](entry)
import target_runtime_cli
raise SystemExit(target_runtime_cli.main(['--help']))
'''


def inventory(root):
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob('*') if path.is_file()}


class PythonEntrypointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        cls.original = package_fixture(cls.base)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=self.base)
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.plugin = self.home/'plugin'
        shutil.copytree(self.original, self.plugin)
        self.before = inventory(self.plugin)
        self.environment = {key: value for key, value in os.environ.items()
                            if not key.startswith(('PYTHON', 'OPENUBMC_', 'OPENAI_', 'CODEX_', 'XDG_'))}
        self.environment.update(HOME=str(self.home), CODEX_HOME=str(self.home/'.codex'),
                                XDG_DATA_HOME=str(self.home/'.local/share'),
                                XDG_CONFIG_HOME=str(self.home/'.config'))

    def run_python(self, *arguments, input_text=''):
        return subprocess.run([sys.executable, *map(str, arguments)], cwd=self.home,
                              env=self.environment, input=input_text, capture_output=True, text=True, timeout=30)

    def test_configuration_cli_and_check_worker_preserve_package_integrity(self):
        # Use the assembled product with an empty dependency lock: this HTTP/Conan
        # scenario uses only the standard library and a controlled external tool.
        requirements = self.plugin/'requirements.lock'
        requirements.write_bytes(b'')
        lock_path = self.plugin/'plugin-lock.json'
        lock = json.loads(lock_path.read_bytes())
        lock['files']['requirements.lock'] = hashlib.sha256(b'').hexdigest()
        del lock['content_digest']
        canonical = lambda value: (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False)+'\n').encode()
        lock['content_digest'] = hashlib.sha256(canonical(lock)).hexdigest()
        lock_path.write_bytes(canonical(lock))
        before = inventory(self.plugin)
        binary = self.home/'bin'; binary.mkdir()
        conan = binary/'conan'
        conan.write_text('#!/bin/sh\necho "ERROR: Connection refused" >&2\nexit 1\n')
        conan.chmod(0o700)
        env = dict(self.environment, XDG_CACHE_HOME=str(self.home/'cache'),
                   PIP_NO_INDEX='1', PATH=str(binary)+os.pathsep+os.environ['PATH'])
        from urllib.parse import urlsplit
        from urllib.request import Request, urlopen
        with tempfile.TemporaryFile(mode='w+') as errors:
            child = subprocess.Popen([sys.executable, '-I', str(self.plugin/'scripts/pluginctl.py'),
                                      'configure', '--no-browser'], cwd=self.home, env=env,
                                     stdout=subprocess.PIPE, stderr=errors, text=True)
            try:
                self.assertTrue(select.select([child.stdout], [], [], 30)[0], 'page launch timed out')
                url = urlsplit(child.stdout.readline().strip())
                errors.seek(0)
                self.assertEqual(url.scheme, 'http', errors.read())
                origin = f'http://{url.netloc}'
                def request(path, data):
                    with urlopen(Request(origin+path, data=json.dumps(data).encode(), headers={
                            'Origin': origin, 'X-OpenUBMC-Session': url.fragment,
                            'Content-Type': 'application/json'}), timeout=15) as response:
                        return json.load(response)
                saved = request('/api/save', {'kind':'conan', 'expected_revision':None,
                    'config':{'credentials':{'fixture':{'user':'fixture',
                        'password':{'action':'replace','value':'fixture-package-secret'}}}}})
                request('/api/activate', {'kind':'conan','revision':saved['revision'],
                                          'expected_active_revision':None})
                checked = request('/api/check', {'kind':'conan','target':{'remote':'fixture'},'confirm':True})
                self.assertEqual(checked['code'], 'network_error', checked)
                self.assertFalse(checked['verified'])
                self.assertNotIn('fixture-package-secret', json.dumps(checked))
                request('/api/close', {})
                self.assertEqual(child.wait(timeout=10), 0)
                self.assertEqual(inventory(self.plugin), before)
                verified = subprocess.run([sys.executable, '-I', str(self.plugin/'scripts/pluginctl.py'),
                                           'verify'], env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(verified.returncode, 0, verified.stderr)
            finally:
                if child.poll() is None:
                    child.terminate(); child.wait(timeout=10)
                child.stdout.close()

    def test_ordinary_debug_help_preserves_plugin_integrity(self):
        result = self.run_python(self.plugin/'skills/openubmc-debug/scripts/target_runtime_cli.py', '--help')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(inventory(self.plugin), self.before)
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from plugin_archive import verify_directory
        self.assertEqual(verify_directory(self.plugin)['name'], 'openubmc')
        verified = self.run_python('-I', self.plugin/'scripts/pluginctl.py', 'verify')
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertTrue(json.loads(verified.stdout)['ok'])

    def test_supported_cli_help_preserves_the_complete_package(self):
        groups = {
            'openubmc-build': ('check_dependency_delta', 'check_rootfs_access', 'create_build_plan',
                'detect_changed_components', 'ensure_planned_version', 'finalize_product_attempt',
                'run_bmcgo_checked', 'run_build_attempt', 'update_manifest_conan_ref',
                'verify_product_artifact', 'write_artifact_metadata'),
            'openubmc-debug': ('active_alarms', 'busctl_remote', 'collect_logs', 'compare_remote',
                'doctor', 'mdbctl_remote', 'package_skill', 'preflight_checks',
                'preflight_recommendations', 'preflight_remote', 'read_remote_file',
                'target_runtime_cli', 'workflow_remote'),
            'openubmc-environment-setup': ('install_environment',),
            'openubmc-live-patch': ('deploy_current_patch', 'deploy_live_file', 'infer_live_patch', 'rollback_live_file'),
            'openubmc-log-analyzer': ('package_skill', 'pull_bundle'),
            'openubmc-upgrade': ('artifact_identity', 'preflight_upgrade', 'redfish_credentials'),
        }
        entries = [f'skills/{skill}/scripts/{name}.py' for skill, names in groups.items() for name in names]
        entries += ['scripts/install_plugin.py', 'scripts/plugin_admin.py', 'scripts/pluginctl.py']
        entries += [f'skills/openubmc-target-runtime/tools/{name}.py'
                    for name in ('benchmark_context_runtime', 'package_runtime_skill', 'smoke_debug_context')]
        entries += ['skills/openubmc-target-runtime/openubmc_target_runtime/release.py']
        for entry in entries:
            with self.subTest(entry=entry):
                result = self.run_python(self.plugin/entry, '--help')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(inventory(self.plugin), self.before)
        self.assertFalse(list(self.plugin.rglob('__pycache__')))

    def test_direct_runtime_mcp_initializes_without_modifying_the_package(self):
        request = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                   'params': {'protocolVersion': '2024-11-05', 'capabilities': {},
                              'clientInfo': {'name': 'package-test', 'version': '1'}}}
        result = self.run_python(self.plugin/'skills/openubmc-debug/scripts/target_runtime_mcp.py',
                                 input_text=json.dumps(request) + '\n')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        response = next(json.loads(line) for line in result.stdout.splitlines() if json.loads(line).get('id') == 1)
        self.assertIn('serverInfo', response['result'])
        self.assertEqual(inventory(self.plugin), self.before)

    def test_supported_module_import_initializes_before_the_importer(self):
        result = self.run_python('-c', MODULE_IMPORT, self.plugin)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(inventory(self.plugin), self.before)

    def test_missing_lock_blocks_cli_module_import_and_both_mcps(self):
        (self.plugin/'plugin-lock.json').unlink()
        marker = self.home/'unverified-source-executed'
        source = self.plugin/'skills/openubmc-debug/scripts/_cli_common.py'
        with source.open('a') as stream:
            stream.write('\nfrom pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
        commands = [(self.plugin/'skills/openubmc-debug/scripts/target_runtime_cli.py', '--help'),
                    ('-c', MODULE_IMPORT, self.plugin)]
        commands += [('-I', self.plugin/'scripts/pluginctl.py', server) for server in ('runtime', 'kb')]
        for snapshot_receipt in (False, True):
            if snapshot_receipt:
                (self.plugin/'.openubmc-runtime-snapshot.json').write_text('{"schema":"openubmc.runtime-snapshot.v1"}')
            for command in commands:
                with self.subTest(command=command[-1], snapshot_receipt=snapshot_receipt):
                    marker.unlink(missing_ok=True)
                    result = self.run_python(*command)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('plugin-lock.json', result.stderr)
                    self.assertFalse(marker.exists())

    def test_runtime_snapshot_children_preserve_integrity_and_reject_drift(self):
        temporary = self.home/'runtime-temporary'
        temporary.mkdir()
        environment = dict(self.environment, TMPDIR=str(temporary))
        child = subprocess.Popen([sys.executable, '-I', '-B', str(self.plugin/'scripts/launch_runtime.py')],
                                 cwd=self.home, env=environment, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            request = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                       'params': {'protocolVersion': '2024-11-05', 'capabilities': {},
                                  'clientInfo': {'name': 'package-test', 'version': '1'}}}
            child.stdin.write(json.dumps(request) + '\n')
            child.stdin.flush()
            self.assertTrue(select.select([child.stdout], [], [], 30)[0], 'MCP initialize timed out')
            line = child.stdout.readline()
            if not line:
                _, stderr = child.communicate(timeout=5)
                self.fail('MCP exited before initialize: ' + stderr)
            self.assertIn('serverInfo', json.loads(line)['result'])
            entries = list(temporary.rglob('target_runtime_cli.py'))
            self.assertEqual(len(entries), 1)
            entry = entries[0]
            for arguments in ((entry, '--help'), ('-I', '-B', entry, '--help')):
                result = self.run_python(*arguments)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            marker = self.home/'snapshot-drift-executed'
            source = entry.with_name('_cli_common.py')
            source.chmod(0o600)
            with source.open('a') as stream:
                stream.write('\nfrom pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
            result = self.run_python(entry, '--help')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('snapshot inventory mismatch', result.stderr)
            self.assertFalse(marker.exists())
            self.assertFalse(list(temporary.rglob('*.pyc')))
            self.assertEqual(inventory(self.plugin), self.before)
        finally:
            try:
                child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)

    def test_isolated_python_child_preserves_package_integrity(self):
        parent = '''
import subprocess, sys
sys.dont_write_bytecode = True
raise SystemExit(subprocess.run([sys.executable, '-I', sys.argv[1], '--help']).returncode)
'''
        result = self.run_python('-c', parent, self.plugin/'skills/openubmc-debug/scripts/target_runtime_cli.py')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(inventory(self.plugin), self.before)

    def poison_cache(self, *, prefix=None):
        original = self.plugin/'skills/openubmc-debug/scripts/_cli_common.py'
        marker = self.home/'unverified-bytecode-executed'
        source = self.home/'poison.py'
        source.write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\nraise RuntimeError("unverified cache executed")\n')
        previous = sys.pycache_prefix
        try:
            sys.pycache_prefix = str(prefix) if prefix else None
            cache = Path(importlib.util.cache_from_source(str(original)))
        finally:
            sys.pycache_prefix = previous
        cache.parent.mkdir(parents=True, exist_ok=True)
        py_compile.compile(str(source), cfile=str(cache), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        return marker

    def test_existing_external_bytecode_is_not_executed(self):
        prefix = self.home/'previous-cache'
        marker = self.poison_cache(prefix=prefix)
        self.environment['PYTHONPYCACHEPREFIX'] = str(prefix)
        result = self.run_python(self.plugin/'skills/openubmc-debug/scripts/target_runtime_cli.py', '--help')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(inventory(self.plugin), self.before)

    def test_untracked_bytecode_is_ignored_without_execution(self):
        marker = self.poison_cache()
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from plugin_archive import verify_directory
        self.assertEqual(verify_directory(self.plugin)['name'], 'openubmc')
        verified = self.run_python('-I', self.plugin/'scripts/pluginctl.py', 'verify')
        self.assertEqual(verified.returncode, 0, verified.stderr)
        commands = [(self.plugin/'skills/openubmc-debug/scripts/target_runtime_cli.py', '--help')]
        commands += [('-I', self.plugin/'scripts/pluginctl.py', server) for server in ('runtime', 'kb')]
        for command in commands:
            with self.subTest(command=command[-1]):
                marker.unlink(missing_ok=True)
                result = self.run_python(*command)
                if command[-1] == '--help':
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn('Dependencies are not prepared', result.stderr)
                self.assertFalse(marker.exists())

    def test_source_drift_and_unknown_files_still_block_both_mcps(self):
        for relative in ('skills/openubmc-debug/scripts/_cli_common.py', 'unexpected.json'):
            with self.subTest(relative=relative):
                path = self.plugin/relative
                before = path.read_bytes() if path.exists() else None
                path.write_text('raise RuntimeError("modified source")\n')
                for server in ('runtime', 'kb'):
                    result = self.run_python('-I', self.plugin/'scripts/pluginctl.py', server)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('inventory mismatch', result.stderr)
                if before is None:
                    path.unlink()
                else:
                    path.write_bytes(before)


if __name__ == '__main__':
    unittest.main()
