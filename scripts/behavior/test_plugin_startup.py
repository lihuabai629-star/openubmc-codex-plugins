"""Exercise startup through verified bytes and capability-specific preflight."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from contextlib import ExitStack
import unittest
from unittest import mock

if __package__:
    from .plugin_fixture import package_fixture
else:
    from plugin_fixture import package_fixture

PLUGIN = None


def load(name):
    spec = importlib.util.spec_from_file_location(name, PLUGIN / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PluginStartupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global PLUGIN
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        PLUGIN = package_fixture(Path(cls.directory.name))

    def test_npm_zero_exit_without_dependencies_does_not_activate_cache(self):
        ctl = load('pluginctl')
        _, content = ctl.verify(PLUGIN)
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / 'dependencies'
            with mock.patch.object(ctl, 'dependency_root', return_value=cache), \
                    mock.patch.object(ctl, '_run_dependency_command'):
                with self.assertRaisesRegex(ValueError, 'incomplete'):
                    ctl.prepare_dependencies(content, False, capability='kb')
            self.assertFalse(cache.exists())

    def test_inventory_rejects_a_linked_directory_even_with_ignored_bytecode(self):
        ctl = load('pluginctl')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / '__pycache__').mkdir()
            (root / '__pycache__/derived.pyc').write_bytes(b'cache')
            (root / 'linked').symlink_to(root / '__pycache__', target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symbolic link'):
                list(ctl.plugin_files(root))

    def test_probe_uses_verified_bytes_without_reopening_mounted_source(self):
        ctl = load('pluginctl')
        lock, content = ctl.verify(PLUGIN)
        with tempfile.TemporaryDirectory() as temporary:
            mounted = Path(temporary) / 'mounted'
            (mounted / 'scripts').mkdir(parents=True)
            # Reopening the mounted launcher represents the redundant slow path.
            (mounted / 'scripts/pluginctl.py').write_text('raise SystemExit(99)\n')
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(ctl, 'ROOT', mounted))
                capability = 'kb'
                if not os.environ.get('OPENUBMC_TEST_PLUGIN_ROOT'):
                    # Exercise the same plan and real protocol without registry access.
                    capability = 'runtime'
                    snapshot = Path(temporary) / 'snapshot'
                    (snapshot / 'scripts').mkdir(parents=True)
                    (snapshot / 'receipt.json').write_text('{}')
                    (snapshot / 'scripts/launch_runtime.py').write_text(
                        'import json,sys\n'
                        'for line in sys.stdin:\n'
                        ' r=json.loads(line)\n'
                        ' if "id" in r: print(json.dumps({"jsonrpc":"2.0","id":r["id"],'
                        '"result":{"serverInfo":{"name":"fixture"}} if r["id"]==1 else '
                        '{"tools":[{"name":"observe"},{"name":"execute"}]}}),flush=True)\n')
                    stack.enter_context(mock.patch.object(ctl, 'dependency_root', return_value=snapshot))
                    stack.enter_context(mock.patch.object(ctl, 'execution_snapshot', return_value=snapshot))
                result = ctl.probe_server(capability, content, lock,
                                         json.loads(content['openubmc-kb-mcp/package.json'])['version'])
            self.assertTrue(result['ok'], result)

    def test_preflight_does_not_require_the_other_capability(self):
        script = '''
const assert = require('node:assert/strict');
const {createSetupOperations} = require(process.argv[1]);
for (const capability of ['runtime', 'kb']) {
  const calls = [];
  const adapter = {decodeOutput: String, run(command, args) {
    calls.push(args);
    const all = args.includes('all');
    return {status: all ? 2 : 0, stdout: JSON.stringify({
      capabilities: {[capability]: {startup_ready: true}},
      mcp_health: {[capability]: {ok: true}}, codex_configuration: {ready: true}
    })};
  }};
  const result = createSetupOperations(adapter, capability).preflightBackend({
    command: 'python3', prefix: [], configurationArgs: []});
  assert.equal(result.ok, true);
  assert.equal(calls.length, 1, 'one verification for cleanup and doctor');
  assert(calls[0].includes('--cleanup-retired'));
}
'''
        result = subprocess.run(['node', '-e', script,
                                 str(PLUGIN / 'scripts/openubmc-bootstrap-operations.js')],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_name_disable_survives_cross_host_path_aliases(self):
        install = load('plugin_install')
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            root = home / '.codex'
            skill = root / 'skills/renamed-folder/SKILL.md'
            skill.parent.mkdir(parents=True)
            skill.write_text('---\nname: openubmc-build\n---\nBuild\n')
            (root / 'config.toml').write_text(
                '[[skills.config]]\nname = "openubmc-build"\nenabled = false\n')
            self.assertEqual(install.actionable_loose_skill_overlaps(
                home, ['openubmc-build'], root, skill_names=['openubmc-build']), [])

    @unittest.skipIf(os.name == 'nt', 'uses a POSIX executable fixture')
    def test_live_session_is_qualified_before_any_client_tool_call(self):
        for healthy in (True, False):
            with self.subTest(healthy=healthy), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                log, starts = root/'requests', root/'starts'
                report = {'knowledge_mcp_version': '1', 'protocol_check_pending': True,
                          'capabilities': {'runtime': {'prerequisites_ready': True}},
                          'mcp_health': {'runtime': {'ok': False, 'checked': False, 'tools': []}},
                          'codex_configuration': {'ready': True}}
                launcher = root/'python-fixture'
                launcher.write_text('''#!/usr/bin/env python3
import json, pathlib, sys
if '-c' in sys.argv:
    raise SystemExit(0)
if 'doctor' in sys.argv:
    assert '--prerequisites-only' in sys.argv
    print(REPORT, flush=True)
    raise SystemExit(0)
with pathlib.Path(STARTS).open('a') as stream:
    stream.write('started\\n')
for line in sys.stdin:
    with pathlib.Path(LOG).open('a') as stream:
        stream.write(line)
    request = json.loads(line)
    if 'id' not in request:
        continue
    method = request['method']
    if method == 'initialize':
        result = {'protocolVersion': '2024-11-05', 'serverInfo': {'name': 'fixture', 'version': '1'}, 'capabilities': {'tools': {}}}
    elif method == 'tools/list':
        result = {'tools': [{'name': name} for name in NAMES]}
    else:
        result = {'content': [], 'structuredContent': {'served': True}}
    print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}), flush=True)
'''.replace('REPORT', repr(json.dumps(report))).replace('STARTS', repr(str(starts)))
                   .replace('LOG', repr(str(log))).replace('NAMES', repr(['observe', 'execute'] if healthy else ['observe'])))
                launcher.chmod(0o755)
                requests = [
                    {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2024-11-05'}},
                    {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                    {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}},
                    {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': 'execute', 'arguments': {}}},
                    {'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call', 'params': {'name': 'openubmc_setup_status', 'arguments': {}}},
                ]
                result = subprocess.run(['node', str(PLUGIN/'scripts/openubmc-mcp-bootstrap.js'), 'runtime'],
                                        input=''.join(json.dumps(row)+'\n' for row in requests),
                                        env=dict(os.environ, OPENUBMC_PLUGIN_HOST_PLATFORM='linux',
                                                 OPENUBMC_PLUGIN_PYTHON=str(launcher)),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(starts.read_text().splitlines(), ['started'])
                observed = list(map(json.loads, log.read_text().splitlines()))
                self.assertEqual(sum(row['method'] == 'initialize' for row in observed), 1)
                self.assertEqual(sum(row['method'] == 'notifications/initialized' for row in observed), 1)
                replies = {row['id']: row for row in map(json.loads, result.stdout.splitlines())}
                if healthy:
                    self.assertTrue(replies[3]['result']['structuredContent']['served'])
                    self.assertEqual(observed[-1]['method'], 'tools/call')
                    self.assertIn('live-mcp-session', result.stderr)
                else:
                    names = {tool['name'] for tool in replies[2]['result']['tools']}
                    self.assertIn('openubmc_setup_status', names)
                    self.assertFalse(any(row['method'] == 'tools/call' for row in observed))
                    status = replies[4]['result']['structuredContent']
                    self.assertEqual(status['reason'], 'mcp_protocol_unhealthy')
                    self.assertEqual(status['startup_reason'], 'mcp_protocol_unhealthy')
                    self.assertTrue(status['prerequisites_ready_for_new_task'])
                    self.assertTrue(status['protocol_check_pending'])
                    self.assertFalse(status['backend_ready_for_new_task'])
                    self.assertEqual(status['protocol_health']['runtime']['error'], 'mcp_protocol_unhealthy')
                    self.assertFalse(status['protocol_health']['runtime']['ok'])
                    self.assertIn('openubmc-startup', result.stderr)

    def test_live_protocol_gate_rejects_version_mismatch_and_timeout(self):
        script = '''
const assert = require('node:assert/strict');
const {EventEmitter} = require('node:events');
const {PassThrough} = require('node:stream');
const {createProtocolGate} = require(process.argv[1]);
(async () => {
  for (const mismatch of [true, false]) {
    const child = new EventEmitter();
    child.stdin = new PassThrough(); child.stdout = new PassThrough();
    let forwarded = 0;
    const failure = new Promise(resolve => {
      const gate = createProtocolGate({child, capability: 'kb', expectedVersion: '1', timeoutMs: 20,
        forward() { forwarded++; }, output() {}, onReady() { assert.fail('unqualified session'); },
        onFailure: reason => resolve(reason)});
      gate.accept(JSON.stringify({jsonrpc:'2.0',id:1,method:'initialize',params:{}}));
      if (mismatch) child.stdout.write(JSON.stringify({jsonrpc:'2.0',id:1,result:{serverInfo:{name:'kb',version:'other'}}})+'\\n');
    });
    assert.equal(await failure, mismatch ? 'mcp_protocol_unhealthy' : 'mcp_protocol_timeout');
    assert.equal(forwarded, 0);
    child.stdin.destroy(); child.stdout.destroy();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
        result = subprocess.run(['node', '-e', script, str(PLUGIN/'scripts/openubmc-bootstrap-protocol.js')],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
