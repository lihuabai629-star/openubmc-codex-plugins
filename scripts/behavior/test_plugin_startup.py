"""Exercise startup through verified bytes and capability-specific preflight."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

PLUGIN = Path(os.environ.get('OPENUBMC_TEST_PLUGIN_ROOT',
                            Path(__file__).resolve().parents[2] / 'plugins/openubmc'))


def load(name):
    spec = importlib.util.spec_from_file_location(name, PLUGIN / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PluginStartupTests(unittest.TestCase):
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
            with mock.patch.object(ctl, 'ROOT', mounted):
                result = ctl.probe_server('kb', content, lock,
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


if __name__ == '__main__':
    unittest.main()
