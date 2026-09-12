"""Exercise packaged migration and native Codex enablement in an isolated home."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
if __package__:
    from .plugin_fixture import package_fixture
else:
    from plugin_fixture import package_fixture


def native_snapshot(home, environment):
    process = subprocess.Popen(['codex', 'app-server', '--stdio'], cwd=home, env=environment,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    timer = threading.Timer(15, process.kill)
    timer.start()
    try:
        def call(number, method, params):
            process.stdin.write(json.dumps({'id': number, 'method': method, 'params': params}) + '\n')
            process.stdin.flush()
            for line in process.stdout:
                response = json.loads(line)
                if response.get('id') == number:
                    if 'error' in response:
                        raise AssertionError(response['error'])
                    return response['result']
            raise AssertionError('Codex closed before returning ' + method)
        call(1, 'initialize', {'clientInfo': {'name': 'migration-test', 'version': '1.0'},
                               'capabilities': {'experimentalApi': True}})
        skills = call(2, 'skills/list', {'cwds': [str(home)], 'forceReload': True})
        config = call(3, 'config/read', {'includeLayers': False, 'cwd': str(home)})
        return skills['data'][0]['skills'], config['config']
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stdout.close()
        timer.cancel()


@unittest.skipUnless(shutil.which('codex'), 'Codex executable is required')
class DisableMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        cls.plugin = package_fixture(cls.base)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=self.base)
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        codex = self.home/'.codex'
        (codex/'skills').mkdir(parents=True)
        self.skill = self.home/'legacy/openubmc-build/SKILL.md'
        self.skill.parent.mkdir(parents=True)
        self.skill.write_text('---\nname: openubmc-build\ndescription: Legacy fixture\n---\nBuild fixture.\n')
        self.link = codex/'skills/openubmc-build'
        self.link.symlink_to(self.skill.parent)
        self.config = codex/'config.toml'
        launcher = str(self.home/'.local/share/openubmc/target-runtime/openubmc-target-runtime-mcp')
        self.original = (f'model = "test"\n[mcp_servers.openubmc-target-runtime]\ncommand = {json.dumps(launcher)}\nargs = []\n'
                         '[mcp_servers.unrelated]\ncommand = "keep"\nenabled = false\n'
                         '[plugins."openubmc@personal"]\nenabled = true\n'
                         '[plugins."openubmc@openubmc-public"]\nenabled = true\n'
                         '[plugins."other@personal"]\nenabled = true\n'
                         f'[[skills.config]]\npath = {json.dumps(str(self.skill.parent))}\nenabled = true\n')
        self.config.write_text(self.original)
        self.state = self.home/'.config/openubmc/environment-state.json'
        self.state.parent.mkdir(parents=True)
        self.state.write_text(json.dumps({'source_root': str(self.skill.parent.parent),
                              'links': {str(self.link): str(self.skill.parent)},
                              'runtime_mcp': {'codex': {'command': launcher, 'args': [], 'created_entry': True}},
                              'codex_skill_center': {'targets': [str(self.skill.parent)]}}))
        self.preserved = [self.state.with_name('credentials.env'), self.state.with_name('kb-mcp.json'),
                          self.home/'.cache/openubmc-mcp/token-cache.json', self.home/'.local/state/openubmc/history.json']
        for path in self.preserved:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'private-fixture-do-not-print')
        self.environment = {key: value for key, value in os.environ.items()
                            if not key.startswith(('CODEX_', 'OPENAI_', 'OPENUBMC_', 'XDG_', 'PYTHON'))}
        self.environment.update(HOME=str(self.home), CODEX_HOME=str(codex),
                                XDG_CONFIG_HOME=str(self.home/'.config'), XDG_DATA_HOME=str(self.home/'.local/share'))

    def cli(self, *arguments, success=True):
        result = subprocess.run([sys.executable, '-I', str(self.plugin/'scripts/pluginctl.py'), *arguments,
                                 '--home', str(self.home)], env=self.environment, capture_output=True, text=True, timeout=30)
        self.assertNotIn('private-fixture-do-not-print', result.stdout + result.stderr)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return json.loads(result.stdout if result.stdout else result.stderr)

    def test_preview_disable_repeat_and_restore_preserve_files_and_native_states(self):
        preview = self.cli('migrate', '--disable-only', '--preview')
        self.assertIn(str(self.skill), preview['changes']['skills'])
        self.assertEqual(self.config.read_text(), self.original)
        self.assertFalse((self.home/'.local/share/openubmc/migrations').exists())
        applied = self.cli('migrate', '--disable-only')
        self.assertTrue(applied['changed'])
        self.assertTrue(self.link.is_symlink())
        self.assertTrue(self.skill.is_file())
        skills, config = native_snapshot(self.home, self.environment)
        matching = [skill for skill in skills if skill['name'] == 'openubmc-build']
        self.assertTrue(matching)
        self.assertTrue(all(not skill['enabled'] for skill in matching))
        self.assertFalse(config['mcp_servers']['openubmc-target-runtime']['enabled'])
        self.assertFalse(config['plugins']['openubmc@personal']['enabled'])
        self.assertTrue(config['plugins']['openubmc@openubmc-public']['enabled'])
        self.assertTrue(config['plugins']['other@personal']['enabled'])
        after = self.config.read_bytes()
        self.assertFalse(self.cli('migrate', '--disable-only')['changed'])
        self.assertEqual(self.config.read_bytes(), after)
        self.cli('restore-legacy', '--transaction', applied['transaction'])
        self.assertEqual(self.config.read_text(), self.original)
        skills, config = native_snapshot(self.home, self.environment)
        self.assertTrue(next(skill for skill in skills if skill['name'] == 'openubmc-build')['enabled'])
        self.assertTrue(config['plugins']['openubmc@personal']['enabled'])
        for path in self.preserved:
            self.assertEqual(path.read_bytes(), b'private-fixture-do-not-print')

    def test_version_pinned_overrides_are_removed_with_backup_and_native_config_recovery(self):
        old = self.home/'.codex/plugins/cache/openubmc-public/openubmc/2.0.12/scripts/pluginctl.py'
        original = '[plugins."openubmc@openubmc-public"]\nenabled = true\n'
        for name, capability in [('openubmc-target-runtime', 'runtime'), ('openubmc-kb', 'kb')]:
            original += (f'[mcp_servers.{name}]\ncommand = "python3"\n'
                         f'args = {json.dumps(["-I", "-B", str(old), capability, "--prepare-on-start"])}\n')
        original += '[mcp_servers.unrelated]\ncommand = "keep"\nenabled = false\n'
        self.config.write_text(original)
        self.assertFalse(old.exists())
        preview = self.cli('repair-overrides', '--preview')
        self.assertEqual(preview['changes']['mcp_servers'], ['openubmc-kb', 'openubmc-target-runtime'])
        self.assertEqual(self.config.read_text(), original)
        applied = self.cli('repair-overrides')
        self.assertTrue(applied['changed'])
        _, config = native_snapshot(self.home, self.environment)
        self.assertNotIn('openubmc-target-runtime', config['mcp_servers'])
        self.assertNotIn('openubmc-kb', config['mcp_servers'])
        self.assertEqual(config['mcp_servers']['unrelated']['command'], 'keep')
        self.assertTrue(config['plugins']['openubmc@openubmc-public']['enabled'])
        backup = self.home/'.local/share/openubmc/migrations'/applied['transaction']/'before.toml'
        self.assertEqual(backup.read_text(), original)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertFalse(self.cli('repair-overrides')['changed'])
        self.cli('restore-legacy', '--transaction', applied['transaction'])
        self.assertEqual(self.config.read_text(), original)

    def test_override_repair_preserves_custom_settings_and_refuses_disabled_replacement(self):
        old = self.home/'.codex/plugins/cache/openubmc-public/openubmc/2.0.12/scripts/pluginctl.py'
        base = ('[plugins."openubmc@openubmc-public"]\nenabled = true\n'
                '[mcp_servers.openubmc-target-runtime]\ncommand = "python3"\n'
                f'args = {json.dumps(["-I", str(old), "runtime"])}\n')
        cases = [base + '[mcp_servers.openubmc-target-runtime.env]\nSECRET = "private-fixture-do-not-print"\n',
                 base.replace('enabled = true', 'enabled = false'),
                 base.replace('/openubmc-public/', '/another-market/'),
                 base.replace('"runtime"', '"runtime", "--custom"')]
        for original in cases:
            with self.subTest(case=cases.index(original)):
                self.config.write_text(original)
                self.assertTrue(self.cli('repair-overrides', '--preview', success=False)['conflicts'])
                self.cli('repair-overrides', success=False)
                self.assertEqual(self.config.read_text(), original)

    def test_override_repair_uses_selected_codex_home_and_protects_later_edits(self):
        codex = self.home/'separate-codex'
        codex.mkdir()
        self.environment['CODEX_HOME'] = str(codex)
        config = codex/'config.toml'
        old = codex/'plugins/cache/openubmc-public/openubmc/2.0.12/scripts/pluginctl.py'
        config.write_text('[plugins."openubmc@openubmc-public"]\nenabled = true\n'
                          '[mcp_servers.openubmc-kb]\ncommand = "python3"\n'
                          f'args = {json.dumps(["-I", str(old), "kb"])}\n')
        applied = self.cli('repair-overrides')
        self.assertTrue(applied['changed'])
        self.assertEqual(self.config.read_text(), self.original)
        changed = config.read_text() + '# later edit\n'
        config.write_text(changed)
        self.cli('restore-legacy', '--transaction', applied['transaction'], success=False)
        self.assertEqual(config.read_text(), changed)

    def test_override_preview_preserves_empty_tables_without_changes(self):
        for original in ('[mcp_servers]\n', '[skills]\n', '[skills]\nconfig = []\n'):
            with self.subTest(original=original):
                self.config.write_text(original)
                self.assertFalse(self.cli('repair-overrides', '--preview')['would_change'])
                self.assertFalse(self.cli('repair-overrides')['changed'])
                self.assertEqual(self.config.read_text(), original)

    def test_override_removal_preserves_unrelated_empty_tables(self):
        old = self.home/'.codex/plugins/cache/openubmc-public/openubmc/2.0.12/scripts/pluginctl.py'
        original = ('[skills]\nconfig = []\n[plugins."openubmc@openubmc-public"]\nenabled = true\n'
                    '[mcp_servers.openubmc-target-runtime]\ncommand = "python3"\n'
                    f'args = {json.dumps(["-I", str(old), "runtime"])}\n')
        self.config.write_text(original)
        self.cli('repair-overrides')
        self.assertEqual(self.config.read_text(), original.split('[mcp_servers.')[0])

    def test_relative_plugin_launcher_with_version_pinned_cwd_is_repaired(self):
        old = self.home/'.codex/plugins/cache/openubmc-public/openubmc/2.0.12'
        self.config.write_text('[plugins."openubmc@openubmc-public"]\nenabled = true\n'
                               '[mcp_servers.openubmc-target-runtime]\ncommand = "python3"\n'
                               f'cwd = {json.dumps(str(old))}\n'
                               'args = ["-I", "-B", "./scripts/pluginctl.py", "runtime"]\n')
        self.assertTrue(self.cli('repair-overrides')['changed'])
        self.assertNotIn('mcp_servers', self.config.read_text())

    def test_override_apply_rejects_configuration_added_after_preview(self):
        old = self.home/'.codex/plugins/cache/openubmc-public/openubmc/2.0.12/scripts/pluginctl.py'
        before = '[plugins."openubmc@openubmc-public"]\nenabled = true\n'
        self.config.write_text(before)
        self.cli('repair-overrides', '--preview')
        changed = (before + '[mcp_servers.openubmc-kb]\ncommand = "python3"\n'
                   f'args = {json.dumps(["-I", str(old), "kb"])}\n')
        self.config.write_text(changed)
        self.cli('repair-overrides', '--expected-config-digest', hashlib.sha256(before.encode()).hexdigest(), success=False)
        self.assertEqual(self.config.read_text(), changed)

    def test_restore_refuses_a_changed_installation_owner(self):
        applied = self.cli('migrate', '--disable-only')
        disabled = self.config.read_bytes()
        self.state.write_text(json.dumps({'source_root': str(self.home/'different-installation')}))
        self.cli('restore-legacy', '--transaction', applied['transaction'], success=False)
        self.assertEqual(self.config.read_bytes(), disabled)
        self.assertTrue(self.link.is_symlink())

    def test_interrupted_migration_cannot_change_the_preserved_target(self):
        wrapper = """
import os, runpy, sys
replace = os.replace
config = sys.argv[1]
def interrupt(source, destination):
    if os.fspath(destination) == config:
        os._exit(86)
    return replace(source, destination)
os.replace = interrupt
sys.argv = sys.argv[2:]
runpy.run_path(sys.argv[0], run_name='__main__')
"""
        result = subprocess.run([sys.executable, '-I', '-c', wrapper, str(self.config),
                                 str(self.plugin/'scripts/pluginctl.py'), 'migrate', '--disable-only', '--home', str(self.home)],
                                env=self.environment, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 86)
        preview = self.cli('migrate', '--preview', '--target-plugin', 'openubmc@personal', success=False)
        self.assertTrue(preview['conflicts'])
        self.cli('migrate', '--target-plugin', 'openubmc@personal', success=False)
        self.assertEqual(self.config.read_text(), self.original)
        self.link.unlink()
        self.link.symlink_to(self.home/'changed-skill')
        self.assertTrue(self.cli('migrate', '--preview', success=False)['conflicts'])
        self.cli('migrate', '--disable-only', success=False)
        self.link.unlink()
        self.link.symlink_to(self.skill.parent)
        self.assertTrue(self.cli('migrate', '--disable-only')['changed'])
        skills, config = native_snapshot(self.home, self.environment)
        self.assertTrue(config['plugins']['openubmc@openubmc-public']['enabled'])

    def test_ownership_conflict_blocks_preview_and_apply(self):
        original = self.original.replace('openubmc-target-runtime-mcp"', 'other-mcp"')
        self.config.write_text(original)
        preview = self.cli('migrate', '--preview', success=False)
        self.assertTrue(preview['conflicts'])
        self.cli('migrate', '--disable-only', success=False)
        self.assertEqual(self.config.read_text(), original)
        self.assertTrue(self.link.is_symlink())

    def test_legacy_pending_remove_preview_resume_and_restore(self):
        # Persisted 2.0.11 journals had no mode, target_plugin, or changes fields.
        after = ('model = "test"\n[mcp_servers.unrelated]\ncommand = "keep"\nenabled = false\n'
                 '[plugins."openubmc@personal"]\nenabled = true\n'
                 '[plugins."openubmc@openubmc-public"]\nenabled = true\n'
                 '[plugins."other@personal"]\nenabled = true\n')
        transaction = 'a' * 32
        journal = self.home/'.local/share/openubmc/migrations'/transaction
        journal.mkdir(parents=True)
        (journal/'before.toml').write_text(self.original)
        (journal/'after.toml').write_text(after)
        record = {'schema': 'openubmc.plugin-migration.v1', 'transaction': transaction,
                  'home': str(self.home), 'codex_home': str(self.home/'.codex'),
                  'before_digest': hashlib.sha256(self.original.encode()).hexdigest(),
                  'after_digest': hashlib.sha256(after.encode()).hexdigest(),
                  'links': [{'path': str(self.link), 'target': str(self.skill.parent)}],
                  'config_existed': True, 'status': 'prepared'}
        (journal/'transaction.json').write_text(json.dumps(record))
        saved = {path.name: path.read_bytes() for path in journal.iterdir()}
        for current in (self.original, after):
            with self.subTest(config_already_written=current == after):
                self.config.write_text(current)
                preview = self.cli('migrate', '--remove', '--preview')
                self.assertEqual(preview['changes']['mcp_servers'], ['openubmc-target-runtime'])
                self.assertEqual(preview['changes']['skills'], [str(self.skill.parent)])
                self.assertEqual(preview['changes']['links'], [str(self.link)])
                self.assertTrue(preview['would_change'])
                self.assertEqual(self.config.read_text(), current)
                self.assertTrue(self.link.is_symlink())
                self.assertEqual({path.name: path.read_bytes() for path in journal.iterdir()}, saved)
        applied = self.cli('migrate', '--remove')
        self.assertEqual(applied['transaction'], transaction)
        self.assertEqual(self.config.read_text(), after)
        self.assertFalse(self.link.is_symlink())
        self.cli('restore-legacy', '--transaction', transaction)
        self.assertEqual(self.config.read_text(), self.original)
        self.assertTrue(self.link.is_symlink())
        self.assertTrue(self.skill.is_file())
        for path in self.preserved:
            self.assertEqual(path.read_bytes(), b'private-fixture-do-not-print')

    def test_restore_does_not_overwrite_later_configuration(self):
        applied = self.cli('migrate', '--disable-only')
        changed = self.config.read_text() + '\n# later user edit\n'
        self.config.write_text(changed)
        self.cli('restore-legacy', '--transaction', applied['transaction'], success=False)
        self.assertEqual(self.config.read_text(), changed)

    def test_already_disabled_skills_and_selected_target_plugin_are_preserved(self):
        self.config.write_text(self.original + f'\n[[skills.config]]\npath = {json.dumps(str(self.skill))}\nenabled = false\n')
        self.cli('migrate', '--target-plugin', 'openubmc@personal')
        skills, config = native_snapshot(self.home, self.environment)
        self.assertFalse(next(skill for skill in skills if skill['name'] == 'openubmc-build')['enabled'])
        self.assertTrue(config['plugins']['openubmc@personal']['enabled'])
        self.assertEqual(sum(row['path'] == str(self.skill) for row in config['skills']['config']), 1)

    def test_restore_removes_only_configuration_created_by_migration(self):
        self.config.unlink()
        applied = self.cli('migrate', '--disable-only')
        self.assertTrue(self.config.is_file())
        self.cli('restore-legacy', '--transaction', applied['transaction'])
        self.assertFalse(self.config.exists())
        self.assertTrue(self.link.is_symlink())


if __name__ == '__main__':
    unittest.main()
