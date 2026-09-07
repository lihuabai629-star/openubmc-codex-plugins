"""Journaled migration of the Codex loose installation."""
from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import tomllib
import uuid


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.'+path.name+'-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save(path: Path, value: dict) -> None:
    write_atomic(path, (json.dumps(value, sort_keys=True, indent=2)+'\n').encode())


def journal_root(home: Path) -> Path:
    return home/'.local/share/openubmc/migrations'


def migration_config(text: str, servers: set[str], targets: set[str]) -> str:
    before = tomllib.loads(text)
    expected = copy.deepcopy(before)
    for name in servers:
        expected.get('mcp_servers', {}).pop(name, None)
    if not expected.get('mcp_servers'):
        expected.pop('mcp_servers', None)
    if 'config' in expected.get('skills', {}):
        expected['skills']['config'] = [row for row in expected['skills']['config'] if row.get('path') not in targets]
        if not expected['skills']['config']:
            expected['skills'].pop('config')
        if not expected['skills']:
            expected.pop('skills')
    chunks = re.split(r'(?m)(?=^[ \t]*\[)', text)
    result = []
    for chunk in chunks:
        header = chunk.splitlines()[0].strip() if chunk.splitlines() else ''
        skip = False
        if header.startswith('['):
            try:
                table = tomllib.loads(header+'\n')
            except tomllib.TOMLDecodeError:
                table = {}
            if set(table.get('mcp_servers', {})) & servers:
                skip = True
            if header == '[[skills.config]]':
                try:
                    rows = tomllib.loads(chunk)['skills']['config']
                    skip = len(rows) == 1 and rows[0].get('path') in targets
                except (tomllib.TOMLDecodeError, KeyError):
                    pass
        if not skip:
            result.append(chunk)
    after = ''.join(result)
    if tomllib.loads(after) != expected:
        raise ValueError('Codex configuration layout cannot be migrated without changing unrelated settings')
    return after


def disable_config(text: str, servers: set[str], skills: set[str], plugins: set[str]) -> str:
    before = tomllib.loads(text)
    expected = copy.deepcopy(before)
    for name in servers:
        expected['mcp_servers'][name]['enabled'] = False
    for name in plugins:
        expected['plugins'][name]['enabled'] = False
    rows = expected.setdefault('skills', {}).setdefault('config', []) if skills else []
    missing = set(skills)
    for row in rows:
        if row.get('path') in skills:
            row['enabled'] = False
            missing.discard(row['path'])
    for path in sorted(missing):
        rows.append({'path': path, 'enabled': False})

    def disable(chunk: str) -> str:
        if re.search(r'(?m)^\s*enabled\s*=', chunk):
            return re.sub(r'(?m)^([ \t]*enabled\s*=\s*)(true|false)([ \t]*(?:#.*)?)$', r'\g<1>false\3', chunk)
        return chunk.rstrip('\n') + '\nenabled = false\n'

    chunks = re.split(r'(?m)(?=^[ \t]*\[)', text)
    result = []
    for chunk in chunks:
        header = chunk.splitlines()[0].strip() if chunk.splitlines() else ''
        try:
            table = tomllib.loads(header + '\n') if header.startswith('[') else {}
        except tomllib.TOMLDecodeError:
            table = {}
        selected = any(table == {'mcp_servers': {name: {}}} for name in servers)
        selected = selected or any(table == {'plugins': {name: {}}} for name in plugins)
        if header == '[[skills.config]]':
            selected = tomllib.loads(chunk)['skills']['config'][0].get('path') in skills
        result.append(disable(chunk) if selected else chunk)
    after = ''.join(result)
    for path in sorted(missing):
        after += '\n[[skills.config]]\npath = ' + json.dumps(path) + '\nenabled = false\n'
    if tomllib.loads(after) != expected:
        raise ValueError('Codex configuration layout cannot be disabled without changing unrelated settings')
    return after


def plan(home: Path, skill_paths: list[str], codex_home: Path | None = None, *,
         mode: str = 'remove', target_plugin: str = 'openubmc@openubmc-public') -> tuple[dict, bytes, bytes]:
    if mode not in {'remove', 'disable-only'}:
        raise ValueError('invalid migration mode')
    codex_root = (codex_home or home/'.codex').resolve()
    config = codex_root/'config.toml'
    state_path = home/'.config/openubmc/environment-state.json'
    if config.is_symlink() or state_path.is_symlink():
        raise ValueError('managed configuration files must not be symbolic links')
    state_bytes = state_path.read_bytes() if state_path.is_file() else b''
    state = json.loads(state_bytes) if state_bytes else {}
    before = config.read_bytes() if config.is_file() else b''
    document = tomllib.loads(before.decode())
    owned_servers = set()
    for name, field in (('openubmc-target-runtime', 'runtime_mcp'), ('openubmc-kb', 'mcp')):
        current = document.get('mcp_servers', {}).get(name)
        if current is None:
            continue
        if mode == 'disable-only' and current.get('enabled') is False:
            continue
        owner = state.get(field, {}).get('codex', {})
        if not owner.get('created_entry') or current.get('command') != owner.get('command') or current.get('args', []) != owner.get('args', []):
            raise ValueError('MCP configuration is not owned by the legacy installer: '+name)
        owned_servers.add(name)
    source = state.get('source_root')
    targets = set(state.get('codex_skill_center', {}).get('targets', []))
    if source:
        targets.update(str(Path(source)/name) for name in skill_paths)
    links = []
    roots = [codex_root/'skills', home/'.agents/skills', home/'.local/share/openubmc/codex-skill-links']
    for root in roots:
        if root.is_symlink():
            raise ValueError('Skill installation root is a symbolic link: '+str(root))
        if not root.is_dir():
            continue
        for path in root.iterdir():
            if path.is_symlink() and str(path.resolve()) in targets:
                links.append({'path': str(path), 'target': os.readlink(path)})
            elif mode == 'disable-only' and (str(path) in state.get('links', {}) or path.name in skill_paths):
                if str(path.resolve()) not in targets:
                    raise ValueError('Skill installation ownership conflicts at: ' + str(path))
    changes = {'skills': [], 'mcp_servers': sorted(owned_servers), 'plugins': []}
    if mode == 'disable-only':
        skill_files = {str((Path(target)/'SKILL.md').resolve()) for target in targets
                       if (Path(target)/'SKILL.md').is_file()}
        # Codex matches the canonical SKILL.md file, not the containing directory.
        current_rows = document.get('skills', {}).get('config', [])
        skill_files = {path for path in skill_files if not any(row.get('path') == path for row in current_rows)
                       or any(row.get('path') == path and row.get('enabled') is not False for row in current_rows)}
        personal = document.get('plugins', {}).get('openubmc@personal')
        plugins = {'openubmc@personal'} if personal is not None and personal.get('enabled') is not False and target_plugin != 'openubmc@personal' else set()
        changes.update(skills=sorted(skill_files), plugins=sorted(plugins))
        after = disable_config(before.decode(), owned_servers, skill_files, plugins).encode()
    else:
        after = migration_config(before.decode(), owned_servers, targets).encode()
    record = {'schema': 'openubmc.plugin-migration.v1', 'home': str(home), 'codex_home': str(codex_root),
              'before_digest': digest(before), 'after_digest': digest(after), 'links': sorted(links, key=lambda item:item['path']),
              'config_existed': config.is_file(), 'status': 'prepared', 'mode': mode, 'changes': changes,
              'ownership_state_digest': digest(state_bytes)}
    return record, before, after


def validate_ownership_state(home: Path, record: dict) -> None:
    if record.get('mode') != 'disable-only':
        return
    path = home/'.config/openubmc/environment-state.json'
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('legacy installation ownership state was replaced')
    current = path.read_bytes() if path.is_file() else b''
    if digest(current) != record.get('ownership_state_digest'):
        raise ValueError('legacy installation ownership changed after migration was planned')


def preview(home: Path, skill_paths: list[str], codex_home: Path | None = None, *,
            mode: str = 'disable-only', target_plugin: str = 'openubmc@openubmc-public') -> dict:
    try:
        record, before, after = plan(home.resolve(), skill_paths, codex_home, mode=mode, target_plugin=target_plugin)
    except (ValueError, OSError) as error:
        return {'ok': False, 'mode': mode, 'conflicts': [str(error)], 'changed': False}
    return {'ok': True, 'mode': mode, 'preview': True, 'conflicts': [], 'changes': record['changes'],
            'would_change': before != after or (mode == 'remove' and bool(record['links']))}


def migrate(home: Path, skill_paths: list[str], codex_home: Path | None = None, *,
            mode: str = 'remove', target_plugin: str = 'openubmc@openubmc-public') -> dict:
    home = home.resolve()
    journals = journal_root(home)
    journals.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (journals/'migration.lock').open('a') as mutex:
        fcntl.flock(mutex, fcntl.LOCK_EX)
        pending = []
        for path in journals.glob('*/transaction.json'):
            record = json.loads(path.read_bytes())
            if record.get('status') == 'prepared':
                # A pending journal is bound to the Codex home selected when
                # it was created.  Never replay another installation's
                # configuration or links into this invocation's home.
                if record.get('schema') != 'openubmc.plugin-migration.v1':
                    raise ValueError('invalid migration journal schema')
                if record.get('home') != str(home) or record.get('codex_home') != str((codex_home or home/'.codex').resolve()):
                    raise ValueError('incomplete migration journal belongs to another home')
                root = path.parent
                before_path, after_path = root/'before.toml', root/'after.toml'
                if not before_path.is_file() or not after_path.is_file() or digest(before_path.read_bytes()) != record.get('before_digest') or digest(after_path.read_bytes()) != record.get('after_digest'):
                    raise ValueError('incomplete migration journal snapshot is invalid')
                pending.append((path.parent, record))
        if len(pending) > 1:
            raise ValueError('multiple incomplete migration journals require reconciliation')
        if pending:
            root, record = pending[0]
            if record.get('mode', 'remove') != mode:
                raise ValueError('incomplete migration uses another mode; reconcile that mode first')
            before, after = (root/'before.toml').read_bytes(), (root/'after.toml').read_bytes()
        else:
            record, before, after = plan(home, skill_paths, codex_home, mode=mode, target_plugin=target_plugin)
            if before == after and (mode == 'disable-only' or not record['links']):
                return {'ok': True, 'changed': False, 'mode': mode}
            transaction = uuid.uuid4().hex
            root = journals/transaction
            root.mkdir(mode=0o700)
            record['transaction'] = transaction
            write_atomic(root/'before.toml', before)
            write_atomic(root/'after.toml', after)
            save(root/'transaction.json', record)
        validate_ownership_state(home, record)
        config = (codex_home or home/'.codex').resolve()/'config.toml'
        current = config.read_bytes() if config.is_file() else b''
        if digest(current) not in {record['before_digest'], record['after_digest']}:
            raise ValueError('Codex configuration changed during migration')
        for item in record['links']:
            path = Path(item['path'])
            if (path.is_symlink() and os.readlink(path) != item['target']) or (path.exists() and not path.is_symlink()):
                raise ValueError('Skill path changed during migration: '+str(path))
            if mode == 'disable-only' and not path.is_symlink():
                raise ValueError('Skill link disappeared during migration: '+str(path))
        if current != after:
            write_atomic(config, after)
        for item in record['links'] if mode == 'remove' else []:
            path = Path(item['path'])
            if path.is_symlink():
                path.unlink()
        record['status'] = 'applied'
        save(root/'transaction.json', record)
        return {'ok': True, 'changed': True, 'mode': mode, 'transaction': record['transaction'],
                'changes': record.get('changes', {}), 'removed_links': len(record['links']) if mode == 'remove' else 0,
                'activation': 'configuration_saved; start a new Codex task'}


def restore(home: Path, transaction: str, codex_home: Path | None = None) -> dict:
    if not re.fullmatch(r'[0-9a-f]{32}', transaction):
        raise ValueError('transaction must be a lowercase 32-character id')
    home = home.resolve()
    journals = journal_root(home)
    root = journals/transaction
    if root.is_symlink() or root.resolve().parent != journals.resolve():
        raise ValueError('transaction escapes the migration journal')
    with (journals/'migration.lock').open('a') as mutex:
        fcntl.flock(mutex, fcntl.LOCK_EX)
        record = json.loads((root/'transaction.json').read_bytes())
        if record.get('transaction') != transaction or record.get('home') != str(home) or record.get('codex_home') != str((codex_home or home/'.codex').resolve()) or record.get('schema') != 'openubmc.plugin-migration.v1':
            raise ValueError('migration journal identity mismatch')
        validate_ownership_state(home, record)
        config = (codex_home or home/'.codex').resolve()/'config.toml'
        if config.is_symlink():
            raise ValueError('Codex configuration was replaced by a symlink')
        before = (root/'before.toml').read_bytes()
        if digest(before) != record['before_digest']:
            raise ValueError('migration backup digest mismatch')
        current = config.read_bytes() if config.is_file() else b''
        if digest(current) not in {record['before_digest'], record['after_digest']}:
            raise ValueError('restore would overwrite subsequent Codex configuration changes')
        codex_root = (codex_home or home/'.codex').resolve()
        allowed_roots = {codex_root/'skills', home/'.agents/skills', home/'.local/share/openubmc/codex-skill-links'}
        for item in record['links']:
            path = Path(item['path'])
            if path.parent not in allowed_roots or path.parent.is_symlink():
                raise ValueError('migration link is outside Codex Skill roots')
            if path.is_symlink():
                if os.readlink(path) != item['target']:
                    raise ValueError('restore would overwrite a changed Skill link')
            elif path.exists():
                raise ValueError('restore would overwrite a changed Skill file')
            elif record.get('mode') == 'disable-only':
                raise ValueError('preserved Skill link disappeared after migration')
        if record.get('config_existed', True):
            write_atomic(config, before)
        else:
            config.unlink(missing_ok=True)
        for item in record['links'] if record.get('mode', 'remove') == 'remove' else []:
            path = Path(item['path'])
            if not path.is_symlink():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to(item['target'])
        record['status'] = 'restored'
        save(root/'transaction.json', record)
        return {'ok': True, 'transaction': transaction,
                'restored_links': len(record['links']) if record.get('mode', 'remove') == 'remove' else 0,
                'activation': 'configuration_restored; start a new Codex task'}
