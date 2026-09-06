#!/usr/bin/env python3
"""Install an immutable OpenUBMC Codex plugin with recoverable activation."""
from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib
import types
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from plugin_archive import canonical, materialize, read_archive, verify_directory


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.'+path.name+'-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def rename(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    source.rename(destination)
    sync_directory(source.parent)
    sync_directory(destination.parent)


def command(argv: list[str], env: dict[str, str]) -> str:
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=240)
    if result.returncode:
        raise ValueError('command failed: '+str(argv[:3])+': '+result.stderr[-2000:])
    return result.stdout


def file_bytes(path: Path) -> bytes:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('configuration path must be a regular file: '+str(path))
    return path.read_bytes() if path.exists() else b''


def identity(path: Path) -> str | None:
    return verify_directory(path)['content_digest'] if path.exists() or path.is_symlink() else None


def stage_directory(path: Path, files: dict[str, bytes]) -> None:
    temporary = path.with_name('.'+path.name+'-'+uuid.uuid4().hex)
    materialize(temporary, files)
    for entry in temporary.rglob('*'):
        if entry.is_file():
            with entry.open('rb') as stream:
                os.fsync(stream.fileno())
    for entry in sorted((p for p in temporary.rglob('*') if p.is_dir()), reverse=True):
        sync_directory(entry)
    sync_directory(temporary)
    rename(temporary, path)


def validate_links(record: dict) -> None:
    for item in record.get('legacy_links', []):
        path = Path(item['path'])
        if path.is_symlink():
            if os.readlink(path) != item['target']:
                raise ValueError('legacy Skill link changed: '+str(path))
        elif path.exists():
            raise ValueError('legacy Skill path changed: '+str(path))


def compensate(journal: Path, record: dict) -> None:
    """Inspect all owned surfaces before an idempotent compare-and-restore."""
    file_states = []
    for key in ('config', 'market'):
        if not record.get(key+'_written'):
            continue
        path = Path(record[key])
        current = digest(file_bytes(path))
        before = (journal/(key+'-before')).read_bytes()
        if digest(before) != record[key+'_before']:
            raise ValueError('activation backup digest mismatch')
        if current not in {record[key+'_before'], record[key+'_after']}:
            raise ValueError('cannot compensate subsequent '+key+' changes; inspect '+str(journal))
        file_states.append((key, path, current, before))
    directories = []
    for key in ('source', 'cache'):
        if not record.get(key+'_written'):
            continue
        path = Path(record[key])
        before, current = record[key+'_before'], identity(path)
        backup = journal/('previous-'+key)
        backup_identity = identity(backup)
        if current not in {None, before, record['content_digest']} or (backup_identity is not None and backup_identity != before):
            raise ValueError('cannot compensate a changed plugin '+key)
        if before is not None and current != before and backup_identity != before:
            raise ValueError('activation is missing its previous '+key)
        directories.append((key, path, current, before, backup))
    for item in record.get('cache_old', []):
        current, saved = identity(Path(item['path'])), identity(Path(item['saved']))
        expected = item['content_digest']
        if (current, saved) not in {(expected, None), (None, expected)}:
            raise ValueError('cannot compensate a changed previous Codex cache')
    validate_links(record)
    # Every operation accepts the already-restored state after interruption.
    for key, path, current, before, backup in directories:
        if current == before:
            continue
        if current is not None:
            rename(path, journal/('failed-'+key))
        if before is not None:
            rename(backup, path)
    for item in record.get('cache_old', []):
        old_path, saved_path = Path(item['path']), Path(item['saved'])
        if not old_path.exists() and saved_path.exists():
            rename(saved_path, old_path)
    for key, path, current, before in file_states:
        if current != record[key+'_before']:
            if record[key+'_existed']:
                write(path, before)
            else:
                path.unlink(missing_ok=True)
                sync_directory(path.parent)
    for item in record.get('legacy_links', []) if record.get('links_written') else []:
        path = Path(item['path'])
        if not path.is_symlink():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(item['target'])
            sync_directory(path.parent)
    record['status'] = 'rolled_back'
    audit_path = journal.parent.parent/'install-audits'/(record.get('content_digest', '')[:16]+'.json')
    if audit_path.is_file():
        audit = json.loads(audit_path.read_bytes())
        if audit.get('transaction') == record.get('transaction'):
            write(audit_path, canonical(record))
    # The audit is made truthful before the terminal transaction marker.  If
    # recovery is interrupted between these writes, the next activation sees
    # the still-pending journal and repeats the same idempotent reconciliation.
    write(journal/'transaction.json', canonical(record))


def replace_directory(journal: Path, record: dict, key: str, candidate: Path) -> None:
    path = Path(record[key])
    if identity(path) != record[key+'_before']:
        raise ValueError('plugin '+key+' changed before activation')
    record[key+'_written'] = True
    write(journal/'transaction.json', canonical(record))
    if path.exists():
        rename(path, journal/('previous-'+key))
    rename(candidate, path)


def verify_staged_config(before: bytes, after: bytes, home: Path, name: str) -> None:
    expected = copy.deepcopy(tomllib.loads(before.decode()))
    marketplaces = expected.setdefault('marketplaces', {})
    entry = {'source_type':'local', 'source':str(home)}
    if name in marketplaces and marketplaces[name] != entry:
        raise ValueError('marketplace registration is owned by another source')
    marketplaces[name] = entry
    expected.setdefault('plugins', {}).setdefault('openubmc@'+name, {})['enabled'] = True
    if tomllib.loads(after.decode()) != expected:
        raise ValueError('Codex changed unrelated staged configuration')


def activate(archive: Path, archive_sha: str, home: Path, codex: Path) -> dict:
    lock, files = read_archive(archive, archive_sha)
    env = dict(os.environ, HOME=str(home), CODEX_HOME=str(codex), XDG_CONFIG_HOME=str(home/'.config'),
               XDG_DATA_HOME=str(home/'.local/share'), XDG_CACHE_HOME=str(home/'.cache'))
    store = home/'.local/share/openubmc/plugin-store'
    store.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (store/'activation.lock').open('a') as mutex:
        fcntl.flock(mutex, fcntl.LOCK_EX)
        for path in (store/'transactions').glob('*/transaction.json'):
            pending = json.loads(path.read_bytes())
            if pending.get('status') not in {'committed', 'rolled_back'}:
                if pending.get('schema') != 'openubmc.plugin-activation.v2' or pending.get('home') != str(home) or pending.get('codex_home') != str(codex):
                    raise ValueError('incomplete activation journal belongs to another scope or schema')
                compensate(path.parent, pending)
        release = store/'releases'/(lock['version']+'-'+lock['content_digest'][:16])
        if release.exists():
            if verify_directory(release) != lock:
                raise ValueError('existing immutable release has drifted')
        else:
            stage_directory(release, files)
        cli = [sys.executable, '-I', str(release/'scripts/pluginctl.py')]
        for operation in ('prepare', 'doctor'):
            command([*cli, operation], env)
        source = home/'plugins/openubmc'
        old = verify_directory(source) if source.exists() or source.is_symlink() else None
        if old:
            owner = store/'install-audits'/(old['content_digest'][:16]+'.json')
            if not owner.is_file() or json.loads(owner.read_bytes()).get('content_digest') != old['content_digest']:
                raise ValueError('existing plugin source has no matching ownership audit')
            if old['version'] == lock['version'] and old['content_digest'] != lock['content_digest']:
                raise ValueError('same-version plugin replacement requires a new qualified version')
        market, config = home/'.agents/plugins/marketplace.json', codex/'config.toml'
        market_before, config_before = file_bytes(market), file_bytes(config)
        marketplace = json.loads(market_before) if market_before else {'name':'personal','interface':{'displayName':'Personal'},'plugins':[]}
        name = marketplace.get('name', '')
        if not re.fullmatch(r'[A-Za-z0-9_-]+', name):
            raise ValueError('invalid personal marketplace name')
        entries = marketplace.setdefault('plugins', [])
        for entry in entries:
            if entry.get('name') == 'openubmc' and entry.get('source') != {'source':'local','path':'./plugins/openubmc'}:
                raise ValueError('existing OpenUBMC marketplace entry has another owner')
        if not any(item.get('name') == 'openubmc' for item in entries):
            entries.append({'name':'openubmc','source':{'source':'local','path':'./plugins/openubmc'},'policy':{'installation':'AVAILABLE','authentication':'ON_INSTALL'},'category':'Productivity'})
        module = types.ModuleType('verified_plugin_migration')
        exec(compile(files['scripts/plugin_install.py'], '<verified-migration>', 'exec'), module.__dict__)
        paths = [item['path'] for item in json.loads(files['workflow.json'])['skills']]
        plan, migration_before, migration_after = module.plan(home, paths, codex)
        if migration_before != config_before:
            raise ValueError('Codex configuration changed while planning')
        journal = store/'transactions'/uuid.uuid4().hex
        journal.mkdir(parents=True, mode=0o700)
        record = {'schema':'openubmc.plugin-activation.v2','status':'prepared','home':str(home),'codex_home':str(codex),
                  'transaction':journal.name, 'source':str(source),'market':str(market),'config':str(config),
                  'source_commit':lock['source_commit'],'version':lock['version'],'content_digest':lock['content_digest'],
                  'archive_sha256':archive_sha,'release_path':str(release),'source_before':old['content_digest'] if old else None,
                  'legacy_links':plan['links']}
        for key, path, data in (('config',config,config_before),('market',market,market_before)):
            write(journal/(key+'-before'), data)
            record[key+'_before'], record[key+'_existed'] = digest(data), path.exists()
        write(journal/'transaction.json', canonical(record))
        try:
            stage_directory(journal/'candidate-source', files)
            replace_directory(journal, record, 'source', journal/'candidate-source')
            record['market_after'], record['market_written'] = digest(canonical(marketplace)), True
            write(journal/'transaction.json', canonical(record))
            if file_bytes(market) != market_before:
                raise ValueError('marketplace changed before activation')
            write(market, canonical(marketplace))
            # Let native Codex validate and prepare its installation in a
            # private home. It never writes the user's live configuration.
            stage_codex = journal/'codex-stage'
            write(stage_codex/'config.toml', migration_after)
            stage_env = dict(env, CODEX_HOME=str(stage_codex))
            command(['codex','plugin','marketplace','add',str(home)], stage_env)
            installed = json.loads(command(['codex','plugin','add','openubmc@'+name,'--json'], stage_env))
            stage_cache = Path(installed['installedPath'])
            expected_cache = stage_codex/'plugins/cache'/name/'openubmc'/lock['version']
            if stage_cache != expected_cache or verify_directory(stage_cache) != lock:
                raise ValueError('Codex installed content differs from the selected release')
            after = file_bytes(stage_codex/'config.toml')
            verify_staged_config(migration_after, after, home, name)
            cache = codex/stage_cache.relative_to(stage_codex)
            cache_before = identity(cache)
            if cache_before not in {None, lock['content_digest']}:
                raise ValueError('existing Codex plugin cache has different content')
            record.update(cache=str(cache), cache_before=cache_before)
            cache_root = cache.parent
            old_caches = []
            saved_root = journal/'cache-old'
            for old_path in sorted(cache_root.glob('*')) if cache_root.exists() else []:
                if old_path.is_dir() and old_path != cache:
                    old_identity = identity(old_path)
                    owner = store/'install-audits'/(old_identity[:16]+'.json')
                    if not owner.is_file() or json.loads(owner.read_bytes()).get('content_digest') != old_identity:
                        raise ValueError('previous Codex cache is not owned by this installer')
                    saved = saved_root/old_path.name
                    old_caches.append({'path':str(old_path), 'saved':str(saved), 'content_digest':old_identity})
            record['cache_old'] = old_caches
            write(journal/'transaction.json', canonical(record))
            for item in old_caches:
                rename(Path(item['path']), Path(item['saved']))
            replace_directory(journal, record, 'cache', stage_cache)
            record['config_after'], record['config_written'] = digest(after), True
            write(journal/'config-after', after)
            write(journal/'transaction.json', canonical(record))
            if file_bytes(config) != config_before:
                raise ValueError('Codex configuration changed before activation')
            validate_links(record)
            write(config, after)
            record['links_written'] = True
            write(journal/'transaction.json', canonical(record))
            for item in record['legacy_links']:
                path = Path(item['path'])
                if path.is_symlink():
                    path.unlink()
                    sync_directory(path.parent)
            selected = json.loads(command(['codex','plugin','list','--json'], env))
            active = [row for row in selected['installed'] if row['pluginId'] == 'openubmc@'+name]
            if len(active) != 1 or active[0]['version'] != lock['version'] or not active[0]['enabled']:
                raise ValueError('Codex selected a different active plugin version')
            installed['installedPath'] = str(cache)
            record['codex_install'] = installed
            # Recovery materials precede the commit marker.
            write(store/'archives'/(archive_sha+'.tar.gz'), archive.read_bytes())
            audit = dict(record, status='committed')
            write(store/'install-audits'/(lock['content_digest'][:16]+'.json'), canonical(audit))
            record['status'] = 'committed'
            write(journal/'transaction.json', canonical(record))
        except BaseException:
            compensate(journal, record)
            raise
        return dict(record, ok=True)


def run() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--home', type=Path, default=Path.home())
    parser.add_argument('--codex-home', type=Path)
    args = parser.parse_args()
    home = args.home.resolve()
    codex = (args.codex_home or home/'.codex').resolve()
    print(json.dumps(activate(args.archive, args.sha256.lower(), home, codex), sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(run())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({'ok':False,'error':str(error)}), file=sys.stderr)
        raise SystemExit(2)
