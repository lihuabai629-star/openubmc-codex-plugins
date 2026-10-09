#!/usr/bin/env python3
"""Refresh generated composition and package locks for a committed candidate."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / 'plugins/openubmc'


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def refresh(source_commit):
    if not re.fullmatch(r'[a-f0-9]{40}', source_commit):
        raise ValueError('source commit must be a full SHA')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if source_commit != head:
        raise ValueError('source commit must be the current committed candidate')
    committed_files = set(subprocess.check_output(
        ['git', 'ls-tree', '-r', '-z', '--name-only', source_commit, '--', 'plugins/openubmc'],
        cwd=ROOT, text=True).split('\0')) - {''}
    payload_files = set()
    for path in PLUGIN.rglob('*'):
        if '__pycache__' in path.parts:
            continue
        if path.is_symlink():
            raise ValueError('plugin contains a symlink')
        if path.is_file():
            payload_files.add(path.relative_to(ROOT).as_posix())
    if payload_files != committed_files:
        raise ValueError('plugin payload inventory differs from committed source')
    subprocess.run(['git', 'diff', '--exit-code', source_commit, '--', 'plugins/openubmc',
                    ':!plugins/openubmc/scripts/launch_runtime.py', ':!plugins/openubmc/plugin-lock.json'],
                   cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    for name in ('release.json', 'qualification.json', 'native-plugin-qualification.json'):
        data = json.loads((ROOT / name).read_text())
        if data.get('status') == 'released' or data.get('passed') is True:
            raise ValueError('reset release qualification before refreshing a candidate')
    launcher = PLUGIN / 'scripts/launch_runtime.py'
    source = subprocess.check_output(
        ['git', 'show', source_commit + ':plugins/openubmc/scripts/launch_runtime.py'],
        cwd=ROOT, text=True)
    tree = ast.parse(source)
    digest = hashlib.sha256(b'openubmc-target-runtime-content-v1\0')
    package = PLUGIN / 'skills/openubmc-target-runtime/openubmc_target_runtime'
    for path in sorted(package.rglob('*.py')):
        if '__pycache__' in path.parts:
            continue
        if path.is_symlink():
            raise ValueError('Runtime contains a symlink')
        name = path.relative_to(package).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(name).to_bytes(8, 'big')); digest.update(name)
        digest.update(len(content).to_bytes(8, 'big')); digest.update(content)
    source = re.sub(r'^EXPECTED_DIGEST = .*$', lambda _: 'EXPECTED_DIGEST = ' + repr('sha256:' + digest.hexdigest()), source, flags=re.M)
    roots = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                 and getattr(n.targets[0], 'id', '') == 'COMPOSITION_ROOTS')
    files = {}
    for name in roots:
        for path in sorted((PLUGIN / 'skills' / name).rglob('*')):
            relative = path.relative_to(PLUGIN / 'skills')
            if {'__pycache__', 'tests', 'node_modules', '.git'}.intersection(relative.parts):
                continue
            if path.is_symlink():
                raise ValueError('composition contains a symlink')
            if path.is_file():
                files[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    source = re.sub(r'^COMPOSITION_FILES = .*$', lambda _: 'COMPOSITION_FILES = ' + repr(files), source, flags=re.M)
    source = re.sub(r'^SOURCE_COMMIT = .*$', lambda _: 'SOURCE_COMMIT = ' + repr(source_commit), source, flags=re.M)
    launcher.write_text(source)
    lockpath = PLUGIN / 'plugin-lock.json'
    lock = json.loads(subprocess.check_output(
        ['git', 'show', source_commit + ':plugins/openubmc/plugin-lock.json'], cwd=ROOT, text=True))
    lock.pop('content_digest', None)
    lock['source_commit'] = source_commit
    lock['version'] = json.loads((PLUGIN / '.codex-plugin/plugin.json').read_text())['version']
    lock['files'] = {p.relative_to(PLUGIN).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(PLUGIN.rglob('*')) if p.is_file() and p != lockpath and '__pycache__' not in p.parts}
    lock['manifest_digest'] = lock['files']['.codex-plugin/plugin.json']
    lock['content_digest'] = hashlib.sha256(canonical(lock)).hexdigest()
    lockpath.write_bytes(canonical(lock))
    identity = {k: lock[k] for k in ('version', 'source_commit', 'content_digest')}
    for name in ('release.json', 'qualification.json', 'native-plugin-qualification.json'):
        p = ROOT / name
        data = json.loads(p.read_text())
        data.update(identity)
        p.write_bytes(canonical(data))
    p = ROOT / 'scripts/behavior/source.json'
    data = json.loads(p.read_text()); data['source_commit'] = source_commit
    p.write_bytes(canonical(data))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-commit', required=True)
    refresh(parser.parse_args().source_commit)
