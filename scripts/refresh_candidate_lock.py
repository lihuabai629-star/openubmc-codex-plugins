#!/usr/bin/env python3
"""Refresh generated composition and package locks for a committed candidate."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / 'plugins/openubmc'


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def refresh(source_commit):
    if not re.fullmatch(r'[a-f0-9]{40}', source_commit):
        raise ValueError('source commit must be a full SHA')
    launcher = PLUGIN / 'scripts/launch_runtime.py'
    source = launcher.read_text()
    tree = ast.parse(source)
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
    lock = json.loads(lockpath.read_text())
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
        if data.get('status') == 'released' or data.get('passed') is True:
            raise ValueError('reset release qualification before refreshing a candidate')
        data.update(identity)
        p.write_bytes(canonical(data))
    p = ROOT / 'scripts/behavior/source.json'
    data = json.loads(p.read_text()); data['source_commit'] = source_commit
    p.write_bytes(canonical(data))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-commit', required=True)
    refresh(parser.parse_args().source_commit)
