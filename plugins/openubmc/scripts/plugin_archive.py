"""Data-only verification for plugin archives and owned installation directories."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../skills/openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False)+'\n').encode()


def verify_content(files: dict[str, bytes]) -> dict:
    lock = json.loads(files['plugin-lock.json'])
    unsigned = dict(lock)
    digest = unsigned.pop('content_digest', None)
    if digest != hashlib.sha256(canonical(unsigned)).hexdigest():
        raise ValueError('plugin lock digest mismatch')
    if lock.get('schema') != 'openubmc.codex-plugin.v1' or lock.get('name') != 'openubmc':
        raise ValueError('unsupported plugin identity')
    if not re.fullmatch(r'[0-9a-f]{40}', lock.get('source_commit', '')):
        raise ValueError('invalid plugin source commit')
    actual = {name: hashlib.sha256(data).hexdigest() for name, data in files.items() if name != 'plugin-lock.json'}
    if actual != lock.get('files'):
        raise ValueError('plugin file inventory mismatch')
    manifest = json.loads(files['.codex-plugin/plugin.json'])
    if manifest.get('version') != lock.get('version') or manifest.get('name') != lock.get('name'):
        raise ValueError('plugin manifest identity mismatch')
    if lock.get('manifest_digest') != hashlib.sha256(files['.codex-plugin/plugin.json']).hexdigest():
        raise ValueError('plugin manifest digest mismatch')
    return lock


def directory_files(root: Path) -> dict[str, bytes]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError('plugin directory must be a real directory')
    files = {}
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('plugin directory contains a symbolic link')
        if path.is_file():
            files[path.relative_to(root).as_posix()] = path.read_bytes()
        elif not path.is_dir():
            raise ValueError('plugin directory contains a special file')
    return files


def verify_directory(root: Path) -> dict:
    return verify_content(directory_files(root))


def read_archive(path: Path, expected_sha256: str) -> tuple[dict, dict[str, bytes]]:
    data = path.read_bytes()
    if not re.fullmatch(r'[0-9a-f]{64}', expected_sha256) or hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError('archive digest mismatch')
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data)) as bundle:
        for item in bundle:
            member = PurePosixPath(item.name)
            if member.is_absolute() or '..' in member.parts or not member.parts or member.parts[0] != 'openubmc':
                raise ValueError('unsafe archive member')
            if item.isdir():
                continue
            if not item.isfile() or len(member.parts) < 2:
                raise ValueError('unsupported archive member')
            name = PurePosixPath(*member.parts[1:]).as_posix()
            total += item.size
            if name in files or total > 128*1024*1024 or len(files) >= 10000:
                raise ValueError('archive duplicates or size limit exceeded')
            files[name] = bundle.extractfile(item).read()
    return verify_content(files), files


def materialize(root: Path, files: dict[str, bytes]) -> None:
    root.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        path = root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o755 if name.startswith('scripts/') or name.endswith('.sh') else 0o644)
    verify_directory(root)
