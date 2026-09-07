"""Prepare source-only imports for a packaged Python entrypoint."""
import hashlib
import json
from pathlib import Path
import runpy
import sys
import tempfile


def verify_snapshot(root):
    """Check the exact bytes recorded by the Runtime launcher's validation."""
    receipt_path = root/'.openubmc-runtime-snapshot.json'
    if receipt_path.is_symlink():
        raise ValueError('Runtime snapshot receipt must not be a symbolic link')
    receipt = json.loads(receipt_path.read_bytes())
    if receipt.get('schema') != 'openubmc.runtime-snapshot.v1' or receipt.get('root') != str(root):
        raise ValueError('Runtime snapshot identity mismatch')
    actual = {}
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('Runtime snapshot contains a symbolic link')
        if path.is_file() and path != receipt_path:
            actual[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != receipt['files']:
        raise ValueError('Runtime snapshot inventory mismatch; restart from the verified archive')


def initialize(entrypoint):
    """Keep the returned cache scope alive for the importing Python process."""
    sys.dont_write_bytecode = True
    cache = tempfile.TemporaryDirectory(prefix='openubmc-python-cache-')
    # -B alone still reads existing caches. A fresh prefix prevents reading
    # the source tree's timestamp- or hash-based __pycache__ entries.
    sys.pycache_prefix = cache.name
    entrypoint = Path(entrypoint).resolve()
    # A package may not fall back to a snapshot receipt when its lock is lost.
    package = next((root for root in entrypoint.parents
                    if (root/'plugin-lock.json').exists() or (root/'.codex-plugin').exists()
                    or (root/'scripts/pluginctl.py').is_file()), None)
    if package is not None:
        # run_path compiles this source directly without importing its pyc.
        runpy.run_path(str(package/'scripts/pluginctl.py'))['verify'](package)
    else:
        snapshot = next((root for root in entrypoint.parents
                         if (root/'.openubmc-runtime-snapshot.json').exists()), None)
        if snapshot is None:
            raise ValueError('plugin-lock.json is missing; reinstall the verified archive')
        verify_snapshot(snapshot)
    # An isolated interpreter omits the script directory. Add it only after
    # checking the packaged sources, so sibling imports also work under -I.
    directory = str(entrypoint.parent)
    if directory not in sys.path:
        sys.path.insert(0, directory)
    return cache
