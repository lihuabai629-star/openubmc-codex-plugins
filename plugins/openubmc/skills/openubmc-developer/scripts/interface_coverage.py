"""Run the pinned, network-free interface documentation coverage checker."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _plugin_sys
    _plugin_sys.dont_write_bytecode = True
    import runpy as _plugin_runpy
    from pathlib import Path as _PluginPath
    _plugin_runpy.run_path(str(_PluginPath(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'))['initialize'](__file__)

import json
from pathlib import Path
import shutil
import subprocess

CHECKER = Path(__file__).resolve().parents[1] / 'resources/interface-coverage/scripts/doc-coverage.mjs'


def check_interface_coverage(path: Path, timeout: int = 120) -> dict:
    node = shutil.which('node')
    if not node:
        return {'status': 'incomplete', 'reason': 'Node.js 18+ is required'}
    try:
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError('Interface input exceeds 8 MiB')
        payload = json.loads(path.read_text())
        if not isinstance(payload, dict) or not isinstance(payload.get('changedFiles'), list):
            raise ValueError('Interface input requires changedFiles')
        if not all(isinstance(f, str) for f in payload['changedFiles']):
            raise ValueError('changedFiles must contain paths')
        # A missing source is not an empty, successfully queried docs repository.
        payload.setdefault('docsTree', None)
        payload.setdefault('docsPrFiles', {})
        completed = subprocess.run([node, str(CHECKER), '--stdin'], input=json.dumps(payload),
                                   capture_output=True, text=True, timeout=timeout)
        if completed.returncode:
            return {'status': 'incomplete', 'reason': 'Interface checker execution failed'}
        result = json.loads(completed.stdout)
        if result.get('conclusion') == 'incomplete':
            status = 'incomplete'
        else:
            status = 'ok'
        return {'status': status, 'advisory': True, 'result': result,
                'source_revision': payload.get('headSha', ''),
                'docs_revision': payload.get('docsRevision', '')}
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return {'status': 'incomplete', 'reason': type(error).__name__}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 600:
        parser.error('--timeout must be between 1 and 600 seconds')
    result = check_interface_coverage(args.input, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(2 if result['status'] == 'incomplete' else 0)
