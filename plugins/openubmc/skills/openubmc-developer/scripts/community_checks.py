#!/usr/bin/env python3
"""Run local community checks against an explicit source scope."""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import json
import os
import signal
import tempfile
import time
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1] / 'resources' / 'community'


def run_check(kind, repo, files=(), *, timeout=120, old_ref=None, new_ref=None, output=None,
              old_dir=None, new_dir=None):
    repo = Path(repo).resolve(strict=True)
    if not repo.is_dir():
        raise ValueError('repo must be a local directory')
    scoped = []
    for name in files:
        path = (repo / name).resolve(strict=True)
        if not path.is_relative_to(repo) or not path.is_file():
            raise ValueError('check files must be regular files inside repo')
        scoped.append(str(path.relative_to(repo)))
    if kind == 'compliance':
        scoped = [p for p in scoped if p.endswith('.json') and p.startswith(
            ('interface_config/redfish/', 'intf/mdb/', 'messages/', 'path/mdb/',
             'json/intf/mdb/', 'json/path/mdb/'))]
        if not scoped:
            return {'status': 'skipped', 'reason': 'no matching interface files', 'files': []}
        node = shutil.which('node')
        if not node:
            return {'status': 'incomplete', 'reason': 'Node.js 18+ is required'}
        command = [node, str(ROOT / 'compliance/scripts/compliance-lint.mjs'), '--files', *scoped, '--scope', 'auto']
    elif kind == 'concurrency':
        if not scoped:
            return {'status': 'skipped', 'reason': 'explicit source files required'}
        command = [sys.executable, str(ROOT / 'concurrency/scripts/collect_candidates.py'), '--root', str(repo)]
        for path in scoped:
            command += ['--scope', path]
    elif kind == 'web-backend':
        if not any(p.startswith('interface_config/web_backend/') for p in scoped):
            return {'status': 'skipped', 'reason': 'no web_backend files changed'}
        command = [sys.executable, str(ROOT / 'web-backend/scripts/rackmount_web_backend_check.py'), '--repo', str(repo)]
    elif kind == 'redfish-diff':
        if not output:
            raise ValueError('output is required')
        if old_dir or new_dir:
            if not old_dir or not new_dir or old_ref or new_ref:
                raise ValueError('supply old-dir/new-dir or old-ref/new-ref')
            roots = [Path(p).resolve(strict=True) for p in (old_dir, new_dir)]
            if not all(p.is_dir() for p in roots):
                raise ValueError('old-dir and new-dir must be directories')
            inputs = ['--old', str(roots[0]), '--new', str(roots[1])]
        else:
            if not old_ref or not new_ref:
                raise ValueError('old-ref and new-ref are required')
            refs = []
            for ref in (old_ref, new_ref):
                result = subprocess.run(['git', 'rev-parse', '--verify', '--end-of-options', ref + '^{commit}'], cwd=repo,
                                        capture_output=True, text=True, timeout=10, check=True,
                                        env={**os.environ, 'GIT_NO_LAZY_FETCH': '1', 'GIT_TERMINAL_PROMPT': '0'})
                refs.append(result.stdout.strip())
            inputs = ['--repo', str(repo), '--old-ref', refs[0], '--new-ref', refs[1]]
        destination = Path(output).resolve()
        sources = [repo] if not (old_dir or new_dir) else roots
        if any(destination == source or source.is_relative_to(destination) for source in sources):
            raise ValueError('output must not contain a source directory')
        if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
            raise ValueError('output must be a new or empty directory')
        command = [sys.executable, str(ROOT / 'redfish-diff/scripts/analyze_redfish_diff.py'),
                   *inputs, '--out-dir', str(destination), '--offline']
    else:
        raise ValueError('unknown check')
    if os.name != "posix":
        return {"status": "incomplete", "reason": "Run bounded community checks in Linux or WSL", "files": scoped}
    process = None
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(command, cwd=repo, stdout=stdout, stderr=stderr, start_new_session=True,
                                       env={**os.environ, 'GIT_NO_LAZY_FETCH': '1', 'GIT_TERMINAL_PROMPT': '0'})
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise TimeoutError('check deadline exceeded')
                if max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) > 2 * 1024 * 1024:
                    raise ValueError('check output exceeded 2 MiB')
                time.sleep(.02)
            texts = []
            for handle in (stdout, stderr):
                handle.seek(0)
                raw = handle.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    raise ValueError('check output exceeded 2 MiB')
                texts.append(raw.decode('utf-8', errors='replace'))
            result = subprocess.CompletedProcess(command, process.returncode, *texts)
    except (TimeoutError, OSError, ValueError) as exc:
        return {'status': 'incomplete', 'reason': str(exc), 'files': scoped}
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    status = 'completed' if result.returncode == 0 else 'findings' if result.returncode == 1 else 'incomplete'
    report = {'check': kind, 'status': status, 'returncode': result.returncode, 'files': scoped,
              'stdout': result.stdout, 'stderr': result.stderr}
    if kind == 'compliance':
        try:
            report['result'] = json.loads(result.stdout)
        except ValueError:
            report['status'] = 'incomplete'
    if kind == 'concurrency':
        report['interpretation'] = 'Candidates require source review; successful scan is not a clean bill of health.'
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=['compliance', 'concurrency', 'web-backend', 'redfish-diff'])
    parser.add_argument('--repo', required=True)
    parser.add_argument('--file', action='append', default=[])
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--old-ref')
    parser.add_argument('--new-ref')
    parser.add_argument('--output')
    parser.add_argument('--old-dir')
    parser.add_argument('--new-dir')
    args = parser.parse_args()
    if not 1 <= args.timeout <= 600:
        parser.error('timeout must be 1-600 seconds')
    try:
        result = run_check(args.kind, args.repo, args.file, timeout=args.timeout,
                           old_ref=args.old_ref, new_ref=args.new_ref, output=args.output,
                           old_dir=args.old_dir, new_dir=args.new_dir)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        result = {'status': 'incomplete', 'reason': str(exc)}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 2 if result['status'] == 'incomplete' else 1 if result['status'] == 'findings' else 0


if __name__ == '__main__':
    raise SystemExit(main())
