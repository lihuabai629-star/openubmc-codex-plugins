#!/usr/bin/env python3
"""Audit, roll back, or remove the owned OpenUBMC Codex plugin."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from plugin_archive import verify_directory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['audit', 'rollback', 'uninstall'])
    parser.add_argument('--home', type=Path, default=Path.home())
    parser.add_argument('--codex-home', type=Path)
    parser.add_argument('--release')
    args = parser.parse_args()
    home = args.home.resolve()
    store = home/'.local/share/openubmc/plugin-store'
    if args.command == 'audit':
        records = [json.loads(path.read_bytes()) for path in sorted((store/'install-audits').glob('*.json'))]
        transactions = {}
        for path in sorted((store/'transactions').glob('*/transaction.json')):
            transaction = json.loads(path.read_bytes())
            if transaction.get('transaction'):
                transactions[transaction['transaction']] = transaction
        # The activation journal is the transaction truth.  This also makes
        # audit output correct if a process died between compensation's audit
        # write and its terminal journal write.
        for record in records:
            transaction = transactions.get(record.get('transaction'))
            if transaction and transaction.get('content_digest') == record.get('content_digest'):
                record.update(status=transaction['status'])
        codex = (args.codex_home or home/'.codex').resolve()
        listing = subprocess.run(['codex','plugin','list','--json'], env=dict(os.environ, HOME=str(home), CODEX_HOME=str(codex),
                                 XDG_CONFIG_HOME=str(home/'.config'), XDG_DATA_HOME=str(home/'.local/share'), XDG_CACHE_HOME=str(home/'.cache')),
                                 capture_output=True, text=True, check=True, timeout=30)
        active_rows = [row for row in json.loads(listing.stdout)['installed']
                       if row.get('name') == 'openubmc' or str(row.get('pluginId', '')).split('@', 1)[0] == 'openubmc']
        active = {'installed': bool(active_rows), 'consistent': True}
        if active_rows:
            source = verify_directory(home/'plugins/openubmc')
            active['source_commit'] = source['source_commit']
            active['content_digest'] = source['content_digest']
            active['versions'] = [row['version'] for row in active_rows]
            active['consistent'] = len(active_rows) == 1 and all(
                verify_directory(codex/'plugins/cache'/row['marketplaceName']/'openubmc'/row['version']) == source
                for row in active_rows)
        print(json.dumps({'schema': 'openubmc.codex-plugin.audit.v1', 'releases': records, 'active': active}, sort_keys=True))
        return 0 if active['consistent'] else 2
    destination = home/'plugins/openubmc'
    current = verify_directory(destination)
    market_path = home/'.agents/plugins/marketplace.json'
    market = json.loads(market_path.read_bytes())
    name = market.get('name', '')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', name):
        raise ValueError('invalid personal marketplace name')
    entry = next((item for item in market.get('plugins', []) if item.get('name') == 'openubmc'), None)
    if not entry or entry.get('source') != {'source': 'local', 'path': './plugins/openubmc'}:
        raise ValueError('marketplace entry is not owned by this distribution')
    selector = 'openubmc@'+name
    codex = (args.codex_home or home/'.codex').resolve()
    env = dict(os.environ, HOME=str(home), CODEX_HOME=str(codex), XDG_CONFIG_HOME=str(home/'.config'),
               XDG_DATA_HOME=str(home/'.local/share'), XDG_CACHE_HOME=str(home/'.cache'))
    if args.command == 'uninstall':
        subprocess.run(['codex', 'plugin', 'remove', selector], env=env, check=True, capture_output=True, text=True)
        # Preserve the distribution source and release audit. Codex owns cache
        # removal; external credentials and Runtime records are never removed.
        print(json.dumps({'ok': True, 'removed': selector, 'preserved_state': True}))
        return 0
    if not args.release or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-[0-9a-f]{16}', args.release):
        raise ValueError('--release must name an audited immutable release')
    release = store/'releases'/args.release
    selected = verify_directory(release)
    audit = store/'install-audits'/(selected['content_digest'][:16]+'.json')
    record = json.loads(audit.read_bytes())
    if record.get('content_digest') != selected['content_digest'] or record.get('source_commit') != selected['source_commit']:
        raise ValueError('release audit identity mismatch')
    archive_sha = record.get('archive_sha256', '')
    if not re.fullmatch(r'[0-9a-f]{64}', archive_sha):
        raise ValueError('release audit has no valid archive digest')
    archive = store/'archives'/(archive_sha+'.tar.gz')
    subprocess.run([sys.executable, '-I', str(Path(__file__).with_name('install_plugin.py')),
                    str(archive), '--sha256', archive_sha, '--home', str(home), '--codex-home', str(codex)],
                   env=env, capture_output=True, text=True, check=True)
    print(json.dumps({'ok': True, 'release': args.release, 'source_commit': selected['source_commit']}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({'ok': False, 'error': str(error)}), file=sys.stderr)
        raise SystemExit(2)
