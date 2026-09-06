#!/usr/bin/env python3
"""Validate the checked-out catalog and its published plugin identity."""
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def main():
    market = json.loads((ROOT/'.agents/plugins/marketplace.json').read_text())
    if market['name'] != 'openubmc-public' or len(market['plugins']) != 1:
        raise ValueError('Unexpected marketplace identity')
    entry = market['plugins'][0]
    if entry['name'] != 'openubmc' or entry['source'] != {'source':'local','path':'./plugins/openubmc'}:
        raise ValueError('Unexpected plugin source')
    plugin = ROOT/'plugins/openubmc'
    spec = importlib.util.spec_from_file_location('pluginctl', plugin/'scripts/pluginctl.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    lock, _ = module.verify(plugin)
    for document in ('release.json', 'qualification.json'):
        record = json.loads((ROOT/document).read_text())
        for key in ('version','source_commit','content_digest'):
            if record[key] != lock[key]:
                raise ValueError(document+' does not match the plugin: '+key)
    if (plugin/'LICENSE').read_bytes() != (ROOT/'LICENSE').read_bytes():
        raise ValueError('Plugin license differs from the distribution license')
    print(json.dumps({'ok':True,'marketplace':market['name'],'version':lock['version'],
                      'content_digest':lock['content_digest']}))


if __name__=='__main__':
    main()
