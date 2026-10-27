#!/usr/bin/env python3
"""Exercise Windows-client setup and native offline analysis from this payload."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]


def call(plugin, entry, messages, environment, args=()):
    process = subprocess.Popen(['node', str(plugin / entry), *args],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding='utf-8', env=environment)
    timer = threading.Timer(45, process.kill)
    timer.start()
    replies = []
    try:
        for message in messages:
            process.stdin.write(json.dumps(message) + '\n')
            process.stdin.flush()
            while True:
                line = process.stdout.readline()
                if not line:
                    raise ValueError('MCP closed before response: '+process.stderr.read()[-1000:])
                reply = json.loads(line)
                if reply.get('id') == message.get('id'):
                    replies.append(reply)
                    break
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()
        process.stdout.close(); process.stderr.close()
        timer.cancel()
    if process.returncode:
        raise ValueError('MCP exited unsuccessfully')
    return replies


def qualify(plugin):
    lock = json.loads((plugin / 'plugin-lock.json').read_text())
    environment = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix='openubmc-portable-') as temporary:
        work = Path(temporary)
        environment.update(HOME=str(work), USERPROFILE=str(work),
                           CODEX_HOME=str(work / 'codex'), LOCALAPPDATA=str(work / 'local'),
                           OPENUBMC_PLUGIN_HOST_PLATFORM='win32',
                           OPENUBMC_PLUGIN_PYTHON=sys.executable,
                           OPENUBMC_OFFLINE_OUTPUT_DIR=str(work / 'artifacts'))
        for capability in ('runtime', 'kb'):
            messages = [
                {'jsonrpc':'2.0','id':1,'method':'initialize','params':{}},
                {'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}},
                {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'openubmc_setup_status','arguments':{}}}]
            replies = {row['id']: row for row in call(plugin,
                'scripts/openubmc-mcp-bootstrap.js',messages,environment,(capability,))}
            assert replies[3]['result']['structuredContent']['reason'] == 'unsupported_platform'
            names = {tool['name'] for tool in replies[2]['result']['tools']}
            assert 'openubmc_setup_status' in names and not names.intersection({'observe','execute'})
        logs = work / 'bundle/dump_info/LogDump'
        logs.mkdir(parents=True)
        (logs.parent / 'dump_log').write_text('capture\n', encoding='utf-8')
        (logs / 'security.log').write_text('2026-10-28 00:00:00 login failed password=portable-private\n', encoding='utf-8')
        replies = call(plugin, 'scripts/openubmc-offline-mcp.js', [
            {'jsonrpc':'2.0','id':1,'method':'initialize','params':{}},
            {'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}},
            {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'openubmc_analyze_bundle',
                'arguments':{'source':str(logs.parent.parent),'problem':'login failed'}}}], environment)
        indexed = {row['id']:row for row in replies}
        assert {tool['name'] for tool in indexed[2]['result']['tools']} == {'openubmc_analyze_bundle','openubmc_read_evidence'}
        result = indexed[3]['result']
        assert result.get('isError') is False, result
        assert 'portable-private' not in json.dumps(result)
        assert Path(result['structuredContent']['artifact']).is_file()
    return {'schema':'openubmc.portable-capabilities.v1','passed':True,
        'version':lock['version'],'source_commit':lock['source_commit'],'content_digest':lock['content_digest'],
        'platform':platform.system(),'python':platform.python_version(),
        'native_windows_runtime':'unsupported','windows_setup_recovery':True,'offline_analysis':True,'redaction':True}


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plugin',type=Path,default=ROOT/'plugins/openubmc')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        report=qualify(args.plugin.resolve())
    except (AssertionError,ValueError,OSError,KeyError,subprocess.SubprocessError) as error:
        report={'passed':False,'error':str(error)}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report))
    raise SystemExit(0 if report['passed'] else 1)
