#!/usr/bin/env python3
"""Qualify installed Host records with native Codex and loopback-only responses."""
from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]


def command(argv, environment, *, cwd, timeout=180):
    process = subprocess.Popen(argv, env=environment, cwd=cwd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        if process.returncode:
            raise ValueError('qualification command failed: ' + (stdout + stderr)[-2500:])
        return stdout
    finally:
        # Drain only this disposable command's owned group before deleting its
        # temporary state. Lifecycle qualification remains a separate gate.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def qualify(codex, output):
    version = subprocess.check_output([codex, '--version'], text=True).strip()
    if version != 'codex-cli 0.153.4':
        raise ValueError('qualification requires the locked Codex 0.153.4')
    with tempfile.TemporaryDirectory(prefix='openubmc-installed-records-') as raw:
        root = Path(raw)
        home = root / 'home'
        codex_home = root / 'codex'
        codex_home.mkdir()
        state = root / 'state'
        environment = {key: value for key, value in os.environ.items()
            if not key.startswith(('OPENAI_', 'OPENUBMC_', 'CODEX_', 'XDG_', 'PYTHON', 'NODE_', 'NPM_'))}
        environment.update(HOME=str(home), CODEX_HOME=str(codex_home),
            XDG_CONFIG_HOME=str(home / '.config'), XDG_DATA_HOME=str(home / 'data'),
            XDG_CACHE_HOME=str(home / 'cache'), OPENUBMC_TARGET_RUNTIME_STATE_DIR=str(state),
            OPENUBMC_MCP_FORMAL_RUN='0', OPENUBMC_LOCAL_RECORD_KEY='synthetic-loopback-only')
        credentials = home / '.config/openubmc/credentials.env'
        credentials.parent.mkdir(mode=0o700, parents=True)
        credentials.write_text('OPENUBMC_SSH_USER=fixture\nOPENUBMC_SSH_PASSWORD=synthetic-loopback-only\n')
        credentials.chmod(0o600)
        market = root / 'market'
        plugin_source = market / 'plugins/openubmc'
        shutil.copytree(ROOT / 'plugins/openubmc', plugin_source, ignore=shutil.ignore_patterns('__pycache__'))
        manifest = market / '.agents/plugins/marketplace.json'
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({'name': 'record-qualification', 'plugins': [
            {'name': 'openubmc', 'source': {'source': 'local', 'path': './plugins/openubmc'}}]}))
        command([codex, 'plugin', 'marketplace', 'add', str(market), '--json'], environment, cwd=root)
        installed = json.loads(command([codex, 'plugin', 'add', 'openubmc@record-qualification', '--json'], environment, cwd=root))
        plugin = Path(installed['installedPath'])
        cli = [sys.executable, '-I', str(plugin / 'scripts/pluginctl.py')]
        identity = json.loads(command([*cli, 'verify'], environment, cwd=root))
        command([*cli, 'prepare'], environment, cwd=root, timeout=540)

        class Responses(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
                self.server.outputs.extend(item for item in request.get('input', [])
                                           if item.get('type') == 'custom_tool_call_output')
                self.server.calls += 1
                item = {'type': 'message', 'id': 'fixture-final', 'role': 'assistant',
                        'phase': 'final_answer', 'content': [{'type': 'output_text', 'text': 'Local record fixture complete.'}]}
                if self.server.start_run and self.server.calls == 1:
                    item = {'type': 'custom_tool_call', 'call_id': 'fixture-start', 'name': 'exec',
                            'input': 'text(await tools.mcp__openubmc_target_runtime__execute(' + json.dumps(
                                {'kind': 'start', 'target': '127.0.0.1', 'intent': 'diagnosis-only', 'deadline': 5}) + '));'}
                elif self.server.outputs:
                    latest = self.server.outputs[-1].get('output', '')
                    waiting = re.search(r'Script running with cell ID ([0-9]+)', str(latest))
                    if waiting:
                        item = {'type': 'function_call', 'call_id': 'fixture-wait-'+str(self.server.calls),
                                'name': 'wait', 'arguments': json.dumps({'cell_id': waiting[1], 'yield_time_ms': 1000})}
                events = [{'type': 'response.created', 'response': {'id': 'fixture'}},
                    {'type': 'response.output_item.done', 'output_index': 0, 'item': item},
                    {'type': 'response.completed', 'response': {'id': 'fixture',
                        'usage': {'input_tokens': 0, 'output_tokens': 0, 'total_tokens': 0}}}]
                body = ''.join('event: '+event['type']+'\ndata: '+json.dumps(event)+'\n\n' for event in events).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Responses)
        server.calls, server.start_run, server.outputs = 0, True, []
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        settings = {'features.hooks': 'true', 'features.plugins': 'true',
            'model_provider': '"record_fixture"', 'model_providers.record_fixture.name': '"Loopback fixture"',
            'model_providers.record_fixture.base_url': json.dumps(f'http://127.0.0.1:{server.server_port}/v1'),
            'model_providers.record_fixture.env_key': '"OPENUBMC_LOCAL_RECORD_KEY"',
            'model_providers.record_fixture.wire_api': '"responses"',
            'model_providers.record_fixture.supports_websockets': 'false'}
        config = [part for key, value in settings.items() for part in ('-c', key+'='+value)]
        flags = ['--json', '--skip-git-repo-check', '--dangerously-bypass-approvals-and-sandbox',
                 '--dangerously-bypass-hook-trust', '--model', 'gpt-5.6-sol', *config]
        tasks = []
        try:
            for name in ('project-a', 'project-b'):
                project = root / name
                project.mkdir()
                command(['git', 'init', '-q'], environment, cwd=project)
                (project / 'source').write_text(name)
                command(['git', 'add', '.'], environment, cwd=project)
                command(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test',
                         'commit', '-qm', 'fixture'], environment, cwd=project)
                server.calls, server.outputs = 0, []
                stdout = command([codex, 'exec', *flags, '-C', str(project),
                    'Exercise only the local record fixture with synthetic credentials and a loopback target.'],
                    environment, cwd=project)
                events = [json.loads(line) for line in stdout.splitlines() if line.strip()]
                task_id = next(event['thread_id'] for event in events if event.get('type') == 'thread.started')
                handoff = json.loads(command([*cli, 'records', '--task-id', task_id], environment, cwd=root))
                if len(handoff['runs']) != 1:
                    raise ValueError('installed Start did not bookmark exactly one Run: '+
                                     json.dumps({'handoff': handoff, 'tool_outputs': server.outputs,
                                                 'events': stdout[-1200:]})[-6500:])
                record = handoff['runs'][0]['run_record']
                binding = record['workspace_binding']
                commit = command(['git', 'rev-parse', 'HEAD'], environment, cwd=project).strip()
                if (binding['status'] != 'bound' or binding['snapshot']['repositories'][0]['commit'] != commit
                        or binding['snapshot']['repositories'][0]['dirty'] is not False):
                    raise ValueError('installed hooks did not bind the actual selected clean repository')
                if record['schema_version'] != 2 or record['usage']['input_tokens'] is not None:
                    raise ValueError('unregistered invocation measurements did not remain unknown')
                tasks.append({'task_id': task_id, 'run_id': record['run_id'], 'binding': binding})
            if tasks[0]['binding']['snapshot']['project_ref'] == tasks[1]['binding']['snapshot']['project_ref']:
                raise ValueError('two installed projects acquired the same project identity')
            server.start_run = False
            server.outputs = []
            command([codex, 'exec', 'resume', *flags, tasks[0]['task_id'], 'Recover without any tool call.'],
                    environment, cwd=root)
            recovered = json.loads(command([*cli, 'records', '--task-id', tasks[0]['task_id']], environment, cwd=root))
            if (len(recovered['runs']) != 1 or recovered['runs'][0]['run_id'] != tasks[0]['run_id']
                    or recovered['runs'][0]['run_record']['workspace_binding'] != tasks[0]['binding']):
                raise ValueError('native resume changed the old Run or its workspace binding')
            exported = json.loads(command([*cli, 'export-records', '--task-id', tasks[0]['task_id'],
                                          '--output-directory', str(root / 'exports')], environment, cwd=root))
            checked = json.loads(command([*cli, 'verify-records', '--record-file', exported['path']], environment, cwd=root))
            if checked['content_digest'] != exported['content_digest']:
                raise ValueError('installed export verification disagrees')
            encoded = Path(exported['path']).read_text()
            if str(root) in encoded or 'synthetic-loopback-only' in encoded:
                raise ValueError('export contains private fixture data')
            command([codex, 'plugin', 'remove', 'openubmc@record-qualification', '--json'], environment, cwd=root)
            report = {'passed': True, 'schema': 'openubmc.installed-host-records.qualification/v1',
                'codex': version, 'version': identity['version'], 'source_commit': identity['source_commit'],
                'content_digest': identity['content_digest'], 'native_hooks': True, 'two_project_bindings': True,
                'native_resume_preserved_run': True, 'fresh_v2_records': True, 'unknown_usage_retained': True,
                'installed_export_verified': True, 'live_model_tested': False, 'live_device_tested': False,
                'network_scope': 'loopback only', 'desktop_ui_tested': False}
            output.write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
            return report
        finally:
            server.shutdown(); server.server_close(); worker.join(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--codex', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(qualify(args.codex, args.output), sort_keys=True))
    except Exception as error:
        args.output.write_text(json.dumps({'passed': False, 'error': str(error)}, indent=2)+'\n')
        raise SystemExit(2)
