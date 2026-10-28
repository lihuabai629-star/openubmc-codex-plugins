#!/usr/bin/env python3
"""Qualify an immutable Codex plugin release using its actual distribution scope."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SOURCE_REPOSITORY = 'lihuabai629-star/openubmc-agent-workflow'
MARKETPLACE_REPOSITORY = 'lihuabai629-star/openubmc-codex-plugins'
SCHEMA = 'openubmc.codex-plugin.release-gate.v1'


def command(*argv: str, cwd: Path | None = None) -> str:
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, timeout=600)
    if result.returncode:
        raise ValueError(f'command failed: {argv[0]} {argv[1]}: {result.stderr[-2000:]}')
    return result.stdout.strip()


def document(path: Path) -> dict:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f'expected JSON object: {path.name}')
    return value


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def identity(record: dict, lock: dict, label: str) -> None:
    for key in ('version', 'source_commit', 'content_digest'):
        require(record.get(key) == lock[key], f'{label} identity mismatch: {key}')


def passed_fields(record: dict, fields: tuple[str, ...], label: str) -> None:
    require(all(record.get(field) is True for field in fields), f'{label} incomplete')


def assess_reports(root: Path, lock: dict, release: dict, previous_version: str) -> dict:
    evidence = root / 'docs' / 'qualification' / lock['version']
    hashes = {}
    reports = {}
    for name in ('plugin-qualification', 'public-behavior', 'installed-host-records',
                 'portable-capabilities-linux', 'portable-capabilities-windows',
                 'repository-validation', 'plugin-provenance', 'source-release-lock'):
        path = evidence / (name + '.json')
        reports[name] = document(path)
        hashes[path.relative_to(root).as_posix()] = digest(path)
    lifecycle = reports['plugin-qualification']
    identity(lifecycle, lock, 'lifecycle')
    require(lifecycle.get('archive_sha256') == release['archive_sha256'], 'lifecycle archive mismatch')
    passed_fields(lifecycle, ('ok', 'deterministic_archive', 'native_install', 'native_uninstall',
                             'reinstall', 'external_state_preserved'), 'lifecycle')
    resume = lifecycle.get('native_thread_resume', {})
    passed_fields(resume, ('native_upgrade', 'old_cache_absent', 'configuration_preserved'), 'upgrade/resume')
    require(resume.get('from_version') == previous_version and resume.get('to_version') == lock['version']
            and resume.get('resume_error') is None, 'upgrade baseline or resume mismatch')
    for field in ('native_codex_exec', 'optional_kb_failure_isolation'):
        run = lifecycle.get(field, {})
        require(run.get('restart_verified') is True and run.get('invocations', 0) >= 2,
                f'{field} incomplete')
    for name in ('public-behavior', 'installed-host-records',
                 'portable-capabilities-linux', 'portable-capabilities-windows'):
        record = reports[name]
        identity(record, lock, name)
        passed_fields(record, ('passed',), name)
    behavior = reports['public-behavior']
    passed_fields(behavior, ('package_integrity_after_checks', 'runtime_shutdown_verified'), 'behavior')
    records = reports['installed-host-records']
    passed_fields(records, ('fresh_v2_records', 'installed_export_verified', 'native_hooks',
                           'native_resume_preserved_run', 'two_project_bindings',
                           'unknown_usage_retained', 'unexecuted_test_receipts_absent'), 'host records')
    for platform in ('linux', 'windows'):
        report = reports['portable-capabilities-' + platform]
        require(report.get('platform') == platform.title()
                and report.get('native_windows_runtime') == 'unsupported', 'platform scope mismatch')
        passed_fields(report, ('windows_setup_recovery', 'offline_analysis', 'redaction'), platform)
    repository = reports['repository-validation']
    require(repository.get('source_commit') == lock['source_commit']
            and repository.get('checkout_commit') == lock['source_commit'], 'repository validation source mismatch')
    passed_fields(repository, ('complete_validation_passed',), 'repository validation')
    for kind in ('python', 'node'):
        groups = repository.get(kind + '_groups', [])
        require(bool(groups) and all(item.get('passed') is True and item.get('tests', 0) > 0
                                    for item in groups), f'{kind} tests incomplete')
        require(sum(item['tests'] for item in groups) == repository.get(kind + '_tests'),
                f'{kind} test count mismatch')
    return {'sha256': hashes, 'reports': reports}


def assess_ci(run: dict, jobs: list[dict], *, repository: str, commit: str,
              workflow: str, required_steps: dict[str, tuple[str, ...]]) -> dict:
    require(run.get('repository', {}).get('full_name') == repository, 'CI repository mismatch')
    require(run.get('head_sha') == commit and run.get('event') == 'push'
            and run.get('path') == '.github/workflows/' + workflow, 'CI source/workflow mismatch')
    require(run.get('status') == 'completed' and run.get('conclusion') == 'success', 'CI has not passed')
    for name, steps in required_steps.items():
        matches = [job for job in jobs if job.get('name') == name]
        require(len(matches) == 1, f'CI job missing or duplicated: {name}')
        job = matches[0]
        require(job.get('status') == 'completed' and job.get('conclusion') == 'success', f'CI job failed: {name}')
        for step in steps:
            executions = [item for item in job.get('steps', []) if item.get('name') == step]
            require(len(executions) == 1 and executions[0].get('status') == 'completed'
                    and executions[0].get('conclusion') == 'success', f'CI step did not execute successfully: {step}')
    return {'repository': repository, 'head_commit': commit, 'run_id': run['id'],
            'run_attempt': run['run_attempt'], 'url': run['html_url'], 'conclusion': 'success',
            'jobs': sorted(required_steps)}


def hosted_ci(repository: str, commit: str, required_steps: dict[str, tuple[str, ...]]) -> dict:
    listing = json.loads(command('gh', 'api', f'repos/{repository}/actions/workflows/validate.yml/runs?head_sha={commit}&event=push&per_page=100'))
    runs = listing.get('workflow_runs', [])
    require(bool(runs), 'no CI run for exact commit')
    selected = max(runs, key=lambda run: run['id'])
    run = json.loads(command('gh', 'api', f'repos/{repository}/actions/runs/{selected["id"]}'))
    jobs = json.loads(command('gh', 'api', f'repos/{repository}/actions/runs/{run["id"]}/attempts/{run["run_attempt"]}/jobs?per_page=100'))
    return assess_ci(run, jobs['jobs'], repository=repository, commit=commit,
                     workflow='validate.yml', required_steps=required_steps)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def qualify(root: Path, source: Path, archive: Path, release_tag: str) -> dict:
    for checkout in (root, source):
        require(not command('git', 'status', '--porcelain', '--untracked-files=all', cwd=checkout), 'release worktree is dirty')
    market_commit = command('git', 'rev-parse', 'HEAD^{commit}', cwd=root)
    source_release = command('git', 'rev-parse', 'HEAD^{commit}', cwd=source)
    release = document(root / 'release.json')
    require(release.get('release_scope') == 'codex-plugin', 'unsupported release scope')
    require(re.fullmatch(r'v\d+\.\d+\.\d+', release_tag) is not None
            and release_tag == 'v' + release['version'], 'release tag/version mismatch')
    require(release.get('source_release_commit') == source_release, 'source release commit mismatch')
    previous = json.loads(command('gh', 'api', f'repos/{MARKETPLACE_REPOSITORY}/releases/latest'))
    previous_tag = previous['tag_name']
    require(not previous['draft'] and not previous['prerelease'], 'baseline is not stable')
    require(re.fullmatch(r'v\d+\.\d+\.\d+', previous_tag) is not None, 'invalid stable baseline')
    require(tuple(map(int, previous_tag[1:].split('.'))) < tuple(map(int, release['version'].split('.'))), 'release is not newer than baseline')
    require(release.get('upgrade_baseline') == previous_tag[1:], 'upgrade baseline is no longer latest')
    tag = json.loads(command('gh', 'api', f'repos/{MARKETPLACE_REPOSITORY}/git/ref/tags/{release_tag}'))
    require(tag.get('object', {}).get('sha') == market_commit
            and tag.get('object', {}).get('type') == 'commit', 'release tag does not point to the checked candidate')
    source_identity = json.loads(command(sys.executable, '-B', str(source / 'scripts/generate_release_lock.py'), 'verify', '--root', str(source)))
    source_commit = source_identity['source_commit']
    require(source_identity['release_version'] == release['version'] and release['source_commit'] == source_commit, 'source lock identity mismatch')
    archive_api = load_module('release_archive', source / 'scripts/plugin_archive.py')
    archive_sha = digest(archive)
    require(archive_sha == release['archive_sha256'], 'release archive checksum mismatch')
    lock, files = archive_api.read_archive(archive, archive_sha)
    require(archive_api.directory_files(root / 'plugins/openubmc') == files, 'marketplace plugin differs from archive')
    identity(release, lock, 'release')
    evidence = assess_reports(root, lock, release, previous_tag[1:])
    require(evidence['reports']['source-release-lock'] == document(source / 'release-lock.json'), 'recorded source lock mismatch')
    with tempfile.TemporaryDirectory(prefix='openubmc-plugin-gate-') as work:
        rebuilt = Path(work) / 'rebuilt.tar.gz'
        command(sys.executable, '-B', str(source / 'scripts/package_plugin.py'), 'build',
                '--source', str(source), '--source-ref', source_commit, '--output', str(rebuilt))
        require(digest(rebuilt) == archive_sha, 'archive is not reproducible from locked source')
    provenance = evidence['reports']['plugin-provenance']
    require(provenance.get('schema') == 'openubmc.codex-plugin.provenance.v1'
            and provenance.get('claim') == 'local-unpublished', 'unsupported provenance')
    require(provenance.get('source') == {'clean': True, 'commit': source_commit,
            'tree': command('git', 'rev-parse', source_commit + '^{tree}', cwd=source)}, 'provenance source mismatch')
    require(provenance.get('package') == {'sha256': archive_sha, 'version': lock['version'],
            'content_digest': lock['content_digest']}, 'provenance package mismatch')
    require(provenance.get('qualification', {}).get('sha256') == evidence['sha256'][f'docs/qualification/{lock["version"]}/plugin-qualification.json'], 'provenance qualification mismatch')
    source_ci = hosted_ci(SOURCE_REPOSITORY, source_release, {
        'CI contract preflight': ('Validate CI contract',),
        'Complete repository validation': ('Run complete repository validation', 'Run sanitized session replay regressions',
            'Validate local configuration in Chromium', 'Test plugin activation recovery with native Codex', 'Qualify immutable Codex plugin'),
    })
    marketplace_ci = hosted_ci(MARKETPLACE_REPOSITORY, market_commit, {
        'verify': ('Check final plugin behavior and cold MCP startup', 'Qualify installed Host records with native Codex',
                   'Run plugin release gate contract tests'),
        'Windows native plugin bootstrap': ('Check Windows setup boundary and native offline analysis',
                                            'Install plugin and initialize setup mode'),
    })
    # Detect edits during qualification without relying on mutable status metadata.
    require(command('git', 'rev-parse', 'HEAD', cwd=root) == market_commit
            and not command('git', 'status', '--porcelain', '--untracked-files=all', cwd=root), 'candidate changed during qualification')
    return {'schema': SCHEMA, 'scope': 'codex-plugin', 'passed': True, 'release_eligible': True,
            'version': lock['version'], 'source_commit': source_commit, 'source_release_commit': source_release,
            'marketplace_commit': market_commit, 'release_tag': release_tag, 'previous_tag': previous_tag,
            'archive_sha256': archive_sha, 'content_digest': lock['content_digest'],
            'evidence_sha256': evidence['sha256'], 'hosted_ci': {'source': source_ci, 'marketplace': marketplace_ci},
            'checks': {'immutable_source_lock': True, 'reproducible_archive': True, 'marketplace_inventory': True,
                       'lifecycle': True, 'public_behavior': True, 'host_records': True, 'linux_windows_offline': True},
            'boundaries': {'desktop_gui': 'not_run', 'live_device': 'not_run', 'external_model_ab': 'not_run'}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--release-tag', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = qualify(args.root.resolve(), args.source_root.resolve(), args.archive.resolve(), args.release_tag)
        result = 0
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        report = {'schema': SCHEMA, 'scope': 'codex-plugin', 'passed': False, 'release_eligible': False, 'error': str(error)}
        result = 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return result


if __name__ == '__main__':
    raise SystemExit(main())
