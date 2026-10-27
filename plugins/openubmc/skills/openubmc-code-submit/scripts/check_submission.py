#!/usr/bin/env python3
"""Read-only submission checks against explicit branch roles and push endpoints."""

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import json
import subprocess
from pathlib import Path


class CheckError(Exception):
    pass


def git(repo, *args):
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args], text=True, capture_output=True,
            timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CheckError(f"git {args[0]} unavailable: {type(exc).__name__}") from exc
    if result.returncode:
        # Remote stderr may contain a credential-bearing URL. Never echo it.
        raise CheckError(f"git {args[0]} failed (exit {result.returncode})")
    return result.stdout.strip()


def remote_url(repo, remote, push=False):
    if remote not in git(repo, "remote").splitlines():
        raise CheckError("named remote does not exist")
    args = ["remote", "get-url", "--all"]
    if push:
        args.append("--push")
    urls = git(repo, *args, remote).splitlines()
    if len(urls) != 1:
        raise CheckError("remote must have exactly one selected URL")
    return urls[0]


def remote_sha(repo, remote, branch, allow_missing=False, push=False):
    url = remote_url(repo, remote, push=push)
    rows = git(repo, "ls-remote", "--refs", "--", url, f"refs/heads/{branch}")
    values = [line.split()[0] for line in rows.splitlines() if line]
    if not values and allow_missing:
        return None
    if len(values) != 1:
        raise CheckError(f"remote branch not found: {remote}/{branch}")
    return values[0]


def inspect(repo, target_branch, source_branch=None, upstream="upstream",
            origin="origin", phase="pre-push", verify_remote=False, expected_commits=1):
    repo = Path(repo).resolve()
    report = {"repo": str(repo), "phase": phase, "scope": "local",
              "errors": [], "warnings": []}
    errors = report["errors"]
    try:
        if expected_commits < 1:
            raise CheckError("expected commits must be positive")
        repo = Path(git(repo, "rev-parse", "--show-toplevel")).resolve()
        report["repo"] = str(repo)
        remotes = git(repo, "remote").splitlines()
        if upstream not in remotes or origin not in remotes:
            raise CheckError("both source and upstream remotes must exist")
        if upstream == origin:
            raise CheckError("source and upstream remote roles must be distinct")
        git(repo, "check-ref-format", f"refs/heads/{target_branch}")
        branch = git(repo, "symbolic-ref", "--short", "HEAD")
        source_branch = source_branch or branch
        git(repo, "check-ref-format", f"refs/heads/{source_branch}")
        baseline_ref = f"refs/remotes/{upstream}/{target_branch}"
        baseline = git(repo, "rev-parse", "--verify", f"{baseline_ref}^{{commit}}")
        head = git(repo, "rev-parse", "HEAD")
        behind, ahead = map(int, git(
            repo, "rev-list", "--left-right", "--count", f"{baseline_ref}...HEAD",
        ).split())
        changes = git(repo, "status", "--porcelain", "--untracked-files=all")
        commits = git(repo, "log", "--format=%H", f"{baseline_ref}..HEAD").splitlines()
        report.update({"development_branch": branch,
                       "source_remote": origin, "source_branch": source_branch,
                       "upstream_remote": upstream, "target_branch": target_branch,
                       "baseline_sha": baseline, "head_sha": head,
                       "behind": behind, "ahead": ahead, "commit_shas": commits,
                       "clean": not changes})
        if behind:
            errors.append("HEAD is missing commits from the target baseline")
        if ahead != expected_commits:
            errors.append(f"expected exactly {expected_commits} commit(s) ahead of the target baseline")
        if changes:
            errors.append("worktree contains staged, unstaged or untracked changes")
        try:
            git(repo, "diff", "--check", f"{baseline_ref}...HEAD")
        except CheckError:
            errors.append("committed diff failed whitespace/conflict-marker checks")
        if verify_remote:
            report["scope"] = "remote"
            latest = remote_sha(repo, upstream, target_branch)
            report["upstream_remote_sha"] = latest
            if latest != baseline:
                errors.append("target baseline reference is stale; fetch and reassess")
            published = remote_sha(repo, origin, source_branch,
                                   allow_missing=phase == "pre-push", push=True)
            report["source_remote_sha"] = published
            if phase == "post-push" and published != head:
                errors.append("source remote branch does not equal local HEAD")
        else:
            report["warnings"].append(
                "local refs only; upstream freshness and publication are unverified",
            )
            if phase == "post-push":
                errors.append("post-push checks require --verify-remote")
    except (CheckError, ValueError) as exc:
        errors.append(str(exc))
    report["checks_passed"] = not errors
    report["remote_verified"] = verify_remote and not errors
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--target-branch", required=True)
    parser.add_argument("--source-branch")
    parser.add_argument("--upstream-remote", default="upstream")
    parser.add_argument("--source-remote", default="origin")
    parser.add_argument("--phase", choices=("pre-push", "post-push"), default="pre-push")
    parser.add_argument("--verify-remote", action="store_true")
    parser.add_argument("--expected-commits", type=int, default=1)
    args = parser.parse_args()
    report = inspect(args.repo, args.target_branch, args.source_branch,
                     args.upstream_remote, args.source_remote,
                     args.phase, args.verify_remote, args.expected_commits)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
