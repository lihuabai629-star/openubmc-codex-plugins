#!/usr/bin/env python3
"""Identify submission platforms from local remotes without network or mutations."""

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit, unquote

from check_submission import CheckError, remote_url


def endpoint(value):
    """Return only a host and project path; never reflect userinfo or queries."""
    try:
        if "://" in value:
            parsed = urlsplit(value)
            if parsed.scheme not in {"https", "http", "ssh"}:
                raise ValueError
            host, path = parsed.hostname, parsed.path
        else:
            match = re.fullmatch(r"(?:[^/@:]+@)?([^/:]+):(.+)", value)
            if not match:
                raise ValueError
            host, path = match.groups()
        path = unquote(path).strip("/").removesuffix(".git")
        if (not host or not re.fullmatch(r"[A-Za-z0-9.:-]+", host)
                or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", path)
                or any(part in {".", ".."} for part in path.split("/"))):
            raise ValueError
        return {"host": host.lower(), "project": path}
    except (ValueError, TypeError):
        raise CheckError("unsupported or invalid remote endpoint") from None


def route(repo, source="origin", upstream="upstream", gitlab_hosts=()):
    report = {"status": "needs_input", "platform": None, "errors": []}
    try:
        if source == upstream:
            raise CheckError("source and upstream remote roles must be distinct")
        selected = endpoint(remote_url(repo, source, push=True))
        target = endpoint(remote_url(repo, upstream))
        report.update({"source_push": selected, "upstream_fetch": target})
        if selected == target:
            raise CheckError("source must be a personal fork, not the upstream project")
        if selected["host"] != target["host"]:
            raise CheckError("source and target hosts differ; verify platform and fork relationship")
        host = target["host"]
        if host == "gitcode.com":
            platform = "gitcode"
        elif host in {value.lower() for value in gitlab_hosts}:
            platform = "gitlab"
        else:
            raise CheckError("unknown platform; supply a verified GitLab host or select matching remotes")
        report.update({"status": "selected", "platform": platform,
                       "reference": "references/" + (
                           "community-gitcode.md" if platform == "gitcode" else "internal-gitlab.md"),
                       "remote_identity_verified": False})
    except CheckError as exc:
        report["errors"].append(str(exc))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--source-remote", default="origin")
    parser.add_argument("--upstream-remote", default="upstream")
    parser.add_argument("--gitlab-host", action="append", default=[])
    args = parser.parse_args()
    result = route(args.repo, args.source_remote, args.upstream_remote, args.gitlab_host)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "selected" else 1


if __name__ == "__main__":
    raise SystemExit(main())
