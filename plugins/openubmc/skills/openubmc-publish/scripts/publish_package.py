#!/usr/bin/env python3
"""Publish one exact Conan binary revision and verify the same remote identity."""

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
from pathlib import Path
import re
import subprocess
import tempfile


EXACT_REF = re.compile(
    r"(?P<recipe>[A-Za-z0-9_][A-Za-z0-9_.+~-]*/[A-Za-z0-9_][A-Za-z0-9_.+~-]*"
    r"(?:@[A-Za-z0-9_][A-Za-z0-9_.+-]*/[A-Za-z0-9_][A-Za-z0-9_.+-]*)?)"
    r"#(?P<rrev>[0-9a-f]{32}|[0-9a-f]{64})"
    r":(?P<package>[0-9a-f]{40}|[0-9a-f]{64})#(?P<prev>[0-9a-f]{32}|[0-9a-f]{64})"
)


def parse_ref(reference):
    match = EXACT_REF.fullmatch(reference)
    if not match:
        raise ValueError("require recipe#recipe_revision:package_id#package_revision; patterns and latest are not allowed")
    return match.groupdict()


def require_identity(listing, identity, namespace):
    try:
        packages = listing[namespace][identity["recipe"]]["revisions"][identity["rrev"]]["packages"]
        revisions = packages[identity["package"]]["revisions"]
        if identity["prev"] not in revisions:
            raise KeyError(identity["prev"])
    except (KeyError, TypeError):
        raise ValueError("the exact binary revision is absent from the Conan listing") from None


class ConanFailure(ValueError):
    """Only the classification and private file path cross the Agent boundary."""

    def __init__(self, code, step, diagnostic_path):
        self.code, self.step, self.diagnostic_path = code, step, diagnostic_path
        super().__init__(f"conan {step} failed: {code}")

    def to_public(self):
        return {"status": "failed", "reason": str(self), "code": self.code,
                "step": self.step, "diagnostic_path": self.diagnostic_path,
                "diagnostics_saved": self.diagnostic_path is not None}


def classify_failure(output):
    text = output.casefold()
    if re.search(r"remote[^\n]*(?:not found|doesn't exist|does not exist|can't be found)", text):
        return "remote_not_found"
    # Trust and connectivity failures must not be reported as bad credentials.
    for code, markers in (
        ("tls_error", ("certificate verify failed", "sslerror", "ssl certificate", "tls error")),
        ("remote_not_found", ("no remote",)),
        ("permission_denied", ("403", "forbidden", "permission denied")),
        ("authentication_rejected", ("401", "unauthorized", "authentication failed", "wrong user or password")),
        ("network_error", ("connection refused", "connectionerror", "could not resolve", "name resolution", "connection timed out")),
    ):
        if any(marker in text for marker in markers):
            return code
    return "command_failed"


def save_diagnostics(argv, *, code, stdout="", stderr="", returncode=None, diagnostics_dir=None):
    root = Path(diagnostics_dir) if diagnostics_dir else Path(
        os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))
    ) / "openubmc/conan-publish"
    try:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        # A fresh private directory also isolates files from a shared parent.
        directory = Path(tempfile.mkdtemp(prefix="attempt-", dir=root))
        path = directory / "diagnostics.json"
        def bounded(value):
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            return str(value or "")[:1024 * 1024]
        data = {"code": code, "argv": ["conan", *argv], "returncode": returncode,
                "stdout": bounded(stdout), "stderr": bounded(stderr)}
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False)
            stream.write("\n")
        return str(path.absolute())
    except OSError:
        return None


def run_conan(argv, *, diagnostics_dir=None):
    try:
        completed = subprocess.run(["conan", *argv], capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as error:
        code = "timeout" if isinstance(error, subprocess.TimeoutExpired) else "conan_unavailable"
        path = save_diagnostics(argv, code=code, stdout=getattr(error, "stdout", ""),
                                stderr=getattr(error, "stderr", ""), diagnostics_dir=diagnostics_dir)
        raise ConanFailure(code, argv[0], path) from None
    if completed.returncode:
        code = classify_failure(completed.stderr + "\n" + completed.stdout)
    else:
        try:
            return json.loads(completed.stdout)
        except (ValueError, TypeError):
            code = "invalid_response"
    path = save_diagnostics(argv, code=code, stdout=completed.stdout, stderr=completed.stderr,
                            returncode=completed.returncode, diagnostics_dir=diagnostics_dir)
    raise ConanFailure(code, argv[0], path)


def publish(reference, remote, *, upload=False, runner=run_conan):
    identity = parse_ref(reference)
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", remote):
        raise ValueError("require one existing Conan remote alias")
    local = runner(["list", reference, "-c", "--format=json"])
    require_identity(local, identity, "Local Cache")
    command = ["upload", reference, "-r", remote, "--check", "--confirm", "--format=json"]
    if not upload:
        return {"status": "prepared", "reference": reference, "remote": remote, "argv": ["conan", *command]}
    runner(command)
    remote_listing = runner(["list", reference, "-r", remote, "--format=json"])
    require_identity(remote_listing, identity, remote)
    return {"status": "published", "reference": reference, "remote": remote, "remote_verified": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--remote", required=True)
    parser.add_argument("--upload", action="store_true", help="execute the authorized upload after local verification")
    parser.add_argument("--diagnostics-dir", type=Path, help="parent directory for private failure diagnostics")
    args = parser.parse_args()
    try:
        result = publish(args.ref, args.remote, upload=args.upload,
                         runner=lambda argv: run_conan(argv, diagnostics_dir=args.diagnostics_dir))
    except ConanFailure as error:
        print(json.dumps(error.to_public()))
        return 2
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"status": "failed", "reason": str(error)}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
