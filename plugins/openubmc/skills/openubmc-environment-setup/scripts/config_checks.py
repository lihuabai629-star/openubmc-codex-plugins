#!/usr/bin/env python3
"""Bounded local checks; credential values travel over private process stdin only."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)

import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]


def run_owned(argv, *, payload=None, env=None, timeout=25):
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(
            json.dumps(payload).encode() if payload is not None else None,
            timeout=timeout,
        )
        return process.returncode, stdout, stderr
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
        raise


class BoundedConfigurationChecker:
    def __call__(self, kind, config, target, *, revision=None, source=None):
        payload = {
            "kind": kind,
            "config": config,
            "target": target,
            "revision": revision,
            "source": str(source),
            "python_paths": sys.path,
        }
        try:
            code, out, _err = run_owned(
                [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--worker"],
                payload=payload,
            )
            return (
                json.loads(out)
                if code == 0
                else {"verified": False, "code": "connection_failed"}
            )
        except subprocess.TimeoutExpired:
            return {"verified": False, "code": "timeout"}
        except FileNotFoundError:
            return {"verified": False, "code": "check_unavailable"}


def check_target(config, target):
    from openubmc_target_runtime import (
        CredentialResolver,
        CredentialSelector,
        TargetSpec,
        OpenUBMCTaskRun,
    )
    from openubmc_target_runtime.credentials import CredentialConfigurationError

    sys.path.insert(0, str(ROOT / "openubmc-debug" / "scripts"))
    sys.path.insert(0, str(ROOT / "openubmc-upgrade"))
    task_id = "configuration-check-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="openubmc-config-check-") as raw:
        path = Path(raw) / "credentials.json"
        with open(
            path, "w", opener=lambda name, flags: os.open(name, flags, 0o600)
        ) as stream:
            json.dump(config, stream)
        selected = (
            CredentialResolver(config_path=path, environ={})
            .resolve_local(
                task_id=task_id,
                host=target["ip"],
                purpose=target["purpose"],
                transport=target["transport"],
            )
            .credentials
        )
    if target["transport"] == "ssh":
        from _remote_common import OpenSshControlMasterTransport

        selector = CredentialSelector.for_ssh(
            user=selected.user,
            user_env="",
            password_env="",
            identity_file=selected.identity_file,
            environ={},
        )
        resolver = CredentialResolver(ssh_loader=lambda _selector: selected)
        transport = OpenSshControlMasterTransport(
            host_key_policy="strict", known_hosts_file="", allow_insecure_host_key=False
        )
    else:
        from openubmc_upgrade.runtime_backend import RedfishUpgradeTransport

        selector = CredentialSelector.for_redfish(
            user=selected.user, user_env="", password_env="", environ={}
        )
        resolver = CredentialResolver(redfish_loader=lambda _selector: selected)
        transport = RedfishUpgradeTransport(verify_tls=True, timeout=8)
    spec = TargetSpec(
        host=target["ip"], credential_selector_fingerprint=selector.fingerprint
    )
    task = OpenUBMCTaskRun(task_id=task_id, credential_resolver=resolver)
    try:
        if target["transport"] == "ssh":
            lane = task.ssh_lane(
                target=spec,
                credential_selector=selector,
                lease_name="configuration-check",
                transport=transport,
            )
            result = lane.run_ssh(
                target["ip"],
                selected.user,
                selected.password,
                "true",
                8,
                identity_file=selected.identity_file,
                replay_safe=False,
                stdout_limit_bytes=4096,
                stderr_limit_bytes=4096,
            )
            status = getattr(result, "returncode", getattr(result, "exit_code", None))
            if status != 0:
                detail = str(getattr(result, "stderr", "")).lower()
                if "permission denied" in detail:
                    return {"verified": False, "code": "authentication_failed"}
                if "host key" in detail:
                    return {"verified": False, "code": "host_identity_failed"}
                return {"verified": False, "code": "network_error"}
        else:
            lane = task.redfish_lane(
                target=spec,
                credential_selector=selector,
                lease_name="configuration-check",
                transport=transport,
            )
            lane.request(
                "configuration-check",
                replay_safe=False,
                callback=lambda session: session.request_json(
                    "GET", "/redfish/v1/Managers"
                ),
            )
        return {"verified": True, "code": "connected"}
    finally:
        task.close()


def check_conan(config, target):
    remote = target["remote"]
    record = config.get("credentials", {}).get(remote, {})
    if not record.get("user") or not record.get("password"):
        return {"verified": False, "code": "credentials_missing"}
    env = os.environ.copy()
    suffix = remote.upper().replace("-", "_")
    env["CONAN_LOGIN_USERNAME_" + suffix] = record["user"]
    env["CONAN_PASSWORD_" + suffix] = record["password"]
    code, out, err = run_owned(
        [
            "conan",
            "remote",
            "auth",
            remote,
            "--force",
            "-cc",
            "core:non_interactive=True",
        ],
        env=env,
        timeout=15,
    )
    failed = code != 0 or re.search(
        rb"(?i)(?:\berror:|wrong user|wrong password|authentication error|interactive mode disabled)",
        out + b"\n" + err,
    )
    if not failed:
        return {"verified": True, "code": "connected"}
    detail = (out + b"\n" + err).decode(errors="replace").lower()
    if any(
        text in detail
        for text in (
            "certificate verify failed",
            "sslerror",
            "certificate_verify_failed",
        )
    ):
        reason = "tls_error"
    elif any(
        text in detail
        for text in ("timed out", "timeouterror", "readtimeout", "connecttimeout")
    ):
        reason = "timeout"
    elif any(
        text in detail
        for text in (
            "connection refused",
            "failed to establish a new connection",
            "name or service not known",
            "temporary failure in name resolution",
            "connection reset",
            "network is unreachable",
            "proxyerror",
        )
    ):
        reason = "network_error"
    elif any(
        text in detail
        for text in (
            "wrong user",
            "wrong password",
            "authentication error",
            "401: unauthorized",
        )
    ):
        reason = "authentication_failed"
    elif "forbidden" in detail or "permission denied" in detail:
        reason = "permission_denied"
    elif "remote" in detail and any(
        text in detail
        for text in ("not found", "doesn't exist", "not defined", "no remote")
    ):
        reason = "remote_missing"
    else:
        reason = "connection_failed"
    return {"verified": False, "code": reason}


def check_kb(config, revision, source):
    # Load the actual source so token ownership and relative cache paths match the live MCP.
    root = ROOT.parent if ROOT.name == "skills" else ROOT
    js = """
import { pathToFileURL } from 'node:url';
import { readFileSync } from 'node:fs';
const input=JSON.parse(readFileSync(0,'utf8'));
const base=pathToFileURL(input.root+'/openubmc-kb-mcp/src/');
const { loadConfig }=await import(new URL('config.js',base));
const { OneIdClient }=await import(new URL('auth/oneid-client.js',base));
const { LightRagClient }=await import(new URL('lightrag-client.js',base));
let result;
try {
  const config=await loadConfig(input.source,{allowMissingCredentials:true});
  if (config.configurationRevision !== input.revision) throw new Error('configuration changed');
  const value=await new LightRagClient({...config,requestTimeoutMs:12000},new OneIdClient(config)).status();
  result={verified:value.configured===true,code:value.configured?'connected':'credentials_missing'};
} catch(error) {
  const codes={KB_CREDENTIALS_MISSING:'credentials_missing',KB_INTERACTION_REQUIRED:'interaction_required',
    KB_AUTHENTICATION_FAILED:'authentication_failed',KB_TIMEOUT:'timeout'};
  const cause=error?.cause?.code || error.code;
  const network=['ECONNREFUSED','ECONNRESET','ENETUNREACH','ENOTFOUND','EAI_AGAIN','UND_ERR_SOCKET'].includes(cause);
  const tls=['DEPTH_ZERO_SELF_SIGNED_CERT','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_VERIFY_LEAF_SIGNATURE','CERT_HAS_EXPIRED'].includes(cause);
  result={verified:false,code:codes[error.code] || ({401:'authentication_failed',403:'permission_denied'}[error.status]) || (tls?'tls_error':network?'network_error':'connection_failed')};
}
process.stdout.write(JSON.stringify(result));
"""
    code, out, _err = run_owned(
        ["node", "--input-type=module", "-e", js],
        payload={"root": str(root), "source": source, "revision": revision},
        timeout=15,
    )
    return (
        json.loads(out)
        if code == 0
        else {"verified": False, "code": "check_unavailable"}
    )


def worker():
    data = json.load(sys.stdin)
    sys.path[:0] = data["python_paths"]
    try:
        if data["kind"] == "targets":
            result = check_target(data["config"], data["target"])
        elif data["kind"] == "conan":
            result = check_conan(data["config"], data["target"])
        else:
            result = check_kb(data["config"], data["revision"], data["source"])
    except Exception as error:
        import ssl

        causes = []
        current = error
        while (
            isinstance(current, BaseException)
            and current not in causes
            and len(causes) < 12
        ):
            causes.append(current)
            current = (
                getattr(current, "reason", None)
                or current.__cause__
                or current.__context__
            )
        code = "connection_failed"
        if getattr(error, "code", None) == "credentials_missing":
            code = "credentials_missing"
        elif getattr(error, "status", None) == 401:
            code = "authentication_failed"
        elif getattr(error, "status", None) == 403:
            code = "permission_denied"
        elif any(
            isinstance(cause, (TimeoutError, subprocess.TimeoutExpired))
            for cause in causes
        ):
            code = "timeout"
        elif isinstance(error, FileNotFoundError):
            code = "check_unavailable"
        elif any(isinstance(cause, ssl.SSLError) for cause in causes):
            code = "tls_error"
        elif hasattr(error, "completed"):
            detail = str(getattr(error.completed, "stderr", "")).lower()
            code = (
                "timeout"
                if getattr(error.completed, "timed_out", False)
                or error.completed.returncode == 124
                else "check_unavailable"
                if getattr(error.completed, "ssh_client_missing", False)
                else "authentication_failed"
                if "permission denied" in detail
                else "host_identity_failed"
                if "host key" in detail
                else "network_error"
            )
        elif isinstance(error, (ConnectionError, OSError)):
            code = "network_error"
        result = {"verified": False, "code": code}
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    worker()
