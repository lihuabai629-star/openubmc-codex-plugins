"""Public Target Runtime backend for Log Analyzer bundle collection."""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Mapping
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from typing import Callable
import uuid


_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def _load_script_module(module_name: str, filename: str):
    """Load a bundled CLI module without occupying a generic module name."""

    cached = sys.modules.get(module_name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(module_name, _SCRIPTS / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load Log Analyzer module: {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


_runtime_distribution = _load_script_module(
    "_openubmc_log_analyzer_runtime_distribution",
    "_runtime_distribution.py",
)
pull_bundle = _load_script_module(
    "_openubmc_log_analyzer_pull_bundle",
    "pull_bundle.py",
)
read_runtime_api_version = _runtime_distribution.read_runtime_api_version
runtime_content_digest = _runtime_distribution.runtime_content_digest


TARGET_RUNTIME_API_VERSION = "openubmc.target-runtime.v1"
PACKAGE_MARKER = ".openubmc-log-analyzer-package.json"
_RUNTIME_CACHE: dict[str, object] = {}
LOG_BUNDLE_KIND = "openubmc-log-bundle"
LOG_INDEX_KIND = "openubmc-log-index"
LOG_QUERY_RAW_KIND = "openubmc-log-query-raw"
LOG_QUERY_KIND = "openubmc-log-query"
LOG_REPORT_RAW_KIND = "openubmc-log-report-raw"
LOG_REPORT_KIND = "openubmc-log-report"
MAX_INDEX_ENTRIES = 4096
MAX_QUERY_BYTES = 64 * 1024
MAX_REPORT_BYTES = 128 * 1024


def _runtime_failure(reason: str) -> SystemExit:
    return SystemExit(
        "Target Runtime v1 validation failed before remote execution: "
        f"{reason}; repair or reinstall the Runtime/MCP environment"
    )


def _import_runtime(package_root: Path, digest: str):
    key = f"{package_root.resolve()}|{digest}"
    cached = _RUNTIME_CACHE.get(key)
    if cached is not None:
        return cached
    module_name = "_openubmc_log_runtime_" + digest.rsplit(":", 1)[-1][:16]
    spec = importlib.util.spec_from_file_location(
        module_name,
        package_root / "__init__.py",
        submodule_search_locations=[str(package_root)],
    )
    if spec is None or spec.loader is None:
        raise _runtime_failure(f"cannot import Runtime package from {package_root}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        for loaded in tuple(sys.modules):
            if loaded == module_name or loaded.startswith(module_name + "."):
                sys.modules.pop(loaded, None)
        raise
    _RUNTIME_CACHE[key] = module
    return module


def _validated_runtime(
    package_root: Path,
    *,
    expected_api: str,
    expected_digest: str | None,
):
    actual_api = read_runtime_api_version(package_root)
    if actual_api != expected_api:
        raise _runtime_failure(
            f"Runtime API mismatch: expected {expected_api}, found {actual_api}"
        )
    actual_digest = runtime_content_digest(package_root)
    if expected_digest is not None and actual_digest != expected_digest:
        raise _runtime_failure(
            "Runtime content digest mismatch: "
            f"expected {expected_digest}, found {actual_digest}"
        )
    return _import_runtime(package_root, actual_digest)


def _load_runtime_module():
    skill_root = Path(__file__).resolve().parents[1]
    marker_path = skill_root / PACKAGE_MARKER
    if marker_path.is_file():
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            contract = marker["target_runtime"]
            vendor_path = Path(contract["vendorPath"])
            expected_api = str(contract["apiVersion"])
            expected_digest = str(contract["contentDigest"])
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise _runtime_failure("package marker is unavailable or invalid") from exc
        if (
            vendor_path.is_absolute()
            or vendor_path.as_posix() != str(contract["vendorPath"])
            or any(part in {"", ".", ".."} for part in vendor_path.parts)
        ):
            raise _runtime_failure("package vendorPath must stay inside the Skill root")
        package_root = (skill_root / vendor_path).resolve()
        if skill_root.resolve() not in package_root.parents:
            raise _runtime_failure("package vendorPath escapes the Skill root")
        return _validated_runtime(
            package_root,
            expected_api=expected_api,
            expected_digest=expected_digest,
        )

    spec = importlib.util.find_spec("openubmc_target_runtime")
    if spec is not None and spec.origin:
        return _validated_runtime(
            Path(spec.origin).resolve().parent,
            expected_api=TARGET_RUNTIME_API_VERSION,
            expected_digest=None,
        )
    canonical = (
        Path(__file__).resolve().parents[2]
        / "openubmc-target-runtime"
        / "openubmc_target_runtime"
    )
    if (canonical / "__init__.py").is_file():
        return _validated_runtime(
            canonical,
            expected_api=TARGET_RUNTIME_API_VERSION,
            expected_digest=None,
        )
    raise _runtime_failure("no installed, canonical, or vendored Runtime is available")


class LogBundleStages:
    """Local content pipeline behind four ArtifactRef-based stage interfaces."""

    def __init__(self, artifact_store: object) -> None:
        required = ("put", "redact", "resolve", "reference", "find")
        missing = [name for name in required if not callable(getattr(artifact_store, name, None))]
        if missing:
            raise TypeError(
                "Log Bundle stages require an ArtifactStore with: "
                + ", ".join(missing)
            )
        self.artifact_store = artifact_store

    def _reference(self, value: object):
        if not isinstance(value, Mapping) and not hasattr(value, "to_public_dict"):
            raise TypeError("artifact_ref must be an object")
        return self.artifact_store.reference(value)

    @staticmethod
    def _write(path: Path, body: bytes) -> None:
        path.write_bytes(body)

    @staticmethod
    def _json_bytes(value: object) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @staticmethod
    def _bounded_analysis(value: Mapping[str, object]) -> dict[str, object]:
        bounded = json.loads(json.dumps(dict(value)))
        while len(LogBundleStages._json_bytes(bounded)) > MAX_QUERY_BYTES:
            selected = bounded.get("selected_logs", [])
            if not isinstance(selected, list) or not selected:
                raise ValueError("Log Bundle query result exceeds its byte budget")
            candidate = next(
                (
                    item
                    for item in reversed(selected)
                    if isinstance(item, dict)
                    and isinstance(item.get("evidence_lines"), list)
                    and item["evidence_lines"]
                ),
                None,
            )
            if candidate is not None:
                candidate["evidence_lines"].pop()
                candidate["evidence_truncated"] = True
                continue
            selected.pop()
            bounded["selected_logs_truncated"] = True
        return bounded

    def collect(
        self,
        bundle_path: Path,
        *,
        target: str,
        run_id: str,
        operation_id: str,
        transport: str,
        remote_bundle_path: str,
        generation_ran: bool,
    ) -> dict[str, object]:
        existing = self.artifact_store.find(
            kind=LOG_BUNDLE_KIND,
            target=target,
            run_id=run_id,
            created_by_effect=operation_id,
        )
        reference = existing or self.artifact_store.put(
            Path(bundle_path),
            kind=LOG_BUNDLE_KIND,
            provenance=f"log-bundle-collect:{transport}",
            retention_hint="run-lifetime",
            target=target,
            run_id=run_id,
            created_by_effect=operation_id,
        )
        return {
            "stage": "collect",
            "artifact_ref": reference.to_public_dict(),
            "remote_bundle_path": remote_bundle_path,
            "generation_ran": bool(generation_ran),
            "transport": transport,
        }

    def index(
        self,
        artifact_ref: object,
        *,
        target: str,
        run_id: str,
        operation_id: str,
    ) -> dict[str, object]:
        reference = self._reference(artifact_ref)
        bundle_path = self.artifact_store.resolve(
            reference,
            expected_kinds=(LOG_BUNDLE_KIND,),
            expected_target=target,
            expected_run_id=run_id,
        )
        existing = self.artifact_store.find(
            kind=LOG_INDEX_KIND,
            target=target,
            run_id=run_id,
            created_by_effect=operation_id,
        )
        if existing is not None:
            return {"stage": "index", "artifact_ref": existing.to_public_dict()}
        with tempfile.TemporaryDirectory(prefix="openubmc-log-index-") as raw:
            extraction = pull_bundle.extract_archive(bundle_path, Path(raw))
            indexed_paths = sorted(
                path
                for path in extraction.bundle_root.rglob("*")
                if path.is_file()
            )
            entries = {
                path.relative_to(extraction.bundle_root).as_posix(): {
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "size": path.stat().st_size,
                }
                for path in indexed_paths[:MAX_INDEX_ENTRIES]
            }
        body = self._json_bytes(
            {
                "schema": "openubmc-log-analyzer/index-v1",
                "source_artifact_ref": reference.to_public_dict(),
                "entries": entries,
                "entry_count": len(indexed_paths),
                "entries_truncated": len(indexed_paths) > MAX_INDEX_ENTRIES,
            }
        )
        with tempfile.TemporaryDirectory(prefix="openubmc-log-index-body-") as raw:
            path = Path(raw) / "index.json"
            self._write(path, body)
            indexed = self.artifact_store.put(
                path,
                kind=LOG_INDEX_KIND,
                provenance="log-bundle-index",
                retention_hint="run-lifetime",
                target=target,
                run_id=run_id,
                created_by_effect=operation_id,
            )
        return {
            "stage": "index",
            "artifact_ref": indexed.to_public_dict(),
            "entry_count": len(indexed_paths),
            "entries_truncated": len(indexed_paths) > MAX_INDEX_ENTRIES,
        }

    def query(
        self,
        artifact_ref: object,
        *,
        target: str,
        run_id: str,
        operation_id: str,
        problem: str,
        max_files: int = pull_bundle.DEFAULT_ANALYSIS_MAX_FILES,
        max_lines: int = pull_bundle.DEFAULT_ANALYSIS_MAX_LINES,
        since: object = None,
        until: object = None,
    ) -> dict[str, object]:
        if not str(problem).strip():
            raise ValueError("Log Bundle query problem is required")
        if not 1 <= int(max_files) <= 32 or not 1 <= int(max_lines) <= 256:
            raise ValueError("Log Bundle query limits are out of range")
        reference = self._reference(artifact_ref)
        index_path = self.artifact_store.resolve(
            reference,
            expected_kinds=(LOG_INDEX_KIND,),
            expected_target=target,
            expected_run_id=run_id,
        )
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("Log Bundle index is unreadable") from exc
        source_raw = index.get("source_artifact_ref") if isinstance(index, Mapping) else None
        source = self._reference(source_raw)
        bundle_path = self.artifact_store.resolve(
            source,
            expected_kinds=(LOG_BUNDLE_KIND,),
            expected_target=target,
            expected_run_id=run_id,
        )
        existing = self.artifact_store.find(
            kind=LOG_QUERY_KIND,
            target=target,
            run_id=run_id,
            created_by_effect=operation_id,
        )
        if existing is not None:
            return {"stage": "query", "artifact_ref": existing.to_public_dict()}
        with tempfile.TemporaryDirectory(prefix="openubmc-log-query-") as raw:
            extraction = pull_bundle.extract_archive(bundle_path, Path(raw))
            entries = index.get("entries") if isinstance(index, Mapping) else None
            if not isinstance(entries, Mapping):
                raise ValueError("Log Bundle index omits its content manifest")
            indexed_paths: set[str] = set()
            for relative_path, raw_identity in entries.items():
                if not isinstance(relative_path, str) or not isinstance(
                    raw_identity, Mapping
                ):
                    raise ValueError("Log Bundle index contains invalid entries")
                normalized = Path(relative_path)
                if normalized.is_absolute() or any(
                    part in {"", ".", ".."} for part in normalized.parts
                ):
                    raise ValueError("Log Bundle index contains an unsafe path")
                candidate = extraction.bundle_root / normalized
                if not candidate.is_file():
                    raise ValueError("Log Bundle content no longer matches its index")
                body = candidate.read_bytes()
                if (
                    hashlib.sha256(body).hexdigest()
                    != str(raw_identity.get("sha256", ""))
                    or len(body) != raw_identity.get("size")
                ):
                    raise ValueError("Log Bundle content no longer matches its index")
                indexed_paths.add(normalized.as_posix())
            for candidate in extraction.bundle_root.rglob("*"):
                if not candidate.is_file():
                    continue
                relative = candidate.relative_to(extraction.bundle_root).as_posix()
                if relative not in indexed_paths:
                    candidate.unlink()
            analysis = pull_bundle.analyze_bundle(
                extraction.bundle_root,
                str(problem).strip(),
                max_files=int(max_files),
                max_lines=int(max_lines),
                since=since,
                until=until,
            )
        bounded = self._bounded_analysis(analysis)
        with tempfile.TemporaryDirectory(prefix="openubmc-log-query-body-") as raw:
            raw_path = Path(raw) / "query-raw.json"
            self._write(raw_path, self._json_bytes(bounded))
            raw_reference = self.artifact_store.put(
                raw_path,
                kind=LOG_QUERY_RAW_KIND,
                provenance="log-bundle-query",
                retention_hint="temporary",
                target=target,
                run_id=run_id,
                created_by_effect=f"{operation_id}-raw",
            )
            queried = self.artifact_store.redact(
                raw_reference,
                kind=LOG_QUERY_KIND,
                provenance="log-bundle-query-redaction",
                retention_hint="run-lifetime",
                created_by_effect=operation_id,
                max_bytes=MAX_QUERY_BYTES,
            )
        return {
            "stage": "query",
            "artifact_ref": queried.to_public_dict(),
            "summary": str(bounded.get("summary", "")),
        }

    def export(
        self,
        artifact_ref: object,
        *,
        target: str,
        run_id: str,
        operation_id: str,
    ) -> dict[str, object]:
        reference = self._reference(artifact_ref)
        query_path = self.artifact_store.resolve(
            reference,
            expected_kinds=(LOG_QUERY_KIND,),
            expected_target=target,
            expected_run_id=run_id,
            require_redacted=True,
        )
        if query_path.stat().st_size > MAX_QUERY_BYTES:
            raise ValueError("Log Bundle query exceeds the export byte budget")
        existing = self.artifact_store.find(
            kind=LOG_REPORT_KIND,
            target=target,
            run_id=run_id,
            created_by_effect=operation_id,
        )
        if existing is not None:
            return {"stage": "export", "artifact_ref": existing.to_public_dict()}
        query = json.loads(query_path.read_text(encoding="utf-8"))
        summary = str(query.get("summary", "")) if isinstance(query, Mapping) else ""
        report = (
            "# openUBMC Log Bundle Report\n\n"
            + summary
            + "\n\n```json\n"
            + json.dumps(query, ensure_ascii=False, sort_keys=True, indent=2)
            + "\n```\n"
        )
        report_body = report.encode("utf-8")
        if len(report_body) > MAX_REPORT_BYTES:
            raise ValueError("Log Bundle report exceeds its byte budget")
        with tempfile.TemporaryDirectory(prefix="openubmc-log-report-") as raw:
            report_path = Path(raw) / "report.md"
            self._write(report_path, report_body)
            raw_reference = self.artifact_store.put(
                report_path,
                kind=LOG_REPORT_RAW_KIND,
                provenance="log-bundle-export",
                retention_hint="temporary",
                target=target,
                run_id=run_id,
                created_by_effect=f"{operation_id}-raw",
            )
            exported = self.artifact_store.redact(
                raw_reference,
                kind=LOG_REPORT_KIND,
                provenance="log-bundle-export-redaction",
                retention_hint="run-lifetime",
                created_by_effect=operation_id,
                max_bytes=MAX_REPORT_BYTES,
            )
        return {
            "stage": "export",
            "artifact_ref": exported.to_public_dict(),
            "summary": summary,
        }


class PullBundleRedfishTransport:
    """Adapt the existing Redfish protocol behavior to a domain Runtime lane."""

    def __init__(self, args) -> None:
        self.args = args

    def open_session(self, *, target, credentials):
        return pull_bundle.redfish_create_session(
            ip=target.host,
            user=credentials.user,
            password=credentials.password,
            port=target.redfish_port,
            timeout=int(getattr(self.args, "redfish_timeout", 60)),
            proxy_mode=str(getattr(self.args, "redfish_proxy", "auto")),
        )

    @staticmethod
    def request(session, operation: str, **kwargs: object):
        del operation
        callback = kwargs.get("callback")
        if not callable(callback):
            raise TypeError("Redfish Runtime request requires a callback")
        return callback(session)

    @staticmethod
    def is_authentication_failure(error: BaseException) -> bool:
        if not isinstance(error, pull_bundle.BundlePullError):
            return False
        message = error.message.casefold()
        return error.code == "redfish_auth_failed" or any(
            token in message for token in ("http 401", "http 403", "invalid token")
        )

    def close_session(self, session) -> None:
        try:
            pull_bundle.redfish_delete_session(
                session,
                timeout=int(getattr(self.args, "redfish_timeout", 60)),
            )
        except pull_bundle.BundlePullError:
            pass


class LogBundleRuntimeLease:
    """Task-owned Redfish primary and SSH bundle fallback lanes."""

    def __init__(
        self,
        *,
        args,
        task_id: str,
        task_run=None,
        redfish_transport=None,
        ssh_transport=None,
        credential_values: Mapping[str, str] | None = None,
    ) -> None:
        runtime = _load_runtime_module()
        self._runtime = runtime
        self.args = args
        self._closed = False
        file_credentials = dict(credential_values or {})

        def selector_env(
            configured: str,
            *,
            direct_explicit: bool,
            fallback_names: tuple[str, ...],
        ) -> str:
            if configured or direct_explicit:
                return configured
            return next(
                (
                    name
                    for name in fallback_names
                    if name in os.environ or name in file_credentials
                ),
                "",
            )

        redfish_user_explicit = bool(
            getattr(args, "_redfish_user_explicit", False)
        )
        ssh_user_explicit = bool(getattr(args, "_ssh_user_explicit", False))
        self.redfish_selector = runtime.CredentialSelector.for_redfish(
            user=(
                str(getattr(args, "redfish_user", ""))
                if redfish_user_explicit
                else ""
            ),
            user_env=selector_env(
                str(getattr(args, "redfish_user_env", "")),
                direct_explicit=redfish_user_explicit,
                fallback_names=("OPENUBMC_REDFISH_USER", "REDFISH_USERNAME"),
            ),
            password_env=selector_env(
                str(getattr(args, "redfish_password_env", "")),
                direct_explicit=bool(getattr(args, "redfish_password", "")),
                fallback_names=(
                    "OPENUBMC_REDFISH_PASSWORD",
                    "REDFISH_PASSWORD",
                ),
            ),
            environ=os.environ,
        )
        self.ssh_selector = runtime.CredentialSelector.for_ssh(
            user=(
                str(getattr(args, "ssh_user", ""))
                if ssh_user_explicit
                else ""
            ),
            user_env=selector_env(
                str(getattr(args, "ssh_user_env", "")),
                direct_explicit=ssh_user_explicit,
                fallback_names=("OPENUBMC_SSH_USER",),
            ),
            password_env=selector_env(
                str(getattr(args, "ssh_password_env", "")),
                direct_explicit=bool(getattr(args, "ssh_password", "")),
                fallback_names=("OPENUBMC_SSH_PASSWORD",),
            ),
            identity_file=str(getattr(args, "ssh_identity_file", "")),
            environ=os.environ,
        )
        self.target = runtime.TargetSpec.for_credential_selectors(
            host=str(args.ip),
            ssh_port=int(getattr(args, "ssh_port", 22)),
            redfish_port=int(getattr(args, "redfish_port", 443)),
            credential_selectors=(self.redfish_selector, self.ssh_selector),
            policy=runtime.TargetPolicy(ssh_host_key_policy="insecure"),
        )
        self.redfish_target = self.target
        self.ssh_target = self.target

        def resolve_runtime_value(
            *,
            direct_value: str,
            direct_explicit: bool,
            env_name: str,
            fallback_env_names: tuple[str, ...],
            label: str,
            default_value: str = "",
        ) -> str:
            if file_credentials.get("__runtime_selected__") == "1":
                from openubmc_target_runtime.credential_file import selected_credential_value
                if direct_explicit and direct_value:
                    return direct_value
                selected = selected_credential_value(file_credentials, (env_name,) if env_name else fallback_env_names)
                if selected is not None:
                    return selected
            if env_name:
                if env_name in os.environ:
                    return os.environ[env_name]
                if env_name in file_credentials:
                    return file_credentials[env_name]
                raise pull_bundle.BundlePullError(
                    "missing_env",
                    f"{label} 环境变量 {env_name} 未设置",
                )
            if direct_explicit and direct_value:
                return direct_value
            from openubmc_target_runtime.credential_file import selected_credential_value
            selected = selected_credential_value(file_credentials, fallback_env_names)
            if selected is not None:
                return selected
            return direct_value or default_value

        def resolve_runtime_secret(
            *,
            direct_value: str,
            env_name: str,
            fallback_env_names: tuple[str, ...],
            label: str,
            allow_empty: bool = False,
        ) -> str:
            value = resolve_runtime_value(
                direct_value=direct_value,
                direct_explicit=bool(direct_value),
                env_name=env_name,
                fallback_env_names=fallback_env_names,
                label=label,
            )
            if value or allow_empty:
                return value
            raise pull_bundle.BundlePullError(
                "missing_secret",
                f"JSON 模式必须提供 {label}；请显式传参、配置凭据文件或使用环境变量。",
            )

        def load_redfish(_selector):
            user = resolve_runtime_value(
                direct_value=str(getattr(args, "redfish_user", "")),
                direct_explicit=bool(
                    getattr(args, "_redfish_user_explicit", False)
                ),
                env_name=str(getattr(args, "redfish_user_env", "")),
                fallback_env_names=(
                    "OPENUBMC_REDFISH_USER",
                    "REDFISH_USERNAME",
                ),
                label="Redfish 用户名",
                default_value="Administrator",
            )
            password = resolve_runtime_secret(
                direct_value=str(getattr(args, "redfish_password", "")),
                env_name=str(getattr(args, "redfish_password_env", "")),
                fallback_env_names=(
                    "OPENUBMC_REDFISH_PASSWORD",
                    "REDFISH_PASSWORD",
                ),
                label="Redfish 密码",
            )
            return runtime.ResolvedRedfishCredentials(
                user=user,
                password=password,
                port=int(getattr(args, "redfish_port", 443)),
            )

        def load_ssh(_selector):
            identity_file = str(getattr(args, "ssh_identity_file", "")) or file_credentials.get("OPENUBMC_SSH_IDENTITY_FILE", "")
            user = resolve_runtime_value(
                direct_value=str(getattr(args, "ssh_user", "")),
                direct_explicit=bool(
                    getattr(args, "_ssh_user_explicit", False)
                ),
                env_name=str(getattr(args, "ssh_user_env", "")),
                fallback_env_names=("OPENUBMC_SSH_USER",),
                label="SSH 用户名",
                default_value="Administrator",
            )
            password = resolve_runtime_secret(
                direct_value=str(getattr(args, "ssh_password", "")),
                env_name=str(getattr(args, "ssh_password_env", "")),
                fallback_env_names=("OPENUBMC_SSH_PASSWORD",),
                label="SSH 密码",
                allow_empty=bool(identity_file),
            )
            return runtime.ResolvedSshCredentials(
                user=user,
                password=password,
                port=int(getattr(args, "ssh_port", 22)),
                identity_file=identity_file,
            )

        resolver = runtime.CredentialResolver(
            ssh_loader=load_ssh,
            redfish_loader=load_redfish,
        )
        self.task_run = task_run or runtime.OpenUBMCTaskRun(
            task_id=task_id,
            credential_resolver=resolver,
        )
        self._owns_task_run = task_run is None
        self.redfish_transport = redfish_transport or PullBundleRedfishTransport(args)
        self.ssh_transport = ssh_transport or runtime.OpenSshControlMasterTransport(
            host_key_policy="insecure",
        )
        self._redfish_lane_value = None
        self._ssh_lane_value = None

    def _redfish_lane(self):
        if self._redfish_lane_value is None:
            self._redfish_lane_value = self.task_run.redfish_lane(
                target=self.redfish_target,
                credential_selector=self.redfish_selector,
                lease_name="log-analyzer-bundle",
                transport=self.redfish_transport,
            )
        return self._redfish_lane_value

    def _ssh_lane(self):
        if self._ssh_lane_value is None:
            self._ssh_lane_value = self.task_run.ssh_lane(
                target=self.ssh_target,
                credential_selector=self.ssh_selector,
                lease_name="log-analyzer-bundle-fallback",
                transport=self.ssh_transport,
            )
        return self._ssh_lane_value

    @staticmethod
    def _identity_from_manager(runtime, payload: Mapping[str, object]):
        return runtime.TargetIdentity(
            product_id=str(payload.get("Model", "")),
            machine_id=str(payload.get("UUID", payload.get("SerialNumber", ""))),
            firmware_id=str(payload.get("FirmwareVersion", "")),
            reboot_anchor=str(
                payload.get("LastResetTime", payload.get("DateTime", ""))
            ),
        )

    def _manager_payload(self) -> dict[str, object]:
        lane = self._redfish_lane()

        def fetch(session):
            return pull_bundle.redfish_request_json(
                session,
                path=(
                    f"/redfish/v1/Managers/"
                    f"{getattr(self.args, 'redfish_manager_id', '1')}"
                ),
                timeout=int(getattr(self.args, "redfish_timeout", 60)),
                error_code="redfish_manager_fetch_failed",
                failure_message="Failed to fetch Redfish manager resource",
            )

        payload = lane.request(
            "log-analyzer-manager-identity",
            replay_safe=True,
            callback=fetch,
        )
        observation = self.task_run.observe_target_identity(
            self.redfish_target,
            self._identity_from_manager(self._runtime, payload),
        )
        if observation.change in {"reboot", "firmware-change", "replacement"}:
            payload = lane.request(
                "log-analyzer-manager-identity-refresh",
                replay_safe=True,
                callback=fetch,
            )
        return payload

    def _collect_redfish(self, *, local_dir: Path):
        if getattr(self.args, "remote_command", ""):
            raise pull_bundle.BundlePullError(
                "invalid_request",
                "--remote-command is SSH-only; use --transport ssh or remove --remote-command.",
            )
        manager_payload = self._manager_payload()
        return self._redfish_lane().request(
            "log-analyzer-bundle-collect",
            replay_safe=False,
            callback=lambda session: pull_bundle.run_redfish_bundle_flow_with_session(
                self.args,
                ip=str(self.args.ip),
                local_dir=local_dir,
                session=session,
                manager_payload=manager_payload,
            ),
        )

    @staticmethod
    def _require_success(result, *, code: str, message: str):
        if int(result.returncode) != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise pull_bundle.BundlePullError(
                code,
                f"{message}{': ' + detail if detail else ''}",
            )
        return result

    def _collect_ssh(
        self,
        *,
        local_dir: Path,
        search_roots: list[str],
        name_globs: list[str],
    ):
        lane = self._ssh_lane()
        remote_bundle_path = str(getattr(self.args, "remote_path", "")).strip()
        generation_ran = False
        remote_command = str(getattr(self.args, "remote_command", ""))
        if remote_command:
            generation_ran = True
            generated = self._require_success(
                lane.run_channel(
                    pull_bundle.build_remote_shell(remote_command),
                    timeout=float(getattr(self.args, "generate_timeout", 1800)),
                ),
                code="remote_collect_failed",
                message="Failed to generate remote bundle",
            )
            remote_bundle_path = (
                pull_bundle.parse_remote_bundle_path(
                    f"{generated.stdout}\n{generated.stderr}"
                )
                or remote_bundle_path
            )
        if not remote_bundle_path:
            discovered = self._require_success(
                lane.run_channel(
                    pull_bundle.build_discovery_command(search_roots, name_globs),
                    timeout=float(getattr(self.args, "search_timeout", 60)),
                ),
                code="bundle_discovery_failed",
                message="Failed to discover remote bundle",
            )
            remote_bundle_path = pull_bundle.parse_remote_bundle_path(
                discovered.stdout or ""
            )
        if not remote_bundle_path:
            raise pull_bundle.BundlePullError(
                "remote_bundle_not_found",
                "No remote bundle was found. Provide --remote-path or --remote-command, or widen --search-root/--name-glob.",
            )
        local_dir.mkdir(parents=True, exist_ok=True)
        filename = Path(remote_bundle_path).name or f"openubmc-bundle-{uuid.uuid4().hex}.tar.gz"
        local_path = local_dir / filename
        transferred = lane.download_file(
            remote_bundle_path,
            str(local_path),
            timeout=float(getattr(self.args, "download_timeout", 1800)),
        )
        self._require_success(
            transferred,
            code="bundle_download_failed",
            message="Failed to download remote bundle",
        )
        return pull_bundle.BundleStageResult(
            remote_bundle_path=remote_bundle_path,
            local_bundle_path=local_path,
            generation_ran=generation_ran,
            transport="ssh",
        )

    def collect(
        self,
        *,
        local_dir: Path,
        search_roots: list[str],
        name_globs: list[str],
    ):
        transport = str(getattr(self.args, "transport", "auto"))
        if transport == "ssh" or (
            transport == "auto" and bool(getattr(self.args, "remote_command", ""))
        ):
            return self._collect_ssh(
                local_dir=local_dir,
                search_roots=search_roots,
                name_globs=name_globs,
            )
        if transport == "redfish":
            return self._collect_redfish(local_dir=local_dir)
        try:
            return self._collect_redfish(local_dir=local_dir)
        except pull_bundle.BundlePullError as redfish_error:
            try:
                return self._collect_ssh(
                    local_dir=local_dir,
                    search_roots=search_roots,
                    name_globs=name_globs,
                )
            except pull_bundle.BundlePullError as ssh_error:
                raise pull_bundle.BundlePullError(
                    "auto_transport_failed",
                    f"Redfish failed: {redfish_error.message}; SSH failed: {ssh_error.message}",
                ) from ssh_error

    def runtime_status(self) -> dict[str, object]:
        return self.task_run.runtime_status()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._owns_task_run:
            self.task_run.close()

    def __enter__(self) -> "LogBundleRuntimeLease":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def open_log_bundle_runtime_lease(
    *,
    args,
    task_id: str | None = None,
    task_run=None,
    redfish_transport=None,
    ssh_transport=None,
    credential_values: Mapping[str, str] | None = None,
) -> LogBundleRuntimeLease:
    return LogBundleRuntimeLease(
        args=args,
        task_id=task_id or f"one-shot-{uuid.uuid4().hex}",
        task_run=task_run,
        redfish_transport=redfish_transport,
        ssh_transport=ssh_transport,
        credential_values=credential_values,
    )


_MCP_STRING_OPTIONS = {
    "ip": "--ip",
    "transport": "--transport",
    "ssh_user": "--ssh-user",
    "ssh_password": "--ssh-password",
    "ssh_user_env": "--ssh-user-env",
    "ssh_password_env": "--ssh-password-env",
    "ssh_identity_file": "--ssh-identity-file",
    "redfish_user": "--redfish-user",
    "redfish_password": "--redfish-password",
    "redfish_user_env": "--redfish-user-env",
    "redfish_password_env": "--redfish-password-env",
    "redfish_manager_id": "--redfish-manager-id",
    "redfish_proxy": "--redfish-proxy",
    "redfish_action": "--redfish-action",
    "remote_path": "--remote-path",
    "remote_command": "--remote-command",
    "local_dir": "--local-dir",
    "extract_dir": "--extract-dir",
    "problem": "--problem",
    "analysis_since": "--analysis-since",
    "analysis_until": "--analysis-until",
}
_MCP_INTEGER_OPTIONS = {
    "ssh_port": "--ssh-port",
    "redfish_port": "--redfish-port",
    "analysis_max_files": "--analysis-max-files",
    "analysis_max_lines": "--analysis-max-lines",
    "search_timeout": "--search-timeout",
    "generate_timeout": "--generate-timeout",
    "download_timeout": "--download-timeout",
    "redfish_timeout": "--redfish-timeout",
    "redfish_task_timeout": "--redfish-task-timeout",
    "redfish_poll_interval": "--redfish-poll-interval",
}
_MCP_LIST_OPTIONS = {
    "search_roots": "--search-root",
    "name_globs": "--name-glob",
}


def _mcp_parse_args(arguments: Mapping[str, object]):
    known = (
        set(_MCP_STRING_OPTIONS)
        | set(_MCP_INTEGER_OPTIONS)
        | set(_MCP_LIST_OPTIONS)
        | {"extract", "deadline"}
    )
    unknown = set(arguments) - known
    if unknown:
        raise ValueError(
            "unsupported Log Analyzer MCP arguments: "
            + ", ".join(sorted(unknown))
        )
    argv: list[str] = []
    for name, option in _MCP_STRING_OPTIONS.items():
        if name not in arguments:
            continue
        value = arguments[name]
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string")
        argv.extend([option, value])
    for name, option in _MCP_INTEGER_OPTIONS.items():
        if name not in arguments:
            continue
        value = arguments[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError(f"{name} must be an integer")
        if int(value) != value:
            raise ValueError(f"{name} must be an integer")
        argv.extend([option, str(int(value))])
    for name, option in _MCP_LIST_OPTIONS.items():
        if name not in arguments:
            continue
        value = arguments[name]
        if not isinstance(value, list) or not all(
            isinstance(item, str) for item in value
        ):
            raise TypeError(f"{name} must be an array of strings")
        for item in value:
            argv.extend([option, item])
    extract = arguments.get("extract", True)
    if not isinstance(extract, bool):
        raise TypeError("extract must be a boolean")
    if not extract:
        argv.append("--no-extract")
    argv.append("--json")
    parsed = pull_bundle.parse_args(argv)
    parsed._ssh_user_explicit = "ssh_user" in arguments
    parsed._redfish_user_explicit = "redfish_user" in arguments
    if not str(parsed.ip).strip():
        raise ValueError("ip is required")
    return parsed


def _lease_key(args) -> tuple[object, ...]:
    return (
        str(args.ip).strip().lower(),
        str(args.transport),
        int(args.ssh_port),
        str(args.ssh_user),
        str(args.ssh_user_env),
        str(args.ssh_password_env),
        str(args.ssh_password),
        str(args.ssh_identity_file),
        int(args.redfish_port),
        str(args.redfish_user),
        str(args.redfish_user_env),
        str(args.redfish_password_env),
        str(args.redfish_password),
        str(args.redfish_proxy),
        os.environ.get("OPENUBMC_CREDENTIALS_FILE", ""),
        os.environ.get("OPENUBMC_DEBUG_CREDENTIALS_FILE", ""),
    )


class LogBundleMcpTask:
    def __init__(
        self,
        task_id: str,
        *,
        redfish_transport_factory: Callable[[object], object] | None,
        ssh_transport_factory: Callable[[object], object] | None,
        max_cached_leases: int = 32,
    ) -> None:
        if max_cached_leases < 1:
            raise ValueError("max_cached_leases must be positive")
        self.task_id = task_id
        self._redfish_transport_factory = redfish_transport_factory
        self._ssh_transport_factory = ssh_transport_factory
        self.max_cached_leases = int(max_cached_leases)
        self._leases: OrderedDict[
            tuple[object, ...], LogBundleRuntimeLease
        ] = OrderedDict()
        self._lease_evictions = 0
        self._lock = threading.RLock()

    def lease_for(
        self,
        args,
        *,
        credential_values: Mapping[str, str] | None = None,
    ) -> LogBundleRuntimeLease:
        key = _lease_key(args)
        victim = None
        with self._lock:
            lease = self._leases.get(key)
            if lease is not None:
                self._leases.move_to_end(key)
                return lease
            lease = open_log_bundle_runtime_lease(
                args=args,
                task_id=self.task_id,
                redfish_transport=(
                    self._redfish_transport_factory(args)
                    if self._redfish_transport_factory is not None
                    else None
                ),
                ssh_transport=(
                    self._ssh_transport_factory(args)
                    if self._ssh_transport_factory is not None
                    else None
                ),
                credential_values=credential_values,
            )
            if len(self._leases) >= self.max_cached_leases:
                _, victim = self._leases.popitem(last=False)
                self._lease_evictions += 1
            self._leases[key] = lease
        if victim is not None:
            victim.close()
        return lease

    def maintain(self) -> int:
        with self._lock:
            leases = list(self._leases.values())
        return sum(
            lease.task_run.prune_dead_connections()
            for lease in leases
        )

    def status(self) -> dict[str, object]:
        with self._lock:
            leases = list(self._leases.values())
            evictions = self._lease_evictions
        return {
            "task_id": self.task_id,
            "lease_count": len(leases),
            "lease_cache_limit": self.max_cached_leases,
            "lease_evictions": evictions,
            "leases": [lease.runtime_status() for lease in leases],
        }

    def close(self) -> None:
        with self._lock:
            leases = list(self._leases.values())
            self._leases.clear()
        for lease in leases:
            lease.close()


class LogBundleMcpBackend:
    """Compatibility adapter over ArtifactRef-based Log Bundle stages."""

    def __init__(
        self,
        *,
        redfish_transport_factory: Callable[[object], object] | None = None,
        ssh_transport_factory: Callable[[object], object] | None = None,
        max_cached_leases: int = 32,
        artifact_store: object | None = None,
    ) -> None:
        if max_cached_leases < 1:
            raise ValueError("max_cached_leases must be positive")
        self.redfish_transport_factory = redfish_transport_factory
        self.ssh_transport_factory = ssh_transport_factory
        self.max_cached_leases = int(max_cached_leases)
        self.artifact_store = artifact_store
        self.stages = (
            LogBundleStages(self.artifact_store)
            if self.artifact_store is not None
            else None
        )

    def bind_artifact_store(self, artifact_store: object) -> None:
        if self.artifact_store is not None and self.artifact_store is not artifact_store:
            raise ValueError("Log Analyzer is already bound to another ArtifactStore")
        self.artifact_store = artifact_store
        self.stages = LogBundleStages(artifact_store)

    def _stage_module(self) -> LogBundleStages:
        if self.stages is None:
            raise RuntimeError("Log Analyzer ArtifactStore is not bound")
        return self.stages

    def open_task(self, task_id: str) -> LogBundleMcpTask:
        return LogBundleMcpTask(
            task_id,
            redfish_transport_factory=self.redfish_transport_factory,
            ssh_transport_factory=self.ssh_transport_factory,
            max_cached_leases=self.max_cached_leases,
        )

    @staticmethod
    def close_task(task: LogBundleMcpTask) -> None:
        task.close()

    @staticmethod
    def maintain_task(task: LogBundleMcpTask) -> int:
        return task.maintain()

    @staticmethod
    def task_status(task: LogBundleMcpTask) -> dict[str, object]:
        return task.status()

    def log_bundle_collect(self, task, arguments, context) -> dict[str, object]:
        context.raise_if_stopped()
        bounded = dict(arguments)
        credential_values = bounded.pop("_credential_values", None)
        native_collect = bounded.pop("_context_authoritative", None) is True
        if credential_values is not None and not isinstance(
            credential_values,
            Mapping,
        ):
            raise TypeError("_credential_values must be an internal mapping")
        args = _mcp_parse_args(bounded)
        remaining = max(1, int(context.remaining()))
        for name in (
            "search_timeout",
            "generate_timeout",
            "download_timeout",
            "redfish_timeout",
            "redfish_task_timeout",
        ):
            setattr(args, name, min(int(getattr(args, name)), remaining))
        local_dir = Path(
            args.local_dir
            or f"/tmp/openubmc-log-analyzer/{args.ip}/bundles"
        )
        search_roots = args.search_roots or list(pull_bundle.DEFAULT_SEARCH_ROOTS)
        name_globs = args.name_globs or list(pull_bundle.DEFAULT_NAME_GLOBS)
        stage = task.lease_for(
            args,
            credential_values=(
                dict(credential_values)
                if isinstance(credential_values, Mapping)
                else None
            ),
        ).collect(
            local_dir=local_dir,
            search_roots=search_roots,
            name_globs=name_globs,
        )
        context.raise_if_stopped()
        stages = self._stage_module()
        collected = stages.collect(
            stage.local_bundle_path,
            target=args.ip,
            run_id=task.task_id,
            operation_id=str(context.operation_id),
            transport=stage.transport,
            remote_bundle_path=stage.remote_bundle_path,
            generation_ran=stage.generation_ran,
        )
        indexed = None
        queried = None
        exported = None
        if args.extract and not native_collect:
            indexed = stages.index(
                collected["artifact_ref"],
                target=args.ip,
                run_id=task.task_id,
                operation_id=f"{context.operation_id}-index",
            )
        if args.problem.strip() and not native_collect:
            if indexed is None:
                raise pull_bundle.BundlePullError(
                    "invalid_request",
                    "--problem requires indexing; remove --no-extract.",
                )
            since = pull_bundle.parse_analysis_time_bound(
                args.analysis_since,
                label="--analysis-since",
            )
            until = pull_bundle.parse_analysis_time_bound(
                args.analysis_until,
                label="--analysis-until",
            )
            queried = stages.query(
                indexed["artifact_ref"],
                target=args.ip,
                run_id=task.task_id,
                operation_id=f"{context.operation_id}-query",
                problem=args.problem.strip(),
                max_files=args.analysis_max_files,
                max_lines=args.analysis_max_lines,
                since=since,
                until=until,
            )
            exported = stages.export(
                queried["artifact_ref"],
                target=args.ip,
                run_id=task.task_id,
                operation_id=f"{context.operation_id}-export",
            )
        result: dict[str, object] = {
            "remote_bundle_path": stage.remote_bundle_path,
            "generation_ran": stage.generation_ran,
            "transport": stage.transport,
            "artifact_ref": (
                exported["artifact_ref"]
                if exported is not None
                else queried["artifact_ref"]
                if queried is not None
                else indexed["artifact_ref"]
                if indexed is not None
                else collected["artifact_ref"]
            ),
            "bundle_artifact_ref": collected["artifact_ref"],
            "index_artifact_ref": indexed["artifact_ref"] if indexed else None,
            "query_artifact_ref": queried["artifact_ref"] if queried else None,
            "report_artifact_ref": exported["artifact_ref"] if exported else None,
            "next_step": (
                "review the redacted report ArtifactRef"
                if exported is not None
                else "query the index ArtifactRef with a bounded problem statement"
                if indexed is not None
                else "index the bundle ArtifactRef"
            ),
        }
        return pull_bundle.build_payload(
            ok=True,
            code="ok",
            error="",
            request={
                "ip": args.ip,
                "transport": args.transport,
                "remote_path": args.remote_path,
                "remote_command": bool(args.remote_command),
                "problem": args.problem,
                "extract": args.extract,
            },
            result=result,
        )

    def log_bundle_index(self, task, arguments, context) -> dict[str, object]:
        context.raise_if_stopped()
        bounded = dict(arguments)
        bounded.pop("_artifact_path", None)
        bounded.pop("_artifact_sha256", None)
        return self._stage_module().index(
            bounded.get("artifact_ref"),
            target=str(bounded.get("ip", "")),
            run_id=task.task_id,
            operation_id=str(context.operation_id),
        )

    def log_bundle_query(self, task, arguments, context) -> dict[str, object]:
        context.raise_if_stopped()
        bounded = dict(arguments)
        bounded.pop("_artifact_path", None)
        bounded.pop("_artifact_sha256", None)
        return self._stage_module().query(
            bounded.get("artifact_ref"),
            target=str(bounded.get("ip", "")),
            run_id=task.task_id,
            operation_id=str(context.operation_id),
            problem=str(bounded.get("problem", "")),
            max_files=int(
                bounded.get("max_files", pull_bundle.DEFAULT_ANALYSIS_MAX_FILES)
            ),
            max_lines=int(
                bounded.get("max_lines", pull_bundle.DEFAULT_ANALYSIS_MAX_LINES)
            ),
        )

    def log_bundle_export(self, task, arguments, context) -> dict[str, object]:
        context.raise_if_stopped()
        bounded = dict(arguments)
        bounded.pop("_artifact_path", None)
        bounded.pop("_artifact_sha256", None)
        return self._stage_module().export(
            bounded.get("artifact_ref"),
            target=str(bounded.get("ip", "")),
            run_id=task.task_id,
            operation_id=str(context.operation_id),
        )
