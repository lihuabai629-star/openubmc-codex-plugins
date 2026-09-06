"""Production Redfish backend for typed Upgrade transactions."""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import threading
import time
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest
import uuid

from .operation_state import UpgradeOperationStateStore
from .webui import (
    SameOriginRedirectHandler,
    WebUiHttpError,
    WebUiHttpSession,
    WebUiTransportError,
    classify_tasks as _classify_webui_tasks,
    matching_tasks as _matching_webui_tasks,
    normalized_tasks as _normalized_webui_tasks,
    safe_upload_filename as _safe_upload_filename,
    task_id_from_start as _webui_task_id_from_start,
    task_identity_signature as _webui_task_identity_signature,
    task_signature as _webui_task_signature,
    tasks_added_since as _webui_tasks_added_since,
    upload_multipart_parts as _webui_multipart_parts,
    uploaded_file_path as _webui_uploaded_file_path,
)


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
_ADAPTER_NAME = "_openubmc_upgrade_target_runtime_adapter"
_adapter_spec = importlib.util.spec_from_file_location(
    _ADAPTER_NAME,
    SCRIPTS / "target_runtime_adapter.py",
)
if _adapter_spec is None or _adapter_spec.loader is None:
    raise ImportError("openubmc-upgrade Runtime adapter is unavailable")
_adapter = importlib.util.module_from_spec(_adapter_spec)
sys.modules[_ADAPTER_NAME] = _adapter
_adapter_spec.loader.exec_module(_adapter)
UpgradeArtifact = _adapter.UpgradeArtifact
UpgradeRuntimeAdapter = _adapter.UpgradeRuntimeAdapter
_identity_spec = importlib.util.spec_from_file_location(
    "_openubmc_upgrade_artifact_identity",
    SCRIPTS / "artifact_identity.py",
)
if _identity_spec is None or _identity_spec.loader is None:
    raise ImportError("openubmc-upgrade artifact identity helper is unavailable")
_identity = importlib.util.module_from_spec(_identity_spec)
_identity_spec.loader.exec_module(_identity)
validate_artifact_metadata = _identity.validate_artifact_metadata
from openubmc_target_runtime import (  # noqa: E402
    CredentialResolver,
    CredentialSelector,
    MutationAuthorization,
    MutationEffectsRejected,
    MutationJournalStore,
    MutationOperationConflict,
    MutationVerificationTerminalFailure,
    OpenUBMCTaskRun,
    OperationDeadlineExceeded,
    ResolvedRedfishCredentials,
    TargetIdentity,
    TargetPolicy,
    effect_recovery_mode,
    require_effect_recovery_journal,
    TargetSpec,
    TaskAuthorizationPolicy,
    load_selected_credentials_file,
    mutation_journal_operation_status,
)


@dataclass(frozen=True)
class RedfishResponse:
    status: int
    headers: Mapping[str, str]
    payload: object


def _manager_reset_time(value: object) -> datetime | None:
    reset_time = value.get("last_reset_time") if isinstance(value, Mapping) else None
    if not isinstance(reset_time, str) or not reset_time.strip():
        return None
    normalized = reset_time.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _manager_target_identity(
    value: Mapping[str, object],
    *,
    previous: TargetIdentity | None = None,
) -> TargetIdentity:
    return TargetIdentity(
        product_id=previous.product_id if previous is not None else "",
        machine_id=previous.machine_id if previous is not None else "",
        firmware_id=str(value.get("version", "")),
        reboot_anchor=str(value.get("last_reset_time", "")),
        target_clock=previous.target_clock if previous is not None else "",
    )


class RedfishHttpError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class RedfishTransportError(ConnectionError):
    """Report a same-origin Redfish request that lost its transport response."""

    def __init__(
        self,
        *,
        method: str,
        path: str,
        request_bytes: int,
        timeout: float,
        cause: BaseException,
    ) -> None:
        self.method = method.upper()
        self.path = path
        self.request_bytes = request_bytes
        self.timeout = timeout
        self.cause_type = type(cause).__name__
        super().__init__(
            f"Redfish {self.method} {path} lost its transport response "
            f"(request_bytes={request_bytes}, timeout_seconds={timeout:g}, "
            f"cause={self.cause_type})"
        )


class WebUiStartError(RuntimeError):
    """The artifact upload completed, but task creation was rejected."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class UpgradeActivationReverted(MutationVerificationTerminalFailure):
    """Raised when the uploaded version is no longer the active BMC image."""

    def __init__(self, message: str) -> None:
        super().__init__(message, outcome="activation-fallback")


class RedfishHttpSession:
    """Small same-origin HTTPS client with in-memory Basic authentication."""

    def __init__(
        self,
        *,
        target: TargetSpec,
        credentials: ResolvedRedfishCredentials,
        verify_tls: bool = True,
        timeout: float = 30,
    ) -> None:
        rendered_host = (
            f"[{target.host}]" if ":" in target.host and not target.host.startswith("[")
            else target.host
        )
        self.origin = f"https://{rendered_host}:{target.redfish_port}"
        token = base64.b64encode(
            f"{credentials.user}:{credentials.password}".encode("utf-8")
        ).decode("ascii")
        self.authorization = f"Basic {token}"
        self.timeout = timeout
        self.context = (
            ssl.create_default_context()
            if verify_tls
            else ssl._create_unverified_context()  # noqa: SLF001
        )
        self.opener = urlrequest.build_opener(
            urlrequest.ProxyHandler({}),
            SameOriginRedirectHandler(),
            urlrequest.HTTPSHandler(context=self.context),
        )
        self.webui = WebUiHttpSession(
            origin=self.origin,
            username=credentials.user,
            password=credentials.password,
            verify_tls=verify_tls,
            timeout=timeout,
            redfish_request=self.request_json,
        )

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            parsed = urlparse.urlsplit(path)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin.lower() != self.origin.lower():
                raise ValueError("Redfish response URI changed target origin")
            return path
        if not path.startswith("/"):
            raise ValueError("Redfish URI must be absolute on the selected target")
        return self.origin + path

    def request_json(
        self,
        method: str,
        path: str,
        *,
        payload: object | None = None,
        data: bytes | Iterable[bytes] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> RedfishResponse:
        if payload is not None and data is not None:
            raise ValueError("Redfish request cannot contain JSON and byte data together")
        request_headers = {
            "Authorization": self.authorization,
            "Accept": "application/json",
            **dict(headers or {}),
        }
        body = data
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        request = urlrequest.Request(
            self._url(path),
            data=body,
            headers=request_headers,
            method=method.upper(),
        )
        request_timeout = self.timeout if timeout is None else float(timeout)
        if request_timeout <= 0:
            raise ValueError("Redfish request timeout must be positive")
        try:
            with self.opener.open(
                request,
                timeout=request_timeout,
            ) as response:
                raw = response.read()
                status = int(response.status)
                response_headers = dict(response.headers.items())
        except urlerror.HTTPError as exc:
            raw = exc.read()
            message = raw.decode("utf-8", errors="replace")[-2048:]
            raise RedfishHttpError(exc.code, message or str(exc)) from exc
        except (OSError, TimeoutError, urlerror.URLError) as exc:
            raise RedfishTransportError(
                method=method,
                path=path,
                request_bytes=(
                    len(body)
                    if isinstance(body, (bytes, bytearray))
                    else int(getattr(body, "content_length", 0))
                ),
                timeout=request_timeout,
                cause=exc,
            ) from exc
        parsed: object = {}
        if raw:
            try:
                parsed = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed = {"body_sha256": hashlib.sha256(raw).hexdigest()}
        return RedfishResponse(status, response_headers, parsed)


class RedfishUpgradeTransport:
    def __init__(self, *, verify_tls: bool = True, timeout: float = 30) -> None:
        self.verify_tls = verify_tls
        self.timeout = timeout

    def open_session(self, *, target, credentials) -> RedfishHttpSession:
        return RedfishHttpSession(
            target=target,
            credentials=credentials,
            verify_tls=self.verify_tls,
            timeout=self.timeout,
        )

    @staticmethod
    def request(session, _operation: str, **kwargs: object):
        callback = kwargs.get("callback")
        if not callable(callback):
            raise ValueError("Upgrade Redfish operation requires a typed callback")
        return callback(session)

    @staticmethod
    def is_authentication_failure(error: BaseException) -> bool:
        return isinstance(error, (RedfishHttpError, WebUiHttpError)) and error.status in {
            401,
            403,
        }

    @staticmethod
    def close_session(session) -> None:
        webui = getattr(session, "webui", None)
        close = getattr(webui, "close", None)
        if callable(close):
            close()


def _argument_text(arguments: Mapping[str, object], name: str) -> str:
    value = arguments.get(name, "")
    return str(value).strip() if isinstance(value, (str, int)) else ""


def _argument_bool(
    arguments: Mapping[str, object],
    name: str,
    *,
    default: bool = False,
) -> bool:
    value = arguments.get(name, default)
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a boolean")
    return value


def _upgrade_protocol(arguments: Mapping[str, object]) -> str:
    value = _argument_text(arguments, "upgrade_protocol").lower() or "auto"
    if value not in {"auto", "redfish", "webui"}:
        raise ValueError("upgrade_protocol must be auto, redfish, or webui")
    return value


def _verification_mode(arguments: Mapping[str, object]) -> str:
    value = _argument_text(arguments, "verification_mode").lower() or "auto"
    aliases = {
        "manager": "manager-version",
        "task": "task-completion",
    }
    value = aliases.get(value, value)
    if value not in {"auto", "manager-version", "task-completion"}:
        raise ValueError(
            "verification_mode must be auto, manager-version, or task-completion"
        )
    return value


def _mutation_options(arguments: Mapping[str, object]) -> dict[str, object]:
    return {
        "image_uri": _argument_text(arguments, "image_uri"),
        "upgrade_protocol": _upgrade_protocol(arguments),
        "verification_mode": _verification_mode(arguments),
    }


def _argument_timeout(
    arguments: Mapping[str, object],
    name: str,
    default: float,
) -> float:
    value = arguments.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a positive number")
    timeout = float(value)
    if timeout <= 0:
        raise ValueError(f"{name} must be a positive number")
    return timeout


def _argument_positive_int(
    arguments: Mapping[str, object],
    name: str,
    default: int,
    *,
    maximum: int | None = None,
) -> int:
    value = arguments.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be at most {maximum}")
    return int(value)


def _argument_nonnegative_int(
    arguments: Mapping[str, object],
    name: str,
    default: int,
    *,
    maximum: int | None = None,
) -> int:
    value = arguments.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be at most {maximum}")
    return int(value)


_BATCH_TARGET_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


def _canonical_batch_host(value: object) -> str:
    host = str(value).strip() if isinstance(value, (str, int)) else ""
    if not host:
        return ""
    bracketed = host.startswith("[") and host.endswith("]")
    candidate = host[1:-1] if bracketed else host
    try:
        return ipaddress.ip_address(candidate).compressed.lower()
    except ValueError:
        return candidate.rstrip(".").lower()


@dataclass(frozen=True)
class _ArtifactSnapshot:
    path: Path
    sha256: str
    size: int
    signature: tuple[int, int, int, int, int]


class _ArtifactFileBody:
    """One-shot, length-delimited iterable over a verified artifact snapshot."""

    def __init__(
        self,
        snapshot: _ArtifactSnapshot,
        *,
        prefix: bytes = b"",
        suffix: bytes = b"",
    ) -> None:
        self.snapshot = snapshot
        self.prefix = prefix
        self.suffix = suffix
        self.content_length = len(prefix) + snapshot.size + len(suffix)

    def __len__(self) -> int:
        return self.content_length

    def __iter__(self):
        if self.prefix:
            yield self.prefix
        descriptor = _open_verified_artifact(self.snapshot)
        try:
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                yield block
            _validate_open_artifact(descriptor, self.snapshot)
        finally:
            os.close(descriptor)
        _validate_artifact_path(self.snapshot)
        if self.suffix:
            yield self.suffix


class _SharedArtifactSource:
    """Verify one batch artifact once and stream independent request bodies."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._snapshot: _ArtifactSnapshot | None = None
        self._lock = threading.Lock()

    def snapshot(self) -> _ArtifactSnapshot:
        with self._lock:
            if self._snapshot is None:
                self._snapshot = _snapshot_stable_artifact(self.path)
            return self._snapshot

    def octet_stream(self) -> _ArtifactFileBody:
        return _ArtifactFileBody(self.snapshot())

    def multipart_stream(
        self,
        artifact: UpgradeArtifact,
    ) -> tuple[_ArtifactFileBody, str]:
        prefix, suffix, boundary = _multipart_parts(artifact)
        return (
            _ArtifactFileBody(
                self.snapshot(),
                prefix=prefix,
                suffix=suffix,
            ),
            boundary,
        )

    def webui_multipart_stream(
        self,
        artifact: UpgradeArtifact,
    ) -> tuple[_ArtifactFileBody, str]:
        prefix, suffix, boundary = _webui_multipart_parts(Path(artifact.path).name)
        return (
            _ArtifactFileBody(
                self.snapshot(),
                prefix=prefix,
                suffix=suffix,
            ),
            boundary,
        )


def _default_credential_loader(
    arguments: Mapping[str, object],
) -> dict[str, dict[str, str | int]]:
    cached = arguments.get("_credential_values")
    if cached is None:
        values = load_selected_credentials_file()
    elif isinstance(cached, Mapping):
        values = {
            str(key): str(value)
            for key, value in cached.items()
            if isinstance(key, str) and isinstance(value, str)
        }
    else:
        raise TypeError("_credential_values must be an internal mapping")

    def selected(explicit: str, selector: str, defaults: tuple[str, ...]) -> str:
        value = _argument_text(arguments, explicit)
        if value:
            return value
        selected_env = _argument_text(arguments, selector)
        names = ((selected_env,) if selected_env else ()) + defaults
        for name in names:
            candidate = os.environ.get(name, values.get(name, ""))
            if candidate:
                return candidate
        return ""

    user = selected(
        "redfish_user",
        "redfish_user_env",
        ("OPENUBMC_REDFISH_USER", "REDFISH_USERNAME"),
    )
    password = selected(
        "redfish_password",
        "redfish_password_env",
        ("OPENUBMC_REDFISH_PASSWORD", "REDFISH_PASSWORD"),
    )
    if not user or not password:
        raise ValueError("Upgrade requires Redfish credentials")
    return {
        "redfish": {
            "user": user,
            "password": password,
            "port": int(arguments.get("redfish_port", 443)),
        }
    }


_STABLE_ARTIFACT_FIELDS = (
    "st_dev",
    "st_ino",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _artifact_signature(value) -> tuple[int, int, int, int, int]:
    return tuple(int(getattr(value, name)) for name in _STABLE_ARTIFACT_FIELDS)


def _safe_artifact_path_stat(path: Path):
    try:
        value = os.lstat(path)
    except FileNotFoundError:
        raise ValueError(f"upgrade artifact is unavailable: {path}") from None
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode):
        raise ValueError(f"upgrade artifact must be a regular file: {path}")
    return value


def _open_artifact_descriptor(path: Path) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        return os.open(path, flags)
    except OSError:
        raise ValueError(
            f"upgrade artifact could not be opened safely: {path}"
        ) from None


def _snapshot_stable_artifact(path: Path) -> _ArtifactSnapshot:
    before_path = _safe_artifact_path_stat(path)
    descriptor = _open_artifact_descriptor(path)
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (
            before_path.st_dev,
            before_path.st_ino,
        ):
            raise ValueError(f"upgrade artifact changed while opening: {path}")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = _safe_artifact_path_stat(path)
    if _artifact_signature(before) != _artifact_signature(after):
        raise ValueError(f"upgrade artifact changed while reading: {path}")
    if _artifact_signature(after) != _artifact_signature(after_path):
        raise ValueError(f"upgrade artifact path changed while reading: {path}")
    return _ArtifactSnapshot(
        path=path,
        sha256=digest.hexdigest(),
        size=int(after.st_size),
        signature=_artifact_signature(after),
    )


def _open_verified_artifact(snapshot: _ArtifactSnapshot) -> int:
    before_path = _safe_artifact_path_stat(snapshot.path)
    if _artifact_signature(before_path) != snapshot.signature:
        raise OSError(f"upgrade artifact changed after verification: {snapshot.path}")
    descriptor = _open_artifact_descriptor(snapshot.path)
    opened = os.fstat(descriptor)
    if _artifact_signature(opened) != snapshot.signature:
        os.close(descriptor)
        raise OSError(f"upgrade artifact changed while reopening: {snapshot.path}")
    return descriptor


def _validate_open_artifact(
    descriptor: int,
    snapshot: _ArtifactSnapshot,
) -> None:
    if _artifact_signature(os.fstat(descriptor)) != snapshot.signature:
        raise OSError(f"upgrade artifact changed while streaming: {snapshot.path}")


def _validate_artifact_path(snapshot: _ArtifactSnapshot) -> None:
    try:
        current = _safe_artifact_path_stat(snapshot.path)
    except ValueError as exc:
        raise OSError(str(exc)) from exc
    if _artifact_signature(current) != snapshot.signature:
        raise OSError(f"upgrade artifact path changed while streaming: {snapshot.path}")


def _read_stable_artifact(path: Path) -> tuple[bytes, str]:
    before_path = _safe_artifact_path_stat(path)
    descriptor = _open_artifact_descriptor(path)

    digest = hashlib.sha256()
    blocks: list[bytes] = []
    try:
        before = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (before_path.st_dev, before_path.st_ino):
            raise ValueError(f"upgrade artifact changed while opening: {path}")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            blocks.append(block)
            digest.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = os.lstat(path)
    if _artifact_signature(before) != _artifact_signature(after):
        raise ValueError(f"upgrade artifact changed while reading: {path}")
    if _artifact_signature(after) != _artifact_signature(after_path):
        raise ValueError(f"upgrade artifact path changed while reading: {path}")
    return b"".join(blocks), digest.hexdigest()


def _response_uri(response: RedfishResponse) -> str:
    for key in ("Location", "TaskMonitor"):
        value = response.headers.get(key)
        if isinstance(value, str) and value:
            return value
    if isinstance(response.payload, Mapping):
        for key in ("@odata.id", "TaskMonitor", "TaskUri", "task_uri"):
            value = response.payload.get(key)
            if isinstance(value, str) and value:
                return value
    return ""


def _multipart_body(
    artifact: UpgradeArtifact,
    artifact_bytes: bytes,
) -> tuple[bytes, str]:
    prefix, suffix, boundary = _multipart_parts(artifact)
    return prefix + artifact_bytes + suffix, boundary


def _webui_multipart_body(
    artifact: UpgradeArtifact,
    artifact_bytes: bytes,
) -> tuple[bytes, str]:
    prefix, suffix, boundary = _webui_multipart_parts(Path(artifact.path).name)
    return prefix + artifact_bytes + suffix, boundary


def _multipart_parts(
    artifact: UpgradeArtifact,
) -> tuple[bytes, bytes, str]:
    boundary = "openubmc-target-runtime-" + uuid.uuid4().hex
    filename = _safe_upload_filename(Path(artifact.path).name)
    prefix = (
        f"--{boundary}\r\n"
        "Content-Disposition: form-data; name=\"UpdateParameters\"\r\n"
        "Content-Type: application/json\r\n\r\n"
        "{}\r\n"
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"UpdateFile\"; filename=\"{filename}\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8")
    suffix = f"\r\n--{boundary}--\r\n".encode("ascii")
    return prefix, suffix, boundary


def _legacy_http_push_uses_multipart(
    update_service: Mapping[str, object],
) -> bool:
    """Recognize the legacy OpenUBMC collection URI compatibility shape.

    Some BMCs advertise ``HttpPushUri`` as the FirmwareInventory collection,
    but reject an octet-stream body and only accept the Redfish multipart
    envelope.  This is a deterministic endpoint-shape check, so the first
    mutating request uses the compatible encoding instead of retrying after an
    ambiguous server error.
    """

    multipart_uri = update_service.get("MultipartHttpPushUri")
    http_push_uri = update_service.get("HttpPushUri")
    return (
        not (isinstance(multipart_uri, str) and multipart_uri)
        and isinstance(http_push_uri, str)
        and http_push_uri.rstrip("/").endswith("/FirmwareInventory")
    )


def _simple_update_action(
    update_service: Mapping[str, object],
) -> str:
    actions = update_service.get("Actions")
    simple_action = (
        actions.get("#UpdateService.SimpleUpdate")
        if isinstance(actions, Mapping)
        else None
    )
    target = simple_action.get("target") if isinstance(simple_action, Mapping) else None
    return target if isinstance(target, str) and target else ""


def _legacy_staged_image_uri(arguments: Mapping[str, object]) -> str:
    return _argument_text(arguments, "image_uri")


def _upgrade_upload_plan(
    update_service: Mapping[str, object],
    arguments: Mapping[str, object],
) -> dict[str, object]:
    requested_protocol = _upgrade_protocol(arguments)
    if requested_protocol == "webui":
        return {
            "protocol": "webui",
            "method": "WebUI",
            "target": "/UI/Rest/FirmwareInventory",
            "encoding": "multipart/form-data",
            "legacy_multipart": False,
            "compatibility_mode": "openubmc-webui",
            "staged_activation": False,
            "simple_update_target": "",
            "image_uri": "",
        }
    multipart_uri = update_service.get("MultipartHttpPushUri")
    http_push_uri = update_service.get("HttpPushUri")
    legacy_multipart = _legacy_http_push_uses_multipart(update_service)
    simple_update_target = _simple_update_action(update_service)
    staged_image_uri = _legacy_staged_image_uri(arguments)
    if isinstance(multipart_uri, str) and multipart_uri:
        method = "MultipartHttpPushUri"
        target = multipart_uri
        encoding = "multipart/form-data"
    elif isinstance(http_push_uri, str) and http_push_uri:
        method = "HttpPushUri"
        target = http_push_uri
        encoding = (
            "multipart/form-data"
            if legacy_multipart
            else "application/octet-stream"
        )
    elif simple_update_target:
        if not staged_image_uri:
            if requested_protocol == "auto":
                return _upgrade_upload_plan({}, {**arguments, "upgrade_protocol": "webui"})
            raise ValueError(
                "SimpleUpdate requires an advertised target and a "
                "BMC-reachable image_uri"
            )
        method = "SimpleUpdate"
        target = simple_update_target
        encoding = "application/json"
    else:
        raise ValueError("target UpdateService advertises no supported upload method")
    staged_activation = bool(
        legacy_multipart and simple_update_target and method == "HttpPushUri"
    )
    if staged_activation and not staged_image_uri:
        if requested_protocol == "auto":
            return _upgrade_upload_plan({}, {**arguments, "upgrade_protocol": "webui"})
        raise ValueError(
            "legacy HttpPushUri requires an explicit BMC-reachable image_uri "
            "for the subsequent SimpleUpdate activation"
        )
    return {
        "protocol": "redfish",
        "method": method,
        "target": target,
        "encoding": encoding,
        "legacy_multipart": legacy_multipart,
        "compatibility_mode": (
            "legacy-firmware-inventory-multipart"
            if legacy_multipart
            else "standard-redfish"
        ),
        "staged_activation": staged_activation,
        "simple_update_target": simple_update_target,
        "image_uri": staged_image_uri,
    }


def _webui_session(session):
    webui = getattr(session, "webui", None)
    required = ("login", "progress", "upload", "start", "close")
    if webui is None or not all(callable(getattr(webui, name, None)) for name in required):
        raise ValueError("selected Upgrade transport does not provide WebUI support")
    return webui


def _close_webui_session(session) -> dict[str, object]:
    try:
        raw = _webui_session(session).close()
    except Exception as exc:
        status = getattr(exc, "status", 0)
        return {
            "attempted": True,
            "completed": False,
            "http_status": status if isinstance(status, int) else 0,
            "error": (
                f"{type(exc).__name__}: HTTP {status}"
                if isinstance(status, int) and status
                else type(exc).__name__
            ),
        }
    if isinstance(raw, Mapping):
        return {
            "attempted": bool(raw.get("attempted", True)),
            "completed": bool(raw.get("completed", False)),
            "http_status": (
                int(raw.get("http_status", 0))
                if isinstance(raw.get("http_status", 0), int)
                else 0
            ),
            "error": str(raw.get("error", "")),
        }
    return {
        "attempted": True,
        "completed": True,
        "http_status": 0,
        "error": "",
    }


def _attach_cleanup_evidence(
    error: BaseException,
    cleanup: Mapping[str, object],
) -> None:
    evidence = dict(cleanup)
    error.cleanup_evidence = evidence
    if evidence.get("completed") is False:
        suffix = "WebUI session cleanup failed: " + str(
            evidence.get("error", "unknown cleanup error")
        )
        message = str(error)
        if suffix not in message:
            error.args = (f"{message}; {suffix}", *error.args[1:])


def _resolved_verification_mode(
    arguments: Mapping[str, object],
    protocol: str,
) -> str:
    requested = _verification_mode(arguments)
    if requested == "auto":
        return "task-completion" if protocol == "webui" else "manager-version"
    if protocol == "redfish" and requested == "task-completion":
        raise ValueError("task-completion verification requires the WebUI protocol")
    return requested


def _resolved_mutation_options(
    arguments: Mapping[str, object],
    *,
    protocol: str,
    verification_mode: str,
) -> dict[str, object]:
    options: dict[str, object] = {
        "image_uri": _argument_text(arguments, "image_uri"),
    }
    # Preserve the operation fingerprint of the existing default Redfish path.
    # WebUI is a distinct remote-effect protocol and must always be pinned.
    if protocol != "redfish" or verification_mode != "manager-version":
        options["upgrade_protocol"] = protocol
        options["verification_mode"] = verification_mode
    return options


@dataclass
class _UpgradeBinding:
    task_run: OpenUBMCTaskRun
    target: TargetSpec
    redfish_selector: CredentialSelector
    ssh_selector: CredentialSelector
    transport: object

    def close(self) -> None:
        self.task_run.close()


class _UpgradeTask:
    def __init__(self, task_id: str, backend: "UpgradeMcpBackend") -> None:
        self.task_id = task_id
        self.backend = backend
        self._bindings: OrderedDict[
            tuple[object, ...], _UpgradeBinding
        ] = OrderedDict()
        self._binding_evictions = 0
        self._lock = threading.RLock()

    @staticmethod
    def _key(arguments: Mapping[str, object]) -> tuple[object, ...]:
        return (
            _argument_text(arguments, "ip").lower(),
            int(arguments.get("redfish_port", 443)),
            _argument_text(arguments, "redfish_user"),
            _argument_text(arguments, "redfish_user_env"),
            _argument_text(arguments, "redfish_password_env"),
            _argument_text(arguments, "redfish_password"),
            _argument_bool(arguments, "allow_insecure_tls", default=True),
        )

    def binding_for(self, arguments: Mapping[str, object]) -> _UpgradeBinding:
        key = self._key(arguments)
        with self._lock:
            existing = self._bindings.get(key)
            if existing is not None:
                self._bindings.move_to_end(key)
                return existing
            binding = self.backend._create_binding(self.task_id, arguments)
            if len(self._bindings) >= self.backend.max_cached_bindings:
                _, victim = self._bindings.popitem(last=False)
                victim.close()
                self._binding_evictions += 1
            self._bindings[key] = binding
            return binding

    def close(self) -> None:
        with self._lock:
            bindings = list(self._bindings.values())
            self._bindings.clear()
        for binding in bindings:
            binding.close()

    def maintain(self) -> int:
        with self._lock:
            bindings = list(self._bindings.values())
        return sum(binding.task_run.prune_dead_connections() for binding in bindings)

    def status(self) -> dict[str, object]:
        with self._lock:
            bindings = list(self._bindings.values())
        return {
            "task_id": self.task_id,
            "target_count": len(bindings),
            "binding_cache_limit": self.backend.max_cached_bindings,
            "binding_evictions": self._binding_evictions,
            "targets": [binding.task_run.runtime_status() for binding in bindings],
        }


class UpgradeMcpBackend:
    def __init__(
        self,
        *,
        journal_store: MutationJournalStore,
        credential_loader: Callable[
            [Mapping[str, object]], dict[str, dict[str, str | int]]
        ] = _default_credential_loader,
        redfish_transport_factory: Callable[[Mapping[str, object]], object]
        | None = None,
        max_cached_bindings: int = 32,
        max_batch_concurrency: int = 32,
        max_batch_targets: int = 128,
    ) -> None:
        if max_cached_bindings < 1:
            raise ValueError("max_cached_bindings must be positive")
        if max_batch_concurrency < 1:
            raise ValueError("max_batch_concurrency must be positive")
        if max_batch_targets < 1:
            raise ValueError("max_batch_targets must be positive")
        self.journal_store = journal_store
        self.operation_state_store = UpgradeOperationStateStore(journal_store.root)
        self.credential_loader = credential_loader
        self.redfish_transport_factory = redfish_transport_factory
        self.max_cached_bindings = int(max_cached_bindings)
        self.max_batch_concurrency = int(max_batch_concurrency)
        self.max_batch_targets = int(max_batch_targets)

    def open_task(self, task_id: str) -> _UpgradeTask:
        return _UpgradeTask(task_id, self)

    @staticmethod
    def close_task(task: _UpgradeTask) -> None:
        task.close()

    @staticmethod
    def maintain_task(task: _UpgradeTask) -> int:
        return task.maintain()

    @staticmethod
    def task_status(task: _UpgradeTask) -> dict[str, object]:
        return task.status()

    def _create_binding(
        self,
        task_id: str,
        arguments: Mapping[str, object],
    ) -> _UpgradeBinding:
        host = _argument_text(arguments, "ip")
        if not host:
            raise ValueError("Upgrade requires a bound ip")
        credentials = self.credential_loader(arguments)
        redfish_selector = CredentialSelector.for_redfish(
            user=str(credentials["redfish"].get("user", "")),
            user_env="",
            password_env=_argument_text(arguments, "redfish_password_env"),
            environ={},
        )
        ssh_selector = CredentialSelector.for_ssh(
            user=_argument_text(arguments, "ssh_user"),
            user_env=_argument_text(arguments, "ssh_user_env"),
            password_env=_argument_text(arguments, "ssh_password_env"),
            identity_file=_argument_text(arguments, "ssh_identity_file"),
            environ={},
        )
        target = TargetSpec.for_credential_selectors(
            host=host,
            ssh_port=int(arguments.get("ssh_port", 22)),
            telnet_port=int(arguments.get("telnet_port", 23)),
            redfish_port=int(arguments.get("redfish_port", 443)),
            credential_selectors=(redfish_selector, ssh_selector),
            policy=TargetPolicy(read_only=False),
        )
        redfish_credentials = ResolvedRedfishCredentials.from_mapping(
            credentials["redfish"]
        )
        task_run = OpenUBMCTaskRun(
            task_id=task_id,
            credential_resolver=CredentialResolver(
                redfish_loader=lambda _selector: redfish_credentials
            ),
            mutation_journal_store=self.journal_store,
        )
        transport = (
            self.redfish_transport_factory(arguments)
            if self.redfish_transport_factory is not None
            else RedfishUpgradeTransport(
                verify_tls=not _argument_bool(
                    arguments,
                    "allow_insecure_tls",
                    default=True,
                ),
                timeout=_argument_timeout(arguments, "redfish_timeout", 30),
            )
        )
        return _UpgradeBinding(
            task_run=task_run,
            target=target,
            redfish_selector=redfish_selector,
            ssh_selector=ssh_selector,
            transport=transport,
        )

    @staticmethod
    def _probe_webui(session) -> dict[str, object]:
        webui = _webui_session(session)
        result: dict[str, object] = {}
        try:
            login = webui.login()
            progress = webui.progress()
            result = {
                "login_http_status": login.status,
                "progress_http_status": progress.status,
                "active_tasks": len(_normalized_webui_tasks(progress.payload)),
            }
        finally:
            cleanup = _close_webui_session(session)
            if result:
                result["cleanup"] = cleanup
            active_error = sys.exc_info()[1]
            if active_error is not None:
                _attach_cleanup_evidence(active_error, cleanup)
        return result

    def _discover_upgrade_plan(
        self,
        binding: _UpgradeBinding,
        arguments: Mapping[str, object],
        context,
    ) -> dict[str, object]:
        lane = binding.task_run.redfish_lane(
            target=binding.target,
            credential_selector=binding.redfish_selector,
            lease_name="upgrade",
            transport=binding.transport,
        )

        def inspect(session) -> dict[str, object]:
            context.raise_if_stopped()
            if _upgrade_protocol(arguments) == "webui":
                update_payload: Mapping[str, object] = {}
            else:
                discovery = session.request_json("GET", "/redfish/v1/UpdateService")
                if not isinstance(discovery.payload, Mapping):
                    raise ValueError("Redfish UpdateService response must be an object")
                update_payload = discovery.payload
            plan = _upgrade_upload_plan(update_payload, arguments)
            if plan.get("protocol") == "webui":
                plan = {**plan, "webui_probe": self._probe_webui(session)}
            return plan

        return lane.request(
            "upgrade-protocol-discovery",
            replay_safe=True,
            callback=inspect,
        )

    @staticmethod
    def _candidate_mutation_options(
        arguments: Mapping[str, object],
    ) -> list[tuple[str, str, dict[str, object]]]:
        requested_protocol = _upgrade_protocol(arguments)
        requested_verification = _verification_mode(arguments)
        candidates: list[tuple[str, str, dict[str, object]]] = []
        if requested_protocol in {"auto", "redfish"} and requested_verification in {
            "auto",
            "manager-version",
        }:
            candidates.append(
                (
                    "redfish",
                    "manager-version",
                    _resolved_mutation_options(
                        arguments,
                        protocol="redfish",
                        verification_mode="manager-version",
                    ),
                )
            )
        requested = _mutation_options(arguments)
        if all(candidate != requested for _protocol, _mode, candidate in candidates):
            candidates.append(
                (requested_protocol, requested_verification, requested)
            )
        if requested_protocol in {"auto", "webui"}:
            mode = _resolved_verification_mode(arguments, "webui")
            webui_candidate = _resolved_mutation_options(
                arguments,
                protocol="webui",
                verification_mode=mode,
            )
            if all(
                candidate != webui_candidate
                for _protocol, _mode, candidate in candidates
            ):
                candidates.append(("webui", mode, webui_candidate))
        return candidates

    @staticmethod
    def _upload_webui(
        session,
        artifact: UpgradeArtifact,
        artifact_bytes: bytes | None,
        *,
        upload_timeout: float,
        mark_effects_started: Callable[[], None],
        record_operation_state: Callable[[Mapping[str, object]], None],
        artifact_source: _SharedArtifactSource | None,
    ) -> dict[str, object]:
        webui = _webui_session(session)
        login = webui.login()
        if login.status < 200 or login.status >= 300:
            raise RuntimeError(f"WebUI login returned HTTP {login.status}")
        baseline = webui.progress()
        baseline_tasks = _matching_webui_tasks(
            baseline.payload,
            Path(artifact.path).name,
        )
        baseline_identities = _webui_task_identity_signature(baseline_tasks)
        record_operation_state(
            {
                "baseline_task_identities": baseline_identities,
                "upload_accepted": False,
                "task_id_remote": "",
                "task_uri": "",
            }
        )
        if artifact_source is not None:
            body, boundary = artifact_source.webui_multipart_stream(artifact)
        else:
            if artifact_bytes is None:
                raise ValueError("artifact bytes are required for WebUI upload")
            body, boundary = _webui_multipart_body(artifact, artifact_bytes)
        content_length = (
            len(body)
            if isinstance(body, (bytes, bytearray))
            else int(getattr(body, "content_length", 0))
        )
        if content_length <= 0:
            raise ValueError("WebUI upload body must have a positive content length")
        mark_effects_started()
        uploaded = webui.upload(
            body=body,
            boundary=boundary,
            content_length=content_length,
            timeout=upload_timeout,
        )
        if uploaded.status < 200 or uploaded.status >= 300:
            if 400 <= uploaded.status < 500:
                raise MutationEffectsRejected(
                    "WebUI upgrade upload was explicitly rejected with "
                    f"HTTP {uploaded.status}"
                )
            raise RuntimeError(f"WebUI upgrade upload returned HTTP {uploaded.status}")
        image_uri = _webui_uploaded_file_path(
            uploaded.payload,
            Path(artifact.path).name,
        )
        record_operation_state(
            {
                "upload_accepted": True,
                "image_uri": image_uri,
            }
        )
        try:
            started = webui.start(image_uri)
        except WebUiHttpError as exc:
            raise WebUiStartError(
                exc.status,
                f"WebUI upgrade start returned HTTP {exc.status} after upload completed",
            ) from exc
        if started.status < 200 or started.status >= 300:
            raise WebUiStartError(
                started.status,
                f"WebUI upgrade start returned HTTP {started.status} after upload completed",
            )
        task_id = _webui_task_id_from_start(started.payload)
        task_uri = (
            f"/UI/Rest/BMCSettings/UpdateService/UpdateProgress/{task_id}"
            if task_id
            else "/UI/Rest/BMCSettings/UpdateService/UpdateProgress"
        )
        record_operation_state(
            {
                "task_id_remote": task_id,
                "task_uri": task_uri,
            }
        )
        return {
            "protocol": "webui",
            "method": "WebUI",
            "encoding": "multipart/form-data",
            "legacy_multipart": False,
            "compatibility_mode": "openubmc-webui",
            "staged_activation": False,
            "http_status": uploaded.status,
            "start_http_status": started.status,
            "task_uri": task_uri,
            "task_id": task_id,
            "_baseline_task_signature": _webui_task_signature(baseline_tasks),
            "_baseline_task_identities": baseline_identities,
            "image_uri": image_uri,
            "upload_timeout_seconds": upload_timeout,
        }

    @staticmethod
    def _monitor_webui_task(
        session,
        artifact: UpgradeArtifact,
        context,
        *,
        task_id: str = "",
        baseline_signature: tuple[tuple[object, ...], ...] = (),
        baseline_identities: tuple[tuple[str, ...], ...] = (),
    ) -> dict[str, object]:
        webui = _webui_session(session)
        observations: list[tuple[tuple[object, ...], ...]] = []
        artifact_name = Path(artifact.path).name
        while True:
            context.raise_if_stopped()
            try:
                response = webui.progress()
            except (WebUiTransportError, WebUiHttpError, OSError, TimeoutError) as exc:
                return {
                    "state": "connection_lost",
                    "task_uri": (
                        f"/UI/Rest/BMCSettings/UpdateService/UpdateProgress/{task_id}"
                        if task_id
                        else "/UI/Rest/BMCSettings/UpdateService/UpdateProgress"
                    ),
                    "error": type(exc).__name__,
                    "observations": observations,
                    "artifact_file_name": artifact_name,
                }
            all_tasks = _matching_webui_tasks(response.payload, artifact_name)
            signature = _webui_task_signature(all_tasks)
            if not observations or observations[-1] != signature:
                observations.append(signature)
                if len(observations) > 64:
                    observations.pop(0)
            tasks = _webui_tasks_added_since(all_tasks, baseline_identities)
            state = _classify_webui_tasks(tasks)
            if task_id:
                try:
                    task_response = webui.progress(task_id)
                except (WebUiTransportError, WebUiHttpError, OSError, TimeoutError):
                    task_response = None
                if task_response is not None:
                    task_tasks = _matching_webui_tasks(
                        task_response.payload,
                        artifact_name,
                        allow_unnamed=True,
                    )
                    task_state = _classify_webui_tasks(task_tasks)
                    if task_state == "failed":
                        tasks = task_tasks
                        state = "failed"
                    elif task_state == "running":
                        state = "running"
                    elif task_state == "completed":
                        state = (
                            "failed"
                            if tasks and _classify_webui_tasks(tasks) == "failed"
                            else "running"
                            if tasks
                            and signature != baseline_signature
                            and _classify_webui_tasks(tasks) != "completed"
                            else "completed"
                        )
                        if not tasks or signature == baseline_signature:
                            tasks = task_tasks
            if state == "completed":
                return {
                    "state": "completed",
                    "task_uri": (
                        f"/UI/Rest/BMCSettings/UpdateService/UpdateProgress/{task_id}"
                        if task_id
                        else "/UI/Rest/BMCSettings/UpdateService/UpdateProgress"
                    ),
                    "tasks": tasks,
                    "components": sorted(
                        {
                            str(task.get("Component"))
                            for task in tasks
                            if isinstance(task.get("Component"), str)
                            and str(task.get("Component"))
                        }
                    ),
                    "artifact_file_name": artifact_name,
                    "observations": observations,
                }
            if state == "failed":
                error = RuntimeError(
                    "WebUI upgrade task failed: "
                    + json.dumps(tasks, ensure_ascii=False, sort_keys=True)
                )
                error.webui_tasks = tasks
                raise error
            context.wait(min(2.0, context.remaining()))

    @staticmethod
    def _upload(
        session,
        update_service: Mapping[str, object],
        artifact: UpgradeArtifact,
        artifact_bytes: bytes | None,
        arguments: Mapping[str, object],
        *,
        upload_timeout: float,
        mark_effects_started: Callable[[], None] | None = None,
        record_operation_state: Callable[[Mapping[str, object]], None] | None = None,
        artifact_source: _SharedArtifactSource | None = None,
    ) -> dict[str, object]:
        mark_effects = mark_effects_started or (lambda: None)
        record_state = record_operation_state or (lambda _values: None)
        plan = _upgrade_upload_plan(update_service, arguments)
        method = str(plan["method"])

        if method == "WebUI":
            return UpgradeMcpBackend._upload_webui(
                session,
                artifact,
                artifact_bytes,
                upload_timeout=upload_timeout,
                mark_effects_started=mark_effects,
                record_operation_state=record_state,
                artifact_source=artifact_source,
            )

        def body_headers(content_type: str, body: object) -> dict[str, str]:
            headers = {"Content-Type": content_type}
            length = (
                len(body)
                if isinstance(body, (bytes, bytearray))
                else getattr(body, "content_length", None)
            )
            if isinstance(length, int) and length >= 0:
                headers["Content-Length"] = str(length)
            return headers

        if method == "MultipartHttpPushUri":
            multipart_uri = str(plan["target"])
            if artifact_source is not None:
                body, boundary = artifact_source.multipart_stream(artifact)
            else:
                if artifact_bytes is None:
                    raise ValueError("artifact bytes are required for upload")
                body, boundary = _multipart_body(artifact, artifact_bytes)
            mark_effects()
            response = session.request_json(
                "POST",
                multipart_uri,
                data=body,
                headers=body_headers(
                    f"multipart/form-data; boundary={boundary}",
                    body,
                ),
                timeout=upload_timeout,
            )
        elif method == "HttpPushUri":
            http_push_uri = str(plan["target"])
            if bool(plan["legacy_multipart"]):
                if artifact_source is not None:
                    body, boundary = artifact_source.multipart_stream(artifact)
                else:
                    if artifact_bytes is None:
                        raise ValueError("artifact bytes are required for upload")
                    body, boundary = _multipart_body(artifact, artifact_bytes)
                mark_effects()
                response = session.request_json(
                    "POST",
                    http_push_uri,
                    data=body,
                    headers=body_headers(
                        f"multipart/form-data; boundary={boundary}",
                        body,
                    ),
                    timeout=upload_timeout,
                )
            else:
                body = (
                    artifact_source.octet_stream()
                    if artifact_source is not None
                    else artifact_bytes
                )
                if body is None:
                    raise ValueError("artifact bytes are required for upload")
                mark_effects()
                response = session.request_json(
                    "POST",
                    http_push_uri,
                    data=body,
                    headers=body_headers("application/octet-stream", body),
                    timeout=upload_timeout,
                )
        elif method == "SimpleUpdate":
            mark_effects()
            response = session.request_json(
                "POST",
                str(plan["target"]),
                payload={"ImageURI": str(plan["image_uri"])},
            )
        else:
            raise ValueError("target UpdateService advertises no supported upload method")
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"Redfish upgrade upload returned HTTP {response.status}")
        return {
            "protocol": "redfish",
            "method": method,
            "encoding": plan["encoding"],
            "legacy_multipart": plan["legacy_multipart"],
            "compatibility_mode": plan["compatibility_mode"],
            "staged_activation": plan["staged_activation"],
            "http_status": response.status,
            "task_uri": _response_uri(response),
            "upload_timeout_seconds": upload_timeout,
        }

    @staticmethod
    def _monitor_task(session, task_uri: str, context) -> dict[str, object]:
        if not task_uri:
            return {"state": "not_advertised", "task_uri": ""}
        terminal_success = {"completed", "completedok", "success", "succeeded"}
        terminal_failure = {
            "exception",
            "killed",
            "cancelled",
            "interrupted",
            "failed",
        }
        observations: list[str] = []
        while True:
            context.raise_if_stopped()
            try:
                response = session.request_json("GET", task_uri)
            except (OSError, TimeoutError, RedfishHttpError) as exc:
                return {
                    "state": "connection_lost",
                    "task_uri": task_uri,
                    "error": type(exc).__name__,
                    "observations": observations,
                }
            payload = response.payload if isinstance(response.payload, Mapping) else {}
            raw_state = payload.get("TaskState", payload.get("TaskStatus", ""))
            state = str(raw_state).strip()
            observations.append(state or f"http-{response.status}")
            normalized = state.lower().replace(" ", "")
            if normalized in terminal_success:
                return {
                    "state": "completed",
                    "task_uri": task_uri,
                    "observations": observations,
                }
            if normalized in terminal_failure:
                raise RuntimeError(f"Redfish upgrade task ended in {state}")
            context.wait(min(2.0, context.remaining()))

    @staticmethod
    def _activate_staged_image(
        session,
        update_service: Mapping[str, object],
        image_uri: str,
        context,
    ) -> dict[str, object]:
        """Activate a legacy multipart upload through SimpleUpdate.

        A BMC may accept the multipart upload as a staging operation and then
        reboot as soon as SimpleUpdate is posted.  A lost response at this
        boundary is therefore an activation observation, not proof of failure;
        version verification must reconnect and decide.
        """

        target = _simple_update_action(update_service)
        if not target:
            return {"state": "not_advertised", "task_uri": ""}
        request_timeout = min(
            float(getattr(session, "timeout", 30)),
            context.remaining(),
        )
        if request_timeout <= 0:
            context.raise_if_stopped()
        try:
            response = session.request_json(
                "POST",
                target,
                payload={"ImageURI": image_uri},
                timeout=request_timeout,
            )
        except (RedfishTransportError, OSError, TimeoutError) as exc:
            return {
                "state": "connection_lost",
                "task_uri": "",
                "error": type(exc).__name__,
            }
        except RedfishHttpError as exc:
            if exc.status >= 500:
                return {
                    "state": "connection_lost",
                    "task_uri": "",
                    "http_status": exc.status,
                    "error": "server_error_during_activation",
                }
            raise
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(
                f"Redfish SimpleUpdate activation returned HTTP {response.status}"
            )
        task_uri = _response_uri(response)
        return {
            "state": "submitted",
            "task_uri": task_uri,
            "http_status": response.status,
            "monitor": UpgradeMcpBackend._monitor_task(session, task_uri, context),
        }

    @staticmethod
    def _installed_version(session) -> dict[str, object]:
        managers = session.request_json("GET", "/redfish/v1/Managers")
        payload = managers.payload if isinstance(managers.payload, Mapping) else {}
        members = payload.get("Members", [])
        if not isinstance(members, list):
            raise ValueError("Redfish Managers collection has no Members array")
        for member in members:
            if not isinstance(member, Mapping):
                continue
            path = member.get("@odata.id")
            if not isinstance(path, str) or not path:
                continue
            response = session.request_json("GET", path)
            manager = response.payload if isinstance(response.payload, Mapping) else {}
            for key in ("FirmwareVersion", "ManagerFirmwareVersion", "Version"):
                version = manager.get(key)
                if isinstance(version, str) and version:
                    identity = {"version": version, "manager": path}
                    last_reset_time = manager.get("LastResetTime")
                    if isinstance(last_reset_time, str) and last_reset_time.strip():
                        identity["last_reset_time"] = last_reset_time.strip()
                    return identity
        raise ValueError("Redfish Managers did not report an installed firmware version")

    def _wait_for_webui_task_completion(
        self,
        verification,
        context,
        artifact: UpgradeArtifact,
        mutation_observation: Mapping[str, object],
    ) -> dict[str, object]:
        artifact_name = Path(artifact.path).name
        operation_state = self.operation_state_store.load(
            str(getattr(context, "task_id", "")),
            str(getattr(context, "operation_id", "")),
        )
        task_id = str(
            mutation_observation.get("task_id", "")
            or (
                operation_state.get("task_id_remote", "")
                if isinstance(operation_state, Mapping)
                else ""
            )
        )
        baseline_identities = (
            operation_state.get("baseline_task_identities")
            if isinstance(operation_state, Mapping)
            else None
        )
        poll_interval = 2.0
        last_error = ""
        while True:
            context.raise_if_stopped()

            def inspect(session) -> dict[str, object]:
                webui = _webui_session(session)
                result: dict[str, object] = {}
                try:
                    if not bool(getattr(webui, "logged_in", False)):
                        webui.login()
                    response = webui.progress()
                    tasks = _matching_webui_tasks(response.payload, artifact_name)
                    task_scoped = False
                    if task_id:
                        try:
                            task_response = webui.progress(task_id)
                        except WebUiHttpError as exc:
                            if exc.status not in {404, 405}:
                                raise
                        else:
                            task_tasks = _matching_webui_tasks(
                                task_response.payload,
                                artifact_name,
                                allow_unnamed=True,
                            )
                            if task_tasks:
                                tasks = task_tasks
                                task_scoped = True
                    if not task_scoped:
                        tasks = (
                            _webui_tasks_added_since(tasks, baseline_identities)
                            if isinstance(baseline_identities, list)
                            else []
                        )
                    result = {
                        "state": _classify_webui_tasks(tasks),
                        "tasks": tasks,
                    }
                finally:
                    cleanup = _close_webui_session(session)
                    if result:
                        result["cleanup"] = cleanup
                    active_error = sys.exc_info()[1]
                    if active_error is not None:
                        _attach_cleanup_evidence(active_error, cleanup)
                return result

            try:
                snapshot = verification.redfish_request(
                    "upgrade-read-webui-task",
                    replay_safe=True,
                    callback=inspect,
                )
            except WebUiHttpError as exc:
                if exc.status in {401, 403}:
                    raise
                last_error = f"{type(exc).__name__}: HTTP {exc.status}"
            except (WebUiTransportError, OSError, TimeoutError, ValueError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            else:
                state = str(snapshot.get("state", ""))
                tasks = snapshot.get("tasks")
                tasks = tasks if isinstance(tasks, list) else []
                cleanup = snapshot.get("cleanup")
                if (
                    isinstance(cleanup, Mapping)
                    and cleanup.get("completed") is False
                ):
                    last_error = "WebUI session cleanup failed: " + str(
                        cleanup.get("error", "unknown cleanup error")
                    )
                if state == "completed":
                    return {
                        "completed": True,
                        "artifact_file_name": artifact_name,
                        "task_id": task_id,
                        "task_uri": mutation_observation.get("task_uri", ""),
                        "tasks": tasks,
                        "cleanup": snapshot.get("cleanup"),
                        "components": sorted(
                            {
                                str(task.get("Component"))
                                for task in tasks
                                if isinstance(task, Mapping)
                                and isinstance(task.get("Component"), str)
                                and str(task.get("Component"))
                            }
                        ),
                    }
                if state == "failed":
                    raise RuntimeError(
                        "fresh WebUI verification found a failed upgrade task: "
                        + json.dumps(tasks, ensure_ascii=False, sort_keys=True)
                    )
                last_error = f"WebUI task state is {state or 'unknown'}"
            if context.remaining() <= poll_interval:
                raise TimeoutError(
                    "WebUI upgrade task did not reach Completed/ErrorCode=0 "
                    f"before the verification deadline ({last_error})"
                )
            context.wait(min(poll_interval, context.remaining()))

    @staticmethod
    def _activation_state(
        session,
        *,
        manager_version: str,
        expected_version: str,
    ) -> dict[str, object]:
        """Read the minimal UpdateService state needed to classify a fallback."""

        update_service = session.request_json("GET", "/redfish/v1/UpdateService")
        update_payload = (
            update_service.payload
            if isinstance(update_service.payload, Mapping)
            else {}
        )
        inventory_link = update_payload.get("FirmwareInventory")
        inventory_uri = (
            inventory_link.get("@odata.id", "")
            if isinstance(inventory_link, Mapping)
            else ""
        )
        versions: dict[str, str] = {}
        if isinstance(inventory_uri, str) and inventory_uri:
            inventory = session.request_json("GET", inventory_uri)
            inventory_payload = (
                inventory.payload if isinstance(inventory.payload, Mapping) else {}
            )
            members = inventory_payload.get("Members", [])
            if isinstance(members, list):
                for member in members:
                    if not isinstance(member, Mapping):
                        continue
                    path = member.get("@odata.id")
                    if not isinstance(path, str) or not path:
                        continue
                    identifier = path.rstrip("/").rsplit("/", 1)[-1]
                    if identifier not in {"ActiveBMC", "AvailableBMC", "BackupBMC"}:
                        continue
                    response = session.request_json("GET", path)
                    payload = (
                        response.payload
                        if isinstance(response.payload, Mapping)
                        else {}
                    )
                    version = payload.get("Version")
                    if isinstance(version, str):
                        versions[identifier] = version

        oem = update_payload.get("Oem")
        openubmc = oem.get("openUBMC") if isinstance(oem, Mapping) else None
        openubmc = openubmc if isinstance(openubmc, Mapping) else {}
        pending_values = (
            update_payload.get("Task"),
            openubmc.get("FirmwareToTakeEffect"),
            openubmc.get("BackgroundUpdateTasks"),
            openubmc.get("SyncUpdateState"),
        )
        activation_pending = any(
            value not in (None, "", [], {}) for value in pending_values
        )
        expected_locations = sorted(
            name for name, version in versions.items() if version == expected_version
        )
        return {
            "manager_version": manager_version,
            "active_version": versions.get("ActiveBMC", ""),
            "available_version": versions.get("AvailableBMC", ""),
            "backup_version": versions.get("BackupBMC", ""),
            "expected_locations": expected_locations,
            "activation_pending": activation_pending,
        }

    @classmethod
    def _wait_for_installed_version(
        cls,
        verification,
        context,
        arguments: Mapping[str, object],
        mutation_observation: Mapping[str, object],
    ) -> dict[str, object]:
        expected = verification.artifact.product_version
        poll_interval = float(arguments.get("version_poll_interval", 5))
        if poll_interval <= 0:
            raise ValueError("version_poll_interval must be positive")
        last_version = ""
        last_error = ""
        last_activation_state: dict[str, object] = {}
        activation_fallback_observations = 0
        monitor = mutation_observation.get("monitor")
        monitor_state = (
            str(monitor.get("state", "")) if isinstance(monitor, Mapping) else ""
        )
        manager_before = mutation_observation.get("manager_before")
        same_version_before_upload = (
            not isinstance(manager_before, Mapping)
            or not str(manager_before.get("version", "")).strip()
            or str(manager_before.get("version", "")) == expected
        )
        reset_before = _manager_reset_time(manager_before)
        # A target that already reports the requested version is only accepted
        # after a fresh activation boundary. Seeing an intermediate/old
        # version after the effect is also a valid boundary signal when the
        # target does not expose LastResetTime.
        observed_intermediate_version = False
        while True:
            context.raise_if_stopped()
            try:
                value = verification.redfish_request(
                    "upgrade-read-installed-version",
                    replay_safe=True,
                    callback=cls._installed_version,
                )
            except RedfishHttpError as exc:
                if exc.status in {401, 403}:
                    raise
                last_error = f"{type(exc).__name__}: {exc}"
            except (OSError, TimeoutError, ValueError, urlerror.URLError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            else:
                version = str(value.get("version", ""))
                if version == expected:
                    if same_version_before_upload and not (
                        observed_intermediate_version
                        or (
                        reset_before is not None
                        and (reset_after := _manager_reset_time(value)) is not None
                        and reset_after > reset_before
                        )
                    ):
                        last_version = version
                        last_error = "fresh activation boundary was not observed"
                        if context.remaining() <= poll_interval:
                            raise ValueError(
                                "target already reported the requested version before upload "
                                "and did not prove a fresh activation boundary"
                            )
                        context.wait(min(poll_interval, context.remaining()))
                        continue
                    return value
                last_version = version
                last_error = ""
                if same_version_before_upload and version != expected:
                    observed_intermediate_version = True

                should_probe_activation = (
                    monitor_state in {"connection_lost", "activation_connection_lost"}
                    or context.remaining() <= poll_interval
                )
                if should_probe_activation:
                    try:
                        last_activation_state = verification.redfish_request(
                            "upgrade-read-activation-state",
                            replay_safe=True,
                            callback=lambda session: cls._activation_state(
                                session,
                                manager_version=version,
                                expected_version=expected,
                            ),
                        )
                    except RedfishHttpError as exc:
                        if exc.status in {401, 403}:
                            raise
                    except (OSError, TimeoutError, ValueError, urlerror.URLError):
                        pass
                    else:
                        if (
                            monitor_state == "activation_connection_lost"
                            and last_activation_state.get("active_version") == version
                            and "AvailableBMC"
                            in last_activation_state.get("expected_locations", [])
                            and not bool(
                                last_activation_state.get("activation_pending", False)
                            )
                        ):
                            activation_fallback_observations += 1
                        else:
                            activation_fallback_observations = 0
                        if (
                            (
                                monitor_state == "connection_lost"
                                or (
                                    monitor_state == "activation_connection_lost"
                                    and (
                                        activation_fallback_observations >= 3
                                        or context.remaining() <= poll_interval
                                    )
                                )
                                or context.remaining() <= poll_interval
                            )
                            and last_activation_state.get("active_version") == version
                            and "AvailableBMC"
                            in last_activation_state.get("expected_locations", [])
                            and not bool(
                                last_activation_state.get("activation_pending", False)
                            )
                        ):
                            raise UpgradeActivationReverted(
                                "target returned on the previous active BMC version after "
                                "activation; the requested version remains only in "
                                "AvailableBMC: "
                                f"expected {expected}, active {version}"
                            )

            if context.remaining() <= poll_interval:
                detail = (
                    f"last version {last_version}"
                    if last_version
                    else last_error or "target did not return a version"
                )
                if last_activation_state:
                    detail += (
                        "; ActiveBMC "
                        f"{last_activation_state.get('active_version', '') or 'unknown'}, "
                        "AvailableBMC "
                        f"{last_activation_state.get('available_version', '') or 'unknown'}, "
                        "activation pending "
                        f"{str(bool(last_activation_state.get('activation_pending'))).lower()}"
                    )
                raise ValueError(
                    "target did not report the expected installed version before "
                    f"the reconnect deadline: expected {expected}; {detail}"
                )
            context.wait(min(poll_interval, context.remaining()))

    @staticmethod
    def _matching_upgrade_journals(
        binding: _UpgradeBinding,
        adapter: UpgradeRuntimeAdapter,
        artifact: UpgradeArtifact,
        mutation_options: Mapping[str, object],
    ) -> list[object]:
        matches = [
            journal
            for journal in binding.task_run.mutation_journals()
            if journal.action == "upgrade"
            and journal.target_fingerprint == binding.target.fingerprint
            and adapter.mutation_request(
                operation_id=journal.operation_id,
                artifact=artifact,
                mutation_options=mutation_options,
            ).fingerprint
            == journal.operation_fingerprint
        ]
        matches.sort(
            key=lambda journal: (
                str(getattr(journal, "updated_at", "")),
                str(getattr(journal, "operation_id", "")),
            ),
            reverse=True,
        )
        return matches

    @staticmethod
    def _terminal_upgrade_replay(
        binding: _UpgradeBinding,
        journal,
    ) -> dict[str, object]:
        completed_epoch = (
            journal.rollback_epoch
            or journal.epoch_after
            or journal.epoch_before
        )
        return {
            "operation_id": journal.operation_id,
            "action": "upgrade",
            "target_fingerprint": binding.target.fingerprint,
            "epoch_before": journal.epoch_before,
            "epoch_after": completed_epoch,
            "mutation": None,
            "verification": None,
            "journal": journal.to_public_dict(),
            "idempotent_replay": True,
        }

    def _upgrade_one(
        self,
        task: _UpgradeTask,
        arguments: Mapping[str, object],
        context,
    ) -> dict[str, object]:
        context.raise_if_stopped()
        artifact_path = Path(
            _argument_text(arguments, "artifact_path")
        ).expanduser()
        artifact_path = Path(os.path.abspath(os.fspath(artifact_path)))
        expected_sha = _argument_text(arguments, "artifact_sha256").lower()
        product_version = _argument_text(arguments, "product_version")
        artifact = UpgradeArtifact(
            path=str(artifact_path),
            sha256=expected_sha,
            product_version=product_version,
            package_binding=_argument_text(arguments, "package_binding"),
            upgrade_eligible=arguments.get("upgrade_eligible"),
            evidence_ids=tuple(arguments.get("evidence_ids", ())),
        )
        allow_insecure_tls = _argument_bool(
            arguments,
            "allow_insecure_tls",
            default=True,
        )
        raw_policy = arguments.get("_task_authorization_policy")
        if raw_policy is not None:
            if not isinstance(raw_policy, Mapping):
                raise TypeError("_task_authorization_policy must be an object")
            authorization = TaskAuthorizationPolicy.from_public_dict(raw_policy)
        else:
            intent = _argument_text(arguments, "_task_intent") or _argument_text(
                arguments, "intent"
            )
            authorization = MutationAuthorization.from_task_intent(
                intent,
                delivery_strategy=_argument_text(
                    arguments,
                    "_task_delivery_strategy",
                )
                or _argument_text(arguments, "delivery_strategy"),
                allow_insecure_tls=allow_insecure_tls,
            )
        if allow_insecure_tls:
            authorization.require_insecure_tls()
        binding = task.binding_for(arguments)
        minimum_target_epoch = arguments.get("_minimum_target_epoch", 0)
        if (
            isinstance(minimum_target_epoch, bool)
            or not isinstance(minimum_target_epoch, int)
            or minimum_target_epoch < 0
        ):
            raise TypeError("_minimum_target_epoch must be a non-negative integer")
        if minimum_target_epoch:
            binding.task_run.ensure_target_epoch(
                binding.target,
                minimum_target_epoch,
                reason="context-runtime-upgrade-sync",
            )
        adapter = UpgradeRuntimeAdapter(
            task_run=binding.task_run,
            target=binding.target,
            redfish_selector=binding.redfish_selector,
            ssh_selector=binding.ssh_selector,
            redfish_transport=binding.transport,
        )
        selected_protocol = ""
        selected_verification = ""
        mutation_options: dict[str, object] = {}
        matching_journals: list[object] = []
        operation_state = self.operation_state_store.load(
            task.task_id,
            context.operation_id,
        )
        for protocol, verification_mode, candidate in self._candidate_mutation_options(
            arguments
        ):
            matches = self._matching_upgrade_journals(
                binding,
                adapter,
                artifact,
                candidate,
            )
            if matches:
                selected_protocol = protocol
                selected_verification = verification_mode
                mutation_options = candidate
                matching_journals = matches
                break
        if not matching_journals:
            if operation_state is not None:
                selected_protocol = str(operation_state.get("protocol", ""))
                selected_verification = str(
                    operation_state.get("verification_mode", "")
                )
                requested_protocol = _upgrade_protocol(arguments)
                requested_verification = _verification_mode(arguments)
                if (
                    selected_protocol not in {"redfish", "webui"}
                    or requested_protocol not in {"auto", selected_protocol}
                ):
                    raise MutationOperationConflict(
                        "Upgrade operation state conflicts with the requested protocol"
                    )
                if requested_verification not in {
                    "auto",
                    selected_verification,
                }:
                    raise MutationOperationConflict(
                        "Upgrade operation state conflicts with verification mode"
                    )
                mutation_options = _resolved_mutation_options(
                    arguments,
                    protocol=selected_protocol,
                    verification_mode=selected_verification,
                )
                matching_journals = self._matching_upgrade_journals(
                    binding,
                    adapter,
                    artifact,
                    mutation_options,
                )
        if operation_state is not None and mutation_options:
            mutation_fingerprint = adapter.mutation_request(
                operation_id=context.operation_id,
                artifact=artifact,
                mutation_options=mutation_options,
            ).fingerprint
            if str(operation_state.get("mutation_fingerprint", "")) != (
                mutation_fingerprint
            ):
                raise MutationOperationConflict(
                    "Upgrade operation state is bound to a different mutation identity"
                )
        operation_arguments = {
            **arguments,
            "upgrade_protocol": selected_protocol or _upgrade_protocol(arguments),
            "verification_mode": (
                selected_verification or _verification_mode(arguments)
            ),
        }
        matching_journal = next(
            (
                journal
                for journal in matching_journals
                if not journal.terminal and journal.stage != "replan_required"
            ),
            None,
        )
        if matching_journal is not None:
            recovery = self._recover_uncertain_upgrade(
                binding=binding,
                adapter=adapter,
                journal=matching_journal,
                artifact=artifact,
                authorization=authorization,
                arguments=operation_arguments,
                context=context,
                mutation_options=mutation_options,
            )
            if recovery is not None:
                return recovery
        terminal_journal = next(
            (journal for journal in matching_journals if journal.terminal),
            None,
        )
        if terminal_journal is not None:
            terminal_status = mutation_journal_operation_status(
                terminal_journal,
                action="upgrade",
            )
            if terminal_status == "completed":
                return self._terminal_upgrade_replay(binding, terminal_journal)
            if (
                terminal_journal.stage == "verification_failed_terminal"
                and terminal_journal.last_known_state == "activation-fallback"
            ):
                raise UpgradeActivationReverted(
                    "the existing upgrade operation already completed with an "
                    "activation fallback; the artifact was not uploaded again"
                )
            error = RuntimeError(
                "a matching upgrade operation already reached terminal failure; "
                "the artifact was not uploaded again"
            )
            error.mutation_journal_stage = terminal_journal.stage
            error.mutation_effects_started = terminal_journal.effects_started
            raise error
        require_effect_recovery_journal(
            effect_recovery_mode(arguments), matching_journals,
            operation_id=context.operation_id, action="upgrade", label="Upgrade",
        )
        shared_artifact = arguments.get("_artifact_source")
        if shared_artifact is not None and not isinstance(
            shared_artifact, _SharedArtifactSource
        ):
            raise TypeError("_artifact_source must be an internal artifact source")
        if isinstance(shared_artifact, _SharedArtifactSource):
            artifact_bytes = None
            snapshot = shared_artifact.snapshot()
            actual_sha = snapshot.sha256
            actual_size = snapshot.size
        else:
            artifact_bytes, actual_sha = _read_stable_artifact(artifact_path)
            actual_size = len(artifact_bytes)
        if actual_sha != artifact.sha256:
            raise ValueError("upgrade artifact SHA-256 does not match")
        validate_artifact_metadata(
            artifact_path,
            expected_sha256=artifact.sha256,
            product_version=artifact.product_version,
            actual_size=actual_size,
        )
        protocol_discovery_error: Exception | None = None
        resolved_protocol = selected_protocol
        resolved_verification = selected_verification
        if not mutation_options or selected_protocol == "auto":
            try:
                plan = self._discover_upgrade_plan(binding, arguments, context)
                resolved_protocol = str(plan.get("protocol", ""))
                resolved_verification = _resolved_verification_mode(
                    arguments,
                    resolved_protocol,
                )
                if not mutation_options:
                    mutation_options = _resolved_mutation_options(
                        arguments,
                        protocol=resolved_protocol,
                        verification_mode=resolved_verification,
                    )
            except Exception as exc:
                protocol_discovery_error = exc
                resolved_protocol = _upgrade_protocol(arguments)
                resolved_verification = _verification_mode(arguments)
                mutation_options = mutation_options or _mutation_options(arguments)
        selected_protocol = resolved_protocol
        selected_verification = resolved_verification
        operation_arguments.update(
            upgrade_protocol=selected_protocol,
            verification_mode=selected_verification,
        )
        mutation_fingerprint = adapter.mutation_request(
            operation_id=context.operation_id,
            artifact=artifact,
            mutation_options=mutation_options,
        ).fingerprint
        if operation_state is None and protocol_discovery_error is None:
            operation_state = self.operation_state_store.initialize(
                task_id=task.task_id,
                operation_id=context.operation_id,
                protocol=selected_protocol,
                verification_mode=selected_verification,
                artifact_file_name=Path(artifact.path).name,
                mutation_fingerprint=mutation_fingerprint,
            )
        mutation_observation: dict[str, object] = {}

        def record_operation_state(values: Mapping[str, object]) -> None:
            self.operation_state_store.update(
                task_id=task.task_id,
                operation_id=context.operation_id,
                values=values,
            )

        def apply(execution) -> dict[str, object]:
            if protocol_discovery_error is not None:
                raise protocol_discovery_error
            # Bind the verified artifact to the durable MutationJournal before
            # crossing the upload effect boundary.  The Runtime Domain Pack
            # verifier uses this receipt to reject results that cannot be
            # tied to the requested HPM identity.
            execution.mutation.journal.record_execution_evidence(
                expected_checksum=artifact.sha256,
            )
            if selected_verification == "manager-version":
                baseline = execution.redfish_request(
                    "upgrade-manager-baseline", replay_safe=True,
                    callback=self._installed_version,
                )
                execution.mutation.record_target_identity(
                    _manager_target_identity(baseline, previous=execution.journal.target_identity)
                )
                mutation_observation["manager_before"] = baseline
            result = execution.redfish_request(
                "upgrade-upload",
                callback=lambda session: self._apply_with_session(
                    session,
                    artifact,
                    artifact_bytes,
                    operation_arguments,
                    context,
                    execution.mark_effects_started,
                    record_operation_state=record_operation_state,
                    artifact_source=shared_artifact,
                ),
            )
            mutation_observation.update(result)
            return result

        def read_verification(verification):
            effective_mode = selected_verification
            if effective_mode == "auto":
                effective_mode = (
                    "task-completion"
                    if mutation_observation.get("protocol") == "webui"
                    else "manager-version"
                )
            if effective_mode == "task-completion":
                return self._wait_for_webui_task_completion(
                    verification,
                    context,
                    artifact,
                    mutation_observation,
                )
            return self._wait_for_installed_version(
                verification,
                context,
                operation_arguments,
                mutation_observation,
            )
        result = adapter.run(
            operation_id=context.operation_id,
            authorization=authorization,
            artifact=artifact,
            apply=apply,
            read_installed_version=read_verification,
            debug_verify=None,
            mutation_options=mutation_options,
            operation_context=context,
        )
        if (
            result.journal.stage == "verification_failed_terminal"
            and result.journal.last_known_state == "activation-fallback"
        ):
            raise UpgradeActivationReverted(
                "the existing upgrade operation already completed with an "
                "activation fallback; the artifact was not uploaded again"
            )
        context.raise_if_stopped()
        return result.to_public_dict()

    def upgrade_run(
        self,
        task: _UpgradeTask,
        arguments: Mapping[str, object],
        context,
    ) -> dict[str, object]:
        """Run one upgrade transaction through the existing deep module."""

        return self._upgrade_one(task, arguments, context)

    @staticmethod
    def _batch_child_context(
        context,
        operation_id: str,
        timeout_seconds: float | None = None,
    ):
        derive = getattr(context, "derive", None)
        parent = derive(operation_id) if callable(derive) else context

        class _ChildContext:
            def __init__(
                self,
                selected_parent,
                child_id: str,
                timeout: float | None,
            ) -> None:
                self._parent = selected_parent
                self.operation_id = child_id
                self.task_id = getattr(selected_parent, "task_id", "")
                self._deadline_at = (
                    time.monotonic() + float(timeout)
                    if timeout is not None
                    else None
                )

            def remaining(self) -> float:
                parent_remaining = float(self._parent.remaining())
                if self._deadline_at is None:
                    return parent_remaining
                return max(
                    0.0,
                    min(parent_remaining, self._deadline_at - time.monotonic()),
                )

            def raise_if_stopped(self) -> None:
                self._parent.raise_if_stopped()
                if self.remaining() <= 0:
                    raise OperationDeadlineExceeded(
                        f"operation {self.operation_id} exceeded its target deadline"
                    )

            def wait(self, seconds: float) -> None:
                self.raise_if_stopped()
                self._parent.wait(min(max(0.0, seconds), self.remaining()))
                self.raise_if_stopped()

            def __getattr__(self, name: str):
                return getattr(self._parent, name)

        return _ChildContext(parent, operation_id, timeout_seconds)

    @staticmethod
    def _batch_journal_status(journal: object) -> str:
        if not isinstance(journal, Mapping):
            return ""
        status = mutation_journal_operation_status(journal, action="upgrade")
        if status == "completed":
            return "completed"
        if status == "failed":
            return "failed"
        if status in {"blocked", "mutation_outcome_unknown"}:
            return (
                "unknown"
                if bool(journal.get("effects_started", False))
                else "failed"
            )
        return ""

    @classmethod
    def _batch_error_status(
        cls,
        error: BaseException,
        journal: object = None,
    ) -> str:
        journal_status = cls._batch_journal_status(journal)
        if journal_status:
            return journal_status
        annotated_stage = str(
            getattr(error, "mutation_journal_stage", "")
        ).strip()
        if annotated_stage:
            annotated_status = cls._batch_journal_status(
                {
                    "stage": annotated_stage,
                    "effects_started": bool(
                        getattr(error, "mutation_effects_started", False)
                    ),
                }
            )
            if annotated_status:
                return annotated_status
        outcome = str(getattr(error, "mutation_outcome", "")).strip().lower()
        if outcome == "unknown":
            return "unknown"
        if outcome == "applied":
            return "unknown"
        recovery_status = getattr(error, "recovery_status", None)
        if isinstance(recovery_status, Mapping):
            status = mutation_journal_operation_status(recovery_status)
            if status == "mutation_outcome_unknown":
                return "unknown"
        if bool(getattr(error, "mutation_effects_started", False)) and isinstance(
            error, (OSError, TimeoutError, ConnectionError)
        ):
            return "unknown"
        return "failed"

    @staticmethod
    def _batch_error_message(
        error: BaseException,
        arguments: Mapping[str, object],
    ) -> str:
        message = str(error)[:2048]
        secret = arguments.get("redfish_password")
        if isinstance(secret, str) and secret:
            message = message.replace(secret, "<redacted>")
        values = arguments.get("_credential_values")
        if isinstance(values, Mapping):
            for name, value in values.items():
                if (
                    isinstance(name, str)
                    and "PASSWORD" in name.upper()
                    and isinstance(value, str)
                    and value
                ):
                    message = message.replace(value, "<redacted>")
        return message

    @staticmethod
    def _batch_failure_evidence(
        task: _UpgradeTask,
        arguments: Mapping[str, object],
        operation_id: str,
        error: BaseException,
    ) -> tuple[str, dict[str, object] | None]:
        try:
            binding = task.binding_for(arguments)
        except Exception:
            return "", None
        try:
            journals = [
                journal
                for journal in binding.task_run.mutation_journals()
                if journal.action == "upgrade"
                and journal.target_fingerprint == binding.target.fingerprint
            ]
            annotated_stage = str(
                getattr(error, "mutation_journal_stage", "")
            ).strip()
            selected = next(
                (
                    journal
                    for journal in journals
                    if journal.operation_id == operation_id
                ),
                next(
                    (
                        journal
                        for journal in reversed(journals)
                        if not journal.terminal
                    ),
                    next(
                        (
                            journal
                            for journal in reversed(journals)
                            if annotated_stage and journal.stage == annotated_stage
                        ),
                        None,
                    ),
                ),
            )
            public = selected.to_public_dict() if selected is not None else None
        except Exception:
            public = None
        return binding.target.fingerprint, public

    def authenticate_batch_journals(self, task, arguments, context, value):
        """Bind replayed child journals to the request using durable local state."""
        bindings: list[tuple[str, str]] = []
        requested = arguments.get("targets", [])
        returned = value.get("targets", [])
        if not isinstance(requested, list) or not isinstance(returned, list):
            raise ValueError("batch journal authentication requires target arrays")
        if len(requested) != len(returned):
            raise ValueError("batch journal target count changed")
        for index, (raw, item) in enumerate(zip(requested, returned, strict=True), start=1):
            if not isinstance(raw, Mapping) or not isinstance(item, Mapping):
                raise ValueError("invalid batch journal target")
            per_target = {**arguments, **raw}
            per_target.pop("targets", None)
            target_id = str(raw.get("target_id", f"target-{index}")).strip()
            host = _canonical_batch_host(per_target.get("ip", ""))
            port = per_target.get("redfish_port", 443)
            suffix = hashlib.sha256(f"{target_id}\0{host}\0{port}".encode()).hexdigest()[:20]
            requested_id = f"{context.operation_id}:target-{suffix}"
            if len(requested_id) > 128:
                requested_id = f"{context.operation_id[:80]}:target-{suffix}"
            journal = item.get("journal")
            if not isinstance(journal, Mapping):
                continue
            journal_id = str(journal.get("operation_id", ""))
            if journal_id == requested_id:
                continue
            stored = self.journal_store.load(context.task_id, journal_id)
            if stored is None or stored.to_public_dict() != dict(journal):
                raise ValueError("reconciled batch journal does not match durable state")
            binding = task.binding_for(per_target)
            if stored.target_fingerprint != binding.target.fingerprint:
                raise ValueError("reconciled batch journal belongs to another target")
            adapter = UpgradeRuntimeAdapter(
                task_run=binding.task_run,
                target=binding.target,
                redfish_selector=binding.redfish_selector,
                ssh_selector=binding.ssh_selector,
                redfish_transport=binding.transport,
            )
            artifact = UpgradeArtifact(
                path=str(Path(str(arguments["artifact_path"])).expanduser().absolute()),
                sha256=str(arguments["artifact_sha256"]),
                product_version=str(arguments["product_version"]),
            )
            if not any(
                adapter.mutation_request(
                    operation_id=journal_id, artifact=artifact, mutation_options=options,
                ).fingerprint == stored.operation_fingerprint
                for _protocol, _verification, options in self._candidate_mutation_options(per_target)
            ):
                raise ValueError("reconciled batch journal does not match upgrade parameters")
            bindings.append((requested_id, journal_id))
        return tuple(bindings)

    def upgrade_batch(
        self,
        task: _UpgradeTask,
        arguments: Mapping[str, object],
        context,
    ) -> dict[str, object]:
        """Run independent Upgrade transactions with bounded concurrency.

        The artifact identity and authorization are shared, while every target
        receives its own binding, Redfish lease, durable journal, and child
        operation identity.  A target failure is captured in the aggregate and
        never cancels sibling upgrades.
        """

        context.raise_if_stopped()
        raw_targets = arguments.get("targets")
        if (
            not isinstance(raw_targets, list)
            or not raw_targets
            or not all(isinstance(item, Mapping) for item in raw_targets)
        ):
            raise ValueError("targets must be a non-empty array of target objects")
        if len(raw_targets) > self.max_batch_targets:
            raise ValueError(
                f"targets must contain at most {self.max_batch_targets} items"
            )
        concurrency_limit = min(
            self.max_batch_concurrency,
            self.max_cached_bindings,
        )
        max_concurrency = _argument_positive_int(
            arguments,
            "max_concurrency",
            min(4, concurrency_limit),
            maximum=concurrency_limit,
        )
        legacy_target_deadline = _argument_timeout(arguments, "deadline", 600)
        target_deadline = _argument_timeout(
            arguments,
            "target_deadline",
            legacy_target_deadline,
        )
        preflight_timeout = _argument_timeout(
            arguments,
            "preflight_timeout",
            30,
        )
        preflight_enabled = _argument_bool(
            arguments,
            "preflight",
            default=True,
        )
        rollout_batch_size = _argument_positive_int(
            arguments,
            "rollout_batch_size",
            max_concurrency,
            maximum=concurrency_limit,
        )
        canary_count = _argument_nonnegative_int(
            arguments,
            "canary_count",
            0,
            maximum=len(raw_targets),
        )
        max_failures = _argument_nonnegative_int(
            arguments,
            "max_failures",
            len(raw_targets),
            maximum=len(raw_targets),
        )
        stop_on_unknown = _argument_bool(
            arguments,
            "stop_on_unknown",
            default=True,
        )

        common = dict(arguments)
        common.pop("targets", None)
        for control in (
            "max_concurrency",
            "target_deadline",
            "batch_deadline",
            "preflight",
            "preflight_timeout",
            "rollout_batch_size",
            "canary_count",
            "max_failures",
            "stop_on_unknown",
        ):
            common.pop(control, None)
        raw_minimum_epochs = common.pop("_minimum_target_epochs", {})
        if not isinstance(raw_minimum_epochs, Mapping):
            raise TypeError("_minimum_target_epochs must be an internal mapping")
        minimum_epochs: dict[str, int] = {}
        for target_id, epoch in raw_minimum_epochs.items():
            if (
                not isinstance(target_id, str)
                or isinstance(epoch, bool)
                or not isinstance(epoch, int)
                or epoch < 0
            ):
                raise TypeError(
                    "_minimum_target_epochs must map target IDs to non-negative integers"
                )
            minimum_epochs[target_id] = epoch
        artifact_path_text = _argument_text(common, "artifact_path")
        expected_sha = _argument_text(common, "artifact_sha256").lower()
        product_version = _argument_text(common, "product_version")
        if not artifact_path_text:
            raise ValueError("artifact_path must be provided")
        if re.fullmatch(r"[0-9a-f]{64}", expected_sha) is None:
            raise ValueError("artifact_sha256 must be 64 hexadecimal characters")
        if not product_version:
            raise ValueError("product_version must not be empty")
        artifact_path = Path(artifact_path_text).expanduser()
        artifact_path = Path(os.path.abspath(os.fspath(artifact_path)))
        artifact_source = _SharedArtifactSource(artifact_path)
        common["_artifact_source"] = artifact_source
        artifact = UpgradeArtifact(
            path=str(artifact_path),
            sha256=expected_sha,
            product_version=product_version,
        )

        target_arguments: list[tuple[str, str, dict[str, object]]] = []
        seen_targets: set[tuple[str, int]] = set()
        seen_ids: set[str] = set()
        for index, raw in enumerate(raw_targets, start=1):
            assert isinstance(raw, Mapping)
            host_value = raw.get("ip", common.get("ip", ""))
            host = str(host_value).strip() if isinstance(host_value, (str, int)) else ""
            canonical_host = _canonical_batch_host(host_value)
            if not host or not canonical_host:
                raise ValueError(f"targets[{index - 1}].ip must be provided")
            target_id_raw = raw.get("target_id", f"target-{index}")
            target_id = (
                str(target_id_raw).strip()
                if isinstance(target_id_raw, (str, int))
                else ""
            )
            if not target_id or not _BATCH_TARGET_ID_RE.fullmatch(target_id):
                raise ValueError(
                    f"targets[{index - 1}].target_id must be a safe identifier"
                )
            if target_id in seen_ids:
                raise ValueError(f"duplicate target_id in batch: {target_id}")
            seen_ids.add(target_id)
            raw_port = raw.get("redfish_port", common.get("redfish_port", 443))
            if isinstance(raw_port, bool) or not isinstance(raw_port, int):
                raise ValueError(f"targets[{index - 1}].redfish_port must be an integer")
            if not 1 <= raw_port <= 65535:
                raise ValueError(
                    f"targets[{index - 1}].redfish_port must be between 1 and 65535"
                )
            target_key = (canonical_host, int(raw_port))
            if target_key in seen_targets:
                raise ValueError(
                    f"duplicate Redfish target in batch: {host}:{raw_port}"
                )
            seen_targets.add(target_key)
            for field in ("artifact_path", "artifact_sha256", "product_version"):
                if field in raw and raw[field] != common.get(field):
                    raise ValueError(
                        f"targets[{index - 1}] cannot override shared {field}"
                    )
            per_target = dict(common)
            per_target.update(
                {
                    key: value
                    for key, value in raw.items()
                    if key
                    not in {
                        "targets",
                        "max_concurrency",
                        "artifact_path",
                        "artifact_sha256",
                        "product_version",
                        "deadline",
                        "target_deadline",
                        "batch_deadline",
                        "preflight",
                        "preflight_timeout",
                        "rollout_batch_size",
                        "canary_count",
                        "max_failures",
                        "stop_on_unknown",
                    }
                }
            )
            per_target["ip"] = host
            per_target["redfish_port"] = int(raw_port)
            per_target["target_id"] = target_id
            per_target["_minimum_target_epoch"] = minimum_epochs.get(target_id, 0)
            target_digest = hashlib.sha256(
                f"{target_id}\0{canonical_host}\0{raw_port}".encode("utf-8")
            ).hexdigest()[:20]
            child_id = f"{context.operation_id}:target-{target_digest}"
            if len(child_id) > 128:
                child_id = f"{context.operation_id[:80]}:target-{target_digest}"
            target_arguments.append((target_id, child_id, per_target))

        preflight_by_id: dict[str, dict[str, object]] = {}

        def preflight_one(
            item: tuple[str, str, dict[str, object]],
        ) -> tuple[str, dict[str, object]]:
            target_id, child_id, per_target = item
            try:
                preflight_id = f"{child_id[:117]}:preflight"
                child_context = self._batch_child_context(
                    context,
                    preflight_id,
                    preflight_timeout,
                )
                child_context.raise_if_stopped()
                binding = task.binding_for(per_target)
                adapter = UpgradeRuntimeAdapter(
                    task_run=binding.task_run,
                    target=binding.target,
                    redfish_selector=binding.redfish_selector,
                    ssh_selector=binding.ssh_selector,
                    redfish_transport=binding.transport,
                )
                selected_protocol = ""
                selected_verification = ""
                mutation_options: dict[str, object] = {}
                matches: list[object] = []
                for protocol, verification_mode, candidate in self._candidate_mutation_options(
                    per_target
                ):
                    candidate_matches = self._matching_upgrade_journals(
                        binding,
                        adapter,
                        artifact,
                        candidate,
                    )
                    if candidate_matches:
                        selected_protocol = protocol
                        selected_verification = verification_mode
                        mutation_options = candidate
                        matches = candidate_matches
                        break
                unfinished = next(
                    (
                        journal
                        for journal in matches
                        if not journal.terminal
                        and journal.stage != "replan_required"
                    ),
                    None,
                )
                terminal = next(
                    (journal for journal in matches if journal.terminal),
                    None,
                )
                if terminal is not None and unfinished is None:
                    terminal_status = mutation_journal_operation_status(
                        terminal,
                        action="upgrade",
                    )
                    if terminal_status == "completed":
                        return target_id, {
                            "status": "ready",
                            "mode": "terminal_replay",
                            "target_fingerprint": binding.target.fingerprint,
                            "journal": terminal.to_public_dict(),
                        }
                    raise RuntimeError(
                        "a matching upgrade operation already reached terminal "
                        "failure; the artifact will not be uploaded again"
                    )
                lane = binding.task_run.redfish_lane(
                    target=binding.target,
                    credential_selector=binding.redfish_selector,
                    lease_name="upgrade",
                    transport=binding.transport,
                )

                def inspect(session) -> dict[str, object]:
                    child_context.raise_if_stopped()
                    if unfinished is not None:
                        if selected_protocol == "webui":
                            probe = self._probe_webui(session)
                            return {
                                "mode": "recovery",
                                "upgrade_protocol": "webui",
                                "verification_mode": selected_verification,
                                "webui_probe": probe,
                            }
                        installed = self._installed_version(session)
                        activation = self._activation_state(
                            session,
                            manager_version=str(installed["version"]),
                            expected_version=artifact.product_version,
                        )
                        return {
                            "mode": "recovery",
                            "installed_version": installed["version"],
                            "activation": activation,
                        }
                    if _upgrade_protocol(per_target) == "webui":
                        update_payload: Mapping[str, object] = {}
                    else:
                        discovery = session.request_json(
                            "GET",
                            "/redfish/v1/UpdateService",
                        )
                        if not isinstance(discovery.payload, Mapping):
                            raise ValueError(
                                "Redfish UpdateService response must be an object"
                            )
                        update_payload = discovery.payload
                    plan = _upgrade_upload_plan(update_payload, per_target)
                    protocol = str(plan.get("protocol", "redfish"))
                    verification_mode = _resolved_verification_mode(
                        per_target,
                        protocol,
                    )
                    webui_probe = (
                        self._probe_webui(session)
                        if protocol == "webui"
                        else None
                    )
                    installed = self._installed_version(session)
                    return {
                        "mode": "upload",
                        "upgrade_protocol": protocol,
                        "verification_mode": verification_mode,
                        "installed_version": installed["version"],
                        "upload_method": plan["method"],
                        "upload_encoding": plan["encoding"],
                        "compatibility_mode": plan["compatibility_mode"],
                        "staged_activation": plan["staged_activation"],
                        "webui_probe": webui_probe,
                    }

                details = lane.request(
                    "upgrade-batch-preflight",
                    replay_safe=True,
                    callback=inspect,
                )
                child_context.raise_if_stopped()
                return target_id, {
                    "status": "ready",
                    "target_fingerprint": binding.target.fingerprint,
                    "journal": (
                        unfinished.to_public_dict()
                        if unfinished is not None
                        else None
                    ),
                    **details,
                }
            except Exception as exc:
                target_fingerprint, journal = self._batch_failure_evidence(
                    task,
                    per_target,
                    child_id,
                    exc,
                )
                return target_id, {
                    "status": self._batch_error_status(exc, journal),
                    "mode": "preflight_failed",
                    "error": type(exc).__name__,
                    "message": self._batch_error_message(exc, per_target),
                    "target_fingerprint": target_fingerprint,
                    "journal": journal,
                }

        if preflight_enabled:
            for offset in range(0, len(target_arguments), self.max_cached_bindings):
                wave = target_arguments[offset : offset + self.max_cached_bindings]
                with ThreadPoolExecutor(
                    max_workers=min(max_concurrency, len(wave)),
                    thread_name_prefix="openubmc-upgrade-preflight",
                ) as pool:
                    futures = [pool.submit(preflight_one, item) for item in wave]
                    for future in as_completed(futures):
                        target_id, result = future.result()
                        preflight_by_id[target_id] = result
        else:
            preflight_by_id = {
                target_id: {"status": "ready", "mode": "disabled"}
                for target_id, _child, _args in target_arguments
            }

        def skipped_result(
            item: tuple[str, str, dict[str, object]],
            *,
            message: str,
            preflight: Mapping[str, object],
        ) -> dict[str, object]:
            target_id, child_id, per_target = item
            return {
                "target_id": target_id,
                "ip": per_target["ip"],
                "redfish_port": per_target["redfish_port"],
                "status": "skipped",
                "error": "BatchRolloutStopped",
                "message": message,
                "operation_id": child_id,
                "target_fingerprint": str(
                    preflight.get("target_fingerprint", "")
                ),
                "journal": preflight.get("journal"),
                "preflight": dict(preflight),
                "skipped": True,
            }

        def finalize(
            results_by_id: Mapping[str, dict[str, object]],
            *,
            stop_reason: str = "",
        ) -> dict[str, object]:
            results = [
                results_by_id[target_id]
                for target_id, _child, _args in target_arguments
            ]
            for item, (_target_id, child_id, _arguments) in zip(results, target_arguments, strict=True):
                item["requested_operation_id"] = child_id
                result = item.get("result")
                journal = result.get("journal") if isinstance(result, Mapping) else item.get("journal")
                if isinstance(journal, Mapping) and journal.get("operation_id"):
                    journal_id = str(journal["operation_id"])
                    item["operation_id"] = journal_id
                    item["reconciled_existing_operation"] = journal_id != child_id
            succeeded = sum(item["status"] == "completed" for item in results)
            unknown = sum(item["status"] == "unknown" for item in results)
            failed = sum(item["status"] == "failed" for item in results)
            skipped = sum(bool(item.get("skipped", False)) for item in results)
            status = (
                "completed"
                if succeeded == len(results)
                else "unknown"
                if unknown == len(results)
                else "failed"
                if succeeded == 0 and unknown == 0 and failed == len(results)
                else "partial"
            )
            epoch_values = {
                str(item["target_id"]): int(item["result"]["epoch_after"])
                for item in results
                if item["status"] == "completed"
                and isinstance(item.get("result"), Mapping)
                and isinstance(item["result"].get("epoch_after"), int)
            }
            return {
                "ok": status == "completed",
                "status": status,
                "outcome_status": (
                    "succeeded" if status == "completed"
                    else "mutation_outcome_unknown" if unknown else "failed"
                ),
                "batch_operation_id": context.operation_id,
                "total": len(results),
                "succeeded": succeeded,
                "failed": failed,
                "unknown": unknown,
                "skipped": skipped,
                "max_concurrency": max_concurrency,
                "target_deadline": target_deadline,
                "preflight_enabled": preflight_enabled,
                "rollout_batch_size": rollout_batch_size,
                "canary_count": canary_count,
                "max_failures": max_failures,
                "stop_on_unknown": stop_on_unknown,
                "stop_reason": stop_reason,
                "target_epochs": epoch_values,
                "epoch_after": max(epoch_values.values(), default=0),
                "targets": results,
            }

        preflight_failures = {
            target_id: result
            for target_id, result in preflight_by_id.items()
            if result.get("status") != "ready"
        }
        if preflight_failures:
            aborted: dict[str, dict[str, object]] = {}
            for item in target_arguments:
                target_id, child_id, per_target = item
                preflight = preflight_by_id[target_id]
                if target_id in preflight_failures:
                    aborted[target_id] = {
                        "target_id": target_id,
                        "ip": per_target["ip"],
                        "redfish_port": per_target["redfish_port"],
                        "status": preflight["status"],
                        "error": preflight.get("error", "BatchPreflightFailed"),
                        "message": preflight.get("message", "batch preflight failed"),
                        "operation_id": child_id,
                        "target_fingerprint": preflight.get(
                            "target_fingerprint", ""
                        ),
                        "journal": preflight.get("journal"),
                        "preflight": dict(preflight),
                    }
                else:
                    aborted[target_id] = skipped_result(
                        item,
                        message=(
                            "batch mutation was not started because another target "
                            "failed the all-target preflight"
                        ),
                        preflight=preflight,
                    )
            return finalize(aborted, stop_reason="preflight_failed")

        # With preflight enabled, validate the shared artifact before any
        # worker can mutate a target.  When preflight is explicitly disabled,
        # retain lazy validation in _upgrade_one so callers that only exercise
        # recovery/journal paths do not need a local artifact up front.
        requires_artifact = preflight_enabled and any(
            result.get("mode") in {"upload", "disabled"}
            for result in preflight_by_id.values()
        )
        if requires_artifact:
            try:
                snapshot = artifact_source.snapshot()
                if snapshot.sha256 != expected_sha:
                    raise ValueError("upgrade artifact SHA-256 does not match")
                validate_artifact_metadata(
                    artifact_path,
                    expected_sha256=expected_sha,
                    product_version=product_version,
                    actual_size=snapshot.size,
                )
            except Exception as exc:
                failed_results = {
                    target_id: skipped_result(
                        item,
                        message=self._batch_error_message(exc, item[2]),
                        preflight=preflight_by_id[target_id],
                    )
                    for item in target_arguments
                    for target_id in (item[0],)
                }
                for value in failed_results.values():
                    value["error"] = type(exc).__name__
                return finalize(
                    failed_results,
                    stop_reason="artifact_preflight_failed",
                )

        def run_one(
            item: tuple[str, str, dict[str, object]],
        ) -> tuple[str, dict[str, object]]:
            target_id, child_id, per_target = item
            preflight = preflight_by_id[target_id]
            try:
                child_context = self._batch_child_context(
                    context,
                    child_id,
                    target_deadline,
                )
                result = self._upgrade_one(task, per_target, child_context)
            except Exception as exc:
                target_fingerprint, journal = self._batch_failure_evidence(
                    task,
                    per_target,
                    child_id,
                    exc,
                )
                return target_id, {
                    "target_id": target_id,
                    "ip": per_target["ip"],
                    "redfish_port": per_target["redfish_port"],
                    "status": self._batch_error_status(exc, journal),
                    "error": type(exc).__name__,
                    "message": self._batch_error_message(exc, per_target),
                    "operation_id": child_id,
                    "target_fingerprint": target_fingerprint,
                    "journal": journal,
                    "preflight": dict(preflight),
                }
            journal = result.get("journal")
            result_status = self._batch_journal_status(journal) or "completed"
            return target_id, {
                "target_id": target_id,
                "ip": per_target["ip"],
                "redfish_port": per_target["redfish_port"],
                "status": result_status,
                "operation_id": result.get("operation_id", child_id),
                "requested_operation_id": child_id,
                "target_fingerprint": result.get("target_fingerprint", ""),
                "journal": journal,
                "preflight": dict(preflight),
                "result": result,
            }

        execution_groups: list[tuple[bool, list[tuple[str, str, dict[str, object]]]]] = []
        cursor = 0
        while cursor < canary_count:
            end = min(canary_count, cursor + rollout_batch_size)
            execution_groups.append((True, target_arguments[cursor:end]))
            cursor = end
        while cursor < len(target_arguments):
            end = min(len(target_arguments), cursor + rollout_batch_size)
            execution_groups.append((False, target_arguments[cursor:end]))
            cursor = end

        results_by_id: dict[str, dict[str, object]] = {}
        stop_reason = ""
        for is_canary, group in execution_groups:
            with ThreadPoolExecutor(
                max_workers=min(max_concurrency, len(group)),
                thread_name_prefix="openubmc-upgrade",
            ) as pool:
                futures = [pool.submit(run_one, item) for item in group]
                for future in as_completed(futures):
                    target_id, result = future.result()
                    results_by_id[target_id] = result
            group_results = [results_by_id[item[0]] for item in group]
            cumulative_failed = sum(
                item["status"] == "failed" for item in results_by_id.values()
            )
            cumulative_unknown = sum(
                item["status"] == "unknown" for item in results_by_id.values()
            )
            if is_canary and any(
                item["status"] != "completed" for item in group_results
            ):
                stop_reason = "canary_failed"
            elif stop_on_unknown and cumulative_unknown:
                stop_reason = "unknown_target_requires_reconciliation"
            elif cumulative_failed > max_failures:
                stop_reason = "failure_threshold_exceeded"
            if stop_reason:
                break

        if stop_reason:
            for item in target_arguments:
                target_id = item[0]
                if target_id in results_by_id:
                    continue
                results_by_id[target_id] = skipped_result(
                    item,
                    message=(
                        "target was not admitted because the rollout stop policy "
                        f"triggered: {stop_reason}"
                    ),
                    preflight=preflight_by_id[target_id],
                )
        return finalize(results_by_id, stop_reason=stop_reason)

    def _recover_uncertain_upgrade(
        self,
        *,
        binding: _UpgradeBinding,
        adapter: UpgradeRuntimeAdapter,
        journal,
        artifact: UpgradeArtifact,
        authorization: MutationAuthorization,
        arguments: Mapping[str, object],
        context,
        mutation_options: Mapping[str, object],
    ) -> dict[str, object] | None:
        """Classify one durable uncertain upload before any possible re-upload."""

        recovery_protocol = str(mutation_options.get("upgrade_protocol", "redfish"))
        if recovery_protocol == "auto":
            operation_state = self.operation_state_store.load(
                journal.task_id,
                journal.operation_id,
            )
            if operation_state is None:
                error = RuntimeError(
                    "legacy auto upgrade journal has no durable resolved protocol; "
                    "recovery cannot safely guess a transport"
                )
                error.mutation_outcome = "unknown"
                error.mutation_journal_stage = journal.stage
                error.mutation_effects_started = journal.effects_started
                raise error
            if (
                operation_state.get("mutation_fingerprint")
                != journal.operation_fingerprint
                or operation_state.get("artifact_file_name")
                != Path(artifact.path).name
            ):
                error = RuntimeError(
                    "Upgrade operation state does not match the uncertain journal"
                )
                error.mutation_outcome = "unknown"
                error.mutation_journal_stage = journal.stage
                error.mutation_effects_started = journal.effects_started
                raise error
            recovery_protocol = str(operation_state.get("protocol", ""))
            if recovery_protocol not in {"redfish", "webui"}:
                error = RuntimeError(
                    "Upgrade operation state has no valid resolved protocol"
                )
                error.mutation_outcome = "unknown"
                error.mutation_journal_stage = journal.stage
                error.mutation_effects_started = journal.effects_started
                raise error
        if recovery_protocol == "webui":
            return self._recover_uncertain_webui_upgrade(
                binding=binding,
                adapter=adapter,
                journal=journal,
                artifact=artifact,
                authorization=authorization,
                arguments=arguments,
                context=context,
                mutation_options=mutation_options,
            )

        lane = binding.task_run.redfish_lane(
            target=binding.target,
            credential_selector=binding.redfish_selector,
            lease_name="upgrade",
            transport=binding.transport,
        )

        def inspect_session(session) -> dict[str, object]:
            installed = self._installed_version(session)
            current = str(installed["version"])
            activation = self._activation_state(
                session,
                manager_version=current,
                expected_version=artifact.product_version,
            )
            return {
                "current_version": current,
                "activation": activation,
            }

        inspection = lane.request(
            "upgrade-recovery-inspection",
            replay_safe=True,
            callback=inspect_session,
        )
        current = str(inspection.get("current_version", ""))
        activation = inspection.get("activation")
        activation = activation if isinstance(activation, Mapping) else {}
        pending = bool(activation.get("activation_pending", False))
        expected_locations = activation.get("expected_locations", [])
        expected_locations = (
            list(expected_locations)
            if isinstance(expected_locations, list)
            else []
        )
        if (
            current != artifact.product_version
            and not pending
            and not expected_locations
        ):
            journal.mark_effects_rejected()
            journal.transition(
                "replan_required",
                verification_state="not_started",
                last_known_state="upgrade-recovery-found-no-artifact-effect",
                recovery_decision="replan",
            )
            return {
                "operation_id": journal.operation_id,
                "action": "upgrade",
                "target_fingerprint": binding.target.fingerprint,
                "epoch_before": journal.epoch_before,
                "epoch_after": journal.epoch_before,
                "mutation": {
                    "recovery": {
                        "decision": "replan",
                        "inspection": inspection,
                    }
                },
                "verification": None,
                "journal": journal.to_public_dict(),
                "idempotent_replay": False,
            }
        if (
            current != artifact.product_version
            and expected_locations
            and not pending
        ):
            journal.transition(
                "verification_failed_terminal",
                verification_state="failed",
                last_known_state="activation-fallback",
                recovery_decision="none",
            )
            raise UpgradeActivationReverted(
                "read-only Upgrade recovery found the requested artifact available "
                "but not active, with no pending activation"
            )
        journal.transition(
            "verification_failed",
            verification_state="failed",
            last_known_state=(
                "upgrade-recovery-found-installed-version"
                if current == artifact.product_version
                else "upgrade-recovery-found-pending-activation"
            ),
            recovery_decision="verify",
        )
        recovered = adapter.recover(
            operation_id=journal.operation_id,
            authorization=authorization,
            artifact=artifact,
            inspection={
                "target_reachable": True,
                "restart_observed": pending or current == artifact.product_version,
            },
            read_installed_version=lambda verification: self._wait_for_installed_version(
                verification,
                context,
                arguments,
                {
                    "monitor": {"state": "connection_lost"},
                    # Recovery must retain the pre-effect Manager identity.
                    # Without it, a target that was already on the requested
                    # version could be accepted immediately after a lost
                    # response, even though no fresh activation boundary was
                    # observed.
                    "manager_before": (
                        {
                            "version": journal.target_identity.firmware_id,
                            "last_reset_time": journal.target_identity.reboot_anchor,
                        }
                        if journal.target_identity is not None
                        else {}
                    ),
                },
            ),
            mutation_options=mutation_options,
            operation_context=context,
        )
        return {
            "operation_id": recovered.operation_id,
            "action": "upgrade",
            "target_fingerprint": binding.target.fingerprint,
            "epoch_before": recovered.journal.epoch_before,
            "epoch_after": (
                recovered.journal.epoch_after
                or recovered.journal.epoch_before + 1
            ),
            "mutation": {"recovery": recovered.to_public_dict()},
            "verification": recovered.verification,
            "journal": recovered.journal.to_public_dict(),
            "idempotent_replay": False,
        }

    def _recover_uncertain_webui_upgrade(
        self,
        *,
        binding: _UpgradeBinding,
        adapter: UpgradeRuntimeAdapter,
        journal,
        artifact: UpgradeArtifact,
        authorization: MutationAuthorization,
        arguments: Mapping[str, object],
        context,
        mutation_options: Mapping[str, object],
    ) -> dict[str, object]:
        lane = binding.task_run.redfish_lane(
            target=binding.target,
            credential_selector=binding.redfish_selector,
            lease_name="upgrade",
            transport=binding.transport,
        )
        artifact_name = Path(artifact.path).name
        operation_state = self.operation_state_store.load(
            journal.task_id,
            journal.operation_id,
        )
        if (
            operation_state is None
            or operation_state.get("protocol") != "webui"
            or operation_state.get("artifact_file_name") != artifact_name
            or operation_state.get("mutation_fingerprint")
            != journal.operation_fingerprint
        ):
            journal.transition(
                "verification_failed",
                verification_state="failed",
                last_known_state="webui-recovery-missing-correlation-evidence",
                recovery_decision="none",
            )
            error = RuntimeError(
                "WebUI recovery has no durable task correlation evidence and "
                "cannot safely accept a historical task"
            )
            error.mutation_outcome = "unknown"
            error.mutation_journal_stage = journal.stage
            error.mutation_effects_started = journal.effects_started
            raise error
        task_id = str(operation_state.get("task_id_remote", ""))
        task_uri = str(
            operation_state.get("task_uri", "")
            or "/UI/Rest/BMCSettings/UpdateService/UpdateProgress"
        )
        baseline_identities = operation_state.get("baseline_task_identities")

        def inspect_session(session) -> dict[str, object]:
            webui = _webui_session(session)
            result: dict[str, object] = {}
            try:
                webui.login()
                progress = webui.progress()
                tasks = _matching_webui_tasks(progress.payload, artifact_name)
                task_scoped = False
                if task_id:
                    try:
                        task_response = webui.progress(task_id)
                    except WebUiHttpError as exc:
                        if exc.status not in {404, 405}:
                            raise
                    else:
                        task_tasks = _matching_webui_tasks(
                            task_response.payload,
                            artifact_name,
                            allow_unnamed=True,
                        )
                        if task_tasks:
                            tasks = task_tasks
                            task_scoped = True
                if not task_scoped:
                    tasks = (
                        _webui_tasks_added_since(tasks, baseline_identities)
                        if isinstance(baseline_identities, list)
                        else []
                    )
                result = {
                    "state": _classify_webui_tasks(tasks),
                    "tasks": tasks,
                    "artifact_file_name": artifact_name,
                    "task_id": task_id,
                    "task_uri": task_uri,
                }
            finally:
                cleanup = _close_webui_session(session)
                if result:
                    result["cleanup"] = cleanup
                active_error = sys.exc_info()[1]
                if active_error is not None:
                    _attach_cleanup_evidence(active_error, cleanup)
            return result

        inspection = lane.request(
            "upgrade-webui-recovery-inspection",
            replay_safe=True,
            callback=inspect_session,
        )
        state = str(inspection.get("state", ""))
        if state == "not_found":
            journal.transition(
                "verification_failed",
                verification_state="failed",
                last_known_state="webui-recovery-found-no-matching-task",
                recovery_decision="none",
            )
            error = RuntimeError(
                "WebUI recovery found no matching task and cannot prove that the "
                "earlier upload had no remote effect"
            )
            error.mutation_outcome = "unknown"
            error.mutation_journal_stage = journal.stage
            error.mutation_effects_started = journal.effects_started
            cleanup = inspection.get("cleanup")
            if isinstance(cleanup, Mapping):
                _attach_cleanup_evidence(error, cleanup)
            raise error
        if state == "failed":
            journal.transition(
                "verification_failed_terminal",
                verification_state="failed",
                last_known_state="webui-upgrade-task-failed",
                recovery_decision="none",
            )
            error = RuntimeError(
                "read-only WebUI recovery found a failed upgrade task: "
                + json.dumps(inspection.get("tasks", []), ensure_ascii=False)
            )
            error.mutation_journal_stage = journal.stage
            error.mutation_effects_started = journal.effects_started
            cleanup = inspection.get("cleanup")
            if isinstance(cleanup, Mapping):
                _attach_cleanup_evidence(error, cleanup)
            raise error
        journal.transition(
            "verification_failed",
            verification_state="failed",
            last_known_state=(
                "webui-recovery-found-completed-task"
                if state == "completed"
                else "webui-recovery-found-running-task"
            ),
            recovery_decision="verify",
        )
        recovered = adapter.recover(
            operation_id=journal.operation_id,
            authorization=authorization,
            artifact=artifact,
            inspection={"target_reachable": True, "restart_observed": True},
            read_installed_version=lambda verification: (
                self._wait_for_installed_version(
                    verification, context, arguments,
                    {"manager_before": {
                        "version": journal.target_identity.firmware_id,
                        "last_reset_time": journal.target_identity.reboot_anchor,
                    } if journal.target_identity is not None else {}},
                )
                if mutation_options.get("verification_mode") == "manager-version"
                else self._wait_for_webui_task_completion(
                    verification,
                    self._batch_child_context(context, journal.operation_id),
                    artifact,
                    {"task_id": task_id, "task_uri": task_uri},
                )
            ),
            mutation_options=mutation_options,
            operation_context=context,
        )
        return {
            "operation_id": recovered.operation_id,
            "action": "upgrade",
            "target_fingerprint": binding.target.fingerprint,
            "epoch_before": recovered.journal.epoch_before,
            "epoch_after": (
                recovered.journal.epoch_after
                or recovered.journal.epoch_before + 1
            ),
            "mutation": {
                "recovery": recovered.to_public_dict(),
                "inspection": inspection,
            },
            "verification": recovered.verification,
            "journal": recovered.journal.to_public_dict(),
            "idempotent_replay": False,
        }

    def _apply_with_session(
        self,
        session,
        artifact: UpgradeArtifact,
        artifact_bytes: bytes | None,
        arguments: Mapping[str, object],
        context,
        mark_effects_started: Callable[[], None],
        record_operation_state: Callable[[Mapping[str, object]], None]
        | None = None,
        artifact_source: _SharedArtifactSource | None = None,
    ) -> dict[str, object]:
        configured_upload_timeout = _argument_timeout(
            arguments,
            "upload_timeout",
            600,
        )
        if _upgrade_protocol(arguments) == "webui":
            update_payload: Mapping[str, object] = {}
        else:
            discovery = session.request_json("GET", "/redfish/v1/UpdateService")
            if not isinstance(discovery.payload, Mapping):
                raise ValueError("Redfish UpdateService response must be an object")
            update_payload = discovery.payload
        plan = _upgrade_upload_plan(update_payload, arguments)
        protocol = str(plan.get("protocol", "redfish"))
        _resolved_verification_mode(arguments, protocol)
        upload_timeout = min(
            configured_upload_timeout,
            context.remaining(),
        )
        if upload_timeout <= 0:
            context.raise_if_stopped()
        legacy_multipart = bool(plan["legacy_multipart"])
        simple_update_target = str(plan["simple_update_target"])
        staged_image_uri = str(plan["image_uri"])
        record_state = record_operation_state or (lambda _values: None)
        webui_result: dict[str, object] | None = None
        primary_error: BaseException | None = None
        try:
            try:
                upload = self._upload(
                    session,
                    update_payload,
                    artifact,
                    artifact_bytes,
                    arguments,
                    upload_timeout=upload_timeout,
                    mark_effects_started=mark_effects_started,
                    record_operation_state=record_state,
                    artifact_source=artifact_source,
                )
            except (RedfishHttpError, WebUiHttpError) as exc:
                if 400 <= exc.status < 500:
                    raise MutationEffectsRejected(
                        f"{protocol} upgrade request was explicitly rejected "
                        f"with HTTP {exc.status}: {exc}"
                    ) from exc
                raise
            if protocol == "webui":
                monitor = self._monitor_webui_task(
                    session,
                    artifact,
                    context,
                    task_id=str(upload.get("task_id", "")),
                    baseline_signature=tuple(
                        upload.pop("_baseline_task_signature", ())
                    ),
                    baseline_identities=tuple(
                        upload.pop("_baseline_task_identities", ())
                    ),
                )
                webui_result = {
                    **upload,
                    "monitor": monitor,
                    "staging_monitor": monitor,
                    "activation": None,
                    "artifact_path": artifact.path,
                    "artifact_sha256": artifact.sha256,
                    "product_version": artifact.product_version,
                }
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            if protocol == "webui":
                cleanup = _close_webui_session(session)
                try:
                    record_state({"cleanup": cleanup})
                except Exception as exc:
                    prior = str(cleanup.get("error", ""))
                    cleanup = {
                        **cleanup,
                        "completed": False,
                        "error": (
                            f"{prior}; " if prior else ""
                        )
                        + "operation state cleanup evidence failed: "
                        + f"{type(exc).__name__}: {exc}",
                    }
                if primary_error is not None:
                    _attach_cleanup_evidence(primary_error, cleanup)
                elif webui_result is not None:
                    webui_result["cleanup"] = cleanup
        if webui_result is not None:
            return webui_result
        staging_monitor = self._monitor_task(
            session,
            str(upload["task_uri"]),
            context,
        )
        activation: dict[str, object] | None = None
        monitor = staging_monitor
        if (
            legacy_multipart
            and simple_update_target
            and staged_image_uri
            and staging_monitor.get("state") in {"completed", "not_advertised"}
        ):
            activation = self._activate_staged_image(
                session,
                update_payload,
                staged_image_uri,
                context,
            )
            activation_monitor = activation.get("monitor")
            if isinstance(activation_monitor, Mapping):
                monitor = dict(activation_monitor)
            elif activation.get("state") == "connection_lost":
                monitor = {
                    "state": "activation_connection_lost",
                    "task_uri": "",
                    "error": activation.get("error", "unknown"),
                }
        return {
            **upload,
            "monitor": monitor,
            "staging_monitor": staging_monitor,
            "activation": activation,
            "image_uri": staged_image_uri or None,
            "artifact_path": artifact.path,
            "artifact_sha256": artifact.sha256,
            "product_version": artifact.product_version,
        }
