"""Same-origin openUBMC WebUI client used by the Upgrade backend."""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib
from http.cookiejar import CookieJar
import json
from pathlib import Path, PurePosixPath
import ssl
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest
import uuid


LOGIN_PATH = "/UI/Rest/Login"
UPLOAD_PATH = "/UI/Rest/FirmwareInventory"
START_PATH = "/UI/Rest/BMCSettings/UpdateService/FirmwareUpdate"
PROGRESS_PATH = "/UI/Rest/BMCSettings/UpdateService/UpdateProgress"


@dataclass(frozen=True)
class WebUiResponse:
    status: int
    headers: Mapping[str, str]
    payload: object


class WebUiHttpError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class WebUiTransportError(ConnectionError):
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
            f"WebUI {self.method} {path} lost its transport response "
            f"(request_bytes={request_bytes}, timeout_seconds={timeout:g}, "
            f"cause={self.cause_type})"
        )


def _url_origin(value: str) -> tuple[str, str, int]:
    parsed = urlparse.urlsplit(value)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").rstrip(".").lower()
    if scheme not in {"http", "https"} or not host:
        raise ValueError("WebUI redirect URI has no valid HTTP origin")
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, host, port


class SameOriginRedirectHandler(urlrequest.HTTPRedirectHandler):
    """Follow redirects only when scheme, host, and effective port are unchanged."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        resolved = urlparse.urljoin(req.full_url, newurl)
        if _url_origin(resolved) != _url_origin(req.full_url):
            raise urlerror.HTTPError(
                req.full_url,
                code,
                "redirect changed request origin",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, resolved)


def safe_upload_filename(filename: str) -> str:
    safe_name = Path(filename).name
    if (
        not safe_name
        or safe_name in {".", ".."}
        or '"' in safe_name
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in safe_name
        )
    ):
        raise ValueError("WebUI upload requires a safe artifact filename")
    return safe_name


def upload_multipart_parts(filename: str) -> tuple[bytes, bytes, str]:
    safe_name = safe_upload_filename(filename)
    boundary = "openubmc-webui-upgrade-" + uuid.uuid4().hex
    prefix = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="imgfile"; filename="{safe_name}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8")
    suffix = f"\r\n--{boundary}--\r\n".encode("ascii")
    return prefix, suffix, boundary


def uploaded_file_path(payload: object, filename: str) -> str:
    safe_name = Path(filename).name
    candidates: list[object] = []
    if isinstance(payload, Mapping):
        candidates.extend(
            payload.get(key)
            for key in ("FilePath", "file_path", "Path", "path")
        )
        result = payload.get("Result")
        if isinstance(result, Mapping):
            candidates.extend(
                result.get(key)
                for key in ("FilePath", "file_path", "Path", "path")
            )
    for value in candidates:
        if not isinstance(value, str) or not value.startswith("/tmp/web/"):
            continue
        path = PurePosixPath(value)
        if path.name == safe_name and ".." not in path.parts:
            return str(path)
    return f"/tmp/web/{safe_name}"


def task_id_from_start(payload: object) -> str:
    if not isinstance(payload, Mapping):
        return ""
    candidates = [
        payload.get("TaskId"),
        payload.get("task_id"),
        payload.get("url"),
        payload.get("@odata.id"),
    ]
    for value in candidates:
        if isinstance(value, int) and value >= 0:
            return str(value)
        if not isinstance(value, str) or not value:
            continue
        segment = value.rstrip("/").rsplit("/", 1)[-1]
        if segment.isdigit():
            return segment
    return ""


def normalized_tasks(payload: object) -> list[dict[str, object]]:
    raw_tasks: object
    if isinstance(payload, Mapping) and isinstance(payload.get("UpgradeTasks"), list):
        raw_tasks = payload["UpgradeTasks"]
    elif isinstance(payload, Mapping) and any(
        key in payload for key in ("TaskState", "ErrorCode", "Percentage")
    ):
        raw_tasks = [payload]
    else:
        raw_tasks = []
    tasks: list[dict[str, object]] = []
    for raw in raw_tasks if isinstance(raw_tasks, list) else []:
        if not isinstance(raw, Mapping):
            continue
        tasks.append(
            {
                key: raw.get(key)
                for key in (
                    "TaskName",
                    "Component",
                    "FileName",
                    "Percentage",
                    "TaskState",
                    "ErrorCode",
                    "Version",
                    "FirmwareId",
                )
            }
        )
    return tasks


def matching_tasks(
    payload: object,
    filename: str,
    *,
    allow_unnamed: bool = False,
) -> list[dict[str, object]]:
    tasks = normalized_tasks(payload)
    safe_name = Path(filename).name
    named = [task for task in tasks if isinstance(task.get("FileName"), str)]
    if not named:
        return tasks if allow_unnamed else []
    return [task for task in named if Path(str(task["FileName"])).name == safe_name]


def task_signature(tasks: list[dict[str, object]]) -> tuple[tuple[object, ...], ...]:
    return tuple(
        tuple(
            task.get(key)
            for key in (
                "TaskName",
                "Component",
                "FileName",
                "Percentage",
                "TaskState",
                "ErrorCode",
                "Version",
                "FirmwareId",
            )
        )
        for task in tasks
    )


def task_signature_digest(tasks: list[dict[str, object]]) -> str:
    payload = json.dumps(
        tasks,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


_TASK_IDENTITY_FIELDS = (
    "TaskName",
    "Component",
    "FileName",
    "FirmwareId",
    "Version",
)


def _task_identity_value(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _task_identity(task: Mapping[str, object]) -> tuple[str, ...]:
    return tuple(
        _task_identity_value(task.get(key)) for key in _TASK_IDENTITY_FIELDS
    )


def task_identity_signature(
    tasks: list[dict[str, object]],
) -> tuple[tuple[str, ...], ...]:
    """Return an order-independent multiset of stable task identities."""

    return tuple(sorted(_task_identity(task) for task in tasks))


def tasks_added_since(
    tasks: list[dict[str, object]],
    baseline: Iterable[Iterable[str]],
) -> list[dict[str, object]]:
    """Return conservative candidates from identities whose count increased."""

    baseline_identities: list[tuple[str, ...]] = []
    for identity in baseline:
        if isinstance(identity, (str, bytes)):
            raise ValueError("WebUI task identity baseline is malformed")
        normalized = tuple(identity)
        if len(normalized) != len(_TASK_IDENTITY_FIELDS) or not all(
            isinstance(value, str) for value in normalized
        ):
            raise ValueError("WebUI task identity baseline is malformed")
        baseline_identities.append(normalized)
    baseline_counts = Counter(baseline_identities)
    current_counts = Counter(_task_identity(task) for task in tasks)
    added_identities = {
        identity
        for identity, count in current_counts.items()
        if count > baseline_counts[identity]
    }
    return [task for task in tasks if _task_identity(task) in added_identities]


def has_new_task_identity(
    tasks: list[dict[str, object]],
    baseline: Iterable[Iterable[str]],
) -> bool:
    """Report whether current tasks contain an identity instance absent at baseline."""

    return bool(tasks_added_since(tasks, baseline))


def classify_tasks(tasks: list[dict[str, object]]) -> str:
    if not tasks:
        return "not_found"
    failure = {
        "exception",
        "failed",
        "warning",
        "killed",
        "cancelled",
        "interrupted",
        "suspended",
    }
    states = [str(task.get("TaskState") or "").strip().lower() for task in tasks]
    error_codes: list[int] = []
    for task in tasks:
        value = task.get("ErrorCode")
        if value is None or isinstance(value, bool):
            error_codes.append(-1)
            continue
        if isinstance(value, str) and not value.strip():
            error_codes.append(-1)
            continue
        try:
            error_codes.append(int(value))
        except (TypeError, ValueError):
            error_codes.append(-1)
    if any(code != 0 for code in error_codes) or any(state in failure for state in states):
        return "failed"
    if all(state == "completed" for state in states):
        return "completed"
    return "running"


class WebUiHttpSession:
    """Cookie and CSRF authenticated client for the target's private WebUI API."""

    def __init__(
        self,
        *,
        origin: str,
        username: str,
        password: str,
        verify_tls: bool = True,
        timeout: float = 30,
        redfish_request=None,
    ) -> None:
        self.origin = origin.rstrip("/")
        self.username = username
        self._password = password
        self.timeout = timeout
        self._redfish_request = redfish_request
        self._csrf_token = ""
        self._session_id = ""
        self._logged_in = False
        self.cookie_jar = CookieJar()
        context = (
            ssl.create_default_context()
            if verify_tls
            else ssl._create_unverified_context()  # noqa: SLF001
        )
        self.opener = urlrequest.build_opener(
            urlrequest.ProxyHandler({}),
            SameOriginRedirectHandler(),
            urlrequest.HTTPCookieProcessor(self.cookie_jar),
            urlrequest.HTTPSHandler(context=context),
        )

    @property
    def logged_in(self) -> bool:
        return self._logged_in

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            parsed = urlparse.urlsplit(path)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin.lower() != self.origin.lower():
                raise ValueError("WebUI response URI changed target origin")
            return path
        if not path.startswith("/"):
            raise ValueError("WebUI URI must be absolute on the selected target")
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
    ) -> WebUiResponse:
        if payload is not None and data is not None:
            raise ValueError("WebUI request cannot contain JSON and byte data together")
        request_headers = {"Accept": "application/json", **dict(headers or {})}
        if self._csrf_token:
            request_headers.setdefault("X-CSRF-Token", self._csrf_token)
            request_headers.setdefault("From", "WebUI")
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
            raise ValueError("WebUI request timeout must be positive")
        try:
            with self.opener.open(request, timeout=request_timeout) as response:
                raw = response.read()
                status = int(response.status)
                response_headers = dict(response.headers.items())
        except urlerror.HTTPError as exc:
            raw = exc.read()
            response_digest = hashlib.sha256(raw).hexdigest() if raw else ""
            message = f"WebUI request returned HTTP {exc.code}"
            if response_digest:
                message += f" (response_sha256={response_digest})"
            raise WebUiHttpError(exc.code, message) from exc
        except (OSError, TimeoutError, urlerror.URLError) as exc:
            raise WebUiTransportError(
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
        return WebUiResponse(status, response_headers, parsed)

    def login(self) -> WebUiResponse:
        if self._session_id and not self._logged_in:
            cleanup = self.close()
            if cleanup.get("completed") is not True:
                raise RuntimeError(
                    "previous WebUI session cleanup is still pending"
                )
        response = self.request_json(
            "POST",
            LOGIN_PATH,
            payload={
                "UserName": self.username,
                "Password": self._password,
                "Type": "Local",
                "Domain": "AutomaticMatching",
            },
        )
        payload = response.payload if isinstance(response.payload, Mapping) else {}
        response_headers = {
            str(name).lower(): value
            for name, value in response.headers.items()
        }
        token_candidates = (
            payload.get("Token"),
            payload.get("XCSRFToken"),
            response_headers.get("x-csrf-token"),
            response_headers.get("xcsrftoken"),
            response_headers.get("token"),
        )
        self._csrf_token = next(
            (str(value) for value in token_candidates if isinstance(value, str) and value),
            "",
        )
        session = payload.get("Session")
        if isinstance(session, Mapping):
            value = session.get("SessionID")
            if isinstance(value, (str, int)):
                self._session_id = str(value)
        if not self._session_id:
            for cookie in self.cookie_jar:
                if cookie.name.lower() == "sessionid" and cookie.value:
                    self._session_id = cookie.value
                    break
        if not self._csrf_token or not self._session_id:
            raise ValueError("WebUI login did not return its CSRF token and session")
        self._logged_in = True
        return response

    def progress(self, task_id: str = "") -> WebUiResponse:
        if not self._logged_in:
            raise RuntimeError("WebUI session is not logged in")
        path = PROGRESS_PATH
        if task_id:
            if not task_id.isdigit():
                raise ValueError("WebUI upgrade task id must be numeric")
            path += "/" + task_id
        return self.request_json("GET", path)

    def upload(
        self,
        *,
        body: bytes | Iterable[bytes],
        boundary: str,
        content_length: int,
        timeout: float,
    ) -> WebUiResponse:
        if not self._logged_in:
            raise RuntimeError("WebUI session is not logged in")
        return self.request_json(
            "POST",
            UPLOAD_PATH,
            data=body,
            headers={
                "Accept": "*/*",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(content_length),
            },
            timeout=timeout,
        )

    def start(self, file_path: str) -> WebUiResponse:
        if not self._logged_in:
            raise RuntimeError("WebUI session is not logged in")
        return self.request_json("POST", START_PATH, payload={"FilePath": file_path})

    def close(self) -> dict[str, object]:
        session_id = self._session_id
        evidence: dict[str, object] = {
            "attempted": bool(session_id),
            "completed": not bool(session_id),
            "http_status": 0,
            "error": "",
        }
        try:
            if session_id:
                if not callable(self._redfish_request):
                    evidence.update(
                        completed=False,
                        error="Redfish session cleanup transport is unavailable",
                    )
                else:
                    safe_id = urlparse.quote(session_id, safe="")
                    response = self._redfish_request(
                        "DELETE",
                        f"/redfish/v1/SessionService/Sessions/{safe_id}",
                    )
                    status = getattr(response, "status", None)
                    if isinstance(status, int):
                        evidence["http_status"] = status
                        evidence["completed"] = 200 <= status < 300 or status == 404
                        if not evidence["completed"]:
                            evidence["error"] = (
                                f"session cleanup returned HTTP {status}"
                            )
                    else:
                        evidence["completed"] = True
        except Exception as exc:
            status = getattr(exc, "status", 0)
            completed = status == 404
            evidence.update(
                completed=completed,
                http_status=status if isinstance(status, int) else 0,
                error=(
                    ""
                    if completed
                    else (
                        f"{type(exc).__name__}: HTTP {status}"
                        if isinstance(status, int) and status
                        else type(exc).__name__
                    )
                ),
            )
        finally:
            self._logged_in = False
            self._csrf_token = ""
            if evidence.get("completed") is True:
                self._session_id = ""
            self.cookie_jar.clear()
        return evidence


__all__ = [
    "PROGRESS_PATH",
    "SameOriginRedirectHandler",
    "WebUiHttpError",
    "WebUiHttpSession",
    "WebUiResponse",
    "WebUiTransportError",
    "classify_tasks",
    "has_new_task_identity",
    "matching_tasks",
    "normalized_tasks",
    "safe_upload_filename",
    "task_id_from_start",
    "task_identity_signature",
    "task_signature",
    "task_signature_digest",
    "tasks_added_since",
    "upload_multipart_parts",
    "uploaded_file_path",
]
