"""Shared secret-key filtering and text redaction for durable runtime output."""
from __future__ import annotations

import re
from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar


SECRET_KEY_TOKENS = (
    "password",
    "passwd",
    "secret",
    "credential",
    "token",
    "authorization",
    "cookie",
    "api_key",
    "api-key",
    "apikey",
    "private_key",
    "private-key",
    "privatekey",
    "passphrase",
)

NON_SECRET_SELECTOR_KEYS = frozenset(
    {
        "ssh_user_env",
        "ssh_password_env",
        "telnet_user_env",
        "telnet_password_env",
        "redfish_user_env",
        "redfish_password_env",
        "ssh_identity_file",
        "ssh_known_hosts_file",
        "authorization_policy",
        "authorized_exceptions",
        "credential_selector_fingerprint",
        "credential_selectors",
        "credential_source",
        "credential_parse_count",
    }
)


class SecretMaterialError(ValueError):
    """A model-visible or durable boundary received inline secret material."""

    code = "secret_material_rejected"


_REQUEST_SECRET_VALUES: ContextVar[tuple[str, ...] | None] = ContextVar(
    "openubmc_request_secret_values",
    default=None,
)

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)((?<![a-z0-9_.-])[\"']?[a-z0-9_.-]{0,128}"
    r"(?:password|passwd|passphrase|secret|token|authorization|cookie|"
    r"api[_-]?key|private[_-]?key)"
    r"[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}]+)"
)
_BEARER = re.compile(r"(?i)\bbearer\s+\S+")
_AUTHORIZATION_HEADER = re.compile(
    r"(?i)\bauthorization\s*[:=]\s*[^\r\n,;}]+"
)
_URI_USERINFO = re.compile(
    r"(?i)((?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,31}://)"
    r"[^\s/@:]+:[^\s/@]+@"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)


def is_secret_key(value: object) -> bool:
    """Return whether a mapping key contains secret material, not a selector."""

    lowered = str(value).strip().lower()
    return (
        lowered not in NON_SECRET_SELECTOR_KEYS
        and any(token in lowered for token in SECRET_KEY_TOKENS)
    )


def redact_text(value: object, *, secret_values: tuple[str, ...] = ()) -> str:
    """Redact common inline secret forms while preserving selector names."""

    text = str(value or "")
    active = _REQUEST_SECRET_VALUES.get() or ()
    for secret in sorted(set((*active, *secret_values)), key=len, reverse=True):
        if secret:
            text = text.replace(secret, "<redacted>")
    text = re.sub(
        r"(?i)(--(?:password|passwd|passphrase|secret|token|api-key)\s+)(?:\"[^\"]*\"|'[^']*'|\S+)",
        r"\1<redacted>", text,
    )
    text = _PRIVATE_KEY.sub("<private-key-redacted>", text)
    text = _AUTHORIZATION_HEADER.sub("Authorization: <redacted>", text)
    text = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}<redacted>",
        text,
    )
    text = _BEARER.sub("Bearer <redacted>", text)
    return _URI_USERINFO.sub(r"\1<redacted>@", text)


def register_secret_values(values: Mapping[str, object]) -> None:
    """Add locally resolved values to the current request's redaction set."""

    current = _REQUEST_SECRET_VALUES.get()
    if current is None:
        return
    discovered = {
        str(value)
        for key, value in values.items()
        if is_secret_key(key) and isinstance(value, str) and value
    }
    if discovered:
        _REQUEST_SECRET_VALUES.set(tuple(sorted(set(current) | discovered)))


def _redact_exception(exc: Exception) -> None:
    if not exc.args:
        return
    try:
        exc.args = tuple(
            redact_text(item) if isinstance(item, str) else item
            for item in exc.args
        )
    except (AttributeError, TypeError):
        pass


@contextmanager
def secret_redaction_request():
    """Keep locally resolved secrets available to every boundary in one call."""

    if _REQUEST_SECRET_VALUES.get() is not None:
        yield
        return
    token = _REQUEST_SECRET_VALUES.set(())
    try:
        yield
    except Exception as exc:
        _redact_exception(exc)
        raise
    finally:
        _REQUEST_SECRET_VALUES.reset(token)


def _secret_material_path(
    value: object,
    path: tuple[str, ...] = (),
) -> tuple[str, ...] | None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key)
            candidate = (*path, name)
            if is_secret_key(name):
                return candidate
            found = _secret_material_path(item, candidate)
            if found is not None:
                return found
        return None
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            found = _secret_material_path(item, (*path, str(index)))
            if found is not None:
                return found
        return None
    if isinstance(value, str) and redact_text(value) != value:
        return path or ("<text>",)
    return None


def require_secret_free(value: object, *, boundary: str) -> None:
    """Reject inline secrets before a model-visible or durable boundary."""

    if _secret_material_path(value) is None:
        return
    raise SecretMaterialError(
        f"secret material is not accepted by {boundary}; "
        "use a local credential reference"
    )
