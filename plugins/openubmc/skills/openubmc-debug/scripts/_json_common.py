#!/usr/bin/env python3
"""Shared machine-readable payload helpers for openUBMC debug scripts."""
from __future__ import annotations

from datetime import datetime, timezone

SCHEMA_VERSION = "openubmc-debug.v1"


def normalize_code(code: str) -> str:
    return code.replace("-", "_")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_json_payload(
    *,
    tool: str,
    ip: str,
    ok: bool,
    code: str,
    returncode: int,
    request: dict[str, object] | None = None,
    result: dict[str, object] | None = None,
    warnings: list[str] | None = None,
    error: str = "",
    observed_at: str | None = None,
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": tool,
        "ip": ip,
        "observed_at": observed_at or utc_now(),
        "ok": ok,
        "code": code,
        "normalized_code": normalize_code(code),
        "returncode": returncode,
        "warnings": warnings or [],
        "error": error,
        "request": request or {},
        "result": result or {},
    }
