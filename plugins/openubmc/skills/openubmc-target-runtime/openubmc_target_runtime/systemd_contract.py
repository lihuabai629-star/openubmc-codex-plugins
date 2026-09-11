"""Literal, bounded system-manager service selection."""
import re
from collections.abc import Mapping
from .redaction import redact_text

UNIT = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.@:-]{0,246}\.service\Z')


def validate_systemd_names(names):
    if isinstance(names, (tuple, list)) and list(names) == ['failed']:
        return
    if (not isinstance(names, (tuple, list)) or not 1 <= len(names) <= 16
            or any(not isinstance(name, str) or not UNIT.fullmatch(name) for name in names)
            or len(set(names)) != len(names)):
        raise ValueError('systemd names require 1 to 16 distinct literal .service IDs or ["failed"]')


def systemd_unit_summaries(child):
    """Project short journal excerpts; retained source owns complete log bytes."""
    return [
        {"unit": item.get("unit"), "properties": item.get("properties", {}),
         "journal_lines": len(item.get("journal", [])),
         "journal_excerpt": [
             {"timestamp": row.get("__REALTIME_TIMESTAMP"),
              "message": redact_text(str(row.get("MESSAGE", "")))[:240]}
             for row in item.get("journal", [])[-3:] if isinstance(row, Mapping)
         ]}
        for item in child.get("units", []) if isinstance(item, Mapping)
    ]
