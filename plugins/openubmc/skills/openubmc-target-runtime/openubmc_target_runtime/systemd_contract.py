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


def systemd_gap_details(child):
    """Keep access and scope failures distinct from temporal evidence gaps."""
    recovery = {
        'permission_denied': ('access', 'Use an authorized account with system-manager and journal read access, then recollect; retrying unchanged cannot grant access.'),
        'unit_not_found': ('scope', 'Verify the exact service ID and deployed component on this target, then recollect; absence is not a timing failure.'),
        'unsupported': ('capability', 'Verify that this target runs systemd and provides systemctl and journalctl; use another supported read-only evidence surface if unavailable.'),
        'transport_failed': ('transport', 'Restore the bound SSH transport before recollecting the same service scope.'),
        'deadline_exceeded': ('budget', 'Recollect within a sufficient bounded deadline after checking target responsiveness.'),
    }
    temporal = {'boot_changed', 'invocation_or_state_changed', 'journal_boot_mismatch', 'journal_invocation_mismatch'}
    details = []
    for gap in child.get('gaps', []):
        if not isinstance(gap, str):
            continue
        category, action = recovery.get(gap, (
            'freshness' if gap in temporal else 'collection',
            'Recollect complete evidence for the same boot and service invocation.' if gap in temporal
            else 'Inspect the reported collection boundary before selecting a corrected read-only observation.',
        ))
        details.append({'code': gap, 'category': category, 'recovery_action': action})
    return details


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
