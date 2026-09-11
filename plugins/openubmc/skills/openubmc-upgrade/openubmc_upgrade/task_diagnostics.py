"""Sanitized Redfish task evidence; firmware verification remains authoritative."""
from collections.abc import Mapping
from openubmc_target_runtime.redaction import redact_text


def safe_task_text(value, secrets: tuple[str, ...] = ()) -> str:
    text = str(value or '')
    for secret in secrets:
        if secret:
            text = text.replace(secret, '<redacted>')
    return redact_text(text)


def task_diagnostics(payload: Mapping[str, object], *, secrets: tuple[str, ...] = ()) -> dict[str, object]:
    def safe(value):
        return safe_task_text(value, secrets)

    messages = payload.get('Messages')
    projected = []
    if isinstance(messages, list):
        for message in messages:
            if not isinstance(message, Mapping):
                continue
            row = {}
            for name in ('MessageId', 'Message', 'MessageSeverity', 'Severity', 'Resolution', 'MessageArgs', 'RelatedProperties'):
                value = message.get(name)
                if isinstance(value, str):
                    row[name] = safe(value)
                elif isinstance(value, list):
                    row[name] = [safe(item) for item in value if isinstance(item, str)]
            projected.append(row)
    return {
        'task_state': safe(payload.get('TaskState', '')),
        'task_status': safe(payload.get('TaskStatus', '')),
        'messages_status': 'missing' if messages is None else 'present' if isinstance(messages, list) else 'invalid',
        'messages': projected,
        'message_count': len(messages) if isinstance(messages, list) else 0,
        'invalid_message_count': sum(not isinstance(item, Mapping) for item in messages) if isinstance(messages, list) else 0,
    }


def externalize_messages(diagnostics, *, store, target: str, run_id: str, operation_id: str, field: str = 'messages'):
    """Keep full sanitized evidence outside the receipt when messages are large."""
    import json
    from pathlib import Path
    import tempfile
    import uuid
    body = json.dumps(diagnostics, ensure_ascii=True).encode()
    if len(body) <= 16384:
        return diagnostics
    observation_id = operation_id + ':task:' + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='openubmc-task-diagnostics-') as raw:
        path = Path(raw) / 'task.json'
        path.write_bytes(body)
        reference = store.put(path, kind='redfish-task-diagnostics-source', provenance='redfish-upgrade-task',
                              retention_hint='run-lifetime', target=target, run_id=run_id, created_by_effect=observation_id + ':source')
    redacted = store.redact(reference, kind='redfish-task-diagnostics', provenance='redfish-upgrade-task-redacted', created_by_effect=observation_id)
    return {key: value for key, value in diagnostics.items() if key != field} | {
        field: [], field + '_artifact_ref': redacted.to_public_dict(),
    }
