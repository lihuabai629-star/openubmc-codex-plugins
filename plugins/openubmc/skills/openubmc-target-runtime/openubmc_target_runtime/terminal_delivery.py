"""Durable, idempotent final-answer presence gate for terminal Runs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile

from .delivery_stage import DELIVERY_STAGES


SCHEMA = "openubmc.terminal-answer/v1"
TERMINAL_STATUSES = frozenset({"completed", "partial", "failed", "cancelled", "blocked"})
TERMINAL_DELIVERY_STAGES = frozenset((*DELIVERY_STAGES, "unverified"))


class TerminalAnswerError(ValueError):
    pass


def _fingerprint(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def _text(value: object) -> str:
    return str(value).strip() if value is not None else ""


@dataclass(frozen=True)
class FinalAnswerRecord:
    task_id: str
    run_id: str
    outcome_fingerprint: str
    status: str
    delivery_stage: str
    text: str
    delivery_id: str
    delivered_at: str
    host_event_id: str = ""
    prepared_at: str = ""
    delivery_source: str = ""

    def __post_init__(self) -> None:
        if not self.task_id or not self.run_id:
            raise TerminalAnswerError("task_id and run_id are required")
        if self.status not in TERMINAL_STATUSES:
            raise TerminalAnswerError("final answer requires a terminal status")
        if not self.text.strip():
            raise TerminalAnswerError("final answer text must not be empty")
        if not self.outcome_fingerprint.startswith("sha256:"):
            raise TerminalAnswerError("final answer must bind an Outcome fingerprint")
        if self.delivery_stage not in TERMINAL_DELIVERY_STAGES:
            raise TerminalAnswerError("final answer has an unsupported delivery stage")

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": SCHEMA,
            "task_id": self.task_id,
            "run_id": self.run_id,
            "outcome_fingerprint": self.outcome_fingerprint,
            "status": self.status,
            "delivery_stage": self.delivery_stage,
            "text": self.text,
            "delivery_id": self.delivery_id,
            "delivered_at": self.delivered_at,
            "host_event_id": self.host_event_id,
            "prepared_at": self.prepared_at,
            "delivery_source": self.delivery_source,
        }


def outcome_fingerprint(
    outcome: Mapping[str, object],
    *,
    delivery_stage: str = "unverified",
) -> str:
    selected_stage = _text(delivery_stage) or "unverified"
    if selected_stage not in TERMINAL_DELIVERY_STAGES:
        raise TerminalAnswerError("unsupported delivery stage")
    return _fingerprint(
        {"outcome": dict(outcome), "delivery_stage": selected_stage}
    )


def render_final_answer(
    *,
    status: str,
    summary: str,
    delivery_stage: str,
    next_action: str = "",
) -> str:
    status = _text(status).lower()
    if status not in TERMINAL_STATUSES:
        raise TerminalAnswerError("cannot render a non-terminal status")
    if not _text(summary):
        raise TerminalAnswerError("terminal summary is required")
    delivery_stage = _text(delivery_stage) or "unverified"
    if delivery_stage not in TERMINAL_DELIVERY_STAGES:
        raise TerminalAnswerError("unsupported delivery stage")
    labels = {
        "completed": "已完成",
        "partial": "部分完成",
        "failed": "失败",
        "cancelled": "已取消",
        "blocked": "受阻",
    }
    lines = [f"状态：{labels[status]}", f"交付阶段：{delivery_stage}", _text(summary)]
    if status != "completed":
        lines.append(f"下一步：{_text(next_action) or '需要补充证据后继续。'}")
    return "\n".join(lines)


def audit_rollout_final(path: Path, *, task_id: str, prepared_at: str) -> tuple[str, str, str]:
    """Read only the host's final event after the prepared answer boundary."""
    try:
        prepared_time = datetime.fromisoformat(prepared_at.replace("Z", "+00:00"))
        if prepared_time.tzinfo is None:
            raise ValueError("preparation time has no timezone")
    except ValueError as exc:
        raise TerminalAnswerError("terminal preparation time is invalid") from exc
    session_id = ""
    final: tuple[str, str, str] | None = None
    try:
        with Path(path).open("r", encoding="utf-8") as stream:
            for line in stream:
                if len(line) > 16 * 1024 * 1024:
                    raise TerminalAnswerError("rollout event exceeds the audit bound")
                event = json.loads(line)
                if not isinstance(event, Mapping):
                    continue
                payload = event.get("payload")
                if not isinstance(payload, Mapping):
                    continue
                if event.get("type") == "session_meta":
                    session_id = _text(payload.get("id") or payload.get("session_id"))
                if (event.get("type") != "response_item" or payload.get("type") != "message"
                        or payload.get("role") != "assistant"
                        or payload.get("phase") != "final_answer"):
                    continue
                content = payload.get("content")
                if not isinstance(content, list):
                    continue
                rendered = "".join(
                    str(item.get("text", "")) for item in content
                    if isinstance(item, Mapping) and item.get("type") == "output_text"
                )
                observed_at = _text(event.get("timestamp"))
                try:
                    observed_time = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if observed_time.tzinfo is None or observed_time <= prepared_time:
                    continue
                final = (_text(payload.get("id")), rendered, observed_at)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TerminalAnswerError("rollout final evidence is unreadable") from exc
    if session_id != task_id:
        raise TerminalAnswerError("rollout belongs to another task")
    if final is None or not final[0] or not final[1].strip():
        raise TerminalAnswerError("rollout final event is missing")
    return final


class TerminalAnswerStore:
    """A tiny JSON store with atomic replacement and duplicate-safe delivery."""

    def __init__(self, path: Path):
        self.path = Path(path).expanduser().resolve()

    def _load(self) -> dict[str, object]:
        if not self.path.exists():
            return {}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise TerminalAnswerError("terminal answer store is unreadable") from exc
        return value if isinstance(value, dict) else {}

    def get(self, task_id: str) -> FinalAnswerRecord | None:
        raw = self._load().get(task_id)
        if not isinstance(raw, Mapping):
            return None
        if raw.get("schema") != SCHEMA:
            raise TerminalAnswerError("unsupported terminal answer schema")
        return FinalAnswerRecord(
            task_id=_text(raw.get("task_id")),
            run_id=_text(raw.get("run_id")),
            outcome_fingerprint=_text(raw.get("outcome_fingerprint")),
            status=_text(raw.get("status")),
            delivery_stage=_text(raw.get("delivery_stage")),
            text=_text(raw.get("text")),
            delivery_id=_text(raw.get("delivery_id")),
            delivered_at=_text(raw.get("delivered_at")),
            host_event_id=_text(raw.get("host_event_id")),
            prepared_at=_text(raw.get("prepared_at")),
            delivery_source=_text(raw.get("delivery_source")),
        )

    def _save(self, task_id: str, record: FinalAnswerRecord) -> None:
        values = self._load()
        values[task_id] = record.to_public_dict()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(values, stream, ensure_ascii=False, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def prepare(
        self,
        *,
        task_id: str,
        run_id: str,
        outcome: Mapping[str, object],
        delivery_stage: str,
        text: str,
    ) -> FinalAnswerRecord:
        selected_stage = _text(delivery_stage) or "unverified"
        fingerprint = outcome_fingerprint(
            outcome,
            delivery_stage=selected_stage,
        )
        existing = self.get(task_id)
        if existing is not None:
            if existing.run_id != run_id or existing.outcome_fingerprint != fingerprint:
                raise TerminalAnswerError("terminal answer belongs to another Run or Outcome")
            return existing
        status = _text(outcome.get("status")).lower()
        record = FinalAnswerRecord(
            task_id=task_id,
            run_id=run_id,
            outcome_fingerprint=fingerprint,
            status=status,
            delivery_stage=selected_stage,
            text=_text(text),
            delivery_id="answer-" + _fingerprint({"task_id": task_id, "run_id": run_id, "outcome": fingerprint}),
            delivered_at="",
            prepared_at=datetime.now(timezone.utc).isoformat(),
        )
        self._save(task_id, record)
        return record

    def acknowledge(
        self, *, task_id: str, run_id: str, outcome: Mapping[str, object],
        delivery_stage: str, text: str, host_event_id: str,
        observed_at: str = "",
        delivery_source: str = "",
    ) -> FinalAnswerRecord:
        """Record an observed host final event after matching prepared terminal facts."""
        record = self.get(task_id)
        if record is None:
            raise TerminalAnswerError("final answer was not prepared")
        selected_stage = _text(delivery_stage) or "unverified"
        if (record.run_id != run_id or record.outcome_fingerprint != outcome_fingerprint(
            outcome, delivery_stage=selected_stage
        )):
            raise TerminalAnswerError("terminal answer belongs to another Run or Outcome")
        if record.text != _text(text):
            raise TerminalAnswerError("final text mismatch")
        if not _text(host_event_id):
            raise TerminalAnswerError("host final event identity is required")
        if record.delivered_at:
            if record.host_event_id != host_event_id:
                raise TerminalAnswerError("final answer already acknowledged by another host event")
            return record
        delivered = replace(record, delivered_at=_text(observed_at) or datetime.now(timezone.utc).isoformat(),
                            host_event_id=_text(host_event_id), delivery_source=delivery_source)
        self._save(task_id, delivered)
        return delivered

    def acknowledge_rollout(
        self, path: Path, *, task_id: str, run_id: str,
        outcome: Mapping[str, object], delivery_stage: str,
    ) -> FinalAnswerRecord:
        """Bind a prepared answer to the last persisted Codex host final event."""
        prepared = self.get(task_id)
        if prepared is None or not prepared.prepared_at:
            raise TerminalAnswerError("terminal answer has no preparation boundary")
        final = audit_rollout_final(path, task_id=task_id, prepared_at=prepared.prepared_at)
        return self.acknowledge(
            task_id=task_id, run_id=run_id, outcome=outcome,
            delivery_stage=delivery_stage, text=final[1],
            host_event_id=final[0], observed_at=final[2],
            delivery_source="codex-rollout-v1",
        )


def qualify_terminal_answer(
    *,
    task_id: str,
    run_id: str,
    outcome: Mapping[str, object],
    delivery_stage: str,
    record: FinalAnswerRecord | None,
) -> dict[str, object]:
    """Fail closed when terminal evidence lacks a matching final answer."""
    status = _text(outcome.get("status")).lower()
    selected_stage = _text(delivery_stage) or "unverified"
    failures: list[str] = []
    if status not in TERMINAL_STATUSES:
        failures.append("outcome_not_terminal")
    if selected_stage not in TERMINAL_DELIVERY_STAGES:
        failures.append("final_answer_stage_invalid")
    if record is None:
        failures.append("final_answer_missing")
    else:
        if record.task_id != task_id:
            failures.append("final_answer_task_mismatch")
        if record.run_id != run_id:
            failures.append("final_answer_run_mismatch")
        if record.delivery_stage != selected_stage:
            failures.append("final_answer_stage_mismatch")
        if selected_stage in TERMINAL_DELIVERY_STAGES:
            if record.outcome_fingerprint != outcome_fingerprint(
                outcome,
                delivery_stage=selected_stage,
            ):
                failures.append("final_answer_outcome_mismatch")
        if record.status != status:
            failures.append("final_answer_status_mismatch")
        if not record.text.strip():
            failures.append("final_answer_empty")
        if (not record.delivered_at or not record.host_event_id
                or record.delivery_source != "codex-rollout-v1"):
            failures.append("final_answer_unconfirmed")
    return {
        "schema": f"{SCHEMA}/qualification",
        "status": "passed" if not failures else "failed",
        "task_id": task_id,
        "run_id": run_id,
        "failures": failures,
    }
