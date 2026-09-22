"""Durable, idempotent final-answer presence gate for terminal Runs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
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
        )

    def deliver(
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
            delivered_at=datetime.now(timezone.utc).isoformat(),
        )
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
        return record


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
    return {
        "schema": f"{SCHEMA}/qualification",
        "status": "passed" if not failures else "failed",
        "task_id": task_id,
        "run_id": run_id,
        "failures": failures,
    }
