"""One normalized diagnostic request plan shared by validation and receipts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass


def _items(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(
        value, (str, bytes, bytearray)
    ):
        return ()
    return tuple(str(item) for item in value if str(item).strip())


@dataclass(frozen=True)
class DiagnosticRequestPlan:
    """Normalized result identities for one target diagnostic request."""

    files: tuple[str, ...]
    logs: str
    include_target_clock: bool
    tree_requested: bool
    tree_service: str
    mdb_queries: tuple[str, ...]
    mdb_expand_classes: tuple[str, ...]
    active_alarms_requested: bool
    alarm_service: str
    source_correlation_requested: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "DiagnosticRequestPlan":
        mdb_only = value.get("mdb_only") is True
        request_present = bool(value)
        raw_logs = value.get("logs")
        raw_alarm_service = value.get("alarm_service")
        return cls(
            files=_items(value.get("files")),
            logs=(
                raw_logs
                if isinstance(raw_logs, str) and raw_logs.strip()
                else ""
            ),
            include_target_clock=request_present and not mdb_only,
            tree_requested=(
                not mdb_only
                and ("tree_service" in value or "tree_head" in value)
            ),
            tree_service=str(value.get("tree_service", "")).strip(),
            mdb_queries=_items(value.get("mdb_queries")),
            mdb_expand_classes=_items(value.get("mdb_expand_classes")),
            active_alarms_requested=("mdb_only" in value and not mdb_only),
            alarm_service=(
                str(raw_alarm_service).strip() if raw_alarm_service else ""
            ),
            source_correlation_requested=(
                value.get("source_correlation_requested") is True
            ),
        )

    @property
    def result_count(self) -> int:
        count = (
            len(self.files)
            + bool(self.logs)
            + self.include_target_clock
            + self.tree_requested
            + len(self.mdb_queries)
            + len(self.mdb_expand_classes)
            + self.active_alarms_requested
            + self.source_correlation_requested
        )
        return max(int(count), 1)

    def total_result_count(self, *, target_count: int) -> int:
        return self.result_count * target_count + (1 if target_count >= 2 else 0)
