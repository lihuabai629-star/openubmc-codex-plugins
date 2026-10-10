"""Reobserve persisted source metadata without rebinding a Run to Host selection."""
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from .workspace_context import WorkspaceSnapshot


@dataclass(frozen=True)
class SourceCheck:
    status: str
    reason: str


SourceChecker = Callable[[Mapping[str, object]], SourceCheck]


def check_source(projection: Mapping[str, object], checker: SourceChecker | None) -> SourceCheck:
    raw = projection.get("start_input", {}).get("workspace_context")
    if raw is None or checker is None:
        return SourceCheck("unavailable", "source_not_registered")
    try:
        snapshot = WorkspaceSnapshot(raw).to_public_dict()
        if not snapshot["repositories"]:
            return SourceCheck("unavailable", "repository_not_bound")
        result = checker(snapshot)
        if (not isinstance(result, SourceCheck) or result.status not in {"matched", "drift", "unavailable"}
                or result.reason not in {"metadata_matched", "commit_changed", "dirty_changed",
                    "repository_unavailable", "identity_unavailable"}):
            raise ValueError("invalid source check")
        return result
    except Exception:
        # Never include source paths, command output or exception messages.
        return SourceCheck("unavailable", "repository_unavailable")


def requires_source_check(projection: Mapping[str, object]) -> bool:
    raw = projection.get("start_input", {}).get("workspace_context")
    return isinstance(raw, Mapping) and bool(raw.get("repositories"))
