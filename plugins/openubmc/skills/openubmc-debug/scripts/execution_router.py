"""Choose structured Runtime/MCP execution and govern shell fallback.

The router is deliberately independent of a particular Windows bridge.  A
caller supplies a small protocol health probe and receives a durable receipt
that names the selected host, fallback boundary, and bounded action budget.
Shell output is observational evidence only; it can never close a typed
mutation or delivery gate.
"""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import json
import re


SCHEMA = "openubmc.execution-routing/v1"
SUPPORTED_OPERATIONS = frozenset({"diagnose", "build", "upgrade", "evidence", "rollback"})
PROTECTED_GATES = frozenset({"mutation", "deployment", "runtime-verification", "rollback"})
_SECRET_KEY = re.compile(r"(?i)(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)")


class RoutingError(ValueError):
    pass


def _digest(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def _safe(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): "<redacted>" if _SECRET_KEY.search(str(key)) else _safe(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_safe(item) for item in value]
    return value


@dataclass(frozen=True)
class ProtocolProbe:
    healthy: bool
    host: str
    reason: str = ""
    structured_tools: tuple[str, ...] = ()

    def to_public_dict(self) -> dict[str, object]:
        return {
            "healthy": self.healthy,
            "host": self.host,
            "reason": self.reason,
            "structured_tools": list(self.structured_tools),
        }


@dataclass
class ShellFallbackBudget:
    limit: int = 8
    calls: int = 0
    repeated: int = 0
    _seen: dict[str, int] = field(default_factory=dict)

    def admit(self, command: Sequence[str]) -> tuple[bool, str]:
        if self.limit < 1:
            raise RoutingError("shell fallback budget must be positive")
        key = _digest(list(command))
        count = self._seen.get(key, 0) + 1
        self._seen[key] = count
        self.repeated = max(self.repeated, count)
        if count > 1:
            return False, "convergence_blocker: equivalent shell action repeated"
        if self.calls >= self.limit:
            return False, "convergence_blocker: shell fallback budget exhausted"
        self.calls += 1
        return True, ""


@dataclass
class ExecutionRouter:
    environment: str = "linux"
    shell_budget: ShellFallbackBudget = field(default_factory=ShellFallbackBudget)
    structured_calls: int = 0
    shell_calls: int = 0
    host_mismatches: int = 0
    _records: list[dict[str, object]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.environment not in {"windows", "wsl", "linux"}:
            raise RoutingError("unsupported execution environment")

    @property
    def expected_host(self) -> str:
        return "windows-native" if self.environment == "windows" else self.environment

    def choose(
        self,
        operation: str,
        *,
        probe: ProtocolProbe | None = None,
        requested_scope: str,
        evidence_boundary: str,
        fallback_reason: str = "",
        shell_budget: int | None = None,
    ) -> dict[str, object]:
        operation = operation.strip().lower()
        if operation not in SUPPORTED_OPERATIONS:
            raise RoutingError(f"unsupported operation: {operation}")
        if not requested_scope.strip() or not evidence_boundary.strip():
            raise RoutingError("requested scope and evidence boundary are required")
        probe = probe or ProtocolProbe(False, self.expected_host, "probe_missing")
        if probe.host != self.expected_host:
            self.host_mismatches += 1
        if probe.healthy and operation in SUPPORTED_OPERATIONS:
            self.structured_calls += 1
            record = {
                "schema": SCHEMA,
                "path": "structured-runtime-mcp",
                "operation": operation,
                "execution_host": probe.host,
                "requested_scope": requested_scope,
                "evidence_boundary": evidence_boundary,
                "protocol": probe.to_public_dict(),
                "fallback": None,
            }
        else:
            reason = fallback_reason.strip() or probe.reason.strip() or "protocol_unavailable"
            if not reason:
                raise RoutingError("shell fallback requires a stable reason code")
            if shell_budget is not None:
                self.shell_budget.limit = shell_budget
            record = {
                "schema": SCHEMA,
                "path": "shell-fallback",
                "operation": operation,
                "execution_host": self.expected_host,
                "requested_scope": requested_scope,
                "evidence_boundary": evidence_boundary,
                "protocol": probe.to_public_dict(),
                "fallback": {
                    "reason_code": reason,
                    "budget": self.shell_budget.limit,
                    "calls": self.shell_budget.calls,
                },
            }
        self._records.append(record)
        return dict(record)

    def admit_shell(self, command: Sequence[str], *, record: Mapping[str, object]) -> dict[str, object]:
        if record.get("path") != "shell-fallback":
            raise RoutingError("shell calls require a shell-fallback receipt")
        allowed, reason = self.shell_budget.admit(command)
        if not allowed:
            raise RoutingError(reason)
        self.shell_calls += 1
        entry = dict(record)
        fallback = dict(entry.get("fallback", {}))
        fallback["calls"] = self.shell_budget.calls
        entry["fallback"] = fallback
        entry["command_digest"] = _digest(list(command))
        return entry

    @staticmethod
    def shell_can_satisfy_gate(gate: str) -> bool:
        return gate.strip().lower() not in PROTECTED_GATES

    def metrics(self) -> dict[str, object]:
        return {
            "structured_calls": self.structured_calls,
            "fallback_calls": self.shell_calls,
            "host_accuracy": self.host_mismatches == 0,
            "host_mismatches": self.host_mismatches,
            "repetitions": self.shell_budget.repeated,
            "unresolved_work": sum(
                1 for record in self._records
                if record.get("path") == "shell-fallback"
            ),
        }

    def report(self) -> dict[str, object]:
        records = [_safe(record) for record in self._records]
        return {
            "schema": SCHEMA,
            "records": records,
            "metrics": self.metrics(),
            "digest": _digest(records),
        }


def probe_protocol(
    operation: str,
    *,
    host: str,
    list_tools: Callable[[], Sequence[str]],
) -> ProtocolProbe:
    """Run a protocol-level health check without invoking a shell command."""
    try:
        tools = tuple(str(item) for item in list_tools())
    except Exception as exc:  # adapters must expose a stable reason only
        return ProtocolProbe(False, host, f"probe_error:{type(exc).__name__}")
    required = {"observe", "execute"}
    healthy = required.issubset(tools)
    return ProtocolProbe(
        healthy,
        host,
        "" if healthy else "required_runtime_tools_missing",
        tools,
    )

