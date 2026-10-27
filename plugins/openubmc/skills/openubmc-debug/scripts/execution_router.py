"""Select the Runtime Agent Interface and account for bounded shell fallback.

This policy module does not execute a command or commit Runtime state. The MCP
adapter supplies bounded initialize and tools/list round trips; the caller must
use the returned route before invoking observe/execute or a shell command.
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
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
import secrets
import shlex
import time
import uuid


SCHEMA = "openubmc.execution-routing/v1"
SUPPORTED_OPERATIONS = frozenset({"diagnose", "build", "upgrade", "evidence", "rollback"})
_RUNTIME_TOOLS = frozenset({"observe", "execute"})
_HOSTS = frozenset({"windows-native", "wsl", "linux"})
_SECRET_KEY = re.compile(r"(?i)(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|authorization)")
_INLINE_SECRET = re.compile(r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*[^\s,;]+")
_BEARER = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
_REASON = re.compile(r"[a-z][a-z0-9_:-]{0,63}\Z")
_OPERATION = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_CHAIN = re.compile(r"(?:;|&&|\|\||[\r\n])")


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
    if isinstance(value, str):
        return _BEARER.sub("Bearer <redacted>", _INLINE_SECRET.sub("<redacted>", value))
    return value


def _bounded_text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 512 or "\x00" in value:
        raise RoutingError(f"{name} must be non-empty and at most 512 bytes")
    if _INLINE_SECRET.search(value) or _BEARER.search(value):
        raise RoutingError(f"{name} must not contain credentials")
    return value.strip()


def _host(value: str) -> str:
    if value not in _HOSTS:
        raise RoutingError("execution host must be windows-native, wsl, or linux")
    return value


@dataclass(frozen=True)
class ProtocolProbe:
    healthy: bool
    host: str
    reason: str = ""
    structured_tools: tuple[str, ...] = ()
    initialized: bool = False
    tools_listed: bool = False
    elapsed_ms: int = 0

    @property
    def ready(self) -> bool:
        return (self.healthy and self.initialized and self.tools_listed
                and _RUNTIME_TOOLS.issubset(self.structured_tools))

    def to_public_dict(self) -> dict[str, object]:
        return {
            "healthy": self.ready,
            "host": self.host,
            "reason": self.reason,
            "structured_tools": list(self.structured_tools),
            "initialized": self.initialized,
            "tools_listed": self.tools_listed,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass
class ShellFallbackBudget:
    limit: int = 8
    calls: int = 0
    repetitions: int = 0
    blocked: int = 0
    _seen: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if isinstance(self.limit, bool) or not isinstance(self.limit, int) or not 1 <= self.limit <= 32:
            raise RoutingError("shell fallback budget must be between 1 and 32")

    def admit(self, command_key: str) -> tuple[bool, str]:
        if command_key in self._seen:
            self.repetitions += 1
            self.blocked += 1
            return False, "convergence_blocker: equivalent shell action repeated"
        if self.calls >= self.limit:
            self.blocked += 1
            return False, "convergence_blocker: shell fallback budget exhausted"
        self._seen.add(command_key)
        self.calls += 1
        return True, ""


def _executable(value: str) -> str:
    name = re.split(r"[/\\]", value)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def _nested_command(command: Sequence[str]) -> list[str]:
    for index, part in enumerate(command):
        if part.lower() in ("-command", "-c", "--command") and index + 1 < len(command):
            try:
                return shlex.split(" ".join(command[index + 1:]))
            except ValueError as exc:
                raise RoutingError("shell fallback has an invalid nested command") from exc
    return []


def _host_path(command: Sequence[str], initial_host: str) -> list[str]:
    """Count known PowerShell -> WSL -> SSH hops, including nested -Command text."""
    path = [initial_host]
    current = list(command)
    for _ in range(6):
        if not current:
            break
        program = _executable(current[0])
        if program in ("powershell", "pwsh"):
            if path[-1] != "windows-native":
                path.append("windows-native")
            current = _nested_command(current)
        elif program == "wsl":
            # Calling wsl.exe from inside WSL crosses through the Windows
            # launcher before entering the distribution again.
            if path[-1] == "wsl":
                path.append("windows-native")
            if path[-1] != "wsl":
                path.append("wsl")
            rest = current[1:]
            while rest and rest[0].lower() in ("-d", "--distribution", "-u", "--user"):
                rest = rest[2:]
            if rest and rest[0].lower() in ("--", "--exec", "-e"):
                rest = rest[1:]
            current = rest
        elif program == "ssh":
            path.append("target")
            break
        elif program in ("bash", "sh"):
            current = _nested_command(current)
        else:
            break
    else:
        raise RoutingError("shell fallback host nesting is unbounded")
    return path


def _command_parts(command: Sequence[str]) -> list[str]:
    if (isinstance(command, (str, bytes)) or not isinstance(command, Sequence)
            or not command or len(command) > 64):
        raise RoutingError("shell command must be a bounded argument vector")
    parts = list(command)
    if any(not isinstance(item, str) or not item or len(item.encode("utf-8")) > 2048
           or "\x00" in item or _CHAIN.search(item) for item in parts):
        raise RoutingError("shell command contains an invalid or chained argument")
    return parts


@dataclass
class ExecutionRouter:
    environment: str = "linux"
    shell_budget: ShellFallbackBudget = field(default_factory=ShellFallbackBudget)
    structured_calls: int = 0
    shell_calls: int = 0
    host_mismatches: int = 0
    host_transitions: int = 0
    _records: dict[str, dict[str, object]] = field(default_factory=dict)
    _shell_events: list[dict[str, object]] = field(default_factory=list)
    _resolved: set[str] = field(default_factory=set)
    _command_key: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False)

    def __post_init__(self) -> None:
        if self.environment not in {"windows", "wsl", "linux"}:
            raise RoutingError("unsupported execution environment")
        self.shell_budget.__post_init__()

    @property
    def expected_host(self) -> str:
        return "wsl" if self.environment == "windows" else self.environment

    def _checked_receipt(self, record: Mapping[str, object], path: str) -> dict[str, object]:
        if not isinstance(record, Mapping):
            raise RoutingError("routing receipt is required")
        receipt_id = record.get("receipt_id")
        saved = self._records.get(receipt_id) if isinstance(receipt_id, str) else None
        if saved is None or saved != record or saved.get("path") != path:
            raise RoutingError("routing receipt does not belong to this router or has changed")
        return saved

    def choose(
        self,
        operation: str,
        *,
        probe: ProtocolProbe | None = None,
        requested_scope: str,
        evidence_boundary: str,
        shell_host: str | None = None,
        fallback_reason: str = "",
        shell_budget: int | None = None,
    ) -> dict[str, object]:
        if not isinstance(operation, str):
            raise RoutingError("operation must be a bounded identifier")
        operation = operation.strip().lower()
        if _OPERATION.fullmatch(operation) is None:
            raise RoutingError("operation must be a bounded identifier")
        scope = _bounded_text(requested_scope, "requested scope")
        boundary = _bounded_text(evidence_boundary, "evidence boundary")
        probe = probe or ProtocolProbe(False, self.expected_host, "probe_missing")
        _host(probe.host)
        if probe.host != self.expected_host:
            self.host_mismatches += 1
        structured = (probe.ready and probe.host == self.expected_host
                      and operation in SUPPORTED_OPERATIONS)
        if structured:
            if shell_host is not None or shell_budget is not None or fallback_reason:
                raise RoutingError("structured route cannot carry shell fallback settings")
            path = "structured-runtime-mcp"
            execution_host = probe.host
            fallback = None
        else:
            if shell_host is None and self.environment == "windows":
                raise RoutingError("Windows shell fallback requires an explicit execution host")
            execution_host = _host(shell_host or self.expected_host)
            if execution_host not in ({"windows-native", "wsl"} if self.environment == "windows"
                                      else {self.environment}):
                self.host_mismatches += 1
                raise RoutingError("shell execution host is outside the selected environment")
            if shell_budget is not None:
                if (isinstance(shell_budget, bool) or not isinstance(shell_budget, int)
                        or not 1 <= shell_budget <= 32):
                    raise RoutingError("shell fallback budget must be between 1 and 32")
                if shell_budget > self.shell_budget.limit or self.shell_budget.calls > shell_budget:
                    raise RoutingError("shell fallback budget cannot be increased or already exceeded")
                self.shell_budget.limit = shell_budget
            reason = ("protocol_host_mismatch" if probe.host != self.expected_host else
                      "operation_unsupported" if operation not in SUPPORTED_OPERATIONS else
                      probe.reason or fallback_reason or "protocol_unhealthy")
            if _REASON.fullmatch(reason) is None:
                raise RoutingError("shell fallback requires a stable reason code")
            path = "shell-fallback"
            fallback = {
                "reason_code": reason,
                "budget": self.shell_budget.limit,
                "calls": self.shell_budget.calls,
                "remaining": self.shell_budget.limit - self.shell_budget.calls,
            }
        receipt_id = uuid.uuid4().hex
        record = {
            "schema": SCHEMA,
            "receipt_id": receipt_id,
            "path": path,
            "operation": operation,
            "client_environment": self.environment,
            "execution_host": execution_host,
            "requested_scope": scope,
            "evidence_boundary": boundary,
            "protocol": probe.to_public_dict(),
            "fallback": fallback,
        }
        self._records[receipt_id] = record
        return deepcopy(record)

    def record_structured_call(self, *, record: Mapping[str, object], tool: str) -> dict[str, object]:
        saved = self._checked_receipt(record, "structured-runtime-mcp")
        if tool not in _RUNTIME_TOOLS:
            raise RoutingError("structured call must use observe or execute")
        self.structured_calls += 1
        return {"receipt_id": saved["receipt_id"], "tool": tool, "execution_host": saved["execution_host"]}

    def admit_shell(
        self, command: Sequence[str], *, record: Mapping[str, object], observed_host: str,
    ) -> dict[str, object]:
        saved = self._checked_receipt(record, "shell-fallback")
        if _host(observed_host) != saved["execution_host"]:
            self.host_mismatches += 1
            raise RoutingError("observed shell host differs from the fallback receipt")
        parts = _command_parts(command)
        host_path = _host_path(parts, str(saved["execution_host"]))
        # A WSL launcher cannot itself be started by a native Linux backend.
        if "wsl" in host_path[1:] and host_path[0] == "linux":
            self.host_mismatches += 1
            raise RoutingError("command host transition conflicts with the receipt")
        canonical = parts.copy()
        canonical[0] = _executable(canonical[0])
        nested = (_nested_command(canonical)
                  if canonical[0] in ("powershell", "pwsh", "bash", "sh") else [])
        if nested:
            canonical = [canonical[0], *nested]
        raw = json.dumps(canonical, ensure_ascii=True, separators=(",", ":")).encode()
        command_key = hmac.new(self._command_key, raw, hashlib.sha256).hexdigest()
        allowed, reason = self.shell_budget.admit(command_key)
        if not allowed:
            raise RoutingError(reason)
        self.shell_calls += 1
        transitions = sum(left != right for left, right in zip(host_path, host_path[1:]))
        self.host_transitions += transitions
        entry = deepcopy(saved)
        entry["fallback"]["calls"] = self.shell_budget.calls
        entry["fallback"]["remaining"] = self.shell_budget.limit - self.shell_budget.calls
        entry["command_digest"] = "hmac-sha256:" + command_key
        entry["host_path"] = host_path
        entry["host_transitions"] = transitions
        self._shell_events.append(entry)
        return deepcopy(entry)

    @staticmethod
    def shell_can_satisfy_gate(gate: str) -> bool:
        # Shell output can inform a diagnosis but never substitutes for Runtime
        # Gate evidence. Unknown future Gate types fail closed as well.
        return False

    def note_runtime_resolution(
        self,
        *,
        record: Mapping[str, object],
        evidence_ref: str,
        verify_runtime_evidence: Callable[[str], bool],
    ) -> None:
        """Mark metrics resolved only after an external Runtime evidence check.

        This is accounting, not Run/Gate/Outcome authority. The verifier is the
        Runtime-facing adapter, never a shell-output predicate.
        """
        saved = self._checked_receipt(record, "shell-fallback")
        if (not isinstance(evidence_ref, str) or not 1 <= len(evidence_ref) <= 128
                or _INLINE_SECRET.search(evidence_ref)):
            raise RoutingError("fallback resolution requires verified Runtime evidence")
        try:
            verified = verify_runtime_evidence(evidence_ref)
        except Exception:
            verified = False
        if verified is not True:
            raise RoutingError("fallback resolution requires verified Runtime evidence")
        self._resolved.add(str(saved["receipt_id"]))

    def metrics(self) -> dict[str, object]:
        fallback_ids = {key for key, record in self._records.items()
                        if record["path"] == "shell-fallback"}
        return {
            "structured_calls": self.structured_calls,
            "fallback_calls": self.shell_calls,
            "host_accuracy": self.host_mismatches == 0,
            "host_mismatches": self.host_mismatches,
            "host_transitions": self.host_transitions,
            "repetitions": self.shell_budget.repetitions,
            "blocked_fallback_calls": self.shell_budget.blocked,
            "unresolved_work": len(fallback_ids - self._resolved),
        }

    def report(self) -> dict[str, object]:
        records = [_safe(record) for record in self._records.values()]
        shell_events = [_safe(event) for event in self._shell_events]
        return {
            "schema": SCHEMA,
            "records": records,
            "shell_calls": shell_events,
            "metrics": self.metrics(),
            "digest": _digest({"records": records, "shell_calls": shell_events}),
        }


def probe_protocol(
    operation: str,
    *,
    host: str,
    initialize: Callable[[], Mapping[str, object]] | None = None,
    list_tools: Callable[[], Mapping[str, object]] | None = None,
    deadline_ms: int = 2000,
    clock: Callable[[], float] = time.monotonic,
) -> ProtocolProbe:
    """Check bounded MCP initialize and tools/list replies from one backend.

    Each callback must enforce the same deadline on transport I/O. An elapsed
    deadline check here rejects slow responses but cannot cancel a hung adapter.
    """
    _host(host)
    if not isinstance(operation, str) or _OPERATION.fullmatch(operation.strip().lower()) is None:
        raise RoutingError("operation must be a bounded identifier")
    if isinstance(deadline_ms, bool) or not isinstance(deadline_ms, int) or not 1 <= deadline_ms <= 5000:
        raise RoutingError("protocol deadline must be between 1 and 5000 ms")
    if initialize is None:
        return ProtocolProbe(False, host, "initialize_missing")
    if list_tools is None:
        return ProtocolProbe(False, host, "tool_probe_missing")
    start = clock()
    initialized = False
    tools_listed = False
    tools: tuple[str, ...] = ()
    reason = ""
    try:
        reply = initialize()
        initialized = (isinstance(reply, Mapping)
                       and isinstance(reply.get("protocolVersion"), str)
                       and bool(reply["protocolVersion"]))
        if not initialized:
            reason = "initialize_invalid"
        elif (clock() - start) * 1000 > deadline_ms:
            reason = "probe_timeout"
        else:
            listing = list_tools()
            raw_tools = listing.get("tools") if isinstance(listing, Mapping) else None
            if isinstance(raw_tools, list) and all(
                isinstance(item, Mapping) and isinstance(item.get("name"), str)
                and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", item["name"])
                for item in raw_tools
            ):
                tools = tuple(item["name"] for item in raw_tools)
                tools_listed = True
                if not _RUNTIME_TOOLS.issubset(tools):
                    reason = "required_runtime_tools_missing"
            else:
                reason = "tools_list_invalid"
            if (clock() - start) * 1000 > deadline_ms:
                reason = "probe_timeout"
    except TimeoutError:
        reason = "probe_timeout"
    except Exception as exc:  # never expose transport messages or credentials
        reason = "probe_error:" + type(exc).__name__.lower()[:40]
    elapsed_ms = max(0, int((clock() - start) * 1000))
    healthy = not reason and initialized and tools_listed
    return ProtocolProbe(healthy, host, reason, tools, initialized, tools_listed, elapsed_ms)
