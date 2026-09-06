"""Small dependency-free MCP surface for task-scoped openUBMC Debug runs."""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import signal
import sys
import threading
import time
from typing import Protocol, TypeVar
import uuid

from .contracts import (
    RUNTIME_API_VERSION,
    CredentialSelector,
    TargetPolicy,
    TargetSpec,
    _fingerprint,
)
from .catalog import OperationCatalog
from .agent_gateway import (
    OBSERVATION_PROJECTION_TARGET_BYTES,
    agent_operation_descriptors,
    render_execute_turn_text,
)
from .semantic_runtime import (
    AGENT_REQUEST_MAX_BYTES,
    AssuranceUnavailable,
    SemanticRuntimePort,
    bounded_request,
)
from .capability import (
    CallableDomainAdapter,
    CapabilityRegistry,
    DomainPackAuthorContract,
    DomainReceipt,
    RUNTIME_EFFECT_RECOVERY_ARGUMENT,
    RuntimeSDKContext,
)
from .context_runtime import (
    AGENT_ENVELOPE_MAX_BYTES,
    BlobRepository,
    CONTEXT_WORKFLOW_STEP_ARGUMENT,
    CaseNotFound,
    ContextRuntime,
    ContextToolResult,
    RevisionConflict,
    RuntimeRepository,
)
from .compatibility import (
    CompatibilityTelemetryRepository,
)
from .composition import RuntimeCompositionOptions, compose_runtime
from .domain_runtime import (
    canonicalize_tool_arguments,
    validate_boolean_argument_types,
)
from .evidence_store import (
    EVIDENCE_QUERY_DEFAULT_ITEMS,
    EVIDENCE_QUERY_MAX_CASE_ID,
    EVIDENCE_QUERY_MAX_FILTER,
    EVIDENCE_QUERY_MAX_ITEMS,
)
from .session_outcome import (
    InMemorySessionOutcomeRepository,
    SessionOutcomeRepository,
    SessionOutcomeService,
)
from .credential_file import load_selected_credentials_file
from .lifecycle import OperationContext, TaskRunRegistry
from .mcp_lifecycle import McpProcessLifecycle
from .mutation import (
    MutationAuthorizedExceptions,
    TaskAuthorizationPolicy,
    TargetLeaseCoordinator,
    mutation_journal_operation_status,
)
from .operation_contracts import DEFAULT_OPERATION_CONTRACTS, LOG_BUNDLE_STAGE_CONTRACTS
from .task_context import TaskContextStore
from .orchestration import (
    DeliveryStrategy,
    DeveloperEditIntent,
    DomainExecutionContext,
    DomainOutcome,
    MutationDomainResult,
    TaskIntent,
    TaskIntentKind,
    TaskOrchestrationContext,
    TaskTargetBinding,
    TaskWorkflowOrchestrator,
    WorkflowStep,
    enforce_fresh_verification,
)
from .workflow import DEFAULT_PHASE_REGISTRY


TaskT = TypeVar("TaskT")
MCP_PROTOCOL_VERSION = "2025-06-18"
STDIO_FRAME_MAX_BYTES = AGENT_REQUEST_MAX_BYTES


class DebugMcpBackend(Protocol[TaskT]):
    def open_task(self, task_id: str) -> TaskT: ...

    def close_task(self, task: TaskT) -> None: ...

    def maintain_task(self, task: TaskT) -> object: ...

    def task_status(self, task: TaskT) -> dict[str, object]: ...

    def debug_run(
        self,
        task: TaskT,
        arguments: Mapping[str, object],
        context: OperationContext,
    ) -> dict[str, object]: ...

    def debug_collect(
        self,
        task: TaskT,
        arguments: Mapping[str, object],
        context: OperationContext,
    ) -> dict[str, object]: ...


_OPERATION_CONTRACTS = DEFAULT_OPERATION_CONTRACTS.contracts()
_TOOL_DOMAINS = {
    contract.name: contract.domain
    for contract in _OPERATION_CONTRACTS
    if contract.domain
}
_ORCHESTRATION_ARGUMENTS = frozenset(
    {
        "intent",
        "final_purpose",
        "entry_domain",
        "delivery_strategy",
        "authorized_exceptions",
        "target_id",
        "target_role",
    }
)
_WORKFLOW_ARGUMENT = "workflow"
_TASK_AUTHORIZATION_POLICY_ARGUMENT = "_task_authorization_policy"
_INTERNAL_TASK_ARGUMENTS = frozenset(
    {
        _TASK_AUTHORIZATION_POLICY_ARGUMENT,
        "_task_intent",
        "_task_delivery_strategy",
        "_task_authorized_exceptions",
        "_credential_values",
    }
)
_DOMAIN_TO_TOOL = DEFAULT_OPERATION_CONTRACTS.domain_to_entry_operation()
_CREDENTIAL_VALUE_TOOLS = frozenset(
    contract.name
    for contract in _OPERATION_CONTRACTS
    if contract.credential_values
)
_MUTATION_TOOLS = frozenset(
    contract.name for contract in _OPERATION_CONTRACTS if contract.mutation
)
_MAX_ORCHESTRATION_HISTORY = 16
_MAX_WORKFLOW_SUMMARIES = 16
_MAX_MUTATION_OUTCOMES = 32
_PERSISTENCE_TOUCH_INTERVAL_SECONDS = 300.0
_SECRET_ARGUMENTS = frozenset(
    {"ssh_password", "telnet_password", "redfish_password", "password"}
)
_SHARED_ARGUMENTS = frozenset(
    {
        "ip",
        "ssh_port",
        "telnet_port",
        "redfish_port",
        "ssh_user",
        "ssh_user_env",
        "ssh_password_env",
        "ssh_identity_file",
        "telnet_user",
        "telnet_user_env",
        "telnet_password_env",
        "redfish_user",
        "redfish_user_env",
        "redfish_password_env",
        "ssh_host_key_policy",
        "ssh_known_hosts_file",
        "allow_insecure_host_key",
        "allow_insecure_tls",
    }
)
_REUSABLE_CONNECTION_ARGUMENTS = frozenset(
    {
        "ssh_user",
        "ssh_password",
        "telnet_user",
        "telnet_password",
        "redfish_user",
        "redfish_password",
    }
)
_TARGET_ADDRESS_ARGUMENTS = frozenset({"ip"})
_SSH_ARGUMENTS = frozenset(
    {
        "ssh_port",
        "ssh_user",
        "ssh_user_env",
        "ssh_password_env",
        "ssh_identity_file",
    }
)
_TELNET_ARGUMENTS = frozenset(
    {
        "telnet_port",
        "telnet_user",
        "telnet_user_env",
        "telnet_password_env",
    }
)
_REDFISH_ARGUMENTS = frozenset(
    {
        "redfish_port",
        "redfish_user",
        "redfish_user_env",
        "redfish_password_env",
    }
)
_SSH_SECRET_ARGUMENTS = frozenset({"ssh_password"})
_TELNET_SECRET_ARGUMENTS = frozenset({"telnet_password"})
_REDFISH_SECRET_ARGUMENTS = frozenset({"redfish_password"})
_DOMAIN_CONNECTION_ARGUMENTS = {
    "debug": (
        _TARGET_ADDRESS_ARGUMENTS
        | _SSH_ARGUMENTS
        | _TELNET_ARGUMENTS
        | frozenset(
            {
                "ssh_host_key_policy",
                "ssh_known_hosts_file",
                "allow_insecure_host_key",
            }
        )
    ),
    "log_analyzer": (
        _TARGET_ADDRESS_ARGUMENTS
        | _SSH_ARGUMENTS
        | _REDFISH_ARGUMENTS
        | _SSH_SECRET_ARGUMENTS
        | _REDFISH_SECRET_ARGUMENTS
    ),
    "live_patch": (
        _TARGET_ADDRESS_ARGUMENTS
        | _SSH_ARGUMENTS
        | _TELNET_ARGUMENTS
        | _SSH_SECRET_ARGUMENTS
        | _TELNET_SECRET_ARGUMENTS
        | frozenset({"ssh_host_key_policy", "ssh_known_hosts_file"})
    ),
    "upgrade": (
        _TARGET_ADDRESS_ARGUMENTS
        | _REDFISH_ARGUMENTS
        | frozenset({"allow_insecure_tls"})
    ),
}
_DOMAIN_ARGUMENTS_TO_STRIP = {
    "debug": frozenset({"problem"}),
}
_WORKFLOW_SECTION_PROTECTED_ARGUMENTS = (
    _ORCHESTRATION_ARGUMENTS
    | _SHARED_ARGUMENTS
    | _SECRET_ARGUMENTS
    | frozenset(
        {
            "targets",
            "role",
            CONTEXT_WORKFLOW_STEP_ARGUMENT,
        }
    )
)


class _OrchestratedMcpTask:
    def __init__(
        self,
        task_id: str,
        tool_backends: Mapping[str, object],
        *,
        state_store: TaskContextStore | None = None,
    ) -> None:
        self.task_id = task_id
        self.tool_backends = dict(tool_backends)
        self._state_store = state_store
        self.orchestration: TaskOrchestrationContext | None = None
        self._orchestration_history: list[TaskOrchestrationContext] = []
        self._shared_arguments: dict[str, object] = {}
        self._target_arguments: dict[str, dict[str, object]] = {}
        self._resources: dict[int, object] = {}
        self._resource_tools: dict[str, object] = {}
        self._credential_values: dict[str, str] | None = None
        self._credential_parse_count = 0
        self._workflow_summaries: list[dict[str, object]] = []
        self._mutation_outcomes: OrderedDict[str, DomainOutcome[object]] = OrderedDict()
        self._mutation_journal_identities: OrderedDict[str, dict[str, str]] = (
            OrderedDict()
        )
        self._target_admissions: dict[str, TargetLeaseCoordinator] = {}
        self._lock = threading.RLock()
        self._workflow_lock = threading.RLock()
        self._persistence_lock = threading.RLock()
        self._last_persisted_digest = ""
        self._last_persisted_at = 0.0
        self._failed_persisted_digest = ""
        self._persistence_error = ""
        self._persistence_disabled = False
        self._recovered_context = False
        self._restoring_context = False
        self._restore_context()

    @staticmethod
    def _persisted_workflow_summary(raw: object) -> dict[str, object] | None:
        if not isinstance(raw, Mapping):
            return None
        request_fingerprint = raw.get("request_fingerprint")
        if not isinstance(request_fingerprint, str) or not request_fingerprint:
            return None
        intent = raw.get("intent")
        phase_states = raw.get("phase_states")
        return {
            "request_fingerprint": request_fingerprint,
            "completed": bool(raw.get("completed", False)),
            "partial": bool(raw.get("partial", False)),
            "next_action": str(raw.get("next_action", "")),
            "intent": dict(intent) if isinstance(intent, Mapping) else None,
            "phase_states": (
                dict(phase_states) if isinstance(phase_states, Mapping) else {}
            ),
        }

    def _snapshot_context(self) -> dict[str, object] | None:
        with self._lock:
            orchestration = self.orchestration
            if orchestration is None:
                return None
            intent = orchestration.intent
            shared_arguments = dict(self._shared_arguments)
            target_payloads = [
                {
                    key: value
                    for key, value in self._target_arguments[target.target_id].items()
                    if key not in _SECRET_ARGUMENTS
                }
                for target in intent.targets
                if target.target_id in self._target_arguments
            ]
        with self._workflow_lock:
            workflow_summaries = [
                {
                    **summary,
                    "intent": (
                        dict(summary["intent"])
                        if isinstance(summary.get("intent"), Mapping)
                        else None
                    ),
                    "phase_states": (
                        dict(summary["phase_states"])
                        if isinstance(summary.get("phase_states"), Mapping)
                        else {}
                    ),
                }
                for summary in self._workflow_summaries
            ]
            mutation_journals = [
                dict(identity)
                for identity in self._mutation_journal_identities.values()
            ]
        return {
            "orchestration": {
                "intent": intent.original_intent.value,
                "final_purpose": intent.final_purpose,
                "entry_domain": intent.entry_domain,
                "delivery_strategy": (
                    intent.delivery_strategy.value
                    if intent.delivery_strategy is not None
                    else None
                ),
                "authorized_exceptions": (
                    intent.authorization.authorized_exceptions.to_public_dict()
                ),
                "authorization_policy": intent.authorization.to_public_dict(),
            },
            "shared_arguments": shared_arguments,
            "targets": target_payloads,
            "workflow_summaries": workflow_summaries,
            "mutation_journal_identities": mutation_journals,
        }

    @staticmethod
    def _context_digest(context: Mapping[str, object]) -> str:
        encoded = json.dumps(
            context,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _persist_context(self, *, force: bool = False) -> None:
        if self._state_store is None or self._restoring_context:
            return
        context = self._snapshot_context()
        if context is None:
            return
        digest = self._context_digest(context)
        now = time.monotonic()
        with self._persistence_lock:
            if self._persistence_disabled or self._restoring_context:
                return
            with self._lock:
                if not force and digest == self._failed_persisted_digest:
                    return
                if (
                    not force
                    and digest == self._last_persisted_digest
                    and now - self._last_persisted_at
                    < _PERSISTENCE_TOUCH_INTERVAL_SECONDS
                ):
                    return
            try:
                self._state_store.save(self.task_id, context)
            except Exception as exc:
                self._state_store.delete(self.task_id)
                with self._lock:
                    self._last_persisted_digest = ""
                    self._last_persisted_at = 0.0
                    self._failed_persisted_digest = digest
                    self._persistence_error = f"{type(exc).__name__}: {exc}"
                return
            with self._lock:
                self._last_persisted_digest = digest
                self._last_persisted_at = now
                self._failed_persisted_digest = ""
                self._persistence_error = ""

    def disable_persistence(self) -> None:
        with self._persistence_lock:
            self._persistence_disabled = True
            if self._state_store is not None:
                self._state_store.delete(self.task_id)
            with self._lock:
                self._last_persisted_digest = ""
                self._last_persisted_at = 0.0
                self._failed_persisted_digest = ""

    def seal_persistence(self) -> None:
        """Persist the final task projection, then reject late background writes."""

        self._persist_context(force=True)
        with self._persistence_lock:
            self._persistence_disabled = True

    def _restore_context(self) -> None:
        if self._state_store is None:
            return
        try:
            raw = self._state_store.load(self.task_id)
        except Exception as exc:
            self._persistence_error = f"{type(exc).__name__}: {exc}"
            return
        if raw is None:
            return
        try:
            orchestration = raw.get("orchestration")
            targets = raw.get("targets")
            shared = raw.get("shared_arguments")
            if not isinstance(orchestration, Mapping):
                raise ValueError("persisted orchestration is unavailable")
            if not isinstance(targets, list) or not targets or not all(
                isinstance(target, Mapping) for target in targets
            ):
                raise ValueError("persisted targets are unavailable")
            arguments = dict(shared) if isinstance(shared, Mapping) else {}
            arguments["targets"] = [dict(target) for target in targets]
            for source, destination in (
                ("intent", "intent"),
                ("final_purpose", "final_purpose"),
                ("entry_domain", "entry_domain"),
                ("delivery_strategy", "delivery_strategy"),
            ):
                value = orchestration.get(source)
                if isinstance(value, str) and value.strip():
                    arguments[destination] = value.strip()
            raw_policy = orchestration.get("authorization_policy")
            if raw_policy is not None:
                if not isinstance(raw_policy, Mapping):
                    raise TypeError("persisted authorization_policy must be an object")
                policy = TaskAuthorizationPolicy.from_public_dict(raw_policy)
                restored_intent = arguments.get("intent")
                if restored_intent != policy.original_intent:
                    raise ValueError(
                        "persisted authorization policy intent does not match orchestration"
                    )
                restored_delivery = str(arguments.get("delivery_strategy", ""))
                if (
                    policy.original_intent == "diagnose-and-fix"
                    and restored_delivery != policy.delivery_strategy
                ):
                    raise ValueError(
                        "persisted authorization policy delivery strategy does not match orchestration"
                    )
                arguments["authorized_exceptions"] = (
                    policy.authorized_exceptions.to_public_dict()
                )
                arguments["allow_insecure_tls"] = policy.allow_insecure_tls
            else:
                authorized_exceptions = orchestration.get("authorized_exceptions")
                if isinstance(authorized_exceptions, Mapping):
                    arguments["authorized_exceptions"] = dict(authorized_exceptions)
            entry_domain = orchestration.get("entry_domain")
            preferred_tool = (
                _DOMAIN_TO_TOOL.get(entry_domain)
                if isinstance(entry_domain, str)
                else None
            )
            tool_name = (
                preferred_tool
                if preferred_tool in self.tool_backends
                else next(iter(self.tool_backends))
            )
            self._restoring_context = True
            try:
                self.bind_intent(tool_name, arguments)
            finally:
                self._restoring_context = False
            raw_summaries = raw.get("workflow_summaries", [])
            summaries = (
                [
                    summary
                    for summary in (
                        self._persisted_workflow_summary(item)
                        for item in raw_summaries
                    )
                    if summary is not None
                ]
                if isinstance(raw_summaries, list)
                else []
            )
            raw_identities = raw.get("mutation_journal_identities", [])
            identities: OrderedDict[str, dict[str, str]] = OrderedDict()
            if isinstance(raw_identities, list):
                for item in raw_identities:
                    if not isinstance(item, Mapping):
                        continue
                    fingerprint = item.get("request_fingerprint")
                    domain = item.get("domain")
                    operation_id = item.get("operation_id")
                    if not all(
                        isinstance(value, str) and value
                        for value in (fingerprint, domain, operation_id)
                    ):
                        continue
                    identities[fingerprint] = {
                        "request_fingerprint": fingerprint,
                        "domain": domain,
                        "operation_id": operation_id,
                    }
            with self._workflow_lock:
                self._workflow_summaries = summaries[-_MAX_WORKFLOW_SUMMARIES:]
                self._mutation_journal_identities = OrderedDict(
                    list(identities.items())[-_MAX_MUTATION_OUTCOMES:]
                )
            self._recovered_context = True
            context = self._snapshot_context()
            if context is not None:
                self._last_persisted_digest = self._context_digest(context)
                self._last_persisted_at = time.monotonic()
        except Exception as exc:
            self._persistence_error = f"{type(exc).__name__}: {exc}"
            self._state_store.delete(self.task_id)

    @staticmethod
    def _target_role(
        raw: Mapping[str, object],
        common: Mapping[str, object],
        *,
        multiple: bool,
    ) -> str:
        value = raw.get("role", common.get("target_role", common.get("reference_role")))
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
        return "symmetric" if multiple else "candidate"

    @staticmethod
    def _selector_arguments(
        raw: Mapping[str, object], common: Mapping[str, object], name: str
    ) -> str:
        value = raw.get(name, common.get(name, ""))
        return str(value) if isinstance(value, (str, int)) else ""

    def _target_bindings(
        self, arguments: Mapping[str, object]
    ) -> tuple[TaskTargetBinding, ...]:
        raw_targets = arguments.get("targets")
        if raw_targets is None:
            raw_targets = [arguments]
        if not isinstance(raw_targets, list) or not raw_targets or not all(
            isinstance(target, Mapping) for target in raw_targets
        ):
            raise ValueError("targets must be a non-empty array of target objects")
        multiple = len(raw_targets) > 1
        bindings: list[TaskTargetBinding] = []
        for index, raw in enumerate(raw_targets, start=1):
            host = raw.get("ip", arguments.get("ip"))
            if not isinstance(host, str) or not host.strip():
                raise ValueError("the first domain call must provide ip or targets")
            ssh_identity_source = self._selector_arguments(
                raw, arguments, "ssh_identity_file"
            )
            ssh_selector = CredentialSelector.for_ssh(
                user=self._selector_arguments(raw, arguments, "ssh_user"),
                user_env=self._selector_arguments(raw, arguments, "ssh_user_env"),
                password_env=self._selector_arguments(
                    raw, arguments, "ssh_password_env"
                ),
                identity_file=ssh_identity_source,
                environ=os.environ,
            )
            telnet_selector = CredentialSelector.for_telnet(
                user=self._selector_arguments(raw, arguments, "telnet_user"),
                user_env=self._selector_arguments(raw, arguments, "telnet_user_env"),
                password_env=self._selector_arguments(
                    raw, arguments, "telnet_password_env"
                ),
                environ=os.environ,
            )
            redfish_selector = CredentialSelector.for_redfish(
                user=self._selector_arguments(raw, arguments, "redfish_user"),
                user_env=self._selector_arguments(
                    raw, arguments, "redfish_user_env"
                ),
                password_env=self._selector_arguments(
                    raw, arguments, "redfish_password_env"
                ),
                environ=os.environ,
            )
            selectors = (ssh_selector, telnet_selector, redfish_selector)
            policy_name = self._selector_arguments(
                raw, arguments, "ssh_host_key_policy"
            ) or "insecure"
            target = TargetSpec.for_credential_selectors(
                host=host,
                ssh_port=int(raw.get("ssh_port", arguments.get("ssh_port", 22))),
                telnet_port=int(
                    raw.get("telnet_port", arguments.get("telnet_port", 23))
                ),
                redfish_port=int(
                    raw.get("redfish_port", arguments.get("redfish_port", 443))
                ),
                credential_selectors=selectors,
                policy=TargetPolicy(
                    read_only=str(arguments.get("intent", "diagnosis-only"))
                    .strip()
                    .lower()
                    in {
                        "diagnosis-only",
                        "debug-only",
                        "diagnose",
                        "bundle-and-diagnose",
                    },
                    ssh_host_key_policy=policy_name,
                ),
            )
            target_id_value = raw.get(
                "target_id",
                arguments.get("target_id", f"target-{index}"),
            )
            bindings.append(
                TaskTargetBinding(
                    target_id=str(target_id_value),
                    role=self._target_role(
                        raw, arguments, multiple=multiple
                    ),
                    target=target,
                    credential_selectors=selectors,
                )
            )
        return tuple(bindings)

    @staticmethod
    def _inferred_delivery_strategy(
        intent_value: str,
        arguments: Mapping[str, object],
        *,
        tool_name: str,
    ) -> str | None:
        if TaskIntentKind.parse(intent_value) is not TaskIntentKind.DIAGNOSE_AND_FIX:
            return None
        supplied = arguments.get("delivery_strategy")
        if isinstance(supplied, str) and supplied.strip():
            return supplied
        workflow = arguments.get(_WORKFLOW_ARGUMENT)
        if isinstance(workflow, Mapping):
            has_build_upgrade = "build" in workflow or "upgrade" in workflow
            has_live_patch = "live_patch" in workflow
            if has_build_upgrade and has_live_patch:
                raise ValueError(
                    "diagnose-and-fix workflow cannot mix live_patch with build/upgrade"
                )
            if has_build_upgrade:
                return DeliveryStrategy.BUILD_UPGRADE.value
            if has_live_patch:
                return DeliveryStrategy.LIVE_PATCH.value
            if "developer" in workflow:
                return DeliveryStrategy.SOURCE_ONLY.value
        domain = _TOOL_DOMAINS.get(tool_name)
        if domain == "live_patch":
            return DeliveryStrategy.LIVE_PATCH.value
        if domain == "upgrade":
            return DeliveryStrategy.BUILD_UPGRADE.value
        return None

    def _new_intent(
        self,
        tool_name: str,
        arguments: Mapping[str, object],
    ) -> TaskIntent:
        domain = _TOOL_DOMAINS[tool_name]
        intent_value = arguments.get("intent")
        if not isinstance(intent_value, str) or not intent_value.strip():
            if (
                domain == "live_patch"
                and str(arguments.get("action", "")).strip().lower()
                == "rollback"
            ):
                intent_value = "rollback"
            else:
                intent_value = {
                    "upgrade": "upgrade-and-verify",
                    "live_patch": "live-patch",
                }.get(domain, "diagnosis-only")
        entry_domain = arguments.get("entry_domain", domain)
        if not isinstance(entry_domain, str):
            raise TypeError("entry_domain must be a string")
        final_purpose = arguments.get("final_purpose")
        if not isinstance(final_purpose, str) or not final_purpose.strip():
            final_purpose = next(
                (
                    str(arguments[key]).strip()
                    for key in ("problem", "keyword", "profile")
                    if isinstance(arguments.get(key), str)
                    and str(arguments[key]).strip()
                ),
                f"complete the {intent_value} task",
            )
        authorized_exceptions = arguments.get("authorized_exceptions")
        if authorized_exceptions is not None and not isinstance(
            authorized_exceptions, Mapping
        ):
            raise TypeError("authorized_exceptions must be an object")
        allow_insecure_tls = arguments.get("allow_insecure_tls", True)
        if not isinstance(allow_insecure_tls, bool):
            raise TypeError("allow_insecure_tls must be a boolean")
        return TaskIntent.create(
            original_intent=intent_value,
            final_purpose=final_purpose,
            entry_domain=entry_domain,
            targets=self._target_bindings(arguments),
            delivery_strategy=self._inferred_delivery_strategy(
                intent_value,
                arguments,
                tool_name=tool_name,
            ),
            authorized_exceptions=authorized_exceptions,
            allow_insecure_tls=allow_insecure_tls,
        )

    def _remember_orchestration(self, context: TaskOrchestrationContext) -> None:
        self._orchestration_history.append(context)
        del self._orchestration_history[:-_MAX_ORCHESTRATION_HISTORY]

    def _current_target_payloads(
        self,
        arguments: Mapping[str, object],
    ) -> list[dict[str, object]]:
        assert self.orchestration is not None
        selected = self._explicit_target_id(arguments)
        connection_overrides = {
            key: value
            for key, value in arguments.items()
            if key in (_SHARED_ARGUMENTS | _SECRET_ARGUMENTS) and key != "ip"
        }
        payloads: list[dict[str, object]] = []
        for binding in self.orchestration.intent.targets:
            payload = dict(self._target_arguments.get(binding.target_id, {}))
            payload.update(
                {
                    "ip": binding.target.host,
                    "ssh_port": binding.target.ssh_port,
                    "telnet_port": binding.target.telnet_port,
                    "redfish_port": binding.target.redfish_port,
                    "target_id": binding.target_id,
                    "role": binding.role,
                }
            )
            if not selected or selected == binding.target_id:
                payload.update(connection_overrides)
            payloads.append(payload)
        return payloads

    def _merged_intent_arguments(
        self,
        tool_name: str,
        arguments: Mapping[str, object],
    ) -> dict[str, object]:
        current = self.orchestration
        supplied_ip = arguments.get("ip")
        has_ip = isinstance(supplied_ip, str) and bool(supplied_ip.strip())
        has_targets = "targets" in arguments
        merged = dict(self._shared_arguments)
        if current is not None and (has_ip or has_targets):
            merged = {
                key: value
                for key, value in self._shared_arguments.items()
                if key in _REUSABLE_CONNECTION_ARGUMENTS
            }
            if len(current.intent.targets) == 1:
                current_target = current.intent.targets[0]
                current_payload = self._target_arguments.get(
                    current_target.target_id, {}
                )
                merged.update(
                    {
                        key: value
                        for key, value in current_payload.items()
                        if key in _REUSABLE_CONNECTION_ARGUMENTS
                    }
                )
                if any(
                    key in current_payload
                    for key in (
                        "ssh_password",
                        "telnet_password",
                        "redfish_password",
                    )
                ) and "ssh_host_key_policy" in current_payload:
                    merged["ssh_host_key_policy"] = current_payload[
                        "ssh_host_key_policy"
                    ]
        if current is not None and not has_ip and not has_targets:
            merged.pop("ip", None)
            merged["targets"] = self._current_target_payloads(arguments)
        elif has_targets:
            merged.pop("ip", None)
        merged.update(arguments)
        if current is None:
            merged.setdefault("allow_insecure_tls", True)
            return merged
        if has_ip and not has_targets and len(current.intent.targets) == 1:
            current_target = current.intent.targets[0]
            merged.setdefault("target_id", current_target.target_id)
            merged.setdefault("target_role", current_target.role)

        supplied_intent = arguments.get("intent")
        if (
            tool_name == "live_patch_run"
            and (not isinstance(supplied_intent, str) or not supplied_intent.strip())
        ):
            supplied_action = str(arguments.get("action", "")).strip().lower()
            if supplied_action == "rollback":
                supplied_intent = "rollback"
                merged["intent"] = supplied_intent
        same_intent = (
            not isinstance(supplied_intent, str)
            or not supplied_intent.strip()
        )
        if isinstance(supplied_intent, str) and supplied_intent.strip():
            same_intent = (
                TaskIntentKind.parse(supplied_intent)
                is current.intent.original_intent
            )
        if same_intent:
            inferred = self._inferred_delivery_strategy(
                current.intent.original_intent.value,
                arguments,
                tool_name=tool_name,
            )
            current_delivery = (
                current.intent.delivery_strategy.value
                if current.intent.delivery_strategy is not None
                else ""
            )
            selecting_delivery = (
                current.intent.original_intent
                is TaskIntentKind.DIAGNOSE_AND_FIX
                and current_delivery == DeliveryStrategy.SOURCE_ONLY.value
                and inferred
                in {
                    DeliveryStrategy.LIVE_PATCH.value,
                    DeliveryStrategy.BUILD_UPGRADE.value,
                }
            )
            merged.setdefault("intent", current.intent.original_intent.value)
            merged.setdefault("entry_domain", current.intent.entry_domain)
            merged.setdefault("final_purpose", current.intent.final_purpose)
            current_exceptions = (
                current.intent.authorization.authorized_exceptions.to_public_dict()
            )
            if selecting_delivery:
                merged.setdefault("authorized_exceptions", current_exceptions)
                if current.intent.authorization.allow_insecure_tls:
                    merged.setdefault("allow_insecure_tls", True)
            else:
                supplied_exceptions = arguments.get("authorized_exceptions")
                if supplied_exceptions is None:
                    merged["authorized_exceptions"] = current_exceptions
                else:
                    if not isinstance(supplied_exceptions, Mapping):
                        raise TypeError("authorized_exceptions must be an object")
                    requested_exceptions = MutationAuthorizedExceptions.from_value(
                        {
                            **current_exceptions,
                            **dict(supplied_exceptions),
                        }
                    ).to_public_dict()
                    merged["authorized_exceptions"] = {
                        name: current_exceptions[name]
                        and requested_exceptions[name]
                        for name in current_exceptions
                    }
                if "allow_insecure_tls" in arguments:
                    supplied_tls = arguments["allow_insecure_tls"]
                    if not isinstance(supplied_tls, bool):
                        raise TypeError("allow_insecure_tls must be a boolean")
                    merged["allow_insecure_tls"] = (
                        current.intent.authorization.allow_insecure_tls
                        and supplied_tls
                    )
                elif current.intent.authorization.allow_insecure_tls:
                    merged["allow_insecure_tls"] = True
            if "delivery_strategy" not in arguments:
                if inferred is not None:
                    merged["delivery_strategy"] = inferred
                elif current.intent.delivery_strategy is not None:
                    merged["delivery_strategy"] = (
                        current.intent.delivery_strategy.value
                    )
        else:
            merged.setdefault("final_purpose", current.intent.final_purpose)
            merged.setdefault(
                "authorized_exceptions",
                current.intent.authorization.authorized_exceptions.to_public_dict(),
            )
            merged.setdefault(
                "allow_insecure_tls",
                current.intent.authorization.allow_insecure_tls,
            )
        return merged

    @staticmethod
    def _captured_target_arguments(
        arguments: Mapping[str, object],
        intent: TaskIntent,
    ) -> dict[str, dict[str, object]]:
        raw_targets = arguments.get("targets")
        if raw_targets is None:
            raw_targets = [arguments]
        assert isinstance(raw_targets, list)
        common = {
            key: value
            for key, value in arguments.items()
            if key in (_SHARED_ARGUMENTS | _SECRET_ARGUMENTS) and key != "ip"
        }
        captured: dict[str, dict[str, object]] = {}
        for binding, raw in zip(intent.targets, raw_targets, strict=True):
            assert isinstance(raw, Mapping)
            payload = dict(common)
            payload.update(
                {
                    key: value
                    for key, value in raw.items()
                    if key in (_SHARED_ARGUMENTS | _SECRET_ARGUMENTS)
                    and key != "ip"
                }
            )
            payload.update(
                {
                    "ip": binding.target.host,
                    "ssh_port": binding.target.ssh_port,
                    "telnet_port": binding.target.telnet_port,
                    "redfish_port": binding.target.redfish_port,
                    "target_id": binding.target_id,
                    "role": binding.role,
                }
            )
            captured[binding.target_id] = payload
        return captured

    @staticmethod
    def _credential_selector_fingerprints(intent: TaskIntent) -> frozenset[str]:
        return frozenset(
            selector.fingerprint
            for target in intent.targets
            for selector in target.credential_selectors
        )

    def bind_intent(self, tool_name: str, arguments: Mapping[str, object]) -> None:
        with self._lock:
            current = self.orchestration
            merged = self._merged_intent_arguments(tool_name, arguments)
            intent = self._new_intent(tool_name, merged)
            if (
                current is not None
                and self._credential_selector_fingerprints(current.intent)
                != self._credential_selector_fingerprints(intent)
            ):
                self._credential_values = None
            if current is not None and current.intent.fingerprint != intent.fingerprint:
                self._remember_orchestration(current)
            if current is None or current.intent.fingerprint != intent.fingerprint:
                self.orchestration = TaskOrchestrationContext(
                    task_id=self.task_id,
                    intent=intent,
                )
            self._shared_arguments = {
                key: value
                for key, value in merged.items()
                if key in _SHARED_ARGUMENTS
                and key != "ip"
                and key not in _SECRET_ARGUMENTS
            }
            self._target_arguments = self._captured_target_arguments(
                merged,
                intent,
            )
        self._persist_context()

    @staticmethod
    def _explicit_target_id(arguments: Mapping[str, object]) -> str:
        selected_id = arguments.get("target_id")
        return (
            selected_id.strip()
            if isinstance(selected_id, str) and selected_id.strip()
            else ""
        )

    def _selected_target(self, arguments: Mapping[str, object]) -> TaskTargetBinding:
        assert self.orchestration is not None
        targets = self.orchestration.intent.targets
        selected_id = self._explicit_target_id(arguments)
        if selected_id:
            for target in targets:
                if target.target_id == selected_id:
                    return target
            raise ValueError(f"unknown task target_id: {selected_id}")
        if len(targets) == 1:
            return targets[0]
        candidates = [target for target in targets if target.role == "candidate"]
        if len(candidates) == 1:
            return candidates[0]
        return targets[0]

    def _selected_mutation_target(
        self, arguments: Mapping[str, object]
    ) -> TaskTargetBinding:
        assert self.orchestration is not None
        targets = self.orchestration.intent.targets
        selected_id = self._explicit_target_id(arguments)
        if selected_id:
            return self._selected_target(arguments)
        if len(targets) == 1:
            return targets[0]
        candidates = [target for target in targets if target.role == "candidate"]
        if len(candidates) == 1:
            return candidates[0]
        eligible = candidates or list(targets)
        label = "candidate" if candidates else "task"
        target_ids = ", ".join(sorted(target.target_id for target in eligible))
        raise ValueError(
            "mutation target is ambiguous; specify target_id from "
            f"{label} targets: {target_ids}"
        )

    @staticmethod
    def _project_domain_arguments(
        tool_name: str,
        arguments: Mapping[str, object],
    ) -> dict[str, object]:
        domain = _TOOL_DOMAINS[tool_name]
        allowed = _DOMAIN_CONNECTION_ARGUMENTS[domain]
        if arguments.get("_context_authoritative") is True:
            allowed = allowed | {
                "debug": _SSH_SECRET_ARGUMENTS | _TELNET_SECRET_ARGUMENTS,
                "log_analyzer": _SSH_SECRET_ARGUMENTS | _REDFISH_SECRET_ARGUMENTS,
                "live_patch": _SSH_SECRET_ARGUMENTS | _TELNET_SECRET_ARGUMENTS,
                "upgrade": _REDFISH_SECRET_ARGUMENTS,
            }[domain]
        projected = dict(arguments)
        disallowed = (
            ((_SHARED_ARGUMENTS | _SECRET_ARGUMENTS) - allowed)
            | _DOMAIN_ARGUMENTS_TO_STRIP.get(domain, frozenset())
        )
        for key in disallowed:
            projected.pop(key, None)
        raw_targets = projected.get("targets")
        if isinstance(raw_targets, list):
            projected["targets"] = [
                (
                    {
                        key: value
                        for key, value in target.items()
                        if key not in disallowed
                    }
                    if isinstance(target, Mapping)
                    else target
                )
                for target in raw_targets
            ]
        projected.pop("_context_authoritative", None)
        return projected

    def arguments_for(
        self, tool_name: str, arguments: Mapping[str, object]
    ) -> dict[str, object]:
        self.bind_intent(tool_name, arguments)
        assert self.orchestration is not None
        merged = dict(self._shared_arguments)
        if (
            tool_name == "debug_run"
            and len(self.orchestration.intent.targets) > 1
            and not self._explicit_target_id(arguments)
        ):
            merged.update(arguments)
            raw_targets = arguments.get("targets")
            target_payloads: list[dict[str, object]] = []
            for index, target in enumerate(self.orchestration.intent.targets):
                payload = dict(self._target_arguments[target.target_id])
                if (
                    isinstance(raw_targets, list)
                    and index < len(raw_targets)
                    and isinstance(raw_targets[index], Mapping)
                ):
                    payload.update(
                        {
                            key: value
                            for key, value in raw_targets[index].items()
                            if key not in _SECRET_ARGUMENTS and not key.startswith("_")
                        }
                    )
                target_payloads.append(payload)
            merged["targets"] = target_payloads
            merged.pop("ip", None)
        else:
            target = (
                self._selected_mutation_target(arguments)
                if tool_name in _MUTATION_TOOLS
                else self._selected_target(arguments)
            )
            merged.update(self._target_arguments[target.target_id])
            merged.update(arguments)
            merged["ip"] = target.target.host
            if tool_name in {
                "debug_run",
                "debug_collect",
                "log_bundle_collect",
                "live_patch_run",
                "upgrade_run",
            }:
                merged["ssh_port"] = target.target.ssh_port
            if tool_name in {"debug_run", "debug_collect", "live_patch_run"}:
                merged["telnet_port"] = target.target.telnet_port
            if tool_name in {"log_bundle_collect", "upgrade_run"}:
                merged["redfish_port"] = target.target.redfish_port
            merged.pop("targets", None)
        merged.pop(_WORKFLOW_ARGUMENT, None)
        for key in _ORCHESTRATION_ARGUMENTS:
            merged.pop(key, None)
        merged.pop("role", None)
        merged = self._project_domain_arguments(tool_name, merged)
        if tool_name in _CREDENTIAL_VALUE_TOOLS:
            merged["_credential_values"] = self.credential_values()
        if tool_name in {"live_patch_run", "upgrade_run"}:
            merged["_task_intent"] = (
                self.orchestration.intent.original_intent.value
            )
            frozen_delivery_strategy = ""
            if arguments.get(CONTEXT_WORKFLOW_STEP_ARGUMENT) is True:
                frozen_delivery_strategy = str(
                    arguments.get("delivery_strategy", "")
                ).strip()
            merged["_task_delivery_strategy"] = frozen_delivery_strategy or (
                self.orchestration.intent.delivery_strategy.value
                if self.orchestration.intent.delivery_strategy is not None
                else ""
            )
            merged["_task_authorized_exceptions"] = (
                self.orchestration.intent.authorization.authorized_exceptions.to_public_dict()
            )
            merged[_TASK_AUTHORIZATION_POLICY_ARGUMENT] = (
                self.orchestration.intent.authorization.to_public_dict()
            )
        merged.pop(CONTEXT_WORKFLOW_STEP_ARGUMENT, None)
        return merged

    def credential_values(self) -> dict[str, str]:
        with self._lock:
            if self._credential_values is None:
                self._credential_values = load_selected_credentials_file()
                self._credential_parse_count += 1
            return dict(self._credential_values)

    def record_workflow_summary(
        self,
        request_fingerprint: str,
        result: dict[str, object],
    ) -> None:
        with self._workflow_lock:
            self._workflow_summaries.append(
                self._workflow_summary(request_fingerprint, result)
            )
            if len(self._workflow_summaries) > _MAX_WORKFLOW_SUMMARIES:
                del self._workflow_summaries[:-_MAX_WORKFLOW_SUMMARIES]
        self._persist_context()

    def record_mutation_identity(
        self,
        domain: str,
        request_fingerprint: str,
        operation_id: str,
    ) -> None:
        identity = {
            "domain": str(domain),
            "request_fingerprint": str(request_fingerprint),
            "operation_id": str(operation_id),
        }
        with self._workflow_lock:
            self._mutation_journal_identities[request_fingerprint] = identity
            self._mutation_journal_identities.move_to_end(request_fingerprint)
            while len(self._mutation_journal_identities) > _MAX_MUTATION_OUTCOMES:
                self._mutation_journal_identities.popitem(last=False)
        self._persist_context()

    def cached_mutation(
        self,
        request_fingerprint: str,
    ) -> DomainOutcome[object] | None:
        with self._workflow_lock:
            outcome = self._mutation_outcomes.get(request_fingerprint)
            if outcome is not None:
                self._mutation_outcomes.move_to_end(request_fingerprint)
            return outcome

    def store_mutation(
        self,
        request_fingerprint: str,
        outcome: DomainOutcome[object],
    ) -> DomainOutcome[object]:
        with self._workflow_lock:
            self._mutation_outcomes[request_fingerprint] = outcome
            self._mutation_outcomes.move_to_end(request_fingerprint)
            while len(self._mutation_outcomes) > _MAX_MUTATION_OUTCOMES:
                self._mutation_outcomes.popitem(last=False)
            return outcome

    @contextmanager
    def domain_admission(
        self,
        tool_name: str,
        arguments: Mapping[str, object],
        context: OperationContext,
    ):
        self.bind_intent(tool_name, arguments)
        assert self.orchestration is not None
        if tool_name in _MUTATION_TOOLS:
            bindings = (self._selected_mutation_target(arguments),)
        elif (
            tool_name == "debug_run"
            and len(self.orchestration.intent.targets) > 1
            and not self._explicit_target_id(arguments)
        ):
            bindings = self.orchestration.intent.targets
        else:
            bindings = (self._selected_target(arguments),)
        ordered = sorted(
            bindings,
            key=lambda binding: binding.target_id,
        )
        with self._lock:
            coordinators = [
                self._target_admissions.setdefault(
                    binding.target_id,
                    TargetLeaseCoordinator(),
                )
                for binding in ordered
            ]
        with ExitStack() as stack:
            for coordinator in coordinators:
                manager = (
                    coordinator.mutation(context)
                    if tool_name in _MUTATION_TOOLS
                    else coordinator.read(context)
                )
                stack.enter_context(manager)
            yield

    def resource_for(self, tool_name: str) -> tuple[object, object]:
        backend = self.tool_backends[tool_name]
        key = id(backend)
        with self._lock:
            resource = self._resources.get(key)
            if resource is None:
                resource = backend.open_task(self.task_id)
                self._resources[key] = resource
            self._resource_tools[tool_name] = resource
            return backend, resource

    def maintain(self) -> int:
        total = 0
        seen: set[int] = set()
        with self._lock:
            resources = list(self._resource_tools.items())
        for tool_name, resource in resources:
            backend = self.tool_backends[tool_name]
            key = id(backend)
            if key in seen:
                continue
            seen.add(key)
            total += int(backend.maintain_task(resource) or 0)
        return total

    @staticmethod
    def _workflow_summary(
        request_fingerprint: str,
        result: Mapping[str, object],
    ) -> dict[str, object]:
        intent = result.get("intent")
        public_intent = (
            {
                key: intent.get(key)
                for key in (
                    "original_intent",
                    "delivery_strategy",
                    "fingerprint",
                )
            }
            if isinstance(intent, Mapping)
            else None
        )
        return {
            "request_fingerprint": request_fingerprint,
            "completed": bool(result.get("completed", False)),
            "partial": bool(result.get("partial", False)),
            "next_action": str(result.get("next_action", "")),
            "intent": public_intent,
            "phase_states": (
                dict(result["phase_states"])
                if isinstance(result.get("phase_states"), Mapping)
                else {}
            ),
        }

    def status(self) -> dict[str, object]:
        with self._lock:
            resources = dict(self._resource_tools)
            orchestration = self.orchestration
            orchestration_history = tuple(self._orchestration_history)
            target_admissions = dict(self._target_admissions)
            credential_parse_count = self._credential_parse_count
            persistence_error = self._persistence_error
            recovered_context = self._recovered_context
        with self._workflow_lock:
            workflow_summaries = [
                {
                    **summary,
                    "intent": (
                        dict(summary["intent"])
                        if isinstance(summary.get("intent"), Mapping)
                        else None
                    ),
                    "phase_states": (
                        dict(summary["phase_states"])
                        if isinstance(summary.get("phase_states"), Mapping)
                        else {}
                    ),
                }
                for summary in self._workflow_summaries
            ]
            cached_mutation_count = len(self._mutation_outcomes)
            mutation_journal_identity_count = len(
                self._mutation_journal_identities
            )
        return {
            "task_id": self.task_id,
            "credential_parse_count": credential_parse_count,
            "orchestration": (
                orchestration.to_public_dict()
                if orchestration is not None
                else None
            ),
            "orchestration_history": [
                context.to_public_dict()
                for context in orchestration_history
            ],
            "automatic_workflow": (
                dict(workflow_summaries[-1])
                if workflow_summaries
                else None
            ),
            "automatic_workflows": workflow_summaries,
            "workflow_history": {
                "entry_count": len(workflow_summaries),
                "max_entries": _MAX_WORKFLOW_SUMMARIES,
            },
            "workflow_cache": {
                "enabled": False,
                "entry_count": 0,
                "bytes": 0,
                "max_entries": 0,
                "max_result_bytes": 0,
                "max_bytes": 0,
            },
            "cached_mutation_count": cached_mutation_count,
            "task_context": {
                "persistent": self._state_store is not None,
                "recovered": recovered_context,
                "last_error": persistence_error,
                "mutation_journal_identity_count": (
                    mutation_journal_identity_count
                ),
                "connections_recovered": False,
                "evidence_results_recovered": False,
            },
            "target_admission": {
                target_id: coordinator.to_public_dict()
                for target_id, coordinator in target_admissions.items()
            },
            "domain_resources": {
                tool_name: self.tool_backends[tool_name].task_status(resource)
                for tool_name, resource in resources.items()
            },
        }

    def close(self) -> None:
        seen: set[int] = set()
        with self._lock:
            resources = list(self._resource_tools.items())
            self._resource_tools.clear()
            self._resources.clear()
            self._credential_values = None
            self._workflow_summaries.clear()
            self._mutation_outcomes.clear()
            self._mutation_journal_identities.clear()
            self._target_arguments.clear()
        for tool_name, resource in resources:
            backend = self.tool_backends[tool_name]
            key = id(backend)
            if key in seen:
                continue
            seen.add(key)
            backend.close_task(resource)


class OrchestratedMcpBackend:
    """Share typed intent across domain backends while isolating their resources."""

    def __init__(
        self,
        tool_backends: Mapping[str, object],
        *,
        state_store: TaskContextStore | None = None,
        phase_adapters: Mapping[str, object] | None = None,
    ) -> None:
        if not tool_backends:
            raise ValueError("at least one domain tool backend is required")
        unknown = set(tool_backends) - set(_TOOL_DOMAINS)
        if unknown:
            raise ValueError(
                "unsupported orchestrated MCP tools: " + ", ".join(sorted(unknown))
            )
        for tool_name, backend in tool_backends.items():
            if not callable(getattr(backend, tool_name, None)):
                raise TypeError(f"backend for {tool_name} does not implement that tool")
        self.tool_backends = dict(tool_backends)
        self.state_store = state_store
        self.phase_adapters = dict(
            phase_adapters
            or {
                "developer.change": self._developer_outcome,
                "build.artifact": lambda raw: self._provided_domain_outcome(
                    "build", raw
                ),
            }
        )
        invalid_phase_adapters = [
            name
            for name, adapter in self.phase_adapters.items()
            if not callable(adapter)
        ]
        if invalid_phase_adapters:
            raise TypeError(
                "workflow phase adapters must be callable: "
                + ", ".join(sorted(invalid_phase_adapters))
            )

    @property
    def artifact_store(self):
        stores = {
            id(store): store
            for store in (
                getattr(backend, "artifact_store", None)
                for backend in self.tool_backends.values()
            )
            if store is not None
        }
        if len(stores) > 1:
            raise ValueError("domain backends must share one Runtime ArtifactStore")
        return next(iter(stores.values()), None)

    def bind_artifact_store(self, artifact_store: LocalArtifactStore) -> None:
        seen: set[int] = set()
        for backend in self.tool_backends.values():
            if id(backend) in seen:
                continue
            seen.add(id(backend))
            binder = getattr(backend, "bind_artifact_store", None)
            if callable(binder):
                binder(artifact_store)

    def open_task(self, task_id: str) -> _OrchestratedMcpTask:
        return _OrchestratedMcpTask(
            task_id,
            self.tool_backends,
            state_store=self.state_store,
        )

    def forget_task(self, task_id: str) -> bool:
        return (
            self.state_store.delete(task_id)
            if self.state_store is not None
            else False
        )

    @staticmethod
    def prepare_task_completion(task: _OrchestratedMcpTask) -> None:
        task.seal_persistence()

    def persistent_status(self) -> dict[str, object]:
        if self.state_store is None:
            return {"enabled": False}
        return self.state_store.status()

    @staticmethod
    def close_task(task: _OrchestratedMcpTask) -> None:
        task.close()

    @staticmethod
    def maintain_task(task: _OrchestratedMcpTask) -> int:
        return task.maintain()

    @staticmethod
    def task_status(task: _OrchestratedMcpTask) -> dict[str, object]:
        return task.status()

    @staticmethod
    def _workflow_sections(arguments: Mapping[str, object]) -> Mapping[str, object]:
        raw = arguments.get(_WORKFLOW_ARGUMENT, {})
        if not isinstance(raw, Mapping):
            raise TypeError("workflow must be an object")
        return raw

    def _should_orchestrate(
        self,
        task: _OrchestratedMcpTask,
        tool_name: str,
        arguments: Mapping[str, object],
    ) -> bool:
        task.bind_intent(tool_name, arguments)
        if arguments.get("_context_authoritative") is True:
            return False
        if arguments.get(CONTEXT_WORKFLOW_STEP_ARGUMENT) is True:
            return False
        assert task.orchestration is not None
        steps = task.orchestration.intent.steps
        if len(steps) <= 1 or steps[0].canonical_name != tool_name:
            return False
        if any(
            step.canonical_name == "diagnosis.acceptance"
            for step in steps
        ):
            return False
        required_tools = {
            step.canonical_name
            for step in steps
            if step.kind == "operation"
        }
        if not required_tools.issubset(self.tool_backends):
            return False
        if (
            task.orchestration.intent.original_intent
            is TaskIntentKind.DIAGNOSE_AND_FIX
        ):
            sections = self._workflow_sections(arguments)
            for step in steps:
                if (
                    step.kind == "phase"
                    and not isinstance(
                    sections.get(step.domain), Mapping
                    )
                ):
                    return False
                if step.kind == "operation":
                    contract = DEFAULT_OPERATION_CONTRACTS.require(
                        step.canonical_name
                    )
                    if (
                        contract.mutation
                        and step.canonical_name != tool_name
                        and not isinstance(sections.get(step.domain), Mapping)
                    ):
                        return False
        return True

    @staticmethod
    def _domain_context(
        parent: OperationContext,
        execution: DomainExecutionContext,
    ) -> OperationContext:
        return parent.derive(execution.operation_id)

    @staticmethod
    def _developer_outcome(
        raw: object,
    ) -> DomainOutcome[object]:
        if not isinstance(raw, Mapping):
            raise ValueError("diagnose-and-fix requires workflow.developer")

        def string_tuple(name: str) -> tuple[str, ...]:
            values = raw.get(name, [])
            if not isinstance(values, list) or not all(
                isinstance(value, str) and value for value in values
            ):
                raise TypeError(f"workflow.developer.{name} must be an array of strings")
            return tuple(values)

        edit = DeveloperEditIntent(
            component_roots=string_tuple("component_roots"),
            authored_files=string_tuple("authored_files"),
            change_summary=str(raw.get("change_summary", "")),
            runtime_artifact=str(raw.get("runtime_artifact", "")),
            restart_scope=str(raw.get("restart_scope", "none")),
            verification_checks=string_tuple("verification_checks"),
        )
        return DomainOutcome.succeeded(
            {"edit_handoff": "provided"},
            edit_intent=edit,
        )

    @staticmethod
    def _provided_domain_outcome(
        domain: str,
        raw: object,
    ) -> DomainOutcome[object]:
        if not isinstance(raw, Mapping):
            raise ValueError(f"workflow.{domain} must be an object")
        value = dict(raw)
        raw_evidence = value.get("evidence_ids", [])
        evidence_ids = (
            tuple(
                item
                for item in raw_evidence
                if isinstance(item, str) and item
            )
            if isinstance(raw_evidence, list)
            else ()
        )
        return DomainOutcome.succeeded(value, evidence_ids=evidence_ids)

    @staticmethod
    def _runtime_status(value: Mapping[str, object]) -> Mapping[str, object]:
        containers: list[Mapping[str, object]] = [value]
        result = value.get("result")
        if isinstance(result, Mapping):
            containers.append(result)
        for container in containers:
            runtime = container.get("runtime")
            if not isinstance(runtime, Mapping):
                continue
            status = runtime.get("status")
            if isinstance(status, Mapping):
                return status
        return {}

    @classmethod
    def _evidence_ids(cls, value: Mapping[str, object]) -> tuple[str, ...]:
        raw = value.get("evidence_ids", [])
        evidence_ids = [
            item for item in raw if isinstance(item, str) and item
        ] if isinstance(raw, list) else []
        status = cls._runtime_status(value)
        ledger = status.get("evidence_ledger")
        if isinstance(ledger, Mapping):
            records = ledger.get("records", [])
            if isinstance(records, list):
                evidence_ids.extend(
                    str(record["evidence_id"])
                    for record in records
                    if isinstance(record, Mapping)
                    and isinstance(record.get("evidence_id"), str)
                    and record["evidence_id"]
                )
        return tuple(dict.fromkeys(evidence_ids))

    @classmethod
    def _observed_target_epoch(
        cls,
        value: Mapping[str, object],
        target: TaskTargetBinding,
    ) -> int:
        observed = value.get("observed_target_epochs")
        if isinstance(observed, Mapping) and target.target_id in observed:
            epoch = observed[target.target_id]
        elif "target_epoch" in value:
            epoch = value.get("target_epoch")
        else:
            epoch = None
            status = cls._runtime_status(value)
            targets = status.get("targets", [])
            if isinstance(targets, list):
                for candidate in targets:
                    if not isinstance(candidate, Mapping):
                        continue
                    target_value = candidate.get("target")
                    if not isinstance(target_value, Mapping):
                        continue
                    fingerprint = target_value.get("fingerprint")
                    host = target_value.get("host")
                    if fingerprint != target.target.fingerprint and (
                        not isinstance(host, str)
                        or host.strip().lower() != target.target.host
                    ):
                        continue
                    epochs = candidate.get("epochs")
                    if isinstance(epochs, Mapping):
                        epoch = epochs.get("target_epoch")
                    break
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
            raise ValueError(
                "fresh verification backend must report a non-negative target epoch"
            )
        return epoch

    @staticmethod
    def _domain_outcome(
        task: _OrchestratedMcpTask,
        execution: DomainExecutionContext,
        arguments: Mapping[str, object],
        value: object,
    ) -> DomainOutcome[object]:
        if execution.phase == "mutation":
            mutation = MutationDomainResult.from_backend(value)
            target = task._selected_mutation_target(arguments)
            return DomainOutcome.modified(
                mutation.value,
                evidence_ids=mutation.evidence_ids,
                modified_target_epochs={target.target_id: mutation.epoch_after},
                operation_id=execution.operation_id,
            )
        if not isinstance(value, Mapping):
            raise TypeError("MCP domain backend must return an object")
        public_value = dict(value)
        evidence_ids = OrchestratedMcpBackend._evidence_ids(public_value)
        if execution.phase == "fresh_verification":
            target = task._selected_target(arguments)
            observed_epoch = OrchestratedMcpBackend._observed_target_epoch(
                public_value,
                target,
            )
            minimum_epoch = int(
                execution.minimum_target_epochs.get(target.target_id, 0)
            )
            if observed_epoch < minimum_epoch:
                raise ValueError(
                    "fresh verification reported stale target epoch "
                    f"{observed_epoch} for {target.target_id}; "
                    f"requires at least {minimum_epoch}"
                )
            return DomainOutcome.verified(
                public_value,
                evidence_ids=evidence_ids,
                observed_target_epochs={target.target_id: observed_epoch},
            )
        return DomainOutcome.succeeded(public_value, evidence_ids=evidence_ids)

    @staticmethod
    def _step_arguments(
        root_arguments: Mapping[str, object],
        sections: Mapping[str, object],
        execution: DomainExecutionContext,
    ) -> dict[str, object]:
        first_step = execution.intent.steps[0]
        if execution.domain == first_step.domain and execution.phase == first_step.phase:
            selected = {
                key: value
                for key, value in root_arguments.items()
                if key != _WORKFLOW_ARGUMENT
            }
        else:
            section_name = (
                "verification"
                if execution.phase == "fresh_verification"
                else execution.domain
            )
            raw = sections.get(section_name, {})
            if not isinstance(raw, Mapping):
                raise TypeError(f"workflow.{section_name} must be an object")
            selected = {
                key: value
                for key, value in raw.items()
                if key not in _WORKFLOW_SECTION_PROTECTED_ARGUMENTS
                and not str(key).startswith("_")
            }
        if execution.domain == "live_patch" and execution.edit_intent is not None:
            selected.setdefault("local_path", execution.edit_intent.runtime_artifact)
            selected.setdefault("restart_scope", execution.edit_intent.restart_scope)
            selected.setdefault(
                "verification_checks",
                list(execution.edit_intent.verification_checks),
            )
        if execution.domain == "upgrade":
            build_result = next(
                (
                    previous.value
                    for previous in reversed(execution.previous)
                    if previous.domain == "build"
                    and previous.phase == "package"
                    and isinstance(previous.value, Mapping)
                ),
                None,
            )
            if isinstance(build_result, Mapping):
                for name in (
                    "artifact_path",
                    "artifact_sha256",
                    "product_version",
                ):
                    if name in build_result:
                        selected.setdefault(name, build_result[name])
        if execution.phase == "fresh_verification":
            if len(execution.minimum_target_epochs) != 1:
                raise ValueError(
                    "fresh verification requires exactly one modified target"
                )
            for name in ("ip", "targets", "role", "target_role", "target_id"):
                selected.pop(name, None)
            selected["target_id"] = next(iter(execution.minimum_target_epochs))
        else:
            target_id = root_arguments.get("target_id")
            if isinstance(target_id, str) and target_id.strip():
                selected.setdefault("target_id", target_id.strip())
        if execution.phase == "fresh_verification":
            selected.setdefault("profile", "freshness")
            selected = enforce_fresh_verification(selected)
            if execution.minimum_target_epochs:
                selected["_minimum_target_epoch"] = max(
                    int(epoch)
                    for epoch in execution.minimum_target_epochs.values()
                )
        return selected

    @staticmethod
    def _mutation_request_fingerprint(
        task: _OrchestratedMcpTask,
        domain: str,
        arguments: Mapping[str, object],
    ) -> str:
        target = task._selected_mutation_target(arguments)
        ignored = _ORCHESTRATION_ARGUMENTS | _SECRET_ARGUMENTS | {
            _WORKFLOW_ARGUMENT,
            "deadline",
            "ssh_user",
            "ssh_user_env",
            "ssh_password_env",
            "ssh_identity_file",
            "telnet_user",
            "telnet_user_env",
            "telnet_password_env",
            "redfish_user",
            "redfish_user_env",
            "redfish_password_env",
        }
        operation = {
            key: value
            for key, value in arguments.items()
            if key not in ignored and not key.startswith("_")
        }
        if domain == "live_patch":
            local_path = operation.get("local_path")
            if isinstance(local_path, str) and local_path.strip():
                path = Path(local_path).expanduser()
                if path.is_file():
                    path = path.resolve()
                    operation["local_path"] = str(path)
                    digest = hashlib.sha256()
                    with path.open("rb") as stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(block)
                    operation["local_sha256"] = digest.hexdigest()
                else:
                    authored_digest = str(
                        operation.get("artifact_sha256", "")
                    ).lower()
                    if len(authored_digest) == 64 and all(
                        character in "0123456789abcdef"
                        for character in authored_digest
                    ):
                        operation["local_sha256"] = authored_digest
        return _fingerprint(
            {
                "domain": domain,
                "phase": "mutation",
                "target": target.target.fingerprint,
                "operation": operation,
            }
        )

    @staticmethod
    def _mutation_operation_id(domain: str, request_fingerprint: str) -> str:
        safe_domain = str(domain).strip().lower().replace("_", "-")
        return f"op-mutation-{request_fingerprint[:40]}-{safe_domain}"

    def _run_workflow(
        self,
        task: _OrchestratedMcpTask,
        entry_tool: str,
        arguments: Mapping[str, object],
        context: OperationContext,
    ) -> dict[str, object]:
        assert task.orchestration is not None
        request_fingerprint = _fingerprint(
            {
                "entry_tool": entry_tool,
                "intent": task.orchestration.intent.fingerprint,
                "arguments": dict(arguments),
            }
        )
        with task._workflow_lock:
            sections = self._workflow_sections(arguments)
            workflow_context = TaskOrchestrationContext(
                task_id=f"{task.task_id}:{request_fingerprint[:16]}",
                intent=task.orchestration.intent,
            )
            handlers = {}
            for step in workflow_context.intent.steps:
                if step.kind == "phase":
                    adapter = self.phase_adapters.get(step.canonical_name)
                    if adapter is not None:
                        handlers[step.key] = (
                            lambda _execution, selected=adapter, raw=sections.get(
                                step.domain
                            ): selected(raw)
                        )
                    continue
                tool_name = step.canonical_name
                if tool_name is None or tool_name not in self.tool_backends:
                    continue

                def handler(
                    execution: DomainExecutionContext,
                    *,
                    selected_tool: str = tool_name,
                ) -> DomainOutcome[object]:
                    step_arguments = self._step_arguments(
                        arguments,
                        sections,
                        execution,
                    )
                    mutation_fingerprint = ""
                    domain_execution = execution
                    if execution.phase == "mutation":
                        mutation_fingerprint = self._mutation_request_fingerprint(
                            task,
                            execution.domain,
                            step_arguments,
                        )
                        domain_execution = replace(
                            execution,
                            operation_id=self._mutation_operation_id(
                                execution.domain,
                                mutation_fingerprint,
                            ),
                        )
                        task.record_mutation_identity(
                            execution.domain,
                            mutation_fingerprint,
                            domain_execution.operation_id,
                        )
                        cached_mutation = task.cached_mutation(
                            mutation_fingerprint
                        )
                        if cached_mutation is not None:
                            return cached_mutation
                    backend, resource = task.resource_for(selected_tool)
                    callback = getattr(backend, selected_tool)
                    child_context = self._domain_context(context, domain_execution)
                    with task.domain_admission(
                        selected_tool,
                        step_arguments,
                        child_context,
                    ):
                        value = callback(
                            resource,
                            task.arguments_for(selected_tool, step_arguments),
                            child_context,
                        )
                    outcome = self._domain_outcome(
                        task,
                        domain_execution,
                        step_arguments,
                        value,
                    )
                    if mutation_fingerprint:
                        task.store_mutation(mutation_fingerprint, outcome)
                    return outcome

                handlers[step.key] = handler
            result = TaskWorkflowOrchestrator(workflow_context).run(handlers)
            public_result = result.to_public_dict()
            task.record_workflow_summary(
                request_fingerprint,
                public_result,
            )
            return public_result

    def __getattr__(self, name: str):
        if name not in self.tool_backends:
            raise AttributeError(name)

        def call(task: _OrchestratedMcpTask, arguments, context):
            if self._should_orchestrate(task, name, arguments):
                return self._run_workflow(task, name, arguments, context)
            backend, resource = task.resource_for(name)
            callback = getattr(backend, name)
            domain_context = context
            if name in _MUTATION_TOOLS:
                domain = _TOOL_DOMAINS[name]
                mutation_fingerprint = self._mutation_request_fingerprint(
                    task,
                    domain,
                    arguments,
                )
                if arguments.get("_context_authoritative") is True:
                    mutation_operation_id = str(
                        getattr(context, "operation_id", "")
                    )
                else:
                    mutation_operation_id = self._mutation_operation_id(
                        domain,
                        mutation_fingerprint,
                    )
                    derive = getattr(context, "derive", None)
                    if callable(derive):
                        domain_context = derive(mutation_operation_id)
                task.record_mutation_identity(
                    domain,
                    mutation_fingerprint,
                    str(
                        getattr(
                            domain_context,
                            "operation_id",
                            mutation_operation_id,
                        )
                    ),
                )
            with task.domain_admission(name, arguments, domain_context):
                projected_arguments = task.arguments_for(name, arguments)
                projected_arguments.pop(CONTEXT_WORKFLOW_STEP_ARGUMENT, None)
                return callback(
                    resource,
                    projected_arguments,
                    domain_context,
                )

        return call

def _mapping_or_empty(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


class RuntimeMcpService:
    """Bind Runtime Core operations to Agent or operator interfaces."""

    def __init__(
        self,
        backend: DebugMcpBackend[TaskT],
        *,
        context_repository: RuntimeRepository | None = None,
        blob_repository: BlobRepository | None = None,
        session_outcome_repository: SessionOutcomeRepository | None = None,
        compatibility_telemetry_repository: (
            CompatibilityTelemetryRepository | None
        ) = None,
        context_runtime: ContextRuntime | None = None,
        envelope_max_bytes: int = AGENT_ENVELOPE_MAX_BYTES,
        context_max_cached_projections: int = 64,
        context_max_cached_projection_bytes: int = 8 * 1024 * 1024,
        context_retention_seconds: float = 7 * 24 * 60 * 60,
        context_storage_soft_limit_bytes: int = 1024 * 1024 * 1024,
        context_maintenance_interval_seconds: float = 60,
        context_mode: str = "authoritative",
        interface_profile: str = "agent",
        domain_pack_extensions: Callable[
            [CapabilityRegistry, Mapping[str, CallableDomainAdapter]],
            Iterable[DomainPackAuthorContract],
        ]
        | None = None,
        artifact_store: LocalArtifactStore | None = None,
        **registry_options: object,
    ) -> None:
        selected_context_mode = str(context_mode).strip().lower()
        if selected_context_mode not in {"authoritative", "shadow"}:
            raise ValueError("context_mode must be authoritative or shadow")
        self.backend = backend
        self.context_mode = selected_context_mode
        self.registry: TaskRunRegistry[TaskT] = TaskRunRegistry(
            factory=backend.open_task,
            closer=self._close_task_resource,
            status_reader=backend.task_status,
            maintenance=backend.maintain_task,
            completion_preparer=getattr(
                backend,
                "prepare_task_completion",
                None,
            ),
            **registry_options,
        )
        definitions = self._build_tool_definitions()
        selected_interface_profile = str(interface_profile).strip().lower()
        if selected_interface_profile not in {"agent", "operator"}:
            raise ValueError("interface_profile must be agent or operator")
        self.interface_profile = selected_interface_profile
        self._runtime = compose_runtime(
            definitions,
            catalog_backend=backend,
            invoke_domain_transport=self._invoke_registered_domain_adapter,
            options=RuntimeCompositionOptions(
                context_repository=context_repository,
                blob_repository=blob_repository,
                compatibility_telemetry_repository=(
                    compatibility_telemetry_repository
                ),
                context_runtime=context_runtime,
                envelope_max_bytes=envelope_max_bytes,
                max_cached_projections=context_max_cached_projections,
                max_cached_projection_bytes=(
                    context_max_cached_projection_bytes
                ),
                retention_seconds=context_retention_seconds,
                storage_soft_limit_bytes=context_storage_soft_limit_bytes,
                orchestrated_backend=isinstance(
                    backend,
                    OrchestratedMcpBackend,
                ),
                domain_pack_extensions=domain_pack_extensions,
                artifact_store=(
                    artifact_store
                    or getattr(backend, "artifact_store", None)
                ),
            ),
        )
        bind_artifact_store = getattr(backend, "bind_artifact_store", None)
        if callable(bind_artifact_store):
            bind_artifact_store(self._runtime.artifact_store)
        self._test = self._runtime._test
        self.replay_service = self._runtime.operator.replay_service()
        self.session_outcome_service = SessionOutcomeService(
            session_outcome_repository or InMemorySessionOutcomeRepository()
        )
        if self.interface_profile == "agent":
            interface_descriptors = agent_operation_descriptors()
        elif self.interface_profile == "operator":
            interface_descriptors = tuple(
                descriptor
                for descriptor in self._runtime.transport.descriptors()
                if descriptor.exposure == "operator"
            )
        self.interface_catalog = OperationCatalog(interface_descriptors)
        if context_maintenance_interval_seconds < 0:
            raise ValueError("context maintenance interval must not be negative")
        self._context_maintenance_interval_seconds = float(
            context_maintenance_interval_seconds
        )
        self._context_maintenance_lock = threading.Lock()
        self._last_context_maintenance_at = 0.0
        self._context_maintenance_attempts = 0
        self._context_maintenance_failures = 0
        self._context_maintenance_last_error = ""
        self._context_maintenance_last_result: dict[str, object] = {}

    @property
    def semantic_runtime(self) -> SemanticRuntimePort:
        return self._runtime.agent.semantic_runtime

    def _close_task_resource(self, task: TaskT) -> None:
        task_id = str(getattr(task, "task_id", "")).strip()
        try:
            self.backend.close_task(task)
        finally:
            if task_id:
                self._runtime.operator.unbind_task(task_id)

    def _maintain_context_if_due(self) -> None:
        now = time.monotonic()
        if (
            self._context_maintenance_interval_seconds > 0
            and now - self._last_context_maintenance_at
            < self._context_maintenance_interval_seconds
        ):
            return
        if not self._context_maintenance_lock.acquire(blocking=False):
            return
        try:
            now = time.monotonic()
            if (
                self._context_maintenance_interval_seconds > 0
                and now - self._last_context_maintenance_at
                < self._context_maintenance_interval_seconds
            ):
                return
            try:
                maintenance_result = self._runtime.operator.maintain()
                self._context_maintenance_last_result = (
                    dict(maintenance_result)
                    if isinstance(maintenance_result, Mapping)
                    else {}
                )
                self._context_maintenance_last_error = ""
            except Exception as exc:
                self._context_maintenance_failures += 1
                self._context_maintenance_last_error = (
                    f"{type(exc).__name__}: {exc}"
                )[:2048]
            self._context_maintenance_attempts += 1
            self._last_context_maintenance_at = now
        finally:
            self._context_maintenance_lock.release()

    def _build_tool_definitions(self) -> list[dict[str, object]]:
        common_target = {
            "type": "string",
            "minLength": 1,
            "description": (
                "BMC host name or address. Required only on the first domain "
                "call when the task has no bound target context."
            ),
        }
        orchestration_properties = {
            "intent": {
                "type": "string",
                "enum": TaskIntentKind.public_values(),
                "description": "Original task intent; parsed once on the first domain call.",
            },
            "final_purpose": {
                "type": "string",
                "minLength": 1,
                "description": "Final task purpose retained across internal handoffs.",
            },
            "delivery_strategy": {
                "type": "string",
                "enum": DeliveryStrategy.public_values(),
                "description": (
                    "Delivery path for diagnose-and-fix. When omitted, infer it "
                    "from workflow sections or the selected mutation tool; otherwise "
                    "remain source-only without asking the user to repeat intent."
                ),
            },
            "authorized_exceptions": {
                "type": "object",
                "description": (
                    "Task-level authorization for narrowly scoped mutation "
                    "exceptions. A mutation flag cannot authorize itself."
                ),
                "properties": {
                    "force_path": {"type": "boolean", "default": False},
                    "no_backup": {"type": "boolean", "default": False},
                    "no_remount": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
            "target_id": {
                "type": "string",
                "description": "Internal target selector for a previously bound multi-target task.",
            },
            "target_role": {
                "type": "string",
                "enum": ["reference", "candidate", "symmetric"],
            },
            "workflow": {
                "type": "object",
                "description": (
                    "Optional typed domain arguments for automatic multi-Skill "
                    "continuation without caller-managed operation or handoff IDs."
                ),
                "additionalProperties": {"type": "object"},
            },
        }
        deadline = {
            "type": "number",
            "exclusiveMinimum": 0,
            "default": 600,
            "description": "Bounded end-to-end budget in seconds.",
        }
        definitions: list[dict[str, object]] = []
        if callable(getattr(self.backend, "debug_run", None)):
            definitions.append({
                "name": "debug_run",
                "description": (
                    "Run the typed openUBMC Debug workflow for one task target. "
                    "The task TargetRun reuses epoch-valid transport/capability state "
                    "while each call recollects live evidence."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        **orchestration_properties,
                        "ip": common_target,
                        "deadline": deadline,
                        "mdb_queries": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Reviewed read-only mdbctl queries collected inside "
                                "the same task-scoped Debug lease."
                            ),
                        },
                        "mdb_expand_classes": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "MDB classes whose current objects are discovered "
                                "and read inside the same Debug lease."
                            ),
                        },
                        "mdb_concurrency": {
                            "oneOf": [
                                {
                                    "type": "string",
                                    "pattern": "^(auto|unbounded|[1-9][0-9]*)$",
                                },
                                {"type": "integer", "minimum": 1},
                            ],
                            "default": "auto",
                        },
                        "mdb_only": {
                            "type": "boolean",
                            "default": False,
                            "description": (
                                "Collect only reviewed MDB queries and lightweight "
                                "preflight freshness."
                            ),
                        },
                        "reference_role": {
                            "type": "string",
                            "enum": ["reference", "candidate", "symmetric"],
                        },
                        "targets": {
                            "type": "array",
                            "minItems": 2,
                            "items": {
                                "type": "object",
                                "required": ["ip"],
                                "properties": {
                                    "ip": common_target,
                                    "role": {
                                        "enum": ["reference", "candidate"]
                                    },
                                    "target_id": {"type": "string"},
                                },
                                "additionalProperties": True,
                            },
                        },
                        "concurrency": {
                            "oneOf": [
                                {
                                    "type": "string",
                                    "pattern": "^(auto|unbounded|[1-9][0-9]*)$"
                                },
                                {"type": "integer", "minimum": 1}
                            ],
                            "default": "auto"
                        },
                    },
                    "additionalProperties": True,
                },
            })
        if callable(getattr(self.backend, "debug_collect", None)):
            definitions.append({
                "name": "debug_collect",
                "description": (
                    "Collect a bounded openUBMC Debug evidence profile with "
                    "task-scoped, epoch-valid capability reuse and fresh evidence reads. "
                    "The mdb and object-alarm profiles are fast current snapshots; "
                    "debug_run retains the full freshness workflow."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        **orchestration_properties,
                        "ip": common_target,
                        "deadline": deadline,
                        "mdb_queries": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Reviewed read-only mdbctl queries collected inside "
                                "the same task-scoped Debug lease."
                            ),
                        },
                        "mdb_expand_classes": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "MDB classes whose current objects are discovered "
                                "and read inside the same Debug lease."
                            ),
                        },
                        "mdb_concurrency": {
                            "oneOf": [
                                {
                                    "type": "string",
                                    "pattern": "^(auto|unbounded|[1-9][0-9]*)$",
                                },
                                {"type": "integer", "minimum": 1},
                            ],
                            "default": "auto",
                        },
                        "mdb_only": {
                            "type": "boolean",
                            "default": False,
                            "description": (
                                "Collect only reviewed MDB queries and lightweight "
                                "preflight freshness."
                            ),
                        },
                        "profile": {
                            "type": "string",
                            "enum": [
                                "standard",
                                "mdb",
                                "object-alarm",
                            ],
                            "default": "standard",
                            "description": (
                                "Select the evidence shape. mdb collects only current "
                                "MDB evidence; object-alarm collects current object and "
                                "alarm evidence. Both skip Telnet, source correlation, "
                                "and the end freshness pass."
                            ),
                        },
                    },
                    "additionalProperties": True,
                },
            })
        if callable(getattr(self.backend, "log_bundle_collect", None)):
            definitions.append(
                {
                    "name": "log_bundle_collect",
                    "description": (
                        "Collect an openUBMC one-click log bundle through the "
                        "Log Analyzer Redfish-primary workflow."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            **orchestration_properties,
                            "ip": common_target,
                            "deadline": deadline,
                            "transport": {
                                "type": "string",
                                "enum": ["auto", "redfish", "ssh"],
                                "default": "auto",
                            },
                            "problem": {"type": "string"},
                            "extract": {"type": "boolean", "default": True},
                        },
                        "additionalProperties": True,
                    },
                }
            )
        artifact_ref_schema = {
            "type": "object",
            "required": [
                "handle",
                "digest",
                "kind",
                "size",
                "provenance",
                "retention_hint",
                "target",
                "run_id",
            ],
            "properties": {
                "schema": {"type": "string"},
                "handle": {"type": "string", "minLength": 1},
                "digest": {"type": "string", "minLength": 64},
                "kind": {"type": "string", "minLength": 1},
                "size": {"type": "integer", "minimum": 0},
                "provenance": {"type": "string", "minLength": 1},
                "retention_hint": {"type": "string", "minLength": 1},
                "version": {"type": "string"},
                "target": {"type": "string", "minLength": 1},
                "run_id": {"type": "string", "minLength": 1},
            },
            "additionalProperties": False,
        }
        for stage in LOG_BUNDLE_STAGE_CONTRACTS:
            if not callable(getattr(self.backend, stage.operation, None)):
                continue
            properties = {
                **orchestration_properties,
                "ip": common_target,
                "deadline": deadline,
                "artifact_ref": artifact_ref_schema,
            }
            required = ["artifact_ref"]
            if stage.problem_required:
                required.append("problem")
                properties.update(
                    {
                        "problem": {"type": "string", "minLength": 1},
                        "max_files": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 32,
                        },
                        "max_lines": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 256,
                        },
                    }
                )
            definitions.append(
                {
                    "name": stage.operation,
                    "description": stage.description,
                    "inputSchema": {
                        "type": "object",
                        "required": required,
                        "properties": properties,
                        "additionalProperties": True,
                    },
                }
            )
        if callable(getattr(self.backend, "live_patch_run", None)):
            definitions.append(
                {
                    "name": "live_patch_run",
                    "description": (
                        "Apply or roll back one typed openUBMC Live Patch mutation "
                        "and retain the task target for fresh verification."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            **orchestration_properties,
                            "ip": common_target,
                            "deadline": deadline,
                            "action": {
                                "type": "string",
                                "enum": ["apply", "rollback"],
                                "default": "apply",
                            },
                            "local_path": {
                                "type": "string",
                                "minLength": 1,
                                "description": "Absolute local runtime artifact path.",
                            },
                            "artifact_sha256": {
                                "type": "string",
                                "pattern": "^[0-9a-fA-F]{64}$",
                                "description": (
                                    "Expected SHA-256 bound by the Runtime ArtifactRef."
                                ),
                            },
                            "backup_path": {
                                "type": "string",
                                "minLength": 1,
                                "description": "Absolute remote backup path for rollback.",
                            },
                            "remove_created": {
                                "type": "boolean",
                                "default": False,
                                "description": (
                                    "Remove a checksum-matched target that the "
                                    "corresponding patch created from absence."
                                ),
                            },
                            "force_path": {
                                "type": "boolean",
                                "default": False,
                            },
                            "no_backup": {
                                "type": "boolean",
                                "default": False,
                            },
                            "no_remount": {
                                "type": "boolean",
                                "default": False,
                            },
                            "expected_current_sha256": {
                                "type": "string",
                                "pattern": "^[0-9a-fA-F]{64}$",
                            },
                            "remote_path": {
                                "type": "string",
                                "minLength": 1,
                                "description": "Absolute authored target file path.",
                            },
                            "restart_scope": {
                                "type": "string",
                                "enum": ["none", "skynet"],
                                "default": "none",
                            },
                            "verification_checks": {
                                "type": "array",
                                "items": {"type": "string", "minLength": 1},
                                "default": [],
                            },
                        },
                        "required": ["remote_path"],
                        "allOf": [
                            {
                                "if": {
                                    "properties": {
                                        "action": {"const": "rollback"}
                                    },
                                    "required": ["action"],
                                },
                                "then": {
                                    "oneOf": [
                                        {"required": ["backup_path"]},
                                        {
                                            "properties": {
                                                "remove_created": {"const": True}
                                            },
                                            "required": [
                                                "remove_created",
                                                "expected_current_sha256",
                                            ],
                                        },
                                    ]
                                },
                                "else": {"required": ["local_path"]},
                            }
                        ],
                        "additionalProperties": True,
                    },
                }
            )
        if callable(getattr(self.backend, "upgrade_run", None)):
            definitions.append(
                {
                    "name": "upgrade_run",
                    "description": (
                        "Install one identified openUBMC upgrade artifact and "
                        "retain the task target for fresh verification."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            **orchestration_properties,
                            "ip": common_target,
                            "deadline": deadline,
                            "artifact_path": {
                                "type": "string",
                                "minLength": 1,
                                "description": "Absolute local HPM artifact path.",
                            },
                            "artifact_sha256": {
                                "type": "string",
                                "pattern": "^[0-9a-fA-F]{64}$",
                            },
                            "product_version": {
                                "type": "string",
                                "minLength": 1,
                            },
                            "upload_timeout": {
                                "type": "number",
                                "exclusiveMinimum": 0,
                                "default": 600,
                                "description": (
                                    "Per-request timeout for HPM byte upload; "
                                    "bounded by the task deadline."
                                ),
                            },
                            "active_mode": {
                                "type": "string",
                                "enum": ["Immediately", "ResetBMC"],
                                "default": "ResetBMC",
                                "description": (
                                    "Target activation mode requested with an upload "
                                    "method that supports UpdateParameters."
                                ),
                            },
                            "force_update": {
                                "type": "boolean",
                                "default": True,
                                "description": (
                                    "Request a deliberate same-version reflash when the "
                                    "target supports UpdateParameters."
                                ),
                            },
                            "transport": {
                                "type": "string",
                                "enum": ["redfish"],
                                "default": "redfish",
                            },
                            "allow_insecure_tls": {
                                "type": "boolean",
                                "default": True,
                            },
                        },
                        "required": [
                            "artifact_path",
                            "artifact_sha256",
                            "product_version",
                        ],
                        "additionalProperties": True,
                    },
                }
            )
        if callable(getattr(self.backend, "upgrade_batch", None)):
            definitions.append({
                "name": "upgrade_batch",
                "description": "Upgrade an identified HPM on a bounded set of targets with per-target journals.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "targets": {"type": "array", "minItems": 1, "maxItems": 128,
                                    "items": {"type": "object", "required": ["ip"],
                                              "properties": {"ip": common_target}}},
                        "artifact_path": {"type": "string", "minLength": 1},
                        "artifact_sha256": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
                        "product_version": {"type": "string", "minLength": 1},
                        "max_concurrency": {"type": "integer", "minimum": 1, "maximum": 32},
                        "deadline": deadline,
                    },
                    "required": ["targets", "artifact_path", "artifact_sha256", "product_version"],
                    "additionalProperties": True,
                },
            })
        definitions.extend(
            [
                {
                    "name": "case_read",
                    "description": (
                        "Read the bounded recoverable openUBMC Case projection without "
                        "advancing the workflow."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "required": ["case_id"],
                        "properties": {"case_id": {"type": "string", "minLength": 1}},
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "evidence_attach",
                    "description": (
                        "Attach digest-verified local file bytes to one open Runtime "
                        "Run without changing its Gate, phase, or Outcome."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "required": [
                            "run_id",
                            "target",
                            "path",
                            "sha256",
                            "evidence_type",
                        ],
                        "properties": {
                            "run_id": {"type": "string", "minLength": 1},
                            "target": {"type": "string", "minLength": 1},
                            "path": {"type": "string", "minLength": 1},
                            "sha256": {
                                "type": "string",
                                "pattern": "^(?:sha256:)?[0-9a-f]{64}$",
                            },
                            "evidence_type": {
                                "type": "string",
                                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
                            },
                        },
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "evidence_query",
                    "description": (
                        "Find bounded Evidence metadata for operator review without "
                        "loading Evidence bodies."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "case_id": {
                                "type": "string",
                                "maxLength": EVIDENCE_QUERY_MAX_CASE_ID,
                            },
                            "target_id": {
                                "type": "string",
                                "maxLength": EVIDENCE_QUERY_MAX_FILTER,
                            },
                            "producer": {
                                "type": "string",
                                "maxLength": EVIDENCE_QUERY_MAX_FILTER,
                            },
                            "workflow_definition_id": {
                                "type": "string",
                                "maxLength": EVIDENCE_QUERY_MAX_FILTER,
                            },
                            "observed_after": {"type": "number", "minimum": 0},
                            "observed_before": {"type": "number", "minimum": 0},
                            "limit": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": EVIDENCE_QUERY_MAX_ITEMS,
                                "default": EVIDENCE_QUERY_DEFAULT_ITEMS,
                            },
                            "deduplicate": {"type": "boolean", "default": True},
                        },
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "evidence_read",
                    "description": (
                        "Read one bounded verified slice of evidence referenced by a Case."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "required": ["case_id", "evidence_id"],
                        "properties": {
                            "case_id": {"type": "string", "minLength": 1},
                            "evidence_id": {"type": "string", "minLength": 1},
                            "offset": {"type": "integer", "minimum": 0, "default": 0},
                            "limit": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 1048576,
                                "default": 65536,
                            },
                            "target_id": {"type": "string"},
                            "generation": {"type": "string"},
                        },
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "case_replay_export",
                    "description": (
                        "Export one redacted, versioned, portable Case Replay Bundle."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "required": ["case_id"],
                        "properties": {
                            "case_id": {"type": "string", "minLength": 1}
                        },
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "case_replay_run",
                    "description": (
                        "Deterministically replay a Case Bundle without network, "
                        "target resources, or mutations."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "required": ["bundle"],
                        "properties": {
                            "bundle": {
                                "type": "object",
                                "additionalProperties": True,
                            }
                        },
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "session_outcome_record",
                    "description": (
                        "Project a terminal Run Outcome, or record one legacy Case "
                        "Outcome, into the redacted governance store."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "required": ["case_id"],
                        "properties": {
                            "session_id": {"type": "string", "minLength": 1},
                            "case_id": {"type": "string", "minLength": 1},
                            "replay_fingerprint": {"type": "string", "minLength": 1},
                            "workflow": {"type": "string", "minLength": 1},
                            "domain": {"type": "string", "minLength": 1},
                            "outcome": {
                                "type": "string",
                                "enum": [
                                    "completed",
                                    "partial",
                                    "failed",
                                    "user-corrected",
                                    "false-success",
                                    "evidence-gap",
                                    "contract-gap",
                                ],
                            },
                            "gap_type": {"type": "string"},
                            "summary": {"type": "string", "minLength": 1},
                            "details": {"type": "object", "additionalProperties": True},
                            "architecture_decision": {"type": "boolean", "default": False},
                        },
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "session_outcome_summary",
                    "description": (
                        "Aggregate reviewed and pending Session Outcomes by workflow, "
                        "domain, outcome, and gap type."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "session_outcome_transition",
                    "description": (
                        "Review, independently approve, or reject a redacted Session Outcome."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "required": ["outcome_id", "action", "actor"],
                        "properties": {
                            "outcome_id": {"type": "string", "minLength": 1},
                            "action": {
                                "type": "string",
                                "enum": ["review", "approve", "reject"],
                            },
                            "actor": {"type": "string", "minLength": 1},
                        },
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "session_outcome_promote",
                    "description": (
                        "Promote an approved Outcome to an inert Golden Scenario, "
                        "knowledge item, or ADR artifact."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "required": ["outcome_id", "target", "payload"],
                        "properties": {
                            "outcome_id": {"type": "string", "minLength": 1},
                            "target": {
                                "type": "string",
                                "enum": ["golden-scenario", "knowledge", "adr"],
                            },
                            "payload": {"type": "object", "additionalProperties": True},
                        },
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "case_close",
                    "description": "Seal one resolved Case while retaining readable history.",
                    "inputSchema": {
                        "type": "object",
                        "required": ["case_id", "expected_revision"],
                        "properties": {
                            "case_id": {"type": "string", "minLength": 1},
                            "expected_revision": {"type": "integer", "minimum": 0},
                        },
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "case_forget",
                    "description": (
                        "Immediately forget one resolved Case and its unshared evidence."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "required": ["case_id"],
                        "properties": {"case_id": {"type": "string", "minLength": 1}},
                        "additionalProperties": False,
                    },
                },
            ]
        )
        definitions.append({
                "name": "runtime_status",
                "description": "Report reusable task state, epochs, leases, and bounded evidence metadata.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            })
        return definitions

    def tool_definitions(self) -> list[dict[str, object]]:
        return self.interface_catalog.tool_definitions()

    def call_exposed_tool(
        self,
        name: str,
        arguments: Mapping[str, object],
        *,
        task_id: str,
        operation_id: str,
    ) -> dict[str, object]:
        """Dispatch only operations selected by the active interface profile."""

        if not isinstance(arguments, Mapping):
            raise TypeError("tool arguments must be an object")
        if self.interface_profile == "agent":
            bounded_request(arguments)
        if self.interface_profile == "agent":
            if name == "observe":
                return self._runtime.agent.observe(
                    arguments,
                    task_id=task_id,
                    operation_id=operation_id,
                )
            if name == "execute":
                return self._runtime.agent.execute(
                    arguments,
                    task_id=task_id,
                    operation_id=operation_id,
                )
            raise ValueError(f"unknown Agent operation: {name}")
        self.interface_catalog.validate_arguments(name, arguments)
        return self.call_tool(
            name,
            arguments,
            task_id=task_id,
            operation_id=operation_id,
        )

    def _invoke_registered_domain_adapter(
        self,
        operation: str,
        sdk_context: RuntimeSDKContext,
        arguments: Mapping[str, object],
    ) -> Mapping[str, object]:
        descriptor = self._runtime.transport.require_operation(operation)
        bounded_arguments = dict(arguments)
        if sdk_context.recovery_mode:
            bounded_arguments[RUNTIME_EFFECT_RECOVERY_ARGUMENT] = (
                sdk_context.recovery_mode
            )
        observation_mode = bounded_arguments.pop("_agent_observation", False)
        capability_names = bounded_arguments.pop("_agent_capability_names", [])
        selectors = bounded_arguments.pop("_agent_selectors", [])
        assured = bounded_arguments.pop("_agent_assured", False)
        prior_observation = bounded_arguments.pop(
            "_agent_prior_observation", None
        )
        if observation_mode:
            observed_arguments = dict(bounded_arguments)
            observed_arguments["capability_names"] = list(capability_names)
            observed_arguments["selectors"] = [
                dict(item) for item in selectors if isinstance(item, Mapping)
            ]
            observed_arguments["assured"] = assured
            if isinstance(prior_observation, Mapping):
                observed_arguments["prior_observation"] = dict(prior_observation)
            if isinstance(self.backend, OrchestratedMcpBackend):
                debug_backend = self.backend.tool_backends.get(operation)
                specialized = getattr(debug_backend, "observe_query", None)
                if operation == "debug_collect" and callable(specialized):
                    return self.registry.execute(
                        task_id=sdk_context.task_id,
                        operation_id=sdk_context.operation_id,
                        timeout_seconds=sdk_context.timeout_seconds,
                        callback=lambda task, context: (
                            lambda backend, resource: backend.observe_query(
                                resource,
                                observed_arguments,
                                context,
                            )
                        )(*task.resource_for("debug_collect")),
                    )
            specialized = getattr(self.backend, "observe_query", None)
            if operation == "debug_collect" and callable(specialized):
                return self.registry.execute(
                    task_id=sdk_context.task_id,
                    operation_id=sdk_context.operation_id,
                    timeout_seconds=sdk_context.timeout_seconds,
                    callback=lambda task, context: specialized(
                        task, observed_arguments, context
                    ),
                )
            if assured:
                raise AssuranceUnavailable(
                    "assured observation requires a scope-preserving observation adapter"
                )
        callback = getattr(self.backend, str(descriptor.handler_name), None)
        if not callable(callback):
            raise RuntimeError(
                f"operation catalog handler became unavailable: {descriptor.name}"
            )
        def invoke_and_authenticate(task, context):
            raw = callback(task, bounded_arguments, context)
            if operation != "upgrade_batch" or not isinstance(raw, Mapping):
                return raw
            backend, resource = (
                task.resource_for(operation)
                if isinstance(self.backend, OrchestratedMcpBackend)
                else (self.backend, task)
            )
            authenticate = getattr(backend, "authenticate_batch_journals", None)
            if not callable(authenticate):
                return raw
            bindings = authenticate(resource, bounded_arguments, context, raw)
            return replace(
                DomainReceipt.from_value(operation, raw),
                authenticated_journal_bindings=tuple(bindings),
            )

        value = self.registry.execute(
            task_id=sdk_context.task_id,
            operation_id=sdk_context.operation_id,
            timeout_seconds=sdk_context.timeout_seconds,
            callback=invoke_and_authenticate,
        )
        return value

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, object],
        *,
        task_id: str,
        operation_id: str,
        _context_workflow_step: bool = False,
    ) -> dict[str, object]:
        self._maintain_context_if_due()
        if not isinstance(arguments, Mapping):
            raise TypeError("tool arguments must be an object")
        arguments = dict(arguments)
        descriptor = self._runtime.transport.require_operation(name)
        external_context_marker = (
            arguments.get(CONTEXT_WORKFLOW_STEP_ARGUMENT) is True
            and not _context_workflow_step
        )
        if descriptor.handler_name is not None and not external_context_marker:
            arguments = self._runtime.operator.restore_domain_arguments(
                task_id,
                name,
                arguments,
            )
        for internal_name in _INTERNAL_TASK_ARGUMENTS:
            arguments.pop(internal_name, None)
        arguments.pop(CONTEXT_WORKFLOW_STEP_ARGUMENT, None)
        arguments = canonicalize_tool_arguments(name, arguments)
        validate_boolean_argument_types(descriptor, arguments)
        self._runtime.transport.validate_arguments(name, arguments)
        if _context_workflow_step:
            arguments[CONTEXT_WORKFLOW_STEP_ARGUMENT] = True
        if descriptor.lifecycle == "status":
            status = {
                "api_version": RUNTIME_API_VERSION,
                "mcp_protocol_version": MCP_PROTOCOL_VERSION,
                **self.registry.status(),
            }
            persistent_status = getattr(self.backend, "persistent_status", None)
            if callable(persistent_status):
                status["persistent_task_contexts"] = persistent_status()
            status["context_runtime"] = self._runtime.operator.status()
            status["operator_projection"] = self._runtime.operator.operator_projection(
                task_id=task_id
            )
            status.update(self._runtime.transport.status())
            status["session_outcomes"] = self.session_outcome_service.status()
            status["context_maintenance"] = {
                "attempts": self._context_maintenance_attempts,
                "failures": self._context_maintenance_failures,
                "last_error": self._context_maintenance_last_error,
                "last_result": dict(self._context_maintenance_last_result),
            }
            status["context_mode"] = self.context_mode
            return self._runtime.operator.wrap_status(
                status,
                task_id=task_id,
                operation_id=operation_id,
            )
        if descriptor.handler_name is None:
            operator_result = self._runtime.operator.dispatch(
                name,
                arguments,
                operation_id=operation_id,
            )
            if operator_result is not None:
                return operator_result
            if name == "case_replay_export":
                case_id = str(arguments.get("case_id", "")).strip()
                value = self.replay_service.export(case_id).to_public_dict()
                return self._runtime.operator.wrap_read(
                    value,
                    operation=name,
                    operation_id=operation_id,
                    case_id=case_id,
                )
            if name == "case_replay_run":
                bundle = arguments.get("bundle")
                if not isinstance(bundle, Mapping):
                    raise TypeError("bundle must be an object")
                value = self.replay_service.replay(bundle).to_public_dict()
                return self._runtime.operator.wrap_read(
                    value,
                    operation=name,
                    operation_id=operation_id,
                    case_id=str(bundle.get("case_id", "")),
                )
            if name == "session_outcome_record":
                details = arguments.get("details", {})
                if not isinstance(details, Mapping):
                    raise TypeError("details must be an object")
                case_id = str(arguments.get("case_id", ""))
                try:
                    projection = self._runtime.operator.read_case_projection(
                        case_id
                    )
                except CaseNotFound:
                    projection = None
                is_run = isinstance(projection, Mapping) and any(
                    projection.get(name)
                    for name in (
                        "run_decisions",
                        "run_gates",
                        "incidents",
                        "run_outcome",
                    )
                )
                if is_run:
                    persisted_outcome = _mapping_or_empty(
                        projection.get("run_outcome")
                    )
                    if not persisted_outcome:
                        raise ValueError(
                            "Session Outcome projection requires a terminal Run Outcome"
                        )
                    closeout = _mapping_or_empty(projection.get("closeout"))
                    replay_fingerprint = "sha256:" + hashlib.sha256(
                        json.dumps(
                            {
                                "run_id": case_id,
                                "workflow": projection.get(
                                    "workflow_definition", {}
                                ),
                                "outcome": persisted_outcome,
                                "closeout_fingerprint": closeout.get(
                                    "fingerprint", ""
                                ),
                            },
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest()
                    run_status = str(persisted_outcome.get("status", ""))
                    record = self.session_outcome_service.record(
                        session_id=f"run:{case_id}",
                        case_id=case_id,
                        replay_fingerprint=replay_fingerprint,
                        workflow=str(
                            _mapping_or_empty(
                                projection.get("workflow_definition")
                            ).get("definition_id", "runtime-workflow")
                        ),
                        domain=str(
                            projection.get("entry_domain", "runtime")
                            or "runtime"
                        ),
                        outcome=(
                            "completed"
                            if run_status == "completed"
                            else "partial"
                            if run_status == "partial"
                            else "failed"
                        ),
                        summary=str(
                            persisted_outcome.get("summary", "")
                        ).strip()
                        or "workflow completed",
                        details={
                            "state": run_status,
                            "run_outcome_id": str(
                                persisted_outcome.get("outcome_id", "")
                            ),
                            "closeout_fingerprint": str(
                                closeout.get("fingerprint", "")
                            ),
                        },
                    )
                else:
                    record = self.session_outcome_service.record(
                        session_id=str(arguments.get("session_id", "")),
                        case_id=case_id,
                        replay_fingerprint=str(
                            arguments.get("replay_fingerprint", "")
                        ),
                        workflow=str(arguments.get("workflow", "")),
                        domain=str(arguments.get("domain", "")),
                        outcome=str(arguments.get("outcome", "")),
                        gap_type=str(arguments.get("gap_type", "")),
                        summary=str(arguments.get("summary", "")),
                        details=details,
                        architecture_decision=bool(
                            arguments.get("architecture_decision", False)
                        ),
                    )
                return self._runtime.operator.wrap_read(
                    record.to_public_dict(),
                    operation=name,
                    operation_id=operation_id,
                    case_id=record.case_id,
                )
            if name == "session_outcome_summary":
                return self._runtime.operator.wrap_read(
                    self.session_outcome_service.summary(),
                    operation=name,
                    operation_id=operation_id,
                    case_id="",
                )
            if name == "session_outcome_transition":
                record = self.session_outcome_service.transition(
                    str(arguments.get("outcome_id", "")),
                    action=str(arguments.get("action", "")),
                    actor=str(arguments.get("actor", "")),
                )
                return self._runtime.operator.wrap_read(
                    record.to_public_dict(),
                    operation=name,
                    operation_id=operation_id,
                    case_id=record.case_id,
                )
            if name == "session_outcome_promote":
                payload = arguments.get("payload")
                if not isinstance(payload, Mapping):
                    raise TypeError("payload must be an object")
                value = self.session_outcome_service.promote(
                    str(arguments.get("outcome_id", "")),
                    target=str(arguments.get("target", "")),
                    payload=payload,
                )
                return self._runtime.operator.wrap_read(
                    value,
                    operation=name,
                    operation_id=operation_id,
                    case_id=str(value.get("case_reference", "")).removeprefix(
                        "case://"
                    ),
                )
            raise RuntimeError(f"context operation is not implemented: {name}")
        return self._runtime.transport.invoke_domain(
            name,
            arguments,
            task_id=task_id,
            operation_id=operation_id,
            context_mode=self.context_mode,
            external_context_marker=external_context_marker,
        )

    def cancel_operation(self, task_id: str, operation_id: str) -> bool:
        return self.registry.cancel_operation(task_id, operation_id)

    def complete_task(self, task_id: str) -> bool:
        completed = self.registry.complete(task_id)
        if not completed:
            self._runtime.operator.unbind_task(task_id)
        return completed

    def error_result(
        self,
        exc: Exception,
        *,
        name: str,
        arguments: Mapping[str, object],
        task_id: str,
        operation_id: str,
    ) -> Mapping[str, object]:
        if name in {"observe", "execute"}:
            return self._runtime.agent.error(
                name,
                exc,
                arguments=arguments,
            )
        return self._runtime.operator.error_result(
            exc,
            operation=name,
            arguments=arguments,
            task_id=task_id,
            operation_id=operation_id,
        )

    def close(self) -> None:
        self._runtime.lifecycle.close()
        self.registry.close()


class JsonRpcMcpEndpoint:
    """Translate MCP JSON-RPC messages without coupling transport to Debug logic."""

    def __init__(
        self,
        service: RuntimeMcpService,
        *,
        session_task_id: str | None = None,
    ) -> None:
        self.service = service
        self.session_task_id = session_task_id or f"mcp-session-{uuid.uuid4().hex}"

    def task_id_for_params(self, params: object) -> str:
        if not isinstance(params, Mapping):
            return self.session_task_id
        metadata = params.get("_meta")
        if isinstance(metadata, Mapping):
            for key in ("codex/taskId", "taskId", "task_id"):
                value = metadata.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return self.session_task_id

    def operation_id_for_params(
        self,
        params: object,
        request_id: object,
    ) -> str:
        if isinstance(params, Mapping):
            metadata = params.get("_meta")
            if isinstance(metadata, Mapping):
                for key in (
                    "openubmc/operationId",
                    "operationId",
                    "operation_id",
                ):
                    value = metadata.get(key)
                    if isinstance(value, str) and value.strip():
                        return value.strip()
        return "mcp-" + _fingerprint(
            {
                "session": self.session_task_id,
                "request_id": request_id,
            }
        )[:32]

    @staticmethod
    def _response(message_id: object, result: object) -> dict[str, object]:
        return {"jsonrpc": "2.0", "id": message_id, "result": result}

    @staticmethod
    def _error(
        message_id: object,
        code: int,
        message: str,
    ) -> dict[str, object]:
        return {
            "jsonrpc": "2.0",
            "id": message_id,
            "error": {"code": code, "message": message},
        }

    @staticmethod
    def _tool_label(tool_name: str | None) -> str:
        return {
            "observe": "openUBMC 观察",
            "execute": "openUBMC 工作流",
            "debug_run": "openUBMC 诊断",
            "debug_collect": "openUBMC 实时采集",
            "log_bundle_collect": "日志包采集",
            "live_patch_run": "Live Patch",
            "upgrade_run": "固件升级",
            "runtime_status": "Target Runtime",
        }.get(tool_name, "MCP 工具调用")

    @staticmethod
    def _summary_text(value: Mapping[str, object], *names: str) -> str:
        for name in names:
            candidate = value.get(name)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        return ""

    @staticmethod
    def _observation_text(value: Mapping[str, object]) -> str:
        scope = _mapping_or_empty(value.get("scope"))
        selectors = scope.get("selectors", [])
        selector_queries: dict[str, list[str]] = {}
        if isinstance(selectors, list):
            for selector_value in selectors:
                selector = _mapping_or_empty(selector_value)
                selector_id = str(selector.get("id", ""))
                queries = selector.get("queries", [])
                if selector_id and isinstance(queries, list):
                    selector_queries[selector_id] = [str(query) for query in queries]
        freshness = _mapping_or_empty(value.get("freshness"))
        coverage = _mapping_or_empty(value.get("coverage"))
        lines = [
            (
                f"ObservationReceipt {value.get('receipt_id', '')} "
                f"status={value.get('status', 'unknown')} "
                f"observed_at={freshness.get('observed_at', '')}"
            )
        ]
        results = _mapping_or_empty(value.get("results"))
        for selector_id, raw_result in results.items():
            result = _mapping_or_empty(raw_result)
            values = result.get("values", [])
            if not isinstance(values, list):
                continue
            if result.get("kind") == "capability":
                rendered = ", ".join(
                    f"{item.get('name', '')}={item.get('status', 'not_checked')}"
                    for raw_item in values
                    if (item := _mapping_or_empty(raw_item))
                )
                lines.append(f"capability[{selector_id}]: {rendered}")
                continue
            queries = selector_queries.get(str(selector_id), [])
            for raw_item in values:
                item = _mapping_or_empty(raw_item)
                index = item.get("query_index", 0)
                query = (
                    queries[index]
                    if isinstance(index, int) and 0 <= index < len(queries)
                    else f"query[{index}]"
                )
                rendered_value = json.dumps(
                    item.get("value"),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                lines.append(
                    f"mdb[{selector_id}] {query} => {rendered_value} "
                    f"status={item.get('status', 'not_checked')}"
                )
        lines.append(
            "coverage: "
            f"requested={coverage.get('requested', 0)} "
            f"available={coverage.get('available', 0)} "
            f"unavailable={coverage.get('unavailable', 0)} "
            f"not_checked={coverage.get('not_checked', 0)}"
        )
        text = "\n".join(lines)
        encoded = text.encode("utf-8")
        if len(encoded) <= OBSERVATION_PROJECTION_TARGET_BYTES:
            return text
        return encoded[: OBSERVATION_PROJECTION_TARGET_BYTES - 3].decode(
            "utf-8", errors="ignore"
        ) + "..."

    @classmethod
    def _human_summary(
        cls,
        tool_name: str | None,
        value: object,
        *,
        error: bool,
    ) -> str:
        label = cls._tool_label(tool_name)
        if error:
            mapping = value if isinstance(value, Mapping) else {}
            message = (
                cls._summary_text(mapping, "message", "error")
                or str(value)
                or "调用未完成"
            )
            error_type = cls._summary_text(mapping, "error")
            lowered = f"{error_type} {message}".lower()
            if any(
                token in lowered
                for token in ("ssh", "telnet", "redfish", "connection", "session")
            ):
                recovery = "失效连接会被丢弃，任务上下文仍保留，重试时将重新建连"
            else:
                recovery = "任务上下文仍保留，但本次调用未自动重放"
            next_action = cls._summary_text(
                mapping,
                "next_guidance",
                "next_action",
                "next_step",
            )
            if not next_action:
                if "deadline" in lowered or "timeout" in lowered:
                    next_action = "增大 deadline 或缩小采集范围后重试"
                elif "capacity" in lowered or "busy" in lowered:
                    next_action = "等待正在执行的任务结束后重试"
                elif error_type in {"ValueError", "TypeError"}:
                    next_action = "修正工具参数后重试"
                else:
                    next_action = "沿用同一任务 ID 重试；实时证据会重新读取"
            return (
                f"{label}失败：{message}。自动恢复：{recovery}。"
                f"下一步：{next_action}。"
            )

        if not isinstance(value, Mapping):
            return str(value)
        if tool_name == "observe":
            return cls._observation_text(value)
        if tool_name == "execute":
            gate = value.get("gate")
            gate = gate if isinstance(gate, Mapping) else {}
            state = str(value.get("state", "unknown"))
            if gate:
                gate_text = (
                    f"openUBMC 工作流已推进到 {state}："
                    f"{gate.get('kind', 'gate')} {gate.get('name', '')}。"
                )
                return render_execute_turn_text(value, heading=gate_text)
            return render_execute_turn_text(value)
        closeout_markdown = value.get("closeout_markdown")
        if isinstance(closeout_markdown, str) and closeout_markdown.strip():
            return closeout_markdown.strip()
        if tool_name == "runtime_status":
            task_count = value.get("task_count", 0)
            persistent = value.get("persistent_task_contexts")
            retained = (
                persistent.get("entry_count", 0)
                if isinstance(persistent, Mapping)
                else 0
            )
            return (
                f"Target Runtime 正常：当前有 {task_count} 个活动任务上下文，"
                f"磁盘保留 {retained} 个可恢复上下文。"
            )
        if "completed" in value:
            if bool(value.get("completed")):
                state = "已完成"
            elif bool(value.get("partial")):
                state = "部分完成"
            else:
                state = "尚未完成"
            next_action = cls._summary_text(value, "next_action", "next_step")
            suffix = f" 下一步：{next_action}。" if next_action else ""
            return f"{label}{state}。{suffix}".strip()
        if tool_name == "log_bundle_collect":
            result = value.get("result")
            result = result if isinstance(result, Mapping) else value
            path = cls._summary_text(result, "bundle_root", "local_bundle_path")
            next_action = cls._summary_text(result, "next_step")
            path_text = f" 本地结果：{path}。" if path else ""
            next_text = f" 下一步：{next_action}。" if next_action else ""
            return f"日志包采集已完成。{path_text}{next_text}".strip()
        if tool_name in {"live_patch_run", "upgrade_run"}:
            journal = value.get("journal")
            stage = (
                cls._summary_text(journal, "stage")
                if isinstance(journal, Mapping)
                else ""
            )
            operation_status = (
                mutation_journal_operation_status(journal)
                if isinstance(journal, Mapping)
                else ""
            )
            next_action = cls._summary_text(value, "next_action", "next_step")
            if isinstance(journal, Mapping) and not next_action:
                next_action = cls._summary_text(
                    journal,
                    "recovery_decision",
                    "next_action",
                    "next_step",
                )
            if operation_status == "completed" and stage != "rollback_verified":
                return f"{label}已完成并验证；结构化结果中保留完整证据。"
            if stage == "replan_required":
                state = "尚未完成，需要重新规划"
                next_action = next_action or "修正变更计划后沿用同一任务重新执行"
            elif stage == "rollback_verified":
                if operation_status == "completed":
                    return f"{label}回滚已完成并验证；结构化结果中保留完整证据。"
                state = "尚未完成，已回滚并验证恢复"
                next_action = next_action or "确认新的变更方案后重新执行"
            elif stage == "verification_failed_terminal":
                state = "尚未完成，变更验证失败且流程已终止"
                next_action = next_action or "检查验证证据并制定恢复或重试方案"
            elif stage == "rollback_verification_failed_terminal":
                state = "尚未完成，回滚验证失败且流程已终止"
                next_action = next_action or "先确认目标当前状态，再决定恢复动作"
            elif operation_status == "mutation_outcome_unknown":
                state = "尚未完成，变更结果未知"
                next_action = next_action or "先核对持久化变更日志和目标现状"
            elif operation_status == "blocked":
                state = "尚未完成，当前恢复流程受阻"
                next_action = next_action or "补齐恢复条件后继续同一变更日志"
            elif operation_status == "failed":
                state = "尚未完成，变更流程失败"
                next_action = next_action or "检查结构化证据后重新规划"
            else:
                stage_text = stage or "unknown"
                state = f"尚未完成，当前变更日志阶段为 {stage_text}"
                next_action = next_action or "查看结构化证据并继续当前流程"
            return (
                f"{label}{state}。下一步：{next_action}。"
                "结构化结果中保留完整证据。"
            )
        if tool_name in {"debug_run", "debug_collect"}:
            ok = value.get("ok")
            code = cls._summary_text(value, "normalized_code", "code")
            targets = value.get("targets")
            target_text = (
                f"，覆盖 {len(targets)} 个目标"
                if isinstance(targets, list)
                else ""
            )
            state = "完成" if ok is not False else "部分失败"
            code_text = f"，状态码 {code}" if code else ""
            return (
                f"{label}{state}{target_text}{code_text}；"
                "本次证据为实时读取，未复用旧诊断结果。"
            )
        return f"{label}已完成；完整数据位于结构化结果中。"

    @classmethod
    def _tool_result(
        cls,
        value: object,
        *,
        tool_name: str | None = None,
        error: bool = False,
    ) -> dict[str, object]:
        if isinstance(value, ContextToolResult) and str(
            value.envelope.get("status", "")
        ) in {
            "failed",
            "cancelled",
            "blocked",
            "mutation_outcome_unknown",
        }:
            error = True
        text = cls._human_summary(tool_name, value, error=error)
        encoded = text.encode("utf-8")
        text_limit = (
            16_384
            if isinstance(value, Mapping) and value.get("closeout_markdown")
            else 4096
        )
        if len(encoded) > text_limit and not (tool_name == "execute" and not error):
            text = encoded[: text_limit - 3].decode("utf-8", errors="ignore") + "..."
        result: dict[str, object] = {
            "content": [{"type": "text", "text": text}],
            "isError": error,
        }
        if isinstance(value, ContextToolResult):
            if tool_name in {
                "case_read",
                "evidence_query",
                "evidence_read",
                "case_close",
                "case_forget",
            }:
                structured = dict(value.envelope)
                structured.update(dict(value))
                structured["agent_envelope"] = dict(value.envelope)
                result["structuredContent"] = structured
            else:
                result["structuredContent"] = value.envelope
        elif isinstance(value, dict):
            result["structuredContent"] = value
        return result

    def handle(self, message: Mapping[str, object]) -> dict[str, object] | None:
        message_id = message.get("id")
        method = message.get("method")
        params = message.get("params", {})
        if message.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return self._error(message_id, -32600, "invalid JSON-RPC request")
        if method == "initialize":
            requested = (
                params.get("protocolVersion")
                if isinstance(params, Mapping)
                else None
            )
            protocol = requested if isinstance(requested, str) else MCP_PROTOCOL_VERSION
            return self._response(
                message_id,
                {
                    "protocolVersion": protocol,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": "openubmc-target-runtime",
                        "version": RUNTIME_API_VERSION,
                    },
                },
            )
        if method == "notifications/initialized":
            return None
        if method == "notifications/openubmc-task-complete":
            self.service.complete_task(self.task_id_for_params(params))
            return None
        if method == "notifications/cancelled":
            task_id = self.task_id_for_params(params)
            request_id = params.get("requestId") if isinstance(params, Mapping) else None
            if request_id is not None:
                self.service.cancel_operation(
                    task_id,
                    self.operation_id_for_params(params, request_id),
                )
            return None
        if method == "tools/list":
            return self._response(
                message_id,
                {"tools": self.service.tool_definitions()},
            )
        if method == "tools/call":
            if not isinstance(params, Mapping):
                return self._response(
                    message_id,
                    self._tool_result("tools/call params must be an object", error=True),
                )
            name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(name, str) or not isinstance(arguments, Mapping):
                return self._response(
                    message_id,
                    self._tool_result("tool name and arguments are required", error=True),
                )
            try:
                operation_id = self.operation_id_for_params(params, message_id)
                value = self.service.call_exposed_tool(
                    name,
                    arguments,
                    task_id=self.task_id_for_params(params),
                    operation_id=operation_id,
                )
            except Exception as exc:
                task_id = self.task_id_for_params(params)
                operation_id = self.operation_id_for_params(params, message_id)
                return self._response(
                    message_id,
                    self._tool_result(
                        self.service.error_result(
                            exc,
                            name=name,
                            arguments=arguments,
                            task_id=task_id,
                            operation_id=operation_id,
                        ),
                        tool_name=name,
                        error=True,
                    ),
                )
            return self._response(
                message_id,
                self._tool_result(value, tool_name=name),
            )
        return self._error(message_id, -32601, f"method not found: {method}")


class StdioMcpServer:
    """Serve newline-delimited MCP messages and accept cancellation concurrently."""

    def __init__(
        self,
        endpoint: JsonRpcMcpEndpoint,
        *,
        max_workers: int = 8,
        max_frame_bytes: int = STDIO_FRAME_MAX_BYTES,
        process_lifecycle: McpProcessLifecycle | None = None,
        lifecycle_poll_seconds: float = 0.25,
    ) -> None:
        if max_frame_bytes <= 1024:
            raise ValueError("stdio frame limit must exceed 1 KiB")
        self.endpoint = endpoint
        self.max_workers = max_workers
        self.max_frame_bytes = max_frame_bytes
        if (
            not math.isfinite(lifecycle_poll_seconds)
            or lifecycle_poll_seconds <= 0
        ):
            raise ValueError("lifecycle_poll_seconds must be finite and positive")
        self.process_lifecycle = process_lifecycle
        self.lifecycle_poll_seconds = float(lifecycle_poll_seconds)

    def serve(self, reader=None, writer=None) -> None:
        input_stream = sys.stdin if reader is None else reader
        output_stream = sys.stdout if writer is None else writer
        write_lock = threading.Lock()
        inflight_lock = threading.Lock()
        executor = ThreadPoolExecutor(max_workers=self.max_workers)
        futures: set[Future[dict[str, object] | None]] = set()
        futures_condition = threading.Condition()
        inflight: dict[str, tuple[str, str]] = {}
        exit_reason = "server-error"
        original_signal_handlers: dict[int, object] = {}

        if (
            self.process_lifecycle is not None
            and threading.current_thread() is threading.main_thread()
        ):
            def request_signal_exit(_signum, _frame) -> None:
                self.process_lifecycle.request_exit("client-terminated")

            for signal_number in (signal.SIGTERM, signal.SIGINT):
                original_signal_handlers[signal_number] = signal.getsignal(
                    signal_number
                )
                signal.signal(signal_number, request_signal_exit)

        def begin_request(message: Mapping[str, object]) -> None:
            if self.process_lifecycle is None:
                return
            params = message.get("params", {})
            metadata = params.get("_meta") if isinstance(params, Mapping) else None
            client = None
            session_id = None
            if isinstance(metadata, Mapping) and isinstance(
                metadata.get("codex/taskId"), str
            ):
                client = "codex"
            if isinstance(metadata, Mapping):
                for key in (
                    "openubmc/sessionId",
                    "codex/sessionId",
                    "sessionId",
                    "session_id",
                ):
                    value = metadata.get(key)
                    if isinstance(value, str) and value.strip():
                        session_id = value.strip()
                        break
            task_id = self.endpoint.task_id_for_params(params)
            if session_id is None and task_id != "unknown-task":
                session_id = task_id
            self.process_lifecycle.attribute(
                client=client,
                task_id=task_id,
                session_id=session_id,
            )
            self.process_lifecycle.begin_request()

        def end_request() -> None:
            if self.process_lifecycle is not None:
                self.process_lifecycle.end_request()

        def write_response(response: dict[str, object] | None) -> None:
            if response is None:
                return
            encoded = json.dumps(response, ensure_ascii=False, separators=(",", ":"))
            with write_lock:
                output_stream.write(encoded + "\n")
                output_stream.flush()

        def drain_accepted_tool_calls() -> None:
            with futures_condition:
                while futures:
                    futures_condition.wait()

        def read_frame() -> tuple[str, bool] | None:
            fragment = input_stream.readline(self.max_frame_bytes + 1)
            if fragment == "":
                return None
            encoded_size = len(fragment.encode("utf-8"))
            complete = fragment.endswith("\n")
            oversized = encoded_size > self.max_frame_bytes
            if not complete and len(fragment) >= self.max_frame_bytes + 1:
                oversized = True
                while True:
                    remainder = input_stream.readline(self.max_frame_bytes + 1)
                    if remainder == "" or remainder.endswith("\n"):
                        break
            return fragment, oversized

        reader_queue: queue.Queue[
            tuple[tuple[str, bool] | None, BaseException | None]
        ] | None = None
        if self.process_lifecycle is not None:
            reader_queue = queue.Queue(maxsize=1)

            def pump_input() -> None:
                try:
                    while True:
                        frame = read_frame()
                        reader_queue.put((frame, None))
                        if frame is None:
                            return
                except BaseException as exc:
                    reader_queue.put((None, exc))

            threading.Thread(
                target=pump_input,
                name="openubmc-mcp-stdio-reader",
                daemon=True,
            ).start()

        try:
            while True:
                if self.process_lifecycle is not None:
                    due_reason = self.process_lifecycle.exit_reason_if_due()
                    if due_reason is not None:
                        assert reader_queue is not None
                        try:
                            frame, read_error = reader_queue.get_nowait()
                        except queue.Empty:
                            exit_reason = due_reason
                            break
                        if read_error is not None:
                            raise read_error
                        if frame is None:
                            exit_reason = due_reason
                            break
                    assert reader_queue is not None
                    if due_reason is None:
                        try:
                            frame, read_error = reader_queue.get(
                                timeout=self.lifecycle_poll_seconds
                            )
                        except queue.Empty:
                            continue
                        if read_error is not None:
                            raise read_error
                        due_reason = self.process_lifecycle.exit_reason_if_due()
                        if due_reason is not None:
                            exit_reason = due_reason
                            break
                else:
                    frame = read_frame()
                if frame is None:
                    exit_reason = "stdin-closed"
                    break
                line, oversized = frame
                if not line.strip():
                    continue
                if oversized:
                    write_response(
                        JsonRpcMcpEndpoint._error(
                            None,
                            -32600,
                            "request exceeds the 256 KiB stdio frame limit",
                        )
                    )
                    continue
                try:
                    message = json.loads(line)
                except (json.JSONDecodeError, RecursionError):
                    write_response(
                        JsonRpcMcpEndpoint._error(None, -32700, "invalid JSON")
                    )
                    continue
                if not isinstance(message, dict):
                    write_response(
                        JsonRpcMcpEndpoint._error(None, -32600, "invalid request")
                    )
                    continue
                if message.get("method") == "notifications/cancelled":
                    params = message.get("params", {})
                    request_id = (
                        params.get("requestId")
                        if isinstance(params, Mapping)
                        else None
                    )
                    if request_id is not None:
                        request_key = str(request_id)
                        with inflight_lock:
                            tracked = inflight.get(request_key)
                        if tracked is not None:
                            task_id, operation_id = tracked
                            self.endpoint.service.cancel_operation(
                                task_id, operation_id
                            )
                    continue
                if (
                    self.process_lifecycle is not None
                    and self.process_lifecycle.shutdown_requested
                ):
                    if "id" in message:
                        write_response(
                            JsonRpcMcpEndpoint._error(
                                message.get("id"),
                                -32000,
                                "MCP process is shutting down",
                            )
                        )
                    continue
                if message.get("method") == "tools/call":
                    request_key = str(message.get("id"))
                    params = message.get("params", {})
                    task_id = self.endpoint.task_id_for_params(
                        params
                    )
                    operation_id = self.endpoint.operation_id_for_params(
                        params,
                        message.get("id"),
                    )
                    with inflight_lock:
                        inflight[request_key] = (task_id, operation_id)
                    try:
                        begin_request(message)
                    except RuntimeError:
                        with inflight_lock:
                            inflight.pop(request_key, None)
                        write_response(
                            JsonRpcMcpEndpoint._error(
                                message.get("id"),
                                -32000,
                                "MCP process is shutting down",
                            )
                        )
                        continue
                    try:
                        future = executor.submit(self.endpoint.handle, message)
                    except Exception:
                        end_request()
                        raise
                    with futures_condition:
                        futures.add(future)

                    def completed(
                        item: Future[dict[str, object] | None],
                        *,
                        request_id: object = message.get("id"),
                        tracked_request_key: str = request_key,
                    ) -> None:
                        with inflight_lock:
                            inflight.pop(tracked_request_key, None)
                        try:
                            write_response(item.result())
                        except Exception as exc:
                            write_response(
                                JsonRpcMcpEndpoint._error(
                                    request_id,
                                    -32603,
                                    f"internal error: {type(exc).__name__}",
                                )
                            )
                        finally:
                            end_request()
                            with futures_condition:
                                futures.discard(item)
                                futures_condition.notify_all()

                    future.add_done_callback(completed)
                else:
                    try:
                        begin_request(message)
                    except RuntimeError:
                        write_response(
                            JsonRpcMcpEndpoint._error(
                                message.get("id"),
                                -32000,
                                "MCP process is shutting down",
                            )
                        )
                        continue
                    try:
                        task_closeout = (
                            message.get("method")
                            == "notifications/openubmc-task-complete"
                        )
                        if task_closeout:
                            if self.process_lifecycle is not None:
                                self.process_lifecycle.request_task_closeout()
                            drain_accepted_tool_calls()
                        write_response(self.endpoint.handle(message))
                    finally:
                        end_request()
        finally:
            executor.shutdown(wait=True, cancel_futures=False)
            self.endpoint.service.close()
            if self.process_lifecycle is not None:
                due_reason = self.process_lifecycle.exit_reason_if_due()
                if due_reason is not None:
                    exit_reason = due_reason
                self.process_lifecycle.record_exit(exit_reason)
            for signal_number, handler in original_signal_handlers.items():
                signal.signal(signal_number, handler)
