#!/usr/bin/env python3
"""Bind Live Patch domain behavior to the shared Target Runtime mutation seam."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import importlib.util
from pathlib import Path
import sys
from typing import Generic, TypeVar


TARGET_RUNTIME_API_VERSION = "openubmc.target-runtime.v1"


def _load_runtime():
    local_loader = Path(__file__).resolve().with_name("_runtime_loader.py")
    loader_path = (
        local_loader
        if local_loader.is_file()
        else Path(__file__).resolve().parents[2]
        / "openubmc-target-runtime"
        / "tools"
        / "runtime_loader.py"
    )
    spec = importlib.util.spec_from_file_location(
        "_openubmc_live_patch_runtime_loader",
        loader_path,
    )
    if spec is None or spec.loader is None:
        raise ImportError("Target Runtime loader is unavailable")
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    try:
        return loader.load_runtime_module(
            Path(__file__),
            expected_api=TARGET_RUNTIME_API_VERSION,
        )
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from None


_runtime = _load_runtime()
CredentialFileError = _runtime.CredentialFileError
FreshVerificationContext = _runtime.FreshVerificationContext
MutationAuthorization = _runtime.MutationAuthorization
TaskAuthorizationPolicy = _runtime.TaskAuthorizationPolicy
MutationContext = _runtime.MutationContext
MutationRequest = _runtime.MutationRequest
MutationTransactionResult = _runtime.MutationTransactionResult
OpenUBMCTaskRun = _runtime.OpenUBMCTaskRun
ResolvedTelnetCredentials = _runtime.ResolvedTelnetCredentials
TargetSpec = _runtime.TargetSpec
close_telnet = _runtime.close_telnet
load_selected_credentials_file = _runtime.load_selected_credentials_file
run_telnet_command = _runtime.run_telnet_command
run_telnet_command_text = _runtime.run_telnet_command_text
telnet_connect = _runtime.telnet_connect


MutationValueT = TypeVar("MutationValueT")
VerificationValueT = TypeVar("VerificationValueT")


@dataclass(frozen=True)
class RuntimePrimitives:
    """Public Runtime functions used by the direct Live Patch CLI."""

    load_credentials_file: Callable[[], dict[str, str]]
    close_telnet: Callable[..., object]
    run_telnet_command: Callable[..., str]
    telnet_connect: Callable[..., object]


class CanonicalTelnetTransport:
    """Bridge canonical Telnet primitives to the persistent Runtime lane."""

    def __init__(
        self,
        *,
        connect_timeout: float = 10,
        prompt_timeout: float = 8,
    ) -> None:
        self.connect_timeout = connect_timeout
        self.prompt_timeout = prompt_timeout

    def open_session(self, *, target, credentials):
        return telnet_connect(
            target.host,
            target.telnet_port,
            credentials.user,
            credentials.password,
            connect_timeout=self.connect_timeout,
            prompt_timeout=self.prompt_timeout,
        )

    @staticmethod
    def run_command(session, command: str, **kwargs: object):
        return run_telnet_command(session, command, **kwargs)

    @staticmethod
    def command_invalidates_session(_session, result) -> bool:
        return not bool(getattr(result, "ok", False))

    @staticmethod
    def close_session(session) -> None:
        close_telnet(session)


def _load_credentials_file_compat() -> dict[str, str]:
    try:
        return load_selected_credentials_file()
    except CredentialFileError as exc:
        raise SystemExit(str(exc)) from None


def load_runtime_primitives() -> RuntimePrimitives:
    """Resolve the canonical credential and Telnet implementation once."""

    return RuntimePrimitives(
        load_credentials_file=_load_credentials_file_compat,
        close_telnet=close_telnet,
        run_telnet_command=run_telnet_command_text,
        telnet_connect=telnet_connect,
    )


@dataclass(frozen=True)
class ProjectedLivePatchAuthorization:
    """Internal projection of one already parsed task intent onto CLI gates."""

    apply: bool
    intent: str
    authorization_live_patch: bool
    restart_scope: str
    original_intent: str

    @classmethod
    def from_authorization(
        cls,
        authorization: MutationAuthorization,
        *,
        restart_scope: str,
        action: str = "live_patch",
    ) -> "ProjectedLivePatchAuthorization":
        normalized_action = str(action).strip().lower().replace("-", "_")
        if normalized_action not in {"live_patch", "rollback"}:
            raise ValueError("action must be live_patch or rollback")
        authorization.require(normalized_action)
        if restart_scope not in {"none", "skynet"}:
            raise ValueError("restart_scope must be none or skynet")
        return cls(
            apply=True,
            intent="live_patch",
            authorization_live_patch=True,
            restart_scope=restart_scope,
            original_intent=authorization.original_intent,
        )

    def to_cli_arguments(self) -> tuple[str, ...]:
        return (
            "--apply",
            "--intent",
            self.intent,
            "--authorize-live-patch",
            "--restart-scope",
            self.restart_scope,
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "apply": self.apply,
            "intent": self.intent,
            "authorization_live_patch": self.authorization_live_patch,
            "restart_scope": self.restart_scope,
            "original_intent": self.original_intent,
        }


@dataclass(frozen=True)
class LivePatchExecutionContext:
    """Domain context retaining direct SSH staging and an isolated Telnet lane."""

    mutation: MutationContext
    telnet_lane: object
    telnet_credentials: ResolvedTelnetCredentials
    gates: ProjectedLivePatchAuthorization
    ssh_lane: object | None = None

    @property
    def target(self) -> TargetSpec:
        return self.mutation.target

    @property
    def journal(self):
        return self.mutation.journal

    def ssh_credentials_mapping(self) -> dict[str, str | int]:
        """Credentials for the existing byte-stream SSH staging implementation."""

        return self.mutation.credentials.to_ssh_mapping()

    def run_telnet(self, command: str, **kwargs: object):
        return self.telnet_lane.run_command(command, **kwargs)

    def run_telnet_text(self, command: str, **kwargs: object) -> str:
        result = self.run_telnet(command, **kwargs)
        if isinstance(result, str):
            return result
        stdout = getattr(result, "stdout", None)
        if isinstance(stdout, str):
            return stdout
        value = getattr(result, "value", None)
        if isinstance(value, str):
            return value
        return str(result)

    def upload_file(
        self,
        local_path: str,
        remote_path: str,
        *,
        timeout: float,
    ):
        if self.ssh_lane is None:
            raise RuntimeError("Live Patch SSH upload transport is unavailable")
        return self.ssh_lane.upload_file(
            local_path,
            remote_path,
            timeout=timeout,
        )

    def record_backup(self, reference: str) -> None:
        self.mutation.record_backup(reference)

    def record_artifact(self, reference: str) -> None:
        self.mutation.record_artifact(reference)

    def mark_effects_started(self) -> None:
        self.mutation.mark_effects_started()


class LivePatchRuntimeAdapter(Generic[MutationValueT, VerificationValueT]):
    """Run Live Patch apply/rollback under one target-exclusive transaction."""

    LEASE_NAME = "live-patch-mutation"

    def __init__(
        self,
        *,
        task_run: OpenUBMCTaskRun,
        target: TargetSpec,
        credential_selector,
        telnet_credentials: ResolvedTelnetCredentials,
        telnet_transport: object,
        ssh_transport: object | None = None,
    ) -> None:
        self.task_run = task_run
        self.target = target
        self.credential_selector = credential_selector
        self.telnet_credentials = telnet_credentials
        self.telnet_transport = telnet_transport
        self.ssh_transport = ssh_transport

    def mutation_request(
        self,
        *,
        operation_id: str,
        restart_scope: str,
        operation: Mapping[str, object],
        action: str = "live_patch",
    ) -> MutationRequest:
        return MutationRequest.create(
            operation_id=operation_id,
            target=self.target,
            credential_selector=self.credential_selector,
            action=action,
            operation={
                **dict(operation),
                "restart_scope": restart_scope,
            },
        )

    def run(
        self,
        *,
        operation_id: str,
        authorization: MutationAuthorization,
        restart_scope: str,
        operation: Mapping[str, object],
        apply: Callable[[LivePatchExecutionContext], MutationValueT],
        verify: Callable[[FreshVerificationContext], VerificationValueT],
        action: str = "live_patch",
        operation_context: object | None = None,
    ) -> MutationTransactionResult[MutationValueT, VerificationValueT]:
        gates = ProjectedLivePatchAuthorization.from_authorization(
            authorization,
            restart_scope=restart_scope,
            action=action,
        )
        request = self.mutation_request(
            operation_id=operation_id,
            restart_scope=restart_scope,
            operation=operation,
            action=action,
        )

        def apply_under_live_patch_lease(
            mutation_context: MutationContext,
        ) -> MutationValueT:
            telnet_lane = self.task_run.telnet_lane(
                target=self.target,
                credentials=self.telnet_credentials,
                lease_name=self.LEASE_NAME,
                transport=self.telnet_transport,
            )
            ssh_lane = None
            if self.ssh_transport is not None:
                ssh_lane = self.task_run.ssh_lane(
                    target=self.target,
                    credential_selector=self.credential_selector,
                    lease_name=self.LEASE_NAME,
                    transport=self.ssh_transport,
                )
            return apply(
                LivePatchExecutionContext(
                    mutation=mutation_context,
                    telnet_lane=telnet_lane,
                    telnet_credentials=self.telnet_credentials,
                    gates=gates,
                    ssh_lane=ssh_lane,
                )
            )

        return self.task_run.run_mutation(
            request,
            authorization=authorization,
            apply=apply_under_live_patch_lease,
            verify=verify,
            operation_context=operation_context,
        )

    def recover(
        self,
        *,
        operation_id: str,
        authorization: MutationAuthorization,
        restart_scope: str,
        operation: Mapping[str, object],
        inspect: Callable[[object], Mapping[str, object]],
        verify: Callable[[FreshVerificationContext], VerificationValueT],
        action: str = "live_patch",
        operation_context: object | None = None,
    ):
        """Reconcile one uncertain Live Patch before any possible re-apply."""

        request = self.mutation_request(
            operation_id=operation_id,
            restart_scope=restart_scope,
            operation=operation,
            action=action,
        )
        return self.task_run.recover_mutation(
            request,
            authorization=authorization,
            inspect=inspect,
            verify=verify,
            operation_context=operation_context,
        )
