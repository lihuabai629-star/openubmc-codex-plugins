"""Single-dispatch property mutation through the existing TaskRun journal seam."""
from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib

from .capability import EffectRecoveryMode
from .contracts import CredentialSelector, TargetSpec
from .mutation import (MutationRequest, MutationRecoveryEvidence, PropertyMutationNoOp,
                       TaskAuthorizationPolicy, MutationOperationConflict)
from .property_state import PropertyContract, PropertyValue, PropertyObservation, PropertyMutationState
from .runtime import OpenUBMCTaskRun, RemoteReadRequest


def annotate_property_preflight_failure(error, journal, recovery_mode):
    """A rejected plan is not evidence that an earlier setter never ran."""
    if hasattr(error, "mutation_outcome") or hasattr(error, "recovery_status"):
        return
    if journal is not None and journal.effects_started:
        if journal.terminal:
            error.mutation_outcome = "applied"
        else:
            error.recovery_status = journal.to_public_dict()
            error.mutation_outcome = "unknown"
    elif recovery_mode is EffectRecoveryMode.RECONCILE and journal is None:
        error.mutation_outcome = "unknown"
    else:
        error.mutation_outcome = "not_started"


class PropertyMutation:
    def __init__(self, *, task_run: OpenUBMCTaskRun, target: TargetSpec,
                 selector: CredentialSelector,
                 observe: Callable[[PropertyContract], PropertyObservation],
                 assign: Callable[[PropertyMutationState], Mapping[str, object]]) -> None:
        self.task_run, self.target, self.selector = task_run, target, selector
        self.observe, self.assign = observe, assign

    def _fresh(self, operation_id: str, contract: PropertyContract, state: PropertyMutationState, context):
        request = RemoteReadRequest.create(
            request_id=f"property-verify-{hashlib.sha256(operation_id.encode()).hexdigest()[:32]}-{context.verification_attempt}",
            target=self.target, credential_selector=self.selector,
            collector_name="mdb-property-verification",
            operation={"mutation_id": operation_id, "state": state.to_public_dict(), "epoch": context.epoch_after,
                       "attempt": context.verification_attempt},
        )
        observed = context.run_read(request, lambda _read: self.observe(contract)).value
        if not state.matches(observed):
            raise ValueError("fresh property verification does not match the frozen plan")
        return {"property_observation": observed.to_public_dict(),
                "target_epoch": context.epoch_after, "verified": True,
                "setter_exactly_once": None, "persistence": contract.persistence,
                "reboot_persistence_verified": False}

    def run(self, *, operation_id: str, contract: PropertyContract,
            expected: PropertyValue, desired: PropertyValue,
            authorization: TaskAuthorizationPolicy,
            recovery_mode: EffectRecoveryMode | None = None,
            operation_context=None) -> dict[str, object]:
        existing = self.task_run.mutation_journal(operation_id)
        try:
            authorization.require("mdb_property_modify")
            if contract.target.strip().lower() != self.target.host:
                raise ValueError("property contract belongs to another target")
            contract.validate_value(expected)
            contract.validate_value(desired)
            request = MutationRequest.create(
                operation_id=operation_id, target=self.target, credential_selector=self.selector,
                action="mdb_property_modify", operation={"contract": contract.to_public_dict(),
                    "expected": expected.to_public_dict(), "desired": desired.to_public_dict()},
            )
            if recovery_mode is EffectRecoveryMode.RECONCILE and existing is None:
                raise MutationOperationConflict("property recovery journal is unavailable; no write permitted")
            if existing is not None and existing.operation_fingerprint != request.fingerprint:
                raise MutationOperationConflict("property plan differs from the durable Effect")
        except Exception as error:
            annotate_property_preflight_failure(error, existing, recovery_mode)
            raise
        if existing is not None and not existing.terminal and existing.stage != "replan_required":
            state = existing.property_state
            if state is None:
                raise MutationOperationConflict("property recovery plan is unavailable; no write permitted")
            result = self.task_run.recover_mutation(
                request, authorization=authorization,
                inspect=lambda _context: MutationRecoveryEvidence(
                    property_observation=self.observe(contract)),
                verify=lambda context: self._fresh(operation_id, contract, state, context),
                operation_context=operation_context,
            ).to_transaction_dict(target_fingerprint=self.target.fingerprint)
            result["ok"] = result["journal"]["stage"] == "verified"
            result["outcome_status"] = "verified" if result["ok"] else "mutation_outcome_unknown"
            return result
        if recovery_mode is EffectRecoveryMode.RECONCILE and existing is not None and existing.stage == "replan_required":
            # A recovery call is read-only even when the durable failure was before send.
            return {"operation_id": operation_id, "ok": False, "outcome_status": "blocked",
                    "journal": existing.to_public_dict(), "new_write_requests": 0}

        def apply(context):
            if operation_context is not None:
                operation_context.raise_if_stopped()
            before = self.observe(contract)
            state = PropertyMutationState(contract, expected, desired, before)
            context.record_target_identity(before.target_identity)
            context.journal.record_property_state(state)
            current = self.observe(contract)
            if (not current.usable or current.identity_dict() != before.identity_dict()
                    or current.value != expected):
                raise ValueError("property changed before dispatch; zero writes")
            if operation_context is not None:
                operation_context.raise_if_stopped()
            if expected == desired:
                return PropertyMutationNoOp({"changed": False, "new_write_requests": 0})
            context.mark_effects_started()
            receipt = self.assign(state)
            return {"changed": True, "new_write_requests": 1, "setter_receipt": dict(receipt)}

        result = self.task_run.run_mutation(
            request, authorization=authorization, apply=apply,
            verify=lambda context: self._fresh(operation_id, contract,
                self.task_run.mutation_journal(operation_id).property_state, context),
            operation_context=operation_context,
        ).to_public_dict()
        result["ok"] = result["journal"]["stage"] == "verified"
        result["outcome_status"] = "verified" if result["ok"] else "blocked"
        return result
