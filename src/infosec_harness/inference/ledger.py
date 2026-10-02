"""Controller-owned request ledger and conservative root-envelope suballocation.

All public mutation functions are trusted controller internals, not an authorization API.
The authenticated HTTP boundary must restrict lease and invocation ownership. No request
allocation is released in v1, including pre-dispatch failure and completed requests.
"""
from __future__ import annotations

import logging
import math
import secrets
import time
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime

from pydantic_ai.messages import ModelResponse
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from infosec_harness.inference.codec import validate_result_usage
from infosec_harness.inference.protocol import (
    MAX_BODY_BYTES,
    BrokerError,
    DispatchPermit,
    InferenceRequest,
    InferenceResult,
    RequestState,
    canonical_bytes,
)
from infosec_harness.persistence import db

_LOG = logging.getLogger(__name__)
_ATTEMPTS = 20
_DIMENSIONS = ("requests", "tokens", "cost_usd")


@dataclass(frozen=True)
class StoredDisposition:
    request: InferenceRequest
    lease_id: str
    state: RequestState
    result: InferenceResult | None
    allocation: dict[str, float]
    overrun: dict[str, float] | None = None


async def _checkpoint(phase: str) -> None:
    """Private injected test fault/barrier seam; never exposed by the service API."""


def _stored(row: db.InferenceRequestRecord) -> StoredDisposition:
    return StoredDisposition(
        request=InferenceRequest.model_validate(row.request), lease_id=row.lease_id,
        state=row.state, result=InferenceResult.model_validate(row.result) if row.result else None,
        allocation=dict(row.allocation), overrun=dict(row.overrun) if row.overrun else None,
    )


def _lease(row: db.InferenceRequestRecord, lease_id: str) -> None:
    if row.lease_id != lease_id:
        raise BrokerError("identity", "Request is owned by a different executor lease")


def _allocation(values: dict[str, float]) -> dict[str, float]:
    if (set(values) != set(_DIMENSIONS) or values.get("requests") != 1
            or any(isinstance(v, bool) or not isinstance(v, (int, float))
                   or not math.isfinite(v) or v < 0 for v in values.values())):
        raise BrokerError("budget", "Invalid trusted request allocation")
    return dict(values)


def _active(state: dict, request: InferenceRequest) -> dict:
    """Check trusted persisted binding again at the actual dispatch boundary."""
    binding = request.binding
    if binding.run_id in state.get("broker_revoked_runs", []):
        raise BrokerError("policy", "Inference run revoked")
    if binding.expires_at <= time.time():
        raise BrokerError("expired", "Inference reservation expired")
    deadline = state.get("deadline_at")
    if deadline is None or datetime.fromisoformat(deadline).timestamp() <= time.time():
        raise BrokerError("expired", "Root deadline is missing or expired")
    operation = state.get("operations", {}).get(binding.operation_id)
    if (operation is None or operation.get("status") == "settled"
            or operation.get("agent") != binding.agent
            or operation.get("kind", "agent") != "agent"
            or operation.get("broker_binding") != binding.model_dump(mode="json")):
        raise BrokerError("identity", "Inference reservation binding is not authoritative")
    if state.get("agent_config_digests", {}).get(binding.agent) != operation.get("broker_configuration_digest"):
        raise BrokerError("identity", "Accepted root configuration no longer matches the invocation")
    if operation.get("broker_overrun"):
        _LOG.warning("IH_BUDGET_GUARD boundary=ledger category=active_overrun")
        raise BrokerError("budget", "A provider overrun blocks further invocation dispatch")
    if operation.get("broker_revoked"):
        raise BrokerError("policy", "Inference reservation revoked")
    return operation


async def get(request_id: str) -> StoredDisposition | None:
    """Trusted read; external callers must be scoped before revealing a record."""
    async with db.session() as session:
        row = await session.get(db.InferenceRequestRecord, request_id)
        return _stored(row) if row is not None else None


async def admit(request: InferenceRequest, *, lease_id: str,
                allocation: dict[str, float]) -> StoredDisposition:
    demand = _allocation(allocation)
    if not lease_id or len(lease_id) > 128:
        raise BrokerError("identity", "Invalid executor lease")
    for _ in range(_ATTEMPTS):
        async with db.session() as session:
            existing = await session.get(db.InferenceRequestRecord, request.request_id)
            if existing is not None:
                _lease(existing, lease_id)
                if existing.request != request.model_dump(mode="json") or existing.allocation != demand:
                    raise BrokerError("conflict", "Request identity already binds different content")
                return _stored(existing)
            root = await session.get(db.BudgetLedger, request.binding.root_id)
            if root is None:
                raise BrokerError("identity", "Inference requires an existing root reservation")
            state = deepcopy(root.state)
            operation = _active(state, request)
            consumed = operation.get("broker_allocated", dict.fromkeys(_DIMENSIONS, 0))
            updated_demand = {key: math.fsum((consumed.get(key, 0), demand[key]))
                              for key in _DIMENSIONS}
            if any(updated_demand[key] > operation["reserved"].get(key, 0) for key in _DIMENSIONS):
                _LOG.warning("IH_BUDGET_GUARD boundary=ledger category=cumulative_allocation")
                raise BrokerError("budget", "Invocation allocation exhausted")
            operation.update(broker_owned=True, broker_allocated=updated_demand)
            await _checkpoint("admit_before_cas")
            won = await session.execute(update(db.BudgetLedger).where(
                db.BudgetLedger.root_id == root.root_id, db.BudgetLedger.revision == root.revision
            ).values(state=state, revision=root.revision + 1))
            if won.rowcount != 1:
                await session.rollback()
                continue
            row = db.InferenceRequestRecord(
                request_id=request.request_id, root_id=request.binding.root_id,
                operation_id=request.binding.operation_id, lease_id=lease_id,
                state="accepted", revision=0, request=request.model_dump(mode="json"),
                allocation=demand,
            )
            session.add(row)
            try:
                await session.flush()
                disposition = _stored(row)
                await _checkpoint("admit_before_commit")
                await session.commit()
                return disposition
            except IntegrityError:
                # Another root may have raced to bind this globally unique request ID.
                # Roll back the root allocation together with the failed insertion.
                await session.rollback()
    raise BrokerError("unavailable", "Bounded ledger contention exhausted")


async def claim(request_id: str, *, lease_id: str) -> DispatchPermit:
    for _ in range(_ATTEMPTS):
        async with db.session() as session:
            row = await session.get(db.InferenceRequestRecord, request_id)
            if row is None:
                raise BrokerError("identity", "Request was not admitted")
            _lease(row, lease_id)
            if row.state != "accepted":
                code = "completion_unknown" if row.state == "completion_unknown" else "pending"
                raise BrokerError(code, "Request does not permit another dispatch")
            root = await session.get(db.BudgetLedger, row.root_id)
            if root is None:
                raise BrokerError("identity", "Root reservation is missing")
            state = deepcopy(root.state)
            operation = _active(state, InferenceRequest.model_validate(row.request))
            if not operation.get("broker_owned"):
                raise BrokerError("identity", "Request allocation is not durably held")
            operation["broker_dispatches"] = operation.get("broker_dispatches", 0) + 1
            await _checkpoint("claim_before_cas")
            won_root = await session.execute(update(db.BudgetLedger).where(
                db.BudgetLedger.root_id == root.root_id, db.BudgetLedger.revision == root.revision
            ).values(state=state, revision=root.revision + 1))
            if won_root.rowcount != 1:
                await session.rollback()
                continue
            permit = DispatchPermit(request_id=request_id, lease_id=lease_id,
                                    fence=secrets.token_hex(32))
            won = await session.execute(update(db.InferenceRequestRecord).where(
                db.InferenceRequestRecord.request_id == request_id,
                db.InferenceRequestRecord.revision == row.revision,
                db.InferenceRequestRecord.state == "accepted",
            ).values(state="dispatch_intent", revision=row.revision + 1,
                     fence=permit.fence, updated_at=db.utcnow()))
            if won.rowcount != 1:
                await session.rollback()
                continue
            await _checkpoint("claim_before_commit")
            await session.commit()
            return permit
    raise BrokerError("unavailable", "Bounded ledger contention exhausted")


def _validate_result(result: InferenceResult) -> ModelResponse:
    if len(canonical_bytes(result.model_dump(mode="json"))) > MAX_BODY_BYTES:
        raise BrokerError("invalid_response", "Inference result exceeds protocol limit")
    return validate_result_usage(result)


async def complete(result: InferenceResult, *, permit: DispatchPermit) -> StoredDisposition:
    response = _validate_result(result)
    if result.request_id != permit.request_id:
        raise BrokerError("identity", "Result and dispatch permit differ")
    for _ in range(_ATTEMPTS):
        async with db.session() as session:
            row = await session.get(db.InferenceRequestRecord, result.request_id)
            if row is None:
                raise BrokerError("identity", "Request was not admitted")
            _lease(row, permit.lease_id)
            if row.fence != permit.fence:
                raise BrokerError("identity", "Dispatch permit does not own this request")
            if row.state == "completed":
                if row.result != result.model_dump(mode="json"):
                    raise BrokerError("conflict", "Completed response is immutable")
                return _stored(row)
            if row.state != "dispatch_intent":
                raise BrokerError("completion_unknown", "Dispatch has been fenced by recovery")
            actual_tokens = response.usage.input_tokens + response.usage.output_tokens
            overrun = {"tokens": actual_tokens - row.allocation["tokens"]} if actual_tokens > row.allocation["tokens"] else None
            if overrun:
                root = await session.get(db.BudgetLedger, row.root_id)
                if root is None:
                    raise BrokerError("identity", "Root reservation is missing")
                state = deepcopy(root.state)
                operation = state["operations"][row.operation_id]
                operation["broker_overrun"] = {"request_id": row.request_id, **overrun}
                won_root = await session.execute(update(db.BudgetLedger).where(
                    db.BudgetLedger.root_id == root.root_id, db.BudgetLedger.revision == root.revision
                ).values(state=state, revision=root.revision + 1))
                if won_root.rowcount != 1:
                    await session.rollback()
                    continue
            won = await session.execute(update(db.InferenceRequestRecord).where(
                db.InferenceRequestRecord.request_id == row.request_id,
                db.InferenceRequestRecord.revision == row.revision,
                db.InferenceRequestRecord.state == "dispatch_intent",
            ).values(state="completed", result=result.model_dump(mode="json"), overrun=overrun,
                     revision=row.revision + 1, updated_at=db.utcnow()))
            if won.rowcount != 1:
                await session.rollback()
                continue
            # Derive the return value from our write, then commit before exposing it.
            row.state, row.result, row.overrun = "completed", result.model_dump(mode="json"), overrun
            disposition = _stored(row)
            await _checkpoint("complete_before_commit")
            await session.commit()
            return disposition
    raise BrokerError("unavailable", "Bounded ledger contention exhausted")


async def _terminal(request_id: str, *, lease_id: str, recovery: bool) -> StoredDisposition:
    for _ in range(_ATTEMPTS):
        async with db.session() as session:
            row = await session.get(db.InferenceRequestRecord, request_id)
            if row is None:
                raise BrokerError("identity", "Retained recovery record is missing")
            _lease(row, lease_id)
            target = "completion_unknown" if recovery else "failed_before_dispatch"
            expected = "dispatch_intent" if recovery else "accepted"
            if row.state != expected:
                if not recovery and row.state == "dispatch_intent":
                    raise BrokerError("completion_unknown", "Pre-dispatch failure cannot erase dispatch intent")
                return _stored(row)
            won = await session.execute(update(db.InferenceRequestRecord).where(
                db.InferenceRequestRecord.request_id == request_id,
                db.InferenceRequestRecord.revision == row.revision,
                db.InferenceRequestRecord.state == expected,
            ).values(state=target, revision=row.revision + 1, updated_at=db.utcnow()))
            if won.rowcount != 1:
                await session.rollback()
                continue
            row.state = target
            disposition = _stored(row)
            await session.commit()
            return disposition
    raise BrokerError("unavailable", "Bounded ledger contention exhausted")


async def fail_before_dispatch(request_id: str, *, lease_id: str) -> StoredDisposition:
    return await _terminal(request_id, lease_id=lease_id, recovery=False)


async def recover(request_id: str, *, lease_id: str) -> StoredDisposition:
    """Trusted controller fences the result; revoke the lease separately, never resend."""
    return await _terminal(request_id, lease_id=lease_id, recovery=True)


async def revoke_run(run_id: str) -> None:
    """Trusted controller closes existing run roots before deleting native leases.

    The service must authenticate an existing run/root reference before calling this
    administrative function. This is not an unauthenticated run-ID API. Its persisted
    fence prevents future operation admission on each existing root; controller lifecycle
    ownership must additionally prevent re-creating a never-registered closed run.
    """
    async with db.session() as session:
        root_ids = (await session.execute(select(db.BudgetLedger.root_id))).scalars().all()
    for root_id in root_ids:
        for _ in range(_ATTEMPTS):
            async with db.session() as session:
                root = await session.get(db.BudgetLedger, root_id)
                if root is None:
                    break
                state = deepcopy(root.state)
                matches = [identity for identity, operation in state.get("operations", {}).items()
                           if operation.get("run_id") == run_id
                           or operation.get("broker_binding", {}).get("run_id") == run_id]
                if not matches and state.get("broker_run_id") != run_id:
                    break
                state["broker_revoked_runs"] = sorted(set(state.get("broker_revoked_runs", [])) | {run_id})
                for identity in matches:
                    state["operations"][identity].update(
                        broker_revoked=True, broker_owned=True, status="uncertain")
                won = await session.execute(update(db.BudgetLedger).where(
                    db.BudgetLedger.root_id == root_id, db.BudgetLedger.revision == root.revision
                ).values(state=state, revision=root.revision + 1))
                if won.rowcount != 1:
                    await session.rollback()
                    continue
                for before, after in (("accepted", "failed_before_dispatch"),
                                      ("dispatch_intent", "completion_unknown")):
                    await session.execute(update(db.InferenceRequestRecord).where(
                        db.InferenceRequestRecord.root_id == root_id,
                        db.InferenceRequestRecord.operation_id.in_(matches),
                        db.InferenceRequestRecord.state == before,
                    ).values(state=after, revision=db.InferenceRequestRecord.revision + 1,
                             updated_at=db.utcnow()))
                await session.commit()
                break
        else:
            raise BrokerError("unavailable", "Bounded run revocation contention exhausted")


async def validate_run_owner(run_id: str, root_id: str) -> None:
    """Trusted authenticated controller precondition for explicit run cleanup."""
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, root_id)
        if root is None:
            raise BrokerError("identity", "Cleanup requires an existing owned root")
        if root.state.get("broker_run_id") == run_id:
            return
        operations = root.state.get("operations", {}).values()
        if any(operation.get("run_id") == run_id
               and operation.get("broker_binding", {}).get("run_id") == run_id
               for operation in operations):
            return
    raise BrokerError("identity", "Cleanup run does not belong to this root")
