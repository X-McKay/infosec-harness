"""Controller-owned request ledger and conservative root-envelope suballocation.

All mutations are trusted controller internals, not an authorization API. The authenticated
HTTP boundary must restrict lease and invocation ownership. No request allocation is released
in v1, including pre-dispatch failure and completed requests.
"""
from __future__ import annotations

import math
import secrets
import time
from collections.abc import Awaitable, Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic_ai.messages import ModelResponse
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from infosec_harness.inference.codec import validate_result_usage
from infosec_harness.inference.diagnostics import budget_guard
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

CAS_ATTEMPTS = 20
_DIMENSIONS = ("requests", "tokens", "cost_usd")


class _Retry:
    """Sentinel: the compare-and-set lost its race and the session was rolled back."""


RETRY = _Retry()


async def cas_retry[T](body: Callable[[Any], Awaitable[T | _Retry]], *,
                       exhausted: str = "Bounded ledger contention exhausted") -> T:
    """Run ``body`` in a fresh session until it stops returning :data:`RETRY`, boundedly."""
    for _ in range(CAS_ATTEMPTS):
        async with db.session() as session:
            outcome = await body(session)
            if not isinstance(outcome, _Retry):
                return outcome
    raise BrokerError("unavailable", exhausted)


async def cas_root(session, root: db.BudgetLedger, state: dict) -> bool:
    """Compare-and-set one root state at its read revision; on a lost race roll back."""
    won = await session.execute(update(db.BudgetLedger).where(
        db.BudgetLedger.root_id == root.root_id, db.BudgetLedger.revision == root.revision
    ).values(state=state, revision=root.revision + 1))
    if won.rowcount != 1:
        await session.rollback()
        return False
    return True


async def _set_state(session, row: db.InferenceRequestRecord, expected: RequestState,
                     target: RequestState, **values: Any) -> bool:
    """Compare-and-set one request row from ``expected``; on a lost race roll back."""
    won = await session.execute(update(db.InferenceRequestRecord).where(
        db.InferenceRequestRecord.request_id == row.request_id,
        db.InferenceRequestRecord.revision == row.revision,
        db.InferenceRequestRecord.state == expected,
    ).values(state=target, revision=row.revision + 1, updated_at=db.utcnow(), **values))
    if won.rowcount != 1:
        await session.rollback()
        return False
    return True


@dataclass(frozen=True)
class StoredDisposition:
    request: InferenceRequest
    lease_id: str
    state: RequestState
    result: InferenceResult | None
    allocation: dict[str, float]
    overrun: dict[str, float] | None = None

    def error(self) -> BrokerError:
        """The disposition a reader sees for a request without a completed result."""
        code = {
            RequestState.ACCEPTED: "pending",
            RequestState.DISPATCH_INTENT: "pending",
            RequestState.COMPLETION_UNKNOWN: "completion_unknown",
            RequestState.FAILED_BEFORE_DISPATCH: "expired",
        }.get(self.state, "identity")  # A completed row without its result is malformed.
        return BrokerError(code)

    def require_completed(self) -> InferenceResult:
        if self.state == RequestState.COMPLETED and self.result is not None:
            return self.result
        raise self.error()


async def _checkpoint(phase: str) -> None:
    """Private injected test fault/barrier seam; never exposed by the service API."""


def _stored(row: db.InferenceRequestRecord) -> StoredDisposition:
    return StoredDisposition(
        request=InferenceRequest.model_validate(row.request), lease_id=row.lease_id,
        state=RequestState(row.state),
        result=InferenceResult.model_validate(row.result) if row.result else None,
        allocation=dict(row.allocation), overrun=dict(row.overrun) if row.overrun else None,
    )


def _owned_row(row: db.InferenceRequestRecord | None, lease_id: str, missing: str) -> db.InferenceRequestRecord:
    if row is None:
        raise BrokerError("identity", missing)
    if row.lease_id != lease_id:
        raise BrokerError("identity", "Request is owned by a different executor lease")
    return row


def _allocation(values: dict[str, float]) -> dict[str, float]:
    if (set(values) != set(_DIMENSIONS) or values.get("requests") != 1
            or any(isinstance(v, bool) or not isinstance(v, (int, float))
                   or not math.isfinite(v) or v < 0 for v in values.values())):
        raise BrokerError("budget", "Invalid trusted request allocation")
    return dict(values)


def _loggable(value: Any) -> bool:
    return (type(value) is int and value.bit_length() <= 1023) or (
        type(value) is float and math.isfinite(value))


def _active(state: dict, request: InferenceRequest, now: float) -> dict:
    """Check trusted persisted binding again at the actual dispatch boundary."""
    binding = request.binding
    if binding.run_id in state.get("broker_revoked_runs", []):
        raise BrokerError("policy", "Inference run revoked")
    if binding.expires_at <= now:
        raise BrokerError("expired", "Inference reservation expired")
    deadline = state.get("deadline_at")
    if deadline is None or datetime.fromisoformat(deadline).timestamp() <= now:
        raise BrokerError("expired", "Root deadline is missing or expired")
    operation = state.get("operations", {}).get(binding.operation_id)
    if (operation is None or operation.get("status") in {"settled", "closed_unknown"}
            or operation.get("agent") != binding.agent
            or operation.get("kind", "agent") != "agent"
            or operation.get("broker_binding") != binding.model_dump(mode="json")):
        raise BrokerError("identity", "Inference reservation binding is not authoritative")
    if state.get("agent_config_digests", {}).get(binding.agent) != operation.get("broker_configuration_digest"):
        raise BrokerError("identity", "Accepted root configuration no longer matches the invocation")
    if operation.get("broker_overrun"):
        raise budget_guard("ledger", "active_overrun",
                           "A provider overrun blocks further invocation dispatch")
    if operation.get("broker_revoked"):
        raise BrokerError("policy", "Inference reservation revoked")
    return operation


def _exhausted(updated: dict[str, float], reserved: dict[str, float]) -> BrokerError:
    """Log each exhausted dimension whose values are loggable numbers, never other content."""
    exhausted = [key for key in _DIMENSIONS
                 if _loggable(updated[key]) and _loggable(reserved.get(key, 0))
                 and updated[key] > reserved.get(key, 0)]
    for key in exhausted:
        budget_guard("ledger", "cumulative_allocation", dimension=key, allocated=updated[key],
                     reserved=reserved.get(key, 0))
    if not exhausted:
        budget_guard("ledger", "cumulative_allocation")
    return BrokerError("budget", "Invocation allocation exhausted")


def _validate_result(result: InferenceResult) -> ModelResponse:
    if len(canonical_bytes(result.model_dump(mode="json"))) > MAX_BODY_BYTES:
        raise BrokerError("invalid_response", "Inference result exceeds protocol limit")
    return validate_result_usage(result)


def _references_run(operation: dict, run_id: str) -> bool:
    """Fencing is deliberately broad: either recorded run field referencing the run is enough."""
    return (operation.get("run_id") == run_id
            or operation.get("broker_binding", {}).get("run_id") == run_id)


class DurableLedger:
    """The controller's request ledger, bound to its injected clock."""

    def __init__(self, *, clock: Callable[[], float] = time.time):
        self.clock = clock

    async def get(self, request_id: str) -> StoredDisposition | None:
        """Trusted read; external callers must be scoped before revealing a record."""
        async with db.session() as session:
            row = await session.get(db.InferenceRequestRecord, request_id)
            return _stored(row) if row is not None else None

    async def admit(self, request: InferenceRequest, *, lease_id: str,
                    allocation: dict[str, float]) -> StoredDisposition:
        demand = _allocation(allocation)
        if not lease_id or len(lease_id) > 128:
            raise BrokerError("identity", "Invalid executor lease")

        async def attempt(session):
            existing = await session.get(db.InferenceRequestRecord, request.request_id)
            if existing is not None:
                _owned_row(existing, lease_id, "Request was not admitted")
                if existing.request != request.model_dump(mode="json") or existing.allocation != demand:
                    raise BrokerError("conflict", "Request identity already binds different content")
                return _stored(existing)
            root = await session.get(db.BudgetLedger, request.binding.root_id)
            if root is None:
                raise BrokerError("identity", "Inference requires an existing root reservation")
            state = deepcopy(root.state)
            operation = _active(state, request, self.clock())
            consumed = operation.get("broker_allocated", dict.fromkeys(_DIMENSIONS, 0))
            updated = {key: math.fsum((consumed.get(key, 0), demand[key])) for key in _DIMENSIONS}
            if any(updated[key] > operation["reserved"].get(key, 0) for key in _DIMENSIONS):
                raise _exhausted(updated, operation["reserved"])
            operation.update(broker_owned=True, broker_allocated=updated)
            await _checkpoint("admit_before_cas")
            if not await cas_root(session, root, state):
                return RETRY
            row = db.InferenceRequestRecord(
                request_id=request.request_id, root_id=request.binding.root_id,
                operation_id=request.binding.operation_id, lease_id=lease_id,
                state=RequestState.ACCEPTED, revision=0, request=request.model_dump(mode="json"),
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
                return RETRY

        return await cas_retry(attempt)

    async def claim(self, request_id: str, *, lease_id: str) -> DispatchPermit:
        async def attempt(session):
            row = _owned_row(await session.get(db.InferenceRequestRecord, request_id), lease_id,
                             "Request was not admitted")
            if row.state != RequestState.ACCEPTED:
                code = "completion_unknown" if row.state == RequestState.COMPLETION_UNKNOWN else "pending"
                raise BrokerError(code, "Request does not permit another dispatch")
            root = await session.get(db.BudgetLedger, row.root_id)
            if root is None:
                raise BrokerError("identity", "Root reservation is missing")
            state = deepcopy(root.state)
            operation = _active(state, InferenceRequest.model_validate(row.request), self.clock())
            if not operation.get("broker_owned"):
                raise BrokerError("identity", "Request allocation is not durably held")
            operation["broker_dispatches"] = operation.get("broker_dispatches", 0) + 1
            await _checkpoint("claim_before_cas")
            if not await cas_root(session, root, state):
                return RETRY
            permit = DispatchPermit(request_id=request_id, lease_id=lease_id,
                                    fence=secrets.token_hex(32))
            if not await _set_state(session, row, RequestState.ACCEPTED,
                                    RequestState.DISPATCH_INTENT, fence=permit.fence):
                return RETRY
            await _checkpoint("claim_before_commit")
            await session.commit()
            return permit

        return await cas_retry(attempt)

    async def complete(self, result: InferenceResult, *, permit: DispatchPermit) -> StoredDisposition:
        response = _validate_result(result)
        if result.request_id != permit.request_id:
            raise BrokerError("identity", "Result and dispatch permit differ")
        encoded = result.model_dump(mode="json")

        async def attempt(session):
            row = _owned_row(await session.get(db.InferenceRequestRecord, result.request_id),
                             permit.lease_id, "Request was not admitted")
            if row.fence != permit.fence:
                raise BrokerError("identity", "Dispatch permit does not own this request")
            if row.state == RequestState.COMPLETED:
                if row.result != encoded:
                    raise BrokerError("conflict", "Completed response is immutable")
                return _stored(row)
            if row.state != RequestState.DISPATCH_INTENT:
                raise BrokerError("completion_unknown", "Dispatch has been fenced by recovery")
            actual_tokens = response.usage.input_tokens + response.usage.output_tokens
            overrun = ({"tokens": actual_tokens - row.allocation["tokens"]}
                       if actual_tokens > row.allocation["tokens"] else None)
            if overrun:
                root = await session.get(db.BudgetLedger, row.root_id)
                if root is None:
                    raise BrokerError("identity", "Root reservation is missing")
                state = deepcopy(root.state)
                state["operations"][row.operation_id]["broker_overrun"] = {
                    "request_id": row.request_id, **overrun}
                if not await cas_root(session, root, state):
                    return RETRY
            if not await _set_state(session, row, RequestState.DISPATCH_INTENT,
                                    RequestState.COMPLETED, result=encoded, overrun=overrun):
                return RETRY
            # Derive the return value from our write, then commit before exposing it.
            row.state, row.result, row.overrun = RequestState.COMPLETED, encoded, overrun
            disposition = _stored(row)
            await _checkpoint("complete_before_commit")
            await session.commit()
            return disposition

        return await cas_retry(attempt)

    async def _terminal(self, request_id: str, *, lease_id: str,
                        expected: RequestState, target: RequestState) -> StoredDisposition:
        async def attempt(session):
            row = _owned_row(await session.get(db.InferenceRequestRecord, request_id), lease_id,
                             "Retained recovery record is missing")
            if row.state != expected:
                if expected == RequestState.ACCEPTED and row.state == RequestState.DISPATCH_INTENT:
                    raise BrokerError("completion_unknown", "Pre-dispatch failure cannot erase dispatch intent")
                return _stored(row)
            if not await _set_state(session, row, expected, target):
                return RETRY
            row.state = target
            disposition = _stored(row)
            await session.commit()
            return disposition

        return await cas_retry(attempt)

    async def fail_before_dispatch(self, request_id: str, *, lease_id: str) -> StoredDisposition:
        return await self._terminal(request_id, lease_id=lease_id, expected=RequestState.ACCEPTED,
                                    target=RequestState.FAILED_BEFORE_DISPATCH)

    async def recover(self, request_id: str, *, lease_id: str) -> StoredDisposition:
        """Trusted controller fences the result; revoke the lease separately, never resend."""
        return await self._terminal(request_id, lease_id=lease_id,
                                    expected=RequestState.DISPATCH_INTENT,
                                    target=RequestState.COMPLETION_UNKNOWN)

    async def revoke_run(self, run_id: str, *, root_id: str) -> None:
        """Trusted controller fences one authenticated run root before deleting native leases.

        Call only after :meth:`validate_run_owner` authenticated ``(run_id, root_id)``; a run
        owns exactly one root (the Temporal workflow root, or the local ``{"local_run": run}``
        digest). This is not an unauthenticated run-ID API. The persisted fence prevents future
        operation admission on that root; the controller's persistent run tombstone additionally
        prevents re-creating a closed run elsewhere.
        """
        async def attempt(session):
            root = await session.get(db.BudgetLedger, root_id)
            if root is None:
                raise BrokerError("identity", "Cleanup requires an existing owned root")
            state = deepcopy(root.state)
            matches = [identity for identity, operation in state.get("operations", {}).items()
                       if _references_run(operation, run_id)]
            if not matches and state.get("broker_run_id") != run_id:
                raise BrokerError("identity", "Cleanup run does not belong to this root")
            state["broker_revoked_runs"] = sorted(set(state.get("broker_revoked_runs", [])) | {run_id})
            for identity in matches:
                operation = state["operations"][identity]
                operation.update(broker_revoked=True, broker_owned=True)
                if operation.get("status") != "closed_unknown":
                    operation["status"] = "uncertain"
            if state != root.state and not await cas_root(session, root, state):
                return RETRY
            # Pending rows are terminalized in the fence's transaction; a repeat is a no-op.
            for before, after in ((RequestState.ACCEPTED, RequestState.FAILED_BEFORE_DISPATCH),
                                  (RequestState.DISPATCH_INTENT, RequestState.COMPLETION_UNKNOWN)):
                await session.execute(update(db.InferenceRequestRecord).where(
                    db.InferenceRequestRecord.root_id == root_id,
                    db.InferenceRequestRecord.operation_id.in_(matches),
                    db.InferenceRequestRecord.state == before,
                ).values(state=after, revision=db.InferenceRequestRecord.revision + 1,
                         updated_at=db.utcnow()))
            await session.commit()
            return None

        await cas_retry(attempt, exhausted="Bounded run revocation contention exhausted")

    async def validate_run_owner(self, run_id: str, root_id: str) -> None:
        """Trusted authenticated controller precondition for explicit run cleanup.

        Authentication is deliberately strict where :meth:`revoke_run` fencing is broad: an
        operation proves ownership only when its recorded run and its controller-issued binding
        both name the run, so one forged or stale field cannot grant cleanup authority.
        """
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
