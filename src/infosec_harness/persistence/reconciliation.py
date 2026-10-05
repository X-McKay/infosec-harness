"""Explicit conservative operator closure; never recovers or resends model results.

These functions are trusted operator internals, not an authorization API. Unknown request
rows remain permanent dispatch tombstones. Accounting charges the entire operation envelope
as an estimate, never as observed provider usage.
"""
from __future__ import annotations

import math
from copy import deepcopy
from datetime import UTC, datetime

from sqlalchemy import select, update

from infosec_harness.persistence import budgets, db
from infosec_harness.persistence.budgets import (
    ClosureRequest,
    _check_bounds,
    _dimensions,
    _marker_is_valid,
    _operation_hash,
    reconciliation_digest,
    validate_closed_accounting,
)


def row_sha256(row: db.BudgetLedger | db.InferenceRequestRecord) -> str:
    """Hash every mapped column, matching private UTC-normalized snapshot encoding."""
    return reconciliation_digest(
        {column.name: getattr(row, column.name) for column in row.__table__.columns})


def _prepare(root, rows, request: ClosureRequest):
    state = deepcopy(root.state)
    try:
        keys = _check_bounds(state)
    except (KeyError, TypeError) as error:
        raise ValueError("Root accounting bounds missing or invalid") from error
    deadline = state.get("deadline_at")
    try:
        expiry = datetime.fromisoformat(deadline)
        if expiry.tzinfo is None or expiry.timestamp() > datetime.now(UTC).timestamp():
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("An expired timezone-aware root deadline is required") from None
    operation = state.get("operations", {}).get(request.operation_id)
    if not operation or operation.get("broker_owned") is not True or operation.get("broker_revoked") is not True:
        raise ValueError("Revoked broker operation required")
    if operation.get("broker_overrun"):
        raise ValueError("Known provider overrun requires separate reconciliation")
    run = operation.get("broker_binding", {}).get("run_id")
    if (not run or operation.get("run_id") != run
            or run not in state.get("broker_revoked_runs", [])):
        raise ValueError("Persisted run revocation and exact binding required")
    if {row.request_id for row in rows} != set(request.expected_request_sha256):
        raise ValueError("All operation request identities must match")
    unknown = []
    for row in rows:
        if row_sha256(row) != request.expected_request_sha256[row.request_id]:
            raise ValueError("Request row changed")
        _dimensions(row.allocation, set(budgets.FIELDS))
        if row.allocation["requests"] != 1:
            raise ValueError("Invalid request allocation")
        if row.root_id != request.root_id or row.operation_id != request.operation_id:
            raise ValueError("Foreign request")
        binding = row.request.get("binding", {})
        if (binding.get("root_id") != request.root_id or binding.get("operation_id") != request.operation_id
                or binding.get("run_id") != run or binding != operation["broker_binding"]):
            raise ValueError("Request binding differs from revoked operation")
        if row.overrun:
            raise ValueError("Known request overrun requires separate reconciliation")
        if row.state not in {"completed", "failed_before_dispatch", "completion_unknown"}:
            raise ValueError("All operation requests must be terminal")
        if row.state == "completion_unknown":
            if row.result is not None:
                raise ValueError("Unknown result must remain absent")
            unknown.append(row.request_id)
    if sorted(unknown) != request.unknown_request_ids:
        raise ValueError("Unknown request allowlist differs")
    reserved = operation.get("reserved")
    _dimensions(reserved, keys)
    for other in state["operations"].values():
        _dimensions(other.get("reserved"), keys)
    allocated = operation.get("broker_allocated")
    _dimensions(allocated, set(budgets.FIELDS))
    if any(math.fsum(row.allocation[key] for row in rows) > allocated[key] for key in budgets.FIELDS):
        raise ValueError("Request allocations exceed recorded operation allocation")
    if any(allocated[key] > reserved[key] for key in budgets.FIELDS):
        raise ValueError("Allocation exceeds reservation")
    audit = request.model_dump(mode="json")
    marker = operation.get("unknown_reconciliation")
    if marker is not None:
        if (not _marker_is_valid(operation) or marker["authorization"] != audit
                or root.revision < request.expected_root_revision + 1):
            raise ValueError("Reconciliation evidence or closed root changed")
        validate_closed_accounting(state)
        return state, marker, "already_closed"
    if row_sha256(root) != request.expected_root_sha256 or root.revision != request.expected_root_revision:
        raise ValueError("Root snapshot changed")
    if operation.get("status") != "uncertain":
        raise ValueError("An uncertain operation is required")
    used = {key: math.fsum((state["used"][key], reserved[key])) for key in keys}
    held = {key: math.fsum(other["reserved"][key] for identity, other in state["operations"].items()
                          if identity != request.operation_id and other.get("status") not in
                          {"settled", "closed_unknown"}) for key in keys}
    if any(not math.isfinite(used[key]) or used[key] + held[key] > state["limits"][key] for key in keys):
        raise ValueError("Closure exceeds root envelope")
    state["used"] = used
    operation["status"] = "closed_unknown"
    marker = {"version": 1, "authorization": audit, "charged": deepcopy(reserved),
              "accounting_basis": "full_reserved_envelope_estimate",
              "closed_operation_sha256": _operation_hash(operation)}
    operation["unknown_reconciliation"] = marker
    validate_closed_accounting(state)
    return state, marker, "planned"


def _projection(request, marker, status):
    return {"status": status, "root_id": request.root_id, "operation_id": request.operation_id,
            "unknown_request_count": len(request.unknown_request_ids),
            "charged": deepcopy(marker["charged"]), "accounting_basis": marker["accounting_basis"],
            "authorization_sha256": reconciliation_digest(marker["authorization"]),
            "request_tombstones_unchanged": True}


async def _read(session, request):
    root = await session.get(db.BudgetLedger, request.root_id)
    if root is None:
        raise ValueError("Root missing")
    rows = (await session.execute(select(db.InferenceRequestRecord).where(
        db.InferenceRequestRecord.root_id == request.root_id,
        db.InferenceRequestRecord.operation_id == request.operation_id))).scalars().all()
    return root, rows


async def plan_closure(request: ClosureRequest) -> dict:
    """SELECT-only dry run; returns no payload, credential, result or lease material."""
    async with db.session() as session:
        root, rows = await _read(session, request)
        _, marker, status = _prepare(root, rows, request)
        return _projection(request, marker, status)


async def close_unknown(request: ClosureRequest) -> dict:
    """One root CAS transaction, with unchanged permanent request fences."""
    async with db.session() as session:
        root, rows = await _read(session, request)
        state, marker, status = _prepare(root, rows, request)
        if status == "already_closed":
            return _projection(request, marker, status)
        won = await session.execute(update(db.BudgetLedger).where(
            db.BudgetLedger.root_id == request.root_id,
            db.BudgetLedger.revision == request.expected_root_revision,
        ).values(state=state, revision=root.revision + 1))
        if won.rowcount != 1:
            await session.rollback()
            raise ValueError("Root changed during closure; replan explicitly")
        await session.commit()
        return _projection(request, marker, "applied")


def is_conservatively_closed(root: db.BudgetLedger | None, row: db.InferenceRequestRecord) -> bool:
    """Fail-closed observation of an audited closure; does not imply known completion."""
    try:
        if (root is None or row.state != "completion_unknown" or row.result is not None
                or row.root_id != root.root_id or row.overrun):
            return False
        operation = root.state["operations"][row.operation_id]
        marker = operation["unknown_reconciliation"]
        request = ClosureRequest.model_validate(marker["authorization"])
        deadline = datetime.fromisoformat(root.state["deadline_at"])
        if deadline.tzinfo is None or deadline.timestamp() > datetime.now(UTC).timestamp():
            return False
        if request.root_id != root.root_id:
            return False
        validate_closed_accounting(root.state)
        return (_marker_is_valid(operation) and operation["broker_owned"] is True
                and operation["broker_revoked"] is True and request.root_id == row.root_id
                and request.operation_id == row.operation_id and row.request_id in request.unknown_request_ids
                and row_sha256(row) == request.expected_request_sha256[row.request_id]
                and root.revision >= request.expected_root_revision + 1
                and row.request["binding"] == operation["broker_binding"]
                and row.request["binding"]["root_id"] == root.root_id
                and row.request["binding"]["operation_id"] == row.operation_id
                and row.request["binding"]["run_id"] == operation["run_id"]
                and operation["run_id"] == operation["broker_binding"]["run_id"]
                and operation["run_id"] in root.state["broker_revoked_runs"])
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return False
