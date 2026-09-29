"""Small compare-and-swap ledger for a single batch's concurrent agent invocations.

Reserve before execution; settle exactly once. An interrupted call retains its reservation
as an upper bound until it can be reconciled, rather than pretending it cost nothing.
"""
from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from math import isfinite
from typing import Any

from pydantic_ai.exceptions import UsageLimitExceeded
from sqlalchemy import update

from infosec_harness.persistence import db

FIELDS = ("requests", "tokens", "cost_usd")


def _validate_usage(values: dict[str, float]) -> None:
    if any(key not in values or not isfinite(values[key]) or values[key] < 0 for key in FIELDS):
        raise ValueError("Budget values must include finite non-negative requests, tokens, and cost_usd")


def initial_state(limits: dict[str, float]) -> dict:
    _validate_usage(limits)
    return {"version": 1, "limits": limits, "used": dict.fromkeys(FIELDS, 0), "operations": {}}


async def _mutate(root_id: str, change: Callable[[dict], dict]) -> dict | None:
    for _ in range(20):
        async with db.session() as session:
            ledger = await session.get(db.BudgetLedger, root_id)
            if ledger is None:
                return None  # Legacy workflows have no root accounting contract.
            state = deepcopy(ledger.state)
            result = change(state)
            updated = await session.execute(update(db.BudgetLedger).where(
                db.BudgetLedger.root_id == root_id, db.BudgetLedger.revision == ledger.revision
            ).values(state=state, revision=ledger.revision + 1))
            if updated.rowcount == 1:
                await session.commit()
                return result
            await session.rollback()
    raise RuntimeError("Root budget contention exceeded bounded retry count")


async def reserve(root_id: str, operation_id: str, requested: dict[str, float], agent: str) -> dict | None:
    _validate_usage(requested)

    def change(state: dict) -> dict:
        operations = state["operations"]
        if operation_id in operations:
            return operations[operation_id]
        held = {key: sum(o["reserved"][key] for o in operations.values()
                         if o["status"] != "settled") for key in FIELDS}
        remaining = {key: state["limits"][key] - state["used"][key] - held[key] for key in FIELDS}
        if any(requested[key] > remaining[key] for key in FIELDS):
            raise UsageLimitExceeded(f"Root budget cannot reserve invocation for {agent}; remaining={remaining}")
        operation = {"agent": agent, "status": "reserved", "reserved": requested}
        operations[operation_id] = operation
        return operation
    return await _mutate(root_id, change)


async def settle(root_id: str, operation_id: str, observed: dict[str, float] | None,
                 record: dict[str, Any]) -> dict | None:
    if observed is not None:
        _validate_usage(observed)

    def change(state: dict) -> dict:
        operation = state["operations"][operation_id]
        if operation["status"] == "settled":
            return operation
        operation["record"] = record
        if observed is None:
            operation["status"] = "uncertain"
        else:
            for key in FIELDS:
                if observed[key] < 0:
                    raise ValueError("Observed usage must be non-negative")
                state["used"][key] += observed[key]
            operation.update(status="settled", observed=observed)
        return operation
    return await _mutate(root_id, change)
