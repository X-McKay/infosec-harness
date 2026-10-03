"""Small compare-and-swap ledger for a single batch's concurrent agent invocations.

Reserve before execution; settle exactly once. An interrupted call retains its reservation
as an upper bound until it can be reconciled, rather than pretending it cost nothing.
"""
from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from math import isfinite
from typing import Any, Literal

from pydantic_ai.exceptions import UsageLimitExceeded
from sqlalchemy import update

from infosec_harness.persistence import db

FIELDS = ("requests", "tokens", "cost_usd")
EXTENDED_FIELDS = ("tool_calls", "agent_runs", "execution_seconds")


def _validate_usage(values: dict[str, float]) -> None:
    if (any(key not in values for key in FIELDS)
            or any(key not in (*FIELDS, *EXTENDED_FIELDS) or not isfinite(value) or value < 0
                   for key, value in values.items())):
        raise ValueError("Budget values must include finite non-negative requests, tokens, and cost_usd")


def initial_state(limits: dict[str, float], *, elapsed_seconds: float | None = None) -> dict:
    _validate_usage(limits)
    if any(key in limits for key in EXTENDED_FIELDS) and not all(key in limits for key in EXTENDED_FIELDS):
        raise ValueError("Extended root dimensions must be provided together")
    state = {"version": 2 if any(key in limits for key in EXTENDED_FIELDS) else 1,
             "limits": limits, "used": dict.fromkeys(limits, 0), "operations": {}}
    if elapsed_seconds is not None:
        if not isfinite(elapsed_seconds) or elapsed_seconds <= 0:
            raise ValueError("Elapsed budget must be finite and positive")
        now = datetime.now(UTC)
        state.update(started_at=now.isoformat(),
                     deadline_at=(now + timedelta(seconds=elapsed_seconds)).isoformat())
    return state


async def remaining_time(root_id: str) -> float | None:
    """Read the persisted acceptance-time deadline; restart never renews it."""
    async with db.session() as session:
        ledger = await session.get(db.BudgetLedger, root_id)
        deadline = ledger.state.get("deadline_at") if ledger else None
    return _remaining_time(deadline)


def _remaining_time(deadline: str | None) -> float | None:
    if deadline is None:
        return None
    remaining = (datetime.fromisoformat(deadline) - datetime.now(UTC)).total_seconds()
    if remaining <= 0:
        raise UsageLimitExceeded("Root elapsed-time budget exhausted")
    return remaining


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


async def reserve(root_id: str, operation_id: str, requested: dict[str, float], agent: str,
                  configuration_digest: str | None = None,
                  operation_kind: Literal["agent", "execution"] = "agent",
                  run_id: str | None = None, invocation_id: str | None = None) -> dict | None:
    _validate_usage(requested)
    if operation_kind not in {"agent", "execution"}:
        raise ValueError("Unknown budget operation kind")
    if operation_kind == "execution" and any(requested.get(key, 0) for key in
            ("requests", "tokens", "tool_calls", "agent_runs")):
        raise ValueError("Execution reservations cannot bypass agent configuration checks")

    def change(state: dict) -> dict:
        _remaining_time(state.get("deadline_at"))
        if run_id is not None and run_id in state.get("broker_revoked_runs", []):
            raise ValueError("Broker run admission has been revoked")
        accepted_configs = state.get("agent_config_digests")
        if accepted_configs is not None and operation_kind == "agent":
            accepted_config = accepted_configs.get(agent)
            if accepted_config is None or configuration_digest != accepted_config:
                raise ValueError(f"Worker configuration for {agent} differs from the accepted batch")
        fields = tuple(state["limits"])
        if any(key not in requested for key in fields):
            raise ValueError("Reservation omits a configured root budget dimension")
        demand = {key: requested[key] for key in fields}
        operations = state["operations"]
        if operation_id in operations:
            operation = operations[operation_id]
            if (operation["agent"] != agent or operation["reserved"] != demand
                    or operation.get("kind", "agent") != operation_kind
                    or (run_id is not None and operation.get("run_id") != run_id)
                    or (invocation_id is not None and operation.get("invocation_id") != invocation_id)):
                raise ValueError("Operation already reserved with different budget or agent")
            return operation
        held = {key: sum(o["reserved"].get(key, 0) for o in operations.values()
                         if o["status"] != "settled") for key in fields}
        remaining = {key: state["limits"][key] - state["used"][key] - held[key] for key in fields}
        if any(demand[key] > remaining[key] for key in fields):
            raise UsageLimitExceeded(f"Root budget cannot reserve invocation for {agent}; remaining={remaining}")
        operation = {"agent": agent, "kind": operation_kind, "status": "reserved", "reserved": demand}
        if run_id is not None or invocation_id is not None:
            if not run_id or not invocation_id:
                raise ValueError("Broker invocation ownership requires both run and invocation")
            operation.update(run_id=run_id, invocation_id=invocation_id)
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
        if operation.get("broker_owned"):
            # Only the controller can reconcile broker dispatches, including lost results.
            # Worker-observed usage cannot release possible spend from another attempt.
            operation["status"] = "uncertain"
            if observed is not None:
                operation["worker_observed"] = observed
        elif observed is None or any(key not in observed for key in state["limits"]):
            operation["status"] = "uncertain"
        else:
            for key in state["limits"]:
                if observed.get(key, 0) < 0:
                    raise ValueError("Observed usage must be non-negative")
                state["used"][key] += observed.get(key, 0)
            operation.update(status="settled", observed=observed)
            operation["overrun"] = {key: observed[key] - operation["reserved"].get(key, 0)
                for key in state["limits"]
                if observed[key] > operation["reserved"].get(key, 0)}
        return operation
    return await _mutate(root_id, change)
