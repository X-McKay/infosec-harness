import asyncio

import pytest
from pydantic_ai.exceptions import UsageLimitExceeded

from infosec_harness.persistence import budgets, db


async def test_reservation_is_durable_idempotent_and_concurrent():
    await db.create_all()
    async with db.session() as session:
        session.add(db.BudgetLedger(root_id="budget-test", state=budgets.initial_state(
            {"tokens": 100, "requests": 10, "cost_usd": 1})))
        await session.commit()
    demand = {"tokens": 60, "requests": 3, "cost_usd": .3}
    results = await asyncio.gather(*(budgets.reserve("budget-test", f"call-{i}", demand, "agent")
                                    for i in range(2)), return_exceptions=True)
    assert sum(isinstance(r, UsageLimitExceeded) for r in results) == 1
    winner = next(i for i, r in enumerate(results) if not isinstance(r, BaseException))
    op = f"call-{winner}"
    assert await budgets.reserve("budget-test", op, demand, "agent") == results[winner]
    await budgets.settle("budget-test", op, {"tokens": 20, "requests": 1, "cost_usd": .1}, {"ok": True})
    await budgets.settle("budget-test", op, {"tokens": 20, "requests": 1, "cost_usd": .1}, {"ok": True})
    assert (await budgets.reserve("budget-test", "next", demand, "agent"))["status"] == "reserved"
    await budgets.settle("budget-test", "next", None, {"failure": "timeout"})
    with pytest.raises(UsageLimitExceeded):
        await budgets.reserve("budget-test", "after-unknown", demand, "agent")
    async with db.session() as session:
        ledger = await session.get(db.BudgetLedger, "budget-test")
        assert ledger.state["used"]["tokens"] == 20
        assert ledger.state["operations"]["next"]["status"] == "uncertain"


@pytest.mark.parametrize("value", [-1, float("nan"), float("inf")])
async def test_non_finite_or_negative_budget_values_fail_before_storage(value):
    invalid = {"requests": 1, "tokens": value, "cost_usd": 0}
    with pytest.raises(ValueError, match="finite non-negative"):
        budgets.initial_state(invalid)
    with pytest.raises(ValueError, match="finite non-negative"):
        await budgets.reserve("nonexistent", "operation", invalid, "agent")
    with pytest.raises(ValueError, match="finite non-negative"):
        await budgets.settle("nonexistent", "operation", invalid, {})


@pytest.mark.parametrize(
    ("root", "parent", "fallback_patch", "expected"),
    [
        ("batch:new-server", "batch:parent", True, "new-server"),
        (None, "batch:old-server", True, "old-server"),
        (None, "batch:old-server", False, None),
        (None, "standalone", True, None),
    ],
)
async def test_temporal_root_budget_old_server_and_replay(
    monkeypatch, root, parent, fallback_patch, expected,
):
    """Older servers must account child calls without changing recorded histories."""
    from types import SimpleNamespace

    from infosec_harness.workflows import accounting

    info = SimpleNamespace(
        workflow_id="triage:fingerprint:batch:old-server",
        root=SimpleNamespace(workflow_id=root) if root else None,
        parent=SimpleNamespace(workflow_id=parent),
    )
    monkeypatch.setattr(accounting.workflow, "info", lambda: info)
    monkeypatch.setattr(accounting.workflow, "patched", lambda name:
                        fallback_patch if name == "root-budget-parent-v1" else True)
    requests = []

    async def execute(activity, args, **kwargs):
        requests.append(args)
        return {"status": "reserved"}

    monkeypatch.setattr(accounting.workflow, "execute_activity", execute)
    config = SimpleNamespace(
        agent_name="context",
        budget=SimpleNamespace(effective=SimpleNamespace(
            max_requests=1, max_input_tokens=100, max_output_tokens=20, max_cost_usd=1)),
        model=SimpleNamespace(transport_retries=0, pricing_status="known_zero", mode="stub"),
    )
    result = await accounting.RootAccounting().reserve(config)
    if expected is None:
        assert result is None
        assert requests == []
    else:
        assert result[0] == expected
        assert requests[0]["root_id"] == expected
        assert requests[0]["requested"]["tokens"] > 0
