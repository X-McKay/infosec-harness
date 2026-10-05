"""Conservative operator closure preserves dispatch tombstones and possible spend."""
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm.attributes import flag_modified

from infosec_harness.persistence import db
from infosec_harness.persistence import reconciliation as rec


@pytest.fixture
async def closure():
    await db.create_all()
    identity = uuid4().hex
    binding = {"root_id": identity, "operation_id": "op", "run_id": "run", "agent": "intake"}
    reserve = {"requests": 4, "tokens": 100, "cost_usd": 2}
    state = {"limits": {"requests": 10, "tokens": 300, "cost_usd": 10},
             "used": {"requests": 1, "tokens": 20, "cost_usd": 1},
             "deadline_at": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
             "agent_config_digests": {"other": "config-other"},
             "broker_revoked_runs": ["run"], "operations": {"op": {
                 "status": "uncertain", "broker_owned": True, "broker_revoked": True,
                 "run_id": "run", "broker_binding": binding, "reserved": reserve,
                 "broker_allocated": {"requests": 2, "tokens": 50, "cost_usd": 1}}}}
    async with db.session() as session:
        root = db.BudgetLedger(root_id=identity, state=state, revision=0)
        session.add(root)
        await session.flush()
        for suffix, status in (("a", "completion_unknown"), ("b", "completed")):
            session.add(db.InferenceRequestRecord(request_id=identity + suffix, root_id=identity,
                operation_id="op", lease_id="deleted", state=status, revision=3,
                request={"binding": binding, "payload": {"sensitive": "must not project"}},
                allocation={"requests": 1, "tokens": 25, "cost_usd": .5}, fence="permanent",
                result=None if suffix == "a" else {"retained": True}))
        await session.commit()
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, identity)
        rows = (await session.execute(select(db.InferenceRequestRecord).where(
            db.InferenceRequestRecord.root_id == identity))).scalars().all()
        request = rec.ClosureRequest(root_id=identity, operation_id="op",
            expected_root_revision=root.revision, expected_root_sha256=rec.row_sha256(root),
            expected_request_sha256={r.request_id: rec.row_sha256(r) for r in rows},
            unknown_request_ids=[identity + "a"], source_commit="a" * 40,
            evidence_sha256={"sealed_snapshot": "b" * 64}, reason="loss_accepted")
    yield request
    await db._engine().dispose()


async def rows_for(request):
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, request.root_id)
        rows = (await session.execute(select(db.InferenceRequestRecord).where(
            db.InferenceRequestRecord.root_id == request.root_id))).scalars().all()
        return root, rows


async def mutate(request, change):
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, request.root_id)
        state = deepcopy(root.state)
        change(state)
        root.state = state
        flag_modified(root, "state")
        await session.commit()
    root, _ = await rows_for(request)
    return request.model_copy(update={"expected_root_sha256": rec.row_sha256(root)})


async def test_dry_run_no_write_then_full_envelope_once_and_exact_tombstones(closure):
    before, rows = await rows_for(closure)
    row_hashes = {r.request_id: rec.row_sha256(r) for r in rows}
    plan = await rec.plan_closure(closure)
    assert plan["charged"] == {"requests": 4, "tokens": 100, "cost_usd": 2}
    assert "sensitive" not in str(plan) and "permanent" not in str(plan)
    assert rec.row_sha256((await rows_for(closure))[0]) == rec.row_sha256(before)
    assert (await rec.close_unknown(closure))["status"] == "applied"
    root, rows = await rows_for(closure)
    assert root.state["used"] == {"requests": 5, "tokens": 120, "cost_usd": 3}
    assert root.state["operations"]["op"]["status"] == "closed_unknown"
    assert {r.request_id: rec.row_sha256(r) for r in rows} == row_hashes
    assert rec.is_conservatively_closed(root, next(r for r in rows if r.state == "completion_unknown"))
    assert (await rec.close_unknown(closure))["status"] == "already_closed"
    assert rec.row_sha256((await rows_for(closure))[0]) == rec.row_sha256(root)


@pytest.mark.parametrize("change", [
    lambda s: s["operations"]["op"].update(broker_revoked=False),
    lambda s: s.update(broker_revoked_runs=[]),
    lambda s: s.pop("deadline_at"),
    lambda s: s.update(deadline_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat()),
    lambda s: s["operations"]["op"]["reserved"].update(tokens=True),
    lambda s: s["operations"]["op"]["reserved"].update(tokens=-1),
    lambda s: s["operations"]["op"]["reserved"].update(tokens=float("inf")),
    lambda s: s["operations"]["op"]["reserved"].pop("tokens"),
    lambda s: s["operations"]["op"]["broker_allocated"].update(tokens=101),
    lambda s: s["used"].update(tokens=250),
])
async def test_invalid_bounds_revocation_deadline_and_root_invariants_reject(closure, change):
    with pytest.raises((ValueError, OverflowError)):
        request = await mutate(closure, change)
        await rec.close_unknown(request)


async def test_unknown_allowlist_and_whole_operation_rows_are_exact(closure):
    with pytest.raises(ValueError):
        await rec.close_unknown(closure.model_copy(update={"expected_request_sha256": {
            closure.unknown_request_ids[0]: closure.expected_request_sha256[closure.unknown_request_ids[0]]}}))
    async with db.session() as session:
        row = await session.get(db.InferenceRequestRecord, closure.unknown_request_ids[0])
        row.state = "dispatch_intent"
        await session.commit()
    with pytest.raises(ValueError, match="row changed"):
        await rec.close_unknown(closure)


async def test_conflicting_audit_and_root_drift_never_double_charge(closure):
    await rec.close_unknown(closure)
    changed = closure.model_copy(update={"evidence_sha256": {"replacement": "c" * 64}})
    with pytest.raises(ValueError):
        await rec.close_unknown(changed)
    await mutate(closure, lambda s: s["used"].update(tokens=99))
    with pytest.raises(ValueError):
        await rec.close_unknown(closure)
    root, rows = await rows_for(closure)
    assert not rec.is_conservatively_closed(root, next(r for r in rows if r.state == "completion_unknown"))


def test_strict_operator_authorization_rejects_bool_revision_and_unknown_reason():
    with pytest.raises(ValueError):
        rec.ClosureRequest(root_id="r", operation_id="o", expected_root_sha256="a" * 64,
            expected_root_revision=True, expected_request_sha256={"r": "b" * 64},
            unknown_request_ids=["r"], source_commit="c" * 40,
            evidence_sha256={"snapshot": "d" * 64}, reason="loss_accepted")


async def test_multiple_closed_operations_keep_first_audit_valid(closure):
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, closure.root_id)
        state = deepcopy(root.state)
        second = deepcopy(state["operations"]["op"])
        second["broker_binding"]["operation_id"] = "second"
        state["operations"]["second"] = second
        root.state = state
        session.add(db.InferenceRequestRecord(request_id=closure.root_id + "second", root_id=closure.root_id,
            operation_id="second", lease_id="deleted", state="completion_unknown", revision=1,
            request={"binding": second["broker_binding"]}, allocation={"requests": 1, "tokens": 25, "cost_usd": .5},
            result=None, fence="never-resend"))
        await session.commit()
    root, _ = await rows_for(closure)
    first = closure.model_copy(update={"expected_root_sha256": rec.row_sha256(root)})
    await rec.close_unknown(first)
    root, rows = await rows_for(closure)
    second_row = next(r for r in rows if r.operation_id == "second")
    second_request = closure.model_copy(update={"operation_id": "second", "expected_root_revision": root.revision,
        "expected_root_sha256": rec.row_sha256(root), "unknown_request_ids": [second_row.request_id],
        "expected_request_sha256": {second_row.request_id: rec.row_sha256(second_row)}})
    await rec.close_unknown(second_request)
    root, rows = await rows_for(closure)
    assert root.state["used"] == {"requests": 9, "tokens": 220, "cost_usd": 5}
    assert all(rec.is_conservatively_closed(root, r) for r in rows if r.state == "completion_unknown")
    assert (await rec.close_unknown(first))["status"] == "already_closed"


async def test_competing_closures_charge_once_and_keep_dispatch_fenced(closure):
    import asyncio

    from infosec_harness.inference import ledger
    from infosec_harness.inference.protocol import BrokerError

    results = await asyncio.gather(rec.close_unknown(closure), rec.close_unknown(closure), return_exceptions=True)
    assert sum(isinstance(r, dict) and r["status"] == "applied" for r in results) == 1
    assert all(isinstance(r, (ValueError, dict)) for r in results)
    root, _ = await rows_for(closure)
    assert root.state["used"]["tokens"] == 120
    with pytest.raises(BrokerError) as caught:
        await ledger.DurableLedger().claim(closure.unknown_request_ids[0], lease_id="deleted")
    assert caught.value.code == "completion_unknown"


async def test_bare_closed_status_or_malformed_marker_never_counts_as_reconciled(closure):
    root, rows = await rows_for(closure)
    unknown = next(r for r in rows if r.state == "completion_unknown")
    assert not rec.is_conservatively_closed(None, unknown)
    root.state["operations"]["op"]["status"] = "closed_unknown"
    assert not rec.is_conservatively_closed(root, unknown)
    root.state["operations"]["op"]["unknown_reconciliation"] = {"authorization": {"reason": "loss_accepted"}}
    assert not rec.is_conservatively_closed(root, unknown)


async def test_replanned_nonterminal_or_unknown_result_still_rejected(closure):
    async with db.session() as session:
        row = await session.get(db.InferenceRequestRecord, closure.unknown_request_ids[0])
        row.result = {"fabricated": True}
        await session.commit()
    _, rows = await rows_for(closure)
    request = closure.model_copy(update={"expected_request_sha256": {r.request_id: rec.row_sha256(r) for r in rows}})
    with pytest.raises(ValueError, match="Unknown result"):
        await rec.close_unknown(request)


@pytest.mark.parametrize("change", [
    lambda m: m.update(version=True),
    lambda m: m.update(extra="unreviewed"),
    lambda m: m.pop("accounting_basis"),
    lambda m: m["authorization"].update(reason="usage_observed"),
])
async def test_corrupt_audit_rejects_repeat_and_api_observation(closure, change):
    await rec.close_unknown(closure)
    await mutate(closure, lambda s: change(s["operations"]["op"]["unknown_reconciliation"]))
    with pytest.raises((ValueError, KeyError)):
        await rec.close_unknown(closure)
    root, rows = await rows_for(closure)
    assert not rec.is_conservatively_closed(root, next(r for r in rows if r.state == "completion_unknown"))


async def test_renewed_deadline_or_foreign_root_never_promotes_unknown(closure):
    await rec.close_unknown(closure)
    root, rows = await rows_for(closure)
    unknown = next(r for r in rows if r.state == "completion_unknown")
    root.state["deadline_at"] = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    assert not rec.is_conservatively_closed(root, unknown)
    root.root_id = "foreign"
    assert not rec.is_conservatively_closed(root, unknown)


async def test_actual_closure_capacity_not_double_held_and_settle_cannot_rewrite(closure, monkeypatch):
    from infosec_harness.persistence import budgets

    await rec.close_unknown(closure)
    before, _ = await rows_for(closure)
    await budgets.settle(closure.root_id, "op", {"requests": 0, "tokens": 0, "cost_usd": 0},
                         {"worker": "cannot replace operator audit"})
    assert rec.row_sha256((await rows_for(closure))[0]) == rec.row_sha256(before)
    # Isolate capacity arithmetic; actual admission independently rejects the expired root.
    monkeypatch.setattr(budgets, "_remaining_time", lambda _: None)
    next_operation = await budgets.reserve(closure.root_id, "next",
        {"requests": 5, "tokens": 180, "cost_usd": 7}, "other", "config-other")
    assert next_operation["status"] == "reserved"


@pytest.mark.parametrize("change", [
    lambda s: s["operations"]["op"]["unknown_reconciliation"].update(version=True),
    lambda s: s["used"].update(tokens=0),
    lambda s: s["operations"]["op"].pop("unknown_reconciliation"),
])
async def test_scheduler_rejects_tampered_real_closure_accounting(closure, monkeypatch, change):
    from infosec_harness.persistence import budgets

    await rec.close_unknown(closure)
    await mutate(closure, change)
    monkeypatch.setattr(budgets, "_remaining_time", lambda _: None)
    with pytest.raises(ValueError):
        await budgets.reserve(closure.root_id, "next", {"requests": 1, "tokens": 1, "cost_usd": 0}, "other")


async def test_recomputed_operation_hash_cannot_rebind_unknown_to_foreign_run(closure):
    await rec.close_unknown(closure)
    root, rows = await rows_for(closure)
    unknown = next(r for r in rows if r.state == "completion_unknown")
    operation = root.state["operations"]["op"]
    operation["run_id"] = "foreign-revoked-run"
    operation["broker_binding"]["run_id"] = "foreign-revoked-run"
    root.state["broker_revoked_runs"].append("foreign-revoked-run")
    operation["unknown_reconciliation"]["closed_operation_sha256"] = rec._operation_hash(operation)
    assert not rec.is_conservatively_closed(root, unknown)


async def test_known_completed_overrun_is_not_erased_by_conservative_envelope(closure):
    async with db.session() as session:
        rows = (await session.execute(select(db.InferenceRequestRecord).where(
            db.InferenceRequestRecord.root_id == closure.root_id))).scalars().all()
        next(r for r in rows if r.state == "completed").overrun = {"tokens": 1}
        await session.commit()
    _, rows = await rows_for(closure)
    request = closure.model_copy(update={"expected_request_sha256": {r.request_id: rec.row_sha256(r) for r in rows}})
    with pytest.raises(ValueError, match="overrun"):
        await rec.close_unknown(request)


async def test_operation_overrun_rejects_plan_and_api_classification(closure):
    request = await mutate(closure, lambda s: s["operations"]["op"].update(broker_overrun={"tokens": 1}))
    with pytest.raises(ValueError, match="overrun"):
        await rec.plan_closure(request)
    # A later known overrun cannot be hidden by recomputing the immutable operation hash.
    async with db.session() as session:
        root = await session.get(db.BudgetLedger, closure.root_id)
        state = deepcopy(root.state)
        state["operations"]["op"].pop("broker_overrun")
        root.state = state
        await session.commit()
    root, _ = await rows_for(closure)
    request = closure.model_copy(update={"expected_root_sha256": rec.row_sha256(root)})
    await rec.close_unknown(request)
    root, rows = await rows_for(closure)
    operation = root.state["operations"]["op"]
    operation["broker_overrun"] = {"tokens": 1}
    operation["unknown_reconciliation"]["closed_operation_sha256"] = rec._operation_hash(operation)
    assert not rec.is_conservatively_closed(root, next(r for r in rows if r.state == "completion_unknown"))


@pytest.mark.parametrize("allocation", [
    {"requests": 1, "tokens": True, "cost_usd": 0},
    {"requests": 1, "tokens": -1, "cost_usd": 0},
    {"requests": 1, "tokens": 51, "cost_usd": 0},
    {"requests": 0, "tokens": 1, "cost_usd": 0},
])
async def test_full_row_hash_cannot_authorize_malformed_request_allocation(closure, allocation):
    async with db.session() as session:
        row = await session.get(db.InferenceRequestRecord, closure.unknown_request_ids[0])
        row.allocation = allocation
        await session.commit()
    _, rows = await rows_for(closure)
    request = closure.model_copy(update={"expected_request_sha256": {r.request_id: rec.row_sha256(r) for r in rows}})
    with pytest.raises(ValueError):
        await rec.plan_closure(request)
