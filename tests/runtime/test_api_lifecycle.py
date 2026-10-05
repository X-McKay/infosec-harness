"""Isolated startup reconciliation boundaries; no Temporal, broker, or provider calls."""

from __future__ import annotations

import asyncio
import json

import pytest
from sqlalchemy import null, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from infosec_harness.persistence import db, lifecycle
from infosec_harness.workflows import submission as runner


@pytest.fixture
async def lifecycle_database(tmp_path, monkeypatch):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'lifecycle-only.sqlite'}")
    async with engine.begin() as connection:
        await connection.run_sync(db.Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(db, "session", sessions)
    try:
        yield sessions
    finally:
        await engine.dispose()


async def seed_submission_states(sessions):
    rows = [
        ("accepted-operational", "accepted", {"token": "operational"}, "operational"),
        ("accepted-demo", "accepted", {"token": "demo"}, "demo"),
        ("accepted-empty", "accepted", {}, "operational"),
        ("accepted-no-payload", "accepted", None, "operational"),
        ("accepted-sql-null", "accepted", None, "operational"),
        ("accepted-scalar", "accepted", "invalid stored payload", "operational"),
        ("accepted-list", "accepted", [{"findings": []}], "demo"),
        ("cancel-with-payload", "cancellation_requested", {"token": "cancel"}, "operational"),
        ("cancel-no-payload", "cancellation_requested", None, "demo"),
    ]
    for population in ("demo", "operational"):
        for state in ("running", "complete", "failed", "cancelled"):
            rows.append((f"{population}-{state}", state, {"token": state}, population))
    async with sessions() as session:
        for identity, state, payload, population in rows:
            session.add(
                db.Batch(
                    id=identity,
                    status=state,
                    submission=null() if identity == "accepted-sql-null" else payload,
                    workflow_id=f"batch:{identity}",
                    finding_count=1,
                )
            )
            session.add(
                db.TriageRun(
                    id=identity,
                    batch_id=identity,
                    fingerprint=identity,
                    repo_url="/test/repo",
                    revision="test",
                    title=identity,
                    status="pending" if state == "accepted" else state,
                    telemetry={"population": population},
                )
            )
        await session.commit()
    return rows


async def test_pending_submissions_uses_exact_status_and_nonnull_payload(lifecycle_database):
    rows = await seed_submission_states(lifecycle_database)
    expected = {
        identity: payload
        for identity, state, payload, _ in rows
        if state == "accepted" and isinstance(payload, dict)
    }
    assert dict(await lifecycle.pending_submissions()) == expected
    assert "accepted-empty" in expected  # SQL nonnull is deliberately not truthiness.
    assert "accepted-no-payload" not in expected
    assert "accepted-sql-null" not in expected
    assert "accepted-scalar" not in expected
    assert "accepted-list" not in expected


async def test_reconcile_only_submission_candidates_never_resumes_unknown_holds(
    lifecycle_database, monkeypatch
):
    from infosec_harness.inference import controller, ledger
    from infosec_harness.workflows import worker

    rows = await seed_submission_states(lifecycle_database)
    held_state = {
        "operations": {"test-operation": {"status": "uncertain", "requests": 1}},
        "reserved": {"requests": 1, "tokens": 1200, "cost_usd": 0.25},
    }
    async with lifecycle_database() as session:
        session.add(db.BudgetLedger(root_id="held-root", revision=7, state=held_state))
        await session.flush()
        session.add(
            db.InferenceRequestRecord(
                request_id="old-unknown",
                root_id="held-root",
                operation_id="test-operation",
                lease_id="old-deleted-lease",
                state="completion_unknown",
                revision=4,
                # Retention-only sentinel metadata: reconciliation must not parse or replace it.
                request={"retained": "unchanged"},
                allocation={"requests": 1, "tokens": 1200, "cost_usd": 0.25},
                overrun=None,
                fence="retained-fence",
                result=None,
            )
        )
        await session.commit()

    async def retained_bytes():
        async with lifecycle_database() as session:
            request = await session.get(db.InferenceRequestRecord, "old-unknown")
            budget = await session.get(db.BudgetLedger, "held-root")
            fields = {
                column.name: getattr(request, column.name) for column in request.__table__.columns
            }
            return json.dumps(
                {"request": fields, "budget": {"revision": budget.revision, "state": budget.state}},
                sort_keys=True,
                default=str,
            )

    before = await retained_bytes()
    started, cancelled = [], []

    async def capture_start(identity, payload):
        started.append((identity, payload))

    async def capture_cancel(identity):
        cancelled.append(identity)

    async def forbidden(*args, **kwargs):
        pytest.fail("Submission reconciliation invoked a broker recovery or live connection")

    monkeypatch.setattr(runner, "start_accepted_batch", capture_start)
    monkeypatch.setattr(runner, "cancel_durable_batch", capture_cancel)
    monkeypatch.setattr(worker, "connect", forbidden)
    monkeypatch.setattr(controller.Controller, "recover", forbidden, raising=False)
    monkeypatch.setattr(controller.Controller, "infer", forbidden, raising=False)
    monkeypatch.setattr(controller.Controller, "revoke_run", forbidden, raising=False)
    monkeypatch.setattr(ledger, "recover", forbidden)
    await runner.reconcile_submissions()
    assert dict(started) == {
        identity: payload
        for identity, state, payload, _ in rows
        if state == "accepted" and isinstance(payload, dict)
    }
    assert set(cancelled) == {
        identity for identity, state, _, _ in rows if state == "cancellation_requested"
    }
    assert len(cancelled) == 2
    assert len(started) == 3
    assert before == await retained_bytes()
    assert all(
        not identity.endswith(("-complete", "-failed", "-cancelled", "-running"))
        for identity, _ in started
    )


async def test_quiescent_store_does_not_start_or_cancel_anything(lifecycle_database, monkeypatch):
    await seed_submission_states(lifecycle_database)
    async with lifecycle_database() as session:
        for row in (await session.scalars(select(db.Batch))).all():
            row.status = "complete"
        await session.commit()

    async def forbidden(*args, **kwargs):
        pytest.fail("Quiescent reconciliation issued a workflow action")

    monkeypatch.setattr(runner, "start_accepted_batch", forbidden)
    monkeypatch.setattr(runner, "cancel_durable_batch", forbidden)
    assert await lifecycle.pending_submissions() == []
    await runner.reconcile_submissions()


@pytest.mark.parametrize("blocked", [False, True])
async def test_lifespan_bootstraps_before_reconciliation_and_joins_task_on_exit(
    monkeypatch, blocked
):
    from infosec_harness import telemetry
    from infosec_harness.api.app import app, lifespan

    calls = []
    entered = asyncio.Event()
    reconciler_tasks = []
    interrupted = asyncio.Event()

    async def bootstrap():
        calls.append("bootstrap")

    async def reconcile():
        assert calls == ["telemetry:api", "bootstrap"]
        calls.append("reconcile")
        reconciler_tasks.append(asyncio.current_task())
        entered.set()
        if blocked:
            try:
                await asyncio.Event().wait()
            finally:
                interrupted.set()

    monkeypatch.setattr(
        telemetry, "configure", lambda component: calls.append(f"telemetry:{component}")
    )
    monkeypatch.setattr(db, "create_all", bootstrap)
    monkeypatch.setattr(runner, "reconcile_submissions", reconcile)
    async with lifespan(app):
        await asyncio.wait_for(entered.wait(), timeout=1)
        assert calls == ["telemetry:api", "bootstrap", "reconcile"]
        assert not reconciler_tasks[0].done()
    assert reconciler_tasks[0].done()
    assert reconciler_tasks[0].cancelled()
    if blocked:
        assert interrupted.is_set()
    # Yield twice: a detached/restarted reconcile task would surface here.
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert calls == ["telemetry:api", "bootstrap", "reconcile"]


async def test_failed_bootstrap_never_launches_reconciliation(monkeypatch):
    from infosec_harness import telemetry
    from infosec_harness.api.app import app, lifespan

    async def fail_bootstrap():
        raise RuntimeError("isolated bootstrap failure")

    async def forbidden():
        pytest.fail("Failed schema bootstrap launched submission reconciliation")

    monkeypatch.setattr(telemetry, "configure", lambda component: None)
    monkeypatch.setattr(db, "create_all", fail_bootstrap)
    monkeypatch.setattr(runner, "reconcile_submissions", forbidden)
    with pytest.raises(RuntimeError, match="isolated bootstrap failure"):
        async with lifespan(app):
            pytest.fail("Failed bootstrap served the application")
    await asyncio.sleep(0)
