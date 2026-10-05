
import pytest

from infosec_harness.domain.models import FindingInput
from infosec_harness.persistence import db, lifecycle, store
from infosec_harness.persistence.metrics import aggregate_metrics, distribution


def test_distribution_preserves_missing_values_and_tails():
    result = distribution([0, 2, 8, None, float("nan")])
    assert result.mean == pytest.approx(10 / 3)
    assert result.p50 == 2 and result.p95 == 8
    assert result.coverage == .6
    assert sum(b.count for b in result.bins) == 3
    assert distribution([]).mean is None
    assert distribution([None]).coverage == 0


async def test_acceptance_events_and_unknown_metrics_are_idempotent():
    await db.create_all()
    findings = [FindingInput(title=f"Finding {i}", repo_url="/repo", file_path=f"a{i}.py")
                for i in range(205)]
    await lifecycle.accept_batch("metric-many", findings + findings[:1], "many", None,
                                 agent_config_digests={})
    await lifecycle.accept_batch("metric-many", findings, "many", None, agent_config_digests={})
    summary = await store.batch_summary("metric-many")
    assert summary["finding_count"] == 205
    rows = await store.list_runs(batch_id="metric-many", limit=300)
    assert len(rows) == 205
    fp = rows[0]["fingerprint"]
    await lifecycle.record_progress("metric-many", fp, "preparing", "preparing")
    await lifecycle.record_progress("metric-many", fp, "preparing", "preparing")
    detail = await store.get_run(rows[0]["id"])
    assert len(detail["events"]) == 2
    async with db.session() as session:
        run = await session.get(db.TriageRun, rows[0]["id"])
        run.telemetry = {**run.telemetry, "cost_usd": 2.0, "total_tokens": 100, "wall_time_s": 10.0}
        run.status = "failed"
        await session.commit()
    metrics = await aggregate_metrics(batch_id="metric-many", population="demo")
    assert metrics.total_runs == 205
    assert metrics.cost_usd.mean == 2.0
    assert metrics.cost_usd.coverage == pytest.approx(1 / 205)
    assert metrics.status_counts["failed"] == 1
    assert metrics.tokens.mean == 100
    await lifecycle.finish_pending("metric-many", "cancelled", "Requested")
    metrics = await aggregate_metrics(batch_id="metric-many", population="demo")
    assert metrics.status_counts == {"failed": 1, "cancelled": 204}


async def test_page_counts_do_not_depend_on_limit():
    from httpx import ASGITransport, AsyncClient

    from infosec_harness.api.app import app
    await db.create_all()
    findings = [FindingInput(title=f"Page {i}", repo_url="/page", file_path=f"p{i}.py") for i in range(3)]
    await lifecycle.accept_batch("page-only", findings, "page", None, agent_config_digests={})
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        result = (await client.get("/api/run-page", params={"batch_id": "page-only", "limit": 2})).json()
        assert result["total"] == 3
        assert len(result["items"]) == 2
        assert (await client.get("/api/run-page", params={"limit": -1})).status_code == 422


async def test_concurrent_progress_delivery_preserves_terminal_status():
    import asyncio

    await db.create_all()
    finding = FindingInput(title="Event race", repo_url="/race", file_path="a.py")
    await lifecycle.accept_batch("race", [finding], "race", None, agent_config_digests={})
    row = (await store.list_runs(batch_id="race"))[0]
    await asyncio.gather(*(lifecycle.record_progress("race", row["fingerprint"], "preparing", "same")
                           for _ in range(3)))
    await lifecycle.finish_pending("race", "cancelled", "cancel request")
    await lifecycle.record_progress("race", row["fingerprint"], "assessing", "late")
    result = await store.get_run(row["id"])
    assert result["status"] == result["telemetry"]["phase"] == "cancelled"
    assert len([e for e in result["events"] if e["id"].endswith(":same")]) == 1


async def test_terminal_progress_recovers_after_concurrent_earlier_transition(monkeypatch):
    """Both deliveries read pending; the earlier phase commits before the terminal CAS."""
    import asyncio

    await db.create_all()
    finding = FindingInput(title="Ordered event race", repo_url="/race", file_path="a.py")
    await lifecycle.accept_batch("ordered-race", [finding], "race", None, agent_config_digests={})
    row = (await store.list_runs(batch_id="ordered-race"))[0]

    real_session = db.session
    both_loaded = asyncio.Barrier(2)
    earlier_committed = asyncio.Event()

    class CoordinatedSession:
        def __init__(self):
            self.inner = real_session()

        async def __aenter__(self):
            await self.inner.__aenter__()
            return self

        async def __aexit__(self, *args):
            return await self.inner.__aexit__(*args)

        def __getattr__(self, name):
            return getattr(self.inner, name)

        async def get(self, model, identity):
            value = await self.inner.get(model, identity)
            if model is db.TriageRun:
                await both_loaded.wait()
            return value

        async def execute(self, statement, *args, **kwargs):
            if asyncio.current_task().get_name() == "terminal-progress":
                await earlier_committed.wait()
            return await self.inner.execute(statement, *args, **kwargs)

        async def commit(self):
            await self.inner.commit()
            if asyncio.current_task().get_name() == "earlier-progress":
                earlier_committed.set()

    monkeypatch.setattr(lifecycle.db, "session", CoordinatedSession)
    earlier = asyncio.create_task(
        lifecycle.record_progress("ordered-race", row["fingerprint"], "assessing", "assessing"),
        name="earlier-progress",
    )
    terminal = asyncio.create_task(
        lifecycle.record_progress("ordered-race", row["fingerprint"], "cancelled", "cancelled"),
        name="terminal-progress",
    )
    await asyncio.gather(earlier, terminal)
    monkeypatch.setattr(lifecycle.db, "session", real_session)

    result = await store.get_run(row["id"])
    assert result["status"] == result["telemetry"]["phase"] == "cancelled"
    assert {event["phase"] for event in result["events"]} >= {"assessing", "cancelled"}


@pytest.mark.parametrize("first", ["cancelled", "failed"])
async def test_first_terminal_batch_status_wins(first):
    await db.create_all()
    await lifecycle.accept_batch(f"first-terminal-{first}", [], "terminal", None,
                                 agent_config_digests={})
    await store.finish_batch(f"first-terminal-{first}", first)
    await store.finish_batch(f"first-terminal-{first}", "complete")
    await store.finish_batch(f"first-terminal-{first}", "failed" if first == "cancelled" else "cancelled")

    summary = await store.batch_summary(f"first-terminal-{first}")
    assert summary["status"] == first


async def test_missing_outputs_cannot_be_marked_complete():
    await db.create_all()
    finding = FindingInput(title="Missing output", repo_url="/missing", file_path="a.py")
    await lifecycle.accept_batch("missing-output", [finding], "missing", None, agent_config_digests={})
    await lifecycle.finish_pending("missing-output", "complete", "")
    summary = await store.batch_summary("missing-output")
    assert summary["status"] == "failed"
    assert summary["status_counts"] == {"failed": 1}


async def test_histogram_drill_down_uses_matching_population_and_bin_edges():
    from httpx import ASGITransport, AsyncClient

    from infosec_harness.api.app import app

    await db.create_all()
    findings = [FindingInput(title=f"Bin {i}", repo_url="/bins", file_path=f"{i}.py") for i in range(4)]
    await lifecycle.accept_batch("bins", findings, "bins", None, agent_config_digests={})
    rows = await store.list_runs(batch_id="bins")
    async with db.session() as session:
        for row, value in zip(rows, [0, 10, 20, None], strict=True):
            run = await session.get(db.TriageRun, row["id"])
            run.telemetry = {**run.telemetry, "total_tokens": value}
        await session.commit()
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        params = {"batch_id": "bins", "population": "demo", "metric": "total_tokens", "lower": 10, "upper": 20}
        assert (await client.get("/api/run-page", params=params)).json()["total"] == 1
        assert (await client.get("/api/run-page", params={**params, "upper_inclusive": True})).json()["total"] == 2
        assert (await client.get("/api/run-page", params={**params, "population": "operational"})).json()["total"] == 0
        assert (await client.get("/api/run-page", params={**params, "lower": "nan"})).status_code == 422


@pytest.mark.parametrize("terminal", ["complete", "failed", "cancelled"])
async def test_cancellation_cannot_resurrect_a_concurrently_finished_batch(monkeypatch, terminal):
    """Completion wins between cancellation's initial access and its status write."""
    from sqlalchemy import update

    await db.create_all()
    batch_id = f"cancel-after-{terminal}"
    await lifecycle.accept_batch(batch_id, [], "race", None, agent_config_digests={})
    real_session = db.session

    class CompletingSession:
        def __init__(self):
            self.inner = real_session()
            self.completed = False

        async def __aenter__(self):
            await self.inner.__aenter__()
            return self

        async def __aexit__(self, *args):
            return await self.inner.__aexit__(*args)

        def __getattr__(self, name):
            return getattr(self.inner, name)

        async def finish(self):
            if not self.completed:
                self.completed = True
                async with real_session() as other:
                    await other.execute(update(db.Batch).where(db.Batch.id == batch_id)
                                        .values(status=terminal))
                    await other.commit()

        async def get(self, *args, **kwargs):
            stale = await self.inner.get(*args, **kwargs)
            await self.finish()
            return stale

        async def execute(self, *args, **kwargs):
            await self.finish()
            return await self.inner.execute(*args, **kwargs)

    monkeypatch.setattr(db, "session", CompletingSession)
    assert await lifecycle.request_cancellation(batch_id) == terminal
    async with real_session() as session:
        assert (await session.get(db.Batch, batch_id)).status == terminal


async def test_cancellation_is_idempotent_and_rejects_unknown_batches():
    await db.create_all()
    await lifecycle.accept_batch("cancel-twice", [], "cancel", None, agent_config_digests={})
    assert await lifecycle.request_cancellation("cancel-twice") == "cancellation_requested"
    assert await lifecycle.request_cancellation("cancel-twice") == "cancellation_requested"
    with pytest.raises(KeyError):
        await lifecycle.request_cancellation("missing-batch")
