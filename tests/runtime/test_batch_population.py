"""Mixed batches must not leak unrelated populations through aggregate counters."""
import httpx
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


@pytest.fixture
async def mixed_batches(tmp_path, monkeypatch):
    from infosec_harness.api.app import app
    from infosec_harness.persistence import db

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'batch-population.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(db.Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(db, "session", sessions)
    async with sessions() as session:
        session.add_all([
            db.Batch(id="mixed", label="mixed populations", finding_count=6),
            db.Batch(id="demo-only", finding_count=1),
            db.Batch(id="empty", finding_count=0),
            db.BudgetLedger(root_id="mixed", state={"scope": "shared batch budget"}),
        ])
        values = [
            ("op-complete", "mixed", {"population": "operational"}, "complete", "inconclusive"),
            ("op-pending", "mixed", {"population": "operational"}, "pending", None),
            ("demo-failed", "mixed", {"population": "demo"}, "failed", "potentially_exploitable"),
            ("demo-complete", "mixed", {"population": "demo"}, "complete", "likely_not_exploitable"),
            ("legacy-complete", "mixed", None, "complete", "inconclusive"),
            ("legacy-unset", "mixed", {}, "needs_info", None),
            ("demo-only-run", "demo-only", {"population": "demo"}, "complete", "inconclusive"),
        ]
        session.add_all(db.TriageRun(id=identity, batch_id=batch, fingerprint=identity,
                                   repo_url="/unused", revision="test", telemetry=telemetry,
                                   status=status, verdict=verdict)
                        for identity, batch, telemetry, status, verdict in values)
        await session.commit()
    # ASGITransport deliberately skips lifespan: no worker or reconciliation is started.
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            yield client
    finally:
        await engine.dispose()


@pytest.mark.parametrize("population, states, verdicts", [
    ("operational", {"complete": 1, "pending": 1}, {"inconclusive": 1}),
    ("demo", {"complete": 1, "failed": 1}, {"likely_not_exploitable": 1, "potentially_exploitable": 1}),
])
async def test_selected_counts_include_only_matching_runs(mixed_batches, population, states, verdicts):
    response = await mixed_batches.get("/api/batches", params={"population": population})
    assert response.status_code == 200
    listed = {row["id"]: row for row in response.json()}
    assert listed["mixed"]["finding_count"] == 2
    assert "empty" not in listed
    assert ("demo-only" in listed) == (population == "demo")
    response = await mixed_batches.get("/api/batches/mixed", params={"population": population})
    assert response.status_code == 200
    detail = response.json()
    assert detail["finding_count"] == sum(states.values()) == 2
    assert detail["status_counts"] == states
    assert detail["verdict_counts"] == verdicts
    assert detail["budget"] == {"scope": "shared batch budget"}


async def test_unscoped_compatibility_preserves_whole_batch_counts(mixed_batches):
    listed = {row["id"]: row for row in (await mixed_batches.get("/api/batches")).json()}
    assert listed["mixed"]["finding_count"] == 6
    assert listed["empty"]["finding_count"] == 0
    detail = (await mixed_batches.get("/api/batches/mixed")).json()
    assert detail["finding_count"] == 6
    assert detail["status_counts"] == {"complete": 3, "failed": 1, "needs_info": 1, "pending": 1}
    assert detail["verdict_counts"] == {"inconclusive": 2, "likely_not_exploitable": 1,
                                        "potentially_exploitable": 1}


async def test_runs_without_an_accepted_population_belong_to_none(mixed_batches):
    """Regression: telemetry without a population formed a "legacy" population; there is none."""
    assert (await mixed_batches.get("/api/batches", params={"population": "legacy"})).status_code == 422
    counted = 0
    for population in ("operational", "demo"):
        detail = (await mixed_batches.get("/api/batches/mixed",
                                          params={"population": population})).json()
        counted += detail["finding_count"]
    assert counted == 4  # the two runs without a population are in neither


@pytest.mark.parametrize("batch", ["demo-only", "empty", "missing"])
async def test_nonmatching_batch_is_not_exposed(mixed_batches, batch):
    response = await mixed_batches.get(f"/api/batches/{batch}", params={"population": "operational"})
    assert response.status_code == 404
