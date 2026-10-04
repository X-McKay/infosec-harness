"""Independent timestamp/count/population expectations for recorded progress."""

from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from infosec_harness.api.app import app
from infosec_harness.persistence import db


@pytest.fixture
async def client(tmp_path, monkeypatch):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'progress.sqlite'}")
    async with engine.begin() as c:
        await c.run_sync(db.Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(db, "session", sessions)
    async with sessions() as s:
        s.add(db.Batch(id="mixed", status="running", finding_count=3))
        s.add(db.Batch(id="legacy", status="complete", finding_count=1))
        for name, state, population, accepted, ended in (
            (
                "a",
                "complete",
                "operational",
                "2026-10-01T10:00:00+00:00",
                "2026-10-01T10:01:00+00:00",
            ),
            ("b", "running", "operational", "2026-10-01T10:00:30+00:00", None),
            ("demo", "failed", "demo", "2026-10-01T09:00:00+00:00", "2026-10-01T12:00:00+00:00"),
            ("old", "complete", None, None, None),
        ):
            s.add(
                db.TriageRun(
                    id=name,
                    batch_id="legacy" if name == "old" else "mixed",
                    fingerprint=name,
                    repo_url="/test",
                    revision="test",
                    status=state,
                    created_at=datetime(2026, 10, 1, 9, tzinfo=UTC),
                    telemetry=None
                    if name == "old"
                    else {
                        "population": population,
                        "phase": "probing",
                        "accepted_at": accepted,
                        "completed_at": ended,
                    },
                )
            )
        await s.flush()
        s.add(
            db.RunEvent(
                id="event",
                run_id="b",
                phase="probing",
                detail="",
                created_at=datetime(2026, 10, 1, 10, 2, tzinfo=UTC),
            )
        )
        s.add(
            db.RunEvent(
                id="demo-event",
                run_id="demo",
                phase="failed",
                detail="",
                created_at=datetime(2026, 10, 1, 15, tzinfo=UTC),
            )
        )
        await s.commit()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c, sessions
    await engine.dispose()


async def test_operational_progress_counts_phases_and_activity_exclude_demo(client):
    c, _ = client
    r = await c.get("/api/batches?population=operational")
    assert r.status_code == 200
    (row,) = r.json()
    assert row["finding_count"] == 2
    assert row["status_counts"] == {"complete": 1, "running": 1}
    assert row["current_phases"] == {"probing": 1}
    assert row["started_at"] == "2026-10-01T10:00:00+00:00"
    assert row["completed_at"] is None
    assert row["last_activity_at"] == "2026-10-01T10:02:00+00:00"


async def test_completion_requires_terminal_batch_and_every_selected_end(client):
    c, sessions = client
    async with sessions() as s:
        b = await s.get(db.TriageRun, "b")
        b.status = "complete"
        b.telemetry = {**b.telemetry, "completed_at": "2026-10-01T10:03:00+00:00"}
        await s.commit()
    assert (await c.get("/api/batches?population=operational")).json()[0]["completed_at"] is None
    async with sessions() as s:
        batch = await s.get(db.Batch, "mixed")
        batch.status = "complete"
        await s.commit()
    row = (await c.get("/api/batches?population=operational")).json()[0]
    assert row["completed_at"] == "2026-10-01T10:03:00+00:00"
    assert row["current_phases"] == {}


async def test_legacy_or_missing_timestamps_are_unavailable(client):
    c, sessions = client
    (row,) = (await c.get("/api/batches?population=legacy")).json()
    assert row["started_at"] is None and row["completed_at"] is None
    async with sessions() as s:
        run = await s.get(db.TriageRun, "b")
        run.telemetry = {**run.telemetry, "accepted_at": "invalid"}
        await s.commit()
    assert (await c.get("/api/batches?population=operational")).json()[0]["started_at"] is None
