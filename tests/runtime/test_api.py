import httpx
import pytest
from httpx import ASGITransport


@pytest.fixture
async def client(tmp_path, monkeypatch):
    from infosec_harness.api.app import app
    from infosec_harness.persistence import db

    await db.create_all()
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_health(client):
    assert (await client.get("/api/health")).json()["status"] == "ok"


async def test_cross_origin_reads_are_not_granted(client):
    """The UI is same-origin (nginx or the Vite proxy); no other origin may read the API."""
    response = await client.get("/api/health", headers={"Origin": "https://elsewhere.example"})
    assert "access-control-allow-origin" not in response.headers
    preflight = await client.options(
        "/api/batches",
        headers={"Origin": "https://elsewhere.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in preflight.headers


async def test_config_lists_agents(client):
    cfg = (await client.get("/api/config")).json()
    names = {a["name"] for a in cfg["agents"]}
    assert {"verdict", "context", "probe-author"} <= names
    assert cfg["model_mode"] == "stub"


def test_openapi_read_routes_publish_named_response_contracts():
    from infosec_harness.api.app import app

    schemas = {
        ("/api/batches", "get"): {"items": {"$ref": "#/components/schemas/BatchSummary"}},
        ("/api/batches/{batch_id}", "get"): {"$ref": "#/components/schemas/BatchDetail"},
        ("/api/run-page", "get"): {"$ref": "#/components/schemas/RunPage"},
        ("/api/runs/{run_id}", "get"): {"$ref": "#/components/schemas/RunDetail"},
        ("/api/experiments", "get"): {"$ref": "#/components/schemas/ExperimentPage"},
        ("/api/experiments/{experiment_id}", "get"): {
            "$ref": "#/components/schemas/ExperimentDetail"
        },
        ("/api/config", "get"): {"$ref": "#/components/schemas/ConfigResponse"},
    }
    document = app.openapi()
    # Removed reads stay removed: the UI pages runs and has no component qualification view.
    assert "/api/runs" not in document["paths"]
    assert "/api/qualification" not in document["paths"]
    for (path, method), expected in schemas.items():
        actual = document["paths"][path][method]["responses"]["200"]["content"][
            "application/json"
        ]["schema"]
        for key, value in expected.items():
            assert actual[key] == value


async def test_experiment_routes_keep_unknown_usage_explicit(client):
    from infosec_harness.persistence import db

    async with db.session() as session:
        session.add(db.EvalExperiment(
            id="api-exp", agent="verdict", dataset="dataset.yaml", dataset_version="3",
            metrics={"status": "complete", "n": 1, "n_planned": 1, "avg_tokens": None},
            pricing="unknown", repetitions=1,
        ))
        session.add(db.EvalCaseResult(
            experiment_id="api-exp", case_name="unknown-usage", repetition=0,
            passed=False, scores={"outcome": "invalid_output", "usage_status": "unknown"},
        ))
        await session.commit()

    listed = (await client.get("/api/experiments", params={"limit": 100})).json()
    summary = next(item for item in listed["items"] if item["id"] == "api-exp")
    assert "metrics" not in summary
    assert summary["cases_completed"] == summary["cases_planned"] == 1
    assert summary["task_success_rate"] is None and summary["average_cost_usd"] is None
    detail = (await client.get("/api/experiments/api-exp")).json()
    assert detail["metrics"]["avg_tokens"] is None
    assert detail["cases"] == [{
        "case_name": "unknown-usage",
        "repetition": 0,
        "passed": False,
        "scores": {"outcome": "invalid_output", "usage_status": "unknown"},
        "cost_usd": None,
        "latency_s": 0.0,
    }]


async def test_batch_detail_excludes_pending_runs_from_verdict_counts(client):
    from sqlalchemy import select

    from infosec_harness.domain.models import FindingInput
    from infosec_harness.persistence import db, lifecycle

    findings = [
        FindingInput(title="first", repo_url="/tmp/repo"),
        FindingInput(title="second", repo_url="/tmp/repo"),
    ]
    await lifecycle.accept_batch("mixed-api-batch", findings, "mixed", None,
                                 agent_config_digests={})

    accepted = await client.get("/api/batches/mixed-api-batch")
    assert accepted.status_code == 200
    assert accepted.json()["status_counts"] == {"pending": 2}
    assert accepted.json()["verdict_counts"] == {}

    async with db.session() as session:
        first = (await session.scalars(
            select(db.TriageRun)
            .where(db.TriageRun.batch_id == "mixed-api-batch")
            .order_by(db.TriageRun.id)
        )).first()
        assert first is not None
        first.status = "complete"
        first.verdict = "inconclusive"
        await session.commit()

    mixed = await client.get("/api/batches/mixed-api-batch")
    assert mixed.status_code == 200
    assert mixed.json()["status_counts"] == {"complete": 1, "pending": 1}
    assert mixed.json()["verdict_counts"] == {"inconclusive": 1}


async def test_submit_local_and_read(client, tmp_path):
    (tmp_path / "app.py").write_text("def f(db, n):\n    return db.execute('SELECT '+n)\n")
    (tmp_path / "requirements.txt").write_text("")
    (tmp_path / "tests").mkdir()
    body = {"mode": "local", "label": "apitest", "findings": [
        {"title": "SQLi", "repo_url": str(tmp_path), "file_path": "app.py", "start_line": 2,
         "cwe": "CWE-89", "severity": "high"}]}
    resp = await client.post("/api/batches", json=body)
    assert resp.status_code == 200
    batch_id = resp.json()["batch_id"]
    batch = (await client.get(f"/api/batches/{batch_id}")).json()
    assert batch["finding_count"] == 1
    assert batch["status_counts"] == {"complete": 1}
    assert batch["status"] == "complete"
    runs = (await client.get("/api/run-page", params={"batch_id": batch_id})).json()["items"]
    assert len(runs) == 1
    assert runs[0]["telemetry"]["population"] == "demo"
    detail = (await client.get(f"/api/runs/{runs[0]['id']}")).json()
    assert detail["verdict"] in {"potentially_exploitable", "likely_not_exploitable", "inconclusive"}
    # review via API
    r = await client.post(f"/api/runs/{runs[0]['id']}/review",
                          json={"reviewer": "bob", "decision": "confirm"})
    assert r.status_code == 200


async def test_submission_modes_are_local_or_temporal_only(client, monkeypatch):
    """`auto` is gone: a submission says which orchestration it wants, and local mode refuses
    real models through the one shared check rather than a copy in the API."""
    from infosec_harness.settings import get_settings

    finding = {"title": "x", "repo_url": "/nonexistent", "file_path": "a.py"}
    response = await client.post("/api/batches", json={"mode": "auto", "findings": [finding]})
    assert response.status_code == 422
    monkeypatch.setattr(get_settings(), "model_mode", "live")
    response = await client.post("/api/batches", json={"mode": "local", "findings": [finding]})
    assert response.status_code == 422
    assert "HARNESS_MODEL_MODE=stub" in response.json()["detail"]


async def test_review_decision_is_a_closed_vocabulary(client):
    response = await client.post("/api/runs/whatever/review", json={"decision": "approve"})
    assert response.status_code == 422


async def test_experiments_are_paged_newest_first_with_headline_measurements(client):
    """Regression: the list returned full metrics for up to 100 experiments (several MiB)."""
    from datetime import UTC, datetime, timedelta

    from infosec_harness.persistence import db

    now = datetime.now(UTC)
    async with db.session() as session:
        for i in range(3):
            session.add(db.EvalExperiment(
                id=f"paged-{i}", agent="paged", dataset="d", backend="stub",
                created_at=now + timedelta(days=3650 + i),
                metrics={"status": "complete",
                         "task_success_rate": True if i == 0 else 0.5 + i / 10,
                         "distributions": {"p95_latency_s": 2.0, "average_cost_usd": "1"},
                         "gate_evaluation": {"status": "passed"}, "per_case": ["x" * 1000]}))
        await session.commit()
    first = (await client.get("/api/experiments", params={"limit": 2,
                                                          "population": "demo"})).json()
    assert [item["id"] for item in first["items"]] == ["paged-2", "paged-1"]
    assert first["total"] >= 3 and first["limit"] == 2 and first["offset"] == 0
    second = (await client.get("/api/experiments", params={"limit": 2, "offset": 2,
                                                           "population": "demo"})).json()
    assert second["items"][0]["id"] == "paged-0"
    newest = first["items"][0]
    assert newest["task_success_rate"] == 0.7 and newest["p95_latency_s"] == 2.0
    assert newest["gate_status"] == "passed" and newest["status"] == "complete"
    # A non-numeric or boolean measurement is unavailable, never coerced.
    assert newest["average_cost_usd"] is None
    assert second["items"][0]["task_success_rate"] is None
    assert (await client.get("/api/experiments", params={"limit": 101})).status_code == 422


def test_the_api_version_is_the_package_version():
    from importlib.metadata import version

    from infosec_harness.api.app import app

    assert app.version == version("infosec-harness")
