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


async def test_config_lists_agents(client):
    cfg = (await client.get("/api/config")).json()
    names = {a["name"] for a in cfg["agents"]}
    assert {"verdict", "context", "probe-author"} <= names
    assert cfg["model_mode"] == "stub"


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
    runs = (await client.get("/api/runs", params={"batch_id": batch_id})).json()
    assert len(runs) == 1
    detail = (await client.get(f"/api/runs/{runs[0]['id']}")).json()
    assert detail["verdict"] in {"potentially_exploitable", "likely_not_exploitable", "inconclusive"}
    # review via API
    r = await client.post(f"/api/runs/{runs[0]['id']}/review",
                          json={"reviewer": "bob", "decision": "confirm"})
    assert r.status_code == 200
