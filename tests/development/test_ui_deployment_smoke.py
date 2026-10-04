"""Controlled HTTP fixtures verify deployment checks without any live services or data writes."""
import importlib.util
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ui_smoke", ROOT / "scripts/ui_deployment_smoke.py")
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)
COMMIT = "a" * 40


@pytest.fixture
def deployment():
    runtime = {"environment": "test", "model_mode": "live", "assessment_transport": "brokered",
               "api_source_commit": COMMIT, "as_of": "2026-10-04T00:00:00Z",
               "database_backend": "sqlite", "temporal_mode": "tls",
               "broker": {"configured": True, "status": "not_checked", "detail": "No observation"}}
    qualification = {"as_of": runtime["as_of"], "status": "not_checked", "detail": "No evidence",
                     "components": [{"agent": agent, "scope": "agent_semantics", "status": "not_checked",
                                     "freshness": "unavailable", "reason": "No evidence"}
                                    for agent in smoke.AGENT_BINDINGS], "limitations": []}
    metrics = {"as_of": runtime["as_of"], "population": "operational", "total_runs": 0,
               "status_counts": {}, "verdict_counts": {}, "trends": [], "stages": [], "definitions": {}}
    for field in ("tokens", "input_tokens", "output_tokens", "cost_usd", "wall_time_s", "agent_time_s"):
        metrics[field] = {"count": 0, "population": 0, "coverage": None}
    requests = []
    overrides = {}

    def serve(request):
        requests.append(request)
        key = (request.url.host, request.url.path)
        if key in overrides:
            return overrides[key](request)
        if request.url.path == "/api/runtime-status":
            return httpx.Response(200, json=runtime)
        if request.url.path == "/api/qualification":
            return httpx.Response(200, json=qualification)
        if request.url.path == "/api/metrics":
            return httpx.Response(200, json=metrics)
        if request.url.path.startswith("/api/"):
            return httpx.Response(200, json=[])
        if request.url.path == "/assets/app.js":
            return httpx.Response(200, text="console.log('test fixture')", headers={"content-type": "text/javascript"})
        if request.url.path == "/assets/app.css":
            return httpx.Response(200, text="body {}", headers={"content-type": "text/css"})
        return httpx.Response(200, text='<div id="root"></div><script src="/assets/app.js"></script>'
                              '<link rel="stylesheet" href="/assets/app.css">', headers={"content-type": "text/html"})

    with httpx.Client(transport=httpx.MockTransport(serve)) as client:
        yield client, requests, overrides, runtime, qualification


def run(deployment, **kwargs):
    return smoke.check("http://api.test", "http://web.test", client=deployment[0], **kwargs)


def test_real_contract_empty_operational_data_and_all_asset_routes(deployment):
    result = run(deployment, expected_source_commit=COMMIT,
                 expected_model_mode="live", expected_transport="brokered")
    assert result == {"status": "passed", "components": 11, "operational_counts": {
        "batches": 0, "runs": 0, "experiments": 0}, "assets": 2, "writes": 0}
    requests = deployment[1]
    assert all(request.method == "GET" for request in requests)
    for request in requests:
        if request.url.path in {"/api/batches", "/api/runs", "/api/experiments", "/api/metrics"}:
            assert dict(request.url.params) == {"population": "operational"}
    assert {"/", "/qualification", "/experiments", "/assets/app.js", "/assets/app.css"} <= {
        request.url.path for request in requests}
    assert {request.url.host for request in requests if request.url.path == "/api/runtime-status"} == {
        "api.test", "web.test"}


@pytest.mark.parametrize("host,path", [("api.test", "/api/runtime-status"),
                                      ("web.test", "/api/qualification"),
                                      ("web.test", "/assets/app.js")])
def test_old_api_proxy_or_missing_asset_fail(deployment, host, path):
    deployment[2][host, path] = lambda request: httpx.Response(404, text="private body")
    with pytest.raises(smoke.SmokeFailure, match="HTTP check failed"):
        run(deployment)


@pytest.mark.parametrize("field,value,expected", [("api_source_commit", "b" * 40, {"expected_source_commit": COMMIT}),
                                                  ("model_mode", "stub", {"expected_model_mode": "live"}),
                                                  ("assessment_transport", "direct", {"expected_transport": "brokered"})])
def test_stale_or_wrong_deployment_identity_fails(deployment, field, value, expected):
    deployment[3][field] = value
    with pytest.raises(smoke.SmokeFailure, match="deployment identity mismatch"):
        run(deployment, **expected)


def test_proxy_identity_mismatch(deployment):
    value = {**deployment[3], "api_source_commit": "b" * 40}
    deployment[2]["web.test", "/api/runtime-status"] = lambda request: httpx.Response(200, json=value)
    with pytest.raises(smoke.SmokeFailure, match="proxy identity mismatch"):
        run(deployment)


@pytest.mark.parametrize("problem", ["malformed", "duplicate", "missing"])
def test_malformed_or_incomplete_contract(deployment, problem):
    if problem == "malformed":
        deployment[3]["broker"]["status"] = "invented"
    elif problem == "duplicate":
        deployment[4]["components"][-1] = deployment[4]["components"][0]
    else:
        deployment[4]["components"].pop()
    with pytest.raises(smoke.SmokeFailure):
        run(deployment)


@pytest.mark.parametrize("url", ["http://user:secret@api.test", "http://api.test?secret=yes",
                                "http://api.test#key", "file:///private/key", "http://[broken", "http://api.test:bad"])
def test_credential_or_non_http_endpoints_rejected_without_requests(deployment, url):
    with pytest.raises(smoke.SmokeFailure, match="invalid endpoint"):
        smoke.check(url, "http://web.test", client=deployment[0])
    assert not deployment[1]


def test_external_asset_and_html_fallback_rejected(deployment):
    deployment[2]["web.test", "/qualification"] = lambda request: httpx.Response(
        200, text='<div id="root"></div><script src="https://external.test/app.js"></script>',
        headers={"content-type": "text/html"})
    with pytest.raises(smoke.SmokeFailure, match="external asset"):
        run(deployment)
    deployment[2].pop(("web.test", "/qualification"))
    deployment[2]["web.test", "/assets/app.js"] = lambda request: httpx.Response(
        200, text="<html>fallback</html>", headers={"content-type": "text/html"})
    with pytest.raises(smoke.SmokeFailure, match="unexpected content type"):
        run(deployment)


def test_deadline_blocks_further_requests(deployment, monkeypatch):
    clock = iter([0, 61])
    monkeypatch.setattr(smoke.time, "monotonic", lambda: next(clock))
    with pytest.raises(smoke.SmokeFailure, match="deadline exceeded"):
        run(deployment)
    assert not deployment[1]


def test_cli_failure_does_not_echo_transport_payload(deployment, monkeypatch, capsys):
    def broken(request):
        raise httpx.ConnectError("secret credentials private URL", request=request)
    deployment[2]["api.test", "/api/runtime-status"] = broken
    original = smoke.check
    monkeypatch.setattr(smoke, "check", lambda **kwargs: original(**kwargs, client=deployment[0]))
    assert smoke.main(["--api-url", "http://api.test", "--web-url", "http://web.test"]) == 1
    output = capsys.readouterr().out
    assert "transport check failed" in output
    assert "secret" not in output and "private" not in output


def test_metrics_must_report_operational_population(deployment):
    value = deployment[0].get("http://api.test/api/metrics").json()
    value["population"] = "demo"
    deployment[2]["api.test", "/api/metrics"] = lambda request: httpx.Response(200, json=value)
    with pytest.raises(smoke.SmokeFailure, match="unexpected metrics population"):
        run(deployment)
