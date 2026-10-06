from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from temporalio.client import WorkflowExecutionStatus

from infosec_harness import api
from infosec_harness.contracts import Finding, InvestigationResult, Verdict


@pytest.fixture
def client():
    backend = SimpleNamespace(start_workflow=AsyncMock())
    api.app.dependency_overrides[api.temporal] = lambda: backend
    yield backend
    api.app.dependency_overrides.clear()


async def request(method, path, **kwargs):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://test"
    ) as client:
        return await client.request(method, path, **kwargs)


async def test_submit_records_native_workflow_and_server_limits(client):
    response = await request(
        "POST", "/api/runs", json={"title": "SQL injection", "repo_url": "https://example.org/repo"}
    )
    assert response.status_code == 202
    args, kwargs = client.start_workflow.call_args
    assert args[0] == "InvestigationWorkflow"
    assert kwargs["task_queue"] == "investigate-v11"
    assert kwargs["id"] == response.json()["id"]
    assert args[1].limits.max_requests == 30
    assert kwargs["execution_timeout"] == timedelta(seconds=args[1].limits.timeout_seconds + 600)
    invalid = await request(
        "POST",
        "/api/runs",
        json={"title": "a", "repo_url": "repo", "limits": {"max_requests": 9999}},
    )
    assert invalid.status_code == 422
    assert client.start_workflow.await_count == 1


async def test_terminal_cancellation_never_rewrites_completed_outcome(client):
    handle = SimpleNamespace(
        describe=AsyncMock(return_value=SimpleNamespace(status=WorkflowExecutionStatus.COMPLETED)),
        cancel=AsyncMock(),
    )
    client.get_workflow_handle = lambda *args, **kwargs: handle
    response = await request("POST", "/api/runs/investigate-v11-test/cancel")
    assert response.json()["status"] == "completed"
    handle.cancel.assert_not_awaited()
    handle.describe.return_value.status = WorkflowExecutionStatus.RUNNING
    response = await request("POST", "/api/runs/investigate-v11-test/cancel")
    assert response.json()["status"] == "cancellation_requested"
    handle.cancel.assert_awaited_once()


async def test_completed_result_comes_from_temporal_not_a_shadow_database(client):
    finding = Finding(title="Finding", repo_url="repo")
    result = InvestigationResult(
        finding=finding,
        verdict=Verdict(label="inconclusive", summary="No execution"),
        evidence=[],
        source_digest="abc",
        model="fixture",
    )
    description = SimpleNamespace(
        status=WorkflowExecutionStatus.COMPLETED,
        memo=AsyncMock(return_value={"finding": finding.model_dump()}),
    )
    handle = SimpleNamespace(
        describe=AsyncMock(return_value=description), result=AsyncMock(return_value=result)
    )
    client.get_workflow_handle = lambda *args, **kwargs: handle
    response = await request("GET", "/api/runs/investigate-v11-test")
    assert response.status_code == 200
    assert response.json()["result"]["verdict"]["label"] == "inconclusive"
    assert (await request("GET", "/api/runs/old-batch")).status_code == 404


async def test_pagination_bounded_and_invalid_token_never_reaches_temporal(client):
    row = SimpleNamespace(
        id="investigate-v11-test",
        status=WorkflowExecutionStatus.RUNNING,
        start_time=datetime.now(UTC),
        close_time=None,
        memo=AsyncMock(return_value={"finding": {"title": "A"}}),
    )
    page = SimpleNamespace(fetch_next_page=AsyncMock(), current_page=[row], next_page_token=b"next")
    called = []

    def listing(*args, **kwargs):
        called.append(kwargs)
        return page

    client.list_workflows = listing
    response = await request("GET", "/api/runs")
    assert response.json()["next_page_token"] == "bmV4dA=="
    assert called[0]["page_size"] == 50
    assert (await request("GET", "/api/runs?page_token=!!!")).status_code == 400
    assert len(called) == 1


@pytest.mark.requires_temporal
async def test_real_temporal_submit_query_and_cancellation(temporal_cli, tmp_path):
    import asyncio

    from fakes import FakeOpenShell, runner
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from pydantic_ai.models.function import FunctionModel
    from temporalio.client import WorkflowFailureError
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    from infosec_harness.agents.investigator import build_agent
    from infosec_harness.workflows.investigation import (
        InvestigationActivities,
        InvestigationWorkflow,
        bind_investigator,
    )

    entered = asyncio.Event()
    shell = FakeOpenShell()

    async def model(messages, info):
        entered.set()
        await asyncio.Event().wait()

    async def snapshot(finding, run_id):
        return SimpleNamespace(path=str(tmp_path), digest="fixture")

    bind_investigator(build_agent(shell, FunctionModel(model)))
    activities = InvestigationActivities(shell, snapshot, "fixture")
    async with await WorkflowEnvironment.start_local(
        dev_server_existing_path=temporal_cli, plugins=[PydanticAIPlugin()]
    ) as env:
        api.app.dependency_overrides[api.temporal] = lambda: env.client
        try:
            async with Worker(
                env.client,
                task_queue=api.get_settings().task_queue,
                workflows=[InvestigationWorkflow],
                activities=[activities.prepare, activities.finalize, activities.cleanup],
                workflow_runner=runner(),
            ):
                started = await request(
                    "POST",
                    "/api/runs",
                    json={"title": "Native HTTP finding", "repo_url": "fixture"},
                )
                assert started.status_code == 202
                run_id = started.json()["id"]
                await asyncio.wait_for(entered.wait(), 30)
                progress = await request("GET", f"/api/runs/{run_id}")
                assert progress.status_code == 200
                assert progress.json()["status"] == "running"
                assert progress.json()["phase"] == "investigating"
                assert progress.json()["finding"]["title"] == "Native HTTP finding"
                cancelled = await request("POST", f"/api/runs/{run_id}/cancel")
                assert cancelled.json()["status"] == "cancellation_requested"
                with pytest.raises(WorkflowFailureError):
                    await asyncio.wait_for(env.client.get_workflow_handle(run_id).result(), 30)
                final = await request("GET", f"/api/runs/{run_id}")
                assert final.json()["status"] == "cancelled"
                assert shell.closed == [run_id]
        finally:
            api.app.dependency_overrides.clear()


@pytest.mark.requires_temporal
async def test_queued_run_has_server_deadline_without_a_worker(temporal_cli, monkeypatch):
    import asyncio

    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import WorkflowFailureError
    from temporalio.testing import WorkflowEnvironment

    monkeypatch.setattr(api, "execution_timeout", lambda limits: timedelta(seconds=1))
    async with await WorkflowEnvironment.start_local(
        dev_server_existing_path=temporal_cli, plugins=[PydanticAIPlugin()]
    ) as env:
        api.app.dependency_overrides[api.temporal] = lambda: env.client
        try:
            submitted = await request(
                "POST", "/api/runs", json={"title": "Queued", "repo_url": "fixture"}
            )
            run_id = submitted.json()["id"]
            handle = env.client.get_workflow_handle(run_id)
            with pytest.raises(WorkflowFailureError):
                await asyncio.wait_for(handle.result(), 10)
            assert (await handle.describe()).status == WorkflowExecutionStatus.TIMED_OUT
            state = (await request("GET", f"/api/runs/{run_id}")).json()
            assert state["status"] == "failed"
            assert state["error"] == "timed_out"
        finally:
            api.app.dependency_overrides.clear()
