"""Exercise cancellation intent and recovery against a real local Temporal service."""
from __future__ import annotations

import asyncio
import uuid

import pytest

pytestmark = pytest.mark.requires_temporal


@pytest.mark.parametrize("started", [False, True])
async def test_cancellation_survives_pending_and_running_workflows(temporal_cli, started, tmp_path, monkeypatch):
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client, WorkflowFailureError
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    from infosec_harness.domain.models import FindingInput
    from infosec_harness.persistence import db, lifecycle, store
    from infosec_harness.workflows import activities, worker
    from infosec_harness.workflows import submission as runner
    from infosec_harness.workflows.workflows import TriageBatchWorkflow

    await db.create_all()
    finding = FindingInput(title="Cancellation fixture", repo_url=str(tmp_path), file_path="a.py")
    batch_id = f"cancel-{uuid.uuid4().hex[:12]}"
    payload = {"batch_id": batch_id, "findings": [finding.model_dump(mode="json")]}
    await lifecycle.accept_batch(batch_id, [finding], "Cancellation fixture", payload)
    entered = asyncio.Event()

    async def blocked_checkout(ref):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(activities, "checkout", blocked_checkout)
    env = await WorkflowEnvironment.start_local(dev_server_existing_path=temporal_cli)
    try:
        client = await Client.connect(env.client.service_client.config.target_host,
                                      plugins=[PydanticAIPlugin()])

        async def connect():
            return client

        monkeypatch.setattr(worker, "connect", connect)
        if started:
            async with Worker(client, task_queue="cancel-test", workflows=worker.WORKFLOWS,
                              activities=activities.ALL_ACTIVITIES):
                handle = await client.start_workflow(TriageBatchWorkflow.run, payload,
                    id=f"batch:{batch_id}", task_queue="cancel-test")
                await asyncio.wait_for(entered.wait(), timeout=30)
                assert await runner.cancel_durable_batch(batch_id) == "cancellation_requested"
                with pytest.raises(WorkflowFailureError):
                    await asyncio.wait_for(handle.result(), timeout=30)
        else:
            assert await runner.cancel_durable_batch(batch_id) == "cancelled"
        summary = await store.batch_summary(batch_id)
        assert summary["status"] == "cancelled"
        assert summary["status_counts"] == {"cancelled": 1}
        assert not [item for item in await lifecycle.pending_submissions() if item[0] == batch_id]
        # Repeated requests acknowledge the durable terminal state without restarting work.
        assert await runner.cancel_durable_batch(batch_id) == "cancelled"
    finally:
        await env.shutdown()


async def test_root_budget_stop_keeps_a_structured_reason(temporal_cli, tmp_path, monkeypatch):
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    from infosec_harness.domain.models import FindingInput
    from infosec_harness.persistence import db, lifecycle, store
    from infosec_harness.settings import get_settings
    from infosec_harness.workflows import activities, worker
    from infosec_harness.workflows.workflows import TriageBatchWorkflow

    (tmp_path / "a.py").write_text("def target():\n    return 1\n")
    monkeypatch.setattr(get_settings(), "root_max_requests", 0)
    await db.create_all()
    finding = FindingInput(title="Budget fixture", repo_url=str(tmp_path), file_path="a.py",
                           start_line=1, severity="critical")
    batch_id = f"budget-stop-{uuid.uuid4().hex[:12]}"
    payload = {"batch_id": batch_id, "findings": [finding.model_dump(mode="json")]}
    await lifecycle.accept_batch(batch_id, [finding], "Budget fixture", payload)
    env = await WorkflowEnvironment.start_local(dev_server_existing_path=temporal_cli)
    try:
        client = await Client.connect(env.client.service_client.config.target_host,
                                      plugins=[PydanticAIPlugin()])
        async with Worker(client, task_queue="budget-test", workflows=worker.WORKFLOWS,
                          activities=activities.ALL_ACTIVITIES):
            outputs = await client.execute_workflow(TriageBatchWorkflow.run, payload,
                id=f"batch:{batch_id}", task_queue="budget-test")
        result = outputs[0].result
        assert result.verdict.inconclusive_reason.value == "budget_exhausted"
        assert result.priority_score >= .6
        assert outputs[0].invocations == []
        assert (await store.batch_summary(batch_id))["status"] == "complete"
    finally:
        await env.shutdown()


async def test_worker_replacement_resumes_accepted_batch(temporal_cli, tmp_path, monkeypatch):
    from datetime import timedelta

    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    from infosec_harness.domain.models import FindingInput
    from infosec_harness.persistence import db, lifecycle, store
    from infosec_harness.sandbox import docker
    from infosec_harness.settings import get_settings
    from infosec_harness.workflows import activities, worker
    from infosec_harness.workflows.workflows import TriageBatchWorkflow

    (tmp_path / "a.py").write_text("def target():\n    return 1\n")
    await db.create_all()
    monkeypatch.setattr(get_settings(), "recipe_cache_enabled", False)
    finding = FindingInput(title="Worker replacement fixture", repo_url=str(tmp_path),
                           file_path="a.py", start_line=1)
    batch_id = f"worker-restart-{uuid.uuid4().hex[:12]}"
    payload = {"batch_id": batch_id, "findings": [finding.model_dump(mode="json")]}
    await lifecycle.accept_batch(batch_id, [finding], "Worker replacement", payload)
    entered = asyncio.Event()
    original_checkout = activities.checkout
    attempts = 0

    async def interrupted_checkout(ref):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            entered.set()
            await asyncio.Event().wait()
        return await original_checkout(ref)

    async def unavailable(*args):
        return False

    monkeypatch.setattr(activities, "checkout", interrupted_checkout)
    monkeypatch.setattr(docker, "image_exists", unavailable)
    monkeypatch.setattr(docker, "runtime_available", unavailable)
    env = await WorkflowEnvironment.start_local(dev_server_existing_path=temporal_cli)
    try:
        client = await Client.connect(env.client.service_client.config.target_host,
                                      plugins=[PydanticAIPlugin()])
        handle = await client.start_workflow(TriageBatchWorkflow.run, payload,
            id=f"batch:{batch_id}", task_queue="replacement-test")
        async with Worker(client, task_queue="replacement-test", workflows=worker.WORKFLOWS,
                          activities=activities.ALL_ACTIVITIES,
                          graceful_shutdown_timeout=timedelta(seconds=0)):
            await asyncio.wait_for(entered.wait(), timeout=30)
        async with Worker(client, task_queue="replacement-test", workflows=worker.WORKFLOWS,
                          activities=activities.ALL_ACTIVITIES):
            outputs = await asyncio.wait_for(handle.result(), timeout=45)
        assert attempts >= 2
        assert len(outputs) == 1
        summary = await store.batch_summary(batch_id)
        assert summary["status"] == "complete"
        rows = await store.list_runs(batch_id=batch_id)
        assert len(rows) == 1
        assert rows[0]["status"] == "complete"
        detail = await store.get_run(rows[0]["id"])
        assert len({event["id"] for event in detail["events"]}) == len(detail["events"])
    finally:
        await env.shutdown()


async def test_terminal_persistence_retries_past_transient_database_outage(temporal_cli, monkeypatch):
    """A closed Temporal workflow must not leave its accepted batch permanently running."""
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    from infosec_harness.persistence import db, lifecycle, store
    from infosec_harness.workflows import worker
    from infosec_harness.workflows.workflows import TriageBatchWorkflow

    await db.create_all()
    batch_id = f"terminal-retry-{uuid.uuid4().hex[:12]}"
    payload = {"batch_id": batch_id, "findings": []}
    await lifecycle.accept_batch(batch_id, [], "Terminal retry", payload)
    original = lifecycle.finish_pending
    attempts = 0

    async def transient_failure(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts <= 3:
            raise ConnectionError("database temporarily unavailable")
        return await original(*args, **kwargs)

    monkeypatch.setattr(lifecycle, "finish_pending", transient_failure)
    env = await WorkflowEnvironment.start_local(dev_server_existing_path=temporal_cli)
    try:
        client = await Client.connect(env.client.service_client.config.target_host,
                                      plugins=[PydanticAIPlugin()])
        async with Worker(client, task_queue="terminal-retry-test", workflows=worker.WORKFLOWS,
                          activities=worker.ALL_ACTIVITIES):
            result = await client.execute_workflow(TriageBatchWorkflow.run, payload,
                id=f"batch:{batch_id}", task_queue="terminal-retry-test")
        assert result == []
        assert attempts == 4
        assert (await store.batch_summary(batch_id))["status"] == "complete"
    finally:
        await env.shutdown()


async def test_root_elapsed_deadline_cancels_inflight_work_and_persists_failure(temporal_cli, tmp_path, monkeypatch):
    from datetime import timedelta

    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client, WorkflowFailureError
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    from infosec_harness.domain.models import FindingInput
    from infosec_harness.persistence import db, lifecycle, store
    from infosec_harness.settings import get_settings
    from infosec_harness.workflows import activities, worker
    from infosec_harness.workflows.workflows import TriageBatchWorkflow

    await db.create_all()
    monkeypatch.setattr(get_settings(), 'root_max_elapsed_seconds', 5)
    entered, cancelled = asyncio.Event(), asyncio.Event()
    async def blocked_checkout(ref):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()
    monkeypatch.setattr(activities, 'checkout', blocked_checkout)
    env = await WorkflowEnvironment.start_local(dev_server_existing_path=temporal_cli)
    try:
        client = await Client.connect(env.client.service_client.config.target_host,
                                      plugins=[PydanticAIPlugin()])
        finding = FindingInput(title='Root deadline fixture', repo_url=str(tmp_path), file_path='a.py')
        batch_id = f'deadline-{uuid.uuid4().hex[:12]}'
        payload = {'batch_id': batch_id, 'findings': [finding.model_dump(mode='json')]}
        await lifecycle.accept_batch(batch_id, [finding], 'Deadline fixture', payload)
        async with Worker(client, task_queue='deadline-test', workflows=worker.WORKFLOWS,
                          activities=activities.ALL_ACTIVITIES,
                          max_heartbeat_throttle_interval=timedelta(seconds=1)):
            handle = await client.start_workflow(TriageBatchWorkflow.run, payload,
                id=f'batch:{batch_id}', task_queue='deadline-test')
            await asyncio.wait_for(entered.wait(), timeout=10)
            with pytest.raises(WorkflowFailureError, match='Workflow execution failed'):
                await asyncio.wait_for(handle.result(), timeout=15)
            await asyncio.wait_for(cancelled.wait(), timeout=10)
        summary = await store.batch_summary(batch_id)
        assert summary['status'] == 'failed'
        assert summary['status_counts'] == {'failed': 1}
    finally:
        await env.shutdown()
