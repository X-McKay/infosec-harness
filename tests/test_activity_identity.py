"""Candidate identity follows native PydanticAI activity delivery across workers."""

import asyncio
import uuid
from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest
from pydantic import BaseModel
from pydantic_ai.durable_exec.temporal import PydanticAIPlugin, TemporalDurability
from pydantic_ai.models.function import FunctionModel
from temporalio import workflow
from temporalio.client import WorkflowFailureError
from temporalio.common import RetryPolicy
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import ExecuteActivityInput, Worker
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions
from test_agent import FakeOpenShell

from infosec_harness.agent import InvestigationDeps, WorkerIdentityInterceptor, build_agent
from infosec_harness.models import Finding, InvestigationRequest, WorkerIdentity
from infosec_harness.openshell import Sandbox
from infosec_harness.workflow import (
    CleanupInvestigation,
    InvestigationActivities,
    PreparedInvestigation,
)


def identity(value="a"):
    return WorkerIdentity(
        fingerprint=value * 64, code_sha256="b" * 64, config_sha256="c" * 64, dependencies={}
    )


def deps(candidate):
    return InvestigationDeps(
        run_id="run",
        sandbox=Sandbox("id", "run", "name", "workspace"),
        source_digest="digest",
        snapshot_path="/fixture",
        request=InvestigationRequest(finding=Finding(title="case", repo_url="fixture")),
        worker_identity=candidate,
    )


@pytest.mark.parametrize("mode", ["matching", "different", "missing", "drift"])
async def test_guard_checks_prepared_and_current_identity_before_handler(monkeypatch, mode):
    current = [identity()]
    guard = WorkerIdentityInterceptor(lambda: current[0])
    downstream = SimpleNamespace(execute_activity=AsyncMock(return_value="executed"))
    guarded = guard.intercept_activity(downstream)
    monkeypatch.setattr(
        "infosec_harness.agent.activity.info",
        lambda: SimpleNamespace(activity_type="agent__investigator__model_request"),
    )
    candidate = None if mode == "missing" else identity("d") if mode == "different" else identity()
    if mode == "drift":
        current[0] = identity("d")
    payload = ExecuteActivityInput(
        fn=lambda: None, args=[{}, deps(candidate)], executor=None, headers={}
    )
    if mode == "matching":
        assert await guarded.execute_activity(payload) == "executed"
        downstream.execute_activity.assert_awaited_once()
    else:
        with pytest.raises(ValueError, match="identity|changed; restart"):
            await guarded.execute_activity(payload)
        downstream.execute_activity.assert_not_awaited()


async def test_cleanup_remains_available_after_identity_drift(monkeypatch):
    current = [identity()]
    guard = WorkerIdentityInterceptor(lambda: current[0])
    current[0] = identity("d")
    downstream = SimpleNamespace(execute_activity=AsyncMock(return_value=None))
    monkeypatch.setattr(
        "infosec_harness.agent.activity.info",
        lambda: SimpleNamespace(activity_type="cleanup_investigation"),
    )
    await guard.intercept_activity(downstream).execute_activity(
        ExecuteActivityInput(fn=lambda: None, args=["run"], executor=None, headers={})
    )
    downstream.execute_activity.assert_awaited_once()


class IdentityDispatch(BaseModel):
    request: InvestigationRequest
    activity_name: str
    parameters: dict[str, Any]
    activity_queue: str


@workflow.defn
class IdentityDispatchWorkflow:
    @workflow.run
    async def run(self, payload: IdentityDispatch) -> None:
        prepared = await workflow.execute_activity(
            "prepare_investigation",
            payload.request,
            result_type=PreparedInvestigation,
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )
        try:
            await workflow.execute_activity(
                payload.activity_name,
                args=[payload.parameters, prepared.deps],
                task_queue=payload.activity_queue,
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=RetryPolicy(maximum_attempts=1),
            )
        finally:
            await workflow.execute_activity(
                "cleanup_investigation",
                CleanupInvestigation(
                    run_id=workflow.info().workflow_id,
                    expected_worker_identity=prepared.worker_identity.fingerprint,
                ),
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=RetryPolicy(maximum_attempts=1),
            )


@pytest.mark.requires_temporal
@pytest.mark.parametrize("kind", ["model", "workspace", "skill"])
async def test_real_temporal_different_worker_refuses_native_activity_before_execution(
    temporal_cli, tmp_path, kind
):
    shell = FakeOpenShell()
    model_calls = []

    def respond(messages, info):
        model_calls.append(messages)
        raise AssertionError("A different candidate must never invoke the model")

    agent = build_agent(shell, FunctionModel(respond))
    native = TemporalDurability.from_agent(agent).temporal_activities
    if kind == "model":
        name = "agent__investigator__model_request"
        parameters = {
            "messages": [],
            "model_settings": None,
            "model_request_parameters": {},
            "serialized_run_context": {},
            "model_id": None,
        }
    else:
        toolset = "workspace" if kind == "workspace" else "<agent>"
        name = f"agent__investigator__toolset__{toolset}__call_tool"
        parameters = {
            "name": "execute" if kind == "workspace" else "load_capability",
            "tool_args": {"command": "true"} if kind == "workspace" else {"id": "probe"},
            "serialized_run_context": {},
            "tool_def": None,
        }
    # Use actual SDK registrations and wire conversion, not substitute activities.
    from temporalio import activity

    assert name in {activity._Definition.from_callable(fn).name for fn in native}

    async def snapshot(finding, run_id):
        return SimpleNamespace(path=str(tmp_path), digest="digest")

    activities = InvestigationActivities(shell, snapshot, "fixture", identity=lambda: identity())
    queue = f"identity-{uuid.uuid4().hex}"
    activity_queue = queue + "-native"
    runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            __name__, "infosec_harness.workflow", "annotated_types", "typing_inspection"
        )
    )
    async with (
        await WorkflowEnvironment.start_local(
            dev_server_existing_path=temporal_cli, plugins=[PydanticAIPlugin()]
        ) as env,
        Worker(
            env.client,
            task_queue=queue,
            workflows=[IdentityDispatchWorkflow],
            activities=[activities.prepare, activities.cleanup],
            workflow_runner=runner,
            interceptors=[WorkerIdentityInterceptor(lambda: identity())],
        ),
        Worker(
            env.client,
            task_queue=activity_queue,
            activities=native,
            interceptors=[WorkerIdentityInterceptor(lambda: identity("d"))],
        ),
    ):
        handle = await env.client.start_workflow(
            IdentityDispatchWorkflow.run,
            IdentityDispatch(
                request=InvestigationRequest(
                    finding=Finding(title="case", repo_url="fixture"),
                    expected_worker_identity=identity().fingerprint,
                ),
                activity_name=name,
                parameters=parameters,
                activity_queue=activity_queue,
            ),
            id=queue,
            task_queue=queue,
        )
        with pytest.raises(WorkflowFailureError) as failed:
            await asyncio.wait_for(handle.result(), 30)
        assert "does not match the prepared worker identity" in str(failed.value.cause.cause)
    assert model_calls == []
    assert shell.executions == []
    assert shell.closed == [queue]
