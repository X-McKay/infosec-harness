"""Candidate identity follows native PydanticAI activity delivery across workers."""

import asyncio
import uuid
from datetime import timedelta
from importlib.metadata import version
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fakes import FakeOpenShell
from pydantic import BaseModel
from pydantic_ai.durable_exec.temporal import TemporalDurability
from pydantic_ai.models.function import FunctionModel
from temporalio import workflow
from temporalio.client import WorkflowFailureError
from temporalio.common import RetryPolicy
from temporalio.worker import ExecuteActivityInput, Worker
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

from infosec_harness.agents.investigator import (
    AGENT_NAME,
    GUARDED_ACTIVITY_PREFIX,
    InvestigationDeps,
    build_agent,
)
from infosec_harness.config import Settings
from infosec_harness.contracts import Finding, InvestigationRequest, Limits, WorkerIdentity
from infosec_harness.sandbox import Sandbox
from infosec_harness.workflows.investigation import (
    CleanupInvestigation,
    InvestigationActivities,
    InvestigationWorkflow,
    PreparedInvestigation,
)
from infosec_harness.workflows.worker import (
    WorkerIdentityInterceptor,
    WorkerIdentityMismatch,
    worker_identity,
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
        "infosec_harness.workflows.worker.activity.info",
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
        with pytest.raises(WorkerIdentityMismatch, match="identity|changed; restart") as error:
            await guarded.execute_activity(payload)
        assert error.value.non_retryable and error.value.type == "WorkerIdentityMismatch"
        # Both fingerprints are named so an operator can see which candidate is running.
        assert "bound=aaaaaaaaaaaa" in str(error.value)
        downstream.execute_activity.assert_not_awaited()


def test_guard_prefix_matches_every_registered_native_activity():
    """Renaming the agent must not silently disable the identity guard."""
    from temporalio import activity

    agent = build_agent(FakeOpenShell(), FunctionModel(lambda messages, info: None))
    assert agent.name == AGENT_NAME
    names = {
        activity._Definition.from_callable(fn).name
        for fn in TemporalDurability.from_agent(agent).temporal_activities
    }
    assert "agent__investigator__model_request" in names
    assert names and all(name.startswith(GUARDED_ACTIVITY_PREFIX) for name in names)
    lifecycle = ("prepare_investigation", "finalize_investigation", "cleanup_investigation")
    assert not any(name.startswith(GUARDED_ACTIVITY_PREFIX) for name in lifecycle)


async def test_cleanup_remains_available_after_identity_drift(monkeypatch):
    current = [identity()]
    guard = WorkerIdentityInterceptor(lambda: current[0])
    current[0] = identity("d")
    downstream = SimpleNamespace(execute_activity=AsyncMock(return_value=None))
    monkeypatch.setattr(
        "infosec_harness.workflows.worker.activity.info",
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
                    expected_worker_identity=prepared.deps.worker_identity.fingerprint,
                ),
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=RetryPolicy(maximum_attempts=1),
            )


@pytest.mark.requires_temporal
@pytest.mark.parametrize("kind", ["model", "workspace", "skill"])
async def test_real_temporal_different_worker_refuses_native_activity_before_execution(
    temporal_env, tmp_path, kind
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
            __name__, "infosec_harness.workflows.investigation", "annotated_types", "typing_inspection"
        )
    )
    env = temporal_env
    async with (
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


def test_identity_binds_policy_contents_dependencies_and_configuration(tmp_path):
    import json

    policy = tmp_path / "policy.yaml"
    policy.write_text("network: deny")
    config = tmp_path / "runtime.json"
    config.write_text(json.dumps({"profiles": {"probe": {"policy": str(policy)}}}))
    settings = Settings(openshell_config=config, temporal_api_key="do-not-report")
    first = worker_identity(settings)
    assert "do-not-report" not in first.model_dump_json()
    assert first.dependencies["openshell"] == version("openshell")
    settings.temporal_api_key = "another-secret"
    assert worker_identity(settings) == first
    policy.write_text("network: allow")
    second = worker_identity(settings)
    assert second.code_sha256 == first.code_sha256
    assert second.config_sha256 != first.config_sha256
    settings.model_name = "other-model"
    assert worker_identity(settings).fingerprint != second.fingerprint


def test_identity_ignores_operator_settings_that_cannot_change_an_investigation(tmp_path):
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    settings = Settings(openshell_config=config)
    first = worker_identity(settings)
    changed = settings.model_copy(update={"log_level": "DEBUG", "reports_dir": tmp_path / "r"})
    assert worker_identity(changed) == first


@pytest.mark.parametrize(("budget", "output_bytes"), [(300, None), (301, None), (300, 260_070)])
def test_worker_refuses_command_budget_above_runtime_maximum(
    tmp_path, monkeypatch, budget, output_bytes
):
    """Above the runtime bound every execute is refused mid-investigation; the worker must
    refuse to start instead of silently capping only the model timeout. Below the wrapper's
    bounded output, a large command would become an unknown execution: refuse likewise."""
    from infosec_harness.config import get_settings
    from infosec_harness.tools.execute import WRAPPER_OUTPUT_BYTES
    from infosec_harness.workflows import worker

    output_bytes = output_bytes or WRAPPER_OUTPUT_BYTES
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    settings = get_settings().model_copy(update={
        "openshell_config": config,
        "limits": Limits(command_timeout_seconds=budget),
    })
    monkeypatch.setattr(worker, "OpenShellConfig", SimpleNamespace(
        load=lambda path: SimpleNamespace(max_timeout_seconds=300,
                                          max_output_bytes=output_bytes)))
    monkeypatch.setattr(worker, "OpenShell", lambda config: SimpleNamespace(config=config))
    monkeypatch.setattr(worker, "Worker", lambda client, **kwargs: kwargs)
    monkeypatch.setattr(InvestigationWorkflow, "agent", None)
    monkeypatch.setattr(InvestigationWorkflow, "__pydantic_ai_agents__", [])
    if budget > 300:
        with pytest.raises(ValueError, match=r"command_timeout_seconds \(301\) exceeds"):
            worker.create_worker(None, settings)
        assert InvestigationWorkflow.agent is None
        return
    if output_bytes < WRAPPER_OUTPUT_BYTES:
        with pytest.raises(ValueError, match=r"max_output_bytes \(260070\) is below"):
            worker.create_worker(None, settings)
        assert InvestigationWorkflow.agent is None
        return
    captures = []
    monkeypatch.setattr(worker, "worker_identity",
                        lambda settings: captures.append(settings) or identity())
    created = worker.create_worker(None, settings)
    assert created["task_queue"] == settings.task_queue
    assert InvestigationWorkflow.agent.model.timeout == 300
    # One capture at startup, shared by the lifecycle activities and the native guard.
    assert len(captures) == 1
    activities = created["activities"][0].__self__
    assert activities.bound_identity is created["interceptors"][0].bound_identity
