"""Replay a real pre-guard model activity after the independent build patch lands."""

from __future__ import annotations

import asyncio
import shutil
import uuid

import pytest
from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from pydantic_ai.exceptions import UnexpectedModelBehavior
    from pydantic_ai.usage import UsageLimits

    from infosec_harness.agents.deps import AgentDeps
    from infosec_harness.agents.durable import AGENT_LIST, LEGACY_OUTPUT_AGENTS
    from infosec_harness.agents.render import render_prompt
    from infosec_harness.domain.models import EnvironmentSpec
    from infosec_harness.workflows.temporal_ops import TemporalOps

async def _invoke(agent, args):
    spec = EnvironmentSpec.model_validate(args["spec"])
    try:
        result = await agent.run(
            render_prompt("Repair the synthetic failed spec.", {"failed_spec": spec}),
            deps=AgentDeps(repo_path=args["repo"]),
            usage_limits=UsageLimits(request_limit=16),
        )
    except UnexpectedModelBehavior:
        return {"generation": agent.name, "status": "rejected"}
    return {"generation": agent.name, "status": "accepted",
            "spec_preserved": result.output == spec}


@workflow.defn(name="BuildInstallSourceReplayFixture")
class _PreGuardWorkflow:
    __pydantic_ai_agents__ = AGENT_LIST

    @workflow.run
    async def run(self, args: dict) -> dict:
        # An existing shared marker must not select the later build-specific contract.
        assert workflow.patched("agent-output-contracts-v2")
        return await _invoke(LEGACY_OUTPUT_AGENTS["build-repair"], args)


@workflow.defn(name="BuildInstallSourceReplayFixture")
class _CurrentWorkflow:
    __pydantic_ai_agents__ = AGENT_LIST

    @workflow.run
    async def run(self, args: dict) -> dict:
        assert workflow.patched("agent-output-contracts-v2")
        return await _invoke(TemporalOps()._agent_for("build-repair"), args)


def _markers(history) -> str:
    # Patch payloads are bounded fixture metadata, not model input or output.
    return " ".join(
        payload.data.decode()
        for event in history.events if event.HasField("marker_recorded_event_attributes")
        for payload in event.marker_recorded_event_attributes.details.values()
        for payload in payload.payloads
    )


def _model_activities(history) -> list[str]:
    return [event.activity_task_scheduled_event_attributes.activity_type.name
            for event in history.events if event.HasField("activity_task_scheduled_event_attributes")
            and "model" in event.activity_task_scheduled_event_attributes.activity_type.name]


async def test_recorded_old_build_replays_with_shared_marker_and_no_build_marker(tmp_path):
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Replayer, Worker

    temporal = shutil.which("temporal")
    if temporal is None:
        pytest.skip("temporal CLI not available")
    (tmp_path / "requirements.txt").write_text("pytest\n")
    spec = EnvironmentSpec(
        base_image="python:3.12-slim",
        install_commands=["python -m pip install --user --index-url "
                          "https://undeclared.invalid/simple -r requirements.txt"],
        test_command="python -m pytest -q -s -o addopts= {test_file}",
    )
    args = {"repo": str(tmp_path), "spec": spec.model_dump(mode="json")}
    env = await WorkflowEnvironment.start_local(dev_server_existing_path=temporal)
    try:
        client = await Client.connect(env.client.service_client.config.target_host,
                                      plugins=[PydanticAIPlugin()])
        queue = "build-source-replay-" + uuid.uuid4().hex[:12]
        async with Worker(client, task_queue=queue, workflows=[_PreGuardWorkflow]):
            handle = await client.start_workflow(_PreGuardWorkflow.run, args,
                                                id=uuid.uuid4().hex, task_queue=queue)
            old_result = await asyncio.wait_for(handle.result(), 45)
        assert old_result == {"generation": "build-repair", "status": "accepted",
                              "spec_preserved": True}
        history = await handle.fetch_history()
        markers = _markers(history)
        assert "agent-output-contracts-v2" in markers
        assert "build-repair-install-source-v1" not in markers
        activities = _model_activities(history)
        assert activities and all("agent__build-repair__" in name for name in activities)
        # This actually replays the recorded legacy model response through the current
        # selector. Applying the new validator would retry and mismatch the recorded history.
        await Replayer(workflows=[_CurrentWorkflow], plugins=[PydanticAIPlugin()]).replay_workflow(history)
        async with Worker(client, task_queue=queue, workflows=[_CurrentWorkflow]):
            current = await client.start_workflow(_CurrentWorkflow.run, args,
                                                 id=uuid.uuid4().hex, task_queue=queue)
            assert await asyncio.wait_for(current.result(), 45) == {
                "generation": "build-repair-output-v2", "status": "rejected"}
        current_history = await current.fetch_history()
        assert "build-repair-install-source-v1" in _markers(current_history)
        assert all("agent__build-repair-output-v2__" in name
                   for name in _model_activities(current_history))
        await Replayer(workflows=[_CurrentWorkflow], plugins=[PydanticAIPlugin()]).replay_workflow(
            current_history)
    finally:
        await env.shutdown()
