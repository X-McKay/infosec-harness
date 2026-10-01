"""Record actual intake SDK activities and replay across its independent patch marker."""

from __future__ import annotations

import asyncio
import json
import shutil
import uuid

import pytest
from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from pydantic import BaseModel
    from pydantic_ai.exceptions import UnexpectedModelBehavior
    from pydantic_ai.usage import UsageLimits

    from infosec_harness.agents.deps import AgentDeps
    from infosec_harness.agents.durable import AGENT_LIST, LEGACY_OUTPUT_AGENTS
    from infosec_harness.agents.render import render_prompt
    from infosec_harness.workflows.temporal_ops import TemporalOps


class _HistoricalDeps(BaseModel):
    # Encode the actual older wire shape, rather than a new field containing null.
    repo_path: str


async def _invoke(agent, args):
    deps = (AgentDeps.model_validate(args["deps"]) if "report_text" in args["deps"]
            else _HistoricalDeps.model_validate(args["deps"]))
    try:
        result = await agent.run(
            render_prompt("Extract the synthetic finding.", {"report": args["report"]}),
            deps=deps,
            usage_limits=UsageLimits(request_limit=4),
        )
    except UnexpectedModelBehavior:
        return {"generation": agent.name, "status": "rejected"}
    return {"generation": agent.name, "status": "accepted", "cwe": result.output.cwe}


@workflow.defn(name="IntakeEvidenceReplayFixture")
class _PreGuardWorkflow:
    __pydantic_ai_agents__ = AGENT_LIST

    @workflow.run
    async def run(self, args: dict) -> dict:
        assert workflow.patched("agent-output-contracts-v2")
        return await _invoke(LEGACY_OUTPUT_AGENTS["intake"], args)


@workflow.defn(name="IntakeEvidenceReplayFixture")
class _CurrentWorkflow:
    __pydantic_ai_agents__ = AGENT_LIST

    @workflow.run
    async def run(self, args: dict) -> dict:
        assert workflow.patched("agent-output-contracts-v2")
        return await _invoke(TemporalOps()._agent_for("intake"), args)


def _markers(history):
    return " ".join(payload.data.decode()
                    for event in history.events if event.HasField("marker_recorded_event_attributes")
                    for payloads in event.marker_recorded_event_attributes.details.values()
                    for payload in payloads.payloads)


def _model_events(history):
    return [event.activity_task_scheduled_event_attributes for event in history.events
            if event.HasField("activity_task_scheduled_event_attributes")
            and "model" in event.activity_task_scheduled_event_attributes.activity_type.name]


async def test_recorded_intake_with_old_deps_and_shared_marker_replays_without_new_guard(
    tmp_path, monkeypatch,
):
    from dataclasses import replace

    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from pydantic_ai.messages import ModelResponse, ToolCallPart
    from pydantic_ai.models.function import FunctionModel
    from temporalio.client import Client
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Replayer, Worker

    from infosec_harness.agents import models
    from infosec_harness.agents.durable import AGENTS
    from infosec_harness.agents.intake_contracts import retained_intake_spec
    from infosec_harness.agents.registry import build_agent
    from infosec_harness.settings import get_settings
    from infosec_harness.workflows import temporal_ops

    assert get_settings().model_mode == "stub"
    temporal = shutil.which("temporal")  # Host only: workflow sandbox remains enabled.
    if temporal is None:
        pytest.skip("temporal CLI not available")
    report = "Caller input is interpolated into a shell command."
    contradictory = {"cwe": None, "evidence": [
        {"field": "cwe", "quote": report, "confidence": 1}]}
    def respond(_messages, info):
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, contradictory)])

    # Worker plugins retain resolved models on shared agent singletons after earlier tests.
    # Fresh agents capture only this host resolver; all requests use the dedicated fixture.
    fixture_model = FunctionModel(respond)

    def resolve_fixture(name, _tier, *, durable=False):
        assert name == "intake" and durable
        return fixture_model

    monkeypatch.setattr(models, "resolve", resolve_fixture)
    legacy = build_agent("intake", legacy_output_contract=True, spec_override=retained_intake_spec(), atomic_output=False)
    current_agent = build_agent("intake", execution_name="intake-output-v2",
                                spec_override=retained_intake_spec(), atomic_output=False)
    # This fixture records the pre-adoption v2 worker. Its replay selector uses the same
    # immutable v2 bundle; canonical retained workers deny any newly executed provider call.
    def pre_adoption_generation(self, **kwargs):
        return (replace(temporal_ops.INTAKE_GENERATIONS["quoted"], agent=current_agent)
                if workflow.patched("intake-evidence-v1")
                else replace(temporal_ops.INTAKE_GENERATIONS["bare"], agent=legacy))
    monkeypatch.setattr(TemporalOps, "_intake_for", pre_adoption_generation)
    monkeypatch.setitem(LEGACY_OUTPUT_AGENTS, "intake", legacy)
    monkeypatch.setitem(AGENTS, "intake", current_agent)
    for fixture in (_PreGuardWorkflow, _CurrentWorkflow):
        monkeypatch.setattr(fixture, "__pydantic_ai_agents__", [legacy, current_agent])

    async def assert_recorded_responses(history):
        scheduled = {event.event_id for event in history.events
                     if event.HasField("activity_task_scheduled_event_attributes")
                     and "model" in event.activity_task_scheduled_event_attributes.activity_type.name}
        completed = [event.activity_task_completed_event_attributes for event in history.events
                     if event.HasField("activity_task_completed_event_attributes")
                     and event.activity_task_completed_event_attributes.scheduled_event_id in scheduled]
        assert len(completed) == len(scheduled) > 0
        for event in completed:
            responses = await client.data_converter.decode(event.result.payloads, [ModelResponse])
            assert [part.args for part in responses[0].parts if isinstance(part, ToolCallPart)] == [
                contradictory]

    args = {"deps": {"repo_path": str(tmp_path)}, "report": report}
    env = await WorkflowEnvironment.start_local(dev_server_existing_path=temporal)
    try:
        client = await Client.connect(env.client.service_client.config.target_host,
                                      plugins=[PydanticAIPlugin()])
        queue = "intake-evidence-replay-" + uuid.uuid4().hex[:12]
        async with Worker(client, task_queue=queue, workflows=[_PreGuardWorkflow]):
            old = await client.start_workflow(_PreGuardWorkflow.run, args,
                                             id=uuid.uuid4().hex, task_queue=queue)
            assert await asyncio.wait_for(old.result(), 45) == {
                "generation": "intake", "status": "accepted", "cwe": None}
        history = await old.fetch_history()
        await assert_recorded_responses(history)
        assert "agent-output-contracts-v2" in _markers(history)
        assert "intake-evidence-v1" not in _markers(history)
        events = _model_events(history)
        assert len(events) == 1 and "agent__intake__" in events[0].activity_type.name
        old_deps_payload = events[0].input.payloads[-1]
        assert json.loads(old_deps_payload.data) == args["deps"]
        decoded = await client.data_converter.decode([old_deps_payload], [AgentDeps])
        assert decoded[0].repo_path == str(tmp_path) and decoded[0].report_text is None
        # Replaying the old accepted response with the new guard would add a request
        # and fail determinism. The actual current selector must retain the old generation.
        await Replayer(workflows=[_CurrentWorkflow], plugins=[PydanticAIPlugin()]).replay_workflow(history)
        args["deps"]["report_text"] = report
        async with Worker(client, task_queue=queue, workflows=[_CurrentWorkflow]):
            current = await client.start_workflow(_CurrentWorkflow.run, args,
                                                 id=uuid.uuid4().hex, task_queue=queue)
            assert await asyncio.wait_for(current.result(), 45) == {
                "generation": "intake-output-v2", "status": "rejected"}
        current_history = await current.fetch_history()
        await assert_recorded_responses(current_history)
        assert "intake-evidence-v1" in _markers(current_history)
        current_events = _model_events(current_history)
        assert len(current_events) > 1
        assert all("agent__intake-output-v2__" in e.activity_type.name for e in current_events)
        assert json.loads(current_events[0].input.payloads[-1].data)["report_text"] == report
        await Replayer(workflows=[_CurrentWorkflow], plugins=[PydanticAIPlugin()]).replay_workflow(
            current_history)
    finally:
        await env.shutdown()
