"""Actual Temporal activities replay retained intake and deny new retained frontiers."""

from __future__ import annotations

import asyncio
import shutil
import uuid

import pytest
from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from pydantic_ai.messages import ModelResponse, ToolCallPart
    from pydantic_ai.usage import UsageLimits

    from infosec_harness.agents.deps import AgentDeps
    from infosec_harness.agents.durable import AGENT_LIST, AGENTS, LEGACY_OUTPUT_AGENTS
    from infosec_harness.agents.intake_contracts import render_intake_prompt
    from infosec_harness.workflows.temporal_ops import TemporalOps


async def _record(agent, args):
    result = await agent.run(
        render_intake_prompt("synthetic", {"report": args["report"]}),
        deps=AgentDeps(repo_path="/synthetic", report_text=args["report"]),
        usage_limits=UsageLimits(request_limit=4),
    )
    return {"name": agent.name, "cwe": result.output.cwe}


@workflow.defn(name="AtomicIntakeReplayFixture")
class _Bare:
    @workflow.run
    async def run(self, args: dict):
        return await _record(LEGACY_OUTPUT_AGENTS["intake"], args)


@workflow.defn(name="AtomicIntakeReplayFixture")
class _Quoted:
    @workflow.run
    async def run(self, args: dict):
        assert workflow.patched("intake-evidence-v1")
        return await _record(AGENTS["intake"], args)


@workflow.defn(name="AtomicIntakeReplayFixture")
class _Adopted:
    __pydantic_ai_agents__ = AGENT_LIST

    @workflow.run
    async def run(self, args: dict):
        atomic = workflow.patched("intake-atomic-inline-v1")
        ops = TemporalOps(intake_atomic_inline=atomic)
        result = await ops.run_agent(
            "intake",
            ops.intake_prompt("synthetic", {"report": args["report"]}),
            AgentDeps(repo_path="/synthetic", report_text=args["report"]),
        )
        return {"name": ops._intake_for(check_frontier=False).agent.name, "cwe": result.output.cwe}


@workflow.defn(name="AtomicIntakeParkFixture")
class _ParkOld:
    def __init__(self):
        self.go = False

    @workflow.signal
    def resume(self):
        self.go = True

    @workflow.query
    def waiting(self) -> bool:
        return not self.go

    @workflow.run
    async def run(self, args: dict):
        await workflow.wait_condition(lambda: self.go)
        return await _record(LEGACY_OUTPUT_AGENTS["intake"], args)


@workflow.defn(name="AtomicIntakeParkFixture")
class _ParkAdopted:
    __pydantic_ai_agents__ = AGENT_LIST

    def __init__(self):
        self.go = False

    @workflow.signal
    def resume(self):
        self.go = True

    @workflow.query
    def waiting(self) -> bool:
        return not self.go

    @workflow.run
    async def run(self, args: dict):
        atomic = workflow.patched("intake-atomic-inline-v1")
        await workflow.wait_condition(lambda: self.go)
        try:
            await TemporalOps(intake_atomic_inline=atomic).run_agent(
                "intake", [], AgentDeps(repo_path="/synthetic", report_text=args["report"])
            )
        except RuntimeError:
            return "blocked-before-reserve-or-model"
        raise AssertionError("old parked workflow must not adopt a new request")


def _markers(history):
    return " ".join(
        payload.data.decode()
        for event in history.events
        if event.HasField("marker_recorded_event_attributes")
        for detail in event.marker_recorded_event_attributes.details.values()
        for payload in detail.payloads
    )


async def test_retained_completed_histories_and_atomic_entry_marker(tmp_path, monkeypatch):
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from pydantic_ai.models.function import FunctionModel
    from temporalio.client import Client
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Replayer, Worker

    from infosec_harness.agents import models
    from infosec_harness.agents.intake_contracts import retained_intake_spec
    from infosec_harness.agents.intake_generations import intake_generations
    from infosec_harness.agents.registry import build_agent
    from infosec_harness.workflows import temporal_ops

    temporal = shutil.which("temporal")
    if temporal is None:
        pytest.skip("managed temporal CLI unavailable")
    calls = []
    mode = {"retry": False, "requests": 0}
    retry_pending = asyncio.Event()

    async def respond(messages, info):
        calls.append(1)
        if mode["retry"]:
            mode["requests"] += 1
            if mode["requests"] == 1:
                return ModelResponse(
                    parts=[
                        ToolCallPart(
                            info.output_tools[0].name,
                            {
                                "cwe": None,
                                "evidence": [
                                    {
                                        "field": "cwe",
                                        "quote": "No operations or weakness mechanism described.",
                                        "confidence": 1.0,
                                    }
                                ],
                            },
                        )
                    ]
                )
            retry_pending.set()
            await asyncio.Event().wait()
        return ModelResponse(
            parts=[
                ToolCallPart(
                    info.output_tools[0].name,
                    {
                        "file_path": None,
                        "start_line": None,
                        "end_line": None,
                        "symbol": None,
                        "cwe": None,
                        "vulnerability_class": None,
                        "attack_preconditions": None,
                        "claimed_impact": None,
                    }
                    if "anyOf"
                    in info.output_tools[0].parameters_json_schema["properties"][
                        "attack_preconditions"
                    ]
                    else {"cwe": None},
                )
            ]
        )

    model = FunctionModel(respond, model_name="synthetic-intake")
    monkeypatch.setattr(models, "resolve", lambda *a, **kw: model)
    # Current atomic resolver must also use this independently authored local model.
    monkeypatch.setattr(models, "resolve_intake_atomic", lambda *a, **kw: model)
    retained = retained_intake_spec()
    recording = {
        "bare": build_agent(
            "intake",
            spec_override=retained,
            atomic_output=False,
            legacy_output_contract=True,
            execution_name="intake",
        ),
        "quoted": build_agent(
            "intake", spec_override=retained, atomic_output=False, execution_name="intake-output-v2"
        ),
    }
    monkeypatch.setitem(LEGACY_OUTPUT_AGENTS, "intake", recording["bare"])
    monkeypatch.setitem(AGENTS, "intake", recording["quoted"])
    intake_generations.cache_clear()
    bundles = intake_generations()
    monkeypatch.setattr(temporal_ops, "INTAKE_GENERATIONS", bundles)
    adopted_agents = [v.agent for v in bundles.values()]
    for cls in (_Bare, _Quoted, _ParkOld):
        monkeypatch.setattr(cls, "__pydantic_ai_agents__", list(recording.values()), raising=False)
    for cls in (_Adopted, _ParkAdopted):
        monkeypatch.setattr(cls, "__pydantic_ai_agents__", adopted_agents)
    env = await WorkflowEnvironment.start_local(dev_server_existing_path=temporal)
    try:
        client = await Client.connect(
            env.client.service_client.config.target_host, plugins=[PydanticAIPlugin()]
        )
        queue = "intake-atomic-replay-" + uuid.uuid4().hex[:12]
        args = {"report": "No operations or weakness mechanism described."}
        histories = []
        for cls, expected in [(_Bare, "intake"), (_Quoted, "intake-output-v2")]:
            async with Worker(client, task_queue=queue, workflows=[cls]):
                h = await client.start_workflow(
                    cls.run, args, id=uuid.uuid4().hex, task_queue=queue
                )
                assert await asyncio.wait_for(h.result(), 45) == {"name": expected, "cwe": None}
            histories.append(await h.fetch_history())
        count = len(calls)
        for history in histories:
            await Replayer(workflows=[_Adopted], plugins=[PydanticAIPlugin()]).replay_workflow(
                history
            )
        assert (
            len(calls) == count
        )  # Completed activity replay never executes retained wrapper/provider.
        async with Worker(client, task_queue=queue, workflows=[_Adopted]):
            h = await client.start_workflow(
                _Adopted.run, args, id=uuid.uuid4().hex, task_queue=queue
            )
            assert await asyncio.wait_for(h.result(), 45) == {
                "name": "intake-output-v3",
                "cwe": None,
            }
        history = await h.fetch_history()
        assert "intake-atomic-inline-v1" in _markers(history)
        await Replayer(workflows=[_Adopted], plugins=[PydanticAIPlugin()]).replay_workflow(history)
        # A historical v2 response is recorded, rejected by its existing validator, and
        # leaves a second SDK model activity pending. A replacement worker must not run
        # that pending/retry provider operation under the retained generation.
        from temporalio.api.enums.v1 import RetryState
        from temporalio.client import WorkflowFailureError
        from temporalio.exceptions import ActivityError, ApplicationError

        mode["retry"] = True
        async with Worker(client, task_queue=queue, workflows=[_Quoted]):
            pending = await client.start_workflow(
                _Quoted.run, args, id=uuid.uuid4().hex, task_queue=queue
            )
            await asyncio.wait_for(retry_pending.wait(), 30)
        before_pending = len(calls)
        async with Worker(client, task_queue=queue, workflows=[_Adopted]):
            with pytest.raises(WorkflowFailureError) as failure:
                await asyncio.wait_for(pending.result(), 45)
        assert isinstance(failure.value.cause, ActivityError)
        assert isinstance(failure.value.cause.cause, ApplicationError)
        assert failure.value.cause.cause.type == "RetainedModelUnavailable"
        assert failure.value.cause.cause.non_retryable is True
        assert len(calls) == before_pending
        pending_history = await pending.fetch_history()
        failures = [
            e.activity_task_failed_event_attributes
            for e in pending_history.events
            if e.HasField("activity_task_failed_event_attributes")
        ]
        assert failures[-1].retry_state == RetryState.RETRY_STATE_NON_RETRYABLE_FAILURE
        scheduled = [
            e.activity_task_scheduled_event_attributes
            for e in pending_history.events
            if e.HasField("activity_task_scheduled_event_attributes")
        ]
        assert len(scheduled) == 2  # First invalid response, then the existing validation retry.
        mode["retry"] = False
        async with Worker(client, task_queue=queue, workflows=[_ParkOld]):
            parked = await client.start_workflow(
                _ParkOld.run, args, id=uuid.uuid4().hex, task_queue=queue
            )
            # A query ensures the initial workflow task has replayable history without intake marker.
            assert await parked.query(_ParkOld.waiting) is True
        count = len(calls)
        async with Worker(client, task_queue=queue, workflows=[_ParkAdopted]):
            await parked.signal(_ParkAdopted.resume)
            assert await asyncio.wait_for(parked.result(), 45) == "blocked-before-reserve-or-model"
        assert len(calls) == count
        assert "intake-atomic-inline-v1" not in _markers(await parked.fetch_history())
    finally:
        await env.shutdown()
        intake_generations.cache_clear()
