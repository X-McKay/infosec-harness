"""A tool allocation cannot bypass evidence validation or turn missing usage into zero."""

from types import SimpleNamespace

import pytest
from pydantic import BaseModel
from pydantic_ai import Agent, ModelRetry
from pydantic_ai.capabilities import PrepareTools
from pydantic_ai.exceptions import UnexpectedModelBehavior
from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.usage import UsageLimits

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.planning_window import PlanningWindow, PlanningWindowTelemetry

POLICY = PlanningWindow("build-tool-allocation-v1", 8, 16)


@pytest.mark.parametrize(
    "limit,target", [(16, 8), (48, 24), (10, 5), (3, 2), (2, 1), (1, 0), (None, None)]
)
def test_target_tracks_actual_scaled_or_root_clipped_ceiling(limit, target):
    assert POLICY.target(limit) == target


async def test_boundary_and_unknown_request_observation():
    tools = [SimpleNamespace(name="read_files")]

    def context(requests, limit=16):
        return SimpleNamespace(
            usage=SimpleNamespace(requests=requests), usage_limits=UsageLimits(request_limit=limit)
        )

    assert await POLICY.prepare_tools(context(7), tools) == tools
    assert await POLICY.prepare_tools(context(8), tools) == []
    assert await POLICY.prepare_tools(context(0, 1), tools) == []
    assert await POLICY.prepare_tools(context(None), tools) == []
    for requests in (None, -1, True):
        diagnostic = POLICY.diagnostic(16, requests)
        assert diagnostic["final_requests"] is None and diagnostic["cutoff_hit"] is None
    assert POLICY.diagnostic(16, 8)["cutoff_hit"] is False
    assert POLICY.diagnostic(16, 9)["cutoff_hit"] is True


class Evidence(BaseModel):
    supported: bool


def looping_model(log, bad_output=False):
    def model(messages, info):
        log.append((len(info.function_tools), len(info.output_tools)))
        if info.function_tools:
            return ModelResponse(parts=[ToolCallPart("read_files", {}, tool_call_id=str(len(log)))])
        return ModelResponse(
            parts=[
                ToolCallPart(
                    info.output_tools[0].name,
                    {"supported": not bad_output},
                    tool_call_id=str(len(log)),
                )
            ]
        )

    return FunctionModel(model)


def make_agent(log, bad_output=False, provider=None):
    agent = Agent(
        looping_model(log, bad_output),
        deps_type=AgentDeps,
        output_type=Evidence,
        capabilities=[PrepareTools(POLICY.prepare_tools), PlanningWindowTelemetry(POLICY)],
        retries=1,
    )

    @agent.tool_plain
    def read_files() -> str:
        return "bounded synthetic evidence"

    @agent.output_validator
    def validate(value: Evidence) -> Evidence:
        if not value.supported:
            raise ModelRetry("Evidence required")
        return value

    if provider is not None:
        from infosec_harness.telemetry import private_instrumentation

        agent.instrument = private_instrumentation(provider)
    return agent


async def test_actual_sdk_filters_functions_keeps_output_and_has_no_cross_run_counter():
    log = []
    agent = make_agent(log)
    for _ in range(2):
        before = len(log)
        result = await agent.run(
            "synthetic",
            deps=AgentDeps(repo_path="/tmp"),
            usage_limits=UsageLimits(request_limit=16),
        )
        assert result.usage.requests == 9 and result.output.supported
        assert log[before:] == [(1, 1)] * 8 + [(0, 1)]


async def test_cutoff_never_bypasses_output_evidence_validator():
    log = []
    agent = make_agent(log, bad_output=True)
    with pytest.raises(UnexpectedModelBehavior):
        await agent.run(
            "synthetic",
            deps=AgentDeps(repo_path="/tmp"),
            usage_limits=UsageLimits(request_limit=16),
        )
    assert log[-2:] == [(0, 1), (0, 1)]


async def test_real_sdk_span_records_measured_allocation_without_content():
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    agent = make_agent([], provider=provider)
    await agent.run(
        "synthetic-sensitive",
        deps=AgentDeps(repo_path="/tmp"),
        usage_limits=UsageLimits(request_limit=16),
    )
    attrs = [s.attributes for s in exporter.get_finished_spans()]
    observed = [a for a in attrs if "agent.planning_window.effective_target" in a]
    assert observed and observed[-1]["agent.planning_window.effective_target"] == 8
    assert observed[-1]["agent.planning_window.final_requests"] == 9
    assert observed[-1]["agent.planning_window.cutoff_hit"] == 1
    assert "synthetic-sensitive" not in str(attrs)
    provider.shutdown()


async def test_failed_run_does_not_export_partial_requests_as_final_usage():
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    agent = make_agent([], bad_output=True, provider=provider)
    with pytest.raises(UnexpectedModelBehavior):
        await agent.run(
            "synthetic-sensitive",
            deps=AgentDeps(repo_path="/tmp"),
            usage_limits=UsageLimits(request_limit=16),
        )
    spans = exporter.get_finished_spans()
    observed = [s for s in spans if "agent.planning_window.effective_target" in s.attributes]
    assert observed and observed[-1].attributes["agent.planning_window.effective_target"] == 8
    assert observed[-1].attributes["agent.planning_window.final_requests"] == -1
    assert observed[-1].attributes["agent.planning_window.cutoff_hit"] == -1
    assert not observed[-1].events
    provider.shutdown()


def test_policy_changes_frozen_effective_config_digest():
    from infosec_harness.agents.registry import load_spec, resolve_agent_config

    spec = load_spec("build-repair")
    policy = {
        "policy_version": "build-tool-allocation-v1",
        "target_requests": 8,
        "baseline_requests": 16,
    }
    updated = spec.model_copy(update={"metadata": {**spec.metadata, "planning_window": policy}})
    candidate = resolve_agent_config("build-repair", updated, durable=True)
    changed = updated.model_copy(
        update={
            "metadata": {**updated.metadata, "planning_window": {**policy, "target_requests": 7}}
        }
    )
    assert candidate.digest != resolve_agent_config("build-repair", changed, durable=True).digest
    assert candidate.effective_spec["metadata"]["planning_window"] == policy


async def test_workflow_observation_cannot_create_a_span_or_mutate_policy(monkeypatch):
    from infosec_harness.agents import planning_window

    records = []
    monkeypatch.setattr(planning_window.workflow, "in_workflow", lambda: True)
    monkeypatch.setattr(
        planning_window.workflow.logger, "info", lambda _fmt, value: records.append(value)
    )

    class ForbiddenTracer:
        def start_as_current_span(self, *_args, **_kwargs):
            raise AssertionError("Workflow instrumentation must not create random span IDs")

    ctx = SimpleNamespace(usage_limits=UsageLimits(request_limit=16), tracer=ForbiddenTracer())
    result = SimpleNamespace(usage=SimpleNamespace(requests=9))

    async def handler():
        return result

    capability = PlanningWindowTelemetry(POLICY)
    assert await capability.wrap_run(ctx, handler=handler) is result
    assert await capability.wrap_run(ctx, handler=handler) is result
    assert records[0] == records[1] == POLICY.diagnostic(16, 9)
    assert POLICY.target_requests == 8
