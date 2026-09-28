"""Ops implementation that runs inside a Temporal workflow (D3).

Agent calls go to the durable agents (their model/tool calls become activities via
TemporalDurability); deterministic side effects go to activities. Bookkeeping uses
precomputed, cached maps so nothing here does disk or config I/O inside the workflow.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta

from pydantic_ai.messages import UserContent
from temporalio import workflow
from temporalio.common import RetryPolicy

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.domain.models import (
    BuildResult,
    EnvironmentSpec,
    ProbeExecution,
    ProbeSource,
    RepoSnapshot,
    SmokeResult,
    StackFingerprint,
)
from infosec_harness.graph.ops import AgentOutcome

with workflow.unsafe.imports_passed_through():
    from infosec_harness.agents import models as model_factory
    from infosec_harness.agents.durable import AGENTS
    from infosec_harness.agents.registry import (
        agent_config_hashes,
        agent_usage_limits,
        resolved_model_names,
    )
    from infosec_harness.evals.trajectory import count_repeated_calls, inspect_messages
    from infosec_harness.workflows import activities


# Temporal's default retry policy is *unlimited* attempts. A deterministic programming
# error in one of these activities (a bad signature, a validation failure) would then retry
# forever and the workflow would hang rather than fail — silently holding a worker slot.
# Bound the attempts and never retry the error classes that cannot succeed on a retry.
_NON_RETRYABLE = ["TypeError", "ValueError", "AttributeError", "KeyError", "ValidationError"]
_RETRY = RetryPolicy(maximum_attempts=3, non_retryable_error_types=_NON_RETRYABLE)


class TemporalOps:
    """Bound to one workflow execution; created inside the workflow's run method."""

    def __init__(self) -> None:
        self._agents = AGENTS
        self._hashes = agent_config_hashes()
        self._models = resolved_model_names()
        # Precomputed on the host: reading a spec inside a workflow would be I/O.
        self._limits = agent_usage_limits()

    async def run_agent(self, name: str, prompt: Sequence[UserContent], deps: AgentDeps) -> AgentOutcome:
        agent = self._agents[name]
        started = workflow.now()
        result = await agent.run(list(prompt), deps=deps, usage_limits=self._limits[name])
        usage = result.usage
        model_name = self._models[name]
        cost, estimated = model_factory.estimate_cost(model_name, usage)
        tools_called, skills_loaded = inspect_messages(messages := result.all_messages())
        repeated = count_repeated_calls(messages)
        return AgentOutcome(
            output=result.output, agent=name, model_name=model_name, config_hash=self._hashes[name],
            input_tokens=usage.input_tokens, output_tokens=usage.output_tokens,
            cache_read_tokens=usage.cache_read_tokens or 0, cache_write_tokens=usage.cache_write_tokens or 0,
            cost_usd=cost, cost_estimated=estimated,
            latency_s=(workflow.now() - started).total_seconds(),
            tools_called=tools_called, skills_loaded=skills_loaded,
            requests=usage.requests or 0, repeated_tool_calls=repeated,
        )

    async def new_nonce(self) -> str:
        return await workflow.execute_activity(
            activities.new_nonce_activity, start_to_close_timeout=timedelta(seconds=10),
            retry_policy=_RETRY,
        )

    async def build_environment(self, snapshot: RepoSnapshot, spec: EnvironmentSpec) -> BuildResult:
        return await workflow.execute_activity(
            activities.build_environment_activity,
            {"snapshot": snapshot.model_dump(), "spec": spec.model_dump()},
            start_to_close_timeout=timedelta(minutes=40),
            retry_policy=_RETRY,
        )

    async def smoke_test(self, image_tag: str, test_command: str = "") -> SmokeResult:
        return await workflow.execute_activity(
            activities.smoke_test_activity,
            {"image_tag": image_tag, "test_command": test_command},
            start_to_close_timeout=timedelta(minutes=3), retry_policy=_RETRY,
        )

    async def lookup_recipe(self, stack: StackFingerprint) -> EnvironmentSpec | None:
        return await workflow.execute_activity(
            activities.lookup_recipe_activity,
            stack,
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_RETRY,
        )

    async def record_recipe(self, stack: StackFingerprint, spec: EnvironmentSpec,
                            *, worked: bool) -> None:
        await workflow.execute_activity(
            activities.record_recipe_activity,
            {"stack": stack.model_dump(mode="json"), "spec": spec.model_dump(mode="json"),
             "worked": worked},
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_RETRY,
        )

    async def execute_probe(
        self, image_tag: str, probe: ProbeSource, spec: EnvironmentSpec, nonce: str, attempt: int
    ) -> ProbeExecution:
        return await workflow.execute_activity(
            activities.execute_probe_activity,
            {"image_tag": image_tag, "probe": probe.model_dump(), "spec": spec.model_dump(),
             "nonce": nonce, "attempt": attempt},
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=_RETRY,
        )
