"""Ops implementation that runs inside a Temporal workflow (D3).

Agent calls go to the durable agents (their model/tool calls become activities via
TemporalDurability); deterministic side effects go to activities. Bookkeeping uses
precomputed, cached maps so nothing here does disk or config I/O inside the workflow.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
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
    from infosec_harness.agents.durable import AGENTS, CONFIGS, LEGACY_OUTPUT_AGENTS, MODELS
    from infosec_harness.evals.trajectory import count_repeated_calls, inspect_messages
    from infosec_harness.workflows import activities
    from infosec_harness.workflows.accounting import RootAccounting


# Temporal's default retry policy is *unlimited* attempts. A deterministic programming
# error in one of these activities (a bad signature, a validation failure) would then retry
# forever and the workflow would hang rather than fail — silently holding a worker slot.
# Bound the attempts and never retry the error classes that cannot succeed on a retry.
_NON_RETRYABLE = ["TypeError", "ValueError", "AttributeError", "KeyError", "ValidationError"]
_RETRY = RetryPolicy(maximum_attempts=3, non_retryable_error_types=_NON_RETRYABLE)


class TemporalOps:
    """Bound to one workflow execution; created inside the workflow's run method."""

    def __init__(self) -> None:
        self._accounting = RootAccounting()
        self._agents = AGENTS
        self._legacy_output_agents = LEGACY_OUTPUT_AGENTS
        self._configs = CONFIGS
        self._models = MODELS
        # Precomputed on the host: reading a spec inside a workflow would be I/O. The immutable
        # config retains its declared budget and applies repository-size scaling replay-safely.

    async def run_agent(
        self, name: str, prompt: Sequence[UserContent], deps: AgentDeps
    ) -> AgentOutcome:
        # Resolve the replay generation before any accounting activity. If an old execution
        # has reached a live frontier without a recorded model request, fail without mutating
        # budget state or issuing current behavior under historical provenance.
        self._agent_for(name)
        config = self._configs[name].for_source_files(deps.source_files)
        identity = await self._accounting.reserve(
            config, configuration_digest=self._configs[name].digest
        )
        try:
            outcome = await self._run_agent(name, prompt, deps)
        except (Exception, asyncio.CancelledError) as exc:
            await self._accounting.settle(identity, None, type(exc).__name__)
            raise
        await self._accounting.settle(identity, outcome)
        return outcome

    async def _run_agent(
        self, name: str, prompt: Sequence[UserContent], deps: AgentDeps
    ) -> AgentOutcome:
        # Keep this three-argument seam stable for failure injection and recovery tests.
        # run_agent already performed the fail-closed check before accounting; selecting
        # again is pure and returns the same workflow-patched generation.
        agent = self._agent_for(name)
        started = workflow.now()
        effective_config = self._configs[name].for_source_files(deps.source_files)
        result = await agent.run(
            list(prompt), deps=deps, usage_limits=effective_config.budget.to_usage_limits()
        )
        usage = result.usage
        model_name = self._models[name]
        cost, estimated = model_factory.estimate_cost(model_name, usage)
        tools_called, skills_loaded = inspect_messages(messages := result.all_messages())
        repeated = count_repeated_calls(messages)
        return AgentOutcome(
            output=result.output,
            agent=name,
            model_name=model_name,
            config_hash=effective_config.digest,
            effective_config=effective_config.model_dump(mode="json"),
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_read_tokens=usage.cache_read_tokens or 0,
            cache_write_tokens=usage.cache_write_tokens or 0,
            cost_usd=cost,
            cost_estimated=estimated,
            latency_s=(workflow.now() - started).total_seconds(),
            tools_called=tools_called,
            skills_loaded=skills_loaded,
            requests=usage.requests or 0,
            tool_calls=usage.tool_calls,
            repeated_tool_calls=repeated,
        )

    def _agent_for(self, name: str):
        """Select the output-contract generation as a replay-recorded workflow decision."""
        # Old histories contain `final_result` payloads parsed by the original contracts.
        # Record one workflow patch decision before scheduling the model activity, then keep
        # each history on the matching Temporal activity identity forever.
        patch = {
            "build-repair": "build-repair-install-source-v1",
            "intake": "intake-evidence-v1",
        }.get(name, "agent-output-contracts-v2")
        if name in self._legacy_output_agents and not workflow.patched(patch):
            # Only the parser and activity identity are retained here; the historical prompt
            # and resolved model config are not. A fresh request would therefore create new
            # behavior with false old provenance. Recorded or pending activities replay, but
            # an old execution which first reaches this agent after deployment fails closed.
            if not workflow.unsafe.is_replaying():
                raise RuntimeError(
                    f"legacy {name} execution has no recorded model activity; "
                    "retry the triage as a new workflow"
                )
            return self._legacy_output_agents[name]
        return self._agents[name]

    async def new_nonce(self) -> str:
        return await workflow.execute_activity(
            activities.new_nonce_activity,
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=_RETRY,
        )

    async def build_environment(self, snapshot: RepoSnapshot, spec: EnvironmentSpec) -> BuildResult:
        return await self._execute_workload(
            activities.build_environment_activity,
            {"snapshot": snapshot.model_dump(), "spec": spec.model_dump()},
            start_to_close_timeout=timedelta(minutes=40),
            retry_policy=_RETRY,
        )

    async def smoke_test(
        self, image_tag: str, test_command: str = "", *, language: str = "", module_path: str = ""
    ) -> SmokeResult:
        return await self._execute_workload(
            activities.smoke_test_activity,
            {
                "image_tag": image_tag,
                "test_command": test_command,
                "language": language,
                "module_path": module_path,
            },
            # Longer than the runner check alone: this also compiles and runs a canary test
            # inside the image, which on a JVM project means a Maven invocation.
            start_to_close_timeout=timedelta(minutes=8),
            retry_policy=_RETRY,
        )

    async def lookup_recipe(self, stack: StackFingerprint) -> EnvironmentSpec | None:
        return await workflow.execute_activity(
            activities.lookup_recipe_activity,
            stack,
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_RETRY,
        )

    async def record_recipe(
        self, stack: StackFingerprint, spec: EnvironmentSpec, *, worked: bool
    ) -> None:
        await workflow.execute_activity(
            activities.record_recipe_activity,
            {
                "stack": stack.model_dump(mode="json"),
                "spec": spec.model_dump(mode="json"),
                "worked": worked,
            },
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_RETRY,
        )

    async def execute_probe(
        self, image_tag: str, probe: ProbeSource, spec: EnvironmentSpec, nonce: str, attempt: int
    ) -> ProbeExecution:
        return await self._execute_workload(
            activities.execute_probe_activity,
            {
                "image_tag": image_tag,
                "probe": probe.model_dump(),
                "spec": spec.model_dump(),
                "nonce": nonce,
                "attempt": attempt,
            },
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=_RETRY,
        )

    async def _execute_workload[T](
        self,
        activity: Callable[[dict], Awaitable[T]],
        args: dict,
        *,
        start_to_close_timeout: timedelta,
        retry_policy: RetryPolicy,
    ) -> T:
        """Reserve the full retry envelope before any sandbox workload is dispatched."""
        identity = await self._accounting.reserve_execution(
            activity.__name__,
            start_to_close_timeout.total_seconds() * (retry_policy.maximum_attempts or 1),
        )
        options = {}
        if workflow.patched("workload-heartbeat-v1"):
            options = {
                "heartbeat_timeout": timedelta(seconds=30),
                "cancellation_type": workflow.ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
            }
        try:
            result = await workflow.execute_activity(
                activity,
                args,
                start_to_close_timeout=start_to_close_timeout,
                retry_policy=retry_policy,
                **options,
            )
        except (Exception, asyncio.CancelledError) as exc:
            await self._accounting.settle(identity, None, type(exc).__name__)
            raise
        # An activity return does not expose resource use of lost/retried attempts.
        await self._accounting.settle(identity, None, "completed; retry resource usage unobserved")
        return result
