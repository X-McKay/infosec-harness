"""The side-effecting operations the graph needs, behind one interface (D3).

`LocalOps` runs everything in-process (tests, evals, offline demos). `TemporalOps`
(workflows/temporal_ops.py) offloads to activities and durable agents. The graph nodes
only ever touch this interface, so the exact same topology runs standalone and durably.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from pydantic_ai.messages import UserContent

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.domain.models import (
    AgentOutcome,
    BuildResult,
    EnvironmentSpec,
    ProbeExecution,
    ProbeSource,
    RepoSnapshot,
    SmokeResult,
)


class Ops(Protocol):
    async def run_agent(
        self, name: str, prompt: Sequence[UserContent], deps: AgentDeps
    ) -> AgentOutcome: ...

    async def new_nonce(self) -> str: ...

    async def build_environment(self, snapshot: RepoSnapshot, spec: EnvironmentSpec) -> BuildResult: ...

    async def smoke_test(self, image_tag: str) -> SmokeResult: ...

    async def execute_probe(
        self, image_tag: str, probe: ProbeSource, spec: EnvironmentSpec, nonce: str, attempt: int
    ) -> ProbeExecution: ...


class LocalOps:
    """Direct, in-process implementation for standalone runs, tests, and evals."""

    def __init__(self, *, sandbox: bool = True):
        self._sandbox = sandbox

    async def run_agent(self, name: str, prompt, deps: AgentDeps) -> AgentOutcome:
        import time

        from infosec_harness import telemetry
        from infosec_harness.agents import models as model_factory
        from infosec_harness.agents.budgets import usage_limits_for
        from infosec_harness.agents.registry import build_agent, config_hash, load_spec
        from infosec_harness.evals.trajectory import inspect_messages

        agent = build_agent(name, durable=False)
        spec = load_spec(name)
        model_name = model_factory.resolved_model_name(name, spec.model or "sonnet")
        attrs = telemetry.agent_run_attributes(name, model_name, config_hash(name, spec))
        start = time.monotonic()
        with telemetry.agent_span(name, attrs) as span:
            result = await agent.run(list(prompt), deps=deps,
                                     usage_limits=usage_limits_for(name, spec.metadata))
        usage = result.usage
        cost, estimated = model_factory.estimate_cost(model_name, usage)
        tools_called, skills_loaded = inspect_messages(result.all_messages())
        outcome = AgentOutcome(
            output=result.output, agent=name, model_name=model_name, config_hash=config_hash(name, spec),
            input_tokens=usage.input_tokens, output_tokens=usage.output_tokens,
            cache_read_tokens=usage.cache_read_tokens or 0, cache_write_tokens=usage.cache_write_tokens or 0,
            cost_usd=cost, cost_estimated=estimated, latency_s=time.monotonic() - start,
            tools_called=tools_called, skills_loaded=skills_loaded,
        )
        span.set_attributes(telemetry.outcome_attributes(outcome))
        return outcome

    async def new_nonce(self) -> str:
        import secrets

        return secrets.token_hex(8)

    async def build_environment(self, snapshot, spec) -> BuildResult:
        if not self._sandbox:
            return BuildResult(ok=True, image_tag="local-noop", spec=spec)
        from infosec_harness.workflows.activities import build_environment_activity

        return await build_environment_activity(
            {"snapshot": snapshot.model_dump(), "spec": spec.model_dump()}
        )

    async def smoke_test(self, image_tag) -> SmokeResult:
        if not self._sandbox:
            return SmokeResult(ok=True)
        from infosec_harness.workflows.activities import smoke_test_activity

        return await smoke_test_activity(image_tag)

    # Mirrors the shape `execute_probe_activity` returns when the isolation runtime is
    # missing, so the offline path stands in for the real one instead of contradicting it.
    SANDBOX_DISABLED = "sandbox disabled: probe not executed (running with --no-sandbox)"

    async def execute_probe(self, image_tag, probe, spec, nonce, attempt) -> ProbeExecution:
        if not self._sandbox:
            # Offline: don't touch Docker. Report honestly that the probe never ran.
            #
            # Claiming `exit_code=0, precondition_reached=True` here would be a *clean run
            # that found nothing*, which is a materially different thing: probe-diagnosis
            # reads the probe source alongside those markers, decides the probe must be
            # defective because a known-vulnerable target produced no oracle, and the graph
            # enters its repair loop — on every case, to the repair limit. That made the
            # documented Docker-free mode both far slower and unrepresentative, and it
            # inflated probe-repair's share of the trajectory metrics.
            return ProbeExecution(attempt=attempt, exit_code=None, oracle_fired=False,
                                  precondition_reached=False,
                                  stderr_tail=self.SANDBOX_DISABLED)
        from infosec_harness.workflows.activities import execute_probe_activity

        return await execute_probe_activity(
            {"image_tag": image_tag, "probe": probe.model_dump(), "spec": spec.model_dump(),
             "nonce": nonce, "attempt": attempt}
        )

