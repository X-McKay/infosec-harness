"""The side-effecting operations the graph needs, behind one interface (D3).

`LocalOps` runs everything in-process (tests, evals, offline demos). `TemporalOps`
(workflows/temporal_ops.py) offloads to activities and durable agents. The graph nodes
only ever touch this interface, so the exact same topology runs standalone and durably.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

import httpx
from pydantic_ai.exceptions import ModelAPIError, UsageLimitExceeded
from pydantic_ai.messages import UserContent

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.domain.models import (
    AgentOutcome,
    BuildResult,
    EnvironmentSpec,
    InconclusiveReason,
    ProbeExecution,
    ProbeSource,
    RepoSnapshot,
    SmokeResult,
    StackFingerprint,
)


def is_infrastructure_failure(e: BaseException) -> bool:
    """True when the harness's own dependencies failed, rather than the work failing.

    A provider outage, a transport error or a run timeout says nothing about the repository or
    the finding, so it must not be recorded as `environment_unbuildable` -- an eval reading
    that cannot tell an endpoint being down from a pipeline regression.
    """
    return isinstance(e, ModelAPIError | httpx.TransportError | TimeoutError)


def classify_pipeline_failure(e: BaseException) -> InconclusiveReason:
    """Which ``InconclusiveReason`` an exception escaping a pipeline stage deserves.

    Classified by exception *type*, extending :func:`is_infrastructure_failure` rather than
    matching on message text: a provider's or a library's wording is not a contract, and a
    taxonomy built on strings silently reclassifies itself when one of them is reworded.

    Three outcomes the pipeline used to file under one reason, each with a different fix:

    - ``budget_exhausted`` -- a ceiling *we* set stopped the run; it was not answered. The fix
      is ours: raise the limit, or find the loop that burned it (which is what the per-agent
      ``repeated_tool_calls`` record exists to show). ``UsageLimitExceeded`` means exactly this,
      and the enum member already existed while nothing on this path ever produced it, so a
      budget breach during preparation was indistinguishable from a repository that will not
      build.
    - ``infrastructure_error`` -- our own dependency failed (provider outage, transport error,
      run timeout). Says nothing about the finding at all.
    - ``error`` -- the harness fell over some other way, which is a bug report, not a triage
      result.

    ``environment_unbuildable`` is deliberately *not* reachable from here. It is a claim about
    the repository -- "preparation ran to completion and produced no usable environment" -- and
    a completed ``run_prepare`` makes that claim itself by returning ``status != "ready"``. An
    exception is not that claim: a preparation that crashed never reached a verdict on the
    repository, so recording one put the blame on a stage that had not finished being tried.
    """
    if isinstance(e, UsageLimitExceeded):
        return InconclusiveReason.budget_exhausted
    if is_infrastructure_failure(e):
        return InconclusiveReason.infrastructure_error
    return InconclusiveReason.error


class Ops(Protocol):
    async def run_agent(
        self, name: str, prompt: Sequence[UserContent], deps: AgentDeps
    ) -> AgentOutcome: ...

    async def new_nonce(self) -> str: ...

    async def build_environment(self, snapshot: RepoSnapshot, spec: EnvironmentSpec) -> BuildResult: ...

    async def smoke_test(self, image_tag: str, test_command: str = "", *,
                         language: str = "", module_path: str = "") -> SmokeResult: ...

    async def lookup_recipe(self, stack: StackFingerprint) -> EnvironmentSpec | None: ...

    async def record_recipe(self, stack: StackFingerprint, spec: EnvironmentSpec,
                            *, worked: bool) -> None: ...

    async def execute_probe(
        self, image_tag: str, probe: ProbeSource, spec: EnvironmentSpec, nonce: str, attempt: int
    ) -> ProbeExecution: ...


class LocalOps:
    """Direct, in-process implementation for standalone runs, tests, and evals."""

    def __init__(self, *, sandbox: bool = True, recipe_cache: bool = True):
        self._sandbox = sandbox
        # Off during corpus scoring. The cache is a latency win, not an accuracy one, and with
        # it on the first repository of a stack records a recipe that every later repository of
        # that stack then reuses -- so env-planner runs once instead of eighteen times and the
        # stage funnel loses the signal it exists to provide. Measured: the trajectory report
        # dropped env-planner entirely, and whether it did so depended on what a previous run
        # had left on disk.
        self._recipe_cache = recipe_cache

    async def run_agent(self, name: str, prompt, deps: AgentDeps) -> AgentOutcome:
        import asyncio
        import time

        from infosec_harness import telemetry
        from infosec_harness.agents import models as model_factory
        from infosec_harness.agents.budgets import usage_limits_for
        from infosec_harness.agents.registry import build_agent, config_hash, load_spec
        from infosec_harness.evals.trajectory import count_repeated_calls, inspect_messages
        from infosec_harness.settings import get_settings

        agent = build_agent(name, durable=False)
        spec = load_spec(name)
        model_name = model_factory.resolved_model_name(name, spec.model or "sonnet")
        attrs = telemetry.agent_run_attributes(name, model_name, config_hash(name, spec))
        start = time.monotonic()
        timeout = get_settings().agent_run_timeout_s
        with telemetry.agent_span(name, attrs) as span:
            try:
                result = await asyncio.wait_for(
                    agent.run(list(prompt), deps=deps,
                              usage_limits=usage_limits_for(
                                  name, spec.metadata, source_files=deps.source_files)),
                    timeout=timeout,
                )
            except TimeoutError as e:
                # A hung provider request never fails on its own, so neither the client's
                # retries nor a budget will end it. Observed repeatedly against the test
                # endpoint: a corpus run sat for twenty minutes on one request. Surface it as
                # the infrastructure failure it is; callers contain it per finding.
                raise TimeoutError(
                    f"agent {name!r} exceeded HARNESS_AGENT_RUN_TIMEOUT_S={timeout}s"
                ) from e
        usage = result.usage
        cost, estimated = model_factory.estimate_cost(model_name, usage)
        tools_called, skills_loaded = inspect_messages(messages := result.all_messages())
        repeated = count_repeated_calls(messages)
        outcome = AgentOutcome(
            output=result.output, agent=name, model_name=model_name, config_hash=config_hash(name, spec),
            input_tokens=usage.input_tokens, output_tokens=usage.output_tokens,
            cache_read_tokens=usage.cache_read_tokens or 0, cache_write_tokens=usage.cache_write_tokens or 0,
            cost_usd=cost, cost_estimated=estimated, latency_s=time.monotonic() - start,
            tools_called=tools_called, skills_loaded=skills_loaded,
            requests=usage.requests or 0, repeated_tool_calls=repeated,
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

    async def smoke_test(self, image_tag, test_command: str = "", *,
                         language: str = "", module_path: str = "") -> SmokeResult:
        if not self._sandbox:
            return SmokeResult(ok=True)
        from infosec_harness.workflows.activities import smoke_test_activity

        return await smoke_test_activity({"image_tag": image_tag, "test_command": test_command,
                                         "language": language, "module_path": module_path})

    async def lookup_recipe(self, stack: StackFingerprint) -> EnvironmentSpec | None:
        if not self._recipe_cache:
            return None
        from infosec_harness.persistence.recipes import get_recipe_store, stack_key

        return get_recipe_store().lookup(stack_key(stack))

    async def record_recipe(self, stack: StackFingerprint, spec: EnvironmentSpec,
                            *, worked: bool) -> None:
        """Keep a spec that built, drop one that did not.

        Eviction on first failure is the whole safety story: a stale recipe costs exactly one
        build attempt, once, and then stops existing.
        """
        if not self._recipe_cache:
            return
        from infosec_harness.persistence.recipes import get_recipe_store, is_cacheable, stack_key

        store, key = get_recipe_store(), stack_key(stack)
        if worked and is_cacheable(spec):
            store.record(key, spec)
        elif not worked:
            store.forget(key)

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
                                  precondition_reached=False, sink_returned=False,
                                  stderr_tail=self.SANDBOX_DISABLED)
        from infosec_harness.workflows.activities import execute_probe_activity

        return await execute_probe_activity(
            {"image_tag": image_tag, "probe": probe.model_dump(), "spec": spec.model_dump(),
             "nonce": nonce, "attempt": attempt}
        )

