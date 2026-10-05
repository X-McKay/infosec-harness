"""The side-effecting operations the graph needs, behind one interface (D3).

`LocalOps` runs everything in-process (tests, evals, offline demos). `TemporalOps`
(workflows/temporal_ops.py) offloads to activities and durable agents. The graph nodes
only ever touch this interface, so the exact same topology runs standalone and durably.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import Any, Protocol

import httpx
from pydantic_ai.exceptions import ModelAPIError, UsageLimitExceeded
from pydantic_ai.messages import UserContent

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.domain.models import (
    AgentOutcome,
    BuildResult,
    EnvironmentSpec,
    Finding,
    FindingInput,
    InconclusiveReason,
    ProbeExecution,
    ProbeSource,
    RepoSnapshot,
    SmokeResult,
    StackFingerprint,
)


def _failure_chain(e: BaseException) -> Iterator[BaseException]:
    """Yield wrapper causes once, including Temporal's serialized failure chain."""
    seen: set[int] = set()
    current: BaseException | None = e
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = getattr(current, "cause", None) or current.__cause__


def _application_error_type(e: BaseException) -> str | None:
    """The serialized type name of a Temporal ``ApplicationError``, without importing Temporal.

    Classification runs on both paths, and the in-process one must not depend on Temporal.
    """
    if any(cls.__name__ == "ApplicationError" for cls in type(e).__mro__):
        value = getattr(e, "type", None)
        return value if isinstance(value, str) else None
    return None


def is_infrastructure_failure(e: BaseException) -> bool:
    """True when the harness's own dependencies failed, rather than the work failing.

    A provider outage, a transport error or a run timeout says nothing about the repository or
    the finding, so it must not be recorded as `environment_unbuildable` -- an eval reading
    that cannot tell an endpoint being down from a pipeline regression.
    """
    serialized_types = {"ModelAPIError", "ModelHTTPError", "APIConnectionError", "APITimeoutError",
                        "ConnectError", "ReadTimeout", "TimeoutError", "BrokerError"}
    from infosec_harness.inference.protocol import BrokerError
    return any(isinstance(cause, ModelAPIError | httpx.TransportError | TimeoutError | BrokerError)
        or _application_error_type(cause) in serialized_types
        for cause in _failure_chain(e))


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
    if any(isinstance(cause, UsageLimitExceeded)
           or _application_error_type(cause) == "UsageLimitExceeded"
           for cause in _failure_chain(e)):
        return InconclusiveReason.budget_exhausted
    if is_infrastructure_failure(e):
        return InconclusiveReason.infrastructure_error
    return InconclusiveReason.error


class Ops(Protocol):
    async def normalize_finding(self, inp: FindingInput) -> Finding: ...

    async def resolve_location(self, finding: Finding, repo_path: str) -> Finding | None: ...

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

    # Mirrors the shape the probe workload returns when the isolation runtime is missing, so
    # the offline path stands in for the real one instead of contradicting it.
    SANDBOX_DISABLED = "sandbox disabled: probe not executed (running with --no-sandbox)"

    def __init__(self, *, sandbox: bool = True, recipe_cache: bool | None = None):
        import uuid

        from infosec_harness.persistence.recipes import get_recipe_store

        self._broker_run_id = str(uuid.uuid4())
        self._broker_sequence = 0
        self._broker_used = False
        self._broker_closed = False
        self._sandbox = sandbox
        # Off during corpus scoring. The cache is a latency win, not an accuracy one, and with
        # it on the first repository of a stack records a recipe that every later repository of
        # that stack then reuses -- so env-planner runs once instead of eighteen times and the
        # stage funnel loses the signal it exists to provide. None follows the settings switch.
        self._recipes = get_recipe_store(recipe_cache)
        self._agents: dict[str, tuple[Any, Any]] = {}

    def _agent(self, name: str):
        """The agent and its base configuration, resolved once per operations instance."""
        if name not in self._agents:
            from infosec_harness.agents.registry import build_agent, load_spec, resolve_agent_config

            self._agents[name] = (build_agent(name, durable=False),
                                  resolve_agent_config(name, load_spec(name), durable=False))
        return self._agents[name]

    async def normalize_finding(self, inp: FindingInput) -> Finding:
        from infosec_harness.intake.adapters import to_finding

        return to_finding(inp)

    async def resolve_location(self, finding: Finding, repo_path: str) -> Finding | None:
        from infosec_harness.intake.adapters import resolve_location

        return resolve_location(finding, repo_path)

    async def run_agent(self, name: str, prompt, deps: AgentDeps) -> AgentOutcome:
        import asyncio
        import time

        from pydantic_ai import capture_run_messages

        from infosec_harness import telemetry
        from infosec_harness.graph.pipeline import agent_outcome, partial_outcome
        from infosec_harness.settings import get_settings

        if self._broker_closed:
            raise RuntimeError("Local operations have been closed")
        agent, base_config = self._agent(name)
        config = base_config.for_source_files(deps.source_files)
        if config.model.broker_contract is not None:
            from infosec_harness.inference.invocations import request_invocation
            from infosec_harness.inference.protocol import InvocationRequest, digest
            self._broker_used = True
            contract = config.model.broker_contract
            ordinal = self._broker_sequence
            self._broker_sequence += 1
            invocation = f"{self._broker_run_id}:{ordinal}:{name}"
            binding = await request_invocation(InvocationRequest(
                mode="local", root_id=digest({"local_run": self._broker_run_id}),
                run_id=self._broker_run_id, invocation_id=invocation, operation_id=invocation,
                agent=name, configuration_digest=base_config.digest, contract=contract))
            deps = deps.model_copy(update={"broker_binding": binding, "broker_contract": contract})
        attrs = telemetry.agent_run_attributes(name, config.model.resolved_model, config.digest)
        start = time.monotonic()
        timeout = get_settings().agent_run_timeout_s
        with telemetry.agent_span(name, attrs) as span, capture_run_messages() as messages:
            try:
                result = await asyncio.wait_for(
                    agent.run(list(prompt), deps=deps,
                              usage_limits=config.budget.to_usage_limits()),
                    timeout=timeout,
                )
            except Exception as e:
                # Record the failed call's observed usage on the error for the graph to keep.
                e.agent_outcome = partial_outcome(  # type: ignore[attr-defined]
                    name, messages, config, time.monotonic() - start, e)
                if not isinstance(e, TimeoutError):
                    raise
                # A hung provider request never fails on its own, so neither the client's
                # retries nor a budget will end it. Surface it as the infrastructure failure it
                # is; callers contain it per finding.
                raise TimeoutError(
                    f"agent {name!r} exceeded HARNESS_AGENT_RUN_TIMEOUT_S={timeout}s"
                ) from e
            outcome = agent_outcome(name, result, config, time.monotonic() - start)
            span.set_attributes(telemetry.outcome_attributes(outcome))
        return outcome

    async def close(self) -> None:
        if self._broker_closed:
            return
        if self._broker_used:
            from infosec_harness.inference.invocations import close_run
            from infosec_harness.inference.protocol import digest
            await close_run(self._broker_run_id, digest({"local_run": self._broker_run_id}))
        self._broker_closed = True

    async def new_nonce(self) -> str:
        import secrets

        return secrets.token_hex(8)

    async def build_environment(self, snapshot, spec) -> BuildResult:
        if not self._sandbox:
            return BuildResult(ok=True, image_tag="local-noop", spec=spec)
        from infosec_harness.graph import workloads

        return await workloads.build_environment(snapshot, spec)

    async def smoke_test(self, image_tag, test_command: str = "", *,
                         language: str = "", module_path: str = "") -> SmokeResult:
        if not self._sandbox:
            return SmokeResult(ok=True)
        from infosec_harness.graph import workloads

        return await workloads.smoke_test(image_tag, test_command, language=language,
                                          module_path=module_path)

    async def lookup_recipe(self, stack: StackFingerprint) -> EnvironmentSpec | None:
        from infosec_harness.persistence.recipes import lookup_recipe

        return lookup_recipe(stack, self._recipes)

    async def record_recipe(self, stack: StackFingerprint, spec: EnvironmentSpec,
                            *, worked: bool) -> None:
        from infosec_harness.persistence.recipes import record_recipe_outcome

        record_recipe_outcome(stack, spec, worked=worked, store=self._recipes)

    async def execute_probe(self, image_tag, probe, spec, nonce, attempt) -> ProbeExecution:
        if not self._sandbox:
            # Offline: don't touch Docker. Report honestly that the probe never ran.
            #
            # Claiming `exit_code=0, precondition_reached=True` here would be a *clean run
            # that found nothing*, which is a materially different thing: probe-diagnosis
            # reads the probe source alongside those markers, decides the probe must be
            # defective because a known-vulnerable target produced no oracle, and the graph
            # enters its repair loop — on every case, to the repair limit.
            return ProbeExecution(attempt=attempt, exit_code=None, oracle_fired=False,
                                  precondition_reached=False, sink_returned=False,
                                  stderr_tail=self.SANDBOX_DISABLED)
        from infosec_harness.graph import workloads

        return await workloads.execute_probe(image_tag, probe, spec, nonce, attempt)
