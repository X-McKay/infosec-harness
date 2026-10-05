"""The side-effecting operations the graph needs, behind one interface (D3).

`LocalOps` runs everything in-process (tests, evals, offline demos). `TemporalOps`
(workflows/temporal_ops.py) offloads to activities and durable agents. The graph nodes
only ever touch this interface, so the exact same topology runs standalone and durably.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol

from pydantic_ai.messages import UserContent

from infosec_harness.domain.models import (
    AgentOutcome,
    BuildResult,
    CodeRef,
    EnvironmentSpec,
    Finding,
    ProbeExecution,
    ProbeSource,
    RepoSnapshot,
    SmokeResult,
    StackFingerprint,
)
from infosec_harness.runtime.deps import AgentDeps


class Ops(Protocol):
    async def resolve_location(self, finding: Finding, repo_path: str) -> Finding | None: ...

    async def validate_citations(self, repo_path: str,
                                 references: list[CodeRef | None]) -> list[CodeRef | None]: ...

    async def run_agent(
        self, name: str, prompt: Sequence[UserContent], deps: AgentDeps, *,
        record: list[AgentOutcome] | None = None,
    ) -> AgentOutcome:
        """Run one agent call. Its outcome -- a failed call's partial usage included -- is
        appended to ``record`` before this returns or raises (see ``pipeline.run_recorded``)."""
        ...

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

        from infosec_harness.persistence.recipes import RecipeStore

        self._broker_run_id = str(uuid.uuid4())
        self._broker_sequence = 0
        self._broker_used = False
        self._broker_closed = False
        self._sandbox = sandbox
        # Off during corpus scoring. The cache is a latency win, not an accuracy one, and with
        # it on the first repository of a stack records a recipe that every later repository of
        # that stack then reuses -- so env-planner runs once instead of eighteen times and the
        # stage funnel loses the signal it exists to provide. None follows the settings switch.
        self._recipes = RecipeStore(enabled=recipe_cache)
        self._agents: dict[str, tuple[Any, Any]] = {}

    def _agent(self, name: str):
        """The agent and its base configuration, resolved once per operations instance."""
        if name not in self._agents:
            from infosec_harness.runtime.registry import (
                build_agent,
                load_spec,
                resolve_agent_config,
            )

            self._agents[name] = (build_agent(name, durable=False),
                                  resolve_agent_config(name, load_spec(name), durable=False))
        return self._agents[name]

    async def resolve_location(self, finding: Finding, repo_path: str) -> Finding | None:
        from infosec_harness.intake.adapters import resolve_location

        return resolve_location(finding, repo_path)

    async def validate_citations(self, repo_path: str,
                                 references: list[CodeRef | None]) -> list[CodeRef | None]:
        from infosec_harness.repo.access import validate_citations

        return validate_citations(repo_path, references)

    async def run_agent(self, name: str, prompt, deps: AgentDeps, *,
                        record: list[AgentOutcome] | None = None) -> AgentOutcome:
        import time

        from infosec_harness import telemetry
        from infosec_harness.graph.pipeline import run_recorded
        from infosec_harness.settings import get_settings

        if self._broker_closed:
            raise RuntimeError("Local operations have been closed")
        agent, base_config = self._agent(name)
        config = base_config.for_source_files(deps.source_files)
        if config.model.broker_contract is not None:
            from infosec_harness.inference.wire.protocol import InvocationRequest, digest
            from infosec_harness.inference.worker.invocations import request_invocation
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
        timeout = get_settings().agent_run_timeout_s
        with telemetry.agent_span(name, attrs) as span:
            try:
                outcome = await run_recorded(agent, name, prompt, deps, config,
                                             [] if record is None else record,
                                             clock=time.monotonic, timeout=timeout)
            except TimeoutError as e:
                # A hung provider request never fails on its own, so neither the client's
                # retries nor a budget will end it. Surface it as the infrastructure failure it
                # is; callers contain it per finding.
                raise TimeoutError(
                    f"agent {name!r} exceeded HARNESS_AGENT_RUN_TIMEOUT_S={timeout}s"
                ) from e
            span.set_attributes(telemetry.outcome_attributes(outcome))
        return outcome

    async def close(self) -> None:
        if self._broker_closed:
            return
        if self._broker_used:
            from infosec_harness.inference.wire.protocol import digest
            from infosec_harness.inference.worker.invocations import close_run
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
