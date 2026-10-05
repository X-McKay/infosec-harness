"""Ops implementation that runs inside a Temporal workflow (D3).

Agent calls go to the durable agents (their model/tool calls become activities via
TemporalDurability); deterministic side effects go to activities. Bookkeeping uses
precomputed, cached maps so nothing here does disk or config I/O inside the workflow. Outcome
accounting is :mod:`infosec_harness.graph.pipeline`'s, shared with ``LocalOps``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta

from pydantic_ai.messages import UserContent
from temporalio import workflow

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

with workflow.unsafe.imports_passed_through():
    # Imported here, on the host, so nothing below imports or reads configuration in-workflow.
    import pydantic_ai.usage  # noqa: F401 - used by graph.pipeline.partial_outcome

    import infosec_harness.inference.models  # noqa: F401 - used by graph.pipeline
    import infosec_harness.inference.wire.protocol  # noqa: F401 - used for broker bindings
    import infosec_harness.inference.worker.provenance  # noqa: F401 - used by graph.pipeline
    import infosec_harness.runtime.stubs  # noqa: F401 - resolved lazily by stub-mode model resolution
    import infosec_harness.runtime.trajectory  # noqa: F401 - used by graph.pipeline
    from infosec_harness.graph.pipeline import run_recorded
    from infosec_harness.runtime.durable import AGENTS, CONFIGS
    from infosec_harness.workflows import activities
    from infosec_harness.workflows.accounting import RootAccounting
    from infosec_harness.workflows.activity_options import HEARTBEAT, RETRY, SHORT
    from infosec_harness.workflows.payloads import (
        BuildArgs,
        CloseBrokerRunArgs,
        ProbeArgs,
        RecordRecipeArgs,
        ResolveLocationArgs,
        SmokeArgs,
        ValidateCitationsArgs,
    )


def _workflow_clock() -> float:
    """Deterministic workflow time, in seconds, for agent-call latency."""
    return workflow.now().timestamp()


class TemporalOps:
    """Bound to one workflow execution; created inside the workflow's run method.

    ``root_id`` and ``fingerprint`` say which batch budget and which finding this workflow's
    operations are accounted to; both come from the workflow's own arguments.
    """

    def __init__(self, *, root_id: str, fingerprint: str) -> None:
        self._accounting = RootAccounting(root_id=root_id, fingerprint=fingerprint)
        self._broker_identity: tuple[str, str] | None = None
        # Built and resolved on the host: reading a spec inside a workflow would be I/O. The
        # immutable config retains its declared budget and applies repository-size scaling.
        self._agents = AGENTS
        self._configs = CONFIGS

    async def resolve_location(self, finding: Finding, repo_path: str) -> Finding | None:
        return await workflow.execute_activity(activities.resolve_location_activity,
            ResolveLocationArgs(finding=finding, repo_path=repo_path), **SHORT)

    async def validate_citations(self, repo_path: str,
                                 references: list[CodeRef | None]) -> list[CodeRef | None]:
        return await workflow.execute_activity(activities.validate_citations_activity,
            ValidateCitationsArgs(repo_path=repo_path, references=references), **SHORT)

    async def run_agent(
        self, name: str, prompt: Sequence[UserContent], deps: AgentDeps, *,
        record: list[AgentOutcome] | None = None,
    ) -> AgentOutcome:
        base_config = self._configs[name]
        config = base_config.for_source_files(deps.source_files)
        identity = await self._accounting.reserve(config, configuration_digest=base_config.digest)
        if config.model.broker_contract is not None:
            self._broker_identity = (workflow.info().run_id, identity[0])
            from infosec_harness.inference.wire.protocol import InvocationRequest
            # Host-resolved contract and a side-effecting activity; replay only reads its result.
            request = InvocationRequest(
                mode="temporal", root_id=identity[0], run_id=workflow.info().run_id,
                invocation_id=identity[1], operation_id=identity[1], agent=name,
                configuration_digest=base_config.digest,
                contract=config.model.broker_contract,
            )
            binding = await workflow.execute_activity(activities.issue_broker_invocation_activity,
                request, start_to_close_timeout=timedelta(seconds=45), retry_policy=RETRY)
            deps = deps.model_copy(update={"broker_binding": binding,
                                           "broker_contract": request.contract})
        recorded = [] if record is None else record
        before = len(recorded)
        try:
            outcome = await run_recorded(self._agents[name], name, prompt, deps, config,
                                         recorded, clock=_workflow_clock)
        except (Exception, asyncio.CancelledError) as exc:
            # run_recorded appends the failed call's partial outcome when it has one.
            partial = recorded[before] if len(recorded) > before else None
            await self._accounting.settle(identity, None, type(exc).__name__, partial=partial)
            raise
        await self._accounting.settle(identity, outcome)
        return outcome

    async def close(self) -> None:
        if self._broker_identity is None:
            return  # No owned reservation or lease exists merely because config names a broker.
        run_id, root_id = self._broker_identity
        await asyncio.shield(workflow.execute_activity(activities.close_broker_run_activity,
            CloseBrokerRunArgs(run_id=run_id, root_id=root_id),
            start_to_close_timeout=timedelta(seconds=120), retry_policy=RETRY))

    async def new_nonce(self) -> str:
        return await workflow.execute_activity(
            activities.new_nonce_activity,
            start_to_close_timeout=timedelta(seconds=10), retry_policy=RETRY)

    async def build_environment(self, snapshot: RepoSnapshot, spec: EnvironmentSpec) -> BuildResult:
        return await self._execute_workload(
            activities.build_environment_activity, BuildArgs(snapshot=snapshot, spec=spec),
            start_to_close_timeout=timedelta(minutes=40))

    async def smoke_test(
        self, image_tag: str, test_command: str = "", *, language: str = "", module_path: str = ""
    ) -> SmokeResult:
        return await self._execute_workload(
            activities.smoke_test_activity,
            SmokeArgs(image_tag=image_tag, test_command=test_command, language=language,
                      module_path=module_path),
            # Longer than the runner check alone: this also compiles and runs a canary test
            # inside the image, which on a JVM project means a Maven invocation.
            start_to_close_timeout=timedelta(minutes=8))

    async def lookup_recipe(self, stack: StackFingerprint) -> EnvironmentSpec | None:
        return await workflow.execute_activity(
            activities.lookup_recipe_activity, stack,
            start_to_close_timeout=timedelta(seconds=30), retry_policy=RETRY)

    async def record_recipe(
        self, stack: StackFingerprint, spec: EnvironmentSpec, *, worked: bool
    ) -> None:
        await workflow.execute_activity(
            activities.record_recipe_activity,
            RecordRecipeArgs(stack=stack, spec=spec, worked=worked),
            start_to_close_timeout=timedelta(seconds=30), retry_policy=RETRY)

    async def execute_probe(
        self, image_tag: str, probe: ProbeSource, spec: EnvironmentSpec, nonce: str, attempt: int
    ) -> ProbeExecution:
        return await self._execute_workload(
            activities.execute_probe_activity,
            ProbeArgs(image_tag=image_tag, probe=probe, spec=spec, nonce=nonce, attempt=attempt),
            start_to_close_timeout=timedelta(minutes=10))

    async def _execute_workload[A, T](
        self, activity: Callable[[A], Awaitable[T]], args: A, *,
        start_to_close_timeout: timedelta,
    ) -> T:
        """Reserve the full retry envelope before any sandbox workload is dispatched."""
        identity = await self._accounting.reserve_execution(
            activity.__name__,
            start_to_close_timeout.total_seconds() * (RETRY.maximum_attempts or 1),
        )
        try:
            result = await workflow.execute_activity(
                activity, args, start_to_close_timeout=start_to_close_timeout,
                retry_policy=RETRY, **HEARTBEAT)
        except (Exception, asyncio.CancelledError) as exc:
            await self._accounting.settle(identity, None, type(exc).__name__)
            raise
        # An activity return does not expose resource use of lost/retried attempts.
        await self._accounting.settle(identity, None, "completed; retry resource usage unobserved")
        return result
