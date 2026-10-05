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
from temporalio.common import RetryPolicy

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.domain.models import (
    AgentOutcome,
    BuildResult,
    EnvironmentSpec,
    Finding,
    FindingInput,
    ProbeExecution,
    ProbeSource,
    RepoSnapshot,
    SmokeResult,
    StackFingerprint,
)

with workflow.unsafe.imports_passed_through():
    # Imported here, on the host, so nothing below imports or reads configuration in-workflow.
    import pydantic_ai.usage  # noqa: F401 - used by graph.pipeline.partial_outcome
    from pydantic_ai import capture_run_messages

    import infosec_harness.agents.models  # noqa: F401 - used by graph.pipeline
    import infosec_harness.agents.stubs  # noqa: F401 - resolved lazily by stub-mode model resolution
    import infosec_harness.evals.trajectory  # noqa: F401 - used by graph.pipeline
    import infosec_harness.inference.protocol  # noqa: F401 - used for broker bindings
    import infosec_harness.inference.provenance  # noqa: F401 - used by graph.pipeline
    from infosec_harness.agents.durable import AGENTS, CONFIGS
    from infosec_harness.graph.pipeline import agent_outcome, partial_outcome
    from infosec_harness.workflows import activities
    from infosec_harness.workflows.accounting import RootAccounting


# Temporal's default retry policy is *unlimited* attempts. A deterministic programming
# error in one of these activities (a bad signature, a validation failure) would then retry
# forever and the workflow would hang rather than fail — silently holding a worker slot.
# Bound the attempts and never retry the error classes that cannot succeed on a retry.
_NON_RETRYABLE = ["TypeError", "ValueError", "AttributeError", "KeyError", "ValidationError"]
_RETRY = RetryPolicy(maximum_attempts=3, non_retryable_error_types=_NON_RETRYABLE)
_SHORT = dict(start_to_close_timeout=timedelta(minutes=5), retry_policy=_RETRY)
# Long workloads heartbeat so cancellation reaches them and their cleanup completes.
_WORKLOAD = dict(heartbeat_timeout=timedelta(seconds=30),
                 cancellation_type=workflow.ActivityCancellationType.WAIT_CANCELLATION_COMPLETED)


class TemporalOps:
    """Bound to one workflow execution; created inside the workflow's run method.

    ``root_id`` and ``fingerprint`` say which batch budget and which finding this workflow's
    operations are accounted to; both come from the workflow's own arguments.
    """

    def __init__(self, *, root_id: str | None = None, fingerprint: str | None = None) -> None:
        self._accounting = RootAccounting(root_id=root_id, fingerprint=fingerprint)
        self._broker_identity: tuple[str, str] | None = None
        # Built and resolved on the host: reading a spec inside a workflow would be I/O. The
        # immutable config retains its declared budget and applies repository-size scaling.
        self._agents = AGENTS
        self._configs = CONFIGS

    async def normalize_finding(self, inp: FindingInput) -> Finding:
        return await workflow.execute_activity(activities.normalize_finding_activity, inp,
                                               **_SHORT)

    async def resolve_location(self, finding: Finding, repo_path: str) -> Finding | None:
        return await workflow.execute_activity(activities.resolve_location_activity,
            {"finding": finding.model_dump(mode="json"), "repo_path": repo_path}, **_SHORT)

    async def run_agent(
        self, name: str, prompt: Sequence[UserContent], deps: AgentDeps
    ) -> AgentOutcome:
        base_config = self._configs[name]
        config = base_config.for_source_files(deps.source_files)
        identity = await self._accounting.reserve(config, configuration_digest=base_config.digest)
        if config.model.broker_contract is not None:
            if identity is None:
                raise RuntimeError("Brokered durable execution requires a persisted root reservation")
            self._broker_identity = (workflow.info().run_id, identity[0])
            from infosec_harness.inference.protocol import ExecutorContract, ReservationBinding
            # Host-resolved contract and a side-effecting activity; replay only reads its result.
            request = {
                "mode": "temporal", "root_id": identity[0], "run_id": workflow.info().run_id,
                "invocation_id": identity[1], "operation_id": identity[1], "agent": name,
                "configuration_digest": base_config.digest,
                "contract": config.model.broker_contract.model_dump(mode="json"),
            }
            binding = await workflow.execute_activity(activities.issue_broker_invocation_activity,
                request, start_to_close_timeout=timedelta(seconds=45), retry_policy=_RETRY)
            deps = deps.model_copy(update={
                "broker_binding": ReservationBinding.model_validate(binding),
                "broker_contract": ExecutorContract.model_validate(request["contract"]),
            })
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
        config = self._configs[name].for_source_files(deps.source_files)
        started = workflow.now()
        with capture_run_messages() as messages:
            try:
                result = await self._agents[name].run(
                    list(prompt), deps=deps, usage_limits=config.budget.to_usage_limits())
            except Exception as exc:
                # The failed call's observed usage travels with the error for the graph to keep.
                exc.agent_outcome = partial_outcome(  # type: ignore[attr-defined]
                    name, messages, config, (workflow.now() - started).total_seconds(), exc)
                raise
        return agent_outcome(name, result, config, (workflow.now() - started).total_seconds())

    async def close(self) -> None:
        if self._broker_identity is None:
            return  # No owned reservation or lease exists merely because config names a broker.
        run_id, root_id = self._broker_identity
        await asyncio.shield(workflow.execute_activity(activities.close_broker_run_activity,
            {"run_id": run_id, "root_id": root_id},
            start_to_close_timeout=timedelta(seconds=120), retry_policy=_RETRY))

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
        try:
            result = await workflow.execute_activity(
                activity,
                args,
                start_to_close_timeout=start_to_close_timeout,
                retry_policy=retry_policy,
                **_WORKLOAD,
            )
        except (Exception, asyncio.CancelledError) as exc:
            await self._accounting.settle(identity, None, type(exc).__name__)
            raise
        # An activity return does not expose resource use of lost/retried attempts.
        await self._accounting.settle(identity, None, "completed; retry resource usage unobserved")
        return result
