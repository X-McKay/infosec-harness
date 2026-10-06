"""One durable investigation per finding. Temporal history is the source of truth."""

import asyncio
import shlex
from collections.abc import Awaitable, Callable
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from typing import ClassVar

from temporalio import activity, workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError

with workflow.unsafe.imports_passed_through():
    from pydantic import BaseModel
    from pydantic_ai import Agent
    from pydantic_ai.durable_exec.temporal import PydanticAIWorkflow
    from pydantic_ai.tool_manager import ToolManager
    from pydantic_ai.usage import UsageLimits

    from infosec_harness.agents.evidence import parse_probe_observations
    from infosec_harness.agents.investigator import InvestigationDeps
    from infosec_harness.contracts import (
        MAX_EVIDENCE_IDS,
        MAX_SUMMARY_CHARS,
        Finding,
        InvestigationRequest,
        InvestigationResult,
        RunState,
        Verdict,
        WorkerIdentity,
        definitive_support,
    )
    from infosec_harness.sandbox import OpenShell
    from infosec_harness.sandbox.process import finish
    from infosec_harness.tools.execute import evidence_from_result, unwrap_output

    from .snapshot import Snapshot, validate_citation

# The terminal failure message embeds at most this many cause links, each message cut to
# FAILURE_LINK_CHARS. Clients classify failures from it, so these values are a v11 contract.
FAILURE_CHAIN_LINKS = 8
FAILURE_LINK_CHARS = 400
# Temporal wrapper types; the outermost other type names a terminal failure.
FAILURE_WRAPPERS = frozenset({"ActivityError", "ChildWorkflowError", "WorkflowFailureError"})

# Lifecycle activity bounds (v11 values; replay does not compare them, but keep them stable).
PREPARE_TIMEOUT = timedelta(minutes=10)
FINALIZE_TIMEOUT = timedelta(minutes=2)
CLEANUP_TIMEOUT = timedelta(minutes=5)
CLEANUP_ATTEMPTS = 3
CLEANUP_RETRY = RetryPolicy(maximum_attempts=CLEANUP_ATTEMPTS)
# Server-side backoff between cleanup attempts under CLEANUP_RETRY's (default) intervals.
CLEANUP_BACKOFF = sum(
    (
        min(
            CLEANUP_RETRY.initial_interval * CLEANUP_RETRY.backoff_coefficient**attempt,
            CLEANUP_RETRY.maximum_interval or CLEANUP_RETRY.initial_interval * 100,
        )
        for attempt in range(CLEANUP_ATTEMPTS - 1)
    ),
    timedelta(),
)
# Workflow-task latency around the cleanup schedule and completion.
CLEANUP_MARGIN = timedelta(minutes=5)
# Time owned cleanup can need after the investigation deadline fires: prepare waits for its
# own completion (WAIT_CANCELLATION_COMPLETED, no heartbeat), then every cleanup attempt runs
# with its backoff. The server execution timeout and a cohort's drain must cover it, or the
# server ends the run before its `finally` closes the owned sandboxes.
CLEANUP_RESERVE = (
    PREPARE_TIMEOUT + CLEANUP_ATTEMPTS * CLEANUP_TIMEOUT + CLEANUP_BACKOFF + CLEANUP_MARGIN
)


class PreparedInvestigation(BaseModel):
    # Default extra='ignore' keeps decoding v11 payloads that duplicated
    # deps.snapshot_path and deps.worker_identity at this level.
    deps: InvestigationDeps


class FinalizeInvestigation(BaseModel):
    prepared: PreparedInvestigation
    verdict: Verdict
    usage: dict


class CleanupInvestigation(BaseModel):
    run_id: str
    expected_worker_identity: str | None = None


class WorkerIdentityMismatch(ApplicationError):
    """A worker identity check refused an activity before any side effect.

    Non-retryable: another attempt on the same worker meets the same identity. Never in a
    cohort's agent-level set, so it always stops a cohort. Exported from ``worker``.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, type="WorkerIdentityMismatch", non_retryable=True)


def short(fingerprint: str | WorkerIdentity | None) -> str:
    """A fingerprint prefix for messages; fingerprints are content digests, not secrets."""
    if isinstance(fingerprint, WorkerIdentity):
        fingerprint = fingerprint.fingerprint
    return fingerprint[:12] if fingerprint else "none"


def require_unchanged(
    identity: Callable[[], WorkerIdentity], bound: WorkerIdentity | None
) -> None:
    """Refuse when the worker's current content identity differs from the one it bound."""
    current = identity()
    if current != bound:
        raise WorkerIdentityMismatch(
            "Worker code or isolation configuration changed; restart the worker "
            f"(bound={short(bound)} current={short(current)})"
        )


class InvestigationActivities:
    def __init__(
        self,
        openshell: OpenShell,
        snapshot: Callable[[Finding, str], Awaitable[Snapshot]],
        model_name: str,
        *,
        identity: Callable[[], WorkerIdentity] | None = None,
        bound_identity: WorkerIdentity | None = None,
    ):
        """``identity`` recomputes the worker identity for drift checks; ``bound_identity`` is
        the one captured at worker start (computed from ``identity`` when not given)."""
        self.openshell = openshell
        self.snapshot = snapshot
        self.model_name = model_name
        self.identity = identity
        if bound_identity is None and identity is not None:
            bound_identity = identity()
        self.bound_identity = bound_identity

    def check_identity(self) -> None:
        if self.identity is not None:
            require_unchanged(self.identity, self.bound_identity)

    @activity.defn(name="prepare_investigation")
    async def prepare(self, request: InvestigationRequest) -> PreparedInvestigation:
        self.check_identity()
        if request.expected_worker_identity and (
            self.bound_identity is None
            or request.expected_worker_identity != self.bound_identity.fingerprint
        ):
            raise WorkerIdentityMismatch(
                "Requested candidate does not match this worker identity "
                f"(expected={short(request.expected_worker_identity)} "
                f"bound={short(self.bound_identity)})"
            )
        run_id = activity.info().workflow_id
        snapshot = await self.snapshot(request.finding, run_id)
        try:
            sandbox = await self.openshell.create(run_id, profile="workspace")
            await self.openshell.upload(sandbox, Path(snapshot.path), "/workspace/repo")
        except BaseException:
            # This worker knows which runtime received the create, even when no
            # Prepared result reaches the workflow. Close that ownership locally.
            await finish(asyncio.ensure_future(self.openshell.close_run(run_id)))
            raise
        return PreparedInvestigation(
            deps=InvestigationDeps(
                run_id=run_id,
                sandbox=sandbox,
                source_digest=snapshot.digest,
                snapshot_path=str(snapshot.path),
                request=request,
                worker_identity=self.bound_identity,
            ),
        )

    @activity.defn(name="finalize_investigation")
    async def finalize(self, payload: FinalizeInvestigation) -> InvestigationResult:
        self.check_identity()
        deps = payload.prepared.deps
        if deps.worker_identity != self.bound_identity:
            raise WorkerIdentityMismatch(
                "Investigation changed worker identity before finalization "
                f"(prepared={short(deps.worker_identity)} bound={short(self.bound_identity)})"
            )
        evidence = []
        for receipt in self.openshell.receipts(deps.run_id):
            operation_id = receipt.operation_id
            if not operation_id.startswith(("execute:", "probe:")):
                continue
            # Same cut detection as the tool return: the receipt holds the wrapper's marker.
            result = unwrap_output(receipt.result)
            observations = (
                parse_probe_observations(result.stdout)
                if receipt.sandbox.profile == "probe"
                else {}
            )
            if receipt.workspace_digest:
                observations["workspace_digest"] = receipt.workspace_digest
                observations["source_verified"] = receipt.source_verified
            evidence.append(
                evidence_from_result(
                    operation_id,
                    kind="probe" if receipt.sandbox.profile == "probe" else "command",
                    command=shlex.join(receipt.command),
                    result=result,
                    sandbox_id=receipt.sandbox.id,
                    source_digest=deps.source_digest,
                    observations=observations,
                )
            )
        known = {item.id for item in evidence}
        if unknown := [item for item in payload.verdict.evidence_ids if item not in known]:
            # Model-supplied IDs: bounded in the message.
            raise ValueError(
                "Verdict cites an execution without a trusted OpenShell receipt: "
                + repr(unknown)[:200]
            )
        for citation in payload.verdict.citations:
            validate_citation(deps.snapshot_path, citation)
        limitations = []
        if any(item.output_truncated for item in evidence):
            limitations.append(
                "Execution output was truncated; conclusions must account for missing output."
            )
        if any(item.kind == "probe" for item in evidence):
            limitations.append(
                "Probe markers are self-reported observations; their semantics are not independently verified."
            )
            limitations.append(
                "Source checks bracket probe execution; they cannot exclude changes that are restored during execution."
            )
        verdict = payload.verdict
        report_ids = set(verdict.evidence_ids)
        if verdict.label != "inconclusive":
            # Same admission rule as the validator, over receipt-rebuilt evidence only.
            support = definitive_support(verdict, evidence)
            corroborated, contrary = support.corroborated, support.contrary
            # Contradicting qualified probes the verdict superseded and the ordering rule excused.
            superseded = [item.id for item in support.superseded]
            if superseded:
                limitations.append(
                    "The investigator superseded earlier complete probes whose observations "
                    "contradicted the verdict: " + ", ".join(superseded)
                    + ". Their excerpts are retained; the summary states the claimed flaw."
                )
                for operation_id in superseded:
                    if len(report_ids) >= MAX_EVIDENCE_IDS:
                        break
                    report_ids.add(operation_id)
            if contrary:
                limitations.append(
                    "Successful source-verified offline probes reported contradictory observations: "
                    + ", ".join(item.id for item in contrary)
                    + ". The contradiction prevents a definitive verdict."
                )
                # Retain contrary excerpts within the existing ten-receipt report bound;
                # every contrary ID remains named above even when excerpts do not fit.
                for item in contrary:
                    if len(report_ids) >= MAX_EVIDENCE_IDS:
                        break
                    report_ids.add(item.id)
            if not corroborated or contrary:
                if not corroborated:
                    limitations.append(
                        f"Proposed {verdict.label} verdict lacked a cited successful offline probe with both controls and source citations."
                    )
                explanation = (
                    "The proposed conclusion could not reconcile contradictory successful offline probe observations. "
                    if contrary
                    else "The proposed conclusion could not be corroborated by the required execution and source evidence. "
                )
                verdict = verdict.model_copy(
                    update={
                        "label": "inconclusive",
                        "summary": (explanation + verdict.summary)[:MAX_SUMMARY_CHARS],
                    }
                )
        # Native receipts retain full bounded output. Reports contain cited and contrary excerpts.
        reported = [item.excerpt() for item in evidence if item.id in report_ids]
        if any(item.observations.get("report_excerpted") for item in reported):
            limitations.append(
                "Report output excerpts are bounded; full native receipts remain in the private execution state."
            )
        return InvestigationResult(
            finding=deps.request.finding,
            verdict=verdict,
            evidence=reported,
            source_digest=deps.source_digest,
            model=self.model_name,
            worker_identity=deps.worker_identity,
            usage=payload.usage,
            limitations=limitations,
        )

    @activity.defn(name="cleanup_investigation")
    async def cleanup(self, payload: CleanupInvestigation) -> None:
        expected = payload.expected_worker_identity
        if expected is not None and (
            self.bound_identity is None or expected != self.bound_identity.fingerprint
        ):
            raise WorkerIdentityMismatch(
                "Owned sandbox cleanup reached a different worker identity "
                f"(expected={short(expected)} bound={short(self.bound_identity)})"
            )
        # Current code/policy drift must not prevent the original bound adapter
        # from closing its own sandboxes.
        await self.openshell.close_run(payload.run_id)
        if self.identity is not None and expected is None:
            raise ApplicationError(
                "Local cleanup attempted, but original worker identity is unknown; cleanup unverified",
                non_retryable=True,
            )


@workflow.defn
class InvestigationWorkflow(PydanticAIWorkflow):
    # Bound outside the workflow by worker setup; no provider/SDK construction in workflows.
    agent: ClassVar[Agent[InvestigationDeps, Verdict] | None] = None
    __pydantic_ai_agents__: ClassVar[list] = []

    def __init__(self):
        self._state: RunState | None = None

    @workflow.query
    def state(self) -> RunState | None:
        return self._state

    @workflow.run
    async def run(self, request: InvestigationRequest) -> InvestigationResult:
        run_id = workflow.info().workflow_id
        self._state = RunState(
            id=run_id, status="running", phase="preparing", finding=request.finding
        )
        result = None
        caught = None
        prepared = None
        try:
            async with asyncio.timeout(request.limits.timeout_seconds):
                prepared = await workflow.execute_activity(
                    "prepare_investigation",
                    request,
                    result_type=PreparedInvestigation,
                    start_to_close_timeout=PREPARE_TIMEOUT,
                    retry_policy=RetryPolicy(maximum_attempts=1),
                    cancellation_type=workflow.ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
                )
                self._state.phase = "investigating"
                if self.agent is None:
                    raise RuntimeError("Investigator is not bound to this worker")
                # All tools, including Skills, are native serial barriers. Each history
                # guard therefore sees the preceding activity completion before scheduling.
                with ToolManager.parallel_execution_mode("sequential"):
                    run = await self.agent.run(
                        request.finding.model_dump_json(exclude={"repo_url"}),
                        deps=prepared.deps,
                        usage_limits=UsageLimits(
                            request_limit=request.limits.max_requests,
                            tool_calls_limit=request.limits.max_tool_calls,
                            total_tokens_limit=request.limits.total_tokens,
                        ),
                    )
                self._state.phase = "validating"
                result = await workflow.execute_activity(
                    "finalize_investigation",
                    FinalizeInvestigation(
                        prepared=prepared,
                        verdict=run.output,
                        usage={
                            key: value
                            for key, value in asdict(run.usage).items()
                            if value is None or isinstance(value, (int, float))
                        },
                    ),
                    result_type=InvestigationResult,
                    start_to_close_timeout=FINALIZE_TIMEOUT,
                    retry_policy=RetryPolicy(maximum_attempts=1),
                )
        except asyncio.CancelledError as error:
            caught = error
            self._state.status = "cancelled"
            self._state.error = "Investigation cancelled"
        except Exception as error:
            # Keep the whole cause chain: Temporal wraps activity failures, and callers classify
            # outcomes by the outermost meaningful type (e.g. a terminal executor exit vs
            # unknown dispatch) and by the chain embedded in the message.
            chain = [error]
            while len(chain) < FAILURE_CHAIN_LINKS and (
                nxt := getattr(chain[-1], "cause", None) or chain[-1].__cause__
            ):
                chain.append(nxt)

            def label(item: BaseException) -> str:
                return getattr(item, "type", None) or type(item).__name__

            # The outermost non-wrapper type names the failure (UnexpectedModelBehavior, not
            # the ModelRetry it wraps; ModelExecutorError, not the ActivityError around it).
            named = next((item for item in chain if label(item) not in FAILURE_WRAPPERS), error)
            message = " <- ".join(
                f"{label(item)}: {str(item)[:FAILURE_LINK_CHARS]}" for item in chain
            )
            caught = ApplicationError(message, type=label(named), non_retryable=True)
            self._state.status = "failed"
            self._state.error = message
        finally:
            self._state.phase = "cleaning_up"
            try:
                # A cancelled caller still waits for owned sandbox cleanup to settle.
                await finish(
                    asyncio.ensure_future(
                        workflow.execute_activity(
                            "cleanup_investigation",
                            CleanupInvestigation(
                                run_id=run_id,
                                expected_worker_identity=(
                                    prepared.deps.worker_identity.fingerprint
                                    if prepared is not None
                                    and prepared.deps.worker_identity is not None
                                    else request.expected_worker_identity
                                ),
                            ),
                            start_to_close_timeout=CLEANUP_TIMEOUT,
                            retry_policy=CLEANUP_RETRY,
                            cancellation_type=workflow.ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
                        )
                    )
                )
            except Exception as error:
                self._state.status = "failed"
                self._state.error = f"Owned sandbox cleanup failed: {error}"
                self._state.phase = "failed"
                raise ApplicationError(self._state.error, non_retryable=True) from error
        if caught is not None:
            self._state.phase = self._state.status
            raise caught
        if result is None:  # Unreachable: every path without a result raised above.
            raise RuntimeError("Investigation ended without a result or a failure")
        self._state.status = "completed"
        self._state.phase = "completed"
        self._state.result = result
        return result


def bind_investigator(agent: Agent[InvestigationDeps, Verdict]) -> None:
    InvestigationWorkflow.agent = agent
    InvestigationWorkflow.__pydantic_ai_agents__ = [agent]
