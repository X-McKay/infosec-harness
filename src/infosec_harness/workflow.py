"""One durable investigation per finding. Temporal history is the source of truth."""

import asyncio
import shlex
from dataclasses import asdict
from datetime import timedelta
from functools import partial
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

    from .agent import InvestigationDeps, build_agent, parse_probe_observations
    from .models import (
        Evidence,
        InvestigationRequest,
        InvestigationResult,
        RunState,
        Verdict,
        definitive_support,
    )
    from .openshell import OpenShell
    from .process import _finish
    from .repository import validate_citation


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


class InvestigationActivities:
    def __init__(self, openshell: OpenShell, snapshot, model_name: str, *, identity=None):
        self.openshell = openshell
        self.snapshot = snapshot
        self.model_name = model_name
        self.identity = identity
        self.bound_identity = identity() if identity else None

    def check_identity(self):
        if self.identity and self.identity() != self.bound_identity:
            raise ValueError("Worker code or isolation configuration changed; restart the worker")

    @activity.defn(name="prepare_investigation")
    async def prepare(self, request: InvestigationRequest) -> PreparedInvestigation:
        self.check_identity()
        if request.expected_worker_identity and (
            self.bound_identity is None
            or request.expected_worker_identity != self.bound_identity.fingerprint
        ):
            raise ValueError("Requested candidate does not match this worker identity")
        run_id = activity.info().workflow_id
        snapshot = await self.snapshot(request.finding, run_id)
        try:
            sandbox = await self.openshell.create(run_id, profile="workspace")
            await self.openshell.upload(sandbox, Path(snapshot.path), "/workspace/repo")
        except BaseException:
            # This worker knows which runtime received the create, even when no
            # Prepared result reaches the workflow. Close that ownership locally.
            await _finish(asyncio.ensure_future(self.openshell.close_run(run_id)))
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
            raise ValueError("Investigation changed worker identity before finalization")
        evidence = []
        for receipt in self.openshell.receipts(deps.run_id):
            identity = receipt.operation_id
            if not identity.startswith(("execute:", "probe:")):
                continue
            result = receipt.result
            observations = (
                parse_probe_observations(result.stdout)
                if receipt.sandbox.profile == "probe"
                else {}
            )
            if digest := getattr(receipt, "workspace_digest", None):
                observations["workspace_digest"] = digest
                observations["source_verified"] = getattr(receipt, "source_verified", False)
            evidence.append(
                Evidence(
                    id=identity,
                    kind="probe" if receipt.sandbox.profile == "probe" else "command",
                    command=shlex.join(receipt.command),
                    exit_code=result.exit_code,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    timed_out=False,
                    output_truncated=result.output_truncated,
                    sandbox_id=receipt.sandbox.id,
                    source_digest=deps.source_digest,
                    observations=observations,
                )
            )
        known = {item.id for item in evidence}
        if any(identity not in known for identity in payload.verdict.evidence_ids):
            raise ValueError("Verdict cites an execution without a trusted OpenShell receipt")
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
            corroborated, contrary = definitive_support(verdict, evidence)
            if contrary:
                limitations.append(
                    "Successful source-verified offline probes reported contradictory observations: "
                    + ", ".join(item.id for item in contrary)
                    + ". The contradiction prevents a definitive verdict."
                )
                # Retain contrary excerpts within the existing ten-receipt report bound;
                # every contrary ID remains named above even when excerpts do not fit.
                for item in contrary:
                    if len(report_ids) >= 10:
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
                        "summary": (explanation + verdict.summary)[:12000],
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
            raise ApplicationError(
                "Owned sandbox cleanup reached a different worker identity", non_retryable=True
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
                    start_to_close_timeout=timedelta(minutes=10),
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
                    start_to_close_timeout=timedelta(minutes=2),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                )
        except asyncio.CancelledError as error:
            caught = error
            self._state.status = "cancelled"
            self._state.error = "Investigation cancelled"
        except Exception as error:
            caught = ApplicationError(str(error), type=type(error).__name__, non_retryable=True)
            self._state.status = "failed"
            self._state.error = str(error)
        finally:
            self._state.phase = "cleaning_up"
            try:
                # A cancelled caller still waits for owned sandbox cleanup to settle.
                await _finish(
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
                            start_to_close_timeout=timedelta(minutes=5),
                            retry_policy=RetryPolicy(maximum_attempts=3),
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
        assert result is not None
        self._state.status = "completed"
        self._state.phase = "completed"
        self._state.result = result
        return result


def bind_investigator(agent: Agent[InvestigationDeps, Verdict]) -> None:
    InvestigationWorkflow.agent = agent
    InvestigationWorkflow.__pydantic_ai_agents__ = [agent]


def create_worker(client, settings):
    """Register native PydanticAI model/tool activities and three lifecycle activities."""
    from temporalio.worker import Worker
    from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

    from . import repository
    from .agent import WorkerIdentityInterceptor
    from .identity import worker_identity
    from .model import OpenShellModel
    from .openshell import OpenShellConfig

    openshell = OpenShell(OpenShellConfig.load(settings.openshell_config))
    model = OpenShellModel(
        openshell,
        settings.model_name,
        provider=settings.model_provider,
        base_url=settings.model_base_url,
        region=settings.model_region,
    )
    agent = build_agent(openshell, model)
    bind_investigator(agent)
    activities = InvestigationActivities(
        openshell,
        partial(repository.snapshot, settings=settings),
        settings.model_name,
        identity=partial(worker_identity, settings),
    )
    return Worker(
        client,
        task_queue=settings.task_queue,
        workflows=[InvestigationWorkflow],
        activities=[activities.prepare, activities.finalize, activities.cleanup],
        interceptors=[WorkerIdentityInterceptor(partial(worker_identity, settings))],
        workflow_runner=SandboxedWorkflowRunner(
            restrictions=SandboxRestrictions.default.with_passthrough_modules(
                __name__, "annotated_types", "typing_inspection"
            )
        ),
    )
