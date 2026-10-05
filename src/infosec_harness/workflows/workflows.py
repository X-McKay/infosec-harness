"""Temporal workflows (D3): a graph of durable agents + deterministic activities.

- TriageBatchWorkflow groups findings by repository, discovers each repository once, splits it
  into compatible components, prepares each component once (ComponentPreparationWorkflow) and
  fans its findings out warm-first (FindingTriageWorkflow) so they share the cached prompt
  prefix (§6.2).
- The grouping, scheduling, per-finding pipeline and failure records are shared with the
  in-process path (:mod:`infosec_harness.graph.pipeline`); this module adds only durability.

Every batch is durable: it is accepted with a budget ledger before it starts, and every
progress event, output and operation is recorded against it. Workflow type names carry the
execution generation. Histories recorded by an earlier generation are not replayable by design:
retry such a batch as a new workflow.
"""

from __future__ import annotations

import asyncio

from temporalio import workflow
from temporalio.exceptions import ApplicationError, is_cancelled_exception

with workflow.unsafe.imports_passed_through():
    from infosec_harness.agents.durable import AGENT_LIST
    from infosec_harness.agents.registry import EXECUTION_GENERATION
    from infosec_harness.domain.models import (
        BatchStatus,
        Finding,
        FindingInput,
        PreparedEnvironment,
        RepoPreparation,
        RepoRef,
        TriageRunOutput,
    )
    from infosec_harness.graph.failures import (
        classify_pipeline_failure,
        describe_failure,
        failure_cause,
    )
    from infosec_harness.graph.manifests import execution_manifest
    from infosec_harness.graph.pipeline import (
        clamp_concurrency,
        dedupe_by_fingerprint,
        group_by_repository,
        inconclusive_output,
        split_components,
        triage_finding,
        warm_then_fan_out,
    )
    from infosec_harness.graph.prepare import PrepareFailed, run_prepare
    from infosec_harness.workflows import activities
    from infosec_harness.workflows.activity_options import CHECKOUT, SHORT, TERMINAL
    from infosec_harness.workflows.payloads import (
        BatchArgs,
        ComponentPreparationArgs,
        FindingTriageArgs,
        FinishBatchArgs,
        ProgressArgs,
        SaveOutputArgs,
        WritebackArgs,
    )
    from infosec_harness.workflows.persistence_activities import (
        finish_batch_activity,
        progress_activity,
        remaining_budget_time_activity,
        save_output_activity,
        writeback_output_activity,
    )
    from infosec_harness.workflows.temporal_ops import TemporalOps


def _failed_preparation(exc: BaseException) -> RepoPreparation:
    cause = failure_cause(exc)
    return RepoPreparation(failure_reason=classify_pipeline_failure(cause),
                           failure_detail=describe_failure(cause))


@workflow.defn(name=f"ComponentPreparation-{EXECUTION_GENERATION}")
class ComponentPreparationWorkflow:
    """Prepare one component of one immutable repository discovery result.

    A preparation that raises is a result about this component, not a reason to fail the
    workflow: the batch has other components, and the agent calls already made are the only
    evidence about why it failed.
    """

    @workflow.run
    async def run(self, args: ComponentPreparationArgs) -> RepoPreparation:
        ops = TemporalOps(root_id=args.batch_id, fingerprint=args.fingerprint)
        try:
            outcome = await run_prepare(ops, args.snapshot, args.stack,
                                        component_root=args.component_root)
        except PrepareFailed as exc:
            if is_cancelled_exception(exc.cause):
                raise exc.cause from exc
            return RepoPreparation(
                prepared=PreparedEnvironment(snapshot=args.snapshot, stack=args.stack,
                                             status="failed",
                                             reason=f"prepare_failed: {type(exc.cause).__name__}"),
                invocations=exc.invocations,
                failure_reason=classify_pipeline_failure(exc.cause),
                failure_detail=describe_failure(exc.cause))
        finally:
            await ops.close()
        return RepoPreparation(prepared=outcome.prepared, invocations=outcome.invocations)


@workflow.defn(name=f"FindingTriage-{EXECUTION_GENERATION}")
class FindingTriageWorkflow:
    @workflow.run
    async def run(self, args: FindingTriageArgs) -> TriageRunOutput:
        ops = TemporalOps(root_id=args.batch_id,
                          fingerprint=Finding.compute_fingerprint(args.finding_input))
        try:
            return await triage_finding(ops, args.finding_input, args.prepared,
                                        is_cancelled=is_cancelled_exception)
        finally:
            await ops.close()


@workflow.defn(name=f"TriageBatch-{EXECUTION_GENERATION}")
class TriageBatchWorkflow:
    # The plugin registers every durable agent's activities once, from this workflow, for
    # the whole worker (the other workflows call the same agents).
    __pydantic_ai_agents__ = AGENT_LIST

    @workflow.run
    async def run(self, args: BatchArgs) -> list[TriageRunOutput]:
        self._batch_id = args.batch_id
        try:
            # Read before the first other activity so an already-expired batch is persisted too.
            remaining = await workflow.execute_activity(remaining_budget_time_activity,
                                                        self._batch_id, **SHORT)
            deadline = asyncio.timeout(remaining)
            try:
                async with deadline:
                    return await self._run_batch(args)
            except (Exception, asyncio.CancelledError) as exc:
                if deadline.expired():
                    raise ApplicationError("Root elapsed-time budget exhausted",
                        type="UsageLimitExceeded", non_retryable=True) from exc
                raise
        except (Exception, asyncio.CancelledError) as exc:
            status = BatchStatus.cancelled if is_cancelled_exception(exc) else BatchStatus.failed
            await asyncio.shield(workflow.execute_activity(finish_batch_activity, FinishBatchArgs(
                batch_id=self._batch_id, status=status,
                detail=f"Batch {status}: {type(exc).__name__}"), **TERMINAL))
            raise

    async def _run_batch(self, args: BatchArgs) -> list[TriageRunOutput]:
        findings = dedupe_by_fingerprint(args.findings)
        concurrency = clamp_concurrency(args.per_repo_concurrency)
        order = {id(f): i for i, f in enumerate(findings)}
        results: dict[int, TriageRunOutput] = {}
        for (repo_url, revision, source_mode), group in group_by_repository(findings).items():
            for finding_input in group:
                await self._progress(finding_input, "preparing")
            ref = RepoRef(repo_url=repo_url, revision=revision, source_mode=source_mode)
            results.update(await self._repository(ref, group, order, concurrency))
        await workflow.execute_activity(finish_batch_activity, FinishBatchArgs(
            batch_id=self._batch_id, status=BatchStatus.complete, detail=""), **TERMINAL)
        return [results[i] for i in sorted(results)]

    async def _repository(self, ref: RepoRef, group: list[FindingInput], order: dict[int, int],
                          concurrency: int) -> dict[int, TriageRunOutput]:
        """Discover once; prepare and account separately for incompatible component scopes."""
        try:
            snapshot = await workflow.execute_activity(activities.checkout_activity, ref,
                                                       **CHECKOUT)
            stack = await workflow.execute_activity(activities.detect_stack_activity, snapshot,
                                                    **SHORT)
        except Exception as exc:
            if is_cancelled_exception(exc):
                raise
            return await self._abandon_group(group, order, _failed_preparation(exc), ref.repo_url)
        results: dict[int, TriageRunOutput] = {}
        for component in split_components(stack, group):
            first = Finding.compute_fingerprint(component.findings[0])
            try:
                prep = await workflow.execute_child_workflow(
                    ComponentPreparationWorkflow.run,
                    ComponentPreparationArgs(batch_id=self._batch_id, fingerprint=first,
                                             snapshot=snapshot, stack=component.stack,
                                             component_root=component.root),
                    id=f"prep:{workflow.info().workflow_id}:{first}")
            except Exception as exc:  # noqa: BLE001 - one component must not sink the batch
                if is_cancelled_exception(exc):
                    raise
                prep = _failed_preparation(exc)
            if not prep.ok:
                results.update(await self._abandon_group(component.findings, order, prep,
                                                         ref.repo_url))
                continue
            outputs = await self._triage_group(component.findings, prep, concurrency)
            results.update({order[id(finding)]: output
                            for finding, output in zip(component.findings, outputs, strict=True)})
        return results

    async def _abandon_group(self, group: list[FindingInput], order: dict[int, int],
                             prep: RepoPreparation, repo_url: str) -> dict[int, TriageRunOutput]:
        """Report every finding of a component whose preparation failed, and no others.

        The shared preparation's invocations are attributed to the *first* finding of the group
        only. Attributing them to all of them would multiply one repository's spend by its
        finding count in every cost figure downstream; attributing them to none would lose the
        per-agent record entirely. Naming the agents in each rationale keeps the failure legible
        on the others.
        """
        ran = ", ".join(i.agent for i in prep.invocations) or "none"
        rationale = (f"Preparing {repo_url} failed after {len(prep.invocations)} agent call(s) "
                     f"({ran}): {prep.failure_detail}")
        status = prep.prepared.status if prep.prepared else "failed"
        manifest = execution_manifest(prep.prepared) if prep.prepared else {}
        out: dict[int, TriageRunOutput] = {}
        for i, f in enumerate(group):
            finding = Finding.from_input(f)
            output = inconclusive_output(finding, prep.failure_reason, rationale, status,
                                         prep.invocations if i == 0 else [], manifest)
            await self._save(output)
            out[order[id(f)]] = output
        return out

    async def _triage_group(self, group: list[FindingInput], prep: RepoPreparation,
                            concurrency: int) -> list[TriageRunOutput]:
        async def triage(f: FindingInput) -> TriageRunOutput:
            await self._progress(f, "assessing")
            try:
                output = await workflow.execute_child_workflow(
                    FindingTriageWorkflow.run,
                    FindingTriageArgs(batch_id=self._batch_id, finding_input=f,
                                      prepared=prep.prepared),
                    id=f"triage:{Finding.compute_fingerprint(f)}:{workflow.info().workflow_id}",
                )
            except Exception as exc:  # noqa: BLE001 - one finding must not sink the batch
                if is_cancelled_exception(exc):
                    raise
                finding = Finding.from_input(f)
                cause = failure_cause(exc)
                output = inconclusive_output(finding, classify_pipeline_failure(cause),
                    f"Finding workflow failed: {describe_failure(cause)}", "failed")
            if f is group[0]:
                # Shared preparation is attributed once, to the warm finding.
                output.invocations = list(prep.invocations) + output.invocations
            await self._save(output)
            return output

        return await warm_then_fan_out(group, triage, concurrency)

    async def _progress(self, finding: FindingInput, phase: str) -> None:
        await workflow.execute_activity(progress_activity, ProgressArgs(
            batch_id=self._batch_id, fingerprint=Finding.compute_fingerprint(finding),
            phase=phase, event_key=phase), **SHORT)

    async def _save(self, output: TriageRunOutput) -> None:
        run_id = await workflow.execute_activity(
            save_output_activity, SaveOutputArgs(batch_id=self._batch_id, output=output),
            **TERMINAL)
        try:
            await workflow.execute_activity(writeback_output_activity,
                                            WritebackArgs(run_id=run_id, output=output), **SHORT)
        except Exception as exc:  # Optional writeback cannot discard a completed assessment.
            if is_cancelled_exception(exc):
                raise
            try:
                await workflow.execute_activity(progress_activity, ProgressArgs(
                    batch_id=self._batch_id, fingerprint=output.finding.fingerprint,
                    phase="writeback_failed", event_key="writeback_failed",
                    detail=f"ADO writeback failed: {describe_failure(exc)}"), **SHORT)
            except Exception as progress_exc:
                if is_cancelled_exception(progress_exc):
                    raise
