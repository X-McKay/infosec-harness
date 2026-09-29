"""Temporal workflows (D3): a graph of durable agents + deterministic activities.

- RepoPreparationWorkflow runs once per repo@revision (P0-P6), and is cached by workflow id.
- FindingTriageWorkflow runs the intake + triage graph for one finding (F0-F9).
- TriageBatchWorkflow groups findings by repo (then CWE), prepares each repo once, and fans
  its findings out warm-first so they share the cached prompt prefix (§6.2).
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import is_cancelled_exception

with workflow.unsafe.imports_passed_through():
    from infosec_harness.agents.deps import AgentDeps
    from infosec_harness.agents.durable import AGENT_LIST
    from infosec_harness.agents.render import render_prompt
    from infosec_harness.domain.models import (
        Finding,
        FindingInput,
        InconclusiveReason,
        PreparedEnvironment,
        RepoPreparation,
        RepoRef,
        RepoSnapshot,
        StackFingerprint,
        TriageResult,
        TriageRunOutput,
        Verdict,
        VerdictLabel,
    )
    from infosec_harness.graph.manifests import execution_manifest
    from infosec_harness.graph.ops import classify_pipeline_failure
    from infosec_harness.graph.prepare import PrepareFailed, prepare_resolved_component, run_prepare
    from infosec_harness.graph.scoring import priority_for_inconclusive
    from infosec_harness.graph.triage import TRIAGE_GRAPH, PreFilter, TriageDeps, TriageState
    from infosec_harness.intake import adapters
    from infosec_harness.repo.components import component_stack, owning_component, preparation_key
    from infosec_harness.workflows import activities
    from infosec_harness.workflows.progress import (
        finish_batch_activity,
        progress_activity,
        save_output_activity,
    )
    from infosec_harness.workflows.temporal_ops import TemporalOps

_ACT = dict(start_to_close_timeout=timedelta(minutes=5), retry_policy=RetryPolicy(maximum_attempts=3))


def _inconclusive(finding: Finding, reason: InconclusiveReason, rationale: str, status: str,
                  invocations=None, manifest: dict | None = None) -> TriageRunOutput:
    verdict = Verdict(label=VerdictLabel.inconclusive, confidence=0.0, rationale=rationale,
                      inconclusive_reason=reason)
    score, band = priority_for_inconclusive(finding)
    result = TriageResult(fingerprint=finding.fingerprint, verdict=verdict, priority_score=score,
                          priority=band, environment_scope="none", early_exit=reason.value)
    return TriageRunOutput(finding=finding, result=result, prepared_status=status,
                           manifest=manifest or {}, invocations=invocations or [], needs_info=(reason == InconclusiveReason.needs_info))


@workflow.defn
class RepoPreparationWorkflow:
    @workflow.run
    async def run(self, ref: RepoRef) -> RepoPreparation:
        """Prepare one repository, returning the outcome rather than failing on a bad one.

        A preparation that raises is a result about this repository, not a reason to fail the
        workflow: the batch has other repositories, and the agent calls this one already made
        are the only evidence about why it failed. Both used to be lost -- the child workflow
        failed, taking the batch with it, and the invocations never crossed the boundary.
        """
        snapshot = await workflow.execute_activity(activities.checkout_activity, ref, **_ACT)
        stack = await workflow.execute_activity(activities.detect_stack_activity, snapshot, **_ACT)
        return await _prepare_result(snapshot, stack)


async def _prepare_result(snapshot: RepoSnapshot, stack: StackFingerprint,
                          component_root: str = ".") -> RepoPreparation:
    try:
        outcome = await run_prepare(TemporalOps(), snapshot, stack, component_root=component_root)
    except PrepareFailed as exc:
        if is_cancelled_exception(exc.cause):
            raise exc.cause from exc
        return RepoPreparation(
            prepared=PreparedEnvironment(snapshot=snapshot, stack=stack, status="failed",
                                         reason=f"prepare_failed: {type(exc.cause).__name__}"),
            invocations=exc.invocations,
            failure_reason=classify_pipeline_failure(exc.cause),
            failure_detail=f"{type(exc.cause).__name__}: {exc.cause}")
    return RepoPreparation(prepared=outcome.prepared, invocations=outcome.invocations)


@workflow.defn
class ComponentPreparationWorkflow:
    """Prepare a selected component from one immutable repository discovery result."""

    @workflow.run
    async def run(self, args: dict) -> RepoPreparation:
        return await _prepare_result(RepoSnapshot.model_validate(args["snapshot"]),
                                     StackFingerprint.model_validate(args["stack"]),
                                     args["component_root"])



@workflow.defn
class FindingTriageWorkflow:
    @workflow.run
    async def run(self, args: dict) -> TriageRunOutput:
        inp = FindingInput.model_validate(args["finding_input"])
        prepared = PreparedEnvironment.model_validate(args["prepared"])
        ops = TemporalOps()
        invocations = []

        # F0: normalize, extract from prose if needed, resolve location.
        finding = await workflow.execute_activity(activities.normalize_finding_activity, inp, **_ACT)
        if adapters.needs_extraction(finding) and finding.description.strip():
            deps = AgentDeps(repo_path=prepared.snapshot.path)
            outcome = await ops.run_agent(
                "intake", render_prompt("Extract the missing finding fields from the report text, "
                                        "with citations.", {"report": finding.description,
                                                            "known": finding}), deps)
            invocations.append(outcome)
            finding = adapters.merge_extraction(finding, outcome.output)
        resolved = await workflow.execute_activity(
            activities.resolve_location_activity,
            {"finding": finding.model_dump(), "repo_path": prepared.snapshot.path}, **_ACT)
        if resolved is None:
            return _inconclusive(finding, InconclusiveReason.needs_info,
                                 "The finding's location could not be resolved in the repository.",
                                 prepared.status, invocations, execution_manifest(prepared))
        finding = Finding.model_validate(resolved)

        if workflow.patched("resolved-component-v1"):
            try:
                rebound = await prepare_resolved_component(ops, finding, prepared)
                if rebound is not None:
                    prepared = rebound.prepared
                    invocations.extend(rebound.invocations)
            except PrepareFailed as exc:
                if is_cancelled_exception(exc.cause):
                    raise exc.cause from exc
                return _inconclusive(finding, classify_pipeline_failure(exc.cause),
                    f"Preparing the resolved component failed: {type(exc.cause).__name__}: {exc.cause}",
                    "failed", invocations + exc.invocations, execution_manifest(prepared))
        if prepared.status != "ready":
            return _inconclusive(finding, InconclusiveReason.environment_unbuildable,
                                 f"The environment could not be prepared: {prepared.reason}.",
                                 prepared.status, invocations, execution_manifest(prepared))

        state = TriageState(finding=finding, prepared=prepared)
        result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())
        return TriageRunOutput(finding=finding, result=result, prepared_status=prepared.status,
                               invocations=invocations + state.invocations,
                               context=state.context, executions=state.executions,
                               manifest=execution_manifest(prepared))


@workflow.defn
class TriageBatchWorkflow:
    # The plugin registers every durable agent's activities once, from this workflow, for
    # the whole worker (the other workflows call the same agents).
    __pydantic_ai_agents__ = AGENT_LIST

    @workflow.run
    async def run(self, args: dict) -> list[TriageRunOutput]:
        try:
            return await self._run_batch(args)
        except (Exception, asyncio.CancelledError) as exc:
            if getattr(self, "_durable", False):
                status = "cancelled" if is_cancelled_exception(exc) else "failed"
                await asyncio.shield(workflow.execute_activity(finish_batch_activity,
                    {"batch_id": self._batch_id, "status": status,
                     "detail": f"Batch {status}: {type(exc).__name__}"}, **_ACT))
            raise

    async def _run_batch(self, args: dict) -> list[TriageRunOutput]:
        self._batch_id = args.get("batch_id")
        self._durable = workflow.patched("durable-output-v1") and bool(self._batch_id)
        findings = [FindingInput.model_validate(f) for f in args["findings"]]
        if self._durable:
            findings = list({Finding.compute_fingerprint(f): f for f in findings}.values())
        concurrency = max(1, min(32, int(args.get("per_repo_concurrency", 4))))

        groups: dict[tuple[str, str, str | None], list[FindingInput]] = defaultdict(list)
        for f in findings:
            groups[(f.repo_url, f.revision, f.source_mode)].append(f)

        results: dict[int, TriageRunOutput] = {}
        order = {id(f): i for i, f in enumerate(findings)}

        for (repo_url, revision, source_mode), group in groups.items():
            group.sort(key=lambda f: (f.cwe or "", f.file_path or ""))
            if self._durable:
                for finding_input in group:
                    await self._progress(finding_input, "preparing")
            if self._durable and workflow.patched("component-preparation-v1"):
                results.update(await self._prepare_components(group, order, repo_url, revision, source_mode, concurrency))
                continue
            try:
                prep = await workflow.execute_child_workflow(
                    RepoPreparationWorkflow.run, RepoRef(repo_url=repo_url, revision=revision, source_mode=source_mode),
                    id=(f"prep:{workflow.info().workflow_id}:{Finding.compute_fingerprint(group[0])}"
                        if workflow.patched("scoped-preparation-v1") else f"prep:{repo_url}:{revision}"), task_queue=workflow.info().task_queue,
                )
            except Exception as e:  # noqa: BLE001 - one repo must not sink the batch
                if is_cancelled_exception(e):
                    raise
                # The child workflow itself failed (its checkout activity exhausted its
                # attempts, say), which `RepoPreparation` cannot express because it never got
                # to return one. Temporal wraps the cause, so classify on that.
                cause = getattr(e, "cause", None) or e
                prep = RepoPreparation(
                    failure_reason=classify_pipeline_failure(cause),
                    failure_detail=f"{type(cause).__name__}: {cause}")
            if not prep.ok:
                results.update(await self._abandon_group(group, order, prep, repo_url))
                continue
            for f, out in zip(group,
                              await self._triage_group(group, prep.prepared.model_dump(), concurrency, prep.invocations),
                              strict=True):
                results[order[id(f)]] = out

        if self._durable:
            await workflow.execute_activity(finish_batch_activity, {"batch_id": self._batch_id}, **_ACT)
        return [results[i] for i in sorted(results)]

    async def _prepare_components(self, group: list[FindingInput], order: dict[int, int],
                                  repo_url: str, revision: str, source_mode,
                                  concurrency: int) -> dict[int, TriageRunOutput]:
        """Discover once; prepare and account separately for incompatible component scopes."""
        try:
            snapshot = await workflow.execute_activity(activities.checkout_activity,
                RepoRef(repo_url=repo_url, revision=revision, source_mode=source_mode), **_ACT)
            stack = await workflow.execute_activity(activities.detect_stack_activity, snapshot, **_ACT)
        except Exception as exc:
            if is_cancelled_exception(exc):
                raise
            cause = getattr(exc, "cause", None) or exc
            return await self._abandon_group(group, order, RepoPreparation(
                failure_reason=classify_pipeline_failure(cause),
                failure_detail=f"{type(cause).__name__}: {cause}"), repo_url)
        groups: dict[str, list[FindingInput]] = defaultdict(list)
        for finding in group:
            groups[preparation_key(owning_component(stack, finding.file_path))].append(finding)
        results: dict[int, TriageRunOutput] = {}
        for component_group in groups.values():
            component = owning_component(stack, component_group[0].file_path)
            narrowed = component_stack(stack, component) if component else stack
            try:
                prep = await workflow.execute_child_workflow(ComponentPreparationWorkflow.run,
                    {"snapshot": snapshot.model_dump(), "stack": narrowed.model_dump(),
                     "component_root": component.root if component else "."},
                    id=f"prep:{workflow.info().workflow_id}:{Finding.compute_fingerprint(component_group[0])}")
            except Exception as exc:
                if is_cancelled_exception(exc):
                    raise
                cause = getattr(exc, "cause", None) or exc
                prep = RepoPreparation(failure_reason=classify_pipeline_failure(cause),
                                       failure_detail=f"{type(cause).__name__}: {cause}")
            if not prep.ok:
                results.update(await self._abandon_group(component_group, order, prep, repo_url))
                continue
            outputs = await self._triage_group(component_group, prep.prepared.model_dump(),
                                                concurrency, prep.invocations)
            results.update({order[id(finding)]: output
                            for finding, output in zip(component_group, outputs, strict=True)})
        return results

    async def _abandon_group(self, group, order: dict, prep: RepoPreparation,
                             repo_url: str) -> dict[int, TriageRunOutput]:
        """Report every finding of a repository whose preparation failed, and no others.

        Mirrors ``triage_batch_local``: preparation is shared by a repo's findings, so its
        failure decides all of them and nothing else in the batch.

        The shared preparation's invocations are attributed to the *first* finding of the group
        only. Attributing them to all of them would multiply one repository's spend by its
        finding count in every cost figure downstream; attributing them to none would lose the
        per-agent record entirely, which is the defect this exists to fix. Naming the agents in
        each rationale keeps the failure legible on the others.
        """
        ran = ", ".join(i.agent for i in prep.invocations) or "none"
        rationale = (f"Preparing {repo_url} failed after {len(prep.invocations)} agent call(s) "
                     f"({ran}): {prep.failure_detail}")
        status = prep.prepared.status if prep.prepared else "failed"
        out: dict[int, TriageRunOutput] = {}
        for i, f in enumerate(group):
            finding = await workflow.execute_activity(
                activities.normalize_finding_activity, f, **_ACT)
            out[order[id(f)]] = _inconclusive(
                finding, prep.failure_reason, rationale, status,
                prep.invocations if i == 0 else [],
                execution_manifest(prep.prepared) if prep.prepared else {})
            if self._durable:
                await self._save(out[order[id(f)]])
        return out

    async def _triage_group(self, group, prepared_dump: dict, concurrency: int, preparation_invocations=None) -> list[TriageRunOutput]:
        async def triage(f: FindingInput) -> TriageRunOutput:
            if self._durable:
                await self._progress(f, "assessing")
            try:
                output = await workflow.execute_child_workflow(
                    FindingTriageWorkflow.run,
                {"finding_input": f.model_dump(), "prepared": prepared_dump},
                    id=f"triage:{Finding.compute_fingerprint(f)}:{workflow.info().workflow_id}",
                )
            except Exception as exc:
                if is_cancelled_exception(exc) or not self._durable:
                    raise
                finding = await workflow.execute_activity(activities.normalize_finding_activity, f, **_ACT)
                cause = getattr(exc, "cause", None) or exc
                output = _inconclusive(finding, classify_pipeline_failure(cause),
                    f"Finding workflow failed: {type(cause).__name__}: {cause}", "failed")
            if self._durable:
                if f is group[0]:
                    output.invocations = list(preparation_invocations or []) + output.invocations
                await self._save(output)
            return output

        # Warm-then-fan-out: the first finding writes the shared cache prefix alone, then
        # the rest read it concurrently under a per-repo limit (§6.2).
        sem = asyncio.Semaphore(concurrency)

        async def bounded(f: FindingInput) -> TriageRunOutput:
            async with sem:
                return await triage(f)

        first = await triage(group[0])
        rest = await asyncio.gather(*(bounded(f) for f in group[1:]))
        return [first, *rest]


    async def _progress(self, finding: FindingInput, phase: str) -> None:
        await workflow.execute_activity(progress_activity,
            {"batch_id": self._batch_id, "fingerprint": Finding.compute_fingerprint(finding),
             "phase": phase, "event_key": phase}, **_ACT)

    async def _save(self, output: TriageRunOutput) -> None:
        await workflow.execute_activity(save_output_activity,
            {"batch_id": self._batch_id, "output": output.model_dump(mode="json")}, **_ACT)
