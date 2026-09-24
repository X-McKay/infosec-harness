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

with workflow.unsafe.imports_passed_through():
    from infosec_harness.agents.deps import AgentDeps
    from infosec_harness.agents.durable import AGENT_LIST
    from infosec_harness.agents.render import render_prompt
    from infosec_harness.domain.models import (
        Finding,
        FindingInput,
        InconclusiveReason,
        PreparedEnvironment,
        PriorityBand,
        RepoRef,
        TriageResult,
        TriageRunOutput,
        Verdict,
        VerdictLabel,
    )
    from infosec_harness.graph.prepare import run_prepare
    from infosec_harness.graph.triage import TRIAGE_GRAPH, PreFilter, TriageDeps, TriageState
    from infosec_harness.intake import adapters
    from infosec_harness.workflows import activities
    from infosec_harness.workflows.temporal_ops import TemporalOps

_ACT = dict(start_to_close_timeout=timedelta(minutes=5), retry_policy=RetryPolicy(maximum_attempts=3))


def _inconclusive(finding: Finding, reason: InconclusiveReason, rationale: str, status: str,
                  invocations=None) -> TriageRunOutput:
    verdict = Verdict(label=VerdictLabel.inconclusive, confidence=0.0, rationale=rationale,
                      inconclusive_reason=reason)
    result = TriageResult(fingerprint=finding.fingerprint, verdict=verdict, priority_score=0.0,
                          priority=PriorityBand.p4, environment_scope="none", early_exit=reason.value)
    return TriageRunOutput(finding=finding, result=result, prepared_status=status,
                           invocations=invocations or [], needs_info=(reason == InconclusiveReason.needs_info))


@workflow.defn
class RepoPreparationWorkflow:
    @workflow.run
    async def run(self, ref: RepoRef) -> PreparedEnvironment:
        snapshot = await workflow.execute_activity(activities.checkout_activity, ref, **_ACT)
        stack = await workflow.execute_activity(activities.detect_stack_activity, snapshot, **_ACT)
        outcome = await run_prepare(TemporalOps(), snapshot, stack)
        return outcome.prepared


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
                                 prepared.status, invocations)
        finding = Finding.model_validate(resolved)

        if prepared.status != "ready":
            return _inconclusive(finding, InconclusiveReason.environment_unbuildable,
                                 f"The environment could not be prepared: {prepared.reason}.",
                                 prepared.status, invocations)

        state = TriageState(finding=finding, prepared=prepared)
        result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())
        return TriageRunOutput(finding=finding, result=result, prepared_status=prepared.status,
                               invocations=invocations + state.invocations)


@workflow.defn
class TriageBatchWorkflow:
    # The plugin registers every durable agent's activities once, from this workflow, for
    # the whole worker (the other workflows call the same agents).
    __pydantic_ai_agents__ = AGENT_LIST

    @workflow.run
    async def run(self, args: dict) -> list[TriageRunOutput]:
        findings = [FindingInput.model_validate(f) for f in args["findings"]]
        concurrency = int(args.get("per_repo_concurrency", 4))

        groups: dict[tuple[str, str], list[FindingInput]] = defaultdict(list)
        for f in findings:
            groups[(f.repo_url, f.revision)].append(f)

        results: dict[int, TriageRunOutput] = {}
        order = {id(f): i for i, f in enumerate(findings)}

        for (repo_url, revision), group in groups.items():
            group.sort(key=lambda f: (f.cwe or "", f.file_path or ""))
            prepared = await workflow.execute_child_workflow(
                RepoPreparationWorkflow.run, RepoRef(repo_url=repo_url, revision=revision),
                id=f"prep:{repo_url}:{revision}", task_queue=workflow.info().task_queue,
            )
            for f, out in zip(group, await self._triage_group(group, prepared.model_dump(), concurrency),
                              strict=True):
                results[order[id(f)]] = out

        return [results[i] for i in sorted(results)]

    async def _triage_group(self, group, prepared_dump: dict, concurrency: int) -> list[TriageRunOutput]:
        async def triage(f: FindingInput) -> TriageRunOutput:
            return await workflow.execute_child_workflow(
                FindingTriageWorkflow.run,
                {"finding_input": f.model_dump(), "prepared": prepared_dump},
                id=f"triage:{Finding.compute_fingerprint(f)}:{workflow.info().workflow_id}",
            )

        # Warm-then-fan-out: the first finding writes the shared cache prefix alone, then
        # the rest read it concurrently under a per-repo limit (§6.2).
        sem = asyncio.Semaphore(concurrency)

        async def bounded(f: FindingInput) -> TriageRunOutput:
            async with sem:
                return await triage(f)

        first = await triage(group[0])
        rest = await asyncio.gather(*(bounded(f) for f in group[1:]))
        return [first, *rest]
