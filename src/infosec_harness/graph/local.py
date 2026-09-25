"""In-process batch triage (no Temporal): prepare each repo once, then triage its findings.

Mirrors TriageBatchWorkflow so the CLI and tests can run the full pipeline offline. Uses
LocalOps; sandbox build/probe run for real when Docker is available, else pass sandbox=False.
"""

from __future__ import annotations

from collections import defaultdict

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.render import render_prompt
from infosec_harness.domain.models import (
    Finding,
    FindingInput,
    InconclusiveReason,
    PriorityBand,
    RepoRef,
    TriageResult,
    TriageRunOutput,
    Verdict,
    VerdictLabel,
)
from infosec_harness.graph.ops import LocalOps
from infosec_harness.graph.prepare import run_prepare
from infosec_harness.graph.triage import TRIAGE_GRAPH, PreFilter, TriageDeps, TriageState
from infosec_harness.intake import adapters
from infosec_harness.repo.checkout import checkout
from infosec_harness.repo.detect import detect_stack


def _inconclusive(finding: Finding, reason: InconclusiveReason, rationale: str, status: str,
                  invocations=None) -> TriageRunOutput:
    verdict = Verdict(label=VerdictLabel.inconclusive, confidence=0.0, rationale=rationale,
                      inconclusive_reason=reason)
    result = TriageResult(fingerprint=finding.fingerprint, verdict=verdict, priority_score=0.0,
                          priority=PriorityBand.p4, environment_scope="none", early_exit=reason.value)
    return TriageRunOutput(finding=finding, result=result, prepared_status=status,
                           invocations=invocations or [], needs_info=(reason == InconclusiveReason.needs_info))


async def triage_one(ops: LocalOps, inp: FindingInput, prepared) -> TriageRunOutput:
    finding = adapters.to_finding(inp)
    invocations = []
    if adapters.needs_extraction(finding) and finding.description.strip():
        outcome = await ops.run_agent(
            "intake", render_prompt("Extract the missing finding fields from the report text, "
                                    "with citations.", {"report": finding.description, "known": finding}),
            AgentDeps(repo_path=prepared.snapshot.path))
        invocations.append(outcome)
        finding = adapters.merge_extraction(finding, outcome.output)
    if adapters.resolve_location(finding, prepared.snapshot.path) is None:
        return _inconclusive(finding, InconclusiveReason.needs_info,
                             "The finding's location could not be resolved in the repository.",
                             prepared.status, invocations)
    if prepared.status != "ready":
        return _inconclusive(finding, InconclusiveReason.environment_unbuildable,
                             f"The environment could not be prepared: {prepared.reason}.",
                             prepared.status, invocations)
    state = TriageState(finding=finding, prepared=prepared)
    result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())
    return TriageRunOutput(finding=finding, result=result, prepared_status=prepared.status,
                           invocations=invocations + state.invocations)


async def triage_batch_local(findings: list[FindingInput], *, sandbox: bool = True) -> list[TriageRunOutput]:
    ops = LocalOps(sandbox=sandbox)
    groups: dict[tuple[str, str], list[FindingInput]] = defaultdict(list)
    for f in findings:
        groups[(f.repo_url, f.revision)].append(f)
    results: dict[int, TriageRunOutput] = {}
    order = {id(f): i for i, f in enumerate(findings)}
    for (repo_url, revision), group in groups.items():
        snapshot = await checkout(RepoRef(repo_url=repo_url, revision=revision))
        stack = detect_stack(snapshot.path)
        prep = await run_prepare(ops, snapshot, stack)
        for f in group:
            results[order[id(f)]] = await triage_one(ops, f, prep.prepared)
    return [results[i] for i in sorted(results)]
