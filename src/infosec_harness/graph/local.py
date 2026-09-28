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
from infosec_harness.graph.ops import LocalOps, is_infrastructure_failure
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
                           invocations=invocations + state.invocations,
                           context=state.context, executions=state.executions)


async def triage_batch_local(findings: list[FindingInput], *, sandbox: bool = True,
                             recipe_cache: bool = True,
                             prepare_sink: dict[tuple[str, str], list] | None = None) -> list[TriageRunOutput]:
    """Run the pipeline in-process. If ``prepare_sink`` is given, each repo's prepare-phase
    agent invocations (recon, env-planner, build repair) are recorded there keyed by
    (repo_url, revision) — once per repo, since preparation is shared across a repo's
    findings and must not be double-counted per finding."""
    ops = LocalOps(sandbox=sandbox, recipe_cache=recipe_cache)
    groups: dict[tuple[str, str], list[FindingInput]] = defaultdict(list)
    for f in findings:
        groups[(f.repo_url, f.revision)].append(f)
    results: dict[int, TriageRunOutput] = {}
    order = {id(f): i for i, f in enumerate(findings)}
    for (repo_url, revision), group in groups.items():
        snapshot = await checkout(RepoRef(repo_url=repo_url, revision=revision))
        stack = detect_stack(snapshot.path)
        try:
            prep = await run_prepare(ops, snapshot, stack)
        except Exception as e:  # noqa: BLE001 - one repo must not sink the batch either
            # Preparation is shared by a repo's findings, so a failure here decides all of
            # them — but only theirs. Observed live: build-repair exhausted its token budget
            # on real build logs and the exception left this loop, discarding every finding in
            # the run including repos already triaged. `environment_unbuildable` is what the
            # contract reserves for "no usable environment", which is exactly the situation.
            # A provider outage is not a statement about this repository, so it must not be
            # filed as `environment_unbuildable` -- an eval reading that cannot tell an endpoint
            # being down from a pipeline regression.
            reason = (InconclusiveReason.infrastructure_error if is_infrastructure_failure(e)
                      else InconclusiveReason.environment_unbuildable)
            for f in group:
                results[order[id(f)]] = _inconclusive(
                    adapters.to_finding(f), reason,
                    f"Preparing {repo_url} failed: {type(e).__name__}: {e}", "failed")
            continue
        if prepare_sink is not None:
            prepare_sink[(repo_url, revision)] = prep.invocations
        for f in group:
            try:
                results[order[id(f)]] = await triage_one(ops, f, prep.prepared)
            except Exception as e:  # noqa: BLE001 - one finding must not sink the batch
                # In the durable path each finding is its own child workflow, so a failure is
                # already contained. Here the batch shares a process, and an agent that
                # exhausts a retry budget on one finding used to discard every result in the
                # run — including findings already triaged. Record it as inconclusive/error,
                # which is what the three-way contract reserves for exactly this, and go on.
                results[order[id(f)]] = _inconclusive(
                    adapters.to_finding(f),
                    InconclusiveReason.infrastructure_error if is_infrastructure_failure(e)
                    else InconclusiveReason.error,
                    f"Triage failed for this finding: {type(e).__name__}: {e}",
                    prep.prepared.status)
    return [results[i] for i in sorted(results)]
