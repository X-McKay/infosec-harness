"""In-process batch triage (no Temporal): prepare each repo once, then triage its findings.

Mirrors TriageBatchWorkflow so the CLI and tests can run the full pipeline offline. Uses
LocalOps; sandbox build/probe run for real when Docker is available, else pass sandbox=False.
"""

from __future__ import annotations

import asyncio
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
from infosec_harness.graph.ops import LocalOps, classify_pipeline_failure
from infosec_harness.graph.prepare import PrepareFailed, run_prepare
from infosec_harness.graph.triage import TRIAGE_GRAPH, PreFilter, TriageDeps, TriageState
from infosec_harness.intake import adapters
from infosec_harness.repo.checkout import checkout
from infosec_harness.repo.detect import detect_stack
from infosec_harness.settings import get_settings


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
                             concurrency: int | None = None,
                             prepare_sink: dict[tuple[str, str], list] | None = None,
                             mask_paths: dict[tuple[str, str], list[str]] | None = None,
                             ) -> list[TriageRunOutput]:
    """Run the pipeline in-process. If ``prepare_sink`` is given, each repo's prepare-phase
    agent invocations (recon, env-planner, build repair) are recorded there keyed by
    (repo_url, revision) — once per repo, since preparation is shared across a repo's
    findings and must not be double-counted per finding.

    ``mask_paths`` is benchmark hygiene and is empty in production: repo-relative paths, keyed
    the same way, that are stripped from the checkout before any agent reads it. A harvested
    case ships the proof-of-vulnerability test that established its ground truth, and on a
    `-fixed` revision that test is in the tree because the fix commit added it — an agent can
    copy it instead of writing a probe, which turns the probe-author measurement into a
    measurement of transcription.

    ``concurrency`` is how many of one repository's findings may be triaged at a time; None
    takes `settings.per_repo_concurrency`, which is what `TriageBatchWorkflow` already uses.
    This path ignored that setting and ran strictly sequentially, so the offline pipeline — the
    one the CLI, the corpus scorer and every test exercise — had a different shape from the
    durable one it exists to mirror, and its measured wall clock could not be read as a
    prediction of production's. Same schedule as the workflow, for the same reasons:

    * Repository groups stay sequential. `run_prepare` writes the shared recipe cache, builds
      images, and is why image-cache GC has a bound to respect; two prepares at once would race
      that cache and double the peak disk. Nothing here changes that.
    * Findings *within* a prepared repo share only the finished `PreparedEnvironment` — an
      image tag and a spec, both read-only by then — so they are independent by construction.
    * Warm, then fan out: the first finding runs alone so it establishes the shared prompt
      prefix in the provider's cache, and the rest read that prefix concurrently. Fanning out
      from the start would have every finding of the repo miss the cache and write it.

    What it costs is real: each concurrent finding runs its own probe container against the
    same image, so N in flight means N containers and N times the sandbox CPU, memory and disk,
    plus N concurrent request streams against a shared rate limit. `per_repo_concurrency` is
    the one place to say how much of that the runner has capacity for."""
    if concurrency is None:
        concurrency = get_settings().per_repo_concurrency
    if concurrency < 1:
        raise ValueError(f"concurrency must be at least 1, got {concurrency}")
    ops = LocalOps(sandbox=sandbox, recipe_cache=recipe_cache)
    groups: dict[tuple[str, str], list[FindingInput]] = defaultdict(list)
    for f in findings:
        groups[(f.repo_url, f.revision)].append(f)
    results: dict[int, TriageRunOutput] = {}
    order = {id(f): i for i, f in enumerate(findings)}
    for (repo_url, revision), group in groups.items():
        try:
            snapshot = await checkout(RepoRef(
                repo_url=repo_url, revision=revision,
                exclude_paths=(mask_paths or {}).get((repo_url, revision), [])))
            stack = detect_stack(snapshot.path)
            prep = await run_prepare(ops, snapshot, stack)
        except Exception as e:  # noqa: BLE001 - one repo must not sink the batch either
            # Preparation is shared by a repo's findings, so a failure here decides all of
            # them — but only theirs. Observed live: build-repair exhausted its token budget
            # on real build logs and the exception left this loop, discarding every finding in
            # the run including repos already triaged.
            #
            # The checkout and stack detection are inside the guard too. They are the only
            # per-repo work that was still outside it, and a repository that cannot be cloned
            # is the likeliest failure of all on a harvested manifest — it would have taken the
            # whole batch with it for the same reason preparation used to.
            #
            # The calls preparation had already made are the only evidence about a repository
            # that failed to prepare, so they are recorded rather than discarded: a run whose
            # every case died here used to report nothing about which agents ran, how many
            # requests they made, or whether one was looping.
            partial = e.invocations if isinstance(e, PrepareFailed) else []
            cause = e.cause if isinstance(e, PrepareFailed) else e
            if prepare_sink is not None:
                # Keyed and counted exactly like the success path: once per repo, because
                # preparation is shared across a repo's findings.
                prepare_sink[(repo_url, revision)] = partial
            ran = ", ".join(i.agent for i in partial) or "none"
            for f in group:
                results[order[id(f)]] = _inconclusive(
                    adapters.to_finding(f), classify_pipeline_failure(cause),
                    f"Preparing {repo_url} failed after {len(partial)} agent call(s) ({ran}): "
                    f"{type(cause).__name__}: {cause}", "failed")
            continue
        if prepare_sink is not None:
            prepare_sink[(repo_url, revision)] = prep.invocations
        # Same deterministic order the workflow uses, so the two paths warm on the same finding.
        group.sort(key=lambda f: (f.cwe or "", f.file_path or ""))
        for f, out in zip(group, await _triage_group(ops, group, prep.prepared, concurrency),
                          strict=True):
            results[order[id(f)]] = out
    return [results[i] for i in sorted(results)]


async def _triage_group(ops: LocalOps, group: list[FindingInput], prepared,
                        concurrency: int) -> list[TriageRunOutput]:
    """One repository's findings, warmed then fanned out under `concurrency`."""

    async def one(f: FindingInput) -> TriageRunOutput:
        try:
            return await triage_one(ops, f, prepared)
        except Exception as e:  # noqa: BLE001 - one finding must not sink the batch
            # In the durable path each finding is its own child workflow, so a failure is
            # already contained. Here the batch shares a process, and an agent that exhausts a
            # retry budget on one finding used to discard every result in the run — including
            # findings already triaged. Record it as inconclusive/error, which is what the
            # three-way contract reserves for exactly this, and go on. That is also why
            # `gather` below needs no `return_exceptions`: a failure is already an outcome.
            return _inconclusive(
                adapters.to_finding(f), classify_pipeline_failure(e),
                f"Triage failed for this finding: {type(e).__name__}: {e}",
                prepared.status)

    gate = asyncio.Semaphore(concurrency)

    async def bounded(f: FindingInput) -> TriageRunOutput:
        async with gate:
            return await one(f)

    first = await one(group[0])
    return [first, *await asyncio.gather(*(bounded(f) for f in group[1:]))]
