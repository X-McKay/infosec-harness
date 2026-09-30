"""In-process batch triage (no Temporal): prepare each repo once, then triage its findings.

Mirrors TriageBatchWorkflow so the CLI and tests can run the full pipeline offline. Uses
LocalOps; sandbox build/probe run for real when Docker is available, else pass sandbox=False.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.intake_claims import WIRE_VERSION
from infosec_harness.agents.intake_contracts import render_intake_prompt
from infosec_harness.domain.models import (
    ComponentProfile,
    Finding,
    FindingInput,
    InconclusiveReason,
    RepoRef,
    SourceMode,
    TriageResult,
    TriageRunOutput,
    Verdict,
    VerdictLabel,
)
from infosec_harness.graph.manifests import execution_manifest, source_manifest
from infosec_harness.graph.ops import LocalOps, classify_pipeline_failure
from infosec_harness.graph.prepare import PrepareFailed, prepare_resolved_component, run_prepare
from infosec_harness.graph.scoring import priority_for_inconclusive
from infosec_harness.graph.triage import TRIAGE_GRAPH, PreFilter, TriageDeps, TriageState
from infosec_harness.intake import adapters
from infosec_harness.repo.checkout import checkout
from infosec_harness.repo.components import component_stack, owning_component, preparation_key
from infosec_harness.repo.detect import detect_stack
from infosec_harness.settings import get_settings


def _inconclusive(finding: Finding, reason: InconclusiveReason, rationale: str, status: str,
                  invocations=None, manifest=None) -> TriageRunOutput:
    verdict = Verdict(label=VerdictLabel.inconclusive, confidence=0.0, rationale=rationale,
                      inconclusive_reason=reason)
    score, band = priority_for_inconclusive(finding)
    result = TriageResult(fingerprint=finding.fingerprint, verdict=verdict, priority_score=score,
                          priority=band, environment_scope="none", early_exit=reason.value)
    return TriageRunOutput(finding=finding, result=result, prepared_status=status,
                           invocations=invocations or [], manifest=manifest or {},
                           needs_info=(reason == InconclusiveReason.needs_info))


async def triage_one(ops: LocalOps, inp: FindingInput, prepared) -> TriageRunOutput:
    finding = adapters.to_finding(inp)
    invocations = []
    if adapters.needs_extraction(finding) and finding.description.strip():
        outcome = await ops.run_agent(
            "intake", render_intake_prompt("Extract the missing finding fields from the report text, "
                                    "with citations.", {"report": finding.description, "known": finding},
                                    protocol=WIRE_VERSION),
            AgentDeps(repo_path=prepared.snapshot.path, report_text=finding.description))
        invocations.append(outcome)
        finding = adapters.merge_extraction(finding, outcome.output)
    if adapters.resolve_location(finding, prepared.snapshot.path) is None:
        return _inconclusive(finding, InconclusiveReason.needs_info,
                             "The finding's location could not be resolved in the repository.",
                             prepared.status, invocations, execution_manifest(prepared))
    try:
        rebound = await prepare_resolved_component(ops, finding, prepared)
        if rebound is not None:
            prepared = rebound.prepared
            invocations.extend(rebound.invocations)
    except PrepareFailed as exc:
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
                           manifest=execution_manifest(prepared),
                           invocations=invocations + state.invocations,
                           context=state.context, executions=state.executions)


async def triage_batch_local(findings: list[FindingInput], *, sandbox: bool = True,
                             recipe_cache: bool = True,
                             concurrency: int | None = None,
                             prepare_sink: dict[tuple[str, ...], list] | None = None,
                             mask_paths: dict[tuple[str, str], list[str]] | None = None,
                             ) -> list[TriageRunOutput]:
    """Run the pipeline in-process. If ``prepare_sink`` is given, each repo's prepare-phase
    agent invocations (recon, env-planner, build repair) are recorded there once per compatible
    prepared component. Single-component keys retain ``(repo_url, revision)`` compatibility;
    polyglot keys add the component root as a third element.

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
    groups: dict[tuple[str, str, SourceMode | None], list[FindingInput]] = defaultdict(list)
    for f in findings:
        groups[(f.repo_url, f.revision, f.source_mode)].append(f)
    results: dict[int, TriageRunOutput] = {}
    order = {id(f): i for i, f in enumerate(findings)}
    for (repo_url, revision, source_mode), group in groups.items():
        snapshot = None
        stack = None
        try:
            snapshot = await checkout(RepoRef(
                repo_url=repo_url, revision=revision,
                source_mode=source_mode,
                exclude_paths=(mask_paths or {}).get((repo_url, revision), [])))
            stack = detect_stack(snapshot.path)
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
            for f in group:
                results[order[id(f)]] = _inconclusive(
                    adapters.to_finding(f), classify_pipeline_failure(e),
                    f"Discovering {repo_url} failed: {type(e).__name__}: {e}", "failed", manifest=(
                        source_manifest(snapshot, stack) if snapshot is not None else {}
                    ))
            continue

        component_groups: dict[str, tuple[ComponentProfile | None, list[FindingInput]]] = {}
        for finding_input in group:
            component = owning_component(stack, finding_input.file_path)
            key = preparation_key(component)
            component_groups.setdefault(key, (component, []))[1].append(finding_input)

        for component_root, (component, component_group) in component_groups.items():
            narrowed = component_stack(stack, component) if component is not None else stack
            effective_root = component.root if component is not None else "."
            try:
                # Preserve the historical three-argument seam for root/single-component callers
                # and tests which wrap preparation. Only a nested component needs the new bind.
                if effective_root == ".":
                    prep = await run_prepare(ops, snapshot, narrowed)
                else:
                    prep = await run_prepare(
                        ops, snapshot, narrowed, component_root=effective_root)
            except Exception as e:  # noqa: BLE001 - one component must not sink the repository
                partial = e.invocations if isinstance(e, PrepareFailed) else []
                cause = e.cause if isinstance(e, PrepareFailed) else e
                sink_key = ((repo_url, revision) if len(component_groups) == 1
                            else (repo_url, revision, component_root))
                if prepare_sink is not None:
                    prepare_sink[sink_key] = partial
                ran = ", ".join(i.agent for i in partial) or "none"
                for finding_input in component_group:
                    results[order[id(finding_input)]] = _inconclusive(
                        adapters.to_finding(finding_input), classify_pipeline_failure(cause),
                        f"Preparing component {component_root!r} of {repo_url} failed after "
                        f"{len(partial)} agent call(s) ({ran}): {type(cause).__name__}: {cause}",
                        "failed", manifest=source_manifest(snapshot, narrowed))
                continue
            sink_key = ((repo_url, revision) if len(component_groups) == 1
                        else (repo_url, revision, component_root))
            if prepare_sink is not None:
                prepare_sink[sink_key] = prep.invocations
            # Same deterministic order the workflow uses, so both paths warm the same finding.
            component_group.sort(key=lambda f: (f.cwe or "", f.file_path or ""))
            outputs = await _triage_group(ops, component_group, prep.prepared, concurrency)
            for finding_input, out in zip(component_group, outputs, strict=True):
                results[order[id(finding_input)]] = out
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
                prepared.status, manifest=execution_manifest(prepared))

    gate = asyncio.Semaphore(concurrency)

    async def bounded(f: FindingInput) -> TriageRunOutput:
        async with gate:
            return await one(f)

    first = await one(group[0])
    return [first, *await asyncio.gather(*(bounded(f) for f in group[1:]))]
