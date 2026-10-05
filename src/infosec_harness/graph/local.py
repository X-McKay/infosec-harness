"""In-process batch triage (no Temporal): prepare each repo once, then triage its findings.

Test and development scaffolding, not a product mode. The grouping, scheduling, per-finding
pipeline and failure records are the durable path's own (:mod:`infosec_harness.graph.pipeline`);
this module only supplies in-process discovery and preparation. Uses LocalOps; sandbox
build/probe run for real when Docker is available, else pass sandbox=False.
"""

from __future__ import annotations

from infosec_harness.domain.models import (
    Finding,
    FindingInput,
    PreparedEnvironment,
    RepoRef,
    TriageRunOutput,
)
from infosec_harness.graph.failures import classify_pipeline_failure, describe_failure
from infosec_harness.graph.manifests import execution_manifest, source_manifest
from infosec_harness.graph.ops import LocalOps
from infosec_harness.graph.pipeline import (
    dedupe_by_fingerprint,
    group_by_repository,
    inconclusive_output,
    split_components,
    triage_finding,
    warm_then_fan_out,
)
from infosec_harness.graph.prepare import PrepareFailed, run_prepare
from infosec_harness.repo.checkout import checkout
from infosec_harness.repo.detect import detect_stack
from infosec_harness.settings import get_settings


async def triage_one(ops: LocalOps, inp: FindingInput,
                     prepared: PreparedEnvironment) -> TriageRunOutput:
    return await triage_finding(ops, inp, prepared)


async def triage_batch_local(findings: list[FindingInput], *, sandbox: bool = True,
                             recipe_cache: bool | None = None,
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
    takes `settings.per_repo_concurrency`, and the value is clamped exactly as the workflow
    clamps it. Grouping, deduplication, ordering and the schedule come from
    :mod:`infosec_harness.graph.pipeline`, which the workflow uses too:

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
    findings = dedupe_by_fingerprint(findings)
    ops = LocalOps(sandbox=sandbox, recipe_cache=recipe_cache)
    try:
        results: dict[int, TriageRunOutput] = {}
        order = {id(f): i for i, f in enumerate(findings)}
        for (repo_url, revision, source_mode), group in group_by_repository(findings).items():
            snapshot = None
            stack = None
            try:
                snapshot = await checkout(RepoRef(
                    repo_url=repo_url, revision=revision, source_mode=source_mode,
                    exclude_paths=(mask_paths or {}).get((repo_url, revision), [])))
                stack = detect_stack(snapshot.path)
            except Exception as e:  # noqa: BLE001 - one repo must not sink the batch
                # Discovery is shared by a repo's findings, so a failure here decides all of
                # them -- but only theirs. A repository that cannot be cloned is the likeliest
                # failure of all on a harvested manifest.
                for f in group:
                    results[order[id(f)]] = inconclusive_output(
                        Finding.from_input(f), classify_pipeline_failure(e),
                        f"Discovering {repo_url} failed: {describe_failure(e)}", "failed",
                        manifest=(source_manifest(snapshot, stack) if snapshot is not None
                                  else {}))
                continue

            components = split_components(stack, group)
            for component in components:
                sink_key = ((repo_url, revision) if len(components) == 1
                            else (repo_url, revision, component.root))
                try:
                    prep = await run_prepare(ops, snapshot, component.stack,
                                             component_root=component.root)
                except Exception as e:  # noqa: BLE001 - one component must not sink the repo
                    # The calls preparation had already made are the only evidence about a
                    # repository that failed to prepare, so they are recorded, not discarded.
                    partial = e.invocations if isinstance(e, PrepareFailed) else []
                    cause = e.cause if isinstance(e, PrepareFailed) else e
                    if prepare_sink is not None:
                        prepare_sink[sink_key] = partial
                    ran = ", ".join(i.agent for i in partial) or "none"
                    for f in component.findings:
                        results[order[id(f)]] = inconclusive_output(
                            Finding.from_input(f), classify_pipeline_failure(cause),
                            f"Preparing component {component.root!r} of {repo_url} failed after "
                            f"{len(partial)} agent call(s) ({ran}): {describe_failure(cause)}",
                            "failed", manifest=source_manifest(snapshot, component.stack))
                    continue
                if prepare_sink is not None:
                    prepare_sink[sink_key] = prep.invocations
                outputs = await _triage_group(ops, component.findings, prep.prepared, concurrency)
                for f, out in zip(component.findings, outputs, strict=True):
                    results[order[id(f)]] = out
        return [results[i] for i in sorted(results)]
    finally:
        await ops.close()


async def _triage_group(ops: LocalOps, group: list[FindingInput], prepared: PreparedEnvironment,
                        concurrency: int) -> list[TriageRunOutput]:
    """One repository component's findings, warmed then fanned out under `concurrency`."""

    async def one(f: FindingInput) -> TriageRunOutput:
        try:
            return await triage_one(ops, f, prepared)
        except Exception as e:  # noqa: BLE001 - one finding must not sink the batch
            # triage_finding already contains failures after normalization; this is the
            # in-process equivalent of a failed child workflow.
            return inconclusive_output(
                Finding.from_input(f), classify_pipeline_failure(e),
                f"Triage failed for this finding: {describe_failure(e)}",
                prepared.status, manifest=execution_manifest(prepared))

    return await warm_then_fan_out(group, one, concurrency)
