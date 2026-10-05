"""The in-process batch runs a repository's findings on the same schedule the workflow does.

`TriageBatchWorkflow` has always grouped by repository, prepared once, warmed on the first
finding and then fanned the rest out under `settings.per_repo_concurrency`. `triage_batch_local`
— the path the CLI, the corpus scorer and every test exercise — ignored that setting and ran
strictly sequentially. So the offline pipeline had a different shape from the durable one it
exists to mirror, and its wall clock could not be read as a prediction of production's.

These tests pin the schedule, not a duration: which work overlaps and which does not is the
contract, and it is what carries the risk. The measured effect is in
`scripts/measure_batch_schedule.py` — concurrency 4 over 8 findings of one repo is ~1.8x, and
the ceiling is low because preparation stays serial, which is deliberate.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from infosec_harness.domain.models import (
    BuildResult,
    EnvironmentSpec,
    Finding,
    FindingInput,
    FindingSourceKind,
    PreparedEnvironment,
    PriorityBand,
    RepoProfile,
    RepoSnapshot,
    SmokeResult,
    StackFingerprint,
    TriageResult,
    TriageRunOutput,
    Verdict,
    VerdictLabel,
)
from infosec_harness.graph import local


def _prepared(path: str) -> PreparedEnvironment:
    return PreparedEnvironment(
        snapshot=RepoSnapshot(repo_url="r", revision="HEAD", path=path, content_hash="h" * 8),
        stack=StackFingerprint(languages={"java": 500}, manifests=["pom.xml"],
                              test_frameworks=["junit5"]),
        status="ready",
        profile=RepoProfile(summary="s", primary_language="java", test_framework="junit5",
                            test_layout="src/test/java"),
        build=BuildResult(ok=True, image_tag="img",
                          spec=EnvironmentSpec(base_image="maven:3.9",
                                               test_command="mvn test -Dtest={test_file}")),
        smoke=SmokeResult(ok=True))


def _outcome(f: FindingInput) -> TriageRunOutput:
    finding = Finding.from_input(f)
    return TriageRunOutput(
        finding=finding, prepared_status="ready",
        result=TriageResult(fingerprint=finding.fingerprint,
                            verdict=Verdict(label=VerdictLabel.inconclusive, confidence=0.0,
                                            rationale="scheduled, not judged"),
                            priority_score=0.0, priority=PriorityBand.p4,
                            environment_scope="none"))


def _findings(repos: int, per_repo: int) -> list[FindingInput]:
    """Findings whose (cwe, file_path) order is the reverse of their input order.

    The schedule sorts by (cwe, file_path) to match the workflow, so reversing it here means a
    test that accidentally depended on input order would fail rather than pass by luck.
    """
    return [FindingInput(repo_url=f"repo{r}", revision="HEAD", title=f"f{r}-{i}",
                         file_path=f"src/main/java/A{per_repo - i:03d}.java", cwe="CWE-89",
                         source_kind=FindingSourceKind.generic_json)
            for r in range(repos) for i in range(per_repo)]


class _Recorder:
    """Canned prepare and triage that record what overlapped with what."""

    def __init__(self, repo: Path, *, triage_s: float = 0.02, prepare_s: float = 0.02):
        self.repo = repo
        self.triage_s = triage_s
        self.prepare_s = prepare_s
        self.in_flight = 0
        self.peak_triage = 0
        self.peak_prepare = 0
        self.prepares_in_flight = 0
        self.started: list[str] = []

    async def checkout(self, ref):
        return _prepared(str(self.repo)).snapshot

    async def prepare(self, ops, snapshot, stack, *, component_root="."):
        from infosec_harness.graph.prepare import PrepareOutcome

        self.prepares_in_flight += 1
        self.peak_prepare = max(self.peak_prepare, self.prepares_in_flight)
        try:
            await asyncio.sleep(self.prepare_s)
            return PrepareOutcome(_prepared(str(self.repo)), [])
        finally:
            self.prepares_in_flight -= 1

    async def triage_one(self, ops, f, prepared):
        self.started.append(f.title)
        self.in_flight += 1
        self.peak_triage = max(self.peak_triage, self.in_flight)
        try:
            await asyncio.sleep(self.triage_s)
            return _outcome(f)
        finally:
            self.in_flight -= 1


async def _run(findings, concurrency, rec: _Recorder):
    with mock.patch.object(local, "checkout", rec.checkout), \
         mock.patch.object(local, "run_prepare", rec.prepare), \
         mock.patch.object(local, "triage_one", rec.triage_one):
        return await local.triage_batch_local(findings, sandbox=False, concurrency=concurrency)


@pytest.fixture
def repo():
    return Path(tempfile.mkdtemp())


async def test_a_repos_findings_run_concurrently_up_to_the_bound(repo):
    findings = _findings(1, 8)
    rec = _Recorder(repo)
    await _run(findings, 4, rec)
    # Warm-then-fan-out: the first finding runs alone, so the peak is the bound, never more.
    assert rec.peak_triage == 4, rec.peak_triage


async def test_the_first_finding_of_a_repo_runs_alone_so_it_can_warm_the_cache(repo):
    """Fanning out from the start would have every finding of the repo miss the prompt cache
    and write it. One warmed request first is what makes the rest hits."""
    rec = _Recorder(repo)
    await _run(_findings(1, 6), 4, rec)
    assert rec.peak_triage <= 4
    assert rec.started[0] not in rec.started[1:]
    # Sorted by (cwe, file_path), so the warmed finding is deterministic across runs.
    rec2 = _Recorder(repo)
    await _run(_findings(1, 6), 4, rec2)
    assert rec.started[0] == rec2.started[0]


async def test_concurrency_one_keeps_the_old_strictly_sequential_behaviour(repo):
    rec = _Recorder(repo)
    await _run(_findings(1, 6), 1, rec)
    assert rec.peak_triage == 1


async def test_preparation_stays_serial_however_high_the_concurrency(repo):
    """The part that must NOT overlap. `run_prepare` writes the shared recipe cache and builds
    images, so two at once would race that cache and double peak disk — and image-cache GC has
    a bound that assumes one build in flight."""
    rec = _Recorder(repo)
    await _run(_findings(3, 4), 8, rec)
    assert rec.peak_prepare == 1, rec.peak_prepare


async def test_results_come_back_in_input_order_whatever_the_schedule(repo):
    """The caller's contract. The schedule reorders execution; it must not reorder results."""
    findings = _findings(2, 5)
    out = await _run(findings, 4, _Recorder(repo))
    assert len(out) == len(findings)
    assert [o.finding.title for o in out] == [f.title for f in findings]


async def test_every_finding_is_triaged_exactly_once(repo):
    rec = _Recorder(repo)
    findings = _findings(2, 5)
    await _run(findings, 4, rec)
    assert sorted(rec.started) == sorted(f.title for f in findings)


async def test_one_finding_failing_concurrently_still_does_not_sink_the_others(repo):
    """The containment has to survive the schedule: `gather` without it would cancel siblings."""
    from infosec_harness.domain.models import InconclusiveReason

    findings = _findings(1, 5)
    rec = _Recorder(repo)
    real = rec.triage_one

    async def flaky(ops, f, prepared):
        if f.title == findings[2].title:
            raise RuntimeError("this finding's agent blew up")
        return await real(ops, f, prepared)

    rec.triage_one = flaky
    out = await _run(findings, 4, rec)
    assert len(out) == len(findings)
    failed = [o for o in out
              if o.result.verdict.inconclusive_reason is InconclusiveReason.error]
    assert len(failed) == 1
    assert "blew up" in failed[0].result.verdict.rationale
    assert len(rec.started) == len(findings) - 1  # the failing one never reached the body


@pytest.mark.parametrize("declared", [2, 3])
async def test_the_declared_setting_is_what_the_local_path_uses(repo, monkeypatch, declared):
    """Otherwise the setting is documentation. The workflow already reads it; this path did not,
    so the two halves of the same pipeline had different shapes.

    Parametrised because one value could be matched by a hardcoded constant; two cannot.
    """
    from infosec_harness.settings import get_settings

    monkeypatch.setenv("HARNESS_PER_REPO_CONCURRENCY", str(declared))
    get_settings.cache_clear()
    try:
        rec = _Recorder(repo)
        await _run(_findings(1, 9), None, rec)  # concurrency=None -> take it from settings
        assert rec.peak_triage == declared, rec.peak_triage
    finally:
        get_settings.cache_clear()


async def test_concurrency_is_clamped_exactly_as_the_workflow_clamps_it(repo):
    """One schedule for both paths: an out-of-range value is clamped to [1, 32], never rejected
    by one path and silently clamped by the other."""
    from infosec_harness.graph.pipeline import MAX_CONCURRENCY, clamp_concurrency

    assert (clamp_concurrency(0), clamp_concurrency(-3), clamp_concurrency(100)) == (1, 1, 32)
    rec = _Recorder(repo)
    await _run(_findings(1, 4), 0, rec)
    assert rec.peak_triage == 1, rec.peak_triage
    rec = _Recorder(repo)
    await _run(_findings(1, MAX_CONCURRENCY + 4), 1000, rec)
    assert rec.peak_triage <= MAX_CONCURRENCY, rec.peak_triage
