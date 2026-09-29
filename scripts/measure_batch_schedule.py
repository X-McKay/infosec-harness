"""Measure what per-repo concurrency buys the in-process batch path, offline.

    uv run python scripts/measure_batch_schedule.py

No provider and no container: every agent and every build is a canned coroutine with a fixed
`asyncio.sleep`, so the elapsed time measured is the *schedule* and nothing else. That is the
only honest thing to measure here — a real run's wall clock is dominated by provider and
container latency, which this deliberately stands in for with a constant.

The per-finding latency stands in for one triage's serial chain of agent calls; the prepare
latency for one repository's recon/env-planner/build. Both are arbitrary, and the ratio between
the schedules is what carries over, not the seconds.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from unittest import mock

from infosec_harness.domain.models import (
    BuildResult,
    EnvironmentSpec,
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

PREPARE_S = 0.30
PER_FINDING_S = 0.10


def _prepared(path: str) -> PreparedEnvironment:
    stack = StackFingerprint(languages={"java": 500}, manifests=["pom.xml"],
                             test_frameworks=["junit5"])
    return PreparedEnvironment(
        snapshot=RepoSnapshot(repo_url="r", revision="HEAD", path=path, content_hash="h" * 8),
        stack=stack, status="ready",
        profile=RepoProfile(summary="s", primary_language="java", test_framework="junit5",
                            test_layout="src/test/java"),
        build=BuildResult(ok=True, image_tag="img",
                          spec=EnvironmentSpec(base_image="maven:3.9",
                                               test_command="mvn test -Dtest={test_file}")),
        smoke=SmokeResult(ok=True),
    )


def _outcome(f: FindingInput) -> TriageRunOutput:
    from infosec_harness.intake import adapters

    finding = adapters.to_finding(f)
    return TriageRunOutput(
        finding=finding, prepared_status="ready",
        result=TriageResult(fingerprint=finding.fingerprint,
                            verdict=Verdict(label=VerdictLabel.inconclusive, confidence=0.0,
                                            rationale="measured, not judged"),
                            priority_score=0.0, priority=PriorityBand.p4,
                            environment_scope="none"))


async def elapsed(findings: list[FindingInput], concurrency: int, repo: Path) -> float:
    async def fake_checkout(ref):
        return _prepared(str(repo)).snapshot

    async def fake_prepare(ops, snapshot, stack):
        from infosec_harness.graph.prepare import PrepareOutcome

        await asyncio.sleep(PREPARE_S)
        return PrepareOutcome(_prepared(str(repo)), [])

    async def fake_triage_one(ops, f, prepared):
        await asyncio.sleep(PER_FINDING_S)
        return _outcome(f)

    with mock.patch.object(local, "checkout", fake_checkout), \
         mock.patch.object(local, "run_prepare", fake_prepare), \
         mock.patch.object(local, "triage_one", fake_triage_one):
        start = time.monotonic()
        out = await local.triage_batch_local(findings, sandbox=False, concurrency=concurrency)
        took = time.monotonic() - start
    assert len(out) == len(findings), (len(out), len(findings))
    return took


def _findings(repos: int, per_repo: int) -> list[FindingInput]:
    return [FindingInput(repo_url=f"repo{r}", revision="HEAD", title=f"f{r}-{i}",
                         file_path=f"src/main/java/A{i}.java", cwe="CWE-89",
                         source_kind=FindingSourceKind.generic_json)
            for r in range(repos) for i in range(per_repo)]


def main() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        print(f"\nBatch schedule (canned latencies: prepare {PREPARE_S}s/repo, "
              f"triage {PER_FINDING_S}s/finding)\n")
        header = (f"{'repos':>6} {'findings/repo':>14} {'concurrency':>12} {'elapsed s':>10} "
                  f"{'ideal s':>9} {'speedup':>8}")
        print(header)
        print("-" * len(header))
        for repos, per_repo in ((1, 8), (3, 6)):
            findings = _findings(repos, per_repo)
            base = asyncio.run(elapsed(findings, 1, repo))
            for c in (1, 4, 8):
                took = asyncio.run(elapsed(findings, c, repo))
                # Warm-then-fan-out: one finding serially, then ceil((n-1)/c) waves.
                waves = 1 + -(-(per_repo - 1) // c)
                ideal = repos * (PREPARE_S + waves * PER_FINDING_S)
                print(f"{repos:>6} {per_repo:>14} {c:>12} {took:>10.2f} {ideal:>9.2f} "
                      f"{base / took:>7.2f}x")
            print()


if __name__ == "__main__":
    main()
