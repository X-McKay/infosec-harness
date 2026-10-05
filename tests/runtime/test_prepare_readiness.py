from __future__ import annotations

from infosec_harness.domain.models import (
    AgentOutcome,
    BuildResult,
    EnvironmentSpec,
    RepoProfile,
    RepoSnapshot,
    SmokeResult,
    StackFingerprint,
)
from infosec_harness.graph.prepare import run_prepare


def _spec(*, repaired: bool = False) -> EnvironmentSpec:
    return EnvironmentSpec(
        base_image="python:3.12-slim",
        install_commands=["pip install pytest"] if repaired else [],
        test_command="python -m pytest {test_file}",
    )


class _Ops:
    def __init__(self, *, progress: bool):
        self.progress = progress
        self.repairs = 0
        self.smokes = 0

    async def run_agent(self, name, prompt, deps, *, record=None):
        if name == "recon":
            output = RepoProfile(summary="fixture", primary_language="python",
                                 test_framework="pytest", test_layout="tests")
        elif name == "env-planner":
            output = _spec()
        elif name == "build-repair":
            self.repairs += 1
            output = _spec(repaired=self.progress)
        else:  # pragma: no cover - a failure makes the assertion clearer than a mock default
            raise AssertionError(name)
        outcome = AgentOutcome(output=output, agent=name)
        if record is not None:
            record.append(outcome)
        return outcome

    async def lookup_recipe(self, stack):
        return None

    async def record_recipe(self, stack, spec, *, worked):
        return None

    async def build_environment(self, snapshot, spec):
        return BuildResult(ok=True, image_tag="image", spec=spec)

    async def smoke_test(self, image_tag, test_command="", *, language="", module_path=""):
        self.smokes += 1
        return SmokeResult(ok=self.smokes > 1, output_excerpt="pytest missing")


async def _prepare(tmp_path, ops):
    (tmp_path / "app.py").write_text("x = 1\n")
    snapshot = RepoSnapshot(repo_url=str(tmp_path), revision="HEAD", path=str(tmp_path),
                            content_hash="a" * 64)
    stack = StackFingerprint(languages={"python": 1}, test_frameworks=["pytest"])
    return await run_prepare(ops, snapshot, stack)


async def test_readiness_failure_returns_to_bounded_environment_repair(tmp_path):
    ops = _Ops(progress=True)
    outcome = await _prepare(tmp_path, ops)
    assert outcome.prepared.status == "ready"
    assert ops.repairs == 1
    assert outcome.prepared.attempts == 1


async def test_equivalent_readiness_plan_stops_as_no_progress(tmp_path):
    ops = _Ops(progress=False)
    outcome = await _prepare(tmp_path, ops)
    assert outcome.prepared.status == "failed"
    assert outcome.prepared.reason == "readiness_repair_no_progress"
    assert ops.repairs == 1
