"""Preparation and probe-time environment repair render byte-identical prompts.

The digests below were recorded from the implementation before the revise-and-rebuild loops
were collapsed into one helper. Each scenario drives every branch of a loop (recipe eviction,
full-build repair, equivalent-plan exit, partial build, readiness repair, probe-time repair),
and the digest covers the agent name, its dependencies and every prompt part, so a refactor
that reorders a payload key, rewords an instruction or changes which image an agent is shown
fails here rather than silently invalidating every prompt-cache prefix and eval baseline.
"""

from __future__ import annotations

import hashlib
import json

from pydantic_graph import GraphRunContext

from infosec_harness.domain.models import (
    AgentOutcome,
    BuildResult,
    DiagnosisKind,
    EnvironmentSpec,
    PreparedEnvironment,
    ProbeDiagnosis,
    ProbeExecution,
    ProbeSource,
    RepoProfile,
    RepoSnapshot,
    SmokeResult,
    StackFingerprint,
)
from infosec_harness.graph.prepare import run_prepare
from infosec_harness.graph.triage import RepairEnvironment, TriageDeps, TriageState

# Re-recorded when StackFingerprint dropped its never-populated `registries` field: the only
# difference from the previous digests is `"registries":[]` leaving the rendered fingerprint
# (verified by re-inserting it and reproducing the earlier values).
PREPARE_COMPONENT_DIGEST = "003bfb9c4fda34a6a5eacd6140ca5d52b709e3d334b76b08846c7835745c69a9"
PREPARE_ROOT_DIGEST = "7dc0061ce80b171b610aea10c527bcdc2d370a11699103effb5bc396295b0ef5"
REPAIR_ENVIRONMENT_DIGEST = "467b7e4c9ff9cf17b77d42b4a10295e4b4c0ec20de1c8b7350b01fde4ed46a57"


def _spec(name: str) -> EnvironmentSpec:
    return EnvironmentSpec(base_image=f"python:{name}", install_commands=[f"pip install {name}"],
                           test_command="python -m pytest {test_file}")


_PROFILE = RepoProfile(summary="fixture", primary_language="python", test_framework="pytest",
                       test_layout="tests")


class _ScriptedOps:
    """Answers each agent from a script and each build/smoke from a queue; records prompts."""

    def __init__(self, *, recipe: EnvironmentSpec | None, agents: dict[str, list],
                 builds: list[bool], smokes: list[bool]) -> None:
        self.recipe = recipe
        self.agents = {name: list(outputs) for name, outputs in agents.items()}
        self.builds = list(builds)
        self.smokes = list(smokes)
        self.calls: list[dict] = []

    async def run_agent(self, name, prompt, deps, *, record=None):
        self.calls.append({
            "agent": name,
            "deps": deps.model_dump(mode="json", include={"repo_path", "sandbox_image",
                                                          "source_files", "report_text"}),
            "prompt": [part if isinstance(part, str) else type(part).__name__ for part in prompt],
        })
        outcome = AgentOutcome(output=self.agents[name].pop(0), agent=name)
        if record is not None:
            record.append(outcome)
        return outcome

    async def lookup_recipe(self, stack):
        return self.recipe

    async def record_recipe(self, stack, spec, *, worked):
        self.calls.append({"record_recipe": spec.base_image, "worked": worked})

    async def build_environment(self, snapshot, spec):
        ok = self.builds.pop(0)
        return BuildResult(ok=ok, image_tag="image" if ok else None, spec=spec,
                           error_excerpt="" if ok else f"failed {spec.base_image}")

    async def smoke_test(self, image_tag, test_command="", *, language="", module_path=""):
        self.calls.append({"smoke": [test_command, language, module_path]})
        ok = self.smokes.pop(0)
        return SmokeResult(ok=ok, output_excerpt="" if ok else "runner missing")


def _digest(calls: list[dict]) -> str:
    return hashlib.sha256(json.dumps(calls, sort_keys=True).encode()).hexdigest()


def _fixture(tmp_path) -> tuple[RepoSnapshot, StackFingerprint]:
    (tmp_path / "app.py").write_text("x = 1\n")
    snapshot = RepoSnapshot(repo_url="https://example.invalid/repo.git", revision="HEAD",
                            path="/fixture/checkout", content_hash="a" * 64)
    stack = StackFingerprint(languages={"python": 3}, test_frameworks=["pytest"],
                             manifests=["pyproject.toml"])
    return snapshot, stack


async def test_component_preparation_prompts_are_unchanged(tmp_path):
    snapshot, stack = _fixture(tmp_path)
    ops = _ScriptedOps(
        recipe=_spec("cached"),
        agents={"recon": [_PROFILE], "env-planner": [_spec("planned")],
                "build-repair": [_spec("repair-1"), _spec("repair-1"), _spec("ready-1"),
                                 _spec("ready-1")],
                "partial-build": [_spec("partial-1")]},
        # cached, planned, repair-1, partial-1 (ok), ready-1 (ok)
        builds=[False, False, False, True, True],
        smokes=[False, False],
    )
    outcome = await run_prepare(ops, snapshot, stack, component_root="pkg")
    assert outcome.prepared.status == "failed"
    assert outcome.prepared.reason == "readiness_repair_no_progress"
    assert [i.agent for i in outcome.invocations] == [
        "recon", "env-planner", "build-repair", "build-repair", "partial-build",
        "build-repair", "build-repair"]
    assert _digest(ops.calls) == PREPARE_COMPONENT_DIGEST


async def test_root_preparation_prompts_are_unchanged(tmp_path):
    snapshot, stack = _fixture(tmp_path)
    ops = _ScriptedOps(
        recipe=None,
        agents={"recon": [_PROFILE], "env-planner": [_spec("planned")],
                "build-repair": [_spec("ready-1")]},
        builds=[True, False],
        smokes=[False],
    )
    outcome = await run_prepare(ops, snapshot, stack)
    assert outcome.prepared.status == "failed"
    assert outcome.prepared.reason == "readiness_repair_build_failed"
    assert _digest(ops.calls) == PREPARE_ROOT_DIGEST


async def test_probe_time_environment_repair_prompt_is_unchanged(tmp_path):
    snapshot, stack = _fixture(tmp_path)
    spec = _spec("planned")
    prepared = PreparedEnvironment(
        snapshot=snapshot, stack=stack, profile=_PROFILE,
        build=BuildResult(ok=True, image_tag="image", spec=spec),
        smoke=SmokeResult(ok=True), status="ready")
    ops = _ScriptedOps(recipe=None, agents={"build-repair": [_spec("with-driver")]},
                       builds=[True], smokes=[True])
    state = TriageState(finding=None, prepared=prepared)  # type: ignore[arg-type]
    state.probe = ProbeSource(test_file_path="tests/test_probe.py", content="def test(): pass")
    state.executions.append(ProbeExecution(attempt=1, exit_code=1, oracle_fired=False,
                                           precondition_reached=False,
                                           stderr_tail="No suitable driver found"))
    state.last_diagnosis = ProbeDiagnosis(kind=DiagnosisKind.environment_issue,
                                          explanation="driver missing")
    node = RepairEnvironment()
    following = await node.run(GraphRunContext(state=state, deps=TriageDeps(ops=ops)))
    assert type(following).__name__ == "ExecuteProbe"
    assert state.prepared.build.spec == _spec("with-driver")
    assert [i.agent for i in state.invocations] == ["build-repair"]
    assert _digest(ops.calls) == REPAIR_ENVIRONMENT_DIGEST
