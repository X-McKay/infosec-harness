"""System validation: for every agent, prove the wiring, tools, skills, and contracts.

This is the repeatable form of the per-agent step-through. It does not validate model
*judgment* (that needs live models + the eval corpus); it validates that each agent is
offered exactly the tools and skills it should be, that those tools execute and are
path-confined, that skills load with real content, that every agent emits its typed
output contract, and that the deterministic guards reject bad output.
"""

from __future__ import annotations

import contextlib
from types import SimpleNamespace

import pytest
from pydantic_ai import ModelRetry
from pydantic_ai.models.test import TestModel

from infosec_harness.agents import capabilities as caps
from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.registry import AGENT_BINDINGS, build_agent, load_spec
from infosec_harness.agents.render import render_prompt
from infosec_harness.agents.validators import validate_probe, verdict_violations
from infosec_harness.domain.models import (
    DiagnosisKind,
    ProbeExecution,
    ProbeSource,
    Reachability,
    StackFingerprint,
    Verdict,
    VerdictFacts,
    VerdictLabel,
)
from infosec_harness.settings import get_settings

# The tools each agent must expose to the model (design contract).
#
# `repo_digest` is the one tool not given to every repo agent, and the split is deliberate. It
# answers "what is this repository" in a single call, which is recon's and env-planner's whole
# job; every other repo agent is handed the finished RepoProfile in its prompt, so for them the
# digest would restate what they already know and cost a 20-40 kB tool result that every later
# request of the run resends. Widening this set is a design decision, not a formality: assert
# the tools each agent should have, not the tools it happens to have.
REPO = {
    "load_capability",
    "list_tree",
    "list_files",
    "read_file",
    "read_files",
    "search_code",
    "describe_callables",
}
PROFILING = REPO | {"repo_digest"}
EXPECTED_TOOLS = {
    "intake": {"load_capability"},
    "recon": PROFILING,
    "env-planner": PROFILING,
    "build-repair": REPO | {"run_in_sandbox"},
    "partial-build": REPO,
    "context": REPO,
    "probe-planner": {"load_capability"},
    "probe-author": REPO | {"inspect_target"},
    "probe-diagnosis": {"load_capability"},
    "probe-repair": REPO | {"inspect_target"},
    "verdict": set(),
}


async def _model_facing_tools(name: str) -> set[str]:
    agent = build_agent(name, durable=False)
    tm = TestModel(call_tools=[])
    with agent.override(model=tm), contextlib.suppress(Exception):
        await agent.run("x", deps=AgentDeps(repo_path="/tmp"))
    params = tm.last_model_request_parameters
    return {t.name for t in (params.function_tools if params else [])}


def _configured_skills(spec) -> list[str]:
    for cap in spec.capabilities:
        if cap.name == "Skills":
            return list((cap.kwargs or {}).get("include") or [])
    return []


@pytest.mark.parametrize("name", list(AGENT_BINDINGS))
async def test_agent_tool_wiring(name):
    assert await _model_facing_tools(name) == EXPECTED_TOOLS[name]


async def test_partial_build_plans_without_shell_but_build_repair_can_inspect_images():
    """Planning a module boundary needs repository evidence; build repair owns image checks.

    A fresh image has no repository or previous build state, so shell exploration cannot
    establish the partial module's dependency boundary. Check the actual model surface,
    independently of the spec's toolset declarations.
    """
    assert "run_in_sandbox" not in await _model_facing_tools("partial-build")
    assert "run_in_sandbox" in await _model_facing_tools("build-repair")


@pytest.mark.parametrize("name", list(AGENT_BINDINGS))
def test_configured_skills_exist(name):
    root = get_settings().agents_dir.parent / "skills"
    for skill in _configured_skills(name and load_spec(name)):
        assert (root / skill / "SKILL.md").exists(), f"{name} references missing skill {skill}"


@pytest.mark.parametrize("name", list(AGENT_BINDINGS))
def test_model_and_thinking_pinned(name):
    spec = load_spec(name)
    assert spec.model, f"{name} must pin a model tier for cache stability"
    # thinking is pinned per agent (never varied per request) except where omitted by design.
    assert (spec.model_settings or {}).get("thinking") in {"low", "medium", "high", None}


def test_repo_tools_execute_and_confine(tmp_path):
    (tmp_path / "app.py").write_text("import os\ndef run(c):\n    os.system('sh -c ' + c)\n")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "u.py").write_text("SECRET=1\n")
    ctx = SimpleNamespace(deps=AgentDeps(repo_path=str(tmp_path)))
    assert "app.py" in caps.list_files(ctx, ".", "*.py")
    body = caps.read_file(ctx, "app.py", 1, 3)
    assert "os.system" in body and "lines 1-3" in body
    assert "app.py:3" in caps.search_code(ctx, r"os\.system", "*.py")
    for bad in ("../../etc/passwd", "pkg/../../../etc/hosts"):
        with pytest.raises(ModelRetry):
            caps.read_file(ctx, bad)


def test_skills_load_with_real_content():
    from pydantic_ai_harness.skills import Skills

    root = str(get_settings().agents_dir.parent / "skills")
    sk = Skills(root, include=["cwe-89-sql-injection", "probe-oracle-protocol"])
    discovered = {
        getattr(c, "name", getattr(c, "id", "?")) for c in getattr(sk, "_deferred_capabilities", ())
    }
    assert {"cwe-89-sql-injection", "probe-oracle-protocol"} <= discovered


@pytest.mark.parametrize("name", list(AGENT_BINDINGS))
async def test_agent_emits_typed_contract(name):
    stack = StackFingerprint(
        languages={"python": 3}, test_frameworks=["pytest"], manifests=["requirements.txt"]
    )
    payload = {"oracle_nonce": "testnonce"}
    if name == "probe-diagnosis":
        payload = {
            "probe_execution": ProbeExecution(
                attempt=1, exit_code=0, oracle_fired=True, precondition_reached=True
            ).model_dump()
        }
    facts = None
    if name == "verdict":
        facts = VerdictFacts(
            environment_ready=True,
            oracle_fired=True,
            precondition_reached=True,
            last_diagnosis=DiagnosisKind.valid_positive,
            reachability=Reachability.reachable,
        )
    agent = build_agent(name, durable=False)
    result = await agent.run(
        render_prompt("do the task", payload, stack=stack),
        deps=AgentDeps(repo_path="/tmp", sandbox_image="img", facts=facts),
    )
    assert isinstance(result.output, AGENT_BINDINGS[name])


CONFORMANT_PROBE = (
    "print('HARNESS_PRECONDITION::x')\n"
    "result = target('payload')\n"
    "print('HARNESS_SINK_RETURNED::x')\n"
    "if 'x' in str(result):\n"
    "    print('HARNESS_ORACLE::x')\n"
)


def test_probe_guard_rejects_bad_probes(tmp_path):
    ctx = SimpleNamespace(deps=AgentDeps(repo_path=str(tmp_path)))
    assert validate_probe(ctx, ProbeSource(test_file_path="tests/t.py", content=CONFORMANT_PROBE))
    with pytest.raises(ModelRetry):  # no markers at all
        validate_probe(ctx, ProbeSource(test_file_path="tests/t.py", content="print('hi')"))
    with pytest.raises(ModelRetry, match="sink-returned"):
        # Reaching the sink is not the same as the call completing; without the second marker a
        # probe that threw on the way in is indistinguishable from a clean negative.
        validate_probe(
            ctx,
            ProbeSource(
                test_file_path="tests/t.py",
                content="print('HARNESS_PRECONDITION::x')\nprint('HARNESS_ORACLE::x')\n",
            ),
        )
    with pytest.raises(ModelRetry, match="oracle signal"):
        # A probe with no oracle branch can never report exploitability, so it is useless.
        validate_probe(
            ctx,
            ProbeSource(
                test_file_path="tests/t.py",
                content="print('HARNESS_PRECONDITION::x')\nprint('HARNESS_SINK_RETURNED::x')\n",
            ),
        )
    with pytest.raises(ModelRetry):  # path traversal
        validate_probe(ctx, ProbeSource(test_file_path="../evil.py", content="HARNESS_ORACLE::x"))


def test_verdict_guard_blocks_unsupported_exploitable_claim():
    v = Verdict(label=VerdictLabel.potentially_exploitable, confidence=0.9, rationale="x")
    assert verdict_violations(
        v, VerdictFacts(environment_ready=True, oracle_fired=False)
    )  # blocked
    assert (
        verdict_violations(
            v,
            VerdictFacts(
                environment_ready=True,
                oracle_fired=True,
                precondition_reached=True,
                last_diagnosis=DiagnosisKind.valid_positive,
            ),
        )
        == []
    )
