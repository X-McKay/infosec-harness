"""Tool/skill-usage evaluators: proven with a scripted tool-calling model (no live model).

Under stub models no tools are called (rates are 0). This test scripts a model that calls
the expected repo tool and loads the matching CWE skill, and asserts the inspector detects
them, the tools actually execute (real content), and the expectation checker passes — then
a negative model that skips them must fail the check.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from pydantic_ai.messages import ModelMessage, ModelResponse, ToolCallPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.registry import build_agent
from infosec_harness.agents.render import render_prompt
from infosec_harness.domain.models import StackFingerprint
from infosec_harness.evals.trajectory import (
    AGENT_EXPECTATIONS,
    TrajectoryExpectation,
    check_expectations,
    cwe_skill_prefix,
    inspect_messages,
)


def test_cwe_skill_prefix():
    assert cwe_skill_prefix("CWE-89") == "cwe-89"
    assert cwe_skill_prefix("cwe-22") == "cwe-22"
    assert cwe_skill_prefix(None) is None


def test_check_expectations_pass_and_fail():
    exp = TrajectoryExpectation(tool_groups=(frozenset({"read_file", "search_code"}),),
                                skill_prefixes=("cwe-89",))
    ok = check_expectations(["read_file"], ["cwe-89-sql-injection"], exp)
    assert ok.ok and ok.tools_ok and ok.skills_ok
    bad = check_expectations([], [], exp)
    assert not bad.ok
    assert bad.missing_tool_groups and bad.missing_skill_prefixes


def _context_agent():
    return build_agent("context", durable=False)


async def _run_context(model, cwe="CWE-89"):
    repo = tempfile.mkdtemp()
    Path(repo, "app.py").write_text("import sqlite3\n\n\ndef get(c, n):\n    return c.execute('SELECT '+n)\n")
    agent = _context_agent()
    stack = StackFingerprint(languages={"python": 1}, test_frameworks=["pytest"])
    prompt = render_prompt("gather context", {"finding": {"cwe": cwe, "file_path": "app.py"}}, stack=stack)
    with agent.override(model=model):
        return await agent.run(prompt, deps=AgentDeps(repo_path=repo))


def _scripted(calls):
    it = iter(calls)

    def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        try:
            return ModelResponse(parts=next(it))
        except StopIteration:
            return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {
                "summary": "s", "reachability": "reachable", "reachability_rationale": "r"})])

    return FunctionModel(fn)


async def test_trajectory_detects_tools_and_skills():
    model = _scripted([
        [ToolCallPart("load_capability", {"id": "cwe-89-sql-injection"})],
        [ToolCallPart("read_file", {"path": "app.py", "start_line": 1, "end_line": 5})],
    ])
    result = await _run_context(model)
    tools, skills = inspect_messages(result.all_messages())
    assert "read_file" in tools
    assert "cwe-89-sql-injection" in skills
    # the read tool actually executed and returned real content (not just recorded)
    assert any("c.execute" in str(m) for m in result.all_messages())
    # expectation check for context on a CWE-89 finding passes
    base = AGENT_EXPECTATIONS["context"]
    exp = TrajectoryExpectation(tool_groups=base.tool_groups, skill_prefixes=(cwe_skill_prefix("CWE-89"),))
    assert check_expectations(tools, skills, exp).ok


async def test_trajectory_flags_missing_tool_and_skill_use():
    # A model that reads nothing and loads no skill must fail the expectation check.
    model = _scripted([])  # goes straight to output
    result = await _run_context(model)
    tools, skills = inspect_messages(result.all_messages())
    assert tools == [] and skills == []
    base = AGENT_EXPECTATIONS["context"]
    exp = TrajectoryExpectation(tool_groups=base.tool_groups, skill_prefixes=(cwe_skill_prefix("CWE-89"),))
    res = check_expectations(tools, skills, exp)
    assert not res.ok and res.missing_tool_groups and res.missing_skill_prefixes


async def test_wrong_cwe_skill_does_not_satisfy_match():
    # Loading a different CWE skill must not count as the matching one.
    model = _scripted([
        [ToolCallPart("load_capability", {"id": "cwe-22-path-traversal"})],
        [ToolCallPart("read_file", {"path": "app.py"})],
    ])
    result = await _run_context(model)
    tools, skills = inspect_messages(result.all_messages())
    exp = TrajectoryExpectation(tool_groups=(frozenset({"read_file"}),), skill_prefixes=("cwe-89",))
    res = check_expectations(tools, skills, exp)
    assert res.tools_ok and not res.skills_ok  # read the file, but wrong skill
