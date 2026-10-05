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
from infosec_harness.agents.trajectory import trace_calls
from infosec_harness.domain.models import StackFingerprint
from infosec_harness.evals.trajectory import (
    AGENT_EXPECTATIONS,
    TrajectoryExpectation,
    check_expectations,
    cwe_skill_prefix,
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
                "summary": "s", "reachability": "reachable", "reachability_rationale": "r",
                "source": None, "sink": None, "path": [], "sanitizers": []})])

    return FunctionModel(fn)


async def test_trajectory_detects_tools_and_skills():
    model = _scripted([
        [ToolCallPart("load_capability", {"id": "cwe-89-sql-injection"})],
        [ToolCallPart("read_file", {"path": "app.py", "start_line": 1, "end_line": 5})],
    ])
    result = await _run_context(model)
    trace = trace_calls(result.all_messages())
    tools, skills = trace.tools, trace.skills
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
    trace = trace_calls(result.all_messages())
    tools, skills = trace.tools, trace.skills
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
    trace = trace_calls(result.all_messages())
    tools, skills = trace.tools, trace.skills
    exp = TrajectoryExpectation(tool_groups=(frozenset({"read_file"}),), skill_prefixes=("cwe-89",))
    res = check_expectations(tools, skills, exp)
    assert res.tools_ok and not res.skills_ok  # read the file, but wrong skill


# --- Reporting must not claim a skill check that never ran ---

def test_agents_without_a_skill_expectation_are_not_reported_as_passing():
    """An empty skill_prefixes trivially satisfies the check.

    Printing that as 100% claims a pass that was never tested — which is how recon and
    env-planner appeared to be loading their skills perfectly while nothing was asserted.
    """
    from infosec_harness.evals.trajectory import AGENT_EXPECTATIONS, scores_skills

    for agent, exp in AGENT_EXPECTATIONS.items():
        assert scores_skills(agent) is bool(exp.skill_prefixes), agent
    assert scores_skills("recon") is False
    assert scores_skills("env-planner") is False
    assert scores_skills("context") is True
    assert scores_skills("probe-author") is True
    assert scores_skills("no_such_agent") is False


def test_a_vacuous_skill_pass_is_still_reported_as_ok_by_check_expectations():
    """The scoring primitive is unchanged; only the reporting distinguishes the two."""
    from infosec_harness.evals.trajectory import TrajectoryExpectation, check_expectations

    res = check_expectations(["read_file"], [], TrajectoryExpectation(tool_groups=()))
    assert res.skills_ok and not res.missing_skill_prefixes


def _calls(*specs) -> list[ModelMessage]:
    """One response per (tool_name, args) pair, in order."""
    return [ModelResponse(parts=[ToolCallPart(tool_name=n, args=a)]) for n, a in specs]


def test_reading_different_files_is_not_counted_as_repetition():
    """Legitimate exploration must stay invisible, or the signal is useless noise."""
    messages = _calls(("read_file", {"path": "a.py"}), ("read_file", {"path": "b.py"}),
                      ("describe_callables", {"path": "a.py"}))
    assert trace_calls(messages).repeated == {}


def test_the_same_call_made_repeatedly_is_counted():
    """The distinction tool evocation cannot make: eight reads of one file vs one read."""
    messages = _calls(*[("read_file", {"path": "a.py"})] * 8)
    repeated = trace_calls(messages).repeated
    assert repeated == {"read_file(path='a.py')": 8}, repeated


def test_a_loop_and_legitimate_work_are_distinguishable_at_equal_call_counts():
    """Both runs make six calls and evoke the same tool, so only argument-awareness separates
    them. This is the property that makes a request_limit breach diagnosable from the record.
    """
    working = _calls(*[("read_file", {"path": f"f{i}.py"}) for i in range(6)])
    looping = _calls(*[("read_file", {"path": "f0.py"}) for _ in range(6)])
    assert (trace_calls(working).tools, trace_calls(working).skills) == (
        trace_calls(looping).tools, trace_calls(looping).skills), "premise: indistinguishable before"
    assert trace_calls(working).repeated == {}
    assert trace_calls(looping).repeated == {"read_file(path='f0.py')": 6}


def test_argument_order_does_not_create_spurious_distinct_keys():
    messages = _calls(("read_file", {"path": "a.py", "start_line": 1}),
                      ("read_file", {"start_line": 1, "path": "a.py"}))
    assert trace_calls(messages).repeated == {"read_file(path='a.py', start_line=1)": 2}


def test_output_tool_calls_are_excluded_like_they_are_from_evocation():
    messages = _calls(*[("final_result", {"kind": "x"})] * 3)
    assert trace_calls(messages).repeated == {}


def test_malformed_skill_arguments_are_recorded_not_raised():
    """Regression: evocation read ``load_capability`` arguments without a malformed-args
    policy, so the raw text of a malformed call was recorded as a loaded skill. Every view now
    shares one policy: malformed arguments are ``None``."""
    messages = _calls(("load_capability", "{bad"), ("load_capability", "{bad"),
                      ("read_file", "{also bad"))
    trace = trace_calls(messages)
    assert trace.skills == [] and trace.tools == ["read_file"]
    assert trace.repeated == {"load_capability(None)": 2}


def test_runtime_and_eval_summaries_agree_on_repetition():
    from infosec_harness.evals.trajectory import summarize_calls
    messages = _calls(("read_file", {"path": "a.py"}), ("read_file", {"path": "a.py"}),
                      ("read_file", "{bad"), ("read_file", "{bad"))
    repeated = trace_calls(messages).repeated
    assert sum(n - 1 for n in repeated.values()) == summarize_calls(messages)[
        "repeated_call_count"] == 2
