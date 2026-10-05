"""Prompt caching: the structural precondition, and the one thing that breaks it.

The README claims a stable->volatile prompt layout, every spec sets provider cache keys, and
runs record `cache_hit_ratio`. `WarnOnCacheBusts` reads the provider's own verdict, so it says
nothing offline and nothing in a stub run — which meant the claim was unchecked by the suite.

Two halves are checkable without a model, because both are properties of this repository's code:

1. Across the findings of one repository, the text before the `CachePoint` must be
   byte-identical, or the shared prefix the warm-then-fan-out schedule exists to exploit does
   not exist.
2. Within one run, each request's message list must *extend* the previous one. A request that
   rewrites part of the history it already sent cannot be served from cache from that point on,
   and pays full prefill on every request after it.

The second is where the surprise is: `ClearToolResults`, which is what bounds per-request input
(tests/agents/test_context_growth.py), is also what rewrites the history. So the fix for the input
ceiling costs the prompt cache, and the only way to have both is a run whose history never
reaches the compaction trigger — which is what fewer, larger tool calls buys
(tests/agents/test_exploration_cost.py).
"""

from __future__ import annotations

from pathlib import Path

from conftest import load_script
from pydantic_ai.messages import ModelMessage, ModelResponse, ToolCallPart
from pydantic_ai.models.function import AgentInfo

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.registry import DEFAULT_CLEAR_TOOL_TOKENS, build_agent
from infosec_harness.agents.render import render_prompt
from infosec_harness.domain.models import (
    Finding,
    FindingSourceKind,
    OracleKind,
    ProbePlan,
    RepoProfile,
    StackFingerprint,
)

exploration = load_script("exploration")
MEASUREMENT_LIMITS = exploration.MEASUREMENT_LIMITS
common_prefix_len = exploration.common_prefix_len
prefix_report = exploration.prefix_report
recording_model = exploration.recording_model
serialise_history = exploration.serialise_history

_STACK = StackFingerprint(languages={"java": 500}, manifests=["pom.xml"],
                          test_frameworks=["junit5"])
_PROFILE = RepoProfile(summary="s", primary_language="java", test_framework="junit5",
                       test_layout="src/test/java")


def _cacheable_prefix(content) -> str:
    """Everything before the first `CachePoint` — what a provider can serve from cache."""
    cut = next((n for n, c in enumerate(content) if not isinstance(c, str)), len(content))
    return "\n".join(str(c) for c in content[:cut])


def _finding(n: int) -> Finding:
    return Finding(fingerprint=f"{n:016d}", title=f"SQLi {n}", repo_url="r", revision="HEAD",
                   cwe="CWE-89", source_kind=FindingSourceKind.generic_json)


# --- 1. Across the findings of one repository ----------------------------------------------


def test_every_finding_of_one_repo_renders_the_same_cacheable_prefix():
    """The premise of repo-grouped, warm-then-fan-out scheduling.

    If the prefix differed per finding there would be nothing for the warmed request to warm,
    and grouping by repository would buy latency only by accident.
    """
    prefixes = [_cacheable_prefix(render_prompt("Gather context.", {"finding": _finding(i)},
                                                stack=_STACK, profile=_PROFILE))
                for i in range(4)]
    assert len(set(prefixes)) == 1, "the pre-CachePoint text differs between findings"
    assert prefixes[0], "there is no cacheable prefix at all"


def test_the_volatile_half_really_is_after_the_cache_point():
    """Otherwise the test above would pass on a prompt that simply has no finding in it."""
    a = render_prompt("Gather context.", {"finding": _finding(1)}, stack=_STACK, profile=_PROFILE)
    b = render_prompt("Gather context.", {"finding": _finding(2)}, stack=_STACK, profile=_PROFILE)
    assert "\n".join(str(c) for c in a) != "\n".join(str(c) for c in b), (
        "the two prompts are identical, so this proves nothing about where the boundary is"
    )


def test_a_prompt_with_no_repo_context_has_no_cache_point_to_claim_one():
    """An agent given no repo block gets a prompt whose whole text is volatile; saying
    otherwise would credit it with a shared prefix it does not have."""
    content = render_prompt("Do it.", {"finding": _finding(1)})
    assert all(isinstance(c, str) for c in content)


# --- 2. Within one run ---------------------------------------------------------------------

_VALID_PROBE = {
    "test_file_path": "src/test/java/HarnessProbeTest.java",
    "content": ("public class HarnessProbeTest {\n"
                "  // HARNESS_PRECONDITION::n HARNESS_SINK_RETURNED::n HARNESS_ORACLE::n\n}\n"),
    "explanation": "drives the sink",
}
_READS = 14


def _repo_of_large_files(root: Path) -> Path:
    """Idempotent: the compacted and uncompacted arms are run over the same fixture on purpose,
    so that the only difference between them is the capability under test."""
    (root / "pom.xml").write_text("<project/>\n")
    src = root / "src/main/java/com/example"
    src.mkdir(parents=True, exist_ok=True)
    for n in range(_READS):
        # 400 lines is MAX_READ_LINES, so one read returns a whole file in a single result;
        # the files have to be this large for the history to reach the compaction trigger.
        body = "\n".join(f"    void helper_{n}_{i}(String s) {{ /* {'x' * 60} */ }}"
                         for i in range(400))
        (src / f"Big{n:03d}.java").write_text(
            f"package com.example;\npublic class Big{n:03d} {{\n{body}\n}}\n")
    return root


async def _histories(root: Path, *, compact: bool) -> list[list[str]]:
    repo = _repo_of_large_files(root)
    overlay = ({"metadata": {"clear_tool_results": True,
                             "clear_tool_tokens": DEFAULT_CLEAR_TOOL_TOKENS}} if compact
               else {"metadata": {"clear_tool_results": False}})
    agent = build_agent("probe-author", overlay, durable=False)
    reads = iter(f"src/main/java/com/example/Big{n:03d}.java" for n in range(_READS))
    sink: list[list[str]] = []

    def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        try:
            path = next(reads)
        except StopIteration:
            return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, _VALID_PROBE)])
        return ModelResponse(parts=[ToolCallPart("read_file", {
            "path": path, "start_line": 1, "end_line": 400})])

    plan = ProbePlan(hypothesis="h", payload="p", oracle=OracleKind.marker_output,
                     oracle_condition="c", precondition_checkpoint="k",
                     test_file_path="src/test/java/HarnessProbeTest.java")
    prompt = render_prompt("Write the probe.", {"probe_plan": plan, "oracle_nonce": "n"})
    with agent.override(model=recording_model(fn, sink)):
        await agent.run(prompt, deps=AgentDeps(repo_path=str(repo)),
                        usage_limits=MEASUREMENT_LIMITS)
    return sink


async def test_an_uncompacted_run_only_ever_appends_to_its_history(tmp_path):
    """The baseline: ordinary turns extend the prefix, so each one is a cache hit on the last."""
    report = prefix_report(await _histories(tmp_path, compact=False))
    assert len(report.part_counts) > _READS // 2, "the fixture must make many requests"
    assert report.stable, f"the prefix was rewritten at requests {report.rewrites}"


async def test_compaction_rewrites_the_history_and_so_breaks_the_cached_prefix(tmp_path):
    """The cost of bounding the history, measured rather than assumed.

    `ClearToolResults` blanks the oldest tool results *in place*, which is exactly what makes
    per-request input plateau — and exactly what moves the cacheable prefix. Every request after
    the first compaction pays full prefill. Recording it here means the trade-off is a known
    one; the alternative (an unbounded history) fails the input ceiling instead, so neither is
    free and the real fix is a run short enough to need neither.
    """
    report = prefix_report(await _histories(tmp_path, compact=True))
    assert report.rewrites, (
        "compaction never fired, so this says nothing; the fixture must reach "
        f"{DEFAULT_CLEAR_TOOL_TOKENS} estimated tokens"
    )


async def test_the_bust_is_compactions_and_not_the_fixtures(tmp_path):
    """The companion, so the test above cannot keep passing for the wrong reason."""
    uncompacted = prefix_report(await _histories(tmp_path, compact=False))
    compacted = prefix_report(await _histories(tmp_path, compact=True))
    assert uncompacted.stable and compacted.rewrites, (uncompacted.rewrites, compacted.rewrites)
    # Same run otherwise: same number of requests, same number of message parts.
    assert uncompacted.part_counts == compacted.part_counts


# --- the primitives -------------------------------------------------------------------------


def test_common_prefix_len_counts_only_the_leading_agreement():
    assert common_prefix_len(["a", "b", "c"], ["a", "b", "z"]) == 2
    assert common_prefix_len(["a"], ["b"]) == 0
    assert common_prefix_len(["a", "b"], ["a", "b", "c"]) == 2


def test_prefix_report_calls_a_shortened_history_a_rewrite():
    assert prefix_report([["a", "b"], ["a", "b", "c"]]).stable
    assert prefix_report([["a", "b", "c"], ["a", "z", "c"]]).rewrites == [1]
    # A history that merely got shorter is a rewrite too: the dropped part was already sent.
    assert prefix_report([["a", "b", "c"], ["a", "b"]]).rewrites == [1]


def test_serialising_a_history_distinguishes_a_blanked_tool_result():
    """If the serialisation dropped tool content, compaction would look like a no-op."""
    from pydantic_ai.messages import ModelRequest, ToolReturnPart

    kept = ModelRequest(parts=[ToolReturnPart(tool_name="read_file", content="a file",
                                              tool_call_id="1")])
    blanked = ModelRequest(parts=[ToolReturnPart(tool_name="read_file", content="",
                                                 tool_call_id="1")])
    assert serialise_history([kept]) != serialise_history([blanked])
