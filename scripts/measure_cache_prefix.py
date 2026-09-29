"""Check the structural precondition for prompt caching, offline.

    uv run python scripts/measure_cache_prefix.py

The README claims a stable->volatile prompt layout, the specs set Bedrock/OpenAI cache keys,
and runs record `cache_hit_ratio`. The runtime monitor (`WarnOnCacheBusts`) reads the
provider's own verdict, so it is silent without a provider. What can be checked here is the
structural precondition that verdict depends on:

1. *Across* the findings of one repository, the text before the `CachePoint` must be
   byte-identical, or the shared prefix the warm-then-fan-out schedule exists to exploit does
   not exist.
2. *Within* one run, each request's message list must extend the previous one. A request that
   rewrites part of the history it already sent cannot be served from cache from that point on
   and pays full prefill on every request after it.

Both are properties of this repository's own code, so both are checkable without a model.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

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
from infosec_harness.evals.exploration import (
    MEASUREMENT_LIMITS,
    prefix_report,
    recording_model,
    serialise_history,
    synth_repo,
)

_STACK = StackFingerprint(languages={"java": 500}, manifests=["pom.xml"],
                          test_frameworks=["junit5"])
_PROFILE = RepoProfile(summary="s", primary_language="java", test_framework="junit5",
                       test_layout="src/test/java")


def across_findings() -> tuple[bool, list[str]]:
    """Do two findings of one repository share the text before the cache point?"""
    prefixes: list[str] = []
    for i in range(3):
        finding = Finding(fingerprint=f"{i:016d}", title=f"SQLi {i}", repo_url="r",
                          revision="HEAD", cwe="CWE-89",
                          source_kind=FindingSourceKind.generic_json)
        content = render_prompt("Gather context.", {"finding": finding},
                               stack=_STACK, profile=_PROFILE)
        # Everything up to the first CachePoint is what a provider can serve from cache.
        cut = next((n for n, c in enumerate(content) if not isinstance(c, str)), len(content))
        prefixes.append("\n".join(str(c) for c in content[:cut]))
    return len(set(prefixes)) == 1, prefixes


_VALID_PROBE = {
    "test_file_path": "src/test/java/HarnessProbeTest.java",
    "content": ("public class HarnessProbeTest {\n"
                "  // HARNESS_PRECONDITION::n HARNESS_SINK_RETURNED::n HARNESS_ORACLE::n\n}\n"),
    "explanation": "drives the sink",
}


async def within_one_run(*, compact: bool, reads: int = 14):
    """Serialised histories of every request of one `probe-author` run.

    The files are deliberately large (400 lines, `MAX_READ_LINES`), because the question is
    what happens to the prefix once the history is big enough for compaction to act. Tiny
    files would leave compaction inert and the two arms would be trivially identical.
    """
    with tempfile.TemporaryDirectory() as tmp:
        repo = synth_repo(Path(tmp) / "repo", 24)
        for n in range(reads):
            body = "\n".join(f"    void helper_{n}_{i}(String s) {{ /* {'x' * 60} */ }}"
                             for i in range(400))
            Path(repo, f"src/main/java/com/example/Big{n:03d}.java").write_text(
                f"package com.example;\npublic class Big{n:03d} {{\n{body}\n}}\n")
        paths = [f"src/main/java/com/example/Big{n:03d}.java" for n in range(reads)]
        overlay = ({"metadata": {"clear_tool_results": True,
                                 "clear_tool_tokens": DEFAULT_CLEAR_TOOL_TOKENS}} if compact
                   else {"metadata": {"clear_tool_results": False}})
        agent = build_agent("probe-author", overlay, durable=False)
        step = iter(paths)
        sink: list[list[str]] = []

        def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
            try:
                path = next(step)
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
        return prefix_report(sink)


async def recon_prefix(tools: tuple[str, ...], source_files: int = 500):
    """Prefix behaviour of one real `recon` run over a `source_files`-file repository.

    This is where the two halves meet. Compaction is what bounds per-request input, and
    section 2 shows it is also what rewrites the history — so the cache survives only in a run
    whose history never reaches the compaction trigger. Fewer, larger round trips is how to get
    a run like that, and this reports how much headroom each toolset leaves.

    Returns (prefix report, peak estimated history tokens).
    """
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    from measure_exploration import overlay_for

    from infosec_harness.evals.exploration import _RECON_OUTPUT, DEFAULT_NEED, Explorer

    with tempfile.TemporaryDirectory() as tmp:
        repo = synth_repo(Path(tmp) / "repo", source_files)
        explorer = Explorer(need=DEFAULT_NEED, output_args=_RECON_OUTPUT)
        agent = build_agent("recon", overlay_for(tools), durable=False)
        sink: list[list[str]] = []
        prompt = render_prompt("Profile this repository.", {}, stack=_STACK)
        with agent.override(model=recording_model(explorer, sink)):
            await agent.run(prompt, deps=AgentDeps(repo_path=str(repo),
                                                   source_files=source_files),
                            usage_limits=MEASUREMENT_LIMITS)
        return prefix_report(sink), max(t.history_tokens for t in explorer.trips)


SHIPPED = ("list_files", "read_file", "search_code", "describe_callables")
ALL_TOOLS = (*SHIPPED, "read_files", "list_tree", "repo_digest")


def main() -> None:
    ok, prefixes = across_findings()
    print("\n1. Across the findings of one repository")
    print(f"   identical pre-CachePoint prefix: {'YES' if ok else 'NO'} "
          f"({len(set(prefixes))} distinct over {len(prefixes)} findings, "
          f"{len(prefixes[0])} chars)")

    print("\n2. Within one run (probe-author, 14 reads of distinct files)")
    for compact in (False, True):
        report = asyncio.run(within_one_run(compact=compact))
        label = "compaction ON " if compact else "compaction OFF"
        print(f"   {label}: {len(report.part_counts)} requests, "
              f"parts {report.part_counts[0]}->{report.part_counts[-1]}, "
              f"prefix rewritten at requests {report.rewrites or 'none'} "
              f"-> {'STABLE' if report.stable else 'BUSTS THE CACHE'}")

    print("\n3. One recon run over a 500-file repository (compaction ON, as shipped)")
    print("   How much headroom each toolset leaves to the trigger that causes (2).")
    for label, tools in (("previous toolset", SHIPPED), ("with the three new tools", ALL_TOOLS)):
        report, peak = asyncio.run(recon_prefix(tools))
        print(f"   {label:<25}: {len(report.part_counts):>2} requests, peak history "
              f"{peak:>6} tokens ({peak / DEFAULT_CLEAR_TOOL_TOKENS:.0%} of the "
              f"{DEFAULT_CLEAR_TOOL_TOKENS} trigger), rewritten at {report.rewrites or 'none'} "
              f"-> {'STABLE' if report.stable else 'BUSTS THE CACHE'}")
    print()


if __name__ == "__main__":
    main()


__all__ = ["across_findings", "within_one_run", "serialise_history"]
