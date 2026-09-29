"""What one agent run costs in *round trips*, and why the tool surface is what moves it.

Two live runs over ~500-file repositories failed every case with `UsageLimitExceeded` during
preparation. Scaling every budget ~2.2x by repository size did not fix it — the scaled limits
were exhausted too, wall clock went from 50 to 75 minutes, and accuracy did not move. So the
ceiling was not the variable. These tests pin the variable that is, measured offline with a
scripted model over a synthetic repository whose size is the only knob.

The headline measurement, `recon` over a 500-file Maven tree:

    previous toolset                     55 model requests, 101 of 127 directories ever named
    + read_files                         48                  101 of 127
    + list_tree                          11                  127 of 127
    + repo_digest                         9                  127 of 127
    + all three                           3                  127 of 127

Every assertion below is a *shape* rather than one of those numbers, except where a number is
the point (the budget a run has to fit in). A number would have to be re-chosen the next time
`MAX_LIST` or the synthetic fixture changes; the shape must hold whatever those are.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from infosec_harness.agents.budgets import run_budget
from infosec_harness.agents.registry import load_spec
from infosec_harness.evals.exploration import measure_recon, synth_repo

SHIPPED = ("list_files", "read_file", "search_code", "describe_callables")
ALL_TOOLS = (*SHIPPED, "read_files", "list_tree", "repo_digest")
_SKILLS = {"Skills": {"directories": "skills",
                      "include": ["lang-python", "lang-java", "lang-javascript", "lang-perl"]}}


def _overlay(tools: tuple[str, ...]) -> dict:
    return {"capabilities": [_SKILLS, {"RepoReadOnly": {"tools": list(tools)}},
                             {"WarnOnCacheBusts": {}}]}


@pytest.fixture(scope="module")
def repos():
    with tempfile.TemporaryDirectory() as tmp:
        yield {n: synth_repo(Path(tmp) / f"repo{n}", n) for n in (16, 500)}


async def _measure(repos, tools, size):
    return await measure_recon(repos[size], label="t", source_files=size,
                               overlay=_overlay(tools))


# --- the baseline: one tool call per model request -----------------------------------------


async def test_a_run_makes_one_model_request_per_tool_call(repos):
    """The premise of the whole experiment, asserted rather than assumed.

    If a run could carry several tool calls in one request, the fix for a run that needs fifty
    reads would be to ask for them together and the tool surface would not matter. It cannot:
    every tool call is its own round trip, so `requests` is `tool_calls` plus the final answer.
    That is what makes "fewer, larger calls" the lever and "a bigger budget" not one.
    """
    m = await _measure(repos, SHIPPED, 500)
    assert m.requests == m.tool_calls + 1, (m.requests, m.tool_calls)


async def test_the_shipped_toolset_cannot_profile_a_real_repository_inside_its_budget(repos):
    """The measured failure, reproduced offline and for free.

    `recon`'s budget scaled for 500 source files is ~27 requests. Ordinary exploration — no
    repeated call, nothing a looping report would flag — needs twice that, because
    `list_files` truncates at `MAX_LIST` entries and covering the tree then costs one call per
    directory the truncated window named. This is the "is it a loop or is it large work"
    question answered: large work, and work the toolset makes larger than it needs to be.
    """
    m = await _measure(repos, SHIPPED, 500)
    budget = run_budget("recon", load_spec("recon").metadata).scaled_for(500)
    assert m.requests > budget.max_requests, (
        f"{m.requests} requests now fits the {budget.max_requests}-request budget, so this "
        "test no longer demonstrates the failure it was written for"
    )
    assert not m.unmet, f"the run must be a complete one to be comparable: {m.unmet}"


async def test_the_cost_of_the_shipped_toolset_grows_with_the_repository(repos):
    """A fixture-sized repository is free and a real one is not, on the same procedure."""
    small = await _measure(repos, SHIPPED, 16)
    large = await _measure(repos, SHIPPED, 500)
    assert large.requests > small.requests * 3, (small.requests, large.requests)


# --- each candidate, attributed ------------------------------------------------------------


async def test_batching_the_reads_removes_one_round_trip_per_file(repos):
    """`read_files` is worth exactly the reads it merges, which on a small repo is most of them."""
    before = await _measure(repos, SHIPPED, 16)
    after = await _measure(repos, (*SHIPPED, "read_files"), 16)
    assert after.requests < before.requests
    # Same information, so the same bytes reach the model; only the number of trips changed.
    assert after.result_bytes == pytest.approx(before.result_bytes, rel=0.05)


async def test_a_directory_level_tree_is_what_collapses_a_large_repository(repos):
    """The single biggest effect, and the one that also fixes what the run *knows*."""
    before = await _measure(repos, SHIPPED, 500)
    after = await _measure(repos, (*SHIPPED, "list_tree"), 500)
    assert after.requests < before.requests / 4, (before.requests, after.requests)
    budget = run_budget("recon", load_spec("recon").metadata).scaled_for(500)
    assert after.requests <= budget.max_requests
    assert not after.unmet


async def test_a_truncated_flat_listing_hides_directories_and_a_tree_does_not(repos):
    """The accuracy half. A capped per-file listing does not say what it left out.

    So a run can finish having never been told that part of the repository exists — and a
    profile of part of a repository is wrong, not merely expensive. This is the cost that
    raising a request budget cannot buy back at all.
    """
    before = await _measure(repos, SHIPPED, 500)
    after = await _measure(repos, (*SHIPPED, "list_tree"), 500)
    assert before.dir_coverage < 1.0, (
        "the flat listing must leave directories unnamed for this comparison to mean anything"
    )
    assert after.dir_coverage == 1.0, after.dirs_seen


async def test_the_digest_answers_the_tree_the_manifests_and_the_tests_together(repos):
    """One call for the three things every profiling run needs before it can answer."""
    tree_only = await _measure(repos, (*SHIPPED, "list_tree"), 500)
    digest = await _measure(repos, (*SHIPPED, "repo_digest"), 500)
    assert digest.requests < tree_only.requests
    assert not digest.unmet


async def test_all_three_together_make_the_cost_independent_of_repository_size(repos):
    """The property the size-scaled budget was trying to buy, obtained directly instead.

    `budgets.size_factor` widens every ceiling logarithmically in the file count because
    exploration was assumed to cost more on a larger repository. With a tool that answers the
    whole tree in one call it does not, which is a better answer than a wider ceiling: the
    ceiling stays a brake.
    """
    small = await _measure(repos, ALL_TOOLS, 16)
    large = await _measure(repos, ALL_TOOLS, 500)
    assert large.requests <= small.requests + 1, (small.requests, large.requests)
    assert large.requests < 6, large.requests
    assert not large.unmet


async def test_the_cheaper_run_stays_far_below_the_compaction_trigger(repos):
    """Round trips and history size are the same problem seen twice.

    Compaction is what bounds per-request input, and `scripts/measure_cache_prefix.py` shows
    compaction is also what rewrites the history and so breaks the provider's cached prefix. A
    run that needs a handful of calls never reaches the trigger, so it never pays either cost.
    """
    from infosec_harness.agents.registry import DEFAULT_CLEAR_TOOL_TOKENS

    before = await _measure(repos, SHIPPED, 500)
    after = await _measure(repos, ALL_TOOLS, 500)
    assert after.peak_history_tokens < before.peak_history_tokens / 3
    assert after.peak_history_tokens < DEFAULT_CLEAR_TOOL_TOKENS / 3


# --- the measurement itself has to be able to fail -----------------------------------------


async def test_the_explorer_reports_an_incomplete_run_as_incomplete(repos):
    """Otherwise a variant could look cheap by simply answering less.

    Every comparison above asserts `unmet` is empty on the cheap side, which is only worth
    anything if `unmet` can be non-empty. It can: a run given no way to read a file cannot
    satisfy the manifest or source part of the need.
    """
    m = await _measure(repos, ("list_files",), 16)
    assert m.unmet, "a run with no read tool at all must not be reported as complete"
