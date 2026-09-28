"""Every agent declares a run budget, and it is enforced rather than merely documented.

The playbook (§9) puts "prevent runaway execution" first in its control order. The repair
storm in docs/LIVE_VALIDATION.md is why: one agent's context grew from 8.8k to 24k tokens
across three turns with 6-7k-token outputs, and nothing stopped it — it was noticed by
reading a trace. A budget turns that into a bounded, named failure.
"""

from __future__ import annotations

import pathlib

import pytest
from pydantic import ValidationError

from infosec_harness.agents.budgets import MissingBudget, RunBudget, run_budget, usage_limits_for
from infosec_harness.agents.registry import AGENT_BINDINGS, agent_usage_limits, load_spec


def test_every_agent_declares_a_run_budget():
    for name in AGENT_BINDINGS:
        budget = run_budget(name, load_spec(name).metadata)
        assert budget.max_requests > 0, name


def test_a_spec_without_a_budget_fails_loudly():
    """Defaulting would hide exactly the condition the budget exists to catch."""
    with pytest.raises(MissingBudget):
        run_budget("nameless", {})
    with pytest.raises(MissingBudget):
        run_budget("nameless", None)
    with pytest.raises(MissingBudget):
        run_budget("nameless", {"budgets": {}})


def test_a_zero_or_negative_ceiling_is_rejected():
    """A limit of zero is not a limit; it is a disabled agent, which is never intended."""
    base = {"max_requests": 4, "max_tool_calls": 4, "max_input_tokens_per_request": 100,
            "max_input_tokens": 400, "max_output_tokens": 100, "max_cost_usd": 0.1}
    for field in base:
        with pytest.raises(ValidationError):
            RunBudget.model_validate({**base, field: 0})


def test_budgets_reach_pydantic_ai_as_usage_limits():
    limits = usage_limits_for("probe-author", load_spec("probe-author").metadata)
    assert limits.request_limit == 16
    assert limits.tool_calls_limit == 64
    # The per-request ceiling is the context brake; the cumulative one is its worst case.
    assert limits.per_request_input_tokens_limit == 120_000
    assert limits.input_tokens_limit == 16 * 120_000
    assert float(limits.cost_limit) == pytest.approx(1.0)


def test_the_per_request_input_ceiling_is_wired_to_the_per_request_limit():
    """It must not land on `input_tokens_limit`, which pydantic-ai sums over the whole run.

    This is the defect the Java corpus surfaced as `input_tokens_limit of 120000 exceeded`:
    the numbers were calibrated against a single healthy call (see the companion test below)
    but wired to the cumulative limit, which every request in a run adds to because each one
    resends the whole conversation. A 16-request agent therefore had ~7.5k of cumulative
    input per request, while its measured per-request floor on a Java case — instructions,
    tool schemas and task input, before any tool result — is already ~3.2k.
    """
    for name in AGENT_BINDINGS:
        budget = run_budget(name, load_spec(name).metadata)
        limits = usage_limits_for(name, load_spec(name).metadata)
        assert limits.per_request_input_tokens_limit == budget.max_input_tokens_per_request, name
        assert limits.input_tokens_limit != budget.max_input_tokens_per_request, (
            f"{name}: the per-request ceiling is on the cumulative limit, which every request "
            "in the run adds to"
        )


def test_cost_ceiling_is_decimal_so_it_is_exact():
    """A float ceiling can compare just under or over its intended value."""
    from decimal import Decimal

    limits = usage_limits_for("verdict", load_spec("verdict").metadata)
    assert isinstance(limits.cost_limit, Decimal)


def test_limits_are_precomputed_for_every_agent_the_workflow_can_run():
    """TemporalOps reads these inside a workflow, where loading a spec would be I/O."""
    limits = agent_usage_limits()
    assert set(limits) == set(AGENT_BINDINGS)
    assert all(limits[name].request_limit for name in AGENT_BINDINGS)


def test_a_budget_leaves_room_for_the_measured_worst_case():
    """A ceiling below observed normal operation would fail healthy runs.

    The maxima are from the live-model corpus runs recorded in docs/LIVE_VALIDATION.md, and
    they are *single-call* observations — so the field they belong against is the per-request
    ceiling. Comparing them with the cumulative ceiling is what made a 16-request agent look
    like it had 12x headroom when it had less than half a request's worth per call.
    """
    observed_max_input = {"context": 3438, "env-planner": 6019, "probe-author": 9695,
                          "probe-diagnosis": 3718, "probe-planner": 6886, "recon": 2300,
                          "verdict": 6830}
    for name, observed in observed_max_input.items():
        budget = run_budget(name, load_spec(name).metadata)
        assert budget.max_input_tokens_per_request > observed * 2, (
            f"{name}: per-request budget {budget.max_input_tokens_per_request} leaves little "
            f"headroom over the {observed} tokens measured in a single healthy call"
        )


def test_the_cumulative_input_ceiling_is_not_below_the_runs_arithmetic_worst_case():
    """`input_tokens_limit` is summed over the run, so it must be derived from max_requests.

    Same shape as the output-ceiling invariant below, and the same root cause: a ceiling set
    from what one call was observed to use, while the run is allowed `max_requests` of them.
    Live on the Java corpus this fired as `input_tokens_limit of 120000` on a repository whose
    entire source is 1.3 kB — not a runaway, just a run that used the turns it was given.
    Deriving the ceiling keeps `max_requests` the operative brake and leaves the per-request
    ceiling as the one that catches an oversized context.
    """
    for name in AGENT_BINDINGS:
        budget = run_budget(name, load_spec(name).metadata)
        assert budget.max_input_tokens >= budget.worst_case_input_tokens, (
            f"{name}: max_input_tokens {budget.max_input_tokens} is below the worst case "
            f"{budget.max_requests} requests x {budget.max_input_tokens_per_request} tokens = "
            f"{budget.worst_case_input_tokens}, so the ceiling can fire on a healthy run"
        )


def test_raising_the_request_budget_is_caught_by_the_cumulative_input_invariant():
    """The two are coupled; the invariant above must be load-bearing, not incidentally true."""
    budget = run_budget("probe-author", load_spec("probe-author").metadata)
    doubled = budget.model_copy(update={"max_requests": budget.max_requests * 2})
    assert doubled.max_input_tokens < doubled.worst_case_input_tokens, (
        "this test exists to show the derivation is enforced: raising max_requests without "
        "raising max_input_tokens would put the ceiling back under its own worst case"
    )


def test_the_output_ceiling_is_not_below_the_runs_arithmetic_worst_case():
    """An output ceiling under max_requests x per-call cap fires on verbose runs, not runaway ones.

    Every agent had this wrong at once, because the ceilings were set from *observed* output
    while the per-call cap comes from the backend's min_max_tokens floor — added so a reasoning
    model's thinking could not exhaust max_tokens before it answered. The result was an
    intermittent UsageLimitExceeded that failed healthy prepares whenever the model happened to
    be wordy. max_requests is the operative brake; this keeps the token ceiling consistent with
    it rather than a lottery.
    """
    import yaml

    from infosec_harness.agents.models import load_models_config
    from infosec_harness.agents.registry import spec_path

    floor = max(b.min_max_tokens for b in load_models_config().backends.values())
    for name in AGENT_BINDINGS:
        spec = yaml.safe_load(spec_path(name).read_text())
        per_call = max((spec.get("model_settings") or {}).get("max_tokens", 0), floor)
        budget = spec["metadata"]["budgets"]
        worst = per_call * budget["max_requests"]
        assert budget["max_output_tokens"] >= worst, (
            f"{name}: max_output_tokens {budget['max_output_tokens']} is below the worst case "
            f"{budget['max_requests']} requests x {per_call} tokens = {worst}, so the ceiling "
            f"can fire on a healthy run"
        )


def test_raising_a_backends_token_floor_is_caught_by_the_invariant():
    """The floor and the ceilings are coupled; a change to one must not silently break the other."""
    import yaml

    from infosec_harness.agents.registry import spec_path

    spec = yaml.safe_load(spec_path("verdict").read_text())
    budget = spec["metadata"]["budgets"]
    inflated_floor = 64_000
    worst = inflated_floor * budget["max_requests"]
    assert budget["max_output_tokens"] < worst, (
        "this test exists to show the invariant is load-bearing: raising a backend's "
        "min_max_tokens without regenerating the budgets would make the ceilings too low again"
    )


TOOL_CAPABILITIES = {"Skills", "RepoReadOnly", "SandboxShell"}
TOOL_CALLS_PER_REQUEST = 4


def _capability_names(spec: dict) -> set[str]:
    names: set[str] = set()
    for capability in spec.get("capabilities") or []:
        names |= set(capability) if isinstance(capability, dict) else {capability}
    return names


def test_tool_call_ceilings_scale_with_the_request_budget():
    """A tool-call ceiling calibrated against yesterday's toolset breaks when a tool is added.

    Adding a fourth read tool (`describe_callables`) made agents call more tools per turn, and the
    ceilings set when there were three became tight. The breach surfaced as an intermittent
    UsageLimitExceeded in whichever stage happened to explore hardest — pointing nowhere near the
    cause. Tying the ceiling to max_requests keeps the request limit the operative brake and makes
    the next capability addition safe by construction.
    """
    import yaml

    from infosec_harness.agents.registry import spec_path

    for name in AGENT_BINDINGS:
        spec = yaml.safe_load(spec_path(name).read_text())
        budget = spec["metadata"]["budgets"]
        if not (_capability_names(spec) & TOOL_CAPABILITIES):
            continue  # no tools to call; see the companion test
        want = budget["max_requests"] * TOOL_CALLS_PER_REQUEST
        assert budget["max_tool_calls"] >= want, (
            f"{name}: max_tool_calls {budget['max_tool_calls']} is below "
            f"{budget['max_requests']} requests x {TOOL_CALLS_PER_REQUEST} tools = {want}"
        )


def test_an_agent_with_no_tools_keeps_a_tight_ceiling():
    """verdict exposes no toolset, so a tool call from it is an anomaly worth braking on."""
    import yaml

    from infosec_harness.agents.registry import spec_path

    for name in AGENT_BINDINGS:
        spec = yaml.safe_load(spec_path(name).read_text())
        if _capability_names(spec) & TOOL_CAPABILITIES:
            continue
        budget = spec["metadata"]["budgets"]
        assert budget["max_tool_calls"] <= 8, (
            f"{name} exposes no tools; a large tool-call ceiling brakes nothing"
        )


# Toolsets that return content into the history, where it is resent on every later request.
READ_TOOL_CAPABILITIES = {"RepoReadOnly", "SandboxShell"}


def test_an_agent_that_accumulates_tool_results_bounds_its_history():
    """A ceiling on input is not a bound on the history that produces it.

    probe-author and probe-repair breached the cumulative input ceiling on the Java corpus
    while build-repair and partial-build — same 16-request budget, strictly larger tool
    surface, bigger tool results — did not, and the one thing that differed was compaction.
    Without it, per-request input grows with turn count (measured on
    eval-corpus/java/sqli/vulnerable: 12.8 kB at turn 1, 116 kB at turn 19, on a repository
    whose entire source is 1.3 kB), so *any* per-request ceiling is eventually reached by a
    run that merely keeps working. Raising the ceiling moves that point; bounding the history
    removes it. The rule has no threshold on purpose — a cutoff would only say which agent is
    allowed to grow unboundedly next.
    """
    import yaml

    from infosec_harness.agents.registry import DEFAULT_CLEAR_TOOL_TOKENS, spec_path

    for name in AGENT_BINDINGS:
        spec = yaml.safe_load(spec_path(name).read_text())
        meta = spec["metadata"]
        if not (_capability_names(spec) & READ_TOOL_CAPABILITIES):
            continue  # no tool results to accumulate
        assert meta.get("clear_tool_results"), (
            f"{name} may make {meta['budgets']['max_requests']} requests with read tools and "
            "nothing bounds the history it resends on each one"
        )
        trigger = meta.get("clear_tool_tokens", DEFAULT_CLEAR_TOOL_TOKENS)
        assert trigger < meta["budgets"]["max_input_tokens_per_request"], (
            f"{name}: compaction triggers at {trigger} tokens, at or above the per-request "
            f"ceiling {meta['budgets']['max_input_tokens_per_request']} — the ceiling fires "
            "first and the compaction never runs"
        )


# --- size-scaled budgets ---------------------------------------------------------------------
#
# Every ceiling was fitted against the seeded corpus, whose Java fixture is three files. The
# first live run over the harvested Vul4J repositories (~500 files) failed five of six cases
# with UsageLimitExceeded during preparation and produced not one build failure: `recon` spent
# all twelve requests having made exactly one repeated call. A constant fitted to a toy
# repository is not a brake on a real one, it is a wall.


def _recon_budget():
    import yaml

    from infosec_harness.agents.budgets import RunBudget

    md = yaml.safe_load(pathlib.Path("agents/recon/agent.yaml").read_text())
    return RunBudget.model_validate(md["metadata"]["budgets"])


def test_a_fixture_sized_or_unknown_repo_keeps_its_declared_budget_exactly():
    """The seeded corpus must behave exactly as before, and an unmeasured repo gets the
    declared ceiling rather than a guessed one."""
    from infosec_harness.agents.budgets import size_factor

    budget = _recon_budget()
    for files in (None, 0, 1, 3, 16):
        assert size_factor(files) == 1.0, files
        assert budget.scaled_for(files) is budget, f"{files} should be the same object"


def test_a_real_repository_gets_past_the_ceiling_that_stopped_it():
    """The measurement that motivated this: 12 requests was not enough for ~500 files."""
    from infosec_harness.agents.budgets import size_factor

    scaled = _recon_budget().scaled_for(500)
    assert scaled.max_requests > 12, "still capped at the number the live run exhausted"
    assert 2.0 < size_factor(500) < 2.5, size_factor(500)


def test_growth_is_logarithmic_rather_than_linear():
    """Exploration cost grows with the breadth and depth of the tree, not the file count:
    doubling a repository does not double the directories you have to list."""
    from infosec_harness.agents.budgets import size_factor

    f64, f500, f4000 = size_factor(64), size_factor(500), size_factor(4000)
    assert f64 < f500 < f4000
    # Eight times the files must cost far less than eight times the budget.
    assert f500 / f64 < 2.0, (f64, f500)


def test_the_brake_stays_a_brake_however_large_the_repository():
    from infosec_harness.agents.budgets import MAX_SIZE_FACTOR, size_factor

    assert size_factor(10**7) == MAX_SIZE_FACTOR
    capped = _recon_budget().scaled_for(10**7)
    assert capped.max_requests == round(_recon_budget().max_requests * MAX_SIZE_FACTOR)


def test_every_ceiling_scales_together_so_the_invariants_survive():
    """The output ceiling is `max_requests x` the per-call cap and the cumulative input ceiling
    is `max_requests x` the per-request one. Scaling `max_requests` alone would break both, so
    a uniform factor is what keeps them true without a second set of numbers to drift.
    """
    base = _recon_budget()
    scaled = base.scaled_for(500)
    ratio = scaled.max_requests / base.max_requests
    for field in ("max_tool_calls", "max_input_tokens", "max_output_tokens"):
        got = getattr(scaled, field) / getattr(base, field)
        assert abs(got - ratio) < 0.02, f"{field} scaled by {got:.3f}, requests by {ratio:.3f}"
    # The per-request context brake is NOT size-dependent: one request's context does not grow
    # because the repository has more files in it.
    assert scaled.max_input_tokens_per_request == base.max_input_tokens_per_request


def test_the_derived_input_ceiling_still_matches_its_own_derivation_after_scaling():
    scaled = _recon_budget().scaled_for(500)
    assert scaled.max_input_tokens >= scaled.worst_case_input_tokens * 0.98


def test_the_repo_size_reaches_the_limits_a_run_is_given():
    """Threaded end to end: without this the scaling exists and never applies."""
    import yaml

    from infosec_harness.agents.budgets import usage_limits_for

    md = yaml.safe_load(pathlib.Path("agents/recon/agent.yaml").read_text())["metadata"]
    small = usage_limits_for("recon", md, source_files=3)
    large = usage_limits_for("recon", md, source_files=500)
    assert large.request_limit > small.request_limit
    assert usage_limits_for("recon", md).request_limit == small.request_limit
