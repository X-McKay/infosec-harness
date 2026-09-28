"""Every agent declares a run budget, and it is enforced rather than merely documented.

The playbook (§9) puts "prevent runaway execution" first in its control order. The repair
storm in docs/LIVE_VALIDATION.md is why: one agent's context grew from 8.8k to 24k tokens
across three turns with 6-7k-token outputs, and nothing stopped it — it was noticed by
reading a trace. A budget turns that into a bounded, named failure.
"""

from __future__ import annotations

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
    base = {"max_requests": 4, "max_tool_calls": 4, "max_input_tokens": 100,
            "max_output_tokens": 100, "max_cost_usd": 0.1}
    for field in base:
        with pytest.raises(ValidationError):
            RunBudget.model_validate({**base, field: 0})


def test_budgets_reach_pydantic_ai_as_usage_limits():
    limits = usage_limits_for("probe-author", load_spec("probe-author").metadata)
    assert limits.request_limit == 16
    assert limits.tool_calls_limit == 36
    assert limits.input_tokens_limit == 120_000
    assert float(limits.cost_limit) == pytest.approx(1.0)


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

    The maxima are from the live-model corpus runs recorded in docs/LIVE_VALIDATION.md.
    """
    observed_max_input = {"context": 3438, "env-planner": 6019, "probe-author": 9695,
                          "probe-diagnosis": 3718, "probe-planner": 6886, "recon": 2300,
                          "verdict": 6830}
    for name, observed in observed_max_input.items():
        budget = run_budget(name, load_spec(name).metadata)
        assert budget.max_input_tokens > observed * 2, (
            f"{name}: budget {budget.max_input_tokens} leaves little headroom over the "
            f"{observed} tokens measured in a single healthy call"
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
