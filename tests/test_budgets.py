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
        assert budget.max_model_requests > 0, name


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
    base = {"max_model_requests": 4, "max_tool_calls": 4, "max_input_tokens": 100,
            "max_output_tokens": 100, "max_cost_usd": 0.1}
    for field in base:
        with pytest.raises(ValidationError):
            RunBudget.model_validate({**base, field: 0})


def test_budgets_reach_pydantic_ai_as_usage_limits():
    limits = usage_limits_for("probe_author", load_spec("probe_author").metadata)
    assert limits.request_limit == 16
    assert limits.tool_calls_limit == 36
    assert limits.input_tokens_limit == 60_000
    assert float(limits.cost_limit) == pytest.approx(0.8)


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
    observed_max_input = {"context": 3438, "env_planner": 6019, "probe_author": 9695,
                          "probe_diagnosis": 3718, "probe_planner": 6886, "recon": 2300,
                          "verdict": 6830}
    for name, observed in observed_max_input.items():
        budget = run_budget(name, load_spec(name).metadata)
        assert budget.max_input_tokens > observed * 2, (
            f"{name}: budget {budget.max_input_tokens} leaves little headroom over the "
            f"{observed} tokens measured in a single healthy call"
        )
