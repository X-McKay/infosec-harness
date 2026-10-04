"""Retained replay specs remain bounded and cannot acquire current serial settings."""
import pytest

from infosec_harness.agents.budgets import run_budget, usage_limits_for
from infosec_harness.agents.durable import (
    RETAINED_BUILD_CONFIGS,
    RETAINED_BUILD_SPECS,
)


@pytest.mark.parametrize("name,version", [("build-repair", "1.0.5"), ("partial-build", "1.1.3")])
def test_retained_spec_has_the_recorded_identity_and_an_enforceable_budget(name, version):
    spec = RETAINED_BUILD_SPECS[name]
    assert spec.metadata["version"] == version
    assert "parallel_tool_calls" not in spec.model_settings
    budget = run_budget(name, spec.metadata)
    assert all(value > 0 for value in budget.model_dump().values())
    assert budget.max_input_tokens >= budget.max_requests * budget.max_input_tokens_per_request
    assert budget.max_output_tokens >= budget.max_requests * 16000
    assert RETAINED_BUILD_CONFIGS[name].budget.requested == budget


@pytest.mark.parametrize("name", ["build-repair", "partial-build"])
def test_retained_budget_per_request_brake_reaches_sdk_limits(name):
    spec = RETAINED_BUILD_SPECS[name]
    budget = run_budget(name, spec.metadata)
    limits = usage_limits_for(name, spec.metadata)
    assert limits.per_request_input_tokens_limit == budget.max_input_tokens_per_request
    assert limits.input_tokens_limit == budget.max_input_tokens
    assert limits.request_limit == budget.max_requests
    assert limits.tool_calls_limit == budget.max_tool_calls
