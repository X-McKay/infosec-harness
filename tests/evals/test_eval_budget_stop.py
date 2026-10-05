"""Budget bounds follow installed SDK checks, without replacing unknown final usage."""

from decimal import Decimal

import pytest
from pydantic_ai import Agent
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.usage import RequestUsage, RunUsage, UsageLimits
from sqlalchemy import select

from infosec_harness.agents.budgets import resolve_declared_budget, run_budget
from infosec_harness.agents.registry import load_spec
from infosec_harness.evals.budget_stop import _binding_limit, budget_stop_diagnostic
from infosec_harness.evals.run import run_experiment


@pytest.mark.parametrize("field,check,usage_field,bound", [
    ("request_limit", "check_before_request", "requests", "request_limit"),
    ("tool_calls_limit", "check_before_tool_call", "tool_calls", "tool_call_limit"),
    ("input_tokens_limit", "check_before_request", "input_tokens", "input_token_limit"),
    ("input_tokens_limit", "check_tokens", "input_tokens", "input_token_limit"),
    ("output_tokens_limit", "check_tokens", "output_tokens", "output_token_limit"),
    # The harness does not configure this SDK limit; retain its conservative unknown.
    ("total_tokens_limit", "check_before_request", "input_tokens", "unknown"),
    ("total_tokens_limit", "check_tokens", "input_tokens", "unknown"),
])
def test_sdk_limit_boundaries_and_current_message_forms(field, check, usage_field, bound):
    limits = UsageLimits(request_limit=None, **{field: 10}) if field != "request_limit" else UsageLimits(request_limit=10)
    check_limit = getattr(limits, check)
    # Request checks reject the *next* request at equality; other limits allow equality.
    last_allowed = 9 if field == "request_limit" else 10
    check_limit(RunUsage(**{usage_field: last_allowed}))
    with pytest.raises(UsageLimitExceeded) as caught:
        check_limit(RunUsage(**{usage_field: last_allowed + 1}))
    assert _binding_limit(caught.value) == bound


def test_per_request_input_boundary():
    limits = UsageLimits(per_request_input_tokens_limit=10)
    limits.check_per_request_input_tokens(10)
    with pytest.raises(UsageLimitExceeded) as caught:
        limits.check_per_request_input_tokens(11)
    assert _binding_limit(caught.value) == "per_request_input_token_limit"


@pytest.mark.parametrize("check", ["check_before_request", "check_cost"])
@pytest.mark.parametrize("ceiling", [Decimal("0.5"), Decimal("1E-8")])
def test_cost_boundary_and_sdk_decimal_forms(check, ceiling):
    limits = UsageLimits(cost_limit=ceiling)
    getattr(limits, check)(RunUsage(cost=ceiling))
    with pytest.raises(UsageLimitExceeded) as caught:
        getattr(limits, check)(RunUsage(cost=ceiling * 2))
    assert _binding_limit(caught.value) == "cost_limit"


@pytest.mark.parametrize("message", [
    "secret provider: The next request would exceed the request_limit of 16",
    "The next request would exceed the request_limit of 16; SECRET_BODY",
    "The next request would exceed the request_limit of sixteen",
    "Exceeded the input_tokens_limit of 10",
    "Root elapsed-time budget exhausted",
    "Root budget cannot reserve invocation for secret-agent; remaining=secret",
    "changed SDK wording: request_limit of 16",
])
def test_unknown_or_adversarial_wording_does_not_classify(message):
    assert _binding_limit(UsageLimitExceeded(message)) == "unknown"
    assert _binding_limit(ValueError("The next request would exceed the request_limit of 16")) == "unknown"


def test_partial_response_observations_are_numeric_and_do_not_infer_missing_usage():
    spec = load_spec("build-repair")
    budget = resolve_declared_budget(
        "build-repair", run_budget("build-repair", spec.metadata), source_files=500)
    messages = [
        ModelResponse(parts=[ToolCallPart("read_file", {"secret": "SENTINEL"})],
                      usage=RequestUsage(input_tokens=100, output_tokens=5)),
        ModelResponse(parts=[TextPart("SECRET_MODEL_OUTPUT")]),
        ModelResponse(parts=[ToolCallPart("final_result", {"secret": "SENTINEL"})],
                      usage=RequestUsage(input_tokens=200, output_tokens=9)),
    ]
    diagnostic = budget_stop_diagnostic(
        UsageLimitExceeded("The next request would exceed the request_limit of 999"), budget, messages,
    )
    assert diagnostic == {
        "bound": "request_limit",
        # The exception's number is never used as the configured ceiling.
        "configured_limit": budget.effective.max_requests,
        "observation_status": "partial",
        "model_responses_observed": 3,
        "tool_calls_observed": 1,
        "token_usage_observed": {"responses_with_usage": 2, "input_tokens": 300, "output_tokens": 14},
    }
    assert "SECRET" not in str(diagnostic) and "SENTINEL" not in str(diagnostic)


@pytest.mark.parametrize("usage", [RequestUsage(), RequestUsage(input_tokens=-1, output_tokens=3),
                                     RequestUsage(input_tokens=True, output_tokens=3)])
def test_unavailable_or_invalid_token_counts_stay_unknown(usage):
    spec = load_spec("build-repair")
    diagnostic = budget_stop_diagnostic(
        UsageLimitExceeded("SECRET_PROVIDER_BODY"),
        resolve_declared_budget("build-repair", run_budget("build-repair", spec.metadata)),
        [ModelResponse(parts=[TextPart("SECRET")], usage=usage)],
    )
    assert diagnostic["bound"] == "unknown"
    assert diagnostic["configured_limit"] is None
    assert diagnostic["model_responses_observed"] == 1
    assert diagnostic["token_usage_observed"] == {
        "responses_with_usage": 0, "input_tokens": None, "output_tokens": None,
    }


async def test_budget_diagnostic_is_persisted_without_fabricating_final_usage(monkeypatch):
    from infosec_harness.agents import registry
    from infosec_harness.persistence import db

    class NoOutputAgent:
        async def run(self, *args, **kwargs):
            raise UsageLimitExceeded("The next request would exceed the request_limit of 16")

    monkeypatch.setattr(registry, "build_agent", lambda *args, **kwargs: NoOutputAgent())
    exp_id = await run_experiment("build-repair")
    async with db.session() as session:
        exp = await session.get(db.EvalExperiment, exp_id)
        rows = (await session.execute(select(db.EvalCaseResult).where(
            db.EvalCaseResult.experiment_id == exp_id,
        ))).scalars().all()
    assert exp.metrics["budget_exhausted_count"] == exp.metrics["n"]
    assert exp.metrics["avg_tokens"] is None
    assert exp.metrics["usage_observations"]["attempts_observed"] == 0
    for diagnostic in [*(row.scores for row in rows), *exp.metrics["attempts"]]:
        assert diagnostic["outcome"] == "budget_exhausted"
        assert diagnostic["usage"] is None and diagnostic["usage_status"] == "unknown"
        assert diagnostic["budget_stop"]["bound"] == "request_limit"
        assert diagnostic["budget_stop"]["observation_status"] == "partial"
        assert diagnostic["budget_stop"]["model_responses_observed"] == 0
        assert diagnostic["budget_stop"]["token_usage_observed"]["input_tokens"] is None


async def test_failed_sdk_run_captures_partial_tokens_without_changing_final_usage(monkeypatch):
    from infosec_harness.agents import registry
    from infosec_harness.persistence import db

    def model(messages, info):
        return ModelResponse(parts=[ToolCallPart("again", {})],
                             usage=RequestUsage(input_tokens=100, output_tokens=5))

    agent = Agent(FunctionModel(model))

    @agent.tool_plain
    def again() -> str:
        return "continue"

    monkeypatch.setattr(registry, "build_agent", lambda *args, **kwargs: agent)
    exp_id = await run_experiment("build-repair")
    async with db.session() as session:
        exp = await session.get(db.EvalExperiment, exp_id)
        rows = (await session.execute(select(db.EvalCaseResult).where(
            db.EvalCaseResult.experiment_id == exp_id,
        ))).scalars().all()
    assert exp.metrics["avg_tokens"] is None
    assert exp.metrics["usage_observations"]["attempts_observed"] == 0
    assert exp.metrics["usage_observations"]["observed_tokens_total"] == 0
    for row in rows:
        diagnostic = row.scores
        stop = diagnostic["budget_stop"]
        requests = diagnostic["effective_budget"]["effective"]["max_requests"]
        assert stop["bound"] == "request_limit"
        assert stop["configured_limit"] == requests
        assert stop["model_responses_observed"] == requests
        assert stop["tool_calls_observed"] == requests
        assert stop["token_usage_observed"] == {
            "responses_with_usage": requests, "input_tokens": requests * 100,
            "output_tokens": requests * 5,
        }
        assert diagnostic["usage"] is None and diagnostic["usage_status"] == "unknown"
