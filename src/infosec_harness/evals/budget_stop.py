"""Sanitized SDK budget-stop diagnostics, separate from completed-run accounting."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Literal, TypedDict, cast

from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.messages import ModelMessage, ModelResponse

from infosec_harness.evals.trajectory import summarize_calls
from infosec_harness.runtime.budgets import BudgetResolution

BudgetBound = Literal[
    "request_limit", "tool_call_limit", "input_token_limit", "output_token_limit",
    "per_request_input_token_limit", "cost_limit", "unknown",
]

# Exact forms in the installed PydanticAI usage.py/exceptions.py. Full matching prevents
# arbitrary tool/provider text containing limit names from becoming a recognized bound.
_HINT = (
    ". Consider raising the limit, or see the docs on usage limits "
    "for budget-aware patterns: https://pydantic.dev/docs/ai/core-concepts/agent/#usage-limits"
)
_INT = r"[0-9]+"
_DECIMAL = r"[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"
_PATTERNS: tuple[tuple[BudgetBound, str], ...] = (
    ("request_limit", rf"The next request would exceed the request_limit of {_INT}"),
    ("tool_call_limit", rf"The next tool call\(s\) would exceed the tool_calls_limit of {_INT} \(tool_calls={_INT}\)"),
    ("input_token_limit", rf"(?:The next request would exceed|Exceeded) the input_tokens_limit of {_INT} \(input_tokens={_INT}\)"),
    ("output_token_limit", rf"Exceeded the output_tokens_limit of {_INT} \(output_tokens={_INT}\)"),
    ("per_request_input_token_limit", rf"Exceeded the per_request_input_tokens_limit of {_INT} \(request_input_tokens={_INT}\)"),
    ("cost_limit", rf"The next request would exceed the `cost_limit` of {_DECIMAL} \(`cost`=Decimal\('{_DECIMAL}'\)\)"),
    ("cost_limit", rf"Exceeded the `cost_limit` of {_DECIMAL} \(`usage.cost`=Decimal\('{_DECIMAL}'\)\)"),
)
_LIMIT_FIELDS = {
    "request_limit": "max_requests",
    "tool_call_limit": "max_tool_calls",
    "input_token_limit": "max_input_tokens",
    "output_token_limit": "max_output_tokens",
    "per_request_input_token_limit": "max_input_tokens_per_request",
    "cost_limit": "max_cost_usd",
}


class TokenObservation(TypedDict):
    responses_with_usage: int
    input_tokens: int | None
    output_tokens: int | None


class BudgetStop(TypedDict):
    bound: BudgetBound
    configured_limit: int | float | None
    observation_status: Literal["partial"]
    model_responses_observed: int
    tool_calls_observed: int
    token_usage_observed: TokenObservation


def _binding_limit(exc: BaseException) -> BudgetBound:
    if not isinstance(exc, UsageLimitExceeded):
        return "unknown"
    # Do not serialize or log this string. Future SDK wording remains unknown.
    message = exc.message
    for bound, pattern in _PATTERNS:
        if re.fullmatch(pattern + re.escape(_HINT), message):
            return bound
    return "unknown"


def budget_stop_diagnostic(
    exc: BaseException, budget: BudgetResolution, messages: Sequence[ModelMessage]
) -> BudgetStop:
    """Count captured responses without presenting them as final SDK run usage.

    Default zero RequestUsage cannot distinguish missing reporting from a real zero, so
    only nonzero, nonnegative integer token snapshots count as token observations. No cost
    or completed request count is inferred. Tools use the existing observation contract,
    which excludes final-output/internal calls and does not imply successful execution.
    """
    bound = _binding_limit(exc)
    field = _LIMIT_FIELDS.get(bound)
    responses = [message for message in messages if isinstance(message, ModelResponse)]
    observations = []
    for response in responses:
        usage = response.usage
        pair = (usage.input_tokens, usage.output_tokens)
        if all(type(value) is int and value >= 0 for value in pair) and any(pair):
            observations.append(pair)
    return {
        "bound": bound,
        "configured_limit": getattr(budget.effective, field) if field else None,
        "observation_status": "partial",
        "model_responses_observed": len(responses),
        "tool_calls_observed": cast(int, summarize_calls(messages)["tool_call_count"]),
        "token_usage_observed": {
            "responses_with_usage": len(observations),
            "input_tokens": sum(pair[0] for pair in observations) if observations else None,
            "output_tokens": sum(pair[1] for pair in observations) if observations else None,
        },
    }
