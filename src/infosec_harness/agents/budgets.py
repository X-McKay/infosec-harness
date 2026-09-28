"""Per-run budgets, declared in each spec's metadata and enforced with UsageLimits.

The agent playbook (§9) requires every production agent to carry per-request and per-run
limits, in the order "prevent runaway execution" first. That ordering is the point: the
repair storm measured in docs/LIVE_VALIDATION.md grew one agent's context from 8.8k to 24k
tokens over three turns before anyone noticed by eye. A budget turns that into a bounded,
named failure.

Budgets are read from ``metadata.budgets`` so they live with the rest of the agent's
declarative contract and move with an overlay during experiments.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from pydantic import BaseModel, Field
from pydantic_ai.usage import UsageLimits


class RunBudget(BaseModel):
    """What one agent run may spend. Every field is a ceiling, never a target.

    Field names are the playbook's (`max_requests`, not `max_model_requests`) so the spec's
    budget block is the same document `agentctl validate` reads.

    Input tokens need *two* ceilings because pydantic-ai's `input_tokens_limit` is
    **cumulative over the whole run**, and every request in a run resends the entire
    conversation. Cumulative input therefore grows quadratically in the number of turns, and
    a ceiling calibrated against one healthy call fires on a healthy *long* call. That is
    what happened on the Java corpus: `probe-author`'s 120k ceiling was ~12x a single
    measured call but only ~7.5k per request across its own 16-request budget, and the
    measured per-request floor on a Java case is ~3.2k tokens before a single tool result.
    So:

    * `max_input_tokens_per_request` is the brake — it catches an oversized context, which
      is the failure the 8.8k -> 24k repair storm in docs/LIVE_VALIDATION.md actually was;
    * `max_input_tokens` is the run's arithmetic worst case derived from it
      (`max_requests x max_input_tokens_per_request`), exactly as `max_output_tokens` is
      derived from `max_requests x` the per-call output cap. It is a backstop, not the
      operative limit; `max_requests` is.

    Both relationships are asserted in tests/test_budgets.py so neither can drift.
    """

    max_requests: int = Field(gt=0)
    max_tool_calls: int = Field(gt=0)
    # Per request: the context-size brake. See the class docstring.
    max_input_tokens_per_request: int = Field(gt=0)
    # Cumulative over the run: derived from the two fields above.
    max_input_tokens: int = Field(gt=0)
    max_output_tokens: int = Field(gt=0)
    max_cost_usd: float = Field(gt=0)

    @property
    def worst_case_input_tokens(self) -> int:
        """The most input a run can legitimately accumulate within its own request budget."""
        return self.max_requests * self.max_input_tokens_per_request

    def to_usage_limits(self) -> UsageLimits:
        return UsageLimits(
            request_limit=self.max_requests,
            tool_calls_limit=self.max_tool_calls,
            input_tokens_limit=self.max_input_tokens,
            per_request_input_tokens_limit=self.max_input_tokens_per_request,
            output_tokens_limit=self.max_output_tokens,
            # Decimal so a float's representation error cannot move the ceiling.
            cost_limit=Decimal(str(self.max_cost_usd)),
        )


class MissingBudget(ValueError):
    """Raised when a spec declares no run budget.

    Construction fails rather than defaulting: an agent with no ceiling is exactly the
    condition the budget exists to prevent, and a silent default would hide it.
    """


def run_budget(agent_name: str, metadata: dict[str, Any] | None) -> RunBudget:
    budgets = (metadata or {}).get("budgets")
    if not isinstance(budgets, dict) or not budgets:
        raise MissingBudget(f"{agent_name}: metadata.budgets is required")
    return RunBudget.model_validate(budgets)


def usage_limits_for(agent_name: str, metadata: dict[str, Any] | None) -> UsageLimits:
    return run_budget(agent_name, metadata).to_usage_limits()
