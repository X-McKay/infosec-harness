"""Per-run budgets, declared in each spec's metadata and enforced with UsageLimits.

The agent playbook (§9) requires every production agent to carry per-request and per-run
limits, in the order "prevent runaway execution" first. That ordering is the point: the
repair storm measured in docs/LIVE_VALIDATION.md grew one agent's context from 8.8k to 24k
tokens over three turns before anyone noticed by eye. A budget turns that into a bounded,
named failure.

Budgets are read from ``metadata.budgets.run`` so they live with the rest of the agent's
declarative contract and move with an overlay during experiments.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from pydantic import BaseModel, Field
from pydantic_ai.usage import UsageLimits


class RunBudget(BaseModel):
    """What one agent run may spend. Every field is a ceiling, never a target."""

    max_model_requests: int = Field(gt=0)
    max_tool_calls: int = Field(gt=0)
    max_input_tokens: int = Field(gt=0)
    max_output_tokens: int = Field(gt=0)
    max_cost_usd: float = Field(gt=0)

    def to_usage_limits(self) -> UsageLimits:
        return UsageLimits(
            request_limit=self.max_model_requests,
            tool_calls_limit=self.max_tool_calls,
            input_tokens_limit=self.max_input_tokens,
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
    budgets = (metadata or {}).get("budgets") or {}
    run = budgets.get("run")
    if not isinstance(run, dict):
        raise MissingBudget(f"{agent_name}: metadata.budgets.run is required")
    return RunBudget.model_validate(run)


def usage_limits_for(agent_name: str, metadata: dict[str, Any] | None) -> UsageLimits:
    return run_budget(agent_name, metadata).to_usage_limits()
