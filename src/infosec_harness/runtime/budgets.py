"""Per-run budgets, declared in each spec's metadata and enforced with UsageLimits.

The agent playbook (§9) requires every production agent to carry per-request and per-run
limits, in the order "prevent runaway execution" first. That ordering is the point: the
repair storm measured in docs/evidence/2026-09-25-live-model-validation/LIVE_VALIDATION.md grew one agent's context from 8.8k to 24k
tokens over three turns before anyone noticed by eye. A budget turns that into a bounded,
named failure.

Budgets are read from ``metadata.budgets`` so they live with the rest of the agent's
declarative contract and move with an overlay during experiments.
"""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, Field
from pydantic_ai.usage import UsageLimits

from infosec_harness.domain.canonical import canonical_bytes, sha256_hex


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
      is the failure the 8.8k -> 24k repair storm in docs/evidence/2026-09-25-live-model-validation/LIVE_VALIDATION.md actually was;
    * `max_input_tokens` is the run's arithmetic worst case derived from it
      (`max_requests x max_input_tokens_per_request`), exactly as `max_output_tokens` is
      derived from `max_requests x` the per-call output cap. It is a backstop, not the
      operative limit; `max_requests` is.

    Both relationships are asserted in tests/agents/test_budgets.py so neither can drift.
    """

    max_requests: int = Field(gt=0)
    max_tool_calls: int = Field(gt=0)
    # Per request: the context-size brake. See the class docstring.
    max_input_tokens_per_request: int = Field(gt=0)
    # Cumulative over the run: derived from the two fields above.
    max_input_tokens: int = Field(gt=0)
    max_output_tokens: int = Field(gt=0)
    max_cost_usd: float = Field(gt=0)

    def scaled_for(self, source_files: int | None) -> RunBudget:
        """This budget, widened for the size of the repository being worked on.

        Every ceiling here was fitted against the seeded corpus, whose Java fixture is **three
        files**. The harvested Vul4J repositories are around **five hundred**, and the first
        live run over them failed five of six cases with `UsageLimitExceeded` during
        preparation -- not one build failure. `recon` spent all twelve of its requests and had
        made exactly one repeated call, so that was a 500-file project needing more turns to
        profile, not a loop. A constant fitted to a toy repository is not a brake on a real one,
        it is a wall.

        Scaling is logarithmic because exploration cost grows with the breadth and depth of the
        tree rather than with the file count: you list directories and read a handful of files,
        and doubling the repository does not double either.

        **Every** ceiling scales by the same factor, deliberately. Each invariant in
        tests/agents/test_budgets.py is linear in `max_requests` -- the output ceiling is
        `max_requests x` the per-call cap, the cumulative input ceiling is `max_requests x` the
        per-request one -- so scaling uniformly preserves all of them by construction rather
        than by a second set of numbers that could drift. `max_input_tokens_per_request` is the
        exception: it is a per-context brake, and one request's context does not get larger
        because the repository has more files in it.
        """
        return self._scaled_by(size_factor(source_files))

    def _scaled_by(self, factor: float) -> RunBudget:
        if factor == 1.0:
            return self
        return self.model_copy(update={
            "max_requests": max(1, round(self.max_requests * factor)),
            "max_tool_calls": max(1, round(self.max_tool_calls * factor)),
            "max_input_tokens": max(1, round(self.max_input_tokens * factor)),
            "max_output_tokens": max(1, round(self.max_output_tokens * factor)),
            "max_cost_usd": round(self.max_cost_usd * factor, 6),
        })

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


class BudgetResolution(BaseModel):
    """Requested, scaled, and finally enforced limits for one invocation."""

    model_config = {"frozen": True}

    agent_name: str
    source_files: int | None
    formula_version: str
    baseline_source_files: int
    growth_per_doubling: float
    maximum_size_factor: float
    size_factor: float
    rounding: str = "python-round-nearest-even"
    requested: RunBudget
    scaled: RunBudget
    root_ceiling: RunBudget | None = None
    effective: RunBudget
    binding_root_fields: tuple[str, ...] = ()
    provider_output_floor: int = 0

    @property
    def digest(self) -> str:
        # Persisted identity: the ASCII-escaped encoding it has always been hashed under.
        return sha256_hex(canonical_bytes(self.model_dump(mode="json"), ascii_only=True))[:16]

    def to_usage_limits(self) -> UsageLimits:
        return self.effective.to_usage_limits()


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


# A repository at or below this many source files is "fixture scale" and gets its declared
# budget unchanged, so the seeded corpus behaves exactly as it did.
BASELINE_SOURCE_FILES = 16
# Added per doubling beyond the baseline. 0.25 puts a 500-file repository at ~2.2x, which
# clears the twelve requests `recon` exhausted on one with room to spare.
GROWTH_PER_DOUBLING = 0.25
# The brake has to stay a brake. Three times the declared budget bounds the worst case at a
# number that is still obviously wrong for one agent run, so a genuine runaway is still caught.
MAX_SIZE_FACTOR = 3.0
SIZE_FORMULA_VERSION = "repo-source-files-log2-v1"

_BUDGET_FIELDS = (
    "max_requests",
    "max_tool_calls",
    "max_input_tokens_per_request",
    "max_input_tokens",
    "max_output_tokens",
    "max_cost_usd",
)


def size_factor(source_files: int | None) -> float:
    """How much to widen a budget for a repository of this many source files.

    1.0 for anything fixture-sized or unknown: absent a measurement, the declared ceiling
    stands rather than being guessed upward.
    """
    if not source_files or source_files <= BASELINE_SOURCE_FILES:
        return 1.0
    doublings = math.log2(source_files / BASELINE_SOURCE_FILES)
    return min(1.0 + GROWTH_PER_DOUBLING * doublings, MAX_SIZE_FACTOR)


def resolve_declared_budget(
    agent_name: str,
    requested: RunBudget,
    *,
    source_files: int | None = None,
    root_ceiling: RunBudget | None = None,
    provider_output_floor: int = 0,
) -> BudgetResolution:
    """Resolve the limits passed to PydanticAI and retain every adjustment as provenance.

    Pure: no file or environment access, so Temporal workflows can rescale a declaration the
    worker loaded outside workflow execution. A root ceiling can only tighten a member budget.
    Production and evals share it, so a calibration overlay changes the limits that execute.
    """
    factor = size_factor(source_files)
    scaled = requested._scaled_by(factor)
    effective = scaled
    binding: list[str] = []
    if root_ceiling is not None:
        updates: dict[str, int | float] = {}
        for field in _BUDGET_FIELDS:
            value = getattr(scaled, field)
            ceiling = getattr(root_ceiling, field)
            updates[field] = min(value, ceiling)
            if ceiling < value:
                binding.append(field)
        effective = scaled.model_copy(update=updates)
    return BudgetResolution(
        agent_name=agent_name,
        source_files=source_files,
        formula_version=SIZE_FORMULA_VERSION,
        baseline_source_files=BASELINE_SOURCE_FILES,
        growth_per_doubling=GROWTH_PER_DOUBLING,
        maximum_size_factor=MAX_SIZE_FACTOR,
        size_factor=factor,
        requested=requested,
        scaled=scaled,
        root_ceiling=root_ceiling,
        effective=effective,
        binding_root_fields=tuple(binding),
        provider_output_floor=provider_output_floor,
    )
