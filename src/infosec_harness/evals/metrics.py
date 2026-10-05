"""Experiment metrics, computed from the attempt records a run produced and nothing else.

Every number here is a pure function of the per-attempt records the runner persists, so a
metric can be recomputed from a stored experiment and tested without running a model. An
attempt is one (case, repetition) invocation; it is *scored* unless its outcome is
``failed`` (the run fell over on it and it never produced a classifiable result).
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

PERCENTILE_METHOD = "nearest-rank-v1"

# The outcome of a scored attempt. Exactly one per attempt, so the failure categories below
# partition the failed attempts and can never sum past them.
OUTCOMES = ("answered", "budget_exhausted", "invalid_output", "execution_not_checked",
            "execution_failed")
FAILURE_CATEGORIES = ("wrong_answer", "budget_exhausted", "invalid_output",
                      "execution_not_checked", "execution_failed")

Attempt = Mapping[str, Any]


@dataclass(frozen=True)
class RunPlan:
    """What a run set out to measure, fixed before the first case."""

    cases: int
    repetitions: int
    execution_checks: int
    """Declared execution checks across every planned run (cases with one x repetitions)."""
    unevidenced_safety: bool
    """Whether the agent's adapter defines the unevidenced-safety predicate at all."""
    uncovered_material_scenarios: int

    @property
    def runs(self) -> int:
        return self.cases * self.repetitions


def percentile(values: Sequence[float], q: float) -> float:
    """Nearest-rank percentile, 0.0 when nothing ran. Small samples, so no interpolation."""
    if not 0.0 <= q <= 1.0:
        raise ValueError(f"percentile must be between 0 and 1, got {q}")
    if not values:
        return 0.0
    ordered = sorted(values)
    # Nearest-rank is the observation at ceil(q * N), using one-based ranks. Clamp q=0
    # to the first observation so the helper remains defined on the closed interval.
    return ordered[max(0, math.ceil(q * len(ordered)) - 1)]


def usage_metrics(attempts: Sequence[Attempt]) -> dict[str, object]:
    """Publish aggregate usage only when every attempted run supplied usage."""
    observed = [a["usage"] for a in attempts if a.get("usage_status") == "observed"]
    tokens = sum(u["input_tokens"] + u["output_tokens"] for u in observed)
    cache_read = sum(u.get("cache_read_tokens") or 0 for u in observed)
    attempt_count, observed_count = len(attempts), len(observed)
    observed_average = round(tokens / observed_count, 1) if observed_count else None
    observed_cache_ratio = (
        round(cache_read / tokens, 4) if tokens else 0.0 if observed_count else None
    )
    complete = attempt_count > 0 and observed_count == attempt_count
    return {
        "avg_tokens": observed_average if complete else None,
        "cache_hit_ratio": observed_cache_ratio if complete else None,
        "usage_observations": {
            "attempts_observed": observed_count,
            "attempts_total": attempt_count,
            "attempt_coverage_rate": (
                round(observed_count / attempt_count, 4) if attempt_count else None
            ),
            "observed_tokens_total": tokens,
            "observed_avg_tokens": observed_average,
            "observed_cache_read_tokens": cache_read,
            "observed_cache_hit_ratio": observed_cache_ratio,
        },
    }


def failure_categories(scored: Sequence[Attempt]) -> dict[str, int]:
    """Why scored attempts failed, one category per failed attempt.

    A wrong answer, a run stopped by its budget, and an output that never validated are three
    different problems. An attempt that passed is in no category, whatever its outcome.
    """
    counts = dict.fromkeys(FAILURE_CATEGORIES, 0)
    for attempt in scored:
        if not attempt["passed"]:
            outcome = attempt["outcome"]
            counts["wrong_answer" if outcome == "answered" else outcome] += 1
    return counts


def experiment_metrics(
    attempts: Sequence[Attempt], plan: RunPlan, *, status: str, cases_completed: int
) -> dict[str, Any]:
    """Every metric an experiment publishes, from its attempts and its plan."""
    scored = [a for a in attempts if a["outcome"] != "failed"]
    total = len(scored)
    passed = sum(bool(a["passed"]) for a in scored)
    invalid_output = sum(a["outcome"] == "invalid_output" for a in scored)
    budget_exhausted = sum(a["outcome"] == "budget_exhausted" for a in scored)
    execution = Counter((a.get("execution_check") or {}).get("status") for a in scored)
    execution_passed, execution_failed = execution["passed"], execution["failed"]
    cost_unknown = sum(a["cost_usd"] is None for a in attempts)
    cost = sum(a["cost_usd"] or 0.0 for a in scored)
    costs = [a["cost_usd"] for a in scored if a["cost_usd"] is not None]
    latencies = [a["latency_s"] for a in scored]
    tool_calls = [float(a["call_summary"]["tool_call_count"]) for a in scored]
    requests = [float(a["usage"]["requests"]) for a in scored if a.get("usage") is not None]
    per_repetition: dict[int, list[int]] = {}
    confusion: Counter[str] = Counter()
    for attempt in scored:
        tally = per_repetition.setdefault(attempt["repetition"], [0, 0])
        tally[0] += int(bool(attempt["passed"]))
        tally[1] += 1
        confusion[f"{attempt['expected']}->{attempt['predicted']}"] += 1
    per_case_cost = round(cost / total, 6) if total and cost_unknown == 0 else None
    p95_requests = int(percentile(requests, 0.95))
    metrics: dict[str, Any] = {
        "accuracy": round(passed / total, 4) if total else 0.0,
        "n": total,
        "passed": passed,
        "cost_usd_total": round(cost, 6) if cost_unknown == 0 else None,
        "cost_usd_per_case": per_case_cost,
        **usage_metrics(attempts),
        "confusion": dict(sorted(confusion.items())),
        "distributions": {
            "percentile_method": PERCENTILE_METHOD,
            # The worst repetition, not the mean across them: with --repeat, averaging
            # launders a bad run into an acceptable number.
            "worst_repetition_pass_rate": (
                round(min(p / t for p, t in per_repetition.values()), 4)
                if per_repetition else 0.0
            ),
            # Every scored attempt is timed, including the ones stopped by their budget: a
            # run that was stopped still took time, and excluding it would make the
            # distribution describe only the cases that behaved.
            "p50_latency_s": round(percentile(latencies, 0.50), 3),
            "p95_latency_s": round(percentile(latencies, 0.95), 3),
            "p50_cost_usd": round(percentile(costs, 0.50), 6) if costs else None,
            "p95_cost_usd": round(percentile(costs, 0.95), 6) if costs else None,
            "p50_model_requests": int(percentile(requests, 0.50)),
            "p95_model_requests": p95_requests,
            "p50_tool_calls": int(percentile(tool_calls, 0.50)),
            "p95_tool_calls": int(percentile(tool_calls, 0.95)),
            "failure_categories": failure_categories(scored),
        },
        # Named to match the release policies' gates and thresholds, so the contract is
        # executable rather than aspirational (agent-playbook §7).
        "task_success_rate": round(passed / total, 4) if total else 0.0,
        "schema_validity_rate": round((total - invalid_output) / total, 4) if total else 0.0,
        "budget_exhausted_count": budget_exhausted,
        "usage_unknown": sum(a.get("usage_status") != "observed" for a in attempts),
        "cost_unknown": cost_unknown,
        "average_cost_usd": per_case_cost,
        "p95_model_requests": p95_requests,
        # Static over the cases this run used: a group-filtered or held-out run cannot
        # borrow coverage from cases it did not exercise.
        "uncovered_material_scenarios": plan.uncovered_material_scenarios,
        # Execution-backed cases are material quality checks. A declared check that never ran
        # (no secure runtime, stub mode, no typed output, or a run cut short) is unknown
        # evidence and stays a failing hard-gate value.
        "execution_not_checked_count": max(
            0, plan.execution_checks - execution_passed - execution_failed),
        "execution_failed_count": execution_failed,
        "execution_checks_planned": plan.execution_checks,
        "execution_checks_passed": execution_passed,
        # Coverage travels with the numbers: every metric above is over `n` of `n_planned`
        # case runs, and only `status == "complete"` means they are equal.
        "status": status,
        "n_planned": plan.runs,
        "cases_planned": plan.cases,
        "cases_completed": cases_completed,
        "attempted_runs": len(attempts),
        "attempts": list(attempts),
    }
    if plan.unevidenced_safety:
        # Only emitted where the predicate is defined: a constant zero for an agent with no
        # predicate would read as a safety gate that held.
        metrics["unevidenced_safe_verdicts"] = sum(bool(a["unevidenced_safe"]) for a in scored)
    return metrics


def gateable_metrics(*, unevidenced_safety: bool) -> frozenset[str]:
    """The numeric metric names a run publishes, so a policy can be checked against them."""
    plan = RunPlan(cases=0, repetitions=1, execution_checks=0,
                   unevidenced_safety=unevidenced_safety, uncovered_material_scenarios=0)
    shape = experiment_metrics([], plan, status="complete", cases_completed=0)
    return frozenset(
        name for name, value in shape.items()
        if value is None or (isinstance(value, int | float) and not isinstance(value, bool))
    )
