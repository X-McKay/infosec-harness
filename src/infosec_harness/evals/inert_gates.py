"""Find the release-policy checks that *could not have failed* for a given run.

Why this exists
---------------
A threshold on a metric that is structurally absent or structurally constant is worse
than no threshold at all, because it reads as coverage. `average_cost_usd: {max: 0.50}`
in every agent policy looks like a spend gate; but the live backend is a self-hosted
endpoint with no per-token pricing, so every case reports a cost of exactly ``0.0`` and no
value of the ceiling — 0.50, 0.05, 0.0005 — could ever trip it. A reviewer reading the
policy concludes cost is governed. Nobody is lying, and nothing is enforced. The same
hazard applies to a policy that names a metric the report never emits: `agentctl release`
reports a missing key instead of a failure, and the gate is decorative.

The fix is not to delete such thresholds (the cost ceiling is the right ceiling the moment
a priced model is used) but to make their inertness *visible at the point the evidence is
produced* — so "the cost gate passed" is never mistaken for "cost was measured".

Two kinds of inertness, deliberately reported differently
---------------------------------------------------------
* **Environment** (:attr:`InertReason.is_defect` is False) — the deployment cannot price
  the model, or prices it at zero because it is self-hosted. That is a true fact about
  where the eval ran, not a bug: the threshold is dormant, and will wake up unchanged
  against a priced backend. Correct to note, wrong to "fix".
* **Defect** (:attr:`InertReason.is_defect` is True) — the metric was never emitted, is
  not a number, or the bound is unsatisfiable-by-construction. Something is wrong in the
  report writer or in the policy, and the check will stay dead until a human edits one of
  them.

This module reports; it never fails a run. Inertness is an evidence-quality signal, and
turning it into a gate would just relocate the same blind spot.
"""

from __future__ import annotations

import textwrap
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from functools import partial
from typing import Any

from infosec_harness.evals.gates import Check, ReleasePolicy
from infosec_harness.evals.pricing import PricingStatus, pricing_label, pricing_status

__all__ = [
    "InertCheck",
    "InertReason",
    "find_inert_checks",
    "format_inert_notice",
]


class InertReason(Enum):
    """Why a policy check could not have failed, and whether that is somebody's bug."""

    METRIC_ABSENT = ("METRIC_ABSENT", True)
    METRIC_NOT_NUMERIC = ("METRIC_NOT_NUMERIC", True)
    BOUND_VACUOUS = ("BOUND_VACUOUS", True)
    COST_UNPRICED_MODEL = ("COST_UNPRICED_MODEL", False)
    COST_ZERO_PRICED_MODEL = ("COST_ZERO_PRICED_MODEL", False)
    COST_STUB_MODEL = ("COST_STUB_MODEL", False)
    COST_ZERO_UNEXPLAINED = ("COST_ZERO_UNEXPLAINED", True)

    def __init__(self, code: str, is_defect: bool) -> None:
        self.code = code
        self.is_defect = is_defect


@dataclass(frozen=True)
class InertCheck:
    """One policy check that this run could not have failed."""

    kind: str
    """``"threshold"`` or ``"hard_gate"``."""

    metric: str
    bound: str | None
    """``"min"`` / ``"max"`` for a threshold; ``None`` for an equality hard gate."""

    limit: float | None
    value: float | None
    reason: InertReason
    detail: str
    """One sentence a human can act on (or decide not to act on)."""

    @property
    def is_defect(self) -> bool:
        return self.reason.is_defect

    def as_report(self) -> dict[str, Any]:
        return {"kind": self.kind, "metric": self.metric, "bound": self.bound,
                "limit": self.limit, "value": self.value, "reason": self.reason.code,
                "is_defect": self.is_defect, "detail": self.detail}

    def describe(self) -> str:
        """``threshold average_cost_usd (max 0.5)`` — how the check is written in the policy."""
        where = f"{self.kind} {self.metric}"
        if self.bound is not None and self.limit is not None:
            where += f" ({self.bound} {self.limit:g})"
        elif self.limit is not None:
            where += f" (== {self.limit:g})"
        return where


# Metric-name shapes whose ranges we know without being told. Used only to spot a bound
# that no observation could violate; unknown names are simply left alone.
def _metric_range(metric: str) -> tuple[float | None, float | None]:
    """Conservative (low, high) bounds implied by a metric's name, ``None`` where unknown."""
    if metric.endswith(("_rate", "_ratio")):
        return 0.0, 1.0
    if metric.endswith("_count") or metric.startswith("p95_") or "cost" in metric:
        return 0.0, None
    return None, None


def _is_cost_metric(metric: str) -> bool:
    return "cost" in metric


_COST_DETAIL = {
    PricingStatus.STUB: (
        "no model was called (stub mode), so every case reports a cost of 0.0 and no "
        "ceiling could trip. An environment fact, not a defect"
    ),
    PricingStatus.UNKNOWN_MODEL: (
        "this deployment cannot price model {model!r} — neither genai-prices nor "
        "config/models.yaml has a rate for it — so cost is not measured for any case and no "
        "ceiling could trip. An environment fact, not a defect: the ceiling wakes up "
        "unchanged against a priced backend"
    ),
    PricingStatus.ZERO_PRICED: (
        "model {model!r} is priced at zero per token (self-hosted, no per-token billing), "
        "so cost is 0.0 for every case and no ceiling could trip. An environment fact, not "
        "a defect"
    ),
}

_COST_REASON = {
    PricingStatus.STUB: InertReason.COST_STUB_MODEL,
    PricingStatus.UNKNOWN_MODEL: InertReason.COST_UNPRICED_MODEL,
    PricingStatus.ZERO_PRICED: InertReason.COST_ZERO_PRICED_MODEL,
}


def find_inert_checks(
    report: Mapping[str, Any],
    policy: ReleasePolicy,
    *,
    pricing: Callable[[str], PricingStatus] | None = None,
) -> list[InertCheck]:
    """Every check in ``policy`` that the run described by ``report`` could not have failed.

    ``report`` is the mapping :func:`infosec_harness.evals.release_report.build_release_report`
    returns (``metrics``, ``hard_gates``, ``provenance``). The checks are exactly the ones
    :meth:`ReleasePolicy.evaluate` makes, so the audit and the verdict cannot disagree about
    what the policy contains or what counts as a number. The model's cost basis is the one the
    run recorded (``provenance.model_pricing``); ``pricing`` overrides it, and without either
    the deployment's price source is asked.

    Returns an empty list when every check is live. Order is the policy's: hard gates, then
    thresholds.
    """
    values = {**(report.get("metrics") or {}), **(report.get("hard_gates") or {})}
    provenance = report.get("provenance") or {}
    model = str(provenance.get("model") or "")

    def cost_basis() -> PricingStatus:
        if pricing is not None:
            return pricing(model)
        return pricing_label(provenance.get("model_pricing")) or pricing_status(model)

    found: list[InertCheck] = []
    for check in policy.evaluate(values).checks:
        inert = partial(_inert, check)
        if check.metric not in values:
            found.append(inert(InertReason.METRIC_ABSENT, (
                "the report emits no such key, so `agentctl release` sees a missing gate "
                "rather than a failure and this gate enforces nothing. Fix the report writer "
                "or drop the gate") if check.kind == "hard_gate" else (
                "the report never emits this metric, so the threshold is compared against "
                "nothing and can never fail. Fix the report writer or drop the threshold")))
            continue
        reported = values[check.metric]
        if check.value is None:
            if (check.kind == "threshold" and reported is None
                    and _is_cost_metric(check.metric)
                    and (status := cost_basis()) is PricingStatus.UNKNOWN_MODEL):
                # An unpriced model has no cost to report: the absence is the environment's,
                # exactly as a zero is for a model priced at zero.
                found.append(inert(_COST_REASON[status],
                                   _COST_DETAIL[status].format(model=model or "<unrecorded>")))
            else:
                found.append(inert(InertReason.METRIC_NOT_NUMERIC, (
                    f"the report emits {reported!r}, which cannot be compared against a "
                    f"numeric {'gate' if check.kind == 'hard_gate' else 'bound'}")))
            continue
        if check.kind == "hard_gate":
            continue
        if (vacuous := _vacuous_detail(check.metric, check.bound, check.limit)) is not None:
            found.append(inert(InertReason.BOUND_VACUOUS, vacuous, check.value))
            continue
        if check.bound == "max" and _is_cost_metric(check.metric) and check.value == 0.0:
            status = cost_basis()
            if not status.can_move:
                found.append(inert(_COST_REASON[status],
                                   _COST_DETAIL[status].format(model=model or "<unrecorded>"),
                                   0.0))
            else:
                found.append(inert(InertReason.COST_ZERO_UNEXPLAINED, (
                    f"cost is exactly 0.0 even though model {model!r} is priced by this "
                    "deployment, so the ceiling could not have tripped and the zero is "
                    "unexplained. Check that the eval loop is accounting usage"), 0.0))
    return found


def _inert(check: Check, reason: InertReason, detail: str,
           value: float | None = None) -> InertCheck:
    return InertCheck(kind=check.kind, metric=check.metric,
                      bound=None if check.kind == "hard_gate" else check.bound,
                      limit=check.limit, value=value, reason=reason, detail=detail)


def _vacuous_detail(metric: str, bound: str, limit: float) -> str | None:
    """A bound no observation of this metric could violate, judged from its name alone."""
    low, high = _metric_range(metric)
    if bound == "min" and low is not None and limit <= low:
        return (f"{metric} can never be below {low:g}, so a floor of {limit:g} is satisfied "
                "by every conceivable run")
    if bound == "max" and high is not None and limit >= high:
        return (f"{metric} can never exceed {high:g}, so a ceiling of {limit:g} is satisfied "
                "by every conceivable run")
    return None


def format_inert_notice(checks: list[InertCheck], *, subject: str,
                        policy: ReleasePolicy | None = None, width: int = 92) -> str:
    """A block loud enough that a human or CI log reader cannot skim past it.

    Always states that this is information: an inert check does not fail the run.
    """
    rule = "=" * width
    total = len(policy.evaluate({}).checks) if policy else None
    if not checks:
        of_n = f"all {total} " if total else ""
        return f"inert-gate audit: {of_n}policy checks for {subject} were live for this run."

    defects = [c for c in checks if c.is_defect]
    head = (f"INERT RELEASE GATES: {len(checks)}"
            + (f" of {total}" if total else "")
            + f" checks in {subject}'s release policy could not have failed for this run.")
    lines = [rule, *textwrap.wrap(head, width), ""]
    for check in checks:
        tag = "DEFECT" if check.is_defect else "environment"
        seen = "" if check.value is None else f" [reported {check.value:g}]"
        body = f"[{tag}] {check.describe()}{seen}: {check.detail}."
        wrapped = textwrap.wrap(body, width - 2)
        lines.extend(["  " + wrapped[0]] + ["      " + line for line in wrapped[1:]])
    lines.append("")
    if defects:
        lines.extend(textwrap.wrap(
            f"{len(defects)} of these is a defect in the report or the policy — the check is "
            "dead until someone edits one of them."
            if len(defects) == 1 else
            f"{len(defects)} of these are defects in the report or the policy — those checks "
            "are dead until someone edits one of them.", width))
    lines.extend(textwrap.wrap(
        "This is information, not a gate: the run's own pass/fail verdict is unchanged. An "
        "inert check enforces nothing, so do not read it as coverage.", width))
    lines.append(rule)
    return "\n".join(lines)
