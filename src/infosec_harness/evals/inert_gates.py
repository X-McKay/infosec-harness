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

import json
import textwrap
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, StrEnum
from pathlib import Path
from typing import Any

__all__ = [
    "InertCheck",
    "InertReason",
    "PricingStatus",
    "announce_inert_checks",
    "find_inert_checks",
    "format_inert_notice",
    "pricing_status",
]


class PricingStatus(StrEnum):
    """Whether *this deployment* can turn token usage for a model into dollars."""

    PRICED = "priced"
    """A nonzero price exists, so a cost metric can move."""

    STUB = "stub"
    """No model was called at all (``HARNESS_MODEL_MODE=stub``); cost is definitionally 0."""

    UNKNOWN_MODEL = "unknown_model"
    """Neither genai-prices nor config/models.yaml knows this model id."""

    ZERO_PRICED = "zero_priced"
    """Prices are configured and are zero — e.g. self-hosted vLLM with no per-token billing."""

    UNDETERMINED = "undetermined"
    """The pricing lookup itself failed; treat cost as unverified rather than live."""

    @property
    def can_move(self) -> bool:
        """True only when a cost metric derived from this model can be nonzero."""
        return self is PricingStatus.PRICED


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


def _probe_usage() -> Any:
    """A usage record large enough that any real price table yields a nonzero cost."""

    class _Usage:
        input_tokens = 1_000_000
        output_tokens = 1_000_000
        cache_read_tokens = None
        cache_write_tokens = None

    return _Usage()


def pricing_status(model_name: str) -> PricingStatus:
    """Ask the deployment's own cost estimator whether ``model_name`` can be priced.

    Deliberately routed through :func:`infosec_harness.agents.models.estimate_cost` — the
    same function the eval loop uses — so this cannot drift from what the report measured.
    A million tokens in and out is priced; if that comes back ``None`` or ``0.0``, no real
    run of this model could have produced a nonzero cost either.
    """
    if model_name.startswith("stub:"):
        return PricingStatus.STUB
    try:
        from infosec_harness.agents.models import estimate_cost

        candidates = [model_name]
        # `resolved_model_name` records "<backend>:<model_id>"; price tables are keyed by
        # the bare model id, so try that too before declaring a model unpriced.
        if ":" in model_name:
            candidates.append(model_name.split(":", 1)[1])
        best = None
        for name in candidates:
            cost, _ = estimate_cost(name, _probe_usage())
            if cost:
                return PricingStatus.PRICED
            if cost == 0.0:
                best = PricingStatus.ZERO_PRICED
        return best or PricingStatus.UNKNOWN_MODEL
    except Exception:
        return PricingStatus.UNDETERMINED


_COST_DETAIL = {
    PricingStatus.STUB: (
        "no model was called (stub mode), so every case reports a cost of 0.0 and no "
        "ceiling could trip. An environment fact, not a defect"
    ),
    PricingStatus.UNKNOWN_MODEL: (
        "this deployment cannot price model {model!r} — neither genai-prices nor "
        "config/models.yaml has a rate for it — so cost is 0.0 for every case and no "
        "ceiling could trip. An environment fact, not a defect: the ceiling wakes up "
        "unchanged against a priced backend"
    ),
    PricingStatus.ZERO_PRICED: (
        "model {model!r} is priced at zero per token (self-hosted, no per-token billing), "
        "so cost is 0.0 for every case and no ceiling could trip. An environment fact, not "
        "a defect"
    ),
    PricingStatus.UNDETERMINED: (
        "the cost is 0.0 and this deployment's pricing for model {model!r} could not be "
        "determined, so the ceiling is unverified rather than live"
    ),
}

_COST_REASON = {
    PricingStatus.STUB: InertReason.COST_STUB_MODEL,
    PricingStatus.UNKNOWN_MODEL: InertReason.COST_UNPRICED_MODEL,
    PricingStatus.ZERO_PRICED: InertReason.COST_ZERO_PRICED_MODEL,
    PricingStatus.UNDETERMINED: InertReason.COST_UNPRICED_MODEL,
}


def find_inert_checks(
    report: dict,
    policy: dict,
    *,
    pricing: Callable[[str], PricingStatus] = pricing_status,
) -> list[InertCheck]:
    """Every check in ``policy`` that the run described by ``report`` could not have failed.

    ``report`` is the mapping :func:`infosec_harness.evals.run.write_release_report` writes
    (``metrics``, ``hard_gates``, ``provenance``); ``policy`` is the agent's parsed
    ``release-policy.yaml``. ``pricing`` is injectable for tests; by default it asks the
    deployment's real cost estimator.

    Returns an empty list when every check is live. Order is stable: hard gates, then
    thresholds, each in policy order.
    """
    metrics = report.get("metrics") or {}
    gates = report.get("hard_gates") or {}
    model = str((report.get("provenance") or {}).get("model") or "")
    found: list[InertCheck] = []

    for metric in policy.get("hard_gates") or {}:
        limit = (policy["hard_gates"] or {})[metric]
        value = gates.get(metric, metrics.get(metric))
        if metric not in gates and metric not in metrics:
            found.append(InertCheck(
                kind="hard_gate", metric=metric, bound=None,
                limit=_as_number(limit), value=None, reason=InertReason.METRIC_ABSENT,
                detail=("the report emits no such key, so `agentctl release` sees a missing "
                        "gate rather than a failure and this gate enforces nothing. Fix the "
                        "report writer or drop the gate"),
            ))
        elif not isinstance(value, (int, float)) or isinstance(value, bool):
            found.append(InertCheck(
                kind="hard_gate", metric=metric, bound=None, limit=_as_number(limit),
                value=None, reason=InertReason.METRIC_NOT_NUMERIC,
                detail=(f"the report emits {value!r}, which cannot be compared against a "
                        "numeric gate"),
            ))

    for metric, spec in (policy.get("thresholds") or {}).items():
        spec = spec if isinstance(spec, dict) else {}
        value = metrics.get(metric, gates.get(metric))
        for bound in ("min", "max"):
            if bound not in spec:
                continue
            limit = _as_number(spec[bound])
            if metric not in metrics and metric not in gates:
                found.append(InertCheck(
                    kind="threshold", metric=metric, bound=bound, limit=limit, value=None,
                    reason=InertReason.METRIC_ABSENT,
                    detail=("the report never emits this metric, so the threshold is "
                            "compared against nothing and can never fail. Fix the report "
                            "writer or drop the threshold"),
                ))
                continue
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                found.append(InertCheck(
                    kind="threshold", metric=metric, bound=bound, limit=limit, value=None,
                    reason=InertReason.METRIC_NOT_NUMERIC,
                    detail=(f"the report emits {value!r}, which cannot be compared against "
                            "a numeric bound"),
                ))
                continue
            if (vacuous := _vacuous_detail(metric, bound, limit)) is not None:
                found.append(InertCheck(
                    kind="threshold", metric=metric, bound=bound, limit=limit,
                    value=float(value), reason=InertReason.BOUND_VACUOUS, detail=vacuous,
                ))
                continue
            if bound == "max" and _is_cost_metric(metric) and float(value) == 0.0:
                status = pricing(model)
                if not status.can_move:
                    found.append(InertCheck(
                        kind="threshold", metric=metric, bound=bound, limit=limit,
                        value=0.0, reason=_COST_REASON[status],
                        detail=_COST_DETAIL[status].format(model=model or "<unrecorded>"),
                    ))
                else:
                    found.append(InertCheck(
                        kind="threshold", metric=metric, bound=bound, limit=limit,
                        value=0.0, reason=InertReason.COST_ZERO_UNEXPLAINED,
                        detail=(f"cost is exactly 0.0 even though model {model!r} is priced "
                                "by this deployment, so the ceiling could not have tripped "
                                "and the zero is unexplained. Check that the eval loop is "
                                "accounting usage"),
                    ))
    return found


def _as_number(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _vacuous_detail(metric: str, bound: str, limit: float | None) -> str | None:
    """A bound no observation of this metric could violate, judged from its name alone."""
    if limit is None:
        return None
    low, high = _metric_range(metric)
    if bound == "min" and low is not None and limit <= low:
        return (f"{metric} can never be below {low:g}, so a floor of {limit:g} is satisfied "
                "by every conceivable run")
    if bound == "max" and high is not None and limit >= high:
        return (f"{metric} can never exceed {high:g}, so a ceiling of {limit:g} is satisfied "
                "by every conceivable run")
    return None


def _policy_check_count(policy: dict) -> int:
    n = len(policy.get("hard_gates") or {})
    for spec in (policy.get("thresholds") or {}).values():
        n += sum(1 for bound in ("min", "max") if isinstance(spec, dict) and bound in spec)
    return n


def format_inert_notice(checks: list[InertCheck], *, subject: str, policy: dict | None = None,
                        width: int = 92) -> str:
    """A block loud enough that a human or CI log reader cannot skim past it.

    Always states that this is information: an inert check does not fail the run.
    """
    rule = "=" * width
    total = _policy_check_count(policy) if policy else None
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


_announced: set[tuple[str, str]] = set()


def default_policy_path(agent: str) -> Path:
    from infosec_harness.settings import get_settings

    return get_settings().agents_dir / agent / "evals" / "release-policy.yaml"


def announce_inert_checks(agent: str, report_path: Path, *, policy_path: Path | None = None,
                          echo: Callable[[str], None] = print,
                          once: bool = True) -> list[InertCheck]:
    """Audit a just-written report against the agent's policy and print the finding.

    Safe to call from more than one place in a process: by default the same
    (agent, report) pair is announced only once, so wiring this into both
    ``write_release_report`` and the CLI does not double-print. Never raises — an audit
    that fails must not take a real eval run with it.
    """
    import yaml

    report_path = Path(report_path)
    key = (agent, str(report_path.resolve()))
    if once and key in _announced:
        return []
    policy_path = policy_path or default_policy_path(agent)
    try:
        report = json.loads(report_path.read_text())
        policy = yaml.safe_load(policy_path.read_text()) or {}
    except Exception as exc:  # pragma: no cover - defensive; audit must not break a run
        echo(f"inert-gate audit skipped: could not read report/policy ({exc})")
        return []
    _announced.add(key)
    checks = find_inert_checks(report, policy)
    echo(format_inert_notice(checks, subject=agent, policy=policy))
    return checks
