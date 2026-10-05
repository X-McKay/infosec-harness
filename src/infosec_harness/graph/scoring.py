"""Operational priority from severity, verdict confidence and reachability."""

from __future__ import annotations

from infosec_harness.domain.models import (
    Finding,
    PriorityBand,
    Reachability,
    Severity,
    Verdict,
    VerdictLabel,
)

SEVERITY_WEIGHT = {
    Severity.critical: 1.0, Severity.high: 0.8, Severity.medium: 0.5,
    Severity.low: 0.3, Severity.info: 0.1, Severity.unknown: 0.4,
}
VERDICT_WEIGHT = {
    VerdictLabel.potentially_exploitable: 1.0,
    VerdictLabel.inconclusive: 0.5,
    VerdictLabel.likely_not_exploitable: 0.1,
}
REACHABILITY_WEIGHT = {
    Reachability.reachable: 1.0,
    Reachability.unknown: 0.6,
    # Input reaches the sink and a control is claimed to stop it. Ranked above `unreachable`
    # because the path exists -- if the control is wrong, or is removed by a later change, the
    # finding is live -- and below `unknown` because a specific control has at least been named.
    Reachability.neutralized: 0.4,
    Reachability.unreachable: 0.2,
}


def priority_score(finding: Finding, verdict: Verdict, reachability: Reachability) -> float:
    if verdict.label is VerdictLabel.inconclusive:
        # Assessment confidence is unknown, not evidence that the underlying security severity
        # fell. Keep operational failures and missing evidence from demoting a critical report.
        return round(SEVERITY_WEIGHT[finding.severity] * 0.6, 4)
    return round(
        VERDICT_WEIGHT[verdict.label]
        * SEVERITY_WEIGHT[finding.severity]
        * REACHABILITY_WEIGHT[reachability]
        * (0.3 + 0.7 * verdict.confidence),
        4,
    )


def priority_band(score: float) -> PriorityBand:
    if score >= 0.6:
        return PriorityBand.p1
    if score >= 0.35:
        return PriorityBand.p2
    if score >= 0.15:
        return PriorityBand.p3
    return PriorityBand.p4


def priority(finding: Finding, verdict: Verdict,
             reachability: Reachability) -> tuple[float, PriorityBand]:
    """The priority score and its band (F9)."""
    score = priority_score(finding, verdict, reachability)
    return score, priority_band(score)
