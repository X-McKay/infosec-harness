"""Deterministic pre-filter (F1) and prioritization (F9). No model involved."""

from __future__ import annotations

from dataclasses import dataclass

from infosec_harness.domain.models import (
    Finding,
    InconclusiveReason,
    PriorityBand,
    Reachability,
    RepoSnapshot,
    Severity,
    Verdict,
    VerdictLabel,
)
from infosec_harness.repo.access import RepositoryAccessError, resolve_confined

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


@dataclass(frozen=True)
class PreFilterResult:
    """Either continue triage, or short-circuit with an early verdict."""

    verdict: Verdict | None
    note: str | None = None


def pre_filter(finding: Finding, snapshot: RepoSnapshot) -> PreFilterResult:
    """Reject a missing location without turning absence or a path name into safety."""
    loc = finding.location
    if loc is None:
        return PreFilterResult(None)  # intake already resolved or parked; nothing cheap to decide
    try:
        target = resolve_confined(snapshot.path, loc.file_path, must_exist=True)
    except (OSError, RepositoryAccessError):
        return PreFilterResult(
            Verdict(
                label=VerdictLabel.inconclusive,
                confidence=0.0,
                rationale=(f"Reported file {loc.file_path} could not be resolved inside the "
                           f"source snapshot for {finding.revision}. Missing source is not "
                           "evidence of safety."),
                inconclusive_reason=InconclusiveReason.needs_info,
            ),
            note="file_missing",
        )
    if not target.is_file():
        return PreFilterResult(
            Verdict(label=VerdictLabel.inconclusive, confidence=0.0,
                    rationale=f"Reported location {loc.file_path} is not a source file.",
                    inconclusive_reason=InconclusiveReason.needs_info),
            note="file_missing",
        )
    return PreFilterResult(None)


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


def priority_for_inconclusive(finding: Finding) -> tuple[float, PriorityBand]:
    """Priority for a run with no supported security judgment, preserving intake severity."""
    score = round(SEVERITY_WEIGHT[finding.severity] * 0.6, 4)
    return score, priority_band(score)
