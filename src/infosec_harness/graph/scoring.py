"""Deterministic pre-filter (F1) and prioritization (F9). No model involved."""

from __future__ import annotations

from pathlib import Path

from infosec_harness.domain.models import (
    Finding,
    PriorityBand,
    Reachability,
    RepoSnapshot,
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
    Reachability.reachable: 1.0, Reachability.unknown: 0.6, Reachability.unreachable: 0.2,
}
TEST_OR_VENDOR = ("test", "tests", "spec", "__tests__", "vendor", "node_modules",
                  "third_party", "examples", "fixtures")


class PreFilterResult:
    """Either continue triage, or short-circuit with an early verdict."""

    def __init__(self, verdict: Verdict | None, note: str | None = None):
        self.verdict = verdict
        self.note = note

    @property
    def continue_triage(self) -> bool:
        return self.verdict is None


def pre_filter(finding: Finding, snapshot: RepoSnapshot) -> PreFilterResult:
    """Cheap deterministic exits before any agent runs."""
    loc = finding.location
    if loc is None:
        return PreFilterResult(None)  # intake already resolved or parked; nothing cheap to decide
    target = Path(snapshot.path) / loc.file_path
    if not target.exists():
        return PreFilterResult(
            Verdict(label=VerdictLabel.likely_not_exploitable, confidence=0.6,
                    rationale=f"Reported file {loc.file_path} does not exist at {finding.revision}."),
            note="file_missing",
        )
    parts = {p.lower() for p in Path(loc.file_path).parts}
    if parts & set(TEST_OR_VENDOR):
        return PreFilterResult(
            Verdict(label=VerdictLabel.likely_not_exploitable, confidence=0.5,
                    rationale="Finding is in test or vendored code, not shipped application code."),
            note="test_or_vendored",
        )
    return PreFilterResult(None)


def priority_score(finding: Finding, verdict: Verdict, reachability: Reachability) -> float:
    return round(
        VERDICT_WEIGHT[verdict.label]
        * SEVERITY_WEIGHT.get(finding.severity, 0.4)
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
