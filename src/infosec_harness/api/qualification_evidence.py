"""Project verified component evidence without promoting the active runtime profile."""

from datetime import UTC, datetime

from infosec_harness.agents.registry import AGENT_BINDINGS
from infosec_harness.api.contracts import QualificationStatus, QualifiedComponent
from infosec_harness.api.evidence_io import COMMIT, load_bundle, read_reference
from infosec_harness.qualification.ledger import assess
from infosec_harness.resources import source_checkout
from infosec_harness.settings import get_settings

_LIMITATIONS = [
    "Fresh full-suite qualification is not established by this component view.",
    "Hosted and Kubernetes qualification require their own measured evidence.",
    "Missing historical replay coverage remains not checked.",
]


def _unknown_components():
    return [
        QualifiedComponent(
            agent=agent,
            scope="agent_semantics",
            status="not_checked",
            freshness="unavailable",
            reason="Verified evidence is unavailable.",
        )
        for agent in AGENT_BINDINGS
    ]


def qualification_status() -> QualificationStatus:
    now = datetime.now(UTC).isoformat()
    try:
        bundle = load_bundle()
        ledger, current, reviews = (
            read_reference(bundle[k]) for k in ("ledger", "current", "reviews")
        )
        if set(bundle["selection"]) != set(AGENT_BINDINGS):
            raise ValueError("incomplete selection")
        # A deployed build label does not replace actual dependency hashing.
        if COMMIT.fullmatch(get_settings().git_commit_sha):
            current["qualification_candidate_commit"] = get_settings().git_commit_sha
        assessment = assess(ledger, current, reviews, root=source_checkout())
        records = {r["id"]: r for r in ledger["records"]}
        results = {r["record_id"]: r for r in assessment["results"]}
        projected = []
        for agent, identity in bundle["selection"].items():
            record, result = records[identity], results[identity]
            if record["component"] != agent or record["scope"] != "agent_semantics":
                raise ValueError("selection identity mismatch")
            status = result["status"]
            if status not in {"passed", "failed", "not_checked"}:
                status = "not_checked"
            witness_ref = record["evidence"].get("completion_witness") or record["evidence"].get(
                "cardinality"
            )
            witness = read_reference(witness_ref) if witness_ref else {}
            n, passed = witness.get("n"), witness.get("passed")
            n = n if type(n) is int and n >= 0 else None
            passed = (
                passed
                if type(passed) is int and passed >= 0 and n is not None and passed <= n
                else None
            )
            changed = bool(result["changed_dependencies"])
            verified = status == "passed"
            fresh = (
                verified
                and record["measured_source_commit"] == current["qualification_candidate_commit"]
            )
            projected.append(
                QualifiedComponent(
                    agent=agent,
                    scope="agent_semantics",
                    status=status,
                    measured_commit=record["measured_source_commit"]
                    if COMMIT.fullmatch(record["measured_source_commit"])
                    else None,
                    freshness="fresh"
                    if fresh
                    else "reused"
                    if verified
                    else "stale"
                    if changed
                    else "unavailable",
                    reason="Complete measured cohort; dependencies verified."
                    if verified
                    else "Dependencies changed; retest or review is required."
                    if changed
                    else "Verified evidence is unavailable or the measured gate did not pass.",
                    cases=n,
                    passed_cases=passed,
                )
            )
        overall = (
            "passed"
            if all(p.status == "passed" for p in projected)
            else "failed"
            if any(p.status == "failed" for p in projected)
            else "not_checked"
        )
        return QualificationStatus(
            as_of=now,
            candidate_commit=current["qualification_candidate_commit"],
            status=overall,
            detail="Selected complete component cohorts assessed against actual dependencies.",
            components=projected,
            limitations=_LIMITATIONS,
        )
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return QualificationStatus(
            as_of=now,
            status="not_checked",
            detail="Qualification evidence is unavailable, invalid, or incomplete.",
            components=_unknown_components(),
            limitations=_LIMITATIONS,
        )
