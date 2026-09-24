from infosec_harness.agents.validators import verdict_violations
from infosec_harness.domain.models import (
    CodeRef,
    DiagnosisKind,
    InconclusiveReason,
    Reachability,
    Verdict,
    VerdictFacts,
    VerdictLabel,
)


def v(label, **kw):
    return Verdict(label=label, confidence=0.8, rationale="r", **kw)


def test_exploitable_requires_oracle():
    facts = VerdictFacts(environment_ready=True, oracle_fired=False)
    assert verdict_violations(v(VerdictLabel.potentially_exploitable), facts)


def test_exploitable_valid_positive_ok():
    facts = VerdictFacts(environment_ready=True, oracle_fired=True, precondition_reached=True,
                         last_diagnosis=DiagnosisKind.valid_positive)
    assert verdict_violations(v(VerdictLabel.potentially_exploitable), facts) == []


def test_not_exploitable_needs_valid_negative_or_unreachable():
    facts = VerdictFacts(environment_ready=True, oracle_fired=False, precondition_reached=False)
    assert verdict_violations(v(VerdictLabel.likely_not_exploitable), facts)
    facts_ok = VerdictFacts(environment_ready=True, oracle_fired=False, precondition_reached=True,
                            last_diagnosis=DiagnosisKind.valid_negative)
    assert verdict_violations(v(VerdictLabel.likely_not_exploitable), facts_ok) == []


def test_unreachable_negative_needs_evidence():
    facts = VerdictFacts(environment_ready=False, reachability=Reachability.unreachable)
    assert verdict_violations(v(VerdictLabel.likely_not_exploitable), facts)  # no evidence
    assert verdict_violations(
        v(VerdictLabel.likely_not_exploitable, evidence=[CodeRef(file_path="a", start_line=1, end_line=2)]),
        facts) == []


def test_inconclusive_needs_reason_and_env_rule():
    facts = VerdictFacts(environment_ready=False)
    assert verdict_violations(v(VerdictLabel.inconclusive), facts)  # missing reason
    assert verdict_violations(
        v(VerdictLabel.inconclusive, inconclusive_reason=InconclusiveReason.conflicting_evidence),
        facts)  # wrong reason for no-env
    assert verdict_violations(
        v(VerdictLabel.inconclusive, inconclusive_reason=InconclusiveReason.environment_unbuildable),
        facts) == []
