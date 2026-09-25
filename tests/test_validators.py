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


# --- Double-encoded nested objects in tool calls (domain/models.py) ---

def test_nested_object_arriving_as_a_json_string_is_decoded():
    """Models often emit a single nested object as a JSON string; accept it."""
    import json

    from infosec_harness.domain.models import FindingContext

    ctx = FindingContext.model_validate({
        "summary": "sqli", "reachability": "reachable", "reachability_rationale": "r",
        "sink": json.dumps({"file_path": "app.py", "start_line": 16, "end_line": 16}),
        "path": [{"file_path": "app.py", "start_line": 13, "end_line": 13}],
    })
    assert ctx.sink is not None and ctx.sink.file_path == "app.py" and ctx.sink.start_line == 16
    assert [p.start_line for p in ctx.path] == [13]


def test_a_string_that_is_not_an_object_is_still_rejected():
    """The coercion widens acceptance; it must not turn bad data into a silent default."""
    import pytest
    from pydantic import ValidationError

    from infosec_harness.domain.models import FindingContext

    for bad in ("not json at all", "[1, 2, 3]", '"just a string"', "42"):
        with pytest.raises(ValidationError):
            FindingContext.model_validate({
                "summary": "s", "reachability": "reachable",
                "reachability_rationale": "r", "sink": bad,
            })


def test_well_formed_nested_objects_are_untouched():
    from infosec_harness.domain.models import FindingContext

    payload = {
        "summary": "s", "reachability": "reachable", "reachability_rationale": "r",
        "sink": {"file_path": "a.py", "start_line": 1, "end_line": 2, "note": "n"},
    }
    ctx = FindingContext.model_validate(payload)
    assert ctx.sink is not None and ctx.sink.note == "n"


def test_coercion_applies_to_every_nested_object_field():
    """Not just `sink` — any singular nested model on an agent output type."""
    import json

    from infosec_harness.domain.models import FindingContext

    ref = {"file_path": "a.py", "start_line": 1, "end_line": 1}
    ctx = FindingContext.model_validate({
        "summary": "s", "reachability": "reachable", "reachability_rationale": "r",
        "source": json.dumps(ref), "sink": json.dumps(ref),
    })
    assert ctx.source is not None and ctx.sink is not None
