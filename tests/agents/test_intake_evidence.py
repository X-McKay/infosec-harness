"""Grounded extraction is required in production and evaluation, without label rewriting."""
from types import SimpleNamespace

import pytest
from pydantic_ai import ModelRetry

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.intake_evidence import EXTRACTED_FIELDS, extraction_evidence_violations
from infosec_harness.agents.registry import load_spec, resolve_agent_config
from infosec_harness.agents.validators import validate_intake_evidence
from infosec_harness.domain.models import AgentOutcome, ExtractedFinding, FindingInput
from infosec_harness.evals.adapters import intake_adapter

REPORT = "Caller input is interpolated into a shell command; a semicolon runs a second command."


def evidence(field="cwe", quote=REPORT, confidence=1):
    return {"field": field, "quote": quote, "confidence": confidence}


def test_field_set_matches_persisted_contract_without_a_schema_change():
    assert set(ExtractedFinding.model_fields) - {"evidence"} == EXTRACTED_FIELDS


def test_null_classification_with_positive_behavior_evidence_is_rejected():
    assert extraction_evidence_violations(REPORT, {"cwe": None, "evidence": [evidence()]})


@pytest.mark.parametrize("output", [
    {"cwe": "CWE-78", "evidence": []},
    {"cwe": "CWE-78", "evidence": [evidence(quote="")]},
    {"cwe": "CWE-78", "evidence": [evidence(confidence=0)]},
    {"cwe": "CWE-78", "evidence": [evidence(quote="The input is executed by a shell.")]},
    {"cwe": "CWE-78", "evidence": [evidence(field="invented-field")]},
])
def test_missing_fabricated_unknown_or_zero_confidence_support_is_rejected(output):
    assert extraction_evidence_violations(REPORT, output)


def test_weakness_and_meaningful_impact_can_use_behavior_evidence_without_literal_labels():
    output = {"cwe": "CWE-78", "claimed_impact": "Execution of a second command",
              "evidence": [evidence(), evidence("claimed_impact", "a semicolon runs a second command.")]}
    assert extraction_evidence_violations(REPORT, output) == []


def test_optional_unknown_fields_can_have_zero_confidence_or_no_evidence():
    assert extraction_evidence_violations(REPORT, {"cwe": None, "evidence": []}) == []
    assert extraction_evidence_violations(REPORT, {"cwe": None, "evidence": [
        evidence(confidence=0), evidence("file_path", "", 0)]}) == []


def test_location_values_must_be_literal_and_line_tokens_are_bounded_without_integer_parsing():
    report = "The issue is in app.py at line 016, in Runner::run."
    value = {"file_path": "app.py", "start_line": 16, "symbol": "Runner::run",
             "evidence": [evidence(field, report) for field in ("file_path", "start_line", "symbol")]}
    assert extraction_evidence_violations(report, value) == []
    value["file_path"] = "invented.py"
    assert extraction_evidence_violations(report, value)
    huge = "9" * 5000
    assert extraction_evidence_violations(huge, {"start_line": 16, "evidence": [
        evidence("start_line", huge)]})


@pytest.mark.parametrize("quote,start,end,accepted", [
    ("https://example.invalid/blob/main/app.py#L42", 42, None, True),
    ("https://example.invalid/blob/main/app.py#L42-L45", 42, 45, True),
    ("https://example.invalid/blob/main/app.py#L420", 42, None, False),
])
def test_literal_line_anchors_accept_complete_tokens_only(quote, start, end, accepted):
    output = {"start_line": start, "end_line": end,
              "evidence": [evidence("start_line", quote)]}
    if end is not None:
        output["evidence"].append(evidence("end_line", quote))
    assert bool(extraction_evidence_violations(quote, output)) != accepted


def test_unavailable_source_fails_closed_and_retry_never_echoes_report_model_or_field_strings():
    assert extraction_evidence_violations(None, {})
    output = ExtractedFinding.model_validate({"cwe": "CWE-78", "evidence": [
        evidence("secret-field", "secret-model-quote")]})
    with pytest.raises(ModelRetry) as error:
        validate_intake_evidence(SimpleNamespace(deps=AgentDeps(
            repo_path="/nonexistent", report_text="secret-source-report")), output)
    assert "secret" not in str(error.value)


def test_eval_adapter_serializes_the_exact_source_without_normalizing_it():
    report = "\n\t" + REPORT + "  \n"
    deps = intake_adapter({"payload": {"report": report}, "expected": "CWE-78"}).deps
    assert deps.report_text == report
    assert AgentDeps.model_validate_json(deps.model_dump_json()).report_text == report
    assert AgentDeps.model_validate({"repo_path": "/legacy"}).report_text is None


async def test_production_local_intake_receives_the_same_exact_report(tmp_path, monkeypatch):
    from infosec_harness.graph import local

    report = "\n\t" + REPORT + "  \n"
    captured = []

    async def run_agent(name, prompt, deps, *, record=None):
        assert name == "intake"
        captured.append(deps.report_text)
        outcome = AgentOutcome(agent=name, output=ExtractedFinding())
        record.append(outcome)
        return outcome

    async def resolve_location(*_args):
        return None

    from infosec_harness.graph import pipeline

    monkeypatch.setattr(pipeline, "execution_manifest", lambda _prepared: {})
    await local.triage_one(SimpleNamespace(run_agent=run_agent,
                                           resolve_location=resolve_location), FindingInput(
        title="Synthetic extraction", description=report, repo_url=str(tmp_path)),
        SimpleNamespace(snapshot=SimpleNamespace(path=str(tmp_path)), status="ready"))
    assert captured == [report]


def test_validation_version_is_part_of_both_effective_and_full_config():
    from infosec_harness.agents.intake_claims import WIRE_VERSION

    config = resolve_agent_config("intake", load_spec("intake"), durable=True)
    assert config.effective_spec["metadata"]["output_validation"] == {
        "version": "intake-evidence/v1", "wire_version": WIRE_VERSION
    }
    metadata = {**config.effective_spec["metadata"], "output_validation": {"version": "older"}}
    altered = config.model_copy(update={"effective_spec": {**config.effective_spec, "metadata": metadata}})
    assert config.digest != altered.digest and config.effective_digest != altered.effective_digest


def test_the_closed_diagnostics_are_distinct_codes_and_sentences():
    """Retry repair and retry classification branch on the code; the sentence is what the model
    sees. Both must be unique, or two rules would be indistinguishable downstream."""
    from infosec_harness.agents.intake_evidence import EVIDENCE_DIAGNOSTICS

    codes = [d.code for d in EVIDENCE_DIAGNOSTICS]
    messages = [d.message for d in EVIDENCE_DIAGNOSTICS]
    assert len(set(codes)) == len(codes) and len(set(messages)) == len(messages)


def test_every_emitted_violation_is_a_registered_diagnostic():
    from infosec_harness.agents.intake_evidence import (
        EVIDENCE_DIAGNOSTICS,
        extraction_evidence_diagnostics,
    )

    output = {"file_path": "missing.py", "start_line": 7, "evidence": [
        {"field": "file_path", "quote": REPORT.splitlines()[0], "confidence": 1.0},
        {"field": "start_line", "quote": REPORT.splitlines()[0], "confidence": 1.0},
        {"field": "nonsense", "quote": "", "confidence": 0.0},
    ]}
    found = extraction_evidence_diagnostics(REPORT, output)
    assert found and set(found) <= set(EVIDENCE_DIAGNOSTICS)
    assert extraction_evidence_diagnostics(None, output) == [EVIDENCE_DIAGNOSTICS[0]]
