"""Aggregate repair reveals all rejected references; acceptance and old bytes stay exact."""

from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from pydantic_ai import ModelRetry

from infosec_harness.agents import registry
from infosec_harness.agents.intake_claims import AtomicFinding, invalid_source_references

REPORT = "CWE-89\nSQL injection\n"


def claims():
    return AtomicFinding.model_validate(
        {
            "cwe": {
                "value": "CWE-89",
                "source": {"start_id": "S000002", "end_id": "S000001"},
                "confidence": 0.8,
            },
            "vulnerability_class": {
                "value": "SQL injection",
                "source": {"start_id": "S000002", "end_id": "S000001"},
                "confidence": 0.9,
            },
        }
    )


def ctx(report=REPORT):
    return SimpleNamespace(deps=SimpleNamespace(report_text=report))


def test_collects_both_failures_before_materialization_and_never_changes_claims(monkeypatch):
    output = claims()
    before = output.model_dump_json()
    monkeypatch.setattr(registry, "_targeted_reference_repair", lambda *_: True)
    with pytest.raises(ModelRetry) as e:
        registry._validate_atomic_intake(ctx(), output)
    assert "cwe=reversed_source_range, vulnerability_class=reversed_source_range" in e.value.message
    assert len(e.value.message) < 600
    assert output.model_dump_json() == before
    assert "S000002" not in e.value.message and "CWE-89" not in e.value.message
    for field in ("cwe", "vulnerability_class"):
        getattr(output, field).source.end_id = getattr(output, field).source.start_id
    # Supply each literal supporting line; no policy acceptance changes.
    output.cwe.source.start_id = output.cwe.source.end_id = "S000001"
    finding = registry._validate_atomic_intake(ctx(), output)
    assert finding.cwe == "CWE-89" and finding.vulnerability_class == "SQL injection"
    assert [e.confidence for e in finding.evidence] == [0.8, 0.9]


@pytest.mark.parametrize("old_enabled", [False, True])
def test_absent_aggregate_marker_preserves_exact_old_feedback_and_old_marker(
    monkeypatch, old_enabled
):
    calls = []

    def patched(version=registry.INTAKE_REFERENCE_REPAIR_VERSION):
        calls.append(version)
        return old_enabled if version == registry.INTAKE_REFERENCE_REPAIR_VERSION else False

    monkeypatch.setattr(registry, "_targeted_reference_repair", patched)
    with pytest.raises(ModelRetry) as e:
        registry._validate_atomic_intake(ctx(), claims())
    old = "Extraction violates its evidence contract:\n- Source reference violates its contract: reversed_source_range"
    extension = (
        ". Fix only the source reference for claim 'cwe': "
        "end_id must be at or after start_id in report source-line order. "
        "For a single source line, use end_id=null or end_id=start_id. "
        "Keep the supported claim value and confidence unchanged."
    )
    assert e.value.message == old + (extension if old_enabled else "")
    assert calls == [
        registry.INTAKE_AGGREGATE_REFERENCE_REPAIR_VERSION,
        registry.INTAKE_REFERENCE_REPAIR_VERSION,
    ]


def test_single_invalid_keeps_current_bytes_without_new_marker(monkeypatch):
    output = claims()
    output.cwe = None
    calls = []

    def patched(version=registry.INTAKE_REFERENCE_REPAIR_VERSION):
        calls.append(version)
        return True

    monkeypatch.setattr(registry, "_targeted_reference_repair", patched)
    with pytest.raises(ModelRetry) as e:
        registry._validate_atomic_intake(ctx(), output)
    assert "claim 'vulnerability_class'" in e.value.message
    assert calls == [registry.INTAKE_REFERENCE_REPAIR_VERSION]


def test_all_eight_errors_are_bounded_closed_and_unknown_ids_not_echoed(monkeypatch):
    data = {}
    for name in AtomicFinding.model_fields:
        value = (
            1
            if name in {"start_line", "end_line"}
            else ["SECRET"]
            if name == "attack_preconditions"
            else "SECRET"
        )
        data[name] = {"value": value, "source": {"start_id": "SECRET_ID"}, "confidence": 0.8}
    output = AtomicFinding.model_validate(data)
    assert invalid_source_references(REPORT, output) == tuple(
        (name, "unknown_source_id") for name in AtomicFinding.model_fields
    )
    monkeypatch.setattr(registry, "_targeted_reference_repair", lambda *_: True)
    with pytest.raises(ModelRetry) as e:
        registry._validate_atomic_intake(ctx("REPORT_SECRET\n"), output)
    assert len(e.value.message) < 800
    assert "SECRET" not in e.value.message


def test_empty_end_id_remains_invalid_not_reinterpreted_as_single_line():
    output = claims()
    output.cwe.source.end_id = ""
    assert invalid_source_references(REPORT, output)[0] == ("cwe", "unknown_source_id")


def test_missing_source_keeps_old_error_without_marker(monkeypatch):
    monkeypatch.setattr(
        registry,
        "_targeted_reference_repair",
        lambda *_: pytest.fail("no marker for unavailable source"),
    )
    with pytest.raises(ModelRetry) as e:
        registry._validate_atomic_intake(ctx(None), claims())
    assert (
        e.value.message
        == "Extraction violates its evidence contract:\n- Source reference violates its contract: source_unavailable"
    )


def test_blank_or_unsupported_symbol_is_not_accepted(monkeypatch):
    monkeypatch.setattr(registry, "_targeted_reference_repair", lambda *_: True)
    output = claims()
    output.cwe.source.end_id = "S000002"
    output.vulnerability_class.source.end_id = "S000002"
    from infosec_harness.agents.intake_claims import Claim

    output.symbol = Claim[str](value="not_present", source={"start_id": "S000001"}, confidence=0.8)
    with pytest.raises(ModelRetry, match="literal location"):
        registry._validate_atomic_intake(ctx(), output)
    data = output.model_dump()
    data["symbol"]["value"] = ""
    with pytest.raises(ValidationError):
        AtomicFinding.model_validate(data)


@pytest.mark.parametrize("in_workflow,enabled", [(False, False), (True, False), (True, True)])
def test_aggregate_has_independent_durable_marker(monkeypatch, in_workflow, enabled):
    from temporalio import workflow

    calls = []
    monkeypatch.setattr(workflow, "in_workflow", lambda: in_workflow)

    def patched(version):
        calls.append(version)
        return enabled

    monkeypatch.setattr(workflow, "patched", patched)
    with pytest.raises(ModelRetry) as e:
        registry._validate_atomic_intake(ctx(), claims())
    assert ("cwe=reversed_source_range" in e.value.message) == (not in_workflow or enabled)
    assert calls == (
        []
        if not in_workflow
        else [registry.INTAKE_AGGREGATE_REFERENCE_REPAIR_VERSION]
        + ([] if enabled else [registry.INTAKE_REFERENCE_REPAIR_VERSION])
    )


def test_mixed_rules_collect_authored_fields_without_changing_first_error():
    output = claims()
    output.cwe.source.start_id = "unknown_SECRET"
    assert invalid_source_references(REPORT, output) == (
        ("cwe", "unknown_source_id"),
        ("vulnerability_class", "reversed_source_range"),
    )


async def test_actual_sdk_gets_both_fields_in_one_bounded_retry(monkeypatch):
    from pydantic_ai import Agent
    from pydantic_ai.messages import ModelRequest, ModelResponse, RetryPromptPart, ToolCallPart
    from pydantic_ai.models.function import FunctionModel

    monkeypatch.setattr(registry, "_targeted_reference_repair", lambda *_: True)
    calls = []

    def respond(messages, info):
        calls.append(messages)
        output = claims()
        if len(calls) == 2:
            output.cwe.source.start_id = output.cwe.source.end_id = "S000001"
            output.vulnerability_class.source.end_id = "S000002"
        return ModelResponse(
            parts=[ToolCallPart(info.output_tools[0].name, output.model_dump(mode="json"))]
        )

    agent = Agent(FunctionModel(respond), output_type=AtomicFinding, retries=1)
    agent.output_validator(registry._validate_atomic_intake)
    result = await agent.run("Extract supported fields.", deps=ctx().deps)
    retries = [
        p
        for m in calls[-1]
        if isinstance(m, ModelRequest)
        for p in m.parts
        if isinstance(p, RetryPromptPart)
    ]
    assert len(retries) == 1
    assert (
        "cwe=reversed_source_range, vulnerability_class=reversed_source_range" in retries[0].content
    )
    assert result.usage.requests == 2
    assert result.output.cwe == "CWE-89" and result.output.vulnerability_class == "SQL injection"
    assert [e.confidence for e in result.output.evidence] == [0.8, 0.9]
