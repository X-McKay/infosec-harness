"""Source order and literal code-line grounding remain acceptance boundaries."""
from types import SimpleNamespace

import pytest
from pydantic_ai import ModelRetry

from infosec_harness.agents import registry
from infosec_harness.agents.durable import INTAKE_GENERATIONS
from infosec_harness.agents.intake_claims import AtomicFinding, ReferenceError, reconstruct
from infosec_harness.agents.intake_contracts import atomic_intake_spec, retained_atomic_intake_spec
from infosec_harness.workflows.temporal_ops import TemporalOps

REPORT = "SQL injection in a database query.\nThe query accepts user input.\n"


def ctx(report=REPORT):
    return SimpleNamespace(deps=SimpleNamespace(report_text=report))


def claim(field, value, start="S000001", end=None):
    return {field: {"value": value, "source": {"start_id": start, "end_id": end}, "confidence": .9}}


def test_source_range_order_and_single_line_are_not_code_line_evidence():
    reversed_claim = AtomicFinding.model_validate(claim("vulnerability_class", "SQL injection", "S000002", "S000001"))
    with pytest.raises(ReferenceError) as error:
        reconstruct(REPORT, reversed_claim)
    assert error.value.rule == "reversed_source_range"
    ascending = AtomicFinding.model_validate(claim("vulnerability_class", "SQL injection", "S000001", "S000002"))
    result = registry._validate_atomic_intake(ctx(), ascending)
    assert result.evidence[0].quote == REPORT
    single = AtomicFinding.model_validate(claim("vulnerability_class", "SQL injection"))
    assert registry._validate_atomic_intake(ctx(), single).evidence[0].quote == REPORT.splitlines(keepends=True)[0]


@pytest.mark.parametrize("field", ["start_line", "end_line"])
@pytest.mark.parametrize("new_feedback", [False, True])
@pytest.mark.parametrize("old_feedback", [False, True])
def test_missing_literal_code_line_stays_rejected_with_versioned_static_feedback(monkeypatch, field, new_feedback, old_feedback):
    from temporalio import workflow

    calls = []
    monkeypatch.setattr(workflow, "in_workflow", lambda: True)
    def patched(marker):
        calls.append(marker)
        return (marker == registry.INTAKE_LITERAL_LINE_REPAIR_VERSION and new_feedback) or (
            marker == registry.INTAKE_UNSUPPORTED_CLAIM_REPAIR_VERSION and old_feedback)
    monkeypatch.setattr(workflow, "patched", patched)
    output = AtomicFinding.model_validate({**claim(field, 1), **claim("vulnerability_class", "SQL injection")})
    before = output.model_dump_json()
    with pytest.raises(ModelRetry) as error:
        registry._validate_atomic_intake(ctx(), output)
    old = ("Extraction violates its evidence contract:\n- A literal line number is absent from its evidence quote."
           "\n- Every nonempty extraction field requires positive grounded evidence.")
    assert error.value.message == old + (registry._INTAKE_LITERAL_LINE_REPAIR if new_feedback else registry._UNSUPPORTED_CLAIM_REPAIR if old_feedback else "")
    assert calls == [registry.INTAKE_LITERAL_LINE_REPAIR_VERSION] + ([] if new_feedback else [registry.INTAKE_UNSUPPORTED_CLAIM_REPAIR_VERSION])
    assert output.model_dump_json() == before
    assert "S000001" not in error.value.message and REPORT not in error.value.message
    repaired = output.model_copy(update={field: None})
    assert registry._validate_atomic_intake(ctx(), repaired).vulnerability_class == "SQL injection"


@pytest.mark.parametrize("field", ["start_line", "end_line"])
def test_literal_code_line_passes_and_does_not_consume_new_marker(monkeypatch, field):
    monkeypatch.setattr(registry, "_targeted_reference_repair", lambda *_: pytest.fail("Valid claim needs no repair marker"))
    output = AtomicFinding.model_validate(claim(field, 42))
    assert getattr(registry._validate_atomic_intake(ctx("The vulnerable code is at line 42.\n"), output), field) == 42


@pytest.mark.parametrize("enabled", [False, True])
def test_atomic_selector_keeps_recorded_agent_prompt_and_reservation_generation(enabled):
    ops = TemporalOps(intake_atomic_inline=True, intake_source_guidance=enabled)
    generation = INTAKE_GENERATIONS["atomic" if enabled else "atomic_v3"]
    assert ops._agent_for("intake") is generation.agent
    assert ops._config_for("intake") is generation.config
    assert generation.agent.name == ("intake-output-v4" if enabled else "intake-output-v3")
    spec = atomic_intake_spec() if enabled else retained_atomic_intake_spec()
    assert generation.config.effective_spec["metadata"]["version"] == spec.metadata["version"]
    assert spec.metadata["budgets"]["max_input_tokens_per_request"] == (32000 if enabled else 20000)
    assert spec.metadata["budgets"]["max_input_tokens"] == (128000 if enabled else 80000)
    assert spec.metadata["budgets"]["max_requests"] == 4
    assert spec.metadata["budgets"]["max_output_tokens"] == 64000


def test_retained_v3_spec_bytes_match_original_generation():
    import hashlib

    from infosec_harness.resources import package_root

    retained = package_root() / "agents" / "intake" / "agent-v1.0.3.yaml"
    assert hashlib.sha256(retained.read_bytes()).hexdigest() == "dbabcbc640b87ea9b63686baf82f01452e7c96875c511de55a68bf5a9977388e"


async def test_sdk_receives_literal_line_feedback_then_accepts_null_whole_claim():
    from pydantic_ai import Agent
    from pydantic_ai.messages import ModelRequest, ModelResponse, RetryPromptPart, ToolCallPart
    from pydantic_ai.models.function import FunctionModel

    messages_seen = []
    def respond(messages, info):
        messages_seen.append(messages)
        data = claim("vulnerability_class", "SQL injection")
        if len(messages_seen) == 1:
            data.update(claim("start_line", 1))
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, data, "synthetic-output")])
    agent = Agent(FunctionModel(respond), output_type=AtomicFinding, retries=1)
    agent.output_validator(registry._validate_atomic_intake)
    result = await agent.run("Extract grounded fields.", deps=ctx().deps)
    assert result.output.start_line is None and result.output.vulnerability_class == "SQL injection"
    retries = [p for m in messages_seen[-1] if isinstance(m, ModelRequest)
               for p in m.parts if isinstance(p, RetryPromptPart)]
    assert len(retries) == 1
    assert retries[0].content.endswith(registry._INTAKE_LITERAL_LINE_REPAIR)
    assert result.usage.requests == 2
