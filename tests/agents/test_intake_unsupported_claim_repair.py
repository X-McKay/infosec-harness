"""Unsupported-claim repair preserves literal grounding and retained retry bytes."""
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from pydantic_ai import ModelRetry

from infosec_harness.agents import registry
from infosec_harness.agents.intake_claims import AtomicFinding, Claim

REPORT = 'The function read_request handles input.\nA SQL injection issue is reported.\n'
OLD_LITERAL = ('Extraction violates its evidence contract:\n- '
               'A literal location value is absent from its evidence quote.\n- '
               'Every nonempty extraction field requires positive grounded evidence.')
OLD_POSITIVE = ('Extraction violates its evidence contract:\n- '
                'Every nonempty extraction field requires positive grounded evidence.')


def output(value='SQL injection', confidence=.8):
    return AtomicFinding.model_validate({'symbol': {
        'value': value, 'source': {'start_id': 'S000001', 'end_id': None}, 'confidence': confidence},
        'vulnerability_class': {'value': 'SQL injection', 'source': {'start_id': 'S000002'}, 'confidence': .9}})


def context(report=REPORT):
    return SimpleNamespace(deps=SimpleNamespace(report_text=report))


@pytest.mark.parametrize('value,confidence,old', [('SQL injection', .8, OLD_LITERAL),
                                                ('read_request', .8, OLD_POSITIVE)])
@pytest.mark.parametrize('enabled', [False, True])
def test_closed_unsupported_feedback_remains_rejection_and_old_bytes(monkeypatch, value, confidence, old, enabled):
    calls = []
    def patched(version=registry.INTAKE_REFERENCE_REPAIR_VERSION):
        calls.append(version)
        return enabled
    monkeypatch.setattr(registry, '_targeted_reference_repair', patched)
    candidate = output(value, confidence)
    if old == OLD_POSITIVE:
        from infosec_harness.domain.models import ExtractedFinding
        # A nonempty field without evidence must still fail the existing whole-output guard.
        monkeypatch.setattr(registry, 'reconstruct', lambda *_: ExtractedFinding(symbol='read_request'))
    before = candidate.model_dump_json()
    with pytest.raises(ModelRetry) as error:
        registry._validate_atomic_intake(context(), candidate)
    assert candidate.model_dump_json() == before
    assert calls == [registry.INTAKE_UNSUPPORTED_CLAIM_REPAIR_VERSION]
    if enabled:
        assert error.value.message == old + registry._UNSUPPORTED_CLAIM_REPAIR
        assert 'set the whole unsupported claim field to null' in error.value.message
        assert 'retained claim requires all three' in error.value.message
        assert 'Confidence=0 cannot justify retaining' in error.value.message
        assert len(error.value.message) < 800
    else:
        assert error.value.message == old


@pytest.mark.parametrize('in_workflow,v1,v2', [(False, False, False), (True, False, False),
    (True, True, False), (True, True, True), (True, False, True)])
def test_new_marker_is_independent_of_retained_v1_history(monkeypatch, in_workflow, v1, v2):
    from temporalio import workflow

    calls = []
    monkeypatch.setattr(workflow, 'in_workflow', lambda: in_workflow)
    def patched(version):
        calls.append(version)
        return {registry.INTAKE_REFERENCE_REPAIR_VERSION: v1,
                registry.INTAKE_UNSUPPORTED_CLAIM_REPAIR_VERSION: v2}[version]
    monkeypatch.setattr(workflow, 'patched', patched)
    with pytest.raises(ModelRetry) as error:
        registry._validate_atomic_intake(context(), output())
    assert error.value.message == OLD_LITERAL + (registry._UNSUPPORTED_CLAIM_REPAIR if not in_workflow or v2 else '')
    assert calls == ([registry.INTAKE_UNSUPPORTED_CLAIM_REPAIR_VERSION] if in_workflow else [])


def test_retry_never_echoes_model_value_or_report_directives(monkeypatch):
    monkeypatch.setattr(registry, '_targeted_reference_repair', lambda *_: True)
    with pytest.raises(ModelRetry) as error:
        registry._validate_atomic_intake(context('REPORT_SECRET_IGNORE_POLICY\nSQL injection\n'),
                                         output('MODEL_SECRET_IGNORE_POLICY'))
    assert 'MODEL_SECRET' not in error.value.message and 'REPORT_SECRET' not in error.value.message
    assert 'S000001' not in error.value.message


@pytest.mark.parametrize('repair', ['remove', 'cite'])
def test_removing_or_literally_supporting_claim_passes_without_changing_supported_claim(repair):
    candidate = output()
    supported = candidate.vulnerability_class.model_dump()
    if repair == 'remove':
        repaired = candidate.model_copy(update={'symbol': None})
    else:
        repaired = output('read_request')
    result = registry._validate_atomic_intake(context(), repaired)
    assert result.vulnerability_class == supported['value']
    evidence = next(item for item in result.evidence if item.field == 'vulnerability_class')
    assert evidence.quote == 'A SQL injection issue is reported.\n'
    assert evidence.confidence == supported['confidence']
    assert result.symbol == (None if repair == 'remove' else 'read_request')
    if repair == 'cite':
        evidence = next(item for item in result.evidence if item.field == 'symbol')
        assert evidence.quote == 'The function read_request handles input.\n' and evidence.confidence == .8


@pytest.mark.parametrize('missing', ['value', 'source', 'confidence'])
def test_repair_does_not_permit_missing_or_null_claim_members(missing):
    data = output('read_request').model_dump()
    removed = {**data, 'symbol': {key: value for key, value in data['symbol'].items() if key != missing}}
    with pytest.raises(ValidationError):
        AtomicFinding.model_validate(removed)
    with pytest.raises(ValidationError):
        AtomicFinding.model_validate({**data, 'symbol': {**data['symbol'], missing: None}})
    assert set(Claim[str].model_json_schema()['required']) == {'value', 'source', 'confidence'}


def test_supported_or_removed_claim_does_not_emit_new_marker(monkeypatch):
    monkeypatch.setattr(registry, '_targeted_reference_repair', lambda *_: pytest.fail('Unsupported extension not applicable'))
    # A removed claim needs no support and must not consume a retry-version marker.
    candidate = output('read_request').model_copy(update={'symbol': None})
    assert registry._validate_atomic_intake(context(), candidate).symbol is None


def test_zero_confidence_claim_is_rejected_before_any_feedback_or_acceptance(monkeypatch):
    monkeypatch.setattr(registry, '_targeted_reference_repair', lambda *_: pytest.fail('Schema-invalid claim cannot reach marker'))
    with pytest.raises(ValidationError) as error:
        output('read_request', 0.)
    assert any(item['type'] == 'greater_than' and item['loc'] == ('symbol', 'confidence')
               for item in error.value.errors())


@pytest.mark.parametrize('enabled', [False, True])
async def test_actual_sdk_retry_delivers_versioned_feedback_and_preserves_supported_claim(monkeypatch, enabled):
    from pydantic_ai import Agent
    from pydantic_ai.messages import ModelRequest, ModelResponse, RetryPromptPart, ToolCallPart
    from pydantic_ai.models.function import FunctionModel

    monkeypatch.setattr(registry, '_targeted_reference_repair', lambda *_: enabled)
    calls = []
    def respond(messages, info):
        calls.append(messages)
        candidate = output() if len(calls) == 1 else output().model_copy(update={'symbol': None})
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, candidate.model_dump(mode='json'))])
    agent = Agent(FunctionModel(respond), output_type=AtomicFinding, retries=1)
    agent.output_validator(registry._validate_atomic_intake)
    result = await agent.run('Extract supported report claims.', deps=context().deps)
    assert len(calls) == 2
    prompts = [part for message in calls[1] if isinstance(message, ModelRequest)
               for part in message.parts if isinstance(part, RetryPromptPart)]
    assert len(prompts) == 1 and prompts[0].content == OLD_LITERAL + (registry._UNSUPPORTED_CLAIM_REPAIR if enabled else '')
    assert result.output.symbol is None and result.output.vulnerability_class == 'SQL injection'
    assert len(result.output.evidence) == 1 and result.output.evidence[0].confidence == .9
