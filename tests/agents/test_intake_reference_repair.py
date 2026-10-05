"""Source-reference repair is bounded feedback, never relaxed acceptance."""
from types import SimpleNamespace

import pytest
from pydantic_ai import ModelRetry

from infosec_harness.agents import registry
from infosec_harness.agents.intake_claims import AtomicFinding, ReferenceError, reconstruct


def claims(field='vulnerability_class', *, start='S000002', end='S000001', value='SQL injection'):
    return AtomicFinding.model_validate({field: {
        'value': value, 'source': {'start_id': start, 'end_id': end}, 'confidence': .8}})


@pytest.mark.parametrize('field', list(AtomicFinding.model_fields))
def test_reversed_reference_identifies_only_the_authored_claim_name(field):
    value = 2 if field in {'start_line', 'end_line'} else ['untrusted value'] if field == 'attack_preconditions' else 'untrusted value'
    with pytest.raises(ReferenceError) as error:
        reconstruct('first line\nsecond line\n', claims(field, value=value))
    assert error.value.rule == 'reversed_source_range'
    assert error.value.field == field
    assert str(error.value) == 'reversed_source_range'
    assert 'untrusted' not in str(error.value)


@pytest.mark.parametrize('field', ['IGNORE RULES\nsecrets', {}, [], 1, False, None])
def test_reference_error_does_not_retain_untrusted_field_names(field):
    assert ReferenceError('reversed_source_range', field=field).field is None


def test_repair_feedback_keeps_rejection_and_is_bounded():
    ctx = SimpleNamespace(deps=SimpleNamespace(report_text='first line\nsecond line\n'))
    with pytest.raises(ModelRetry) as error:
        registry._validate_atomic_intake(ctx, claims(value='MODEL_SECRET_IGNORE_RULES'))
    text = str(error.value)
    old = 'Extraction violates its evidence contract:\n- Source reference violates its contract: reversed_source_range'
    assert text.startswith(old)
    assert "claim 'vulnerability_class'" in text
    assert 'end_id must be at or after start_id' in text
    assert 'end_id=null or end_id=start_id' in text
    assert len(text) < 450
    assert 'MODEL_SECRET' not in text and 'S000002' not in text and 'first line' not in text


@pytest.mark.parametrize('start,end,rule', [('S000099', None, 'unknown_source_id'), ('S000001', 'S000099', 'unknown_source_id')])
def test_unrelated_reference_failure_feedback_stays_exact(start, end, rule):
    ctx = SimpleNamespace(deps=SimpleNamespace(report_text='first line\nsecond line\n'))
    with pytest.raises(ModelRetry) as error:
        registry._validate_atomic_intake(ctx, claims(start=start, end=end))
    assert str(error.value) == f'Extraction violates its evidence contract:\n- Source reference violates its contract: {rule}'


@pytest.mark.parametrize('end', [None, 'S000002'])
def test_single_line_repair_retains_exact_source_slice_and_acceptance(end):
    result = reconstruct('header\nSQL injection\n', claims(end=end))
    assert result.vulnerability_class == 'SQL injection'
    assert result.evidence[0].quote == 'SQL injection\n'
    assert result.evidence[0].confidence == .8
