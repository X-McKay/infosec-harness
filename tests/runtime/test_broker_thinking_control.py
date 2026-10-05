"""Constrained reasoning control preserves default identities and exact wire parity."""
from __future__ import annotations

import json
import time

import httpx2
import pytest
from pydantic import ValidationError
from pydantic_ai.messages import ModelRequest, UserPromptPart
from pydantic_ai.models import ModelRequestParameters
from pydantic_ai.tools import ToolDefinition
from test_broker_executor import request_fixture
from test_broker_profiles import _config

from infosec_harness.agents import models
from infosec_harness.inference.codec import encode_payload
from infosec_harness.inference.compat import input_wire
from infosec_harness.inference.executor import OpenAIInference
from infosec_harness.inference.profiles import BrokerConfig, ExecutorProfile
from infosec_harness.inference.protocol import BrokerError, digest


def test_omitted_thinking_preserves_existing_identities_and_explicit_values_change_them():
    request, _ = request_fixture()
    profile = BrokerConfig.model_validate(_config()).profiles['inference-only']
    for value in (request.contract, profile, models.CapabilityProfile(), models.BackendConfig(kind='openai_compatible')):
        original = value.model_dump(mode='json')
        assert 'enable_thinking' not in original
        assert value.model_copy(update={'enable_thinking': None}).model_dump(mode='json') == original
        for enabled in (False, True):
            assert value.model_copy(update={'enable_thinking': enabled}).model_dump(mode='json')['enable_thinking'] is enabled
    assert request.contract.model_copy(update={'enable_thinking': False}).digest != request.contract.digest
    assert profile.model_copy(update={'enable_thinking': False}).profile_digest != profile.profile_digest


@pytest.mark.parametrize('value', ['false', 0, 1, {}, []])
def test_thinking_setting_is_strict_boolean_everywhere(value):
    request, _ = request_fixture()
    for cls, data in ((models.BackendConfig, {'kind': 'openai_compatible'}),
                      (models.CapabilityProfile, {}), (ExecutorProfile, {}),
                      (type(request.contract), request.contract.model_dump(mode='json'))):
        with pytest.raises(ValidationError):
            cls.model_validate({**data, 'enable_thinking': value})


def test_thinking_rejects_non_openai_backend():
    with pytest.raises(ValidationError):
        models.BackendConfig(kind='bedrock', enable_thinking=False)


@pytest.mark.parametrize('enabled', [False, True])
def test_thinking_requires_exact_operator_profile_match(enabled):
    config = _config()
    config['profiles']['inference-only']['enable_thinking'] = enabled
    catalog = BrokerConfig.model_validate(config)
    for mismatched in (None, not enabled):
        with pytest.raises(ValueError):
            catalog.resolve_contract('recon', 'gateway', 'model', {'max_tokens': 16},
                backend_endpoint='https://provider.example/v1', enable_thinking=mismatched)
    contract = catalog.resolve_contract('recon', 'gateway', 'model', {'max_tokens': 16},
        backend_endpoint='https://provider.example/v1', enable_thinking=enabled)
    assert contract.enable_thinking is enabled


@pytest.mark.parametrize('parallel', [None, False, True])
@pytest.mark.parametrize('enabled', [None, False, True])
async def test_direct_executor_and_admission_match_constrained_thinking_wire(monkeypatch, enabled, parallel):
    import openai

    request, _ = request_fixture()
    settings = {**request.contract.model_settings}
    if parallel is not None:
        settings['parallel_tool_calls'] = parallel
    contract = request.contract.model_copy(update={'enable_thinking': enabled, 'model_settings': settings})
    messages = [ModelRequest(parts=[UserPromptPart('offline sample')])]
    schema = {'type': 'object', 'properties': {}, 'additionalProperties': False}
    params = ModelRequestParameters(function_tools=[ToolDefinition(name='read_files', parameters_json_schema=schema)],
        output_tools=[ToolDefinition(name='final_result', parameters_json_schema=schema, kind='output')])
    payload = encode_payload(messages, contract.model_settings, params)
    request = request.model_copy(update={'contract': contract, 'payload': payload,
        'payload_digest': digest(payload.model_dump(mode='json')), 'binding': request.binding.model_copy(
            update={'contract_digest': contract.digest, 'expires_at': time.time() + 60})})
    expected = await input_wire(payload, contract)
    captured = []
    def respond(native_request):
        captured.append(json.loads(native_request.content))
        return httpx2.Response(200, json={'id': 'offline', 'object': 'chat.completion', 'created': 1,
            'model': contract.model, 'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': 'ready'},
                'finish_reason': 'stop'}], 'usage': {'prompt_tokens': 3, 'completion_tokens': 2, 'total_tokens': 5}})
    await OpenAIInference(contract, 'openshell:resolve:env:MOCK_TOKEN',
        http_transport=httpx2.MockTransport(respond))(request)
    transport = httpx2.AsyncClient(transport=httpx2.MockTransport(respond))
    client_type = openai.AsyncOpenAI
    clients = []
    def client(**kwargs):
        result = client_type(**kwargs, http_client=transport)
        clients.append(result)
        return result
    cfg = models.ModelsConfig(backends={'thinking-offline': models.BackendConfig(
        kind='openai_compatible', base_url=contract.endpoint, enable_thinking=enabled,
        max_retries=0, max_retries_under_temporal=0)}, default_backend='thinking-offline', model_catalog={})
    monkeypatch.setattr(models, 'load_models_config', lambda: cfg)
    monkeypatch.setattr(openai, 'AsyncOpenAI', client)
    try:
        direct = models._build_live('thinking-offline', contract.model)
        await direct.request(messages, contract.model_settings, params)
    finally:
        models._build_live.cache_clear()
        for instance in clients:
            await instance.close()
        await transport.aclose()
    assert len(captured) == 2
    for body in captured:
        assert body['messages'] == expected['messages']
        assert body['tools'] == expected['tools']
        if parallel is None:
            assert 'parallel_tool_calls' not in body
        else:
            assert body['parallel_tool_calls'] is parallel
        if enabled is None:
            assert 'chat_template_kwargs' not in body
        else:
            assert body['chat_template_kwargs'] == expected['extra_body']['chat_template_kwargs'] == {'enable_thinking': enabled}
        assert body['max_completion_tokens'] == contract.model_settings['max_tokens']
    assert payload.model_settings == contract.model_settings


def test_caller_cannot_supply_arbitrary_extra_body():
    for settings in ({'extra_body': {'chat_template_kwargs': {'enable_thinking': False}}},
                     {'extra_body': {'model': 'other'}}, {'extra_headers': {'Authorization': 'injected'}}):
        with pytest.raises(BrokerError, match='Unsupported model settings'):
            encode_payload([ModelRequest(parts=[UserPromptPart('offline')])], settings, ModelRequestParameters())


@pytest.mark.parametrize('setting', ['extra_body', 'extra_headers'])
def test_typed_thinking_rejects_authored_overrides_without_mutating_settings(setting):
    from copy import deepcopy

    from pydantic_ai.providers.openai import OpenAIProvider

    from infosec_harness.inference.compat import CompatOpenAIChatModel

    model = CompatOpenAIChatModel('offline',
        provider=OpenAIProvider(api_key='offline', base_url='https://provider.invalid/v1'), enable_thinking=False)
    settings = {setting: {'unexpected': 'value'}, 'max_tokens': 16}
    before = deepcopy(settings)
    with pytest.raises(BrokerError, match='request overrides'):
        model.prepare_request(settings, ModelRequestParameters())
    assert settings == before


def thinking_baseline(tmp_path, monkeypatch):
    from copy import deepcopy

    from broker_real_provider_fixture import CASES, COMPARISON_MODEL_FIELDS

    old = {'model': dict.fromkeys(COMPARISON_MODEL_FIELDS, 'frozen'),
           'budget': {'requested': {'max_requests': 4}, 'effective': {'max_input_tokens': 20000}}}
    old['model'].update(backend_name='gateway', resolved_model='gateway:Qwen3.6-35B-A3B-NVFP4',
        capability_profile={'tool_calling': True}, pricing_table='sdk:1:abc;models:old;backend:gateway;custom:zero')
    rows = [{'agent': name, 'case': case, 'case_digest': 'a' * 64, 'config': deepcopy(old)} for name, case in CASES.items()]
    path = tmp_path / 'baseline.json'
    path.write_text(json.dumps({'phase': 'direct', 'status': 'passed', 'cases': rows}))
    monkeypatch.setenv('HARNESS_REAL_PROVIDER_BASELINE', str(path))
    candidate = deepcopy(old)
    candidate['model'].update(backend_name='gateway-intake', resolved_model='gateway-intake:Qwen3.6-35B-A3B-NVFP4',
        capability_profile={'tool_calling': True, 'strict_closed_output_tools': True, 'enable_thinking': False},
        pricing_table='sdk:1:abc;models:new;backend:gateway-intake;custom:zero', broker_contract={
            'strict_closed_output_tools': True, 'enable_thinking': False, 'backend': 'gateway-intake',
            'model': 'Qwen3.6-35B-A3B-NVFP4'})
    return candidate


def test_intake_diagnostic_declares_only_reasoning_and_fixed_routing_difference(tmp_path, monkeypatch):
    from copy import deepcopy

    from broker_real_provider_fixture import compare_baseline
    from broker_thinking_diagnostic_fixture import compare_intake_nonthinking

    candidate = thinking_baseline(tmp_path, monkeypatch)
    before = deepcopy(candidate)
    with pytest.raises(ValueError):
        compare_baseline('intake', candidate, 'a' * 64, reviewed_strict_closed_output_tools=True)
    result = compare_intake_nonthinking(candidate, 'a' * 64)
    assert result['status'] == 'passed'
    assert result['declared_reasoning_difference']['enable_thinking'] == {'baseline': None, 'candidate': False}
    assert result['declared_reasoning_difference']['qualification_status'] == 'not_checked'
    assert result['intentional_transport_fields']['capability_profile']['enable_thinking'] is False
    assert candidate == before


@pytest.mark.parametrize('field', ['budget', 'settings', 'price', 'model', 'backend', 'thinking', 'contract'])
def test_intake_diagnostic_rejects_undeclared_drift(tmp_path, monkeypatch, field):
    from broker_thinking_diagnostic_fixture import compare_intake_nonthinking

    candidate = thinking_baseline(tmp_path, monkeypatch)
    if field == 'budget':
        candidate['budget']['effective']['max_input_tokens'] = 30000
    elif field == 'settings':
        candidate['model']['effective_settings'] = {'temperature': .7}
    elif field == 'price':
        candidate['model']['pricing_table'] = candidate['model']['pricing_table'].replace('custom:zero', 'custom:other')
    elif field == 'model':
        candidate['model']['resolved_model'] = 'gateway-intake:other'
    elif field == 'backend':
        candidate['model']['backend_name'] = 'other'
    elif field == 'thinking':
        candidate['model']['capability_profile']['enable_thinking'] = True
    else:
        candidate['model']['broker_contract']['enable_thinking'] = None
    with pytest.raises(ValueError):
        compare_intake_nonthinking(candidate, 'a' * 64)
