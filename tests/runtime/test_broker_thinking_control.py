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
from test_broker_profiles import _config, backend

from infosec_harness.agents import models
from infosec_harness.inference.catalog.profiles import BrokerConfig, ExecutorProfile
from infosec_harness.inference.executor.rendering import input_wire
from infosec_harness.inference.executor.service import OpenAIInference
from infosec_harness.inference.wire.codec import encode_payload
from infosec_harness.inference.wire.protocol import BrokerError, digest


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
                backend=backend(enable_thinking=mismatched))
    contract = catalog.resolve_contract('recon', 'gateway', 'model', {'max_tokens': 16},
        backend=backend(enable_thinking=enabled))
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
        direct = models._build_live('thinking-offline', contract.model, False, False)
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

    from infosec_harness.inference.executor.compat import CompatOpenAIChatModel

    model = CompatOpenAIChatModel('offline',
        provider=OpenAIProvider(api_key='offline', base_url='https://provider.invalid/v1'), enable_thinking=False)
    settings = {setting: {'unexpected': 'value'}, 'max_tokens': 16}
    before = deepcopy(settings)
    with pytest.raises(BrokerError, match='request overrides'):
        model.prepare_request(settings, ModelRequestParameters())
    assert settings == before


