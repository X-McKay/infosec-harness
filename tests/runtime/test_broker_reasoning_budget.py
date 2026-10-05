"""Offline authorization and actual SDK wire checks for typed reasoning budgets."""
from __future__ import annotations

import json
import time
from copy import deepcopy
from types import SimpleNamespace

import httpx2
import pytest
from pydantic import ValidationError
from pydantic_ai.messages import ModelRequest, UserPromptPart
from pydantic_ai.models import ModelRequestParameters
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.tools import ToolDefinition
from test_broker_executor import request_fixture
from test_broker_profiles import _config, backend

from infosec_harness.agents import models
from infosec_harness.inference.auth import AUTH_HEADER, sign_request
from infosec_harness.inference.codec import encode_payload
from infosec_harness.inference.compat import CompatOpenAIChatModel
from infosec_harness.inference.executor import Executor, OpenAIInference
from infosec_harness.inference.profiles import BrokerConfig, ExecutorProfile
from infosec_harness.inference.protocol import BrokerError, canonical_bytes, digest
from infosec_harness.inference.rendering import input_wire


def test_omitted_reasoning_budget_preserves_historical_payloads_and_identities():
    request, _ = request_fixture()
    profile = BrokerConfig.model_validate(_config()).profiles['inference-only']
    # Measured from the unchanged source1579 fixtures, before this optional field existed.
    assert request.contract.digest == '0a982b92b7545b6350977f3c11217de0cb1f7d7c8a60528248400f4e12e31867'
    assert profile.profile_digest == 'bcbf9745a0f0b211cba9b4956763ac2cb8c770e7b057eed883b7a5b6e9816292'
    assert digest(models.CapabilityProfile().model_dump(mode='json')) == 'e3fb71d55c84e3160dcd2211ca552d1887fc5233d791388ada0e98de649fc343'
    for value in (request.contract, profile, models.CapabilityProfile(),
                  models.BackendConfig(kind='openai_compatible')):
        old = value.model_dump(mode='json')
        assert 'thinking_token_budget' not in old
        assert type(value).model_validate_json(json.dumps(old)).model_dump(mode='json') == old
        assert value.model_copy(update={'thinking_token_budget': None}).model_dump(mode='json') == old
    assert request.contract.model_copy(update={'thinking_token_budget': 8}).digest != request.contract.digest
    assert profile.model_copy(update={'thinking_token_budget': 8}).profile_digest != profile.profile_digest


@pytest.mark.parametrize('value', [True, False, 0, -1, 1.0, '8', {}, []])
def test_reasoning_budget_requires_a_strict_positive_integer(value):
    request, _ = request_fixture()
    for cls, data in ((models.BackendConfig, {'kind': 'openai_compatible'}),
                      (models.CapabilityProfile, {}), (ExecutorProfile, {}),
                      (type(request.contract), request.contract.model_dump(mode='json'))):
        with pytest.raises(ValidationError):
            cls.model_validate({**data, 'thinking_token_budget': value})


def test_reasoning_budget_rejects_bedrock_and_disabled_thinking():
    with pytest.raises(ValidationError):
        models.BackendConfig(kind='bedrock', thinking_token_budget=8)
    request, _ = request_fixture()
    for cls, data in ((models.BackendConfig, {'kind': 'openai_compatible'}),
                      (models.CapabilityProfile, {}), (ExecutorProfile, {}),
                      (type(request.contract), request.contract.model_dump(mode='json'))):
        with pytest.raises(ValidationError):
            cls.model_validate({**data, 'enable_thinking': False, 'thinking_token_budget': 8})


@pytest.mark.parametrize('cap', [16, 17])
def test_reasoning_budget_reserves_space_for_final_output(cap):
    request, _ = request_fixture()
    with pytest.raises(ValidationError):
        type(request.contract).model_validate({**request.contract.model_dump(mode='json'),
                                              'thinking_token_budget': cap})
    model = CompatOpenAIChatModel('offline', provider=OpenAIProvider(
        api_key='offline', base_url='https://provider.invalid/v1'), thinking_token_budget=cap)
    with pytest.raises((BrokerError, ValueError)):
        model.prepare_request({'max_tokens': 16}, ModelRequestParameters())


def test_reasoning_budget_is_below_the_effective_floored_total_without_mutation():
    model = CompatOpenAIChatModel('offline', provider=OpenAIProvider(
        api_key='offline', base_url='https://provider.invalid/v1'),
        thinking_token_budget=8, min_max_tokens=16)
    authored = {'max_tokens': 4}
    shaped, _ = model.prepare_request(authored, ModelRequestParameters())
    assert shaped['max_tokens'] == 16
    assert shaped['extra_body'] == {'thinking_token_budget': 8}
    assert authored == {'max_tokens': 4}


def test_reasoning_budget_requires_a_known_total_before_provider_dispatch():
    model = CompatOpenAIChatModel('offline', provider=OpenAIProvider(
        api_key='offline', base_url='https://provider.invalid/v1'), thinking_token_budget=8)
    with pytest.raises((BrokerError, ValueError)):
        model.prepare_request(None, ModelRequestParameters())


@pytest.mark.parametrize('cap', [None, 7, 9])
def test_operator_profile_requires_exact_reasoning_budget(cap):
    config = _config()
    config['profiles']['inference-only']['thinking_token_budget'] = 8
    catalog = BrokerConfig.model_validate(config)
    with pytest.raises(ValueError):
        catalog.resolve_contract('recon', 'gateway', 'model', {'max_tokens': 16},
            backend=backend(thinking_token_budget=cap))
    approved = catalog.resolve_contract('recon', 'gateway', 'model', {'max_tokens': 16},
        backend=backend(thinking_token_budget=8))
    assert approved.thinking_token_budget == 8


@pytest.mark.parametrize('enable_thinking', [None, True])
async def test_actual_sdk_direct_executor_and_admission_use_top_level_budget(monkeypatch, enable_thinking):
    import openai

    request, _ = request_fixture()
    contract = type(request.contract).model_validate({**request.contract.model_dump(mode='json'),
        'thinking_token_budget': 8, 'enable_thinking': enable_thinking})
    messages = [ModelRequest(parts=[UserPromptPart('offline')])]
    schema = {'type': 'object', 'properties': {'value': {'type': 'string'}},
              'required': ['value'], 'additionalProperties': False}
    parameters = ModelRequestParameters(
        function_tools=[ToolDefinition(name='read_files', parameters_json_schema=schema)],
        output_tools=[ToolDefinition(name='final_result', parameters_json_schema=schema, kind='output')])
    payload = encode_payload(messages, contract.model_settings, parameters)
    request = request.model_copy(update={'contract': contract, 'payload': payload,
        'payload_digest': digest(payload.model_dump(mode='json')),
        'binding': request.binding.model_copy(update={'contract_digest': contract.digest,
                                                     'expires_at': time.time() + 60})})
    original = deepcopy(payload.model_dump(mode='json'))
    wire = await input_wire(payload, contract)
    captured = []

    def respond(native_request):
        captured.append(json.loads(native_request.content))
        return httpx2.Response(200, json={'id': 'offline', 'object': 'chat.completion', 'created': 1,
            'model': contract.model, 'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': 'ready'},
                'finish_reason': 'stop'}], 'usage': {'prompt_tokens': 3, 'completion_tokens': 2, 'total_tokens': 5}})

    await OpenAIInference(contract, 'openshell:resolve:env:MOCK_TOKEN',
                          http_transport=httpx2.MockTransport(respond))(request)
    transport = httpx2.AsyncClient(transport=httpx2.MockTransport(respond))
    real_client = openai.AsyncOpenAI
    clients = []

    def client(**kwargs):
        instance = real_client(**kwargs, http_client=transport)
        clients.append(instance)
        return instance

    config = models.ModelsConfig(backends={'offline': models.BackendConfig(
        kind='openai_compatible', base_url=contract.endpoint, thinking_token_budget=8,
        enable_thinking=enable_thinking, max_retries=0, max_retries_under_temporal=0)},
        default_backend='offline', model_catalog={})
    monkeypatch.setattr(models, 'load_models_config', lambda: config)
    monkeypatch.setattr(openai, 'AsyncOpenAI', client)
    try:
        await models._build_live('offline', contract.model, False, False).request(messages, contract.model_settings, parameters)
    finally:
        models._build_live.cache_clear()
        for instance in clients:
            await instance.close()
        await transport.aclose()
    assert len(captured) == 2
    assert wire['extra_body']['thinking_token_budget'] == 8
    for body in captured:
        assert body['thinking_token_budget'] == 8
        assert body['max_completion_tokens'] == 16
        assert body['messages'] == wire['messages']
        assert body['tools'] == wire['tools']
        assert 'thinking_token_budget' not in body.get('chat_template_kwargs', {})
        if enable_thinking is None:
            assert 'chat_template_kwargs' not in body
        else:
            assert body['chat_template_kwargs'] == {'enable_thinking': True}
    assert payload.model_dump(mode='json') == original


@pytest.mark.parametrize('override', [
    {'extra_body': {'thinking_token_budget': 9}},
    {'extra_body': {'chat_template_kwargs': {'thinking_token_budget': 8}}},
    {'extra_headers': {'Authorization': 'injected'}},
])
def test_agents_cannot_inject_or_override_the_operator_reasoning_budget(override):
    with pytest.raises(BrokerError):
        encode_payload([ModelRequest(parts=[UserPromptPart('offline')])], override, ModelRequestParameters())
    model = CompatOpenAIChatModel('offline', provider=OpenAIProvider(
        api_key='offline', base_url='https://provider.invalid/v1'), thinking_token_budget=8)
    before = deepcopy(override)
    with pytest.raises(BrokerError):
        model.prepare_request({**override, 'max_tokens': 16}, ModelRequestParameters())
    assert override == before


async def test_signed_request_with_changed_cap_is_rejected_before_ledger_or_provider():
    request, settings = request_fixture()
    changed = type(request.contract).model_validate({**request.contract.model_dump(mode='json'),
                                                   'thinking_token_budget': 8})
    request = request.model_copy(update={'contract': changed, 'binding': request.binding.model_copy(
        update={'contract_digest': changed.digest})})
    calls = []

    class Ledger:
        async def claim(self, *_args):
            calls.append('claim')
            raise AssertionError('changed cap reached ledger')

    async def infer(_request):
        calls.append('provider')
        raise AssertionError('changed cap reached provider')

    body = canonical_bytes(request.model_dump(mode='json'))
    headers = {AUTH_HEADER: sign_request(bytes.fromhex(settings.ingress_key_hex), 'POST', '/v1/infer', body, 120)}
    with pytest.raises(BrokerError) as error:
        await Executor(settings, ledger=Ledger(), infer=infer, clock=lambda: 100).handle('/v1/infer', body, headers)
    assert error.value.code == 'identity'
    assert calls == []


def test_resolved_model_provenance_routes_budget_after_total_floor(monkeypatch):
    config = models.ModelsConfig(backends={'bounded': models.BackendConfig(
        kind='openai_compatible', base_url='https://provider.invalid/v1',
        thinking_token_budget=8, min_max_tokens=16)},
        default_backend='bounded', model_catalog={'offline-model': {'bounded': 'offline-model'}})
    monkeypatch.setattr(models, 'get_settings', lambda: SimpleNamespace(model_mode='live'))
    monkeypatch.setattr(models, 'load_models_config', lambda: config)
    monkeypatch.setattr(models, 'pricing_source', lambda _: 'custom-zero')
    monkeypatch.setattr(models, 'pricing_table_identity', lambda _: 'offline-reviewed')
    authored = {'max_tokens': 4}
    resolved = models.resolve_config('recon', 'offline-model', model_settings=authored)
    assert resolved.capability_profile.thinking_token_budget == 8
    assert resolved.requested_settings == {'max_tokens': 4}
    assert resolved.effective_settings == {'max_tokens': 16}
    assert authored == {'max_tokens': 4}
    config.backends['bounded'] = config.backends['bounded'].model_copy(
        update={'thinking_token_budget': 16})
    with pytest.raises(ValueError):
        models.resolve_config('recon', 'offline-model', model_settings=authored)
