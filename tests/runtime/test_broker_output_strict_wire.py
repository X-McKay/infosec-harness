"""Offline strict-output wire expectations; endpoint enforcement is not qualified."""
from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError
from pydantic_ai.messages import ModelRequest, UserPromptPart
from pydantic_ai.models import ModelRequestParameters
from pydantic_ai.output import OutputObjectDefinition
from pydantic_ai.profiles.openai import OpenAIJsonSchemaTransformer
from pydantic_ai.tools import ToolDefinition
from test_broker_executor import request_fixture

from infosec_harness.agents.intake_claims import AtomicFinding
from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.inference.codec import decode_payload, encode_payload
from infosec_harness.inference.compat import input_wire


@pytest.mark.parametrize('strict', [None, False, True])
@pytest.mark.parametrize('mode', ['tool', 'native'])
async def test_codec_preserves_output_mode_schema_and_explicit_strict_flags(strict, mode):
    schema = {'type': 'object', 'properties': {'answer': {'type': 'string'}},
              'required': ['answer'], 'additionalProperties': False}
    before = deepcopy(schema)
    params = ModelRequestParameters(output_mode=mode, allow_text_output=False,
        output_tools=[ToolDefinition(name='final_result', parameters_json_schema=schema, kind='output', strict=strict)] if mode == 'tool' else [],
        output_object=OutputObjectDefinition(json_schema=schema, name='final_result', strict=strict))
    payload = encode_payload([ModelRequest(parts=[UserPromptPart('offline typed output')])], {'max_tokens': 16}, params)
    _messages, _settings, recovered = decode_payload(payload)
    assert recovered.output_mode == mode
    assert recovered.output_object.strict is strict
    assert recovered.output_object.json_schema == before
    if mode == 'tool':
        assert recovered.output_tools[0].strict is strict
        assert recovered.output_tools[0].parameters_json_schema == before
    request, _ = request_fixture()
    wire = await input_wire(payload, request.contract)
    # This closed, required schema is already auto-strict compatible in the pinned SDK.
    expected = strict is not False
    if mode == 'tool':
        assert wire['response_format'] is None
        function = wire['tools'][0]['function']
        assert function.get('strict', False) is expected
        assert function['parameters'] == before
    else:
        assert wire['tools'] == []
        assert wire['response_format']['json_schema']['strict'] is expected
        assert wire['response_format']['json_schema']['schema'] == before
    assert schema == before and params.output_object.strict is strict


def mappings(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from mappings(child)
    elif isinstance(value, list):
        for child in value:
            yield from mappings(child)


@pytest.mark.parametrize('strict', [None, True])
async def test_atomic_optional_claims_need_explicit_strict_and_keep_local_validation(strict):
    schema = AtomicFinding.model_json_schema()
    before = deepcopy(schema)
    params = ModelRequestParameters(output_mode='tool', allow_text_output=False,
        output_tools=[ToolDefinition(name='final_result', parameters_json_schema=schema, kind='output', strict=strict)])
    payload = encode_payload([ModelRequest(parts=[UserPromptPart('offline claims only')])], {'max_tokens': 16}, params)
    request, _ = request_fixture()
    wire = await input_wire(payload, request.contract.model_copy(update={'atomic_intake': True}))
    function = wire['tools'][0]['function']
    assert function.get('strict', False) is (strict is True)
    transformed = function['parameters']
    assert '$defs' not in transformed
    assert set(transformed['properties']) == set(AtomicFinding.model_fields)
    if strict is True:
        objects = [node for node in mappings(transformed) if node.get('type') == 'object']
        assert all(node['additionalProperties'] is False for node in objects)
        assert all(set(node['required']) == set(node['properties']) for node in objects)
        assert all('default' not in node for node in mappings(transformed))
        for field in AtomicFinding.model_fields:
            assert {'type': 'null'} in transformed['properties'][field]['anyOf']
    else:
        assert set(transformed.get('required', [])) != set(AtomicFinding.model_fields)
    assert AtomicFinding.model_validate(dict.fromkeys(AtomicFinding.model_fields)).cwe is None
    for confidence in (False, 0, 1.1):
        with pytest.raises(ValidationError):
            AtomicFinding.model_validate({'cwe': {'value': 'CWE-89', 'source': {'start_id': 'S000001'}, 'confidence': confidence}})
    assert schema == before and payload.parameters['output_tools'][0]['strict'] is strict


def test_forcing_strict_on_environment_dictionary_changes_a_legitimate_output_shape():
    schema = EnvironmentSpec.model_json_schema()
    before = deepcopy(schema)
    env = schema['properties']['env']
    assert env['additionalProperties'] == {'type': 'string'}
    transformed = OpenAIJsonSchemaTransformer(schema, strict=True).walk()
    strict_env = transformed['properties']['env']
    assert strict_env['additionalProperties'] is False and strict_env['properties'] == {}
    # Arbitrary authored environment keys remain valid locally and must not be silently dropped.
    assert EnvironmentSpec.model_validate({'base_image': 'python:3', 'test_command': 'pytest', 'env': {'CC': 'clang'}}).env == {'CC': 'clang'}
    assert schema == before


@pytest.mark.parametrize('enabled', [False, True])
async def test_opt_in_changes_only_closed_output_tools_and_preserves_original_payload(enabled):
    schema = AtomicFinding.model_json_schema()
    params = ModelRequestParameters(output_mode='tool', allow_text_output=False,
        output_tools=[ToolDefinition(name='closed_result', parameters_json_schema=schema, kind='output'),
            ToolDefinition(name='explicit_opt_out', parameters_json_schema=schema, kind='output', strict=False),
            ToolDefinition(name='environment_result', parameters_json_schema=EnvironmentSpec.model_json_schema(), kind='output')],
        function_tools=[ToolDefinition(name='read_file', parameters_json_schema={'type': 'object',
            'properties': {'path': {'type': 'string', 'default': '.'}}, 'additionalProperties': False})])
    payload = encode_payload([ModelRequest(parts=[UserPromptPart('offline')])], {'max_tokens': 16}, params)
    before = deepcopy(payload.model_dump(mode='json'))
    request, _ = request_fixture()
    contract = request.contract.model_copy(update={'atomic_intake': True, 'strict_closed_output_tools': enabled})
    wire = await input_wire(payload, contract)
    functions = {tool['function']['name']: tool['function'] for tool in wire['tools']}
    assert functions['closed_result'].get('strict', False) is enabled
    assert 'strict' not in functions['explicit_opt_out']
    assert 'strict' not in functions['environment_result']
    assert functions['environment_result']['parameters']['properties']['env']['additionalProperties'] == {'type': 'string'}
    assert 'strict' not in functions['read_file']
    assert functions['read_file']['parameters']['properties']['path']['default'] == '.'
    assert payload.model_dump(mode='json') == before
    assert all(tool.strict is None for tool in (params.output_tools[0], params.output_tools[2], params.function_tools[0]))


def test_flag_off_keeps_historical_contract_profile_and_capability_identity():
    from test_broker_profiles import _config

    from infosec_harness.agents.models import BackendConfig, CapabilityProfile
    from infosec_harness.inference.profiles import BrokerConfig
    from infosec_harness.inference.protocol import digest

    request, _ = request_fixture()
    for value in (request.contract, CapabilityProfile(), BackendConfig(kind='openai_compatible')):
        assert 'strict_closed_output_tools' not in value.model_dump(mode='json')
        assert value.model_copy(update={'strict_closed_output_tools': False}).model_dump(mode='json') == value.model_dump(mode='json')
    old = request.contract.model_dump(mode='json')
    assert request.contract.digest == digest(old)
    enabled = request.contract.model_copy(update={'strict_closed_output_tools': True})
    assert enabled.digest != request.contract.digest
    assert CapabilityProfile(strict_closed_output_tools=True).model_dump(mode='json')['strict_closed_output_tools'] is True
    cfg = _config()
    catalog = BrokerConfig.model_validate(cfg)
    old_profile = catalog.profiles['inference-only']
    assert old_profile.model_copy(update={'strict_closed_output_tools': False}).profile_digest == old_profile.profile_digest
    cfg['profiles']['inference-only']['strict_closed_output_tools'] = True
    catalog = BrokerConfig.model_validate(cfg)
    with pytest.raises(ValueError, match='Strict output adaptation'):
        catalog.resolve_contract('recon', 'gateway', 'model', {'max_tokens': 16}, backend_endpoint='https://provider.example/v1')
    contract = catalog.resolve_contract('recon', 'gateway', 'model', {'max_tokens': 16},
        backend_endpoint='https://provider.example/v1', strict_closed_output_tools=True)
    assert contract.strict_closed_output_tools and contract.profile_digest != old_profile.profile_digest


async def test_actual_sdk_executor_wire_matches_admission_opt_in_and_never_resends():
    import json
    import time

    import httpx2

    from infosec_harness.inference.executor import OpenAIInference
    from infosec_harness.inference.protocol import digest

    request, _ = request_fixture()
    contract = request.contract.model_copy(update={'atomic_intake': True, 'strict_closed_output_tools': True})
    params = ModelRequestParameters(output_mode='tool', allow_text_output=False,
        output_tools=[ToolDefinition(name='final_result', parameters_json_schema=AtomicFinding.model_json_schema(), kind='output')])
    payload = encode_payload([ModelRequest(parts=[UserPromptPart('offline')])], contract.model_settings, params)
    request = request.model_copy(update={'contract': contract, 'payload': payload,
        'payload_digest': digest(payload.model_dump(mode='json')), 'binding': request.binding.model_copy(
            update={'contract_digest': contract.digest, 'expires_at': time.time() + 60})})
    calls = []
    def respond(native_request):
        calls.append(json.loads(native_request.content))
        return httpx2.Response(200, json={'id': 'offline', 'object': 'chat.completion', 'created': 1,
            'model': 'test-model', 'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': 'offline'},
                'finish_reason': 'stop'}], 'usage': {'prompt_tokens': 3, 'completion_tokens': 2, 'total_tokens': 5}})
    expected = await input_wire(payload, contract)
    await OpenAIInference(contract, 'openshell:resolve:env:MOCK_TOKEN', http_transport=httpx2.MockTransport(respond))(request)
    assert len(calls) == 1
    assert calls[0]['tools'] == expected['tools'] and calls[0]['messages'] == expected['messages']
    assert calls[0]['tools'][0]['function']['strict'] is True
    assert 'response_format' not in calls[0]


@pytest.mark.parametrize('repair', [False, True])
async def test_mock_sdk_strict_output_keeps_bounded_local_validation_repair_and_source_guards(repair):
    import json

    import httpx2
    from openai import AsyncOpenAI
    from pydantic_ai import Agent
    from pydantic_ai.exceptions import UnexpectedModelBehavior
    from pydantic_ai.providers.openai import OpenAIProvider

    from infosec_harness.agents.intake_claims import reconstruct
    from infosec_harness.agents.intake_schema import intake_openai_profile
    from infosec_harness.inference.compat import _CompatOpenAIChatModel

    calls = []
    def respond(native_request):
        body = json.loads(native_request.content)
        calls.append(body)
        function = body['tools'][0]['function']
        assert function['strict'] is True
        confidence = .8 if repair and len(calls) == 2 else False
        args = dict.fromkeys(AtomicFinding.model_fields)
        args['cwe'] = {'value': 'CWE-89', 'source': {'start_id': 'S000001', 'end_id': None}, 'confidence': confidence}
        return httpx2.Response(200, json={'id': 'offline', 'object': 'chat.completion', 'created': 1,
            'model': 'test-model', 'choices': [{'index': 0, 'finish_reason': 'tool_calls', 'message': {
                'role': 'assistant', 'content': None, 'tool_calls': [{'id': f'call-{len(calls)}', 'type': 'function',
                    'function': {'name': function['name'], 'arguments': json.dumps(args)}}]}}],
            'usage': {'prompt_tokens': 3, 'completion_tokens': 2, 'total_tokens': 5}})
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as transport:
        client = AsyncOpenAI(base_url='https://provider.invalid/v1', api_key='offline', max_retries=0, http_client=transport)
        provider = OpenAIProvider(openai_client=client)
        model = _CompatOpenAIChatModel('test-model', provider=provider,
            profile=intake_openai_profile(provider.model_profile('test-model')), strict_closed_output_tools=True)
        agent = Agent(model, output_type=AtomicFinding, retries=1 if repair else 0)
        if repair:
            result = await agent.run('offline claims')
            finding = reconstruct('CWE-89', result.output)
            assert finding.cwe == 'CWE-89' and finding.evidence[0].quote == 'CWE-89'
            unsupported = result.output.model_copy(update={'cwe': result.output.cwe.model_copy(
                update={'source': result.output.cwe.source.model_copy(update={'start_id': 'S999999'})})})
            with pytest.raises(ValueError):
                reconstruct('CWE-89', unsupported)
        else:
            with pytest.raises(UnexpectedModelBehavior):
                await agent.run('offline claims')
    assert len(calls) == (2 if repair else 1)


def test_opt_in_rejects_unqualified_sdk_profile_and_bounded_schema_expansion():
    from infosec_harness.inference.compat import _strict_closed_outputs
    from infosec_harness.inference.protocol import BrokerError

    closed = {'type': 'object', 'properties': {'answer': {'type': 'string'}}, 'additionalProperties': False}
    params = ModelRequestParameters(output_mode='tool', output_tools=[ToolDefinition(name='final_result',
        parameters_json_schema=closed, kind='output')])
    with pytest.raises(BrokerError, match='does not support strict'):
        _strict_closed_outputs(params, {'openai_supports_strict_tool_definition': False})
    defs = {'leaf': closed}
    for i in range(20):
        child = 'leaf' if i == 0 else f'level{i - 1}'
        defs[f'level{i}'] = {'type': 'object', 'additionalProperties': False,
            'properties': {'left': {'$ref': f'#/$defs/{child}'}, 'right': {'$ref': f'#/$defs/{child}'}}}
    exploding = {'$defs': defs, '$ref': '#/$defs/level19'}
    params = ModelRequestParameters(output_mode='tool', output_tools=[ToolDefinition(name='final_result',
        parameters_json_schema=exploding, kind='output')])
    with pytest.raises(BrokerError, match='bound'):
        _strict_closed_outputs(params, {})
    assert params.output_tools[0].strict is None


def test_default_off_resolved_capability_identity_is_exactly_historical():
    from infosec_harness.agents.models import CapabilityProfile, ResolvedModelConfig

    profile = CapabilityProfile()
    resolved = ResolvedModelConfig(mode='live', backend_name='gateway', backend_kind='openai_compatible',
        requested_model='test', resolved_model='gateway:test', capability_profile=profile,
        pricing_table='offline-zero', pricing_status='known_zero')
    old = resolved.model_dump(mode='json')
    assert 'strict_closed_output_tools' not in old['capability_profile']
    assert resolved.model_copy(update={'capability_profile': profile.model_copy(
        update={'strict_closed_output_tools': False})}).digest == resolved.digest
    assert resolved.model_copy(update={'capability_profile': CapabilityProfile(
        strict_closed_output_tools=True)}).digest != resolved.digest


async def test_direct_model_factory_matches_executor_admission_strict_wire(monkeypatch):
    import json

    import httpx2
    import openai

    from infosec_harness.agents import models

    request, _ = request_fixture()
    contract = request.contract.model_copy(update={'atomic_intake': True, 'strict_closed_output_tools': True})
    params = ModelRequestParameters(output_mode='tool', allow_text_output=False,
        output_tools=[ToolDefinition(name='final_result', parameters_json_schema=AtomicFinding.model_json_schema(), kind='output')])
    messages = [ModelRequest(parts=[UserPromptPart('offline')])]
    payload = encode_payload(messages, contract.model_settings, params)
    expected = await input_wire(payload, contract)
    captured = []
    def respond(native_request):
        captured.append(json.loads(native_request.content))
        return httpx2.Response(200, json={'id': 'offline', 'object': 'chat.completion', 'created': 1,
            'model': 'test-model', 'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': 'offline'},
                'finish_reason': 'stop'}], 'usage': {'prompt_tokens': 3, 'completion_tokens': 2, 'total_tokens': 5}})
    transport = httpx2.AsyncClient(transport=httpx2.MockTransport(respond))
    client_type = openai.AsyncOpenAI
    clients = []
    def client(**kwargs):
        value = client_type(**kwargs, http_client=transport)
        clients.append(value)
        return value
    cfg = models.ModelsConfig(backends={'strict-output-factory-offline': models.BackendConfig(
        kind='openai_compatible', transport='direct', base_url=contract.endpoint,
        strict_closed_output_tools=True, max_retries=0, max_retries_under_temporal=0)},
        default_backend='strict-output-factory-offline', model_catalog={})
    monkeypatch.setattr(models, 'load_models_config', lambda: cfg)
    monkeypatch.setattr(openai, 'AsyncOpenAI', client)
    try:
        model = models._build_live('strict-output-factory-offline', contract.model, intake_atomic=True)
        await model.request(messages, contract.model_settings, params)
    finally:
        models._build_live.cache_clear()
        for value in clients:
            await value.close()
        await transport.aclose()
    assert len(captured) == 1
    assert captured[0]['tools'] == expected['tools'] and captured[0]['messages'] == expected['messages']
    assert captured[0]['tools'][0]['function']['strict'] is True
    assert params.output_tools[0].strict is None
