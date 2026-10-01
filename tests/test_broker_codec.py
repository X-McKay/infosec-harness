"""Independent wire outcomes: typed tools survive; network-bearing parts cannot dispatch."""
from copy import deepcopy

import pytest
from pydantic_ai.messages import (
    ImageUrl,
    ModelRequest,
    ModelResponse,
    RetryPromptPart,
    SystemPromptPart,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models import ModelRequestParameters
from pydantic_ai.tools import ToolDefinition
from pydantic_ai.usage import RequestUsage

from infosec_harness.inference.codec import (
    decode_payload,
    decode_response,
    encode_payload,
    encode_response,
)
from infosec_harness.inference.protocol import BrokerError


def test_typed_history_tools_schema_and_usage_survive_roundtrip():
    messages = [ModelRequest(parts=[SystemPromptPart('instructions'), UserPromptPart('finding')]),
                ModelResponse(parts=[ToolCallPart('read_file', {'path': 'a.py'}, 'call-1')]),
                ModelRequest(parts=[ToolReturnPart('read_file', 'source', 'call-1'),
                                    RetryPromptPart('invalid output')])]
    params = ModelRequestParameters(function_tools=[ToolDefinition(name='read_file', parameters_json_schema={'type': 'object'})])
    payload = encode_payload(messages, {'max_tokens': 20}, params)
    decoded, settings, decoded_params = decode_payload(payload)
    assert decoded == messages
    assert decoded_params.function_tools == params.function_tools
    assert settings == {'max_tokens': 20}
    result = ModelResponse(parts=[TextPart('answer')], usage=RequestUsage(input_tokens=3,output_tokens=2,cache_read_tokens=1))
    assert decode_response(encode_response(result)) == result


@pytest.mark.parametrize('settings', [{'extra_headers': {'Authorization': 'x'}}, {'extra_body': {}},
                                      {'unknown_setting': True}, {'max_tokens': True},
                                      {'temperature': float('nan')}])
def test_unsupported_settings_fail_before_wire(settings):
    with pytest.raises((BrokerError, ValueError)):
        encode_payload([ModelRequest(parts=[UserPromptPart('x')])], settings, ModelRequestParameters())


def test_remote_image_cannot_be_fetched():
    with pytest.raises(BrokerError, match='Remote'):
        encode_payload([ModelRequest(parts=[UserPromptPart([ImageUrl('https://metadata.invalid/x')])])], {}, ModelRequestParameters())


def test_unknown_part_fields_are_rejected_instead_of_ignored():
    payload = encode_payload([ModelRequest(parts=[UserPromptPart('x')])], {}, ModelRequestParameters())
    data = deepcopy(payload.model_dump())
    data['messages'][0]['parts'][0]['remote_url'] = 'https://unapproved.invalid'
    with pytest.raises(BrokerError, match='Unknown'):
        decode_payload(type(payload).model_validate(data))


def test_invalid_response_is_not_a_success_or_tool_execution():
    with pytest.raises(BrokerError, match='invalid_response'):
        decode_response({'kind': 'response', 'parts': [{'part_kind': 'native-tool-call', 'tool_name': 'shell', 'args': 'rm'}]})



def test_negative_response_usage_is_rejected():
    response = ModelResponse(parts=[TextPart("x")], usage=RequestUsage(input_tokens=-1))
    with pytest.raises(BrokerError, match="invalid_response"):
        encode_response(response)


def test_contradictory_usage_is_rejected():
    from infosec_harness.inference.codec import validate_result_usage
    from infosec_harness.inference.protocol import InferenceResult
    result = InferenceResult(request_id="a" * 64,
        response=encode_response(ModelResponse(parts=[TextPart("x")], usage=RequestUsage(input_tokens=2))),
        usage={"input_tokens": 0})
    with pytest.raises(BrokerError, match="Contradictory"):
        validate_result_usage(result)
