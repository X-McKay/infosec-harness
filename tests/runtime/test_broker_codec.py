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
                                      {'temperature': float('nan')},
                                      {'bedrock_cache_messages': []},
                                      {'bedrock_cache_messages': 0}])
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


@pytest.mark.parametrize("counter", [True, "3", 3.5])
def test_wire_usage_does_not_coerce_counters(counter):
    from pydantic import ValidationError

    from infosec_harness.inference.protocol import InferenceResult
    with pytest.raises(ValidationError):
        InferenceResult(request_id="a" * 64, response={}, usage={"input_tokens": counter})


def test_set_valued_tool_visibility_is_canonical_without_losing_membership():
    params = ModelRequestParameters(deferred_capability_ids={"z-owner", "a-owner"},
                                    revealed_tool_names={"z-tool", "a-tool"})
    payload = encode_payload([ModelRequest(parts=[UserPromptPart("x")])], {}, params)
    assert payload.parameters["deferred_capability_ids"] == ["a-owner", "z-owner"]
    assert payload.parameters["revealed_tool_names"] == ["a-tool", "z-tool"]
    _, _, decoded = decode_payload(payload)
    assert decoded.deferred_capability_ids == params.deferred_capability_ids
    assert decoded.revealed_tool_names == params.revealed_tool_names
    from infosec_harness.inference.protocol import digest
    changed = payload.model_copy(update={"parameters": {**payload.parameters,
                                  "deferred_capability_ids": ["a-owner", "other-owner"]}})
    assert digest(changed.model_dump(mode="json")) != digest(payload.model_dump(mode="json"))


def test_actual_rendered_graph_prompt_preserves_cache_boundary():
    from pydantic_ai.messages import CachePoint

    from infosec_harness.agents.render import render_prompt
    from infosec_harness.domain.models import StackFingerprint
    content = render_prompt("Inspect the fixture", {"finding": "controlled input"},
                            stack=StackFingerprint(languages={"python": 1}))
    assert any(type(item) is CachePoint for item in content)
    messages = [ModelRequest(parts=[UserPromptPart(content)])]
    payload = encode_payload(messages, {}, ModelRequestParameters())
    decoded, _, _ = decode_payload(payload)
    assert decoded == messages
    assert decoded[0].parts[0].content == content


@pytest.mark.parametrize("ttl", ["5m", "1h"])
def test_authored_cache_marker_order_and_ttl_are_request_identity(ttl):
    from pydantic_ai.messages import CachePoint

    from infosec_harness.inference.protocol import digest
    messages = [ModelRequest(parts=[UserPromptPart(["prefix", CachePoint(ttl=ttl), "suffix"])])]
    payload = encode_payload(messages, {}, ModelRequestParameters())
    decoded, _, _ = decode_payload(payload)
    assert decoded == messages
    other = encode_payload([ModelRequest(parts=[UserPromptPart(["prefix", "suffix", CachePoint(ttl=ttl)])])], {}, ModelRequestParameters())
    assert digest(payload.model_dump(mode="json")) != digest(other.model_dump(mode="json"))


@pytest.mark.parametrize("marker", [
    {"kind": "cache-point", "ttl": "5m", "url": "https://metadata.invalid/x"},
    {"kind": "cache-point", "ttl": "forever"},
    {"kind": "cache-point", "ttl": True},
    {"kind": "image-url", "url": "https://metadata.invalid/x"},
])
def test_wire_marker_cannot_carry_remote_authority_or_invalid_fields(marker):
    payload = encode_payload([ModelRequest(parts=[UserPromptPart("x")])], {}, ModelRequestParameters())
    data = payload.model_dump()
    data["messages"][0]["parts"][0]["content"] = ["prefix", marker]
    with pytest.raises(BrokerError):
        decode_payload(type(payload).model_validate(data))


def test_actual_openai_reasoning_usage_survives_response_and_history_roundtrip():
    from infosec_harness.inference.codec import validate_result_usage
    from infosec_harness.inference.protocol import InferenceResult

    # The pinned SDK extracts a known genai-prices counter into dynamic RequestUsage state.
    # OpenAI reports reasoning as part of completion tokens; it must not be added twice.
    usage = RequestUsage.extract(
        {"model": "fixture-model", "usage": {"prompt_tokens": 7, "completion_tokens": 5,
            "completion_tokens_details": {"reasoning_tokens": 3}}},
        provider="openai", provider_url="https://api.openai.com/v1",
        provider_fallback="openai", api_flavor="chat")
    assert usage.input_tokens == 7
    assert usage.output_tokens == 5
    assert usage.output_reasoning_tokens == 3
    response = ModelResponse(parts=[TextPart("answer")], usage=usage)
    wire = encode_response(response)
    assert wire["usage"]["output_reasoning_tokens"] == 3
    restored = decode_response(wire)
    assert restored.usage == usage
    assert encode_response(restored)["usage"] == wire["usage"]
    assert restored.usage.total_tokens == 12
    result = InferenceResult(request_id="a" * 64, response=wire,
        usage={"input_tokens": 7, "output_tokens": 5, "output_reasoning_tokens": 3})
    assert validate_result_usage(result).usage == usage
    payload = encode_payload([response], {}, ModelRequestParameters())
    messages, _, _ = decode_payload(payload)
    assert messages[0].usage == usage
    assert messages[0].usage.output_reasoning_tokens == 3
    result.usage["output_reasoning_tokens"] = 2
    with pytest.raises(BrokerError, match="Contradictory"):
        validate_result_usage(result)


@pytest.mark.parametrize("counter", [-1, True, 1.5, "3", None])
def test_reasoning_usage_wire_counter_is_strict_nonnegative_integer(counter):
    wire = encode_response(ModelResponse(parts=[TextPart("answer")], usage=RequestUsage(output_tokens=5)))
    wire["usage"]["output_reasoning_tokens"] = counter
    with pytest.raises(BrokerError, match="invalid_response"):
        decode_response(wire)


def test_unknown_dynamic_usage_fields_remain_denied():
    wire = encode_response(ModelResponse(parts=[TextPart("answer")], usage=RequestUsage(output_tokens=5)))
    wire["usage"]["unreviewed_usage_counter"] = 3
    with pytest.raises(BrokerError, match="invalid_response"):
        decode_response(wire)
