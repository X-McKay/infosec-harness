"""Independent tokenizer counterexamples and captured SDK shaping oracles."""
import json
import time

import httpx2
import pytest
from pydantic_ai.messages import ModelRequest, ModelResponse, ToolCallPart, UserPromptPart
from pydantic_ai.models import ModelRequestParameters, OutputObjectDefinition
from pydantic_ai.tools import ToolDefinition
from test_broker_executor import request_fixture

from infosec_harness.inference.codec import encode_payload
from infosec_harness.inference.compat import input_wire
from infosec_harness.inference.executor import OpenAIInference
from infosec_harness.inference.protocol import BrokerError, canonical_bytes, required_input_reserve


def payload(text="hi", params=None):
    return encode_payload([ModelRequest(parts=[UserPromptPart(text)])], {"max_tokens": 16},
                          params or ModelRequestParameters())


@pytest.mark.parametrize("text,params,primary_tokens", [
    ("\u0344" * 5000, None, 15010),
    ("hi", ModelRequestParameters(function_tools=[ToolDefinition(
        name="bounded_tool", description="安" * 5000,
        parameters_json_schema={"type": "object", "properties": {}})]), 25248),
])
async def test_published_qwen_unicode_counterexamples(text, params, primary_tokens):
    # Primary tokenizer/template, revision 6c7f09d4036e97393f82e9f9ecd1a5c35ca5ee92.
    # Frozen counts obtained with tokenizers 0.22.2/Jinja2 3.1.6, not model inference.
    # U+0344 canonically decomposes into two combining characters; Jinja tool JSON
    # escapes each CJK character to six ASCII bytes. Neither fits the old raw bound.
    request, _ = request_fixture()
    value = payload(text, params)
    old = len(canonical_bytes(value.model_dump(mode="json"))) + 1024 * (
        2 + len(value.parameters.get("function_tools", [])))
    assert old < primary_tokens
    assert await required_input_reserve(value, request.contract) >= primary_tokens


@pytest.mark.parametrize("atomic", [False, True])
async def test_admission_wire_matches_independently_captured_sdk_request(atomic, monkeypatch):
    request, _ = request_fixture()
    contract = request.contract.model_copy(update={"atomic_intake": atomic})
    schema = {"type": "object", "properties": {"answer": {"$ref": "#/$defs/A"}},
              "$defs": {"A": {"type": "string", "description": "安<&'"}}}
    params = (ModelRequestParameters(output_mode="native",
              output_object=OutputObjectDefinition(json_schema=schema)) if atomic else
              ModelRequestParameters(function_tools=[ToolDefinition(name="read", description="安",
                  parameters_json_schema=schema, return_schema=schema, include_return_schema=True)]))
    value = payload("\u0344", params)
    request = request.model_copy(update={"contract": contract, "payload": value,
        "binding": request.binding.model_copy(update={"expires_at": time.time() + 60})})
    sends = []

    def capture(native):
        sends.append(json.loads(native.content))
        return httpx2.Response(200, json={"id": "mock", "object": "chat.completion", "created": 1,
            "model": contract.model, "choices": [{"index": 0, "message": {
                "role": "assistant", "content": "approved"}, "finish_reason": "stop"}]})

    await OpenAIInference(contract, "openshell:resolve:env:MOCK_TOKEN",
                          http_transport=httpx2.MockTransport(capture))(request)
    assert len(sends) == 1

    async def forbidden_send(*args, **kwargs):
        pytest.fail("Admission attempted provider I/O")

    monkeypatch.setattr(httpx2.AsyncClient, "send", forbidden_send)
    wire = await input_wire(value, contract)
    for field in ("messages", "tools", "response_format"):
        assert wire[field] == sends[0].get(field, [] if field == "tools" else None)
    assert await required_input_reserve(value, contract) > 0


async def test_exponential_schema_refs_fail_before_sdk_expansion(monkeypatch):
    from infosec_harness.inference.compat import CompatOpenAIChatModel

    definitions = {"D0": {"type": "string"}}
    for index in range(1, 25):
        definitions[f"D{index}"] = {"type": "object", "properties": {
            "left": {"$ref": f"#/$defs/D{index - 1}"},
            "right": {"$ref": f"#/$defs/D{index - 1}"}}}
    schema = {"$ref": "#/$defs/D24", "$defs": definitions}
    value = payload(params=ModelRequestParameters(output_mode="native",
        output_object=OutputObjectDefinition(json_schema=schema)))
    request, _ = request_fixture()

    def forbidden_prepare(*args, **kwargs):
        pytest.fail("Unbounded schema reached SDK expansion")

    monkeypatch.setattr(CompatOpenAIChatModel, "prepare_request", forbidden_prepare)
    with pytest.raises(BrokerError, match="rendering expansion bound"):
        await required_input_reserve(value, request.contract.model_copy(update={"atomic_intake": True}))


async def test_recursive_schema_fails_closed():
    schema = {"$ref": "#/$defs/A", "$defs": {"A": {"type": "object", "properties": {
        "next": {"$ref": "#/$defs/A"}}}}}
    value = payload(params=ModelRequestParameters(output_mode="native",
        output_object=OutputObjectDefinition(json_schema=schema)))
    request, _ = request_fixture()
    with pytest.raises(BrokerError, match="reference cannot be bounded"):
        await required_input_reserve(value, request.contract)


@pytest.mark.parametrize("arguments", ['{"x":NaN}', '{"x":Infinity}',
                                      '{"x":' + '[' * 100 + '0' + ']' * 100 + '}'])
async def test_tool_argument_rendering_negatives_fail_closed(arguments):
    request, _ = request_fixture()
    value = encode_payload([ModelRequest(parts=[UserPromptPart("hi")]),
        ModelResponse(parts=[ToolCallPart("read", arguments, tool_call_id="call")])],
        {"max_tokens": 16}, ModelRequestParameters())
    with pytest.raises(BrokerError) as exc:
        await required_input_reserve(value, request.contract)
    assert exc.value.code == "policy"


async def test_decoded_tool_arguments_have_separate_normalization_reserve():
    request, _ = request_fixture()
    # JSON escapes conceal expanding Unicode from normalization of the wire string.
    arguments = json.dumps({"x": "\u0344" * 5000}, ensure_ascii=True)
    value = encode_payload([ModelRequest(parts=[UserPromptPart("hi")]),
        ModelResponse(parts=[ToolCallPart("read", arguments, tool_call_id="call")])],
        {"max_tokens": 16}, ModelRequestParameters())
    wire = await input_wire(value, request.contract)
    from infosec_harness.inference.protocol import _ascii_normalized_size

    required = await required_input_reserve(value, request.contract)
    assert required >= _ascii_normalized_size(wire) + 128 * 2 + 2048 + 60_000


async def test_ascii_tool_rich_input_remains_practical():
    request, _ = request_fixture()
    definitions = [ToolDefinition(name=f"tool{index}", description="read bounded data",
        parameters_json_schema={"type": "object", "properties": {
            "path": {"type": "string"}}, "required": ["path"]}) for index in range(20)]
    value = payload("bounded task", ModelRequestParameters(function_tools=definitions))
    assert await required_input_reserve(value, request.contract) < 10_000


@pytest.mark.parametrize("arguments", ["{broken", "[]"])
async def test_sdk_wraps_malformed_original_arguments_before_admission(arguments):
    request, _ = request_fixture()
    value = encode_payload([ModelRequest(parts=[UserPromptPart("hi")]),
        ModelResponse(parts=[ToolCallPart("read", arguments, tool_call_id="call")])],
        {"max_tokens": 16}, ModelRequestParameters())
    wire = await input_wire(value, request.contract)
    mapped = wire["messages"][-1]["tool_calls"][0]["function"]["arguments"]
    assert json.loads(mapped) == {"INVALID_JSON": arguments}
    assert await required_input_reserve(value, request.contract) > len(mapped)


async def test_cached_schema_expansion_height_cannot_bypass_depth_limit(monkeypatch):
    from infosec_harness.inference.compat import CompatOpenAIChatModel

    definition = {"type": "string"}
    for _ in range(40):
        definition = {"type": "array", "items": definition}
    deep_reference = {"$ref": "#/$defs/A"}
    for _ in range(32):
        deep_reference = {"type": "array", "items": deep_reference}
    # first populates the SDK/preflight cache shallowly, then second reuses it deep.
    schema = {"type": "object", "properties": {"first": {"$ref": "#/$defs/A"},
              "second": deep_reference}, "$defs": {"A": definition}}
    value = payload(params=ModelRequestParameters(output_mode="native",
        output_object=OutputObjectDefinition(json_schema=schema)))
    request, _ = request_fixture()

    def forbidden_prepare(*args, **kwargs):
        pytest.fail("Unbounded expanded depth reached SDK")

    monkeypatch.setattr(CompatOpenAIChatModel, "prepare_request", forbidden_prepare)
    with pytest.raises(BrokerError, match="expanded rendering depth"):
        await required_input_reserve(value, request.contract.model_copy(update={"atomic_intake": True}))


async def test_supplementary_cjk_normalization_cannot_shrink_json_escape_bound():
    import unicodedata

    from infosec_harness.inference.protocol import _ascii_normalized_size

    text = "\U0002f800" * 5000
    assert len(json.dumps(unicodedata.normalize("NFD", text))) < len(json.dumps(text))
    assert _ascii_normalized_size(text) >= len(json.dumps(text))
    request, _ = request_fixture()
    value = payload(params=ModelRequestParameters(function_tools=[ToolDefinition(
        name="read", description=text, parameters_json_schema={"type": "object"})]))
    assert await required_input_reserve(value, request.contract) >= 60_000
