"""Admission rendering: the exact SDK-shaped provider request, measured without provider I/O."""
from __future__ import annotations

import json
from typing import Any

import httpx2
from openai import AsyncOpenAI
from pydantic_ai.providers.openai import OpenAIProvider

from infosec_harness.inference.executor.compat import model_for_contract
from infosec_harness.inference.wire.codec import (
    ascii_normalized_size,
    check_schemas,
    decode_payload,
)
from infosec_harness.inference.wire.diagnostics import budget_guard
from infosec_harness.inference.wire.protocol import (
    MAX_BODY_BYTES,
    BrokerError,
    ExecutorContract,
    InferencePayload,
    InferenceRequest,
)


async def input_wire(payload: InferencePayload, contract: ExecutorContract) -> dict[str, Any]:
    """Pure SDK shaping, in the same order as request/_completions_create.

    The restricted codec excludes every content item that can fetch a remote resource.
    A rejecting transport additionally prevents any accidental provider request. This
    deliberately does not invoke request() or its global allow-model-requests check.
    """
    def deny_request(request: Any) -> Any:
        raise BrokerError("policy", "Admission rendering cannot send a provider request")

    messages, settings, params = decode_payload(payload)
    schemas = [schema for definition in (*params.function_tools, *params.output_tools)
               for schema in (definition.parameters_json_schema, definition.return_schema)
               if schema is not None]
    if params.output_object is not None:
        schemas.append(params.output_object.json_schema)
    check_schemas(schemas)
    async with (
        httpx2.AsyncClient(transport=httpx2.MockTransport(deny_request), trust_env=False) as transport,
        AsyncOpenAI(base_url=contract.endpoint, api_key="admission-no-network",
                    max_retries=0, http_client=transport) as client,
    ):
        model = model_for_contract(contract, OpenAIProvider(openai_client=client))
        try:
            settings, params = model.prepare_request(settings, params)
            settings = settings or {}
            tools, _ = model._get_tool_choice(settings, params)
            mapped = await model._map_messages(messages, params, model_settings=settings)
            response_format = None
            if params.output_mode == "native":
                if params.output_object is None:
                    raise BrokerError("policy", "Native output schema is missing")
                response_format = model._map_json_schema(params.output_object)
            elif params.output_mode == "prompted":
                raise BrokerError("policy", "Prompted output is not qualified for admission")
        except BrokerError:
            raise
        except Exception as exc:
            raise BrokerError("policy", "Unsupported admission rendering") from exc
    wire = {"messages": mapped, "tools": tools, "response_format": response_format}
    if contract.enable_thinking is not None or contract.thinking_token_budget is not None:
        wire["extra_body"] = settings["extra_body"]
    if ascii_normalized_size(wire) > MAX_BODY_BYTES:
        raise BrokerError("policy", "Transformed admission input exceeds rendering bound")
    return wire


async def required_input_reserve(payload: InferencePayload, contract: ExecutorContract) -> int:
    """Byte-BPE bound over actual SDK shaping, without provider I/O.

    Requires operator qualification of the tokenizer AND chat template. This covers
    the published Qwen3.6 tokenizer/template at revision
    6c7f09d4036e97393f82e9f9ecd1a5c35ca5ee92: NFC + byte-level BPE gives at most
    one token per normalized byte; all 26 special-token literals consume fewer tokens
    than their byte lengths. The template's fixed tools/system/generation literals
    total <2048 bytes, each role/thinking/tool-response envelope <128 bytes, each
    function-call envelope <128 bytes, and each parameter envelope <64 bytes.
    Content is emitted once; stripping/thinking extraction cannot increase it.

    SDK schema expansion, return-schema descriptions, and retry formatting are
    measured AFTER transformation. Jinja HTML-safe ASCII JSON is bounded by the larger original/NFD
    escaped size. Parsed call arguments are additionally counted because vLLM
    decodes their JSON before XML rendering. Unknown templates/tokenizers need
    separate qualification; a model name is never runtime execution evidence.
    Wire digests/identities remain unchanged. Existing held allocations must not be
    released or dispatched under a different executor image/contract.
    """
    wire = await input_wire(payload, contract)
    messages = wire["messages"]
    reserve = ascii_normalized_size(wire) + 2048 + 128 * len(messages)
    for message in messages:
        for call in message.get("tool_calls", []) or []:
            function = call.get("function", {})
            arguments = function.get("arguments", {})
            try:
                arguments = json.loads(arguments) if isinstance(arguments, str) else arguments
            except (ValueError, TypeError, RecursionError) as exc:
                raise BrokerError("policy", "Tool-call arguments cannot be rendered") from exc
            if not isinstance(arguments, dict):
                raise BrokerError("policy", "Tool-call arguments must be an object")
            reserve += 128 + 64 * len(arguments) + ascii_normalized_size(arguments)
    return reserve


async def check_request_bounds(request: InferenceRequest, *, max_input_tokens: int,
                               max_output_tokens: int, boundary: str) -> tuple[int, int]:
    """Trusted per-request caps, checked before any allocation or claim.

    Returns the rendered input reserve and the admitted output cap.
    """
    output = request.contract.model_settings.get("max_tokens")
    if (type(output) is not int or not 0 < output <= max_output_tokens
            or output < request.contract.min_max_tokens):
        raise budget_guard(boundary, "output_cap",
                           "Provider output cap is missing or exceeds trusted bounds")
    reserve = await required_input_reserve(request.payload, request.contract)
    if reserve > max_input_tokens:
        raise budget_guard(boundary, "input_reserve",
                           "Serialized input exceeds the trusted tokenizer/context bound",
                           reserve=reserve, limit=max_input_tokens)
    return reserve, output
