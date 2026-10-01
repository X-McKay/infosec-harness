"""Lossless restricted PydanticAI codec; no remote resources or native execution tools."""
from __future__ import annotations

import dataclasses
from typing import Any

from pydantic import TypeAdapter
from pydantic_ai import messages as m
from pydantic_ai.models import ModelRequestParameters
from pydantic_ai.tools import ToolDefinition
from pydantic_ai.usage import RequestUsage

from infosec_harness.inference.protocol import (
    BrokerError,
    InferencePayload,
    canonical_bytes,
    verify_sdk_version,
)

_PARAMS = TypeAdapter(ModelRequestParameters)
_RESPONSE = TypeAdapter(m.ModelResponse)
_PARTS = {
    "system-prompt": m.SystemPromptPart,
    "user-prompt": m.UserPromptPart,
    "tool-return": m.ToolReturnPart,
    "retry-prompt": m.RetryPromptPart,
    "text": m.TextPart,
    "thinking": m.ThinkingPart,
    "tool-call": m.ToolCallPart,
    "tool-availability-delta": m.ToolAvailabilityDeltaPart,
}
_SETTINGS = {
    "max_tokens", "temperature", "top_p", "top_k", "timeout", "parallel_tool_calls",
    "tool_choice", "seed", "presence_penalty", "frequency_penalty", "logit_bias",
    "stop_sequences", "thinking", "service_tier", "openai_reasoning_effort",
    "openai_logprobs", "openai_top_logprobs", "openai_store", "openai_service_tier",
    "openai_prompt_cache_key", "openai_prompt_cache_retention",
    # These authored cross-backend fields are inert on the OpenAI chat path.
    "bedrock_cache_tool_definitions", "bedrock_cache_instructions", "bedrock_cache_messages",
}


def _keys(value: dict, cls: type) -> None:
    if not isinstance(value, dict) or set(value) - {f.name for f in dataclasses.fields(cls)}:
        raise BrokerError("policy", "Unknown typed inference fields")


def validate_settings(settings: dict[str, Any]) -> None:
    if set(settings) - _SETTINGS:
        raise BrokerError("policy", "Unsupported model settings")
    for name in ("bedrock_cache_tool_definitions", "bedrock_cache_instructions", "bedrock_cache_messages"):
        if name in settings and not (settings[name] is False or
                (type(settings[name]) is str and settings[name] in {"5m", "1h"})):
            raise BrokerError("policy", "Invalid cross-backend cache setting")
    canonical_bytes(settings)  # Reject nonfinite/non-JSON values, including hidden headers.
    maximum = settings.get("max_tokens")
    if maximum is not None and (type(maximum) is not int or maximum <= 0):
        raise BrokerError("policy", "Invalid output token ceiling")


def _cache_point(value: Any) -> bool:
    """Only the pinned SDK's bounded, non-network cache marker is supported."""
    return (type(value) is dict and set(value) == {"kind", "ttl"}
            and value["kind"] == "cache-point" and type(value["ttl"]) is str
            and value["ttl"] in {"5m", "1h"})


def _messages(messages: list[dict]) -> None:
    for message in messages:
        kind = message.get("kind")
        if kind not in {"request", "response"}:
            raise BrokerError("policy", "Unsupported message kind")
        _keys(message, m.ModelRequest if kind == "request" else m.ModelResponse)
        for part in message.get("parts", []):
            part_kind = part.get("part_kind")
            if part_kind not in _PARTS:
                raise BrokerError("policy", "Unsupported message part")
            _keys(part, _PARTS[part_kind])
            if part_kind == "user-prompt":
                content = part.get("content")
                if not isinstance(content, str) and not (
                    isinstance(content, list) and all(
                        isinstance(item, str) or _cache_point(item) for item in content
                    )
                ):
                    raise BrokerError("policy", "Remote and binary content are unsupported")
            if part_kind == "tool-return" and not isinstance(part.get("content"), (str, dict, list, int, float, bool, type(None))):
                raise BrokerError("policy", "Unsupported tool return content")
        if kind == "response" and message.get("usage"):
            # SDK 2.49 preserves this genai-prices extraction counter dynamically,
            # so it is absent from RequestUsage's dataclass fields. Other extras stay denied.
            usage_fields = {f.name for f in dataclasses.fields(RequestUsage)} | {"output_reasoning_tokens"}
            if not isinstance(message["usage"], dict) or set(message["usage"]) - usage_fields:
                raise BrokerError("policy", "Unknown typed usage fields")
            for key, usage in message["usage"].items():
                if key not in {"details", "cost"} and (type(usage) is not int or usage < 0):
                    raise BrokerError("invalid_response", "Invalid typed usage counter")


def decode_payload(payload: InferencePayload) -> tuple[list[m.ModelMessage], dict, ModelRequestParameters]:
    """Validate both received and locally generated JSON before any provider operation."""
    verify_sdk_version()
    validate_settings(payload.model_settings)
    _messages(payload.messages)
    params = payload.parameters
    _keys(params, ModelRequestParameters)
    if params.get("native_tools") or params.get("allow_image_output"):
        raise BrokerError("policy", "Native tools and image output are unsupported")
    for key in ("function_tools", "output_tools"):
        for tool in params.get(key, []):
            _keys(tool, ToolDefinition)
    try:
        messages = m.ModelMessagesTypeAdapter.validate_python(payload.messages)
        parameters = _PARAMS.validate_python(params)
        for message in messages:
            for part in message.parts:
                if isinstance(part, m.ToolReturnPart) and part.files:
                    raise BrokerError("policy", "Multimodal tool returns are unsupported")
    except (ValueError, TypeError):
        raise BrokerError("policy", "Invalid typed inference payload") from None
    return messages, dict(payload.model_settings), parameters


def encode_payload(messages, settings, params) -> InferencePayload:
    for message in messages:
        for part in message.parts:
            if isinstance(part, m.ToolReturnPart) and part.files:
                raise BrokerError("policy", "Multimodal tool returns are unsupported")
            if isinstance(part, m.UserPromptPart) and not isinstance(part.content, str) and not (
                isinstance(part.content, (list, tuple)) and all(
                    isinstance(item, str) or (type(item) is m.CachePoint and _cache_point(vars(item)))
                    for item in part.content
                )
            ):
                raise BrokerError("policy", "Remote and binary content are unsupported")
    parameters = _PARAMS.dump_python(params, mode="json")
    # Pinned SDK declares these as set[str]; order depends on each worker's hash seed.
    # Preserve membership (which controls deferred tool visibility), canonicalize order only.
    for name in ("deferred_capability_ids", "revealed_tool_names"):
        if name in parameters:
            parameters[name] = sorted(parameters[name])
    payload = InferencePayload(
        messages=m.ModelMessagesTypeAdapter.dump_python(messages, mode="json"),
        parameters=parameters,
        model_settings=dict(settings or {}),
    )
    decode_payload(payload)
    return payload


def encode_response(response: m.ModelResponse) -> dict[str, Any]:
    value = _RESPONSE.dump_python(response, mode="json")
    decode_response(value)
    return value


def decode_response(value: dict[str, Any]) -> m.ModelResponse:
    try:
        verify_sdk_version()
        _messages([value])
        if value.get("kind") != "response" or value.get("state", "complete") != "complete":
            raise BrokerError("invalid_response")
        response = _RESPONSE.validate_python(value)
        for name, usage in vars(response.usage).items():
            if name not in {"details", "cost"} and (type(usage) is not int or usage < 0):
                raise BrokerError("invalid_response", "Invalid provider usage")
        if any(type(v) is not int or v < 0 for v in response.usage.details.values()):
            raise BrokerError("invalid_response", "Invalid provider usage details")
        return response
    except (ValueError, TypeError, KeyError, BrokerError):
        raise BrokerError("invalid_response") from None



def validate_result_usage(result) -> m.ModelResponse:
    response = decode_response(result.response)
    for name, value in result.usage.items():
        observed = getattr(response.usage, name, None)
        if name in {"details", "cost"} or type(value) is not int or value < 0 or value != observed:
            raise BrokerError("invalid_response", "Contradictory provider usage")
    return response
