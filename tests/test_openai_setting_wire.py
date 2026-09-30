"""Offline wire checks for the configured OpenAI-compatible intake model settings."""
from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from openai import AsyncOpenAI
from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

from infosec_harness.agents import models


class Output(BaseModel):
    value: str


async def request_payload(model_id: str, settings: dict[str, Any], *, production_adapter: bool) -> dict[str, Any]:
    seen: list[dict[str, Any]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "provider.invalid"
        payload = json.loads(request.content)
        seen.append(payload)
        output_tool = payload["tools"][0]["function"]["name"]
        return httpx.Response(200, json={
            "id": "synthetic-response",
            "object": "chat.completion",
            "created": 1,
            "model": model_id,
            "choices": [{
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "synthetic-tool-call",
                        "type": "function",
                        "function": {"name": output_tool, "arguments": '{"value":"ok"}'},
                    }],
                },
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        client = AsyncOpenAI(
            base_url="https://provider.invalid/v1", api_key="test", http_client=http_client
        )
        provider = OpenAIProvider(openai_client=client)
        if production_adapter:
            backend = models.load_models_config().backends["gateway"]
            model = models._CompatOpenAIChatModel(
                model_id,
                provider=provider,
                merge_system=backend.merge_system_messages,
                min_max_tokens=backend.min_max_tokens,
            )
        else:
            model = OpenAIChatModel(model_id, provider=provider)
        result = await Agent(model, output_type=Output, model_settings=settings).run("return the fixed value")
    finally:
        await http_client.aclose()

    assert result.output == Output(value="ok")
    assert len(seen) == 1
    return seen[0]


@pytest.mark.asyncio
async def test_temperature_zero_is_sent_by_configured_gateway_adapter() -> None:
    payload = await request_payload(
        "Qwen3.6-35B-A3B-NVFP4", {"temperature": 0}, production_adapter=True
    )
    assert payload["temperature"] == 0
    assert "reasoning_effort" not in payload


@pytest.mark.asyncio
async def test_documented_openai_thinking_low_maps_to_reasoning_effort_for_supported_model() -> None:
    payload = await request_payload("gpt-5.5", {"thinking": "low"}, production_adapter=False)
    assert payload["reasoning_effort"] == "low"


@pytest.mark.asyncio
async def test_configured_qwen_profile_omits_unified_thinking_low() -> None:
    payload = await request_payload(
        "Qwen3.6-35B-A3B-NVFP4", {"thinking": "low"}, production_adapter=True
    )
    assert "reasoning_effort" not in payload
