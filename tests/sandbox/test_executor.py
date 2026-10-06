"""Wire-level regression for strict self-hosted chat templates."""

import json

import httpx
import pytest
from openai import AsyncOpenAI
from pydantic import ValidationError
from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    SystemPromptPart,
    TextPart,
    UserPromptPart,
)
from pydantic_ai.models import ModelRequestParameters
from pydantic_ai.usage import RequestUsage

from infosec_harness.sandbox.executor import RESPONSE, ModelInvocation, execute, provider_model


def test_reasoning_usage_extensions_survive_next_turn_transport():
    invocation = ModelInvocation(
        provider="openai",
        model_name="Qwen3.6-35B-A3B-NVFP4",
        settings=None,
        parameters=ModelRequestParameters(),
        messages=[
            ModelResponse(
                parts=[TextPart("inspect the source")],
                usage=RequestUsage(
                    input_tokens=1894,
                    output_tokens=218,
                    output_reasoning_tokens=69,
                    details={"reasoning_tokens": 69},
                ),
            ),
            ModelRequest(parts=[UserPromptPart("continue")]),
        ],
    )
    restored = ModelInvocation.model_validate_json(invocation.model_dump_json())
    assert restored.messages[0].usage.output_reasoning_tokens == 69
    assert RESPONSE.dump_json(restored.messages[0]) == RESPONSE.dump_json(invocation.messages[0])
    assert restored.messages[1].parts[0].content == "continue"


async def test_compatible_chat_preserves_instructions_with_one_leading_system(monkeypatch):
    monkeypatch.setattr("pydantic_ai.models.ALLOW_MODEL_REQUESTS", True)
    seen = []

    def transport(request):
        messages = json.loads(request.content)["messages"]
        seen.append(messages)
        # The Qwen endpoint rejected multiple leading system messages with HTTP 400.
        assert messages[0]["role"] == "system"
        assert all(message["role"] != "system" for message in messages[1:])
        assert "base rules" in messages[0]["content"]
        assert "skill instructions" in messages[0]["content"]
        assert "current instructions" in messages[0]["content"]
        assert "dynamic skill rules" in str(messages[-1]["content"])
        assert messages[1] == {"role": "user", "content": "inspect"}
        return httpx.Response(
            200,
            json={
                "id": "fixture",
                "object": "chat.completion",
                "created": 1,
                "model": "Qwen3.6-35B-A3B-NVFP4",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "ok"},
                    }
                ],
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        monkeypatch.setattr(
            "openai.AsyncOpenAI", lambda **kwargs: AsyncOpenAI(**kwargs, http_client=client)
        )
        invocation = ModelInvocation(
            provider="openai",
            model_name="Qwen3.6-35B-A3B-NVFP4",
            base_url="https://configured.example/v1",
            settings=None,
            messages=[
                ModelRequest(
                    parts=[
                        SystemPromptPart("base rules"),
                        SystemPromptPart("skill instructions"),
                        UserPromptPart("inspect"),
                    ]
                ),
                ModelResponse(parts=[TextPart("need skill")]),
                ModelRequest(
                    parts=[SystemPromptPart("dynamic skill rules")],
                    instructions="current instructions",
                ),
            ],
            parameters=ModelRequestParameters(),
        )
        response = RESPONSE.validate_json(await execute(invocation))
    assert response.parts[0].content == "ok"
    assert len(seen) == 1


def invocation_fields(**overrides):
    fields = {"provider": "bedrock", "model_name": "model", "region": "us-west-2",
              "timeout_seconds": 37, "messages": [], "settings": None,
              "parameters": ModelRequestParameters()}
    return {**fields, **overrides}


def test_unknown_invocation_field_is_refused_not_ignored():
    """A stale executor image must fail on a field it does not know, never drop a budget."""
    with pytest.raises(ValidationError, match="unknown model invocation fields"):
        ModelInvocation.model_validate(invocation_fields(future_budget=5))
    encoded = json.dumps({**invocation_fields(), "parameters": {}, "future_budget": 5})
    with pytest.raises(ValidationError, match=r"\['future_budget'\]"):
        ModelInvocation.model_validate_json(encoded)


def test_bedrock_client_is_bounded_by_the_invocation_budget(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "native-placeholder")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "native-placeholder")
    config = provider_model(ModelInvocation(**invocation_fields())).client.meta.config
    assert (config.connect_timeout, config.read_timeout) == (37, 37)
    assert config.retries["total_max_attempts"] == 1
