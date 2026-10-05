"""Wire-level regression for strict self-hosted chat templates."""

import json

import httpx
from openai import AsyncOpenAI
from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    SystemPromptPart,
    TextPart,
    UserPromptPart,
)
from pydantic_ai.models import ModelRequestParameters

from infosec_harness.model_executor import RESPONSE, ModelInvocation, execute


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
