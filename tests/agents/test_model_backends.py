"""Offline contracts for the two production model backends.

These tests stop at client/model construction. They exercise the real backend selection and
configuration without sending a request to the gateway or AWS.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import httpx
from pydantic import BaseModel
from pydantic_ai import Agent

from infosec_harness.agents import models


def test_openai_compatible_construction_applies_the_production_transport_contract(monkeypatch):
    captured: dict[str, Any] = {}

    class Client:
        def __init__(self, **kwargs: Any) -> None:
            captured["client"] = kwargs

    class Provider:
        def __init__(self, *, openai_client: Any) -> None:
            captured["provider_client"] = openai_client

    class ChatModel:
        def __init__(self, model_id: str, **kwargs: Any) -> None:
            captured["model_id"] = model_id
            captured["model"] = kwargs

    import openai
    import pydantic_ai.providers.openai

    monkeypatch.setattr(openai, "AsyncOpenAI", Client)
    monkeypatch.setattr(pydantic_ai.providers.openai, "OpenAIProvider", Provider)
    monkeypatch.setattr(models, "CompatOpenAIChatModel", ChatModel)
    backend = models.load_models_config().backends["gateway"]
    assert backend.api_key_env
    monkeypatch.setenv(backend.api_key_env, "test-key")
    models._build_live.cache_clear()
    try:
        result = models._build_live("gateway", "model-under-test", durable=True)
    finally:
        models._build_live.cache_clear()

    assert isinstance(result, ChatModel)
    assert captured["model_id"] == "model-under-test"
    assert captured["client"] == {
        "base_url": backend.base_url,
        "api_key": "test-key",
        "max_retries": backend.max_retries_under_temporal,
    }
    assert captured["model"]["merge_system"] is backend.merge_system_messages
    assert captured["model"]["min_max_tokens"] == backend.min_max_tokens


def test_bedrock_construction_uses_region_and_profile_without_a_live_aws_call(monkeypatch):
    captured: dict[str, Any] = {}

    class Provider:
        def __init__(self, **kwargs: Any) -> None:
            captured["provider"] = kwargs

    class ConverseModel:
        def __init__(self, model_id: str, **kwargs: Any) -> None:
            captured["model_id"] = model_id
            captured["model"] = kwargs

    import pydantic_ai.models.bedrock
    import pydantic_ai.providers.bedrock

    monkeypatch.setattr(pydantic_ai.providers.bedrock, "BedrockProvider", Provider)
    monkeypatch.setattr(pydantic_ai.models.bedrock, "BedrockConverseModel", ConverseModel)
    monkeypatch.setenv("AWS_PROFILE", "offline-contract-profile")
    models._build_live.cache_clear()
    try:
        result = models._build_live("bedrock", "bedrock-model-under-test", durable=True)
    finally:
        models._build_live.cache_clear()

    backend = models.load_models_config().backends["bedrock"]
    assert isinstance(result, ConverseModel)
    assert captured["provider"] == {
        "region_name": backend.region,
        "profile_name": "offline-contract-profile",
    }
    assert captured["model_id"] == "bedrock-model-under-test"
    assert isinstance(captured["model"]["provider"], Provider)


def test_backend_capabilities_preserve_typed_output_and_tool_calling(monkeypatch):
    """Both backends advertise the capabilities required by governed agent specs."""
    from infosec_harness.agents.outputs import VERDICT_OUTPUTS
    from infosec_harness.agents.registry import AGENT_BINDINGS, build_agent
    from infosec_harness.domain.models import ProbeSource
    from infosec_harness.settings import get_settings

    monkeypatch.setenv("HARNESS_MODEL_MODE", "live")
    try:
        for backend in ("gateway", "bedrock"):
            monkeypatch.setenv("HARNESS_MODEL_BACKEND", backend)
            get_settings.cache_clear()
            models.load_models_config.cache_clear()
            verdict = build_agent("verdict", durable=False)
            author = build_agent("probe-author", durable=False)
            resolved = models.resolve_config("probe-author", "sonnet")
            assert verdict.output_type == VERDICT_OUTPUTS
            assert author.output_type is ProbeSource
            assert len(verdict.output_json_schema()["anyOf"]) == 3
            assert author.output_json_schema()["title"] == "ProbeSource"
            assert resolved.capability_profile.structured_output == "tool"
            assert resolved.capability_profile.tool_calling is True
            assert AGENT_BINDINGS["probe-author"] is ProbeSource
    finally:
        get_settings.cache_clear()
        models.load_models_config.cache_clear()


def test_pricing_identity_versions_actual_catalog_and_backend_table():
    bedrock = models.pricing_table_identity("bedrock")
    gateway = models.pricing_table_identity("gateway")
    assert "genai-prices:" in bedrock and ";models:" in bedrock
    assert ";backend:bedrock;" in bedrock
    assert ";backend:gateway;" in gateway
    assert bedrock != gateway, "backend-specific custom price tables must change identity"


def test_custom_prices_never_cross_backend_boundaries(monkeypatch):
    cfg = models.ModelsConfig(
        backends={
            "first": models.BackendConfig(
                kind="openai_compatible",
                prices={"same-id": models.Prices(input_per_mtok=1, output_per_mtok=2)},
            ),
            "second": models.BackendConfig(
                kind="openai_compatible",
                prices={"same-id": models.Prices(input_per_mtok=10, output_per_mtok=20)},
            ),
        },
        default_backend="first",
        model_catalog={},
    )
    monkeypatch.setattr(models, "load_models_config", lambda: cfg)
    assert models.custom_prices("first:same-id").input_per_mtok == 1
    assert models.custom_prices("second:same-id").input_per_mtok == 10


def test_stub_cost_is_explicit_known_zero():
    usage = SimpleNamespace(
        input_tokens=100, output_tokens=50,
        cache_read_tokens=0, cache_write_tokens=0,
    )
    assert models.estimate_cost("stub:verdict:sonnet", usage) == (0.0, False)


class _TypedReply(BaseModel):
    value: str


def _echo(value: str) -> dict[str, str]:
    return {"echoed": value}


async def test_openai_compatible_mock_transport_round_trips_tool_and_typed_output():
    """Exercise real OpenAI request/response mapping without endpoint egress."""
    from openai import AsyncOpenAI
    from pydantic_ai.providers.openai import OpenAIProvider

    calls: list[dict[str, Any]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body)
        names = [tool["function"]["name"] for tool in body["tools"]]
        name = "_echo" if len(calls) == 1 else next(n for n in names if n != "_echo")
        arguments = {"value": "hello" if name == "_echo" else "done"}
        return httpx.Response(200, json={
            "id": f"response-{len(calls)}", "object": "chat.completion",
            "created": 1, "model": "test-model",
            "choices": [{
                "index": 0, "finish_reason": "tool_calls",
                "message": {"role": "assistant", "content": None, "tool_calls": [{
                    "id": f"tool-{len(calls)}", "type": "function",
                    "function": {"name": name, "arguments": json.dumps(arguments)},
                }]},
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        client = AsyncOpenAI(
            base_url="https://provider.invalid/v1", api_key="test", http_client=http_client
        )
        model = models.CompatOpenAIChatModel(
            "test-model", provider=OpenAIProvider(openai_client=client)
        )
        result = await Agent(model, output_type=_TypedReply, tools=[_echo]).run("go")
    finally:
        await http_client.aclose()

    assert result.output == _TypedReply(value="done")
    assert len(calls) == 2
    assert calls[1]["messages"][-1] == {
        "role": "tool", "tool_call_id": "tool-1", "content": '{"echoed":"hello"}'
    }


async def test_bedrock_mock_transport_round_trips_tool_and_typed_output():
    """Exercise real Bedrock Converse mapping without AWS credentials or a live call."""
    from pydantic_ai.models.bedrock import BedrockConverseModel
    from pydantic_ai.providers.bedrock import BedrockProvider

    class Events:
        def register_first(self, *args: Any, **kwargs: Any) -> None:
            pass

    class Client:
        meta = SimpleNamespace(endpoint_url="https://bedrock.invalid", events=Events())

        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []

        def converse(self, **request: Any) -> dict[str, Any]:
            self.calls.append(request)
            names = [tool["toolSpec"]["name"] for tool in request["toolConfig"]["tools"]]
            name = "_echo" if len(self.calls) == 1 else next(n for n in names if n != "_echo")
            value = "hello" if name == "_echo" else "done"
            return {
                "output": {"message": {"role": "assistant", "content": [{
                    "toolUse": {
                        "toolUseId": f"tool-{len(self.calls)}", "name": name,
                        "input": {"value": value},
                    }
                }]}},
                "stopReason": "tool_use",
                "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
                "metrics": {"latencyMs": 1},
                "ResponseMetadata": {"RequestId": f"request-{len(self.calls)}"},
            }

    client = Client()
    model = BedrockConverseModel(
        "anthropic.claude-sonnet-5", provider=BedrockProvider(bedrock_client=client)
    )
    result = await Agent(model, output_type=_TypedReply, tools=[_echo]).run("go")

    assert result.output == _TypedReply(value="done")
    assert len(client.calls) == 2
    assert client.calls[1]["messages"][-1]["content"][0]["toolResult"] == {
        "toolUseId": "tool-1",
        "content": [{"text": '{"echoed":"hello"}'}],
        "status": "success",
    }
