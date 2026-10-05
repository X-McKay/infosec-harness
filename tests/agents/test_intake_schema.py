"""OpenAI strict-schema profile construction and mocked SDK request/response codec."""

from __future__ import annotations

import json

import httpx
from openai import AsyncOpenAI
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.intake_claims import AtomicFinding, reconstruct
from infosec_harness.agents.intake_schema import (
    InlineOpenAIJsonSchemaTransformer,
    intake_openai_profile,
)
from infosec_harness.domain.models import ExtractedFinding


def test_profile_builder_copies_base_and_overrides_only_schema_transformer():
    base = OpenAIProvider.model_profile("gpt-4o") or {}
    original = dict(base)

    profile = intake_openai_profile(base)

    assert profile is not base
    assert base == original
    assert profile["json_schema_transformer"] is InlineOpenAIJsonSchemaTransformer
    assert {key: value for key, value in profile.items() if key != "json_schema_transformer"} == {
        key: value for key, value in original.items() if key != "json_schema_transformer"
    }
    assert issubclass(InlineOpenAIJsonSchemaTransformer, original["json_schema_transformer"])


def test_profile_builder_handles_provider_without_profile():
    profile = intake_openai_profile(None)
    assert profile == {"json_schema_transformer": InlineOpenAIJsonSchemaTransformer}


async def test_public_model_constructor_emits_inline_strict_schema_and_parses_atomic_output():
    requests = []
    report = 'path = "C:\\tmp\\src.py"\n'
    path_value = "C:\\tmp\\src.py"

    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "provider.invalid"
        payload = json.loads(request.content)
        requests.append(payload)
        output_tool = next(
            tool["function"] for tool in payload["tools"] if tool["type"] == "function"
        )
        arguments = json.dumps(
            {
                "file_path": {
                    "value": path_value,
                    "source": {"start_id": "S000001"},
                    "confidence": 0.75,
                }
            }
        )
        return httpx.Response(
            200,
            json={
                "id": "mock-chat-completion",
                "object": "chat.completion",
                "created": 1,
                "model": "mock-model",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "mock-call",
                                    "type": "function",
                                    "function": {
                                        "name": output_tool["name"],
                                        "arguments": arguments,
                                    },
                                }
                            ],
                        },
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            },
        )

    http = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        client = AsyncOpenAI(
            base_url="https://provider.invalid/v1", api_key="synthetic", http_client=http
        )
        provider = OpenAIProvider(openai_client=client)
        model_name = "gpt-4o"
        profile = intake_openai_profile(provider.model_profile(model_name))
        model = OpenAIChatModel(model_name, provider=provider, profile=profile)
        agent = Agent(
            model, deps_type=AgentDeps, output_type=AtomicFinding, retries=0
        )

        async def materialize(_ctx: RunContext[AgentDeps], output: AtomicFinding):
            return reconstruct(report, output)

        agent.output_validator(materialize)
        result = await agent.run(
            "Synthetic fixture only.",
            deps=AgentDeps(repo_path="/synthetic", report_text=report),
        )
    finally:
        await http.aclose()

    assert isinstance(result.output, ExtractedFinding)
    assert result.output.file_path == path_value
    assert result.output.evidence[0].quote == report
    assert len(requests) == 1
    tool = next(tool["function"] for tool in requests[0]["tools"] if tool["type"] == "function")
    schema = tool["parameters"]
    assert "$defs" not in json.dumps(schema)
    assert set(schema["properties"]) == set(AtomicFinding.model_fields)

    def mappings(value):
        if isinstance(value, dict):
            yield value
            for nested in value.values():
                yield from mappings(nested)
        elif isinstance(value, list):
            for nested in value:
                yield from mappings(nested)

    object_schemas = [item for item in mappings(schema) if item.get("type") == "object"]
    assert object_schemas
    assert all(item.get("additionalProperties") is False for item in object_schemas)
    confidence_schemas = [
        item["properties"]["confidence"]
        for item in object_schemas
        if "confidence" in item.get("properties", {})
    ]
    assert confidence_schemas
    assert all(
        item.get("exclusiveMinimum") == 0 and item.get("maximum") == 1
        for item in confidence_schemas
    )


async def test_canonical_registry_resolves_current_atomic_spec_through_mock_openai_transport(monkeypatch):
    """Exercise the actual registry resolver, model factory profile, settings, and SDK codec."""
    import openai

    from infosec_harness.agents import models as model_factory
    from infosec_harness.agents.intake_contracts import render_intake_prompt
    from infosec_harness.agents.registry import build_agent
    from infosec_harness.settings import get_settings

    report = 'file: "src\\app.py"\n'
    value = "src\\app.py"
    calls = []

    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body)
        functions = [item["function"] for item in body["tools"] if item["type"] == "function"]
        tool = next((item for item in functions if item["name"] != "load_capability"), None)
        if tool is None:
            tool = next(item for item in functions if item["name"] == "load_capability")
            arguments = json.dumps({"id": "cwe-89-sql-injection"})
        else:
            claims = AtomicFinding.model_validate(
                {
                    **{field: None for field in AtomicFinding.model_fields},
                    "file_path": {
                        "value": value,
                        "source": {"start_id": "S000001"},
                        "confidence": 0.8,
                    },
                }
            ).model_dump(mode="json")
            arguments = json.dumps(claims)
        return httpx.Response(
            200,
            json={
                "id": "registry-mock-chat-completion",
                "object": "chat.completion",
                "created": 1,
                "model": "mock-model",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "registry-mock-call",
                                    "type": "function",
                                    "function": {
                                        "name": tool["name"],
                                        "arguments": arguments,
                                    },
                                }
                            ],
                        },
                    }
                ],
                "usage": {"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4},
            },
        )

    http = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    real_async_openai = openai.AsyncOpenAI

    def mock_sdk_client(**kwargs):
        return real_async_openai(**kwargs, http_client=http)

    monkeypatch.setattr(openai, "AsyncOpenAI", mock_sdk_client)
    monkeypatch.setenv("HARNESS_MODEL_MODE", "live")
    monkeypatch.setenv("HARNESS_MODEL_BACKEND", "gateway")
    monkeypatch.setenv("HARNESS_MODEL_BASE_URL", "https://gateway.invalid/v1")
    get_settings.cache_clear()
    model_factory.load_models_config.cache_clear()
    model_factory._build_live.cache_clear()
    try:
        agent = build_agent("intake", durable=False)
        result = await agent.run(
            render_intake_prompt("Synthetic task", {"report": report, "known": {"x": 1}}),
            deps=AgentDeps(repo_path="/synthetic", report_text=report),
        )
    finally:
        model_factory._build_live.cache_clear()
        model_factory.load_models_config.cache_clear()
        get_settings.cache_clear()
        await http.aclose()

    assert isinstance(result.output, ExtractedFinding)
    assert result.output.file_path == value
    assert result.output.evidence[0].quote == report
    assert len(calls) >= 1
    request = next(item for item in calls if item.get("temperature") == 0.0)
    prompt_content = str(request["messages"][-1]["content"])
    assert "report_source_lines" in prompt_content
    assert '\"report\"' not in prompt_content
    tool_schema = next(tool["function"]["parameters"] for tool in request["tools"]
                       if tool["type"] == "function" and tool["function"]["name"] != "load_capability")
    assert "$defs" not in json.dumps(tool_schema)
