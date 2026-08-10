"""Small provider protocol plus offline fake/replay and lazy native adapters."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from .domain import ModelRequest, ModelResult, Usage
from .policy import digest


class ProviderError(RuntimeError):
    def __init__(self, category: str, message: str) -> None:
        super().__init__(message)
        self.category = category


class ProviderCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid")
    structured_output: bool = True
    tools: bool = False
    caching: bool = False
    reasoning_controls: bool = False
    supported_options: set[str] = Field(default_factory=set)


def validate_provider_request(backend: ModelBackend, request: ModelRequest) -> None:
    capabilities = backend.capabilities
    if not capabilities.structured_output:
        raise ProviderError("unsupported", "backend does not support structured output")
    unsupported = set(request.provider_options).difference(capabilities.supported_options)
    if unsupported:
        raise ProviderError("unsupported", f"unsupported provider options: {sorted(unsupported)}")


class ModelBackend(Protocol):
    name: str
    capabilities: ProviderCapabilities

    async def generate(self, request: ModelRequest) -> ModelResult: ...


class ReplayBackend:
    name = "replay"
    capabilities = ProviderCapabilities(structured_output=True)

    def __init__(self, fixture: Path) -> None:
        self.fixture = fixture

    async def generate(self, request: ModelRequest) -> ModelResult:
        data = json.loads(self.fixture.read_text(encoding="utf-8"))
        expected = data.get("request_digest")
        actual = digest(request.model_dump_json())
        if expected and expected != actual:
            raise ProviderError("replay_miss", "replay fixture does not match the request")
        if "error" in data:
            raise ProviderError(str(data["error"]), "replayed provider outcome")
        return ModelResult(
            visible_output=data["result"],
            usage=Usage.model_validate(data.get("usage", {})),
            provider="replay",
            model_version=data.get("model_version", "replay"),
            provider_request_id=data.get("provider_request_id"),
            replay_fixture_id=data.get("fixture_id"),
        )


class FakeBackend:
    name = "fake"
    capabilities = ProviderCapabilities(structured_output=True)

    def __init__(self, output: dict[str, Any] | ProviderError, usage: Usage | None = None) -> None:
        self.output, self.usage, self.requests = output, usage or Usage(), []

    async def generate(self, request: ModelRequest) -> ModelResult:
        self.requests.append(request)
        if isinstance(self.output, ProviderError):
            raise self.output
        return ModelResult(
            visible_output=self.output,
            usage=self.usage,
            provider="fake",
            model_version="fake-v1",
            provider_request_id="fake-request",
        )


class OpenAIBackend:
    """Direct, optional adapter. It is lazy-imported and never selected by default."""

    name = "openai"
    capabilities = ProviderCapabilities(
        structured_output=True,
        tools=True,
        caching=True,
        reasoning_controls=True,
        supported_options={"reasoning_effort", "store"},
    )

    async def generate(self, request: ModelRequest) -> ModelResult:
        try:
            from openai import AsyncOpenAI
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ProviderError("unsupported", "install the openai extra") from exc
        try:  # pragma: no cover - live calls are intentionally not in ordinary tests
            client = AsyncOpenAI()
            response = await client.responses.create(
                model=request.model,
                input=[{"role": "system", "content": request.system}, {"role": "user", "content": request.evidence.model_dump_json()}],
                text={"format": {"type": "json_schema", "name": "disposition", "schema": request.output_schema, "strict": True}},
            )
            return ModelResult(
                visible_output=json.loads(response.output_text),
                usage=Usage(
                    input_tokens=getattr(response.usage, "input_tokens", 0),
                    output_tokens=getattr(response.usage, "output_tokens", 0),
                ),
                provider="openai",
                model_version=getattr(response, "model", request.model),
                provider_request_id=getattr(response, "_request_id", None),
            )
        except TimeoutError as exc:
            raise ProviderError("timeout", "OpenAI request timed out") from exc
        except Exception as exc:
            raise ProviderError("provider_error", str(exc)) from exc


class AnthropicBackend:
    name = "anthropic"
    capabilities = ProviderCapabilities(
        structured_output=True,
        tools=True,
        caching=True,
        supported_options={"thinking", "cache_control"},
    )

    async def generate(self, request: ModelRequest) -> ModelResult:
        try:
            from anthropic import AsyncAnthropic
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ProviderError("unsupported", "install the anthropic extra") from exc
        try:  # pragma: no cover - live calls are intentionally not in ordinary tests
            client = AsyncAnthropic()
            response = await client.messages.create(
                model=request.model,
                max_tokens=request.budget.max_output_tokens,
                system=request.system,
                messages=[{"role": "user", "content": request.evidence.model_dump_json()}],
            )
            text = "".join(block.text for block in response.content if getattr(block, "type", "") == "text")
            return ModelResult(
                visible_output=json.loads(text),
                usage=Usage(input_tokens=response.usage.input_tokens, output_tokens=response.usage.output_tokens),
                provider="anthropic",
                model_version=response.model,
                provider_request_id=getattr(response, "_request_id", None),
            )
        except TimeoutError as exc:
            raise ProviderError("timeout", "Anthropic request timed out") from exc
        except Exception as exc:
            raise ProviderError("provider_error", str(exc)) from exc
