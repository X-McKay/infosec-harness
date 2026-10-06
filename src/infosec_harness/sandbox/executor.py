"""One native PydanticAI provider request; installed in the model-profile image only."""

import asyncio
import os
import sys
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, TypeAdapter, model_validator
from pydantic_ai.messages import ModelMessage, ModelResponse
from pydantic_ai.models import Model, ModelRequestParameters

RESPONSE = TypeAdapter(ModelResponse)
# Leave room for native Temporal activity metadata below its two-megabyte limit.
MAX_INVOCATION_BYTES = 1_000_000
MAX_RESPONSE_BYTES = 512_000


class ModelInvocation(BaseModel):
    # Native PydanticAI usage records preserve provider-specific extension fields.
    provider: Literal["openai", "bedrock"]
    model_name: str
    base_url: str | None = None
    region: str = "us-east-1"
    # Whole-request budget for the provider call, including connect; the default OpenAI
    # client connect timeout of 5 s turned a slow but healthy endpoint into failures.
    timeout_seconds: int = Field(default=110, ge=1)
    messages: list[ModelMessage]
    settings: dict[str, Any] | None
    parameters: ModelRequestParameters

    @model_validator(mode="before")
    @classmethod
    def _known_fields_only(cls, data: Any) -> Any:
        """Refuse, never ignore, a top-level field this image does not know.

        A stale executor image must fail rather than silently drop a budget such as
        ``timeout_seconds``. Not ``extra="forbid"``: that config also reaches the nested
        PydanticAI dataclasses, whose usage records carry provider extension fields.
        """
        if isinstance(data, dict) and (unknown := sorted(set(data) - set(cls.model_fields))):
            raise ValueError(f"unknown model invocation fields {unknown}; rebuild the executor image")
        return data


def provider_model(invocation: ModelInvocation) -> Model:
    """Explicit provider selection, credentials available only through OpenShell."""
    if invocation.provider == "openai":
        from openai import AsyncOpenAI
        from pydantic_ai.models.openai import OpenAIChatModel
        from pydantic_ai.profiles.openai import OpenAIModelProfile
        from pydantic_ai.providers.openai import OpenAIProvider

        endpoint = urlsplit(invocation.base_url or "")
        if (
            endpoint.scheme not in ("http", "https")
            or not endpoint.hostname
            or endpoint.username is not None
            or endpoint.password is not None
            or endpoint.fragment
        ):
            raise ValueError(
                "An explicit OpenShell-allowed model endpoint without credentials is required"
            )
        # SDK retries would resubmit an unknown provider side effect.
        client = AsyncOpenAI(
            api_key=os.environ.get("OPENAI_API_KEY", "openshell"),
            base_url=invocation.base_url,
            max_retries=0,
            timeout=float(invocation.timeout_seconds),
        )
        return OpenAIChatModel(
            invocation.model_name,
            provider=OpenAIProvider(openai_client=client),
            profile=OpenAIModelProfile(
                supports_inline_system_prompts=False,
                openai_chat_supports_multiple_system_messages=False,
            ),
        )
    if invocation.provider == "bedrock":
        import boto3
        from botocore.config import Config
        from pydantic_ai.models.bedrock import BedrockConverseModel
        from pydantic_ai.providers.bedrock import BedrockProvider

        # Suppress host metadata discovery: credentials must be native provider env values.
        client = boto3.client(
            "bedrock-runtime",
            region_name=invocation.region,
            aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
            aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
            # One attempt, bounded by the same budget as the OpenAI client (botocore's
            # default is 60 s per connect and per read, regardless of the budget).
            config=Config(
                retries={"total_max_attempts": 1},
                connect_timeout=invocation.timeout_seconds,
                read_timeout=invocation.timeout_seconds,
            ),
        )
        return BedrockConverseModel(
            invocation.model_name, provider=BedrockProvider(bedrock_client=client)
        )
    raise ValueError("Unsupported model provider")


async def execute(invocation: ModelInvocation) -> bytes:
    model = provider_model(invocation)
    async with model:
        response = await model.request(
            model.prepare_messages(invocation.messages, invocation.parameters),
            invocation.settings,
            invocation.parameters,
        )
    encoded = RESPONSE.dump_json(response)
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise ValueError("Model response exceeds the durable payload budget")
    return encoded


def main() -> None:
    data = sys.stdin.buffer.read(MAX_INVOCATION_BYTES + 1)
    if len(data) > MAX_INVOCATION_BYTES:
        raise ValueError("Model invocation exceeds the durable payload budget")
    invocation = ModelInvocation.model_validate_json(data)
    sys.stdout.buffer.write(asyncio.run(execute(invocation)))


if __name__ == "__main__":
    main()
