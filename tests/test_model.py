"""Native message fidelity and provider SDK retry constraints."""

from types import SimpleNamespace

import pytest
from pydantic_ai.messages import ModelRequest, ModelResponse, TextPart, ToolCallPart, UserPromptPart
from pydantic_ai.models import ModelRequestParameters
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.tools import ToolDefinition
from test_agent import FakeOpenShell

from infosec_harness import model_executor
from infosec_harness.model import RESPONSE, ModelInvocation, OpenShellModel
from infosec_harness.openshell import CommandResult


async def test_native_message_tools_and_usage_roundtrip(monkeypatch):
    request = ModelInvocation(
        provider="openai",
        model_name="fixture",
        messages=[ModelRequest(parts=[UserPromptPart("inspect")])],
        settings={"temperature": 0},
        parameters=ModelRequestParameters(
            function_tools=[ToolDefinition(name="read", parameters_json_schema={"type": "object"})],
        ),
    )
    request = ModelInvocation.model_validate_json(request.model_dump_json())

    def respond(messages, info):
        assert messages[0].parts[0].content == "inspect"
        assert info.function_tools[0].name == "read"
        return ModelResponse(parts=[ToolCallPart("read", {"path": "sink.py"}, tool_call_id="x")])

    monkeypatch.setattr(model_executor, "provider_model", lambda _: FunctionModel(respond))
    response = RESPONSE.validate_json(await model_executor.execute(request))
    assert response.parts[0].args == {"path": "sink.py"}
    assert response.usage.input_tokens > 0


async def test_transport_runs_only_in_separate_model_sandbox(monkeypatch):
    shell = FakeOpenShell()

    async def execute(sandbox, command, **kwargs):
        shell.executions.append((sandbox, command, kwargs))
        invocation = ModelInvocation.model_validate_json(kwargs["stdin"])
        assert invocation.provider == "openai"
        assert invocation.base_url == "https://configured.example/v1"
        return CommandResult(
            0, RESPONSE.dump_json(ModelResponse(parts=[TextPart("ok")])).decode(), ""
        )

    shell.execute = execute
    monkeypatch.setattr(
        "infosec_harness.model.activity.info",
        lambda: SimpleNamespace(workflow_id="run", activity_id="7"),
    )
    adapter = OpenShellModel(shell, "fixture", base_url="https://configured.example/v1")
    result = await adapter.request([], None, ModelRequestParameters())
    assert result.parts[0].content == "ok"
    sandbox, command, kwargs = shell.executions[0]
    assert sandbox.profile == "model"
    assert command == ["python", "-I", "-m", "infosec_harness.model_executor"]
    assert kwargs["operation_id"] == "model:7"


async def test_failed_executor_exit_is_a_named_terminal_error_with_detail(monkeypatch):
    """A non-zero executor exit has a complete receipt: raise ModelExecutorError carrying the
    last stderr line so reports show the cause (observed live: sandbox DNS ConnectError)."""
    from infosec_harness.model import ModelExecutorError

    shell = FakeOpenShell()

    async def execute(sandbox, command, **kwargs):
        return CommandResult(1, "", "Traceback...\nhttpcore2.ConnectError: [Errno -5] No address")

    shell.execute = execute
    monkeypatch.setattr(
        "infosec_harness.model.activity.info",
        lambda: SimpleNamespace(workflow_id="run", activity_id="7"),
    )
    adapter = OpenShellModel(shell, "fixture", base_url="https://configured.example/v1")
    with pytest.raises(ModelExecutorError, match=r"exit 1.*ConnectError.*No address"):
        await adapter.request([], None, ModelRequestParameters())


async def test_production_model_refuses_non_temporal_inference():
    with pytest.raises(RuntimeError, match="activity context"):
        await OpenShellModel(FakeOpenShell(), "fixture").request([], None, ModelRequestParameters())


def test_provider_has_no_sdk_retries(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "native-injected-placeholder")
    invocation = ModelInvocation(
        provider="openai",
        model_name="fixture",
        base_url="https://configured.example/v1",
        messages=[],
        settings=None,
        parameters=ModelRequestParameters(),
    )
    model = model_executor.provider_model(invocation)
    assert model.provider.client.max_retries == 0


def test_no_ambient_bedrock_credentials_fallback(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    invocation = ModelInvocation(
        provider="bedrock",
        model_name="fixture",
        messages=[],
        settings=None,
        parameters=ModelRequestParameters(),
    )
    with pytest.raises(KeyError, match="AWS_ACCESS_KEY_ID"):
        model_executor.provider_model(invocation)


@pytest.mark.parametrize(
    "endpoint", [None, "", "https://secret@model.example/v1", "file:///tmp/model"]
)
def test_provider_never_falls_back_to_default_endpoint(endpoint):
    invocation = ModelInvocation(
        provider="openai",
        model_name="fixture",
        base_url=endpoint,
        messages=[],
        settings=None,
        parameters=ModelRequestParameters(),
    )
    with pytest.raises(ValueError, match="explicit OpenShell-allowed model endpoint"):
        model_executor.provider_model(invocation)


def test_explicit_keyless_endpoint_uses_native_placeholder(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    invocation = ModelInvocation(
        provider="openai",
        model_name="fixture",
        base_url="http://model.example/v1",
        messages=[],
        settings=None,
        parameters=ModelRequestParameters(),
    )
    model = model_executor.provider_model(invocation)
    assert model.provider.client.api_key == "openshell"


async def test_native_openai_tools_messages_and_usage_with_mock_transport(monkeypatch):
    monkeypatch.setattr("pydantic_ai.models.ALLOW_MODEL_REQUESTS", True)
    import httpx
    from openai import AsyncOpenAI
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.openai import OpenAIProvider

    def transport(request):
        import json

        body = json.loads(request.content)
        assert body["model"] == "configured-model"
        assert body["messages"][-1]["content"] == "inspect sink"
        assert body["tools"][0]["function"]["name"] == "read"
        return httpx.Response(
            200,
            json={
                "id": "response",
                "object": "chat.completion",
                "created": 1,
                "model": "configured-model",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "id": "call",
                                    "type": "function",
                                    "function": {"name": "read", "arguments": '{"path":"sink.py"}'},
                                }
                            ],
                        },
                    }
                ],
                "usage": {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as http_client:
        client = AsyncOpenAI(
            api_key="openshell",
            base_url="https://configured.example/v1",
            max_retries=0,
            http_client=http_client,
        )
        monkeypatch.setattr(
            model_executor,
            "provider_model",
            lambda invocation: OpenAIChatModel(
                invocation.model_name, provider=OpenAIProvider(openai_client=client)
            ),
        )
        invocation = ModelInvocation(
            provider="openai",
            model_name="configured-model",
            base_url="https://configured.example/v1",
            messages=[ModelRequest(parts=[UserPromptPart("inspect sink")])],
            settings=None,
            parameters=ModelRequestParameters(
                function_tools=[
                    ToolDefinition(
                        name="read",
                        parameters_json_schema={
                            "type": "object",
                            "properties": {"path": {"type": "string"}},
                            "required": ["path"],
                        },
                    )
                ]
            ),
        )
        response = RESPONSE.validate_json(await model_executor.execute(invocation))
        assert response.parts[0].tool_call_id == "call"
        assert response.parts[0].args == '{"path":"sink.py"}'
        assert response.usage.input_tokens == 12
        assert response.usage.output_tokens == 4


async def test_executor_response_budget_rejects_before_activity_return(monkeypatch):
    monkeypatch.setattr(
        model_executor,
        "provider_model",
        lambda _: FunctionModel(
            lambda messages, info: ModelResponse(
                parts=[TextPart("x" * model_executor.MAX_RESPONSE_BYTES)]
            )
        ),
    )
    invocation = ModelInvocation(
        provider="openai",
        model_name="fixture",
        messages=[],
        settings=None,
        parameters=ModelRequestParameters(),
    )
    with pytest.raises(ValueError, match="response exceeds the durable payload budget"):
        await model_executor.execute(invocation)


async def test_adapter_rejects_oversized_input_before_sandbox_creation(monkeypatch):
    shell = FakeOpenShell()
    creations = []

    async def create(*args, **kwargs):
        creations.append(args)
        raise AssertionError("Oversized request must not allocate resources")

    shell.create = create
    monkeypatch.setattr(
        "infosec_harness.model.activity.info",
        lambda: SimpleNamespace(workflow_id="run", activity_id="7"),
    )
    with pytest.raises(ValueError, match="invocation exceeds the durable payload budget"):
        await OpenShellModel(shell, "fixture").request(
            [ModelRequest(parts=[UserPromptPart("x" * model_executor.MAX_INVOCATION_BYTES)])],
            None,
            ModelRequestParameters(),
        )
    assert creations == []


async def test_adapter_rejects_oversized_native_response(monkeypatch):
    shell = FakeOpenShell()

    async def execute(*args, **kwargs):
        return CommandResult(0, "x" * (model_executor.MAX_RESPONSE_BYTES + 1), "")

    shell.execute = execute
    monkeypatch.setattr(
        "infosec_harness.model.activity.info",
        lambda: SimpleNamespace(workflow_id="run", activity_id="7"),
    )
    with pytest.raises(ValueError, match="response exceeds the durable payload budget"):
        await OpenShellModel(shell, "fixture").request([], None, ModelRequestParameters())
