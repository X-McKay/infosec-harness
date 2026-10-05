"""Offline OpenAI tool-argument codec regression; client behavior only."""
from __future__ import annotations

import json

import httpx
import pytest
from openai import AsyncOpenAI
from pydantic_ai import Agent
from pydantic_ai.messages import ToolCallPart
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

from infosec_harness.domain.models import ExtractedFinding
from infosec_harness.intake.evidence import extraction_evidence_violations

REPORT = 'alpha\n\tbeta says "quoted" and path \\tmp'


@pytest.mark.parametrize("altered,expected_violations", [(False, []), (True, None)])
async def test_openai_tool_arguments_preserve_literal_quote_through_sdk(
    altered: bool, expected_violations: list[str] | None,
) -> None:
    quote = REPORT.replace("\n\t", " ") if altered else REPORT
    args_json = json.dumps(
        {
            "cwe": "CWE-000",
            "evidence": [{"field": "cwe", "quote": quote, "confidence": 1}],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    wire_response: dict[str, object] = {}
    call_count = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        request_payload = json.loads(request.content)
        output_tool = request_payload["tools"][0]["function"]["name"]
        payload = {
            "id": "synthetic-response",
            "object": "chat.completion",
            "created": 1,
            "model": "synthetic-model",
            "choices": [{
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "synthetic-tool-call",
                        "type": "function",
                        "function": {"name": output_tool, "arguments": args_json},
                    }],
                },
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
        wire = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        wire_response["body"] = wire
        return httpx.Response(200, content=wire, headers={"content-type": "application/json"})

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        client = AsyncOpenAI(
            base_url="https://provider.invalid/v1", api_key="test", http_client=http_client
        )
        model = OpenAIChatModel("synthetic-model", provider=OpenAIProvider(openai_client=client))
        result = await Agent(model, output_type=ExtractedFinding).run("extract the reported finding")
    finally:
        await http_client.aclose()

    parsed_wire = json.loads(wire_response["body"])
    wire_args = parsed_wire["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    assert wire_args == args_json
    assert json.loads(wire_args)["evidence"][0]["quote"] == quote
    assert result.output.evidence[0].quote == quote
    assert call_count == 1

    message_parts = [part for message in result.all_messages()
                     for part in getattr(message, "parts", [])]
    output_calls = [part for part in message_parts if isinstance(part, ToolCallPart)]
    assert len(output_calls) == 1
    sdk_args = output_calls[0].args_as_dict(raise_if_invalid=True)
    assert sdk_args["evidence"][0]["quote"] == quote

    finding = ExtractedFinding.model_validate(sdk_args)
    violations = extraction_evidence_violations(REPORT, finding.model_dump(mode="json"))
    if expected_violations is not None:
        assert violations == expected_violations
    else:
        assert violations
        assert "An evidence quote is not a nonempty verbatim report span." in violations
        assert "Positive evidence requires a nonempty verbatim report span." in violations
