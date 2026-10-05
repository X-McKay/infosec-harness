"""Regression tests for model-facing output schemas and verdict tool filtering."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from pydantic import ValidationError
from pydantic_ai.exceptions import UnexpectedModelBehavior
from pydantic_ai.messages import ModelMessage, ModelResponse, ToolCallPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

from infosec_harness.domain.models import (
    DiagnosisKind,
    EnvironmentSpec,
    FindingContext,
    Reachability,
    Verdict,
    VerdictFacts,
    VerdictLabel,
)
from infosec_harness.inference.executor.compat import CompatOpenAIChatModel
from infosec_harness.runtime.deps import AgentDeps
from infosec_harness.runtime.outputs import (
    VERDICT_OUTPUTS,
    ContextOutput,
    InconclusiveOutput,
    NegativeOutput,
    PartialEnvironmentOutput,
    PositiveOutput,
    allowed_verdict_labels,
    prepare_verdict_tools,
)
from infosec_harness.runtime.registry import build_agent


def _partial_payload(**changes: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "base_image": "python:3.12-slim",
        "test_command": "python -m pytest -q {test_file}",
        "scope": "partial",
        "module_path": "services/api",
    }
    payload.update(changes)
    return payload


@pytest.mark.parametrize(
    "changes, missing",
    [
        ({"scope": "full"}, "scope"),
        ({"scope": None}, "scope"),
        ({"module_path": ""}, "module_path"),
        ({"module_path": None}, "module_path"),
    ],
)
def test_partial_environment_output_requires_partial_scope_and_module(
    changes: dict[str, object], missing: str,
) -> None:
    with pytest.raises(ValidationError, match=missing):
        PartialEnvironmentOutput.model_validate(_partial_payload(**changes))


@pytest.mark.parametrize("field", ["scope", "module_path"])
def test_partial_environment_output_does_not_inherit_domain_defaults(field: str) -> None:
    payload = _partial_payload()
    del payload[field]
    with pytest.raises(ValidationError, match=field):
        PartialEnvironmentOutput.model_validate(payload)


def test_context_rejects_neutralized_prose_without_cited_control() -> None:
    with pytest.raises(ValidationError, match="sanitizers"):
        ContextOutput.model_validate({
            "summary": "A parameterized query neutralizes the input.",
            "source": None,
            "sink": None,
            "path": [],
            "sanitizers": [],
            "reachability": "neutralized",
            "reachability_rationale": "The prose says the query uses a bound parameter.",
        })


def test_context_accepts_neutralized_with_a_cited_control() -> None:
    output = ContextOutput.model_validate({
        "summary": "The bound parameter neutralizes the input.",
        "source": None,
        "sink": None,
        "path": [],
        "sanitizers": [{
            "file_path": "app/db.py", "start_line": 18, "end_line": 18,
            "note": "Bound parameter passed separately from SQL text.",
        }],
        "reachability": "neutralized",
        "reachability_rationale": "The cited call binds rather than interpolates input.",
    })
    assert output.sanitizers[0].file_path == "app/db.py"


def test_inconclusive_output_requires_a_reason() -> None:
    with pytest.raises(ValidationError, match="inconclusive_reason"):
        InconclusiveOutput.model_validate({
            "label": "inconclusive", "confidence": 0.2, "rationale": "Evidence is incomplete.",
        })


@pytest.mark.parametrize(
    "facts",
    [
        VerdictFacts(environment_ready=True, reachability=Reachability.unreachable),
        VerdictFacts(environment_ready=False),
        VerdictFacts(
            environment_ready=True, oracle_fired=True,
            last_diagnosis=DiagnosisKind.probe_defect,
        ),
        VerdictFacts(
            environment_ready=True, last_diagnosis=DiagnosisKind.valid_negative,
            precondition_reached=False, sink_returned=True,
        ),
    ],
    ids=[
        "static-unreachable", "environment-failed", "oracle-on-defective-probe",
        "valid-negative-without-precondition",
    ],
)
def test_observed_failure_facts_offer_only_inconclusive(facts: VerdictFacts) -> None:
    assert allowed_verdict_labels(facts) == {VerdictLabel.inconclusive}
    offered = prepare_verdict_tools(
        SimpleNamespace(deps=AgentDeps(repo_path="/snapshot", facts=facts)),
        [SimpleNamespace(name=output.name) for output in VERDICT_OUTPUTS],
    )
    assert [tool.name for tool in offered] == ["final_result_inconclusive"]


@pytest.mark.parametrize(
    "facts, expected",
    [
        (
            VerdictFacts(
                environment_ready=True, oracle_fired=True,
                last_diagnosis=DiagnosisKind.valid_positive,
            ),
            {VerdictLabel.inconclusive, VerdictLabel.potentially_exploitable},
        ),
        (
            VerdictFacts(
                environment_ready=True, oracle_fired=False, precondition_reached=True,
                sink_returned=True, last_diagnosis=DiagnosisKind.valid_negative,
            ),
            {VerdictLabel.inconclusive, VerdictLabel.likely_not_exploitable},
        ),
    ],
    ids=["valid-positive", "valid-negative"],
)
def test_corroborated_facts_offer_the_corresponding_claim_and_inconclusive(
    facts: VerdictFacts, expected: set[VerdictLabel],
) -> None:
    assert allowed_verdict_labels(facts) == expected


def _reply(tool_name: str, **changes: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "label": "potentially_exploitable",
        "confidence": 0.9,
        "rationale": "The valid probe fired the oracle.",
        "inconclusive_reason": None,
        "evidence": [],
    }
    payload.update(changes)
    return {"tool_name": tool_name, "arguments": payload}


async def _run_scripted_verdict(
    tmp_path, facts: VerdictFacts, scripted: dict[str, object], seen: list[set[str]],
):
    def respond(_messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        seen.append({tool.name for tool in info.output_tools})
        return ModelResponse(parts=[ToolCallPart(
            str(scripted["tool_name"]), scripted["arguments"],
        )])

    agent = build_agent("verdict", durable=False)
    with agent.override(model=FunctionModel(respond)):
        return await agent.run(
            "Decide from the controller-recorded facts.",
            deps=AgentDeps(repo_path=str(tmp_path), facts=facts),
        )


@pytest.mark.parametrize(
    "facts, scripted, output_type, expected_tools",
    [
        (
            VerdictFacts(
                environment_ready=True, oracle_fired=True,
                last_diagnosis=DiagnosisKind.valid_positive,
            ),
            _reply("final_result_positive"),
            PositiveOutput,
            {"final_result_positive", "final_result_inconclusive"},
        ),
        (
            VerdictFacts(
                environment_ready=True, precondition_reached=True, sink_returned=True,
                last_diagnosis=DiagnosisKind.valid_negative,
            ),
            _reply(
                "final_result_negative", label="likely_not_exploitable", confidence=0.8,
                rationale="The valid negative reached and returned from the sink.",
            ),
            NegativeOutput,
            {"final_result_negative", "final_result_inconclusive"},
        ),
        (
            VerdictFacts(environment_ready=False),
            _reply(
                "final_result_inconclusive", label="inconclusive", confidence=0.1,
                rationale="The environment did not build.",
                inconclusive_reason="environment_unbuildable",
            ),
            InconclusiveOutput,
            {"final_result_inconclusive"},
        ),
    ],
    ids=["positive", "negative", "inconclusive"],
)
async def test_build_agent_run_exposes_filtered_tools_and_returns_typed_subtype(
    tmp_path, facts: VerdictFacts, scripted: dict[str, object], output_type: type[Verdict],
    expected_tools: set[str],
) -> None:
    seen: list[set[str]] = []
    result = await _run_scripted_verdict(tmp_path, facts, scripted, seen)
    assert isinstance(result.output, output_type)
    assert seen == [expected_tools]


@pytest.mark.parametrize(
    "facts, scripted",
    [
        (
            VerdictFacts(environment_ready=False),
            _reply(
                "final_result_inconclusive", label="inconclusive", confidence=0.1,
                rationale="The environment did not build.", inconclusive_reason=None,
            ),
        ),
        (
            VerdictFacts(environment_ready=False),
            _reply("final_result_positive"),
        ),
    ],
    ids=["missing-inconclusive-reason", "unoffered-positive-claim"],
)
async def test_build_agent_run_rejects_invalid_or_unoffered_output(
    tmp_path, facts: VerdictFacts, scripted: dict[str, object],
) -> None:
    seen: list[set[str]] = []
    with pytest.raises(UnexpectedModelBehavior):
        await _run_scripted_verdict(tmp_path, facts, scripted, seen)
    assert seen
    assert all(tools == {"final_result_inconclusive"} for tools in seen)


def test_persisted_domain_models_remain_compatible_with_old_payloads() -> None:
    environment = EnvironmentSpec.model_validate({
        "base_image": "python:3.12-slim", "test_command": "pytest {test_file}",
    })
    context = FindingContext.model_validate({
        "summary": "No path was established.",
        "reachability": "unknown",
        "reachability_rationale": "Historical records did not store cited evidence fields.",
    })
    verdict = Verdict.model_validate({
        "label": "potentially_exploitable", "confidence": 0.7,
        "rationale": "Historical records omitted inconclusive_reason.",
    })

    assert environment.scope == "full" and environment.module_path is None
    assert context.source is None and context.path == [] and context.sanitizers == []
    assert verdict.inconclusive_reason is None


_PROVIDER_CASES = [
    pytest.param(
        VerdictFacts(environment_ready=False),
        "final_result_inconclusive",
        {
            "label": "inconclusive", "confidence": 0.1,
            "rationale": "The environment did not build.",
            "inconclusive_reason": "environment_unbuildable", "evidence": [],
        },
        {"final_result_inconclusive"},
        InconclusiveOutput,
        id="invalid-facts-only-inconclusive",
    ),
    pytest.param(
        VerdictFacts(
            environment_ready=True, oracle_fired=True,
            last_diagnosis=DiagnosisKind.valid_positive,
        ),
        "final_result_positive",
        {
            "label": "potentially_exploitable", "confidence": 0.9,
            "rationale": "The valid probe fired the oracle.",
            "inconclusive_reason": None, "evidence": [],
        },
        {"final_result_inconclusive", "final_result_positive"},
        PositiveOutput,
        id="valid-positive",
    ),
    pytest.param(
        VerdictFacts(
            environment_ready=True, precondition_reached=True, sink_returned=True,
            last_diagnosis=DiagnosisKind.valid_negative,
        ),
        "final_result_negative",
        {
            "label": "likely_not_exploitable", "confidence": 0.8,
            "rationale": "The valid negative reached and returned from the sink.",
            "inconclusive_reason": None, "evidence": [],
        },
        {"final_result_inconclusive", "final_result_negative"},
        NegativeOutput,
        id="valid-negative",
    ),
]


def _assert_verdict_wire_contract(
    tools: list[dict[str, Any]], expected_names: set[str], *, bedrock: bool,
) -> None:
    if bedrock:
        definitions = {
            tool["toolSpec"]["name"]: tool["toolSpec"]
            for tool in tools
            if "toolSpec" in tool
        }
        schema = definitions["final_result_inconclusive"]["inputSchema"]["json"]
    else:
        definitions = {tool["function"]["name"]: tool["function"] for tool in tools}
        schema = definitions["final_result_inconclusive"]["parameters"]
    offered = {name for name in definitions if name.startswith("final_result_")}
    assert offered == expected_names
    assert "inconclusive_reason" in schema["required"]


@pytest.mark.parametrize(
    "facts, response_tool, arguments, expected_names, output_type", _PROVIDER_CASES,
)
async def test_openai_verdict_tools_round_trip_through_real_provider_mapping(
    tmp_path, facts: VerdictFacts, response_tool: str, arguments: dict[str, Any],
    expected_names: set[str], output_type: type[Verdict],
) -> None:
    """The OpenAI-compatible request carries the filtered, strict verdict schemas."""
    from openai import AsyncOpenAI
    from pydantic_ai.providers.openai import OpenAIProvider

    calls: list[dict[str, Any]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body)
        _assert_verdict_wire_contract(body["tools"], expected_names, bedrock=False)
        return httpx.Response(200, json={
            "id": "verdict-response", "object": "chat.completion", "created": 1,
            "model": "test-model",
            "choices": [{
                "index": 0, "finish_reason": "tool_calls",
                "message": {"role": "assistant", "content": None, "tool_calls": [{
                    "id": "verdict-tool", "type": "function",
                    "function": {"name": response_tool, "arguments": json.dumps(arguments)},
                }]},
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        client = AsyncOpenAI(
            base_url="https://provider.invalid/v1", api_key="test", http_client=http_client,
        )
        model = CompatOpenAIChatModel(
            "test-model", provider=OpenAIProvider(openai_client=client),
        )
        agent = build_agent("verdict", durable=False)
        with agent.override(model=model):
            result = await agent.run(
                "Decide from controller facts.",
                deps=AgentDeps(repo_path=str(tmp_path), facts=facts),
            )
    finally:
        await http_client.aclose()

    assert len(calls) == 1
    assert isinstance(result.output, output_type)
    assert isinstance(result.output, Verdict)


@pytest.mark.parametrize(
    "facts, response_tool, arguments, expected_names, output_type", _PROVIDER_CASES,
)
async def test_bedrock_verdict_tools_round_trip_through_real_provider_mapping(
    tmp_path, facts: VerdictFacts, response_tool: str, arguments: dict[str, Any],
    expected_names: set[str], output_type: type[Verdict],
) -> None:
    """The Bedrock Converse request carries the same filtered, strict verdict schemas."""
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
            _assert_verdict_wire_contract(
                request["toolConfig"]["tools"], expected_names, bedrock=True,
            )
            return {
                "output": {"message": {"role": "assistant", "content": [{
                    "toolUse": {
                        "toolUseId": "verdict-tool", "name": response_tool,
                        "input": arguments,
                    },
                }]}},
                "stopReason": "tool_use",
                "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
                "metrics": {"latencyMs": 1},
                "ResponseMetadata": {"RequestId": "verdict-request"},
            }

    client = Client()
    model = BedrockConverseModel(
        "anthropic.claude-sonnet-5", provider=BedrockProvider(bedrock_client=client),
    )
    agent = build_agent("verdict", durable=False)
    with agent.override(model=model):
        result = await agent.run(
            "Decide from controller facts.",
            deps=AgentDeps(repo_path=str(tmp_path), facts=facts),
        )

    assert len(client.calls) == 1
    assert isinstance(result.output, output_type)
    assert isinstance(result.output, Verdict)
