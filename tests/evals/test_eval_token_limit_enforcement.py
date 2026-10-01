"""A calibration token overlay must reach the real agent usage limiter."""

import pytest
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.usage import RequestUsage

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.registry import build_agent, load_spec, resolve_agent_config
from infosec_harness.domain.models import VerdictFacts


@pytest.mark.parametrize("ceiling,stopped", [(4096, True), (128000, False)])
async def test_reported_output_tokens_enforce_candidate_limit(ceiling, stopped):
    overlay = {"metadata": {"budgets": {"max_output_tokens": ceiling}}}
    config = resolve_agent_config("verdict", load_spec("verdict", overlay))
    assert config.budget.effective.max_output_tokens == ceiling
    agent = build_agent("verdict", overlay, durable=False)

    def model(messages, info):
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {
            "label": "inconclusive", "confidence": 0.1,
            "rationale": "The environment could not be built.",
            "inconclusive_reason": "environment_unbuildable",
        })], usage=RequestUsage(input_tokens=100, output_tokens=4097))

    with agent.override(model=FunctionModel(model)):
        if stopped:
            with pytest.raises(UsageLimitExceeded, match="output_tokens_limit"):
                await agent.run("evaluate", deps=AgentDeps(repo_path=".", facts=VerdictFacts(
                    environment_ready=False,
                )), usage_limits=config.budget.to_usage_limits())
        else:
            result = await agent.run("evaluate", deps=AgentDeps(repo_path=".", facts=VerdictFacts(
                environment_ready=False,
            )), usage_limits=config.budget.to_usage_limits())
            assert result.usage.output_tokens == 4097
