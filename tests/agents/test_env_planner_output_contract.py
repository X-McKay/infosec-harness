"""Regressions for an omitted install plan repeatedly passing structural validation."""

from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from pydantic_ai import Agent
from pydantic_ai.messages import ModelRequest, ModelResponse, RetryPromptPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel

from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.runtime import stubs as contract
from infosec_harness.runtime import validators
from infosec_harness.runtime.outputs import PlannedEnvironmentOutput


def omitted_maven_plan() -> dict[str, object]:
    # The retained failure supplied these three fields four times. The shared domain model
    # silently supplied [], although an offline Maven probe requires a build-time warmup.
    return {
        "base_image": "maven:3.9-eclipse-temurin-17",
        "system_packages": [],
        "test_command": contract.MAVEN_TEST_COMMAND,
    }


def test_model_facing_plan_rejects_the_retained_omission() -> None:
    with pytest.raises(ValidationError) as error:
        PlannedEnvironmentOutput.model_validate(omitted_maven_plan())
    assert any(
        entry["loc"] == ("install_commands",) and entry["type"] == "missing"
        for entry in error.value.errors()
    )
    assert "install_commands" in PlannedEnvironmentOutput.model_json_schema()["required"]


def test_persisted_environment_keeps_its_historical_default() -> None:
    legacy = EnvironmentSpec.model_validate(omitted_maven_plan())
    assert legacy.install_commands == [] and legacy.env == {}
    assert "install_commands" not in EnvironmentSpec.model_json_schema()["required"]
    assert EnvironmentSpec.model_validate(legacy.model_dump()) == legacy


@pytest.mark.parametrize("invalid", [None, "", {}])
def test_an_explicit_install_plan_must_be_an_array(invalid: object) -> None:
    with pytest.raises(ValidationError):
        PlannedEnvironmentOutput.model_validate(
            {**omitted_maven_plan(), "install_commands": invalid}
        )


def test_explicit_empty_installation_remains_allowed_outside_maven() -> None:
    output = PlannedEnvironmentOutput(
        base_image="node:22-slim",
        install_commands=[],
        env={},
        test_command="node --test {test_file}",
    )
    assert validators.validate_environment_spec(None, output) is output
    assert isinstance(output, EnvironmentSpec)
    assert EnvironmentSpec.model_validate(output.model_dump()).install_commands == []


def test_explicit_empty_maven_plan_is_left_for_build_and_smoke_execution() -> None:
    output = PlannedEnvironmentOutput.model_validate(
        {**omitted_maven_plan(), "install_commands": []}
    )
    assert validators.validate_environment_spec(None, output) is output


@pytest.mark.asyncio
async def test_real_sdk_requests_the_missing_field_then_accepts_a_complete_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []
    validated = []
    prerequisites = "mvn -B -Dmaven.repo.local=/opt/home/.m2/repository -DskipTests test-compile"
    corrected = {
        **omitted_maven_plan(),
        "install_commands": [prerequisites, contract.MAVEN_WARMUP_COMMANDS["junit5"]],
    }

    def respond(messages, info):
        calls.append(messages)
        assert "install_commands" in info.output_tools[0].parameters_json_schema["required"]
        arguments = omitted_maven_plan() if len(calls) == 1 else corrected
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, arguments)])

    agent = Agent(FunctionModel(respond), output_type=PlannedEnvironmentOutput, retries=1)

    @agent.output_validator
    def validate(ctx, output):
        validated.append(output)
        return validators.validate_environment_spec(ctx, output)

    result = await agent.run("Plan a test environment.", deps=SimpleNamespace(repo_path=None))
    assert len(calls) == 2 and len(validated) == 1
    retries = [
        part
        for message in calls[1]
        if isinstance(message, ModelRequest)
        for part in message.parts
        if isinstance(part, RetryPromptPart)
    ]
    assert len(retries) == 1 and isinstance(retries[0].content, list)
    assert any(
        entry["loc"] == ("install_commands",) and entry["type"] == "missing"
        for entry in retries[0].content
    )
    assert result.output.install_commands == corrected["install_commands"]
    assert validators.validate_environment_spec(None, result.output) is result.output
    assert (
        EnvironmentSpec.model_validate(result.output.model_dump()).model_dump()
        == result.output.model_dump()
    )
