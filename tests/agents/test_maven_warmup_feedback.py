"""Field-targeted Maven feedback preserves warmup requirements and its retry text."""

from types import SimpleNamespace

import pytest
from pydantic_ai import Agent, ModelRetry
from pydantic_ai.messages import ModelRequest, ModelResponse, RetryPromptPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel

from infosec_harness.agents import ecosystem_contract as contract
from infosec_harness.agents import validators
from infosec_harness.domain.models import EnvironmentSpec

COMPILE = "mvn -B -Dmaven.repo.local=/opt/home/.m2/repository -DskipTests test-compile"


def spec(installs):
    return EnvironmentSpec(
        base_image="maven:3.9-eclipse-temurin-17",
        install_commands=list(installs),
        test_command=contract.MAVEN_TEST_COMMAND,
    )


@pytest.mark.parametrize("framework", sorted(contract.MAVEN_WARMUP_COMMANDS))
@pytest.mark.parametrize(
    "installs",
    [
        [],
        [COMPILE],
        [
            COMPILE,
            "mvn -B -Dmaven.repo.local=/opt/home/.m2/repository org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test -DfailIfNoTests=false",
        ],
    ],
)
def test_missing_warmup_rejection_equivalence_and_preserved_prerequisites(framework, installs):
    candidate = spec(installs)
    before = candidate.model_dump(mode="json")
    new = contract.offline_warmup_violations(candidate, framework)
    assert len(new) == 1
    assert new[0].startswith("install_commands ")
    assert contract.MAVEN_WARMUP_COMMANDS[framework] in new[0].replace("\\'", "'")
    assert len(new[0]) < 1000
    assert candidate.model_dump(mode="json") == before


def test_the_missing_warmup_message_is_byte_stable():
    """The only form of this retry text; production has sent exactly these bytes since the
    field-targeted wording was introduced, so a change here is a retry-bytes provenance change."""
    assert contract.offline_warmup_violations(spec([COMPILE]), "junit4") == [
        "install_commands must include a build-time test that warms the declared Surefire "
        "provider. Keep prerequisite install commands and append this framework-specific "
        f"warm-up command: {contract.MAVEN_WARMUP_COMMANDS['junit4']!r}. An empty test "
        "directory still requires creating, running, and removing the temporary test; an empty "
        "install_commands list cannot warm the provider."
    ]


@pytest.mark.parametrize("framework", sorted(contract.MAVEN_WARMUP_COMMANDS))
def test_canonical_matching_command_accepted_by_combined_guards(framework):
    output = spec([COMPILE, contract.MAVEN_WARMUP_COMMANDS[framework]])
    assert contract.offline_warmup_violations(output, framework) == []
    assert contract.environment_spec_violations(output) == []
    assert contract.install_path_violations(output) == []


@pytest.mark.parametrize("framework", sorted(contract.MAVEN_WARMUP_COMMANDS))
def test_wrong_framework_still_rejected_with_exact_old_text(framework):
    other = next(x for x in contract.MAVEN_WARMUP_COMMANDS if x != framework)
    output = spec([COMPILE, contract.MAVEN_WARMUP_COMMANDS[other]])
    [problem] = contract.offline_warmup_violations(output, framework)
    assert problem.startswith(f"the warm-up's throwaway test is written in {other}")


@pytest.mark.parametrize("command", [contract.PYTEST_TEST_COMMAND, contract.GRADLE_TEST_COMMAND])
def test_nonmaven_feedback_unchanged(command):
    output = EnvironmentSpec(
        base_image="python:3.12-slim" if "pytest" in command else "gradle:8-jdk17",
        install_commands=[],
        test_command=command,
    )
    assert contract.offline_warmup_violations(output) == []
    validators.validate_environment_spec(None, output)


def test_empty_install_feedback_is_field_targeted():
    output = spec([])
    with pytest.raises(ModelRetry) as exc:
        validators.validate_environment_spec(None, output)
    assert exc.value.message.startswith(
        "The environment spec cannot run a probe:\n- install_commands "
    )


def test_good_warmup_is_accepted():
    output = spec([COMPILE, contract.MAVEN_WARMUP_COMMANDS["junit5"]])
    assert validators.validate_environment_spec(None, output) is output


@pytest.mark.parametrize(
    "mutation",
    [
        lambda o: o.model_copy(
            update={
                "test_command": o.test_command.replace(
                    "-Dtest=HarnessProbeTest", "-Dtest={test_file}"
                )
            }
        ),
        lambda o: o.model_copy(
            update={"install_commands": [COMPILE + " || true", contract.MAVEN_WARMUP_COMMAND]}
        ),
    ],
)
def test_independent_command_and_failure_guards_remain_rejections(monkeypatch, mutation):
    output = mutation(spec([COMPILE, contract.MAVEN_WARMUP_COMMAND]))
    assert contract.offline_warmup_violations(output) == []
    with pytest.raises(ModelRetry):
        validators.validate_environment_spec(None, output)


@pytest.mark.asyncio
@pytest.mark.parametrize("framework", sorted(contract.MAVEN_WARMUP_COMMANDS))
async def test_real_sdk_synthetic_retry_converges_preserving_prerequisites(
    monkeypatch, framework
):
    monkeypatch.setattr(validators, "repo_jvm_test_framework", lambda _: framework)
    calls = []
    initial = spec([COMPILE])
    corrected = spec([COMPILE, contract.MAVEN_WARMUP_COMMANDS[framework]])

    def respond(messages, info):
        calls.append(messages)
        value = initial if len(calls) == 1 else corrected
        return ModelResponse(
            parts=[ToolCallPart(info.output_tools[0].name, value.model_dump(mode="json"))]
        )

    agent = Agent(FunctionModel(respond), output_type=EnvironmentSpec, retries=1)
    agent.output_validator(validators.validate_environment_spec)
    result = await agent.run("Plan a test environment.", deps=SimpleNamespace(repo_path=None))
    assert len(calls) == 2 and result.output == corrected
    retry = [
        p
        for m in calls[1]
        if isinstance(m, ModelRequest)
        for p in m.parts
        if isinstance(p, RetryPromptPart)
    ]
    assert len(retry) == 1
    assert "\n- install_commands " in retry[0].content
    assert result.output.install_commands[0] == initial.install_commands[0]
    assert contract.offline_warmup_violations(result.output, framework) == []


@pytest.mark.parametrize("framework", sorted(contract.MAVEN_WARMUP_COMMANDS))
def test_wrong_framework_rejection_keeps_its_feedback(monkeypatch, framework):
    other = next(x for x in contract.MAVEN_WARMUP_COMMANDS if x != framework)
    output = spec([COMPILE, contract.MAVEN_WARMUP_COMMANDS[other]])
    monkeypatch.setattr(validators, "repo_jvm_test_framework", lambda _: framework)
    legacy = "The environment spec cannot run a probe:\n- " + "\n- ".join(
        contract.offline_warmup_violations(output, framework)
    )
    with pytest.raises(ModelRetry) as exc:
        validators.validate_environment_spec(None, output)
    assert exc.value.message == legacy
