"""Plans obey one sandbox policy; executed controls determine whether recipes work."""

import subprocess
import sys
from types import SimpleNamespace

import pytest
from pydantic_ai import ModelRetry

from infosec_harness.domain.models import EnvironmentSpec, StackFingerprint
from infosec_harness.graph.workloads import _canary_result
from infosec_harness.runtime import registry
from infosec_harness.runtime.stubs import _env_plan
from infosec_harness.runtime.validators import validate_environment_spec
from infosec_harness.sandbox import docker
from infosec_harness.sandbox.controls import parse_control_result
from infosec_harness.sandbox.process import ProcessResult
from infosec_harness.settings import get_settings


@pytest.mark.parametrize("name", ["env-planner", "build-repair", "partial-build"])
def test_worker_binds_image_policy_and_validation_does_not_read_settings(name, monkeypatch):
    monkeypatch.setattr(get_settings(), "allowed_base_registries", ["docker.io/library"])
    resolved = registry.resolve_agent_config(name, registry.load_spec(name))
    policy = resolved.effective_spec["metadata"]["output_validation"]
    assert policy["allowed_base_registries"] == ["docker.io/library"]
    agent = registry.build_agent(name, durable=False)
    validate = next(v.function for v in agent._output_validators
                    if v.function.__name__ == "validate_environment")

    def unexpected_settings_read():
        pytest.fail("durable output validation must use its frozen operator policy")

    monkeypatch.setattr("infosec_harness.sandbox.policy.get_settings", unexpected_settings_read)
    accepted = EnvironmentSpec(base_image="python:3.12", test_command="pytest {test_file}")
    assert validate(None, accepted) is accepted
    rejected = accepted.model_copy(update={"base_image": "public.ecr.aws/unapproved:latest"})
    with pytest.raises(ModelRetry, match="allowlist"):
        validate(None, rejected)


@pytest.mark.parametrize("name", ["env-planner", "build-repair", "partial-build"])
def test_base_image_policy_changes_pin_environment_digests(name, monkeypatch):
    monkeypatch.setattr(get_settings(), "allowed_base_registries", ["docker.io/library"])
    first = registry.resolve_agent_config(name, registry.load_spec(name))
    monkeypatch.setattr(get_settings(), "allowed_base_registries",
                        ["docker.io/library", "public.ecr.aws"])
    second = registry.resolve_agent_config(name, registry.load_spec(name))
    assert first.digest != second.digest
    assert first.effective_digest != second.effective_digest


@pytest.mark.parametrize("image,command", [
    ("python:3.12-slim", "python -m pytest -q {test_file}"),
    ("node:22-slim", "npx vitest run --runTestsByPath {test_file}"),
    ("perl:5.38-slim", "prove {test_file}"),
    ("maven:3.9-eclipse-temurin-21", "mvn test -Dtest=HarnessProbeTest"),
    ("gradle:8-jdk21", "./gradlew test --tests HarnessProbeTest"),
])
def test_admissible_plans_do_not_require_framework_prescriptions(image, command):
    plan = EnvironmentSpec(base_image=image, test_command=command, install_commands=[])
    # The validator needs no repository I/O or inferred framework/JDK compatibility.
    context = SimpleNamespace(deps=SimpleNamespace(repo_path="/repository-that-does-not-exist"))
    assert validate_environment_spec(context, plan) is plan


@pytest.mark.parametrize("fields,reason", [
    ({"test_command": "pytest tests/probe.py"}, "{test_file}"),
    ({"test_command": "pytest {test_file} {test_file}"}, "exactly one"),
    ({"test_command": "mvn test"}, "class selector"),
    ({"test_command": "mvn test -Dtest=src/test/Probe.java"}, "simple test class"),
    ({"base_image": "attacker.invalid/unapproved:latest"}, "allowlist"),
    ({"install_commands": ["echo safe\nRUN hostile"]}, "single-line"),
    ({"scope": "partial", "module_path": "../outside"}, "inside the repository"),
])
def test_security_and_probe_addressing_failures_become_bounded_model_retries(fields, reason):
    plan = EnvironmentSpec(**{
        "base_image": "python:3.12-slim", "test_command": "pytest {test_file}", **fields,
    })
    with pytest.raises(ModelRetry, match=reason):
        validate_environment_spec(None, plan)


@pytest.mark.parametrize("language,manifests", [
    ("python", ["requirements.txt"]), ("java", ["pom.xml"]),
    ("javascript", ["package.json"]), ("perl", ["cpanfile"]),
])
def test_offline_baseline_recipes_satisfy_the_real_sandbox_policy(language, manifests):
    stack = StackFingerprint(languages={language: 1}, manifests=manifests)
    plan = EnvironmentSpec.model_validate(_env_plan(stack.model_dump(mode="json")))
    assert validate_environment_spec(None, plan) is plan


@pytest.mark.parametrize("capture,expected", [(True, False), (False, True)])
async def test_actual_pytest_output_controls_preparation_after_static_acceptance(
    tmp_path, monkeypatch, capture, expected,
):
    """Execute authored fixture controls locally; this test does not qualify sandbox isolation."""
    command = "python -m pytest -q " + ("" if capture else "-s ") + "{test_file}"
    plan = EnvironmentSpec(base_image="python:3.12-slim", test_command=command)
    assert validate_environment_spec(None, plan) is plan

    async def run_fixture(image, path, content, test_command, nonce, module_path=""):
        test_file = tmp_path / path
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text(content)
        args = [sys.executable, "-m", "pytest", "-c", "/dev/null", "-q"]
        if not capture:
            args.append("-s")
        observed = subprocess.run(
            [*args, str(test_file)], cwd=tmp_path, capture_output=True, text=True, timeout=20,
        )
        return ProcessResult(
            exit_code=observed.returncode, stdout=observed.stdout, stderr=observed.stderr,
            timed_out=False, duration_s=0,
        )

    monkeypatch.setattr(docker, "run_probe", run_fixture)
    result = await _canary_result("fixture", command, "python", "", "fixture pytest runner")
    assert result.ok is expected
    if expected:
        controls = parse_control_result(result.output_excerpt)
        assert controls is not None and controls.passed
    else:
        assert "did not reach stdout" in result.output_excerpt
