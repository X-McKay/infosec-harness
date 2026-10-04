"""Static install-source boundary and its durable generation/provenance contract."""
from types import SimpleNamespace

import pytest
from pydantic_ai import ModelRetry

from infosec_harness.agents import registry
from infosec_harness.agents.validators import bind_install_source_validator
from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.sandbox.install_sources import (
    INVALID_SOURCE,
    install_source_policy,
    unapproved_install_sources,
)
from infosec_harness.settings import get_settings


def spec(command="pip install pytest", env=None):
    return EnvironmentSpec(base_image="python:3.12-slim", install_commands=[command],
                           env=env or {}, test_command="python -m pytest -q -s {test_file}")


@pytest.mark.parametrize("command", [
    "pip install --extra-index-url https://mirror.invalid/simple -r requirements.txt",
    "pip install --extra-index-url=https://mirror.invalid/simple internal-package",
    "pip install 'package @ https://mirror.invalid/package.whl'",
    "mvn -Drepo.url=https://mirror.invalid/releases dependency:go-offline",
])
def test_explicit_undeclared_log_mirror_is_rejected(command):
    assert unapproved_install_sources(spec(command), ["pypi.org"]) == ("mirror.invalid",)


def test_default_operator_hosts_are_accepted_without_egress(monkeypatch):
    import socket
    import subprocess
    import urllib.request

    def forbidden(*_args, **_kwargs):
        raise AssertionError("static validation must not resolve or execute")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    approved = tuple(get_settings().default_registry_allowlist)
    for host in approved:
        assert unapproved_install_sources(spec(f"curl https://{host}/artifact"), approved) == ()


def test_operator_approved_internal_source_accepted_but_suffix_match_is_not():
    allowed = ["pypi.org", "packages.internal.example"]
    assert unapproved_install_sources(spec(env={
        "PIP_INDEX_URL": "https://packages.internal.example/simple"}), allowed) == ()
    assert unapproved_install_sources(spec(
        "pip install --index-url https://pypi.org.attacker.example/simple pytest"), allowed)
    assert unapproved_install_sources(spec(
        "pip install --index-url https://sub.pypi.org/simple pytest"), allowed)


@pytest.mark.parametrize("source", [
    "https://", "https:///simple", "https://${HOST}/simple", "https://$HOST/simple",
    "https://pypi.org:bad/simple", "https://pypi.org:99999/simple",
    "https://evil.example\\@pypi.org/simple", "https://[broken/simple",
])
def test_missing_unknown_or_ambiguous_authority_fails_closed(source):
    assert unapproved_install_sources(spec(env={"PIP_INDEX_URL": source}), ["pypi.org"]) == (
        INVALID_SOURCE,)


def test_url_credentials_path_query_never_enter_retry():
    validator = bind_install_source_validator(("pypi.org",))
    output = spec("pip install --index-url "
                  "https://user:secret-password@mirror.invalid/secret-path?token=secret-token pytest")
    with pytest.raises(ModelRetry) as error:
        validator(SimpleNamespace(), output)
    message = str(error.value)
    assert "mirror.invalid" in message
    for secret in ("user", "secret-password", "secret-path", "secret-token", "https://"):
        assert secret not in message


def test_authority_userinfo_cannot_spoof_an_approved_host():
    assert unapproved_install_sources(spec(
        "pip install https://pypi.org@mirror.invalid/pkg.whl"), ["pypi.org"]) == (
        "mirror.invalid",)


def test_bound_tuple_matches_resolved_policy_and_does_not_follow_settings_mutation(monkeypatch):
    monkeypatch.setattr(get_settings(), "default_registry_allowlist", ["pypi.org"])
    resolved = registry.resolve_agent_config("build-repair", registry.load_spec("build-repair"))
    policy = resolved.effective_spec["metadata"]["output_validation"]
    assert policy == install_source_policy(["pypi.org"])
    assert resolved.for_source_files(200).effective_spec["metadata"]["output_validation"] == policy
    agent = registry.build_agent("build-repair", durable=False)
    validate = agent._output_validators[0].function
    assert validate.__name__ == "validate_install_sources"
    monkeypatch.setattr(get_settings(), "default_registry_allowlist", ["pypi.org", "mirror.invalid"])
    with pytest.raises(ModelRetry):
        validate(SimpleNamespace(), spec("pip install https://mirror.invalid/package.whl"))


def test_policy_host_changes_pin_both_build_digests_only(monkeypatch):
    monkeypatch.setattr(get_settings(), "default_registry_allowlist", ["pypi.org"])
    first = {name: registry.resolve_agent_config(name, registry.load_spec(name))
             for name in ("build-repair", "env-planner", "partial-build")}
    monkeypatch.setattr(get_settings(), "default_registry_allowlist", ["pypi.org", "mirror.invalid"])
    second = {name: registry.resolve_agent_config(name, registry.load_spec(name)) for name in first}
    assert first["build-repair"].digest != second["build-repair"].digest
    assert first["build-repair"].effective_digest != second["build-repair"].effective_digest
    for name in ("env-planner", "partial-build"):
        assert first[name].digest == second[name].digest
        assert first[name].effective_digest == second[name].effective_digest


def test_old_build_keeps_pre_guard_validator_generation():
    current = registry.build_agent("build-repair", durable=False)
    legacy = registry.build_agent("build-repair", durable=False, legacy_output_contract=True)
    assert len(current._output_validators) == len(legacy._output_validators) + 1
    assert all(v.function.__name__ != "validate_install_sources" for v in legacy._output_validators)


def test_build_has_independent_patch_even_if_old_shared_patch_was_true(monkeypatch):
    from infosec_harness.agents.durable import LEGACY_OUTPUT_AGENTS, RETAINED_BUILD_AGENTS
    from infosec_harness.workflows import temporal_ops
    from infosec_harness.workflows.temporal_ops import TemporalOps

    monkeypatch.setattr(temporal_ops.workflow, "patched",
                        lambda patch: patch == "agent-output-contracts-v2")
    monkeypatch.setattr(temporal_ops.workflow.unsafe, "is_replaying", lambda: True)
    ops = TemporalOps()
    assert ops._agent_for("build-repair") is LEGACY_OUTPUT_AGENTS["build-repair"]
    assert ops._agent_for("partial-build") is RETAINED_BUILD_AGENTS["partial-build"]
    assert "parallel_tool_calls" not in ops._agent_for("partial-build").model_settings
    assert "parallel_tool_calls" not in ops._agent_for("build-repair").model_settings


async def test_old_build_live_frontier_stops_before_accounting(monkeypatch):
    from infosec_harness.agents.deps import AgentDeps
    from infosec_harness.workflows import temporal_ops
    from infosec_harness.workflows.temporal_ops import TemporalOps

    monkeypatch.setattr(temporal_ops.workflow, "patched",
                        lambda patch: patch == "agent-output-contracts-v2")
    monkeypatch.setattr(temporal_ops.workflow.unsafe, "is_replaying", lambda: False)
    ops = TemporalOps()

    async def forbidden(*_args, **_kwargs):
        raise AssertionError("legacy frontier must stop before accounting or requests")

    monkeypatch.setattr(ops._accounting, "reserve", forbidden)
    with pytest.raises(RuntimeError, match="retry the triage as a new workflow"):
        await ops.run_agent("build-repair", ["fixture"], AgentDeps(repo_path="/snapshot"))
