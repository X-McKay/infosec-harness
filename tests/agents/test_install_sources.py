"""Static install-source boundary and its durable generation/provenance contract."""
from types import SimpleNamespace

import pytest
from pydantic_ai import ModelRetry

from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.runtime import registry
from infosec_harness.runtime.validators import bind_install_source_validator
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
    assert policy == {**install_source_policy(["pypi.org"]),
                      **registry._environment_policy()}
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


def test_build_repair_carries_the_install_source_validator():
    agent = registry.build_agent("build-repair", durable=False)
    assert any(v.function.__name__ == "validate_install_sources" for v in agent._output_validators)
