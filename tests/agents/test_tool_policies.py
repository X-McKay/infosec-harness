"""Every toolset declares what it does to external state, and agents cannot understate it.

Nothing in this system recorded that `run_in_sandbox` executes code while `read_file` only
observes — yet that difference is the whole basis of the execution-class floor
(agent-playbook §5). Without it, `execution_class: durable` is a label rather than a claim.
"""

from __future__ import annotations

import pytest

from infosec_harness.runtime.governance import GovernanceError
from infosec_harness.runtime.registry import BINDINGS, build_agent, load_spec
from infosec_harness.tools.policies import (
    EXECUTION_CLASS_ORDER,
    ToolEffect,
    load_policies,
    required_execution_class,
)


def test_every_toolset_an_agent_enables_has_a_declared_policy():
    declared = set(load_policies())
    for name in BINDINGS:
        enabled = set(load_spec(name).metadata.get("enabled_toolsets") or [])
        assert enabled <= declared, f"{name} enables undeclared toolsets: {sorted(enabled - declared)}"


def test_reading_the_repository_is_a_read_and_running_a_command_is_not():
    policies = load_policies()
    assert policies["repo-read-only"].effect is ToolEffect.read
    assert policies["sandbox-shell"].effect is ToolEffect.write_reversible


def test_a_write_effect_declares_how_a_retry_is_made_safe():
    """A write that is merely assumed safe to repeat is the thing the standard forbids."""
    for policy in load_policies().values():
        if policy.effect is not ToolEffect.read:
            assert policy.retry_safety.value in ("idempotency_key_required", "unsafe"), policy.name


def test_every_toolset_bounds_its_output():
    for policy in load_policies().values():
        assert policy.max_output_bytes > 0, policy.name


def test_the_policy_declares_exactly_the_tools_the_code_exposes():
    """A tool in the code and not in the policy is governed by nothing.

    The policy is what `required_execution_class` reads and what a reviewer reads. Nothing tied
    the two together, so adding a tool to `capabilities.py` silently left its effect, its
    output bound and its confinement undeclared — which is the same gap that made
    `execution_class` a label before this file existed. Both directions are checked: a stale
    entry for a tool that no longer exists is also a lie about the surface.
    """
    from infosec_harness.runtime.capabilities import REPO_RO_TOOLS

    declared = {t.name for t in load_policies()["repo-read-only"].tools}
    assert declared == set(REPO_RO_TOOLS), {
        "in the code, undeclared": sorted(set(REPO_RO_TOOLS) - declared),
        "declared, not in the code": sorted(declared - set(REPO_RO_TOOLS)),
    }


def test_the_declared_output_bound_covers_every_tools_own_cap():
    """The number in the policy has to be the real worst case, not the oldest one.

    `max_output_bytes` was 120000 when the largest single result was a 100000-byte
    `describe_callables`. A tool whose own cap exceeded it would make the declaration false
    without anything failing.
    """
    from infosec_harness.tools import repository as repo_tools
    from infosec_harness.tools import symbols as symbol_inspection
    from infosec_harness.tools import target as target_context

    declared = load_policies()["repo-read-only"].max_output_bytes
    for name, limit in (("describe_callables", symbol_inspection.MAX_DESCRIBE_BYTES),
                        ("read_files", repo_tools.MAX_BATCH_BYTES),
                        ("list_tree", repo_tools.MAX_TREE_BYTES),
                        ("repo_digest", repo_tools.MAX_DIGEST_BYTES),
                        ("inspect_target", target_context.MAX_TARGET_CONTEXT_BYTES)):
        assert limit <= declared, f"{name} can return {limit} bytes, over the declared {declared}"


def test_an_agent_cannot_expose_a_tool_the_policy_does_not_declare():
    """Enforced at build time, like the execution-class floor, not only asserted here."""
    import pytest as _pytest

    with _pytest.raises(GovernanceError, match="Unknown repo-read-only tools"):
        build_agent("recon", {"capabilities": [{"RepoReadOnly": {"tools": ["read_everything"]}}]},
                    durable=False)


def test_the_sandbox_shell_key_is_stable_for_one_logical_call():
    """A retry must produce the same container name; a different call must not."""
    from infosec_harness.sandbox.docker import container_name

    assert container_name("run1:call1:v1") == container_name("run1:call1:v1")
    assert container_name("run1:call1:v1") != container_name("run1:call2:v1")
    name = container_name("run1:call1:v1")
    assert name.startswith("harness-shell-") and len(name) <= 63  # Docker's limit


@pytest.mark.parametrize("name", sorted(BINDINGS))
def test_each_agents_execution_class_covers_its_tools(name):
    metadata = load_spec(name).metadata
    declared = metadata["execution_class"]
    required = required_execution_class(list(metadata.get("enabled_toolsets") or []))
    assert EXECUTION_CLASS_ORDER.index(declared) >= EXECUTION_CLASS_ORDER.index(required), (
        f"{name} declares {declared} but its toolsets require {required}"
    )


def test_construction_refuses_an_agent_that_understates_its_execution_class():
    """The floor is enforced at build time, not just asserted in a test."""
    overlay = {"metadata": {"execution_class": "ephemeral"}}
    with pytest.raises(GovernanceError, match="require at least 'durable'"):
        build_agent("build-repair", overlay, durable=False)


def test_construction_refuses_a_spec_with_no_budget():
    with pytest.raises(GovernanceError, match="budgets"):
        build_agent("verdict", {"metadata": {"budgets": None}}, durable=False)


def test_construction_refuses_a_risk_tier_that_contradicts_nothing_real():
    """A model policy that is not in config/models.yaml cannot be resolved, so it must fail."""
    with pytest.raises(GovernanceError, match="model_policy"):
        build_agent("verdict", {"metadata": {"model_policy": "imaginary-v9"}}, durable=False)


def test_the_floor_is_derived_from_capabilities_not_from_what_metadata_claims():
    """Regression: the floor read `metadata.enabled_toolsets`, so a spec that attached
    SandboxShell but omitted it from its metadata was judged as read-only and could declare
    `ephemeral`. The capabilities are what run; metadata must agree with them."""
    overlay = {"metadata": {"execution_class": "ephemeral", "enabled_toolsets": ["repo-read-only"]}}
    with pytest.raises(GovernanceError, match="enabled_toolsets"):
        build_agent("build-repair", overlay, durable=False)


def test_an_unknown_toolset_name_fails_construction():
    overlay = {"metadata": {"enabled_toolsets": ["repo-read-only", "sandbox-shel"]}}
    with pytest.raises(GovernanceError, match="no declared policy"):
        build_agent("build-repair", overlay, durable=False)


def test_enabled_skills_must_be_the_skills_the_agent_can_load():
    overlay = {"metadata": {"enabled_skills": ["cwe-89-sql-injection"]}}
    with pytest.raises(GovernanceError, match="enabled_skills"):
        build_agent("context", overlay, durable=False)


@pytest.mark.parametrize("name", sorted(BINDINGS))
def test_each_committed_spec_runs_the_tier_its_model_policy_names(name):
    from infosec_harness.inference.models import load_models_config

    spec = load_spec(name)
    assert load_models_config().model_policies[spec.metadata["model_policy"]] == spec.model


def test_a_committed_spec_whose_policy_disagrees_with_its_tier_is_refused(monkeypatch):
    """No silent fallback: a policy that resolves to a different tier than the spec runs is a
    governance error, not a choice made quietly by whichever field is read."""
    from infosec_harness.runtime import registry

    real = registry.load_spec

    def drifted(name, overlay=None):
        spec = real(name, overlay)
        return spec.model_copy(update={"model": "opus"})

    monkeypatch.setattr(registry, "load_spec", drifted)
    with pytest.raises(GovernanceError, match="resolves to 'sonnet', not the spec's model tier 'opus'"):
        build_agent("verdict", durable=False)


def test_a_policy_field_with_no_enforcer_is_rejected():
    """Unknown keys fail, so a policy cannot declare a bound that nothing applies."""
    from pydantic import ValidationError

    from infosec_harness.tools.policies import ToolPolicy

    base = {"name": "x", "effect": "read", "retry_safety": "safe", "timeout_seconds": 1,
            "max_output_bytes": 10, "tools": [{"name": "t", "effect": "read"}]}
    ToolPolicy.model_validate(base)
    with pytest.raises(ValidationError):
        ToolPolicy.model_validate({**base, "data_classification": "confidential"})
    with pytest.raises(ValidationError):
        ToolPolicy.model_validate({**base, "tools": [{"name": "t", "effect": "read", "notes": ""}]})


def test_the_repo_toolset_applies_its_declared_timeout():
    from infosec_harness.runtime.capabilities import DEFAULT_REPO_RO_TOOLS, repo_ro_toolset

    declared = load_policies()["repo-read-only"].timeout_seconds
    assert repo_ro_toolset(DEFAULT_REPO_RO_TOOLS).timeout == declared


def test_every_repo_tool_result_is_held_to_the_declared_output_bound(monkeypatch):
    """list_files and search_code are capped by entry count, not bytes: long paths could exceed
    the declared bound, so the bound is applied to every result, not merely asserted."""
    from infosec_harness.runtime import capabilities

    declared = load_policies()["repo-read-only"].max_output_bytes
    assert capabilities._bounded(lambda: "x" * declared, declared)() == "x" * declared
    out = capabilities._bounded(lambda: "\u00e9" * declared, declared)()
    assert len(out.encode()) <= declared
    assert out.endswith(f"\n... truncated at the toolset's {declared}-byte output bound")


async def test_the_sandbox_shell_uses_the_declared_timeout_and_output_bound(monkeypatch):
    from types import SimpleNamespace

    from infosec_harness.runtime.capabilities import run_in_sandbox
    from infosec_harness.sandbox import docker

    policy = load_policies()["sandbox-shell"]
    seen = {}

    async def run_shell(image, command, *, timeout, idempotency_key):
        seen["timeout"] = timeout
        # Multibyte output: 3000 characters of it is far more than 3000 bytes.
        return SimpleNamespace(exit_code=0, timed_out=False, stdout="é" * 5000,
                               stderr="é" * 5000)

    monkeypatch.setattr(docker, "run_shell", run_shell)
    ctx = SimpleNamespace(deps=SimpleNamespace(sandbox_image="img"), run_id="r", tool_call_id="c")
    out = await run_in_sandbox(ctx, "true")
    assert seen["timeout"] == policy.timeout_seconds
    assert out.startswith("[exit code: 0]\n[stdout]\n")
    assert len(out.encode()) <= policy.max_output_bytes
    assert out.endswith("output bound")
