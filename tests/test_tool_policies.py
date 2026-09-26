"""Every toolset declares what it does to external state, and agents cannot understate it.

Nothing in this system recorded that `run_in_sandbox` executes code while `read_file` only
observes — yet that difference is the whole basis of the execution-class floor
(agent-playbook §5). Without it, `execution_class: durable` is a label rather than a claim.
"""

from __future__ import annotations

import pytest

from infosec_harness.agents.governance import GovernanceError
from infosec_harness.agents.registry import AGENT_BINDINGS, build_agent, load_spec
from infosec_harness.tools.policies import (
    EXECUTION_CLASS_ORDER,
    ToolEffect,
    load_policies,
    required_execution_class,
)


def test_every_toolset_an_agent_enables_has_a_declared_policy():
    declared = set(load_policies())
    for name in AGENT_BINDINGS:
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


def test_the_sandbox_shell_key_is_stable_for_one_logical_call():
    """A retry must produce the same container name; a different call must not."""
    from infosec_harness.sandbox.docker import container_name

    assert container_name("run1:call1:v1") == container_name("run1:call1:v1")
    assert container_name("run1:call1:v1") != container_name("run1:call2:v1")
    name = container_name("run1:call1:v1")
    assert name.startswith("harness-shell-") and len(name) <= 63  # Docker's limit


@pytest.mark.parametrize("name", sorted(AGENT_BINDINGS))
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
