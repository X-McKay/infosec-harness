"""The System Spec describes the system that actually exists.

Most of what the multi-agent playbook asks for is already present here as *code* — the
pydantic-graph topology, the repair budgets, the verdict contract. The spec's job is to state
it declaratively so it can be validated, not to become a second source of truth. These tests
hold it to the code and to the agent specs.
"""

from __future__ import annotations

import subprocess
import sys

import pytest
import yaml

from infosec_harness.agents.registry import AGENT_BINDINGS, load_spec
from infosec_harness.settings import REPO_ROOT

SYSTEM = REPO_ROOT / "systems" / "triage-system"
TIER_ORDER = ("low", "medium", "high", "critical")


def _spec() -> dict:
    return yaml.safe_load((SYSTEM / "system.yaml").read_text())


def test_every_agent_in_the_graph_is_a_declared_member():
    members = {m["agent"] for m in _spec()["members"]}
    assert members == set(AGENT_BINDINGS), (
        f"spec and graph disagree: only in spec {sorted(members - set(AGENT_BINDINGS))}, "
        f"only in graph {sorted(set(AGENT_BINDINGS) - members)}"
    )


def test_member_versions_match_the_agent_specs():
    """A pinned member version that drifts from the spec makes the composition unreproducible."""
    for member in _spec()["members"]:
        assert member["version"] == load_spec(member["agent"]).metadata["version"], member["agent"]


def test_no_agent_may_be_granted_more_than_its_own_spec_allows():
    """Authority only attenuates: the system can narrow a member, never widen it."""
    for member in _spec()["members"]:
        metadata = load_spec(member["agent"]).metadata
        restrictions = member["restrictions"]
        assert set(restrictions["skills"]["include"]) <= set(metadata.get("enabled_skills") or [])
        assert set(restrictions["toolsets"]["include"]) <= set(metadata.get("enabled_toolsets") or [])


def test_the_topology_has_no_model_driven_coordinator():
    """The graph is fixed code, so no agent ever chooses what runs next.

    This is why the topology is `programmatic_pipeline` and delegation depth is zero — and it
    is the strongest available form of "deterministic control, probabilistic collaboration".
    """
    topology = _spec()["topology"]
    assert topology["type"] == "programmatic_pipeline"
    assert "coordinator" not in topology
    assert topology["dynamic_membership"] is False
    assert topology["recursive_delegation"] is False
    assert _spec()["limits"]["max_delegation_depth"] == 0


def test_no_agent_calls_another():
    """Every interaction originates at the orchestrator."""
    for interaction in _spec()["interactions"]:
        assert interaction["from"] == "triage-orchestrator", interaction["id"]
        assert interaction["mode"] == "dispatch", interaction["id"]


def test_the_system_tier_is_at_least_its_strongest_member():
    members = [load_spec(m["agent"]).metadata["risk_tier"] for m in _spec()["members"]]
    strongest = max(members, key=TIER_ORDER.index)
    declared = _spec()["metadata"]["governance_tier"]
    assert TIER_ORDER.index(declared) >= TIER_ORDER.index(strongest)


def test_system_limits_are_at_least_the_members_they_contain():
    """A system ceiling below the sum of what can run would stop healthy work."""
    spec = _spec()
    limits = spec["limits"]
    calls = {i["to"]: i["max_calls"] for i in spec["interactions"]}
    total_requests = sum(load_spec(a).metadata["budgets"]["max_requests"] * n
                         for a, n in calls.items())
    assert limits["max_model_requests"] >= total_requests


def test_inconclusive_is_a_success_state_not_a_failure():
    """Reporting the absence of evidence is the system working, not the system failing."""
    termination = _spec()["termination"]
    assert "inconclusive" in termination["success_states"]
    assert termination["escalation_state"] == "inconclusive"


def test_the_admission_test_names_a_baseline_that_could_refute_it():
    """§1: the evaluation plan must include a baseline capable of testing the claimed benefit."""
    justification = _spec()["justification"]
    assert justification["claimed_benefits"], "a multi-agent design must justify itself"
    assert "single" in justification["baseline"].lower()
    assert justification["success_measures"]


def test_the_conflict_authority_is_deterministic_code():
    termination = yaml.safe_load((SYSTEM / "policies" / "termination.yaml").read_text())
    assert termination["conflict"]["authority"] == "triage-orchestrator"
    assert "facts win" in termination["conflict"]["policy"]


def test_no_agent_sees_another_agents_transcript():
    delegation = yaml.safe_load((SYSTEM / "policies" / "delegation.yaml").read_text())
    assert delegation["defaults"]["share_parent_history"] is False
    assert delegation["defaults"]["forward_credentials"] is False


def test_probe_containers_have_no_egress():
    data_flow = yaml.safe_load((SYSTEM / "policies" / "data-flow.yaml").read_text())
    assert data_flow["egress"]["probe_runtime"] == "none"
    assert "comment-only" in data_flow["egress"]["write_back"]


@pytest.mark.parametrize("policy", ["delegation", "data-flow", "termination"])
def test_the_policies_the_spec_references_exist(policy):
    assert (SYSTEM / "policies" / f"{policy}.yaml").is_file()


def test_the_spec_is_regenerable():
    files = sorted(SYSTEM.rglob("*.yaml"))
    before = {p: p.read_text() for p in files}
    subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "gen_system_spec.py")],
                   check=True, capture_output=True, cwd=REPO_ROOT)
    assert {p: p.read_text() for p in files} == before, (
        "the System Spec is out of date — run `uv run python scripts/gen_system_spec.py`"
    )
