"""Every agent has an executable release policy, and the report speaks its language.

A release policy that names gates the eval report never emits is decorative: `agentctl
release` reports a missing gate rather than a pass, and nothing is actually enforced. The
policies are hand-maintained; these tests are what hold them to the report and to the
playbook's rules, now that nothing regenerates them.
"""

from __future__ import annotations

import pytest
import yaml

from infosec_harness.agents.registry import AGENT_BINDINGS
from infosec_harness.evals.adapters import UNEVIDENCED_SAFETY_AGENTS, is_unevidenced_safe
from infosec_harness.resources import agents_dir

POLICIES = {name: agents_dir() / name / "evals" / "release-policy.yaml" for name in AGENT_BINDINGS}
# Owner-approved task-success floor for iterative development; hard gates stay independent of
# it. See docs/evaluation/AGENT_QUALITY_PLAN.md for the explicit policy and its limits.
SUCCESS_FLOOR = 0.75
REQUIRED_PROVENANCE = {"git_commit", "agent_version", "config_hash", "model", "dataset_version"}


def _policy(name: str) -> dict:
    return yaml.safe_load(POLICIES[name].read_text())


@pytest.mark.parametrize("name", sorted(AGENT_BINDINGS))
def test_every_agent_has_a_release_policy(name):
    assert POLICIES[name].exists(), f"{name} declares evaluation_policy but the file is absent"


@pytest.mark.parametrize("name", sorted(AGENT_BINDINGS))
def test_every_gate_the_policy_names_is_a_metric_the_report_emits(name):
    """Otherwise the gate silently never applies."""
    policy = _policy(name)
    # Verified against a real report: `harness eval run <agent> --report` writes each of
    # these. uncovered_material_scenarios comes from evals.coverage and is computed
    # statically, so it is emitted even when no case ran.
    emitted = {"schema_validity_rate", "budget_exhausted_count", "uncovered_material_scenarios"}
    if name in UNEVIDENCED_SAFETY_AGENTS:
        emitted.add("unevidenced_safe_verdicts")
    if name == "build-repair":
        emitted.update({"execution_not_checked_count", "execution_failed_count"})
    assert set(policy["hard_gates"]) <= emitted, (
        f"{name}: policy names gates the report never writes: "
        f"{sorted(set(policy['hard_gates']) - emitted)}"
    )


@pytest.mark.parametrize("name", sorted(AGENT_BINDINGS))
def test_thresholds_name_metrics_the_report_emits(name):
    emitted = {"task_success_rate", "average_cost_usd", "p95_model_requests"}
    assert set(_policy(name)["thresholds"]) <= emitted, name


@pytest.mark.parametrize("name", sorted(AGENT_BINDINGS))
def test_hard_gates_are_absolute(name):
    """A hard gate is binary; a weighted average must not be able to hide it (§7)."""
    gates = _policy(name)["hard_gates"]
    assert gates["schema_validity_rate"] == 1.0
    assert gates["budget_exhausted_count"] == 0


@pytest.mark.parametrize("name", sorted(AGENT_BINDINGS))
def test_uncovered_material_risk_blocks_release_everywhere(name):
    """agent-playbook 07: "Missing required coverage ... blocks release. Passing average quality
    cannot compensate for an uncovered material risk." Zero is the only passing value."""
    assert _policy(name)["hard_gates"]["uncovered_material_scenarios"] == 0, name


def test_the_agents_on_the_false_negative_path_carry_the_safety_gate():
    for name in UNEVIDENCED_SAFETY_AGENTS:
        assert "unevidenced_safe_verdicts" in _policy(name)["hard_gates"], name


def test_unattested_probe_observations_are_not_release_gates():
    for name in ("probe-author", "probe-repair"):
        gates = _policy(name)["hard_gates"]
        assert "execution_not_checked_count" not in gates
        assert "execution_failed_count" not in gates
    assert _policy("build-repair")["hard_gates"]["execution_not_checked_count"] == 0
    assert _policy("build-repair")["hard_gates"]["execution_failed_count"] == 0


@pytest.mark.parametrize("name", sorted(AGENT_BINDINGS))
def test_every_agent_uses_the_owner_approved_success_floor(name):
    """The 75% quality policy applies to every tier; a policy may never go below it."""
    assert _policy(name)["thresholds"]["task_success_rate"]["min"] >= SUCCESS_FLOOR, name


@pytest.mark.parametrize("name", sorted(AGENT_BINDINGS))
def test_every_policy_requires_the_provenance_that_makes_a_number_attributable(name):
    assert set(_policy(name)["required_provenance"]) >= REQUIRED_PROVENANCE, name


# --- The unevidenced-safety predicate ---------------------------------------------------


@pytest.mark.parametrize("execution", [
    {},
    {"precondition_reached": False, "sink_returned": False},
    {"precondition_reached": True},
    {"precondition_reached": True, "sink_returned": False},
])
def test_diagnosis_negative_without_complete_sink_execution_is_unevidenced(execution):
    case = {"payload": {"probe_execution": execution}}
    assert is_unevidenced_safe("probe-diagnosis", case, "valid_negative")


def test_diagnosis_negative_with_precondition_and_sink_return_is_evidenced():
    complete = {
        "payload": {
            "probe_execution": {
                "precondition_reached": True,
                "sink_returned": True,
                "oracle_fired": False,
            }
        }
    }
    assert not is_unevidenced_safe("probe-diagnosis", complete, "valid_negative")


def test_diagnosis_negative_is_unevidenced_when_oracle_fired():
    positive_execution = {
        "payload": {
            "probe_execution": {
                "precondition_reached": True,
                "sink_returned": True,
                "oracle_fired": True,
            }
        }
    }
    assert is_unevidenced_safe("probe-diagnosis", positive_execution, "valid_negative")


def test_context_calling_an_exploitable_sink_unreachable_is_unevidenced():
    case = {"expected": "reachable"}
    assert is_unevidenced_safe("context", case, "unreachable")
    assert not is_unevidenced_safe("context", {"expected": "unreachable"}, "unreachable")


def test_verdict_needs_a_complete_valid_negative_execution():
    unsupported = {"facts": {"last_diagnosis": "environment_issue"}}
    assert is_unevidenced_safe("verdict", unsupported, "likely_not_exploitable")
    supported = {
        "facts": {
            "last_diagnosis": "valid_negative",
            "precondition_reached": True,
            "sink_returned": True,
            "oracle_fired": False,
        }
    }
    assert not is_unevidenced_safe("verdict", supported, "likely_not_exploitable")
    unreachable = {"facts": {"reachability": "unreachable"}}
    assert is_unevidenced_safe("verdict", unreachable, "likely_not_exploitable")


@pytest.mark.parametrize("agent,label", [
    ("verdict", "likely_not_exploitable"),
    ("probe-diagnosis", "valid_negative"),
])
@pytest.mark.parametrize("field,value", [
    ("oracle_fired", "missing"),
    ("oracle_fired", None),
    ("oracle_fired", 0),
    ("precondition_reached", 1),
    ("sink_returned", "true"),
    ("sink_returned", None),
])
def test_negative_evidence_requires_explicit_boolean_markers(agent, label, field, value):
    evidence = {
        "last_diagnosis": "valid_negative",
        "precondition_reached": True,
        "sink_returned": True,
        "oracle_fired": False,
    }
    if value == "missing":
        evidence.pop(field)
    else:
        evidence[field] = value
    case = ({"facts": evidence} if agent == "verdict"
            else {"payload": {"probe_execution": evidence}})

    assert is_unevidenced_safe(agent, case, label)


def test_the_predicate_is_silent_for_agents_it_is_not_defined_for():
    assert not is_unevidenced_safe("probe-author", {"expected": "conformant"}, "conformant")
    assert not is_unevidenced_safe("recon", {}, "python/pytest")
