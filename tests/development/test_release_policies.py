"""Every agent has an executable release policy, and the report speaks its language.

A release policy that names gates the eval report never emits is decorative: `agentctl
release` reports a missing gate rather than a pass, and nothing is actually enforced. The
policies are hand-maintained; these tests are what hold them to the report and to the
playbook's rules, now that nothing regenerates them.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import yaml

from infosec_harness.agents.registry import AGENT_BINDINGS
from infosec_harness.evals.adapters import defines_unevidenced_safety, is_unevidenced_safe
from infosec_harness.evals.dataset import load_dataset
from infosec_harness.evals.gates import ReleasePolicy, agents_gated_on, load_policy, parse_policy
from infosec_harness.evals.metrics import GATEABLE_METRICS, UNEVIDENCED_SAFETY_METRIC
from infosec_harness.evals.provenance import CodeVersion
from infosec_harness.evals.release_report import report_provenance
from infosec_harness.resources import agents_dir

POLICIES = {name: agents_dir() / name / "evals" / "release-policy.yaml" for name in AGENT_BINDINGS}
# Owner-approved task-success floor for iterative development; hard gates stay independent of
# it. See docs/evaluation/RELEASE_EVIDENCE.md for the explicit policy and its limits.
SUCCESS_FLOOR = 0.75
REQUIRED_PROVENANCE = {"git_commit", "agent_version", "config_hash", "model", "dataset_version"}


def _policy(name: str) -> dict:
    return yaml.safe_load(POLICIES[name].read_text())


def _policy_problems(policy: ReleasePolicy, cases) -> list[str]:
    """Checks in ``policy`` that the agent's eval cannot measure, or cannot fail.

    A gate on a metric the run never publishes is compared against nothing; a gate on
    execution evidence for a dataset that declares no execution check is a constant zero. Both
    read as coverage and enforce nothing. The run reports the first kind again, per report, as
    an inert METRIC_ABSENT check; this catches both before any run.
    """
    published = GATEABLE_METRICS | (
        {UNEVIDENCED_SAFETY_METRIC} if defines_unevidenced_safety(policy.agent) else set())
    problems = [f"{policy.agent}: {metric} is not a metric the eval run publishes"
                for metric in sorted(policy.metrics_named - published)]
    if not any(case.get("execution_check") for case in cases):
        problems += [
            f"{policy.agent}: {metric} gates execution evidence but no case declares an "
            "execution_check, so it is always 0"
            for metric in ("execution_not_checked_count", "execution_failed_count")
            if metric in policy.hard_gates
        ]
    return problems


def _report_provenance_keys() -> set[str]:
    """Every provenance key a release report records."""
    code = CodeVersion(git_commit="a" * 40, git_dirty=False, harness_version="1", python="3")
    spec = SimpleNamespace(metadata={}, model_settings={})
    keys = report_provenance(
        code_identity=code.as_dict(), comparison_identity={}, agent_version="1",
        cfg_hash="h", model_name="m", pricing="priced", experiment_id="e", spec=spec)
    return set(keys) | {"recorded_at"}


@pytest.mark.parametrize("name", sorted(AGENT_BINDINGS))
def test_every_agent_has_a_release_policy(name):
    assert POLICIES[name].exists(), f"{name} declares evaluation_policy but the file is absent"


@pytest.mark.parametrize("name", sorted(AGENT_BINDINGS))
def test_every_check_the_policy_names_is_measurable_and_can_fail(name):
    """A gate on a metric the run never publishes, or on execution evidence the dataset never
    produces, silently never applies."""
    assert _policy_problems(load_policy(name), load_dataset(name).cases) == []


def test_the_policy_check_names_gates_that_cannot_be_measured_or_cannot_fail():
    recon = load_dataset("recon").cases
    problems = _policy_problems(parse_policy("recon", {
        "hard_gates": {"unevidenced_safe_verdicts": 0, "execution_failed_count": 0},
        "thresholds": {"cache_hit_rate": {"min": 0.3}},
    }, POLICIES["recon"]), recon)
    assert any("unevidenced_safe_verdicts is not a metric" in p for p in problems)
    assert any("cache_hit_rate is not a metric" in p for p in problems)
    assert any("execution_failed_count gates execution evidence" in p for p in problems)


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
    """Every agent with an unevidenced-safety predicate is gated on it, and only those."""
    defined = {name for name in AGENT_BINDINGS if defines_unevidenced_safety(name)}
    assert defined
    assert set(agents_gated_on("unevidenced_safe_verdicts")) == defined


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


@pytest.mark.parametrize("name", sorted(AGENT_BINDINGS))
def test_required_provenance_names_keys_a_report_records(name):
    """Required provenance is enforced, so a key no report records would leave every
    evaluation of the policy not_checked forever."""
    assert set(load_policy(name).required_provenance) <= _report_provenance_keys(), name


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
