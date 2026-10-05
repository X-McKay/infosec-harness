"""The release policy is the one definition of gates, and evaluating it fails closed."""

from __future__ import annotations

from pathlib import Path

import pytest

from infosec_harness.evals.adapters import defines_unevidenced_safety
from infosec_harness.evals.gates import (
    agents_gated_on,
    parse_policy,
    policies,
)

PATH = Path("release-policy.yaml")


def policy(agent: str = "verdict", **raw):
    return parse_policy(agent, {"hard_gates": {}, "thresholds": {}, **raw}, PATH)


def test_a_hard_gate_is_binary_and_an_absent_metric_is_not_a_pass():
    gate = policy(hard_gates={"budget_exhausted_count": 0})
    assert gate.evaluate({"budget_exhausted_count": 0}).status == "passed"
    assert gate.evaluate({"budget_exhausted_count": 1}).status == "failed"
    assert gate.evaluate({}).status == "not_checked"
    assert gate.evaluate({"budget_exhausted_count": None}).status == "not_checked"
    assert gate.evaluate({"budget_exhausted_count": True}).status == "not_checked"


def test_thresholds_bound_in_the_declared_direction():
    bounds = policy(thresholds={"task_success_rate": {"min": 0.75},
                                "average_cost_usd": {"max": 0.5}})
    assert bounds.evaluate({"task_success_rate": 0.75, "average_cost_usd": 0.5}).passed
    failed = bounds.evaluate({"task_success_rate": 0.7, "average_cost_usd": 0.6})
    assert [c.status for c in failed.checks] == ["failed", "failed"]
    unpriced = bounds.evaluate({"task_success_rate": 1.0, "average_cost_usd": None})
    assert unpriced.status == "not_checked"


def test_a_failure_outranks_an_unmeasured_check():
    gate = policy(hard_gates={"a": 0, "b": 0})
    assert gate.evaluate({"a": 1}).status == "failed"


def test_hard_gates_only_ignores_thresholds():
    mixed = policy(hard_gates={"a": 0}, thresholds={"task_success_rate": {"min": 0.9}})
    assert mixed.evaluate({"a": 0, "task_success_rate": 0.1}, hard_gates_only=True).passed


@pytest.mark.parametrize("raw,match", [
    ({"hard_gates": {"a": "zero"}}, "numeric limit"),
    ({"thresholds": {"a": {"floor": 1}}}, "min and/or max"),
    ({"thresholds": {"a": {}}}, "min and/or max"),
    ({"hard_gates": ["a"]}, "must be mappings"),
])
def test_a_malformed_policy_is_refused_rather_than_gating_nothing(raw, match):
    with pytest.raises(ValueError, match=match):
        parse_policy("verdict", raw, PATH)


def test_the_unevidenced_safety_gate_is_carried_where_the_predicate_is_defined():
    """Derived from the policies, and checked against the adapters in both directions: an
    agent with a predicate but no gate leaves the costliest error ungated, and a gate with no
    predicate would be a constant zero."""
    gated = set(agents_gated_on("unevidenced_safe_verdicts"))
    defined = {agent for agent in policies() if defines_unevidenced_safety(agent)}
    assert gated == defined == {"context", "probe-diagnosis", "verdict"}


def test_execution_evidence_is_gated_only_where_it_is_declared():
    assert agents_gated_on("execution_failed_count") == ("build-repair",)
    assert agents_gated_on("execution_not_checked_count") == ("build-repair",)


PROVENANCE = {"git_commit": "a" * 40, "agent_version": "1.0.0", "config_hash": "h",
              "model": "m", "dataset_version": "3"}


def test_required_provenance_must_be_present_for_any_verdict_but_failed():
    """A pass nobody can attribute is not a pass: missing provenance fails closed."""
    gate = policy(hard_gates={"a": 0}, required_provenance=list(PROVENANCE))
    assert gate.evaluate({"a": 0}, provenance=PROVENANCE).status == "passed"
    for key in PROVENANCE:
        for absent in ({k: v for k, v in PROVENANCE.items() if k != key},
                       {**PROVENANCE, key: None}, {**PROVENANCE, key: ""}):
            missing = gate.evaluate({"a": 0}, provenance=absent)
            assert missing.status == "not_checked"
            assert missing.missing_provenance == (key,)
            assert missing.as_report()["missing_provenance"] == [key]
    assert gate.evaluate({"a": 0}).status == "not_checked", "no provenance at all is not a pass"
    # A measured failure is still reported as a failure.
    assert gate.evaluate({"a": 1}).status == "failed"
    # Admissibility asks only about the hard gates.
    assert gate.evaluate({"a": 0}, hard_gates_only=True).passed


def test_every_shipped_policy_enforces_its_required_provenance():
    for agent, shipped in policies().items():
        assert shipped.required_provenance, agent
        values = {metric: 0 for metric in shipped.metrics_named}
        assert shipped.evaluate(values).missing_provenance == shipped.required_provenance


@pytest.mark.parametrize("value", [["git_commit", 3], "git_commit", [""]])
def test_malformed_required_provenance_is_refused(value):
    with pytest.raises(ValueError, match="required_provenance"):
        parse_policy("verdict", {"required_provenance": value}, PATH)
