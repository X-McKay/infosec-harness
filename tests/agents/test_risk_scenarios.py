"""The risk scenario library governs the specs, and the rules of agent-playbook §13 hold in it.

`agents/risk-scenarios.yaml` is hand-maintained and read directly by governance and by eval
coverage. Nothing renders it into per-agent documents any more, so these tests are what hold
the cross-artifact rules the playbook requires: a spec's risk tier equals the tier its
scenarios establish, only verified controls reduce residual likelihood, and the project's
largest open risk stays recorded as open.
"""

from __future__ import annotations

import pytest

from infosec_harness.runtime import governance
from infosec_harness.runtime.registry import BINDINGS, load_spec
from infosec_harness.runtime.risk import MATRIX, TIER_ORDER, library, max_tier, parse, tier_for

LIB = library()


def test_every_bound_agent_is_assessed_and_nothing_else_is():
    assert set(LIB.agents) == set(BINDINGS), (
        f"only in library {sorted(set(LIB.agents) - set(BINDINGS))}, "
        f"only in graph {sorted(set(BINDINGS) - set(LIB.agents))}"
    )


@pytest.mark.parametrize("agent", sorted(BINDINGS))
def test_spec_risk_tier_equals_the_tier_its_scenarios_establish(agent):
    """§3: the spec and its assessment cannot drift apart silently."""
    assert load_spec(agent).metadata["risk_tier"] == LIB.governance_tier(agent)
    assert governance.risk_violations(agent, load_spec(agent).metadata) == []


def test_governance_refuses_a_tier_the_scenarios_do_not_establish():
    metadata = dict(load_spec("verdict").metadata)
    metadata["risk_tier"] = "low"
    problems = governance.risk_violations("verdict", metadata)
    assert problems and "establish 'high'" in problems[0]


def test_governance_refuses_an_agent_with_no_assessed_risk():
    problems = governance.risk_violations("not-an-agent", {"risk_tier": "low"})
    assert problems and "unassessed" in problems[0]


@pytest.mark.parametrize("agent", sorted(BINDINGS))
def test_governance_tier_is_the_highest_of_inherent_and_any_floor(agent):
    scenarios = LIB.scenarios_for(agent)
    inherent = max_tier([s.inherent.tier for s in scenarios])
    floors = [s.capability_floor for s in scenarios if s.capability_floor]
    assert LIB.governance_tier(agent) == max_tier([inherent, *floors])


def test_code_execution_scenarios_carry_the_capability_floor():
    """§13: a subject that performs or determines privileged code execution is at least high."""
    for sid in ("RISK-SEC-001", "RISK-SEC-004"):
        assert LIB.scenarios[sid].capability_floor == "high", sid


@pytest.mark.parametrize("sid", sorted(library().scenarios))
def test_only_verified_controls_reduce_residual_likelihood(sid):
    """A planned or merely implemented control earns no residual reduction (§13).

    The gVisor control is the live example: its fail-closed check is tested, but the
    isolation it selects has never executed, so it stays `implemented` and the scenarios
    that depend on it keep a high residual tier.
    """
    scenario = LIB.scenarios[sid]
    if scenario.residual.likelihood < scenario.inherent.likelihood:
        assert any(c.verified for c in scenario.controls), (
            f"{sid} claims a lower residual likelihood with no verified control"
        )


@pytest.mark.parametrize("sid", sorted(library().scenarios))
def test_residual_risk_never_exceeds_inherent_risk(sid):
    scenario = LIB.scenarios[sid]
    assert scenario.residual.impact <= scenario.inherent.impact
    assert scenario.residual.likelihood <= scenario.inherent.likelihood
    assert scenario.controls, f"{sid} credits no control at all"


def test_the_unverified_sandbox_is_recorded_as_unverified():
    """This is the project's largest open risk; it must not quietly become 'verified'."""
    gvisor = LIB.controls["CTRL-SBX-001"]
    assert gvisor.effectiveness == "implemented", (
        "CTRL-SBX-001 may only be `verified` once `harness eval corpus` has run with the "
        "sandbox enabled on a host providing runsc"
    )
    escape = LIB.scenarios["RISK-SEC-001"]
    assert gvisor in escape.controls
    assert escape.residual.tier == "high"


def test_the_matrix_is_the_playbooks_and_tiers_are_ordered():
    assert tier_for(4, 4) == "critical" and tier_for(1, 1) == "low"
    assert set(MATRIX.values()) == set(TIER_ORDER)
    assert max_tier(["low", "critical", "high"]) == "critical"


def test_the_library_refuses_dangling_references():
    with pytest.raises(ValueError, match="not defined"):
        parse({"controls": {}, "scenarios": {"RISK-X": {
            "title": "x", "inherent": {"impact": 1, "likelihood": 1, "confidence": "low",
                                       "rationale": ""},
            "residual": {"impact": 1, "likelihood": 1, "confidence": "low", "rationale": ""},
            "controls": ["CTRL-MISSING"]}}, "agents": {}})
    with pytest.raises(ValueError, match="do not exist"):
        parse({"controls": {}, "scenarios": {}, "agents": {"intake": ["RISK-MISSING"]}})


def test_every_cited_evidence_file_exists():
    """A control's evidence is a path a reviewer can open; a moved module must not leave the
    library citing a file that no longer exists (regression: CTRL-SBX-001 cited sandbox/policy.py
    after ensure_runtime_available moved to sandbox/docker.py)."""
    from pathlib import Path

    root = Path(__file__).parents[2]
    missing = [(name, path) for name, control in LIB.controls.items()
               for path in control.evidence if not (root / path).exists()]
    assert missing == []
