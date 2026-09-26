"""Risk assessments stay in sync with the scenario library and with the specs they govern.

The assessments under docs/risk-assessments/ are rendered from scripts/risk_scenarios.py so
a control edited once moves every assessment that credits it. These tests hold that
relationship, and hold the two cross-artifact rules agent-playbook §3 and §13 require: the
spec's risk_tier equals the assessment's governance_tier, and the governance tier is the
highest of inherent risk and any applicable floor.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from infosec_harness.agents.registry import AGENT_BINDINGS
from infosec_harness.settings import REPO_ROOT

ASSESSMENTS = REPO_ROOT / "docs" / "risk-assessments"
TIER_ORDER = ("low", "medium", "high", "critical")


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def _agent_assessments() -> list[Path]:
    return sorted(ASSESSMENTS.glob("*.yaml"))


def test_every_agent_has_an_assessment():
    covered = {p.stem for p in _agent_assessments()}
    assert set(AGENT_BINDINGS) <= covered, f"no assessment for: {sorted(set(AGENT_BINDINGS) - covered)}"


def test_the_committed_files_match_the_scenario_library():
    """The library is the source of truth; regenerating must be a no-op."""
    before = {p: p.read_text() for p in ASSESSMENTS.rglob("*.yaml")}
    subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "gen_risk_assessments.py")],
                   check=True, capture_output=True, cwd=REPO_ROOT)
    after = {p: p.read_text() for p in ASSESSMENTS.rglob("*.yaml")}
    assert before == after, (
        "docs/risk-assessments/ is out of date with scripts/risk_scenarios.py — run "
        "`uv run python scripts/gen_risk_assessments.py`"
    )


@pytest.mark.parametrize("path", _agent_assessments(), ids=lambda p: p.stem)
def test_spec_risk_tier_equals_assessment_governance_tier(path):
    from infosec_harness.agents.governance import tier_matches_assessment
    from infosec_harness.agents.registry import load_spec

    if path.stem not in AGENT_BINDINGS:
        pytest.skip("not an agent assessment")
    assert tier_matches_assessment(path.stem, load_spec(path.stem).metadata) == []


@pytest.mark.parametrize("path", _agent_assessments(), ids=lambda p: p.stem)
def test_governance_tier_is_the_highest_of_inherent_and_any_floor(path):
    data = _load(path)
    classification = data["classification"]
    floors = [f["tier"] for f in data["regulatory_screen"]["governance_floors"]]
    expected = max([classification["maximum_inherent_tier"], *floors], key=TIER_ORDER.index)
    assert classification["governance_tier"] == expected


@pytest.mark.parametrize("path", _agent_assessments(), ids=lambda p: p.stem)
def test_a_high_residual_cannot_be_an_unconditional_go(path):
    """§13: a high residual needs explicit acceptance and conditions; critical is no_go."""
    classification = _load(path)["classification"]
    residual, decision = classification["maximum_residual_tier"], classification["decision"]
    if residual == "critical":
        assert decision == "no_go"
    elif residual == "high":
        assert decision in ("conditional_go", "no_go")
        assert _load(path)["acceptance"]["conditions"], "a conditional go must list its conditions"


@pytest.mark.parametrize("path", _agent_assessments(), ids=lambda p: p.stem)
def test_only_verified_controls_reduce_residual_likelihood(path):
    """A planned or merely implemented control earns no residual reduction (§13).

    The gVisor control is the live example: its fail-closed check is tested, but the
    isolation it selects has never executed, so it stays `implemented` and the scenarios
    that depend on it keep a high residual tier.
    """
    for scenario in _load(path)["scenarios"]:
        verified = [c for c in scenario["controls"] if c["effectiveness"] == "verified"]
        reduced = scenario["residual"]["likelihood"] < scenario["inherent"]["likelihood"]
        if reduced:
            assert verified, (
                f"{scenario['id']} claims a lower residual likelihood with no verified control"
            )


def test_the_unverified_sandbox_is_recorded_as_unverified():
    """This is the project's largest open risk; it must not quietly become 'verified'."""
    data = _load(ASSESSMENTS / "probe-author.yaml")
    escape = next(s for s in data["scenarios"] if s["id"] == "RISK-SEC-001")
    gvisor = next(c for c in escape["controls"] if c["id"] == "CTRL-SBX-001")
    assert gvisor["effectiveness"] == "implemented", (
        "CTRL-SBX-001 may only be `verified` once `harness eval corpus` has run with the "
        "sandbox enabled on a host providing runsc"
    )
    assert escape["residual"]["tier"] == "high"
