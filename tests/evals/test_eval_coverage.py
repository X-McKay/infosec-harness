"""Every agent's eval dataset must be tagged, and must cover its own material risks.

agent-playbook 07-evaluation makes this a release blocker rather than a report:

    Every material risk scenario has a stable ID used as an eval tag. ... Missing required
    coverage, failed hard gates, or absent control evidence blocks release. Passing average
    quality cannot compensate for an uncovered material risk.

These checks are static -- files only, no model -- so a scenario added to an assessment, or a
case whose tag is a typo, fails the ordinary test run rather than surfacing at release time.
"""
import pytest
import yaml

from infosec_harness.evals.coverage import (
    CATEGORIES,
    agents_with_datasets,
    coverage_for,
    dataset_path,
    load_cases,
    scenarios_for,
)

AGENTS = agents_with_datasets()


def test_every_agent_has_a_dataset():
    assert len(AGENTS) == 11, f"expected 11 agent datasets, found {AGENTS}"


@pytest.mark.parametrize("agent", AGENTS)
def test_every_case_declares_exactly_one_known_category(agent):
    """Untagged cases make a dataset unreadable: you cannot tell coverage from volume."""
    for case in load_cases(agent):
        category = case.get("category")
        assert category, f"{agent}/{case.get('name')}: no category (one of {CATEGORIES})"
        assert category in CATEGORIES, (
            f"{agent}/{case['name']}: category {category!r} is not one of {CATEGORIES}"
        )


@pytest.mark.parametrize("agent", AGENTS)
def test_no_case_tags_a_scenario_its_assessment_does_not_declare(agent):
    """A tag naming an undeclared scenario is a typo or a stale rename, and it would otherwise
    report as coverage of something that does not exist."""
    cov = coverage_for(agent)
    declared = sorted(s.id for s in scenarios_for(agent))
    assert not cov.unknown_scenarios, (
        f"{agent}: cases tag {cov.unknown_scenarios}, which the risk assessment does not "
        f"declare. It declares {declared}."
    )


@pytest.mark.parametrize("agent", AGENTS)
def test_every_material_risk_scenario_has_at_least_one_eval_case(agent):
    """The playbook's release blocker, enforced offline.

    Material means high or critical *inherent* tier. Residual tier already assumes the controls
    work, and evals are part of how that assumption is tested -- so judging materiality on
    residual would let a scenario excuse itself from the evidence for its own mitigation.
    """
    cov = coverage_for(agent)
    assert not cov.uncovered_material, (
        f"{agent}: material risk scenarios with no eval case: {cov.uncovered_material}. "
        f"Tag at least one case with each, e.g. `scenarios: [{cov.uncovered_material[0]}]` "
        f"in {dataset_path(agent).relative_to(dataset_path(agent).parents[3])}."
    )


@pytest.mark.parametrize("agent", AGENTS)
def test_every_agent_carries_the_always_required_categories(agent):
    """Smoke, capability, safety and regression are required of every agent.

    Adversarial and durability are not: an agent that takes no untrusted free text has no
    adversarial surface worth faking a case for, and durability cases belong to the agents whose
    work survives a replay. Requiring all six everywhere would produce filler, which is worse
    than an honest gap -- so those two are checked separately, against the agents that need them.
    """
    required = {"smoke", "capability", "safety", "regression"}
    present = set(coverage_for(agent).by_category)
    assert required <= present, f"{agent}: missing {sorted(required - present)} cases"


def test_the_agents_handling_untrusted_text_have_adversarial_cases():
    """Untrusted repository content and report prose reach these agents, so a planted
    instruction is a real scenario rather than a hypothetical one."""
    for agent in ("intake", "context", "recon", "probe-author"):
        present = set(coverage_for(agent).by_category)
        assert "adversarial" in present, (
            f"{agent} reads untrusted input but has no adversarial case"
        )


def test_the_repair_loops_have_durability_cases():
    """These run inside Temporal activities and are retried, so 'does a retry duplicate a side
    effect' and 'does a replayed run reach the same spec' are real questions for them."""
    for agent in ("build-repair", "partial-build", "probe-repair"):
        present = set(coverage_for(agent).by_category)
        assert "durability" in present, f"{agent} is retried but has no durability case"


@pytest.mark.parametrize("agent", AGENTS)
def test_the_dataset_declares_the_schema_version_the_loader_expects(agent):
    doc = yaml.safe_load(dataset_path(agent).read_text())
    assert str(doc.get("version")) in {"1", "2"}, f"{agent}: unexpected dataset version"


@pytest.mark.parametrize("agent", AGENTS)
def test_case_names_are_unique_within_a_dataset(agent):
    names = [c["name"] for c in load_cases(agent)]
    assert len(names) == len(set(names)), f"{agent}: duplicate case names"
