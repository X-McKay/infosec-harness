"""Which risk scenarios an agent's eval dataset actually exercises.

The agent playbook (07-evaluation) makes this a release blocker, not a report:

    Every material risk scenario has a stable ID used as an eval tag. ... An eval report
    identifies covered and uncovered scenario IDs. Missing required coverage, failed hard
    gates, or absent control evidence blocks release. Passing average quality cannot
    compensate for an uncovered material risk.

Before this module the two halves existed and were not connected. `docs/risk-assessments/`
named the scenarios (RISK-SEC-001 and friends) with impact, likelihood and tier; the datasets
held cases. Nothing said which case covered which scenario, so an agent could carry a
`critical` scenario with no case touching it and still show a green release gate -- the exact
outcome the paragraph above forbids.

Coverage is computed statically, from files, with no model involved. That matters: it means
the check runs in the ordinary test suite rather than only after a live eval, so a scenario
added to an assessment fails the build immediately instead of at release time.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from infosec_harness.resources import agents_dir, project_file

# The dataset categories the playbook names. Every case declares exactly one, so a dataset can
# be read for what it actually exercises rather than inferred from case names.
CATEGORIES = ("smoke", "regression", "capability", "safety", "adversarial", "durability")

# Tiers the playbook calls material: these require coverage, and repeated runs when model
# behaviour is involved. A medium/low scenario may legitimately rely on a deterministic control
# rather than a behavioural case.
MATERIAL_TIERS = ("high", "critical")


def risk_assessment_path(agent: str) -> Path | None:
    """A reviewable project file, so it is absent from a deployment rather than packaged."""
    return project_file("docs", "risk-assessments", f"{agent}.yaml")


def dataset_path(agent: str) -> Path:
    """Packaged beside the spec it grades, so a release check can run against the wheel."""
    return agents_dir() / agent / "evals" / "dataset.yaml"


@dataclass
class ScenarioRef:
    id: str
    inherent_tier: str
    residual_tier: str

    @property
    def material(self) -> bool:
        """Judged on *inherent* tier, deliberately.

        Residual tier already assumes the controls work. Evals are part of how that assumption
        is tested, so letting residual decide what needs an eval would let a scenario excuse
        itself from the evidence for its own mitigation.
        """
        return self.inherent_tier in MATERIAL_TIERS


@dataclass
class Coverage:
    agent: str
    covered: list[str] = field(default_factory=list)
    uncovered: list[str] = field(default_factory=list)
    uncovered_material: list[str] = field(default_factory=list)
    by_category: dict[str, int] = field(default_factory=dict)
    unknown_scenarios: list[str] = field(default_factory=list)
    missing_categories: list[str] = field(default_factory=list)

    def as_report(self) -> dict[str, Any]:
        return {
            "scenarios_covered": self.covered,
            "scenarios_uncovered": self.uncovered,
            "scenarios_uncovered_material": self.uncovered_material,
            "cases_by_category": self.by_category,
            "unknown_scenarios": self.unknown_scenarios,
        }


def scenarios_for(agent: str) -> list[ScenarioRef]:
    """The scenarios an agent's risk assessment declares."""
    path = risk_assessment_path(agent)
    if path is None or not path.is_file():
        return []
    doc = yaml.safe_load(path.read_text()) or {}
    raw = doc.get("scenarios", []) if isinstance(doc, dict) else doc
    return [
        ScenarioRef(
            id=s["id"],
            inherent_tier=(s.get("inherent") or {}).get("tier", ""),
            residual_tier=(s.get("residual") or {}).get("tier", ""),
        )
        for s in raw or []
    ]


def load_cases(agent: str) -> list[dict[str, Any]]:
    path = dataset_path(agent)
    if not path.is_file():
        return []
    return (yaml.safe_load(path.read_text()) or {}).get("cases", []) or []


def coverage_for(agent: str) -> Coverage:
    """Cross the dataset's tags with the assessment's scenarios."""
    declared = {s.id: s for s in scenarios_for(agent)}
    cases = load_cases(agent)

    tagged: set[str] = set()
    by_category: dict[str, int] = {}
    for case in cases:
        category = case.get("category")
        if category:
            by_category[category] = by_category.get(category, 0) + 1
        for sid in case.get("scenarios", []) or []:
            tagged.add(sid)

    covered = sorted(sid for sid in tagged if sid in declared)
    uncovered = sorted(sid for sid in declared if sid not in tagged)
    return Coverage(
        agent=agent,
        covered=covered,
        uncovered=uncovered,
        uncovered_material=sorted(s for s in uncovered if declared[s].material),
        by_category=dict(sorted(by_category.items())),
        # A tag naming a scenario the assessment does not declare is a typo or a stale rename,
        # and silently ignoring it would let a case believe it covers something it does not.
        unknown_scenarios=sorted(sid for sid in tagged if sid not in declared),
        missing_categories=[c for c in CATEGORIES if c not in by_category],
    )


def agents_with_datasets() -> list[str]:
    root = agents_dir()
    return sorted(p.name for p in root.iterdir()
                  if (p / "evals" / "dataset.yaml").is_file())
