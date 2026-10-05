"""Which risk scenarios an agent's eval dataset actually exercises.

The agent playbook (07-evaluation) makes this a release blocker, not a report:

    Every material risk scenario has a stable ID used as an eval tag. ... An eval report
    identifies covered and uncovered scenario IDs. Missing required coverage, failed hard
    gates, or absent control evidence blocks release. Passing average quality cannot
    compensate for an uncovered material risk.

The scenarios an agent carries come from ``agents/risk-scenarios.yaml``; the cases come from
``agents/<name>/evals/dataset.yaml``, each tagged with the scenario IDs it covers. Coverage is
computed statically, from those two files, with no model involved. That matters: it means the
check runs in the ordinary test suite rather than only after a live eval, so a scenario added
to the library fails the build immediately instead of at release time.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from infosec_harness.agents.risk import MATERIAL_TIERS, Scenario, library
from infosec_harness.resources import agents_dir

__all__ = ["CATEGORIES", "MATERIAL_TIERS", "Coverage", "agents_with_datasets", "coverage_for",
           "dataset_path", "load_cases", "scenarios_for"]

# The dataset categories the playbook names. Every case declares exactly one, so a dataset can
# be read for what it actually exercises rather than inferred from case names.
CATEGORIES = ("smoke", "regression", "capability", "safety", "adversarial", "durability")


def dataset_path(agent: str) -> Path:
    """Packaged beside the spec it grades, so a release check can run against the wheel."""
    return agents_dir() / agent / "evals" / "dataset.yaml"


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


def scenarios_for(agent: str) -> list[Scenario]:
    """The scenarios the library attributes to an agent."""
    return library().scenarios_for(agent)


def load_cases(agent: str) -> list[dict[str, Any]]:
    path = dataset_path(agent)
    if not path.is_file():
        return []
    return (yaml.safe_load(path.read_text()) or {}).get("cases", []) or []


def coverage_for(agent: str) -> Coverage:
    """Cross the dataset's tags with the library's scenarios."""
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
        # A tag naming a scenario the library does not attribute to this agent is a typo or a
        # stale rename, and silently ignoring it would let a case believe it covers something
        # it does not.
        unknown_scenarios=sorted(sid for sid in tagged if sid not in declared),
        missing_categories=[c for c in CATEGORIES if c not in by_category],
    )


def agents_with_datasets() -> list[str]:
    root = agents_dir()
    return sorted(p.name for p in root.iterdir()
                  if (p / "evals" / "dataset.yaml").is_file())
