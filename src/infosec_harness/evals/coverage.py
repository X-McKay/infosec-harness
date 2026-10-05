"""Which risk scenarios a set of eval cases actually exercises.

The agent playbook (07-evaluation) makes this a release blocker, not a report:

    Every material risk scenario has a stable ID used as an eval tag. ... An eval report
    identifies covered and uncovered scenario IDs. Missing required coverage, failed hard
    gates, or absent control evidence blocks release. Passing average quality cannot
    compensate for an uncovered material risk.

The scenarios an agent carries come from ``agents/risk-scenarios.yaml``; the cases are tagged
with the scenario IDs they cover. Coverage is computed statically, from those two inputs, with
no model involved: over the agent's own dataset in the ordinary test suite (so a scenario added
to the library fails the build immediately), and over exactly the cases a run used when a run
reports it (so a group-filtered or held-out run cannot borrow coverage it did not exercise).
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from infosec_harness.runtime.risk import Scenario, library

__all__ = ["ScenarioCoverage", "scenario_coverage", "scenarios_for"]


@dataclass
class ScenarioCoverage:
    agent: str
    covered: list[str] = field(default_factory=list)
    uncovered: list[str] = field(default_factory=list)
    uncovered_material: list[str] = field(default_factory=list)
    by_category: dict[str, int] = field(default_factory=dict)
    unknown_scenarios: list[str] = field(default_factory=list)

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


def scenario_coverage(agent: str, cases: Iterable[Mapping[str, Any]]) -> ScenarioCoverage:
    """Cross the cases' tags with the library's scenarios for ``agent``."""
    declared = {s.id: s for s in scenarios_for(agent)}
    tagged: set[str] = set()
    by_category: dict[str, int] = {}
    for case in cases:
        if category := case.get("category"):
            by_category[category] = by_category.get(category, 0) + 1
        tagged.update(case.get("scenarios") or [])
    uncovered = sorted(sid for sid in declared if sid not in tagged)
    return ScenarioCoverage(
        agent=agent,
        covered=sorted(sid for sid in tagged if sid in declared),
        uncovered=uncovered,
        uncovered_material=sorted(s for s in uncovered if declared[s].material),
        by_category=dict(sorted(by_category.items())),
        # A tag naming a scenario the library does not attribute to this agent is a typo or a
        # stale rename, and silently ignoring it would let a case believe it covers something
        # it does not.
        unknown_scenarios=sorted(sid for sid in tagged if sid not in declared),
    )
