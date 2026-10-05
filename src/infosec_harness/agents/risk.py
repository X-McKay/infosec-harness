"""The risk scenario library: scored harm scenarios, their controls, and the agents they reach.

The data lives in ``agents/risk-scenarios.yaml`` and is hand-maintained. This module is the
only reader, so the two things derived from it -- an agent's governance tier and the set of
scenarios its eval dataset must cover -- are computed in exactly one place and never written
down anywhere they could drift.

Scoring follows agent-playbook §13: impact and likelihood on a 1-4 scale map to a tier through
the fixed matrix below. Governance tier is the highest of the agent's inherent scenario tiers
and any capability floor a scenario carries.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from typing import Any

import yaml

from infosec_harness.resources import agents_dir

TIER_ORDER = ("low", "medium", "high", "critical")

MATRIX = {  # (impact, likelihood) -> tier, from agent-playbook §13
    (1, 1): "low", (1, 2): "low", (1, 3): "medium", (1, 4): "medium",
    (2, 1): "low", (2, 2): "medium", (2, 3): "medium", (2, 4): "high",
    (3, 1): "medium", (3, 2): "medium", (3, 3): "high", (3, 4): "critical",
    (4, 1): "high", (4, 2): "high", (4, 3): "critical", (4, 4): "critical",
}

# Tiers the playbook calls material: these require eval coverage, and repeated runs when model
# behaviour is involved. A medium/low scenario may legitimately rely on a deterministic control
# rather than a behavioural case.
MATERIAL_TIERS = ("high", "critical")


def tier_for(impact: int, likelihood: int) -> str:
    return MATRIX[(impact, likelihood)]


def max_tier(tiers: list[str]) -> str:
    return max(tiers, key=TIER_ORDER.index)


@dataclass(frozen=True)
class Rating:
    impact: int
    likelihood: int
    confidence: str
    rationale: str

    @property
    def tier(self) -> str:
        return tier_for(self.impact, self.likelihood)


@dataclass(frozen=True)
class Control:
    id: str
    type: str
    description: str
    owner: str
    evidence: tuple[str, ...]
    effectiveness: str

    @property
    def verified(self) -> bool:
        return self.effectiveness == "verified"


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    inherent: Rating
    residual: Rating
    controls: tuple[Control, ...]
    capability_floor: str | None
    raw: dict[str, Any]

    @property
    def material(self) -> bool:
        """Judged on *inherent* tier, deliberately.

        Residual tier already assumes the controls work. Evals are part of how that assumption
        is tested, so letting residual decide what needs an eval would let a scenario excuse
        itself from the evidence for its own mitigation.
        """
        return self.inherent.tier in MATERIAL_TIERS


@dataclass(frozen=True)
class Library:
    controls: dict[str, Control]
    scenarios: dict[str, Scenario]
    agents: dict[str, tuple[str, ...]]

    def scenarios_for(self, agent: str) -> list[Scenario]:
        return [self.scenarios[sid] for sid in self.agents.get(agent, ())]

    def governance_tier(self, agent: str) -> str:
        """The highest of the agent's inherent scenario tiers and any capability floor (§13)."""
        scenarios = self.scenarios_for(agent)
        if not scenarios:
            raise KeyError(f"{agent!r} is not in the risk scenario library")
        return max_tier([s.inherent.tier for s in scenarios]
                        + [s.capability_floor for s in scenarios if s.capability_floor])


def _rating(data: dict[str, Any]) -> Rating:
    return Rating(int(data["impact"]), int(data["likelihood"]), str(data["confidence"]),
                  str(data["rationale"]))


def parse(doc: dict[str, Any]) -> Library:
    controls = {
        cid: Control(cid, c["type"], c["description"], c["owner"], tuple(c.get("evidence") or ()),
                     c["effectiveness"])
        for cid, c in (doc.get("controls") or {}).items()
    }
    scenarios: dict[str, Scenario] = {}
    for sid, s in (doc.get("scenarios") or {}).items():
        missing = [cid for cid in s.get("controls") or [] if cid not in controls]
        if missing:
            raise ValueError(f"{sid} credits controls that are not defined: {missing}")
        floor = s.get("capability_floor")
        if floor is not None and floor not in TIER_ORDER:
            raise ValueError(f"{sid}: capability_floor must be one of {TIER_ORDER}")
        scenarios[sid] = Scenario(
            id=sid, title=str(s["title"]), inherent=_rating(s["inherent"]),
            residual=_rating(s["residual"]),
            controls=tuple(controls[cid] for cid in s.get("controls") or []),
            capability_floor=floor, raw=s,
        )
    agents: dict[str, tuple[str, ...]] = {}
    for agent, ids in (doc.get("agents") or {}).items():
        unknown = [sid for sid in ids if sid not in scenarios]
        if unknown:
            raise ValueError(f"agents.{agent} names scenarios that do not exist: {unknown}")
        agents[agent] = tuple(ids)
    return Library(controls, scenarios, agents)


@cache
def library() -> Library:
    path = agents_dir() / "risk-scenarios.yaml"
    return parse(yaml.safe_load(path.read_text()) or {})
