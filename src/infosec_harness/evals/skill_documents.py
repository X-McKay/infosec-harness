"""Skill document models, loading, and context-cost checks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic_ai_harness.compaction._shared import estimate_text_tokens
from pydantic_ai_harness.skills._loader import load_skill_libraries

from infosec_harness.resources import agents_dir as _agents_dir
from infosec_harness.resources import skills_dir as _skills_dir

SKILLS_DIR = _skills_dir()
AGENTS_DIR = _agents_dir()

# The nine case types the playbook names. Every one is accounted for by
# ``coverage_summary``, so an unnamed gap is indistinguishable from an oversight.
CASE_TYPES = (
    "activation",
    "non_activation",
    "ambiguity",
    "procedure_adherence",
    "cross_skill",
    "tool_use",
    "stopping",
    "safety",
    "context_cost",
)


class Status(StrEnum):
    """How — or whether — a case type is evaluated for a given skill."""

    STATIC = "static"
    """Checked for this skill by the static suite, with no model."""

    CASES = "cases"
    """Checked by authored scenarios in ``skills/<name>/evals/cases.yaml``."""

    ELSEWHERE = "elsewhere"
    """Really checked, but by another suite. Named so this one cannot take credit for it."""

    LIVE_ONLY = "live_only"
    """Not establishable without a model. Deliberately absent, not overlooked."""

    NOT_APPLICABLE = "not_applicable"
    """The case type does not describe anything this skill has."""


@dataclass(frozen=True)
class Coverage:
    """One skill's disposition on one case type, with the reason it is what it is."""

    case_type: str
    status: Status
    reason: str

    @property
    def is_evaluated(self) -> bool:
        """Whether *this* suite establishes it. ELSEWHERE is real coverage and not ours."""
        return self.status in (Status.STATIC, Status.CASES)


# --- Loading -------------------------------------------------------------------------------

# Skills that carry an executable recipe: shell commands, a probe body, or both. These are the
# ones procedure-adherence and safety cases can actually judge.
RECIPE_FAMILIES = ("build-", "test-")
RECIPE_SKILLS = frozenset({"partial-build", "probe-oracle-protocol"})
# Orientation skills: they describe where things live in an ecosystem. There is no procedure to
# adhere to and no artifact to judge, so claiming procedure cases for them would be filler.
ORIENTATION_FAMILIES = ("lang-", "cwe-")


class Verdict(StrEnum):
    """Which of two competing skills governs where their guidance disagrees."""

    WINS = "wins"
    """The declaring skill's guidance governs."""

    YIELDS = "yields"
    """The named skill's guidance governs."""


# The fixed phrases `scripts/restructure_skills.py` renders for each verdict. Parsing them back
# out of the published file is deliberate: the generator refuses prose that does not carry its
# own verdict, so these two forms are the only way a relation can reach a reader, and reading
# the file is how this module judges what the reader was actually told.
_VERDICT_PHRASES = {"this skill wins": Verdict.WINS, "that skill wins": Verdict.YIELDS}
_RELATION = re.compile(
    r"^`([a-z0-9-]+)`.*?\*\*(" + "|".join(_VERDICT_PHRASES) + r")\*\*", re.I | re.S
)


@dataclass(frozen=True)
class Relation:
    """One skill's declared precedence over another, as its ``SKILL.md`` states it."""

    skill: str
    target: str
    """The other skill. Empty when the bullet named none, which is itself the defect."""

    verdict: Verdict | None
    """``None`` when the bullet carried no verdict phrase and settles nothing."""

    text: str

    @property
    def winner(self) -> str | None:
        if self.verdict is Verdict.WINS:
            return self.skill
        if self.verdict is Verdict.YIELDS:
            return self.target
        return None


@dataclass(frozen=True)
class SkillDoc:
    """One ``SKILL.md`` as the *runtime* sees it, plus the sections the standard requires.

    Loaded through ``load_skill_libraries`` — the same function the ``Skills`` capability calls
    — so ``description`` and ``body`` are exactly the strings an agent is given, rather than a
    re-parse that could disagree with them.
    """

    name: str
    path: Path
    description: str
    body: str

    @property
    def use_when(self) -> list[str]:
        return _bullets(_section(self.body, "Use this skill when"))

    @property
    def avoid_when(self) -> list[str]:
        return _bullets(_section(self.body, "Do not use this skill when"))

    @property
    def relations(self) -> list[Relation]:
        """The precedence this skill declares over another, parsed from what it publishes.

        Read out of the rendered ``SKILL.md`` rather than out of ``scripts/skill_specs.py``:
        the file is what an agent is handed, so a rule that exists only in the generator is a
        rule no model has been told.
        """
        out: list[Relation] = []
        for bullet in _bullets(_section(self.body, "When another skill also applies")):
            match = _RELATION.match(bullet)
            if match is None:
                out.append(Relation(self.name, "", None, bullet))
                continue
            out.append(
                Relation(
                    self.name, match.group(1), _VERDICT_PHRASES[match.group(2).lower()], bullet
                )
            )
        return out

    @property
    def redirect_targets(self) -> frozenset[str]:
        """Skills the negative criteria send the reader to."""
        return frozenset(
            re.findall(
                r"`((?:cwe|lang|build|test|probe|partial)-[a-z0-9-]+)`", " ".join(self.avoid_when)
            )
        )

    @property
    def safety(self) -> list[str]:
        return _bullets(_section(self.body, "Safety constraints"))

    @property
    def completion(self) -> list[str]:
        return _bullets(_section(self.body, "Completion criteria"))

    @property
    def procedure(self) -> str:
        """The skill's own content: everything outside the generated regions and the title."""
        text = self.body
        for begin, end in (
            ("<!-- generated: activation criteria", "<!-- /generated: activation criteria -->"),
            ("<!-- generated: constraints", "<!-- /generated: constraints -->"),
        ):
            while begin in text and end in text:
                head, rest = text.split(begin, 1)
                text = head + rest.split(end, 1)[1]
        return "\n".join(ln for ln in text.splitlines() if not ln.strip().startswith("# "))

    @property
    def carries_a_recipe(self) -> bool:
        return self.name.startswith(RECIPE_FAMILIES) or self.name in RECIPE_SKILLS

    @property
    def cases_path(self) -> Path:
        return SKILLS_DIR / self.name / "evals" / "cases.yaml"


def _section(body: str, heading: str) -> str:
    """The text under ``## <heading>``, ending at the next heading or generated marker."""
    marker = f"## {heading}"
    if marker not in body:
        return ""
    rest = body.split(marker, 1)[1]
    for terminator in ("\n## ", "\n<!-- "):
        rest = rest.split(terminator, 1)[0]
    return rest.strip()


def _bullets(section: str) -> list[str]:
    """Top-level ``- `` bullets, with wrapped continuation lines rejoined."""
    items: list[str] = []
    for line in section.splitlines():
        if line.startswith("- "):
            items.append(line[2:].strip())
        elif items and line.strip() and not line.startswith(("#", "<!--")):
            items[-1] += " " + line.strip()
    return items


def load_skills(directory: Path | str = SKILLS_DIR) -> tuple[SkillDoc, ...]:
    """Every skill in the library, in name order, as the runtime loads it."""
    definitions = load_skill_libraries((str(directory),), include=None, exclude=frozenset())
    return tuple(
        sorted(
            (
                SkillDoc(
                    name=d.name,
                    path=Path(directory) / d.name / "SKILL.md",
                    description=d.description,
                    body=d.body,
                )
                for d in definitions
            ),
            key=lambda s: s.name,
        )
    )


# --- Context cost --------------------------------------------------------------------------

# Upstream refuses nothing but warns above this; tests run with warnings off, so the limit is
# invisible until a description is silently truncated by a provider. Asserted here instead.
UPSTREAM_DESCRIPTION_LIMIT = 1024
# House budget for the always-resident catalog entry. The largest today is 190 characters, so
# this is generous; its job is to make a description that grows into a second procedure a
# decision somebody takes rather than a drift nobody sees.
MAX_DESCRIPTION_CHARS = 400
# Largest body today is build-maven at ~3.3k tokens. A skill is read in full once loaded, so a
# body that doubles doubles what every agent loading it pays.
#
# Raised from 3000 deliberately, which is what this constant exists to force. build-maven grew by
# roughly 700 tokens when the Maven recipe stopped assuming JUnit 5: the framework/provider table,
# the framework-specific warm-up, the measured javac source floors (JDK 11 refuses -source 5, 17
# refuses 6, 21 refuses 7), what a pom's own Surefire `<configuration>` overrides, and Maven 3.8+'s
# http blocker. Each is a measurement that decides whether a Java target scores at all, and a
# compression pass took the body from 4.7k to 3.3k before this line moved. Only build-maven is near
# the limit; the next largest is test-junit4 at ~2.2k.
MAX_BODY_TOKENS = 3_400
# The share of an agent's own declared per-request input ceiling that its skills may occupy in
# the worst case (catalog always, plus every enabled body loaded). Highest today is intake at
# 37%, which is high because intake's ceiling is deliberately small (20k) while it enables all
# eight CWE skills; 40% leaves room to grow without letting the skill library quietly become
# the majority of a prompt. It moved from 31% when the CWE skills gained their precedence
# sections, which is the kind of growth this budget exists to make somebody notice: ten
# relations across eight skills cost intake about 1.1k tokens, and the next such addition has
# roughly 700 left before it has to argue for a bigger ceiling instead.
MAX_AGENT_SKILL_SHARE = 0.40


def description_tokens(skill: SkillDoc) -> int:
    return estimate_text_tokens(skill.description)


def body_tokens(skill: SkillDoc) -> int:
    return estimate_text_tokens(skill.body)


def context_cost_problems(skill: SkillDoc) -> list[str]:
    """Budget violations for one skill, as sentences naming the number and the ceiling."""
    problems: list[str] = []
    chars = len(skill.description)
    if chars > UPSTREAM_DESCRIPTION_LIMIT:
        problems.append(
            f"description is {chars} characters, over the Agent Skills limit of "
            f"{UPSTREAM_DESCRIPTION_LIMIT}; the Skills capability warns and the provider may "
            "truncate it, which silently degrades the one signal activation depends on"
        )
    elif chars > MAX_DESCRIPTION_CHARS:
        problems.append(
            f"description is {chars} characters, over the house budget of "
            f"{MAX_DESCRIPTION_CHARS}. A description is resident in the prompt of every agent "
            "that enables the skill whether or not it is ever loaded, so this is an "
            "unconditional tax; put the detail in the body, which is paid only on load"
        )
    tokens = body_tokens(skill)
    if tokens > MAX_BODY_TOKENS:
        problems.append(
            f"body is ~{tokens} tokens, over the budget of {MAX_BODY_TOKENS}. Every agent that "
            "loads this skill pays it in full, on the request that loads it and every later "
            "request in the same run"
        )
    return problems


@dataclass(frozen=True)
class AgentSkillCost:
    """What one agent's whole skill set costs against the ceiling that agent declares."""

    agent: str
    skills: tuple[str, ...]
    catalog_tokens: int
    """Descriptions, resident on every request whether or not anything is loaded."""

    body_tokens: int
    """Worst case: every enabled skill loaded in one run."""

    ceiling: int
    """The agent's own ``metadata.budgets.max_input_tokens_per_request``."""

    @property
    def total_tokens(self) -> int:
        return self.catalog_tokens + self.body_tokens

    @property
    def share(self) -> float:
        return self.total_tokens / self.ceiling if self.ceiling else 0.0


def skill_enablement(agents_dir: Path = AGENTS_DIR) -> dict[str, list[str]]:
    """agent -> the skills it enables, read from ``metadata.enabled_skills``."""
    out: dict[str, list[str]] = {}
    for path in sorted(agents_dir.glob("*/agent.yaml")):
        spec = yaml.safe_load(path.read_text()) or {}
        out[path.parent.name] = list((spec.get("metadata") or {}).get("enabled_skills") or [])
    return out


def _skills_capability_include(spec: dict) -> list[str] | None:
    """The include list the ``Skills`` capability actually applies, or None for "everything"."""
    for capability in spec.get("capabilities") or []:
        if isinstance(capability, dict) and "Skills" in capability:
            include = (capability["Skills"] or {}).get("include")
            return list(include) if include is not None else None
    return []


def capability_include(agents_dir: Path = AGENTS_DIR) -> dict[str, list[str] | None]:
    """agent -> the skills its ``Skills`` capability exposes (None means the whole library)."""
    out: dict[str, list[str] | None] = {}
    for path in sorted(agents_dir.glob("*/agent.yaml")):
        out[path.parent.name] = _skills_capability_include(yaml.safe_load(path.read_text()) or {})
    return out


def agent_skill_costs(
    skills: tuple[SkillDoc, ...] | None = None, agents_dir: Path = AGENTS_DIR
) -> list[AgentSkillCost]:
    """Price every agent's skill set against its own declared per-request input ceiling."""
    by_name = {s.name: s for s in (skills if skills is not None else load_skills())}
    costs: list[AgentSkillCost] = []
    for path in sorted(agents_dir.glob("*/agent.yaml")):
        spec = yaml.safe_load(path.read_text()) or {}
        metadata = spec.get("metadata") or {}
        enabled = [n for n in (metadata.get("enabled_skills") or []) if n in by_name]
        if not enabled:
            continue
        costs.append(
            AgentSkillCost(
                agent=path.parent.name,
                skills=tuple(enabled),
                catalog_tokens=sum(description_tokens(by_name[n]) for n in enabled),
                body_tokens=sum(body_tokens(by_name[n]) for n in enabled),
                ceiling=int((metadata.get("budgets") or {}).get("max_input_tokens_per_request", 0)),
            )
        )
    return costs


def orphan_skills(
    skills: tuple[SkillDoc, ...] | None = None, agents_dir: Path = AGENTS_DIR
) -> list[str]:
    """Skills no agent enables.

    A skill nothing enables is not merely unused: it is invisible. It passes every structural
    check, costs nothing, and delivers nothing, so adding one and forgetting to wire it into an
    agent is a silent no-op rather than a failure.
    """
    enabled = {n for names in skill_enablement(agents_dir).values() for n in names}
    return [
        s.name for s in (skills if skills is not None else load_skills()) if s.name not in enabled
    ]
