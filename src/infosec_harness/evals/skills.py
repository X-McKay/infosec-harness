"""Skill evals: what can be established about a skill *without* a model, and what cannot.

Why this module is smaller than the requirement looks
-----------------------------------------------------
The playbook (07-evaluation) asks for nine case types per skill — activation,
non-activation, ambiguity, procedure adherence, cross-skill interaction, tool use, stopping,
safety, and context cost. Twenty-four skills times nine is 216 cases, and the honest answer
is that most of them could not fail.

That is the same hazard :mod:`infosec_harness.evals.inert_gates` exists to name: a check that
is structurally incapable of failing is worse than no check, because it reads as coverage. A
suite of 216 cases in which most are filler would report "every skill fully evaluated" while
testing four things. So each case type is triaged here, once, and the triage is *reported*
(see :func:`coverage_summary` and :func:`format_coverage_notice`) rather than hidden: a skill
with no behavioural cases says so, with the reason, at the point the evidence is produced.

The triage
----------
Three questions decide where a case type lands.

1. *Can it fail without a model?* Context cost, activation/non-activation structure, stopping
   criteria, enumeration counts and body substance are all properties of the file. They are
   checked statically for **all 24** skills, and they are cheap.
2. *Does the skill carry a recipe the harness itself can judge?* The ``build-*`` and ``test-*``
   skills show commands and probe bodies, and this repository already owns deterministic
   judges for exactly those artifacts —
   :func:`infosec_harness.agents.validators.environment_spec_violations` and friends. So
   "procedure adherence" and "safety" become real, executable cases for those skills: every
   command and probe a skill *shows* is run through the validator that would judge the same
   artifact coming from a live agent.
3. *Does it need a model?* Ambiguity splits in two, and only one half does. Whether a model
   *follows* a precedence rule needs a live run. Whether the library states one at all is a
   property of the files — and it did not: two skills whose negative criteria each redirect to
   the other left the overlap (a repository carrying both a ``pom.xml`` and a ``build.gradle``,
   an ``eval`` of a string that runs a shell command) with no rule to follow, so the agent
   guessed and no measurement could have told us which way. Declaring the rule is the fix;
   :func:`ambiguity_problems` checks that every competing pair has one and that the two sides
   agree, and the summary keeps saying that adherence is unmeasured.

Routing every judgement through the *production* validator, rather than a copy of its rules,
is deliberate and copied from ``inert_gates``: a check that restates the rule drifts from it,
and then passes while the thing it describes is broken.

The two costs a skill imposes
-----------------------------
``pydantic_ai_harness.skills`` turns each ``SKILL.md`` into a deferred capability, so a skill
is paid for twice and the two prices are very different:

* its **description** is a catalog entry, resident in the system prompt of every agent that
  enables the skill, whether or not the skill is ever loaded — an unconditional tax;
* its **body** is the instruction text, paid only when the model loads it.

:func:`agent_skill_costs` prices both against the ceiling the agent *itself* declares
(``metadata.budgets.max_input_tokens_per_request``), so the budget is anchored to the number
that already governs the agent rather than to one invented here.
"""

from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic_ai import ModelRetry
from pydantic_ai_harness.compaction._shared import estimate_text_tokens
from pydantic_ai_harness.skills._loader import load_skill_libraries

from infosec_harness.agents.validators import (
    environment_spec_violations,
    install_path_violations,
    offline_warmup_violations,
    validate_probe,
)
from infosec_harness.domain.models import EnvironmentSpec, ProbeSource
from infosec_harness.settings import REPO_ROOT

__all__ = [
    "AMBIGUITY_RESIDUE",
    "CASE_TYPES",
    "COMPETING_PAIRS",
    "COMPOSING_PAIRS",
    "MAX_AGENT_SKILL_SHARE",
    "MAX_BODY_TOKENS",
    "MAX_DESCRIPTION_CHARS",
    "UPSTREAM_DESCRIPTION_LIMIT",
    "AgentSkillCost",
    "CompetingPair",
    "Coverage",
    "Relation",
    "ShellCommand",
    "SkillCase",
    "SkillDoc",
    "Status",
    "Verdict",
    "activation_problems",
    "ambiguity_problems",
    "agent_skill_costs",
    "competing_pairs_for",
    "mutual_redirects",
    "body_substance_problems",
    "body_tokens",
    "completion_problems",
    "context_cost_problems",
    "coverage_summary",
    "enumeration_problems",
    "command_violations",
    "extract_commands",
    "extract_exemplar_specs",
    "extract_probe_exemplars",
    "illustrative_commands",
    "format_coverage_notice",
    "load_cases",
    "load_skills",
    "non_activation_problems",
    "orphan_skills",
    "probe_exemplar_violations",
    "resolve_placeholders",
    "run_case",
    "skill_enablement",
    "spec_violations",
]

SKILLS_DIR = REPO_ROOT / "skills"
AGENTS_DIR = REPO_ROOT / "agents"

# The nine case types the playbook names. Every one is accounted for by `coverage_summary`,
# which is the point: an unnamed gap is indistinguishable from an oversight.
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
                Relation(self.name, match.group(1), _VERDICT_PHRASES[match.group(2).lower()],
                         bullet)
            )
        return out

    @property
    def redirect_targets(self) -> frozenset[str]:
        """Skills the negative criteria send the reader to."""
        return frozenset(
            re.findall(r"`((?:cwe|lang|build|test|probe|partial)-[a-z0-9-]+)`",
                       " ".join(self.avoid_when))
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
    return [s.name for s in (skills if skills is not None else load_skills()) if s.name not in enabled]


# --- Activation, non-activation, stopping --------------------------------------------------


def activation_problems(skill: SkillDoc) -> list[str]:
    """The positive criteria must exist and be specific enough to discriminate on."""
    problems: list[str] = []
    if not skill.use_when:
        problems.append("has no '## Use this skill when' bullets, so nothing says when it applies")
    for item in skill.use_when:
        if len(item) < 20:
            problems.append(f"activation criterion is too terse to discriminate on: {item!r}")
    return problems


def _normalise(text: str) -> str:
    """Lowercased, punctuation-free form, for comparing two bullets for sameness."""
    return " ".join(re.findall(r"[a-z0-9{}]+", text.lower()))


def non_activation_problems(skill: SkillDoc, known_skills: frozenset[str]) -> list[str]:
    """The negative criteria must exist, not redirect to the skill itself, and not restate a
    positive criterion verbatim.

    Deliberately narrow. The interesting question — do these two bullets describe the *same*
    situation in different words — is not decidable statically: ``cwe-611`` activates on "entity
    processing is not disabled" and deactivates on "entity resolution disabled", which any
    word-overlap measure reads as a collision and which is in fact the correct complementary
    pair. A check that flags those trains its readers to ignore it, so only contradictions that
    are unambiguous from the text are raised here, and the semantic version is reported as
    needing a model. Redirect targets are checked by tests/test_skills_consistency.py; they are
    not re-checked here.
    """
    problems: list[str] = []
    if not skill.avoid_when:
        problems.append(
            "has no '## Do not use this skill when' bullets. Without them the description is the "
            "only thing keeping the skill from being loaded on every adjacent finding"
        )
    positives = {_normalise(item) for item in skill.use_when}
    for item in skill.avoid_when:
        if _normalise(item) in positives:
            problems.append(
                f"names the same condition as both a reason to use the skill and a reason not "
                f"to: {item!r}. A model reading both has been told to load and not load it at once"
            )
        if re.search(rf"`{re.escape(skill.name)}`", item):
            problems.append(
                f"redirects to itself ({skill.name}) in {item!r}, which leaves the reader with "
                "nowhere to go"
            )
    return problems


def completion_problems(skill: SkillDoc) -> list[str]:
    """Stopping criteria must exist, be decidable, and not repeat one another.

    Checked structurally rather than semantically, and that limit is worth stating: whether a
    criterion is genuinely *actionable* is a judgement, and every cheap proxy for it produced
    false positives here — "Install commands come from the repository's own manifests" opens
    with an imperative verb used as a noun, and an opener-based test flags all five build
    skills for it. Structure plus a length floor catches the failure that actually occurs (a
    criterion generated empty or reduced to a stub); the rest is left to review.
    """
    problems: list[str] = []
    if not skill.completion:
        problems.append("has no '## Completion criteria', so nothing says when the skill is done")
    seen: set[str] = set()
    for item in skill.completion:
        if len(item) < 25:
            problems.append(f"completion criterion is too vague to decide against: {item!r}")
        key = _normalise(item)
        if key in seen:
            problems.append(f"completion criterion is listed twice: {item!r}")
        seen.add(key)
    return problems


# --- Ambiguity: which skill wins when two of them fire -------------------------------------


@dataclass(frozen=True)
class CompetingPair:
    """Two skills one situation can satisfy at once, where only one of them can be right."""

    a: str
    b: str
    situation: str
    """The concrete case that fires both. A pair without one is a pair nobody has to resolve."""

    @property
    def key(self) -> tuple[str, str]:
        return _pair(self.a, self.b)


def _pair(a: str, b: str) -> tuple[str, str]:
    return (a, b) if a <= b else (b, a)


# Pairs a single repository, finding, or task can satisfy on both sides. Each was reached by
# reading the activation criteria of all 24 skills and asking what input satisfies both; the
# situation is recorded so the list can be argued with rather than trusted. Deliberately short.
# The families that merely *overlap* are in COMPOSING_PAIRS below and are not listed here,
# because a resolution asserted between two skills that never disagree is the decorative
# coverage `evals/inert_gates.py` exists to name: it would raise this suite's ambiguity number
# and tell a reader nothing.
COMPETING_PAIRS = (
    CompetingPair(
        "build-maven", "build-gradle",
        "a repository carrying both a pom.xml and a build.gradle — a Gradle build kept beside "
        "a published pom, or a migration half done — satisfies each skill's positive criteria "
        "while each skill's negative criteria send the reader to the other",
    ),
    CompetingPair(
        "cwe-78-os-command-injection", "cwe-94-code-injection",
        "an eval of a string that the evaluated code then hands to a shell is both 'evaluated "
        "as program source' and 'reaches a shell', which is the exact wording of the two "
        "skills' mutual redirects",
    ),
    CompetingPair(
        "cwe-78-os-command-injection", "cwe-89-sql-injection",
        "a query issued through a command-line database client (psql -c, mysql -e) puts the "
        "same untrusted value into a shell command and into SQL, and each skill's negative "
        "criteria point at the other",
    ),
    CompetingPair(
        "cwe-22-path-traversal", "cwe-918-ssrf",
        "a caller-chosen URL resolved by a fetcher that accepts file: both chooses a request "
        "destination and names a filesystem path",
    ),
    CompetingPair(
        "cwe-502-deserialization", "cwe-611-xxe",
        "XML handed to a reader that instantiates the types the document names (XMLDecoder, "
        "XStream) is untrusted XML and untrusted serialized bytes at once, and cwe-502's "
        "negative criteria send every XML payload to cwe-611",
    ),
    CompetingPair(
        "cwe-89-sql-injection", "probe-oracle-protocol",
        "the protocol forbids mocking the sink while cwe-89's structure oracle needs to see the "
        "statement the driver received; the more specific skill won and a wrapped cursor the "
        "target never used reported a clean negative on an exploitable finding "
        "(docs/LIVE_VALIDATION.md)",
    ),
    CompetingPair(
        "cwe-918-ssrf", "probe-oracle-protocol",
        "an SSRF probe has to substitute the transport because the sandbox has no egress, which "
        "is precisely what the protocol's 'do not mock the sink' rule forbids",
    ),
    CompetingPair(
        "test-junit4", "test-junit5",
        "a repository with both junit:junit and junit-jupiter on its test classpath -- a "
        "migration part-done, which is ordinary -- satisfies each skill's positive criteria "
        "while each skill's negative criteria send the reader to the other. The tie is decided "
        "by a measurement rather than taste: Surefire 3.2.5 selects the JUnit Platform provider "
        "as soon as jupiter is present, and a JUnit-4-annotated probe then reports "
        "`Tests run: 0` and exits 0",
    ),
)

_COMPOSE_LANG_BUILD = (
    "one orients the reader in the repository and the other plans its build; the two are "
    "split by task, not by a contest, and an env-planner that reads both has been helped twice"
)
_COMPOSE_PARTIAL = (
    "partial-build narrows the scope and the build-* skill still supplies the recipe inside "
    "it — partial-build's own Maven bullet defers to build-maven for the repo-local flag. The "
    "entry condition (the full build exhausted its repair budget) is already stated in "
    "partial-build's negative criteria, so the ordering is declared and there is no winner"
)
_COMPOSE_PROTOCOL_TEST = (
    "the protocol defines the markers and the test-* skill shows the shape in one framework; "
    "each test-* skill's negative criteria already say to read the protocol first, and the "
    "protocol's closing line says the test-* skills render it per framework"
)

# Pairs that fire together and do not compete. Listed, rather than left out, for two reasons: a
# mutual redirect between two of them would otherwise read as an unclassified deadlock, and
# declaring a winner for one of these is an error this module reports — the guard against
# padding the ambiguity number with pairs that never disagree.
COMPOSING_PAIRS: dict[tuple[str, str], str] = {
    **{_pair(lang, build): _COMPOSE_LANG_BUILD
       for lang, build in (("lang-python", "build-python"), ("lang-java", "build-maven"),
                           ("lang-java", "build-gradle"), ("lang-javascript", "build-npm"),
                           ("lang-perl", "build-cpanm"))},
    **{_pair("partial-build", build): _COMPOSE_PARTIAL
       for build in ("build-python", "build-maven", "build-gradle", "build-npm",
                     "build-cpanm")},
    **{_pair("probe-oracle-protocol", test): _COMPOSE_PROTOCOL_TEST
       for test in ("test-pytest", "test-junit4", "test-junit5", "test-jest",
                    "test-perl-test-more")},
}


def mutual_redirects(skills: tuple[SkillDoc, ...]) -> set[tuple[str, str]]:
    """Pairs whose negative criteria each send the reader to the other.

    A circular redirect is the structural signature of an unresolved ambiguity: every situation
    in the overlap is answered by "use the other skill" from both sides. Deriving the candidates
    instead of only listing them is what makes the classification below load-bearing — a redirect
    added later cannot slip in unclassified.
    """
    by_name = {s.name: s for s in skills}
    return {
        _pair(skill.name, target)
        for skill in skills
        for target in skill.redirect_targets
        if target in by_name and skill.name in by_name[target].redirect_targets
    }


def competing_pairs_for(name: str) -> tuple[CompetingPair, ...]:
    return tuple(p for p in COMPETING_PAIRS if name in (p.a, p.b))


def ambiguity_problems(skills: tuple[SkillDoc, ...]) -> list[str]:
    """Everything wrong with what the library says about two skills both applying.

    Four things are checked, and none of them is about a model: every competing pair has a
    resolution declared by at least one of its two skills; the two sides do not name different
    winners; a declared relation names a skill that exists and a pair that was classified as
    competing; and no pair a structural reading flags as a deadlock is left untriaged.
    """
    names = {s.name for s in skills}
    problems: list[str] = []
    declared: dict[tuple[str, str], list[Relation]] = {}

    for skill in skills:
        for relation in skill.relations:
            if not relation.target or relation.verdict is None:
                problems.append(
                    f"{skill.name}: the relation {relation.text[:60]!r} names no skill or no "
                    "verdict, so a reader in the overlap is no better off than before"
                )
                continue
            if relation.target not in names:
                problems.append(
                    f"{skill.name} declares precedence over {relation.target!r}, which is not a "
                    "skill in this library"
                )
                continue
            key = _pair(skill.name, relation.target)
            if key in COMPOSING_PAIRS:
                problems.append(
                    f"{skill.name} declares a winner against {relation.target}, but that pair is "
                    f"classified as composing: {COMPOSING_PAIRS[key]}. Asserting a winner where "
                    "the two never disagree answers a question nobody asked"
                )
                continue
            if key not in {p.key for p in COMPETING_PAIRS}:
                problems.append(
                    f"{skill.name} declares a winner against {relation.target}, a pair COMPETING_"
                    "PAIRS does not classify. Name the situation that fires both, or drop the "
                    "relation: an unexplained precedence rule cannot be reviewed"
                )
                continue
            declared.setdefault(key, []).append(relation)

    for pair in COMPETING_PAIRS:
        for name in (pair.a, pair.b):
            if name not in names:
                problems.append(f"COMPETING_PAIRS names {name!r}, which is not a skill")
        relations = declared.get(pair.key, [])
        if not relations:
            problems.append(
                f"{pair.a} and {pair.b} both apply when {pair.situation}, and neither declares "
                "which one wins. A reader in that overlap is left to guess, and whatever the "
                "model then does is unmeasurable because there was no rule to follow"
            )
            continue
        winners = {r.winner for r in relations}
        if len(winners) > 1:
            problems.append(
                f"{pair.a} and {pair.b} disagree about which of them wins: "
                + "; ".join(f"{r.skill} says {r.winner}" for r in relations)
                + ". Two skills contradicting each other is the failure this repository has "
                "already paid for once (docs/LIVE_VALIDATION.md)"
            )

    for key in sorted(mutual_redirects(skills)):
        if key in COMPOSING_PAIRS or key in {p.key for p in COMPETING_PAIRS}:
            continue
        problems.append(
            f"{key[0]} and {key[1]} each redirect to the other and neither COMPETING_PAIRS nor "
            "COMPOSING_PAIRS classifies the pair, so a situation matching both is a loop with "
            "no exit. Classify it"
        )
    return problems


# --- Enumeration counts --------------------------------------------------------------------

_CARDINALS = {"two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7}
# Headings like "## The three markers" promise a count the section below must deliver. Two
# agent prompts said "two markers" against a protocol defining three, for long enough to be
# measured, so a count and its enumeration drifting apart is a known failure here.
_COUNTED_HEADING = re.compile(
    r"^#{2,3}\s+(?:the\s+)?(" + "|".join(_CARDINALS) + r")\s+([a-z][a-z -]*)$",
    re.I | re.M,
)


def enumeration_problems(skill: SkillDoc) -> list[str]:
    """A heading that states a count must be followed by exactly that many enumerated items."""
    problems: list[str] = []
    body = skill.body
    for match in _COUNTED_HEADING.finditer(body):
        promised = _CARDINALS[match.group(1).lower()]
        rest = body[match.end() :]
        # The section ends at the next heading of the same or higher level.
        rest = re.split(r"^#{1,3}\s", rest, maxsplit=1, flags=re.M)[0]
        numbered = len(re.findall(r"^\d+\.\s", rest, re.M))
        bulleted = len(re.findall(r"^[-*]\s", rest, re.M))
        found = numbered or bulleted
        if found and found != promised:
            problems.append(
                f"heading {match.group(0).strip()!r} promises {promised} items but the section "
                f"enumerates {found}. A stated count and its list drifting apart is how "
                "'two markers' survived against a three-marker protocol"
            )
    return problems


# --- Body substance ------------------------------------------------------------------------

# A generator that inferred its regions from heading positions once deleted the body of all 24
# skills, and every structural test still passed because the required sections were present.
# A floor on the skill's *own* content is the cheap insurance against that repeating.
MIN_PROCEDURE_TOKENS = 60


def body_substance_problems(skill: SkillDoc) -> list[str]:
    """The skill must still have content of its own outside the generated sections."""
    tokens = estimate_text_tokens(skill.procedure)
    if tokens < MIN_PROCEDURE_TOKENS:
        return [
            f"has only ~{tokens} tokens of content outside its generated sections (floor "
            f"{MIN_PROCEDURE_TOKENS}). The structure is added around a procedure, never instead "
            "of one; a skill this thin has probably had its body eaten"
        ]
    return []


# --- Extracting the recipes a skill shows --------------------------------------------------

_RUNNER_HEADS = ("mvn", "mvnw", "./mvnw", "gradle", "gradlew", "./gradlew", "prove", "pytest",
                 "npx", "npm", "python", "python3", "cpanm", "pip")
# Fenced blocks in these languages are probe bodies, not shell.
_PROBE_LANGS = {
    "python": "tests/test_harness_probe.py",
    "java": "src/test/java/com/example/HarnessProbeTest.java",
    "perl": "t/harness_probe.t",
    "js": "__tests__/harness_probe.test.js",
    "javascript": "__tests__/harness_probe.test.js",
}
_SHELL_LANGS = {"", "sh", "bash", "shell", "console"}
_FENCE = re.compile(r"```(\w*)\n(.*?)```", re.S)


class CommandKind(StrEnum):
    """Which validator family judges a command the skill shows."""

    TEST = "test"
    """Goes in ``EnvironmentSpec.test_command``."""

    INSTALL = "install"
    """Goes in ``EnvironmentSpec.install_commands``."""


@dataclass(frozen=True)
class ShellCommand:
    text: str
    kind: CommandKind
    source: str
    """``fence`` or ``inline`` — where in the skill it was shown."""


# What marks a command as the one that runs the probe rather than one that prepares the image.
_TEST_MARKERS = ("{test_file}", "-Dtest=", "--tests", "--runTestsByPath")
_INSTALL_MARKERS = ("-DskipTests", "testClasses", "HarnessWarmupTest", "pip install", "npm ci",
                    "npm install", "cpanm", "--version", "dependency:get")


def _classify(command: str) -> CommandKind | None:
    if any(marker in command for marker in _INSTALL_MARKERS):
        return CommandKind.INSTALL
    if any(marker in command for marker in _TEST_MARKERS):
        return CommandKind.TEST
    if command.split()[0] in ("prove", "pytest") and len(command.split()) > 1:
        return CommandKind.TEST
    return None


def extract_commands(skill: SkillDoc) -> list[ShellCommand]:
    """Every runnable command the skill shows, classified as a test or an install command.

    Both fenced shell blocks and inline code spans count: ``test-junit5`` shows its Maven
    command as an inline span wrapped over three lines, and that is the exemplar an author
    copies. Line continuations and wrapping are normalised so the span is judged as the one
    command it represents.

    Commands whose role cannot be determined are dropped rather than guessed at: a mis-filed
    install command judged as a test command would fail for a rule that does not apply to it,
    and a check with false positives gets disabled.
    """
    body = skill.procedure
    candidates: list[tuple[str, str]] = []

    fenced: list[str] = []
    for match in _FENCE.finditer(body):
        lang, code = match.group(1).lower(), match.group(2)
        fenced.append(match.group(0))
        if lang not in _SHELL_LANGS:
            continue
        for line in code.replace("\\\n", " ").splitlines():
            candidates.append(("fence", line))

    # Inline spans, with fenced blocks removed first so a fence's backticks cannot pair up
    # with a later inline one and splice unrelated text into a "command".
    prose = body
    for block in fenced:
        prose = prose.replace(block, "\n")
    for match in re.finditer(r"`([^`]+)`", prose):
        candidates.append(("inline", match.group(1)))

    out: list[ShellCommand] = []
    seen: set[str] = set()
    for source, raw in candidates:
        text = " ".join(raw.replace("\\", " ").split())
        if not text or text in seen:
            continue
        head = text.split()[0]
        if head not in _RUNNER_HEADS:
            continue
        kind = _classify(text)
        if kind is None:
            continue
        seen.add(text)
        out.append(ShellCommand(text=text, kind=kind, source=source))
    return out


def extract_exemplar_specs(skill: SkillDoc) -> list[EnvironmentSpec]:
    """Complete ``EnvironmentSpec`` exemplars the skill shows in a YAML fence.

    ``build-cpanm`` presents its recipe as install commands, ``env`` and ``test_command``
    together, which is the whole artifact an env-planner emits — so it can be judged whole, by
    every validator including the ones about coherence *between* those fields.
    """
    specs: list[EnvironmentSpec] = []
    for match in _FENCE.finditer(skill.procedure):
        if match.group(1).lower() != "yaml":
            continue
        try:
            data = yaml.safe_load(resolve_placeholders(match.group(2)))
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict) or "test_command" not in data:
            continue
        data.setdefault("base_image", "perl:5.38-slim")
        specs.append(EnvironmentSpec.model_validate(
            {k: v for k, v in data.items() if k in EnvironmentSpec.model_fields}
        ))
    return specs


def extract_probe_exemplars(skill: SkillDoc) -> list[tuple[str, str, str]]:
    """``(language, assumed test path, source)`` for each probe body the skill shows."""
    out: list[tuple[str, str, str]] = []
    for match in _FENCE.finditer(skill.procedure):
        lang = match.group(1).lower()
        if lang in _PROBE_LANGS and "HARNESS_" in match.group(2):
            out.append((lang, _PROBE_LANGS[lang], match.group(2)))
    return out


# --- Judging them with the production validators -------------------------------------------

# Placeholders a skill legitimately shows in place of a value the author supplies. They are
# substituted before validation so the validators judge the shape, not the placeholder.
_PLACEHOLDERS = {
    "<ProbeClassName>": "HarnessProbeTest",
    "<fqcn>": "com.example.HarnessProbeTest",
    "<module>": "service",
    "<subproject>": "service",
    "<nonce>": "abc123",
    "<settings.xml>": "settings.xml",
}


def resolve_placeholders(text: str) -> str:
    for placeholder, value in _PLACEHOLDERS.items():
        text = text.replace(placeholder, value)
    return text


def spec_violations(spec: EnvironmentSpec) -> list[str]:
    """Every deterministic objection the harness would raise to this spec.

    The three production validators, in the order ``validate_environment_spec`` applies them,
    so a spec this function calls clean is one a live agent could have emitted without being
    told to retry.
    """
    return (
        environment_spec_violations(spec)
        + install_path_violations(spec)
        + offline_warmup_violations(spec)
    )


# A benign counterpart for judging one command on its own. The PERL5LIB entry is present
# because `install_path_violations` couples a cpanm install to it: judging a lone install
# command without it would report the *spec's* incoherence as a fault of the command. Spec
# coherence is judged instead by `extract_exemplar_specs`, where a whole spec is actually shown.
_FILLER_TEST_COMMAND = "python -m pytest -q -s {test_file}"
_FILLER_ENV = {"PERL5LIB": "/work/home/perl5/lib/perl5"}


def command_violations(command: ShellCommand) -> list[str]:
    """The harness's objections to a single command the skill shows, judged on its own.

    ``offline_warmup_violations`` is deliberately not applied: it asks whether the *install*
    commands warmed what the *test* command needs, which is a property of a whole spec and not
    of any one line. Applying it here would report every Maven test command as defective for a
    reason belonging to a different command.
    """
    if command.kind is CommandKind.TEST:
        spec = EnvironmentSpec(
            base_image="scratch", test_command=resolve_placeholders(command.text), env=dict(_FILLER_ENV)
        )
    else:
        spec = EnvironmentSpec(
            base_image="scratch",
            test_command=_FILLER_TEST_COMMAND,
            install_commands=[resolve_placeholders(command.text)],
            env=dict(_FILLER_ENV),
        )
    return environment_spec_violations(spec) + install_path_violations(spec)


def probe_exemplar_violations(test_file_path: str, content: str) -> list[str]:
    """The harness's own objections to a probe body, via the production validator.

    Passing ``None`` for the ``RunContext`` runs the real rules rather than a restatement of them
    that could drift. ``validate_probe`` reads the checkout through the context when it has one,
    to know the repository's test framework and language level, and tolerates its absence: the
    framework-dependent rules simply stay silent here, so a case can only pin the ones that hold
    for any repository. The repo-aware pairings are covered in tests/test_validators.py, which can
    build a checkout.
    """
    try:
        validate_probe(None, ProbeSource(test_file_path=test_file_path, content=content))
    except ModelRetry as exc:
        body = str(exc).split(":\n- ", 1)
        return [p.strip() for p in body[-1].split("\n- ") if p.strip()] if len(body) > 1 else [str(exc)]
    return []


# --- Authored cases ------------------------------------------------------------------------


@dataclass(frozen=True)
class SkillCase:
    """One authored scenario for a skill, executable against the production validators."""

    skill: str
    id: str
    type: str
    scenario: str
    regression: str = ""
    environment_spec: dict[str, Any] | None = None
    probe: dict[str, Any] | None = None
    expect_violations: tuple[str, ...] = ()
    """Substrings, each of which must appear in some violation. Empty means "expect clean"."""

    shown_in_skill: tuple[str, ...] = ()
    """Strings that must still appear in the SKILL.md, so a case cannot outlive its recipe."""

    @property
    def expects_clean(self) -> bool:
        return not self.expect_violations


def illustrative_commands(skill: SkillDoc) -> dict[str, str]:
    """Commands a skill shows to *discuss* rather than to recommend, mapped to the reason.

    An escape hatch, kept deliberately narrow and noisy: the entry must name the exact command
    and carry a reason, so waving a command past the validators is a reviewable line in a file
    rather than a silent hole. ``build-cpanm`` mentions ``cpanm --installdeps .`` mid-sentence
    while explaining what the flag covers; its actual recipe is the YAML spec above it.
    """
    path = skill.cases_path
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text()) or {}
    out: dict[str, str] = {}
    for entry in data.get("illustrative_commands") or []:
        reason = (entry.get("reason") or "").strip()
        if not reason:
            raise ValueError(
                f"{path}: illustrative_commands entry {entry.get('command')!r} has no reason. "
                "An unexplained exemption is indistinguishable from a bug being hidden"
            )
        out[entry["command"]] = reason
    return out


def load_cases(skill: SkillDoc) -> list[SkillCase]:
    """Authored cases for one skill; an empty list when the skill deliberately has none."""
    path = skill.cases_path
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text()) or {}
    declared = data.get("skill")
    if declared != skill.name:
        raise ValueError(f"{path} declares skill {declared!r}, but lives under {skill.name!r}")
    cases: list[SkillCase] = []
    for raw in data.get("cases") or []:
        cases.append(
            SkillCase(
                skill=skill.name,
                id=raw["id"],
                type=raw["type"],
                scenario=raw.get("scenario", ""),
                regression=raw.get("regression", ""),
                environment_spec=raw.get("environment_spec"),
                probe=raw.get("probe"),
                expect_violations=tuple(raw.get("expect_violations") or ()),
                shown_in_skill=tuple(raw.get("shown_in_skill") or ()),
            )
        )
    return cases


def run_case(case: SkillCase, skill: SkillDoc) -> list[str]:
    """Execute one case. Returns the reasons it failed, empty when it passed.

    A case naming ``expect_violations`` is as important as one expecting a clean result: it is
    what proves the validator would actually reject the mistake, rather than the rule merely
    being written down somewhere. A gate that has never been shown to fail is the failure mode
    ``inert_gates`` is about.
    """
    failures: list[str] = []
    for needle in case.shown_in_skill:
        if needle not in skill.body:
            failures.append(
                f"the case pins {needle!r} as something {skill.name} shows, and it is no longer "
                "in the skill: either the recipe changed and the case is stale, or the recipe "
                "lost a load-bearing part"
            )

    violations: list[str] | None = None
    if case.environment_spec is not None:
        raw = {k: v for k, v in case.environment_spec.items()}
        raw["test_command"] = resolve_placeholders(raw.get("test_command", ""))
        raw["install_commands"] = [resolve_placeholders(c) for c in raw.get("install_commands", [])]
        violations = spec_violations(EnvironmentSpec.model_validate(raw))
    elif case.probe is not None:
        violations = probe_exemplar_violations(
            case.probe["test_file_path"], resolve_placeholders(case.probe["content"])
        )
    else:
        failures.append("case declares neither an environment_spec nor a probe to judge")
        return failures

    if case.expects_clean:
        if violations:
            failures.append(
                "expected the harness to accept this, but it objected: " + "; ".join(violations)
            )
        return failures

    for needle in case.expect_violations:
        if not any(needle in v for v in violations):
            failures.append(
                f"expected a violation mentioning {needle!r}; the harness raised "
                + (f"{violations}" if violations else "nothing at all, so this gate is inert")
            )
    return failures


# --- Coverage summary ----------------------------------------------------------------------

AMBIGUITY_RESIDUE = (
    "Declared and checked, but not measured: {n} pairs of skills can fire on the same input, "
    "and each now states in the skill itself which of the two wins. This suite checks that the "
    "rule exists, that the two sides do not name different winners, and that no pair whose "
    "negative criteria point at each other was left untriaged. Whether a model *follows* the "
    "rule is a live question and no eval scores it yet — the difference from before is that "
    "there is now a rule to be scored against, where previously the agent was guessing."
)
_AMBIGUITY_NONE = (
    "no other skill in the library competes with this one: the skills that fire alongside it "
    "compose (a lang-* skill while a build-* skill plans, partial-build inside a build recipe, "
    "a test-* skill after the protocol), so there is no winner to declare. Asserting one would "
    "be filler"
)


def _ambiguity_reason(name: str, pairs: tuple[CompetingPair, ...]) -> str:
    """What the ambiguity check establishes for a skill, and what it still does not."""
    counterparts = ", ".join(sorted({p.b if p.a == name else p.a for p in pairs}))
    return (
        f"{len(pairs)} pair(s) where another skill also applies ({counterparts}); each declares "
        "which skill wins, in the skill itself, and the two sides are checked for naming "
        "different winners. Whether a model *follows* the declared rule is live-only and is not "
        "measured anywhere yet"
    )
_TOOL_USE_ELSEWHERE = (
    "a skill declares no tools; tool evocation is a property of the agent that loads it and is "
    "already scored by evals/trajectory.py against AGENT_EXPECTATIONS"
)
_ACTIVATION_STATIC = (
    "criteria are present, specific, and checked; whether a model actually evokes the skill is "
    "measured live by evals/trajectory.py (skill_use_rate)"
)


def coverage_summary(
    skills: tuple[SkillDoc, ...] | None = None,
) -> dict[str, dict[str, Coverage]]:
    """Per skill, what each of the nine case types is — and why, where it is not evaluated.

    This is the deliverable that keeps the suite honest. Reading it should make it obvious that
    a ``lang-*`` skill has no procedure cases, and that ambiguity is counted only for the ten
    skills some other skill actually competes with, rather than leaving either to be inferred
    from an absence.
    """
    summary: dict[str, dict[str, Coverage]] = {}
    for skill in skills if skills is not None else load_skills():
        has_cases = bool(load_cases(skill))
        commands = extract_commands(skill)
        probes = extract_probe_exemplars(skill)
        entries: dict[str, Coverage] = {
            "activation": Coverage("activation", Status.STATIC, _ACTIVATION_STATIC),
            "non_activation": Coverage(
                "non_activation", Status.STATIC,
                "criteria are present, redirect to skills that exist, and are checked against "
                "the positive criteria for a trigger claimed on both sides",
            ),
            "ambiguity": (
                Coverage("ambiguity", Status.STATIC, _ambiguity_reason(skill.name, competing))
                if (competing := competing_pairs_for(skill.name))
                else Coverage("ambiguity", Status.NOT_APPLICABLE, _AMBIGUITY_NONE)
            ),
            "tool_use": Coverage("tool_use", Status.NOT_APPLICABLE, _TOOL_USE_ELSEWHERE),
            "stopping": Coverage(
                "stopping", Status.STATIC,
                "completion criteria are present and phrased as observable states",
            ),
            "context_cost": Coverage(
                "context_cost", Status.STATIC,
                "description and body are priced against the budgets here and against the "
                "per-request ceiling of every agent that enables the skill",
            ),
            "cross_skill": Coverage(
                "cross_skill", Status.STATIC,
                "checked for contradiction against the other skills in its family and against "
                "the protocol they defer to",
            ),
        }
        if commands or probes:
            entries["procedure_adherence"] = Coverage(
                "procedure_adherence",
                Status.CASES if has_cases else Status.STATIC,
                f"{len(commands)} command(s) and {len(probes)} probe exemplar(s) shown by this "
                "skill are run through the production validators"
                + (", plus authored regression cases" if has_cases else ""),
            )
        else:
            entries["procedure_adherence"] = Coverage(
                "procedure_adherence", Status.NOT_APPLICABLE,
                "this skill shows no command or probe the harness can judge; it orients the "
                "reader in a codebase rather than prescribing an artifact",
            )
        if probes or has_cases:
            entries["safety"] = Coverage(
                "safety", Status.CASES if has_cases else Status.STATIC,
                "the probe bodies it shows are checked against the rules that make a probe "
                "unable to report nothing (no skip, markers present, runs to completion)",
            )
        else:
            entries["safety"] = Coverage(
                "safety", Status.ELSEWHERE,
                "this skill shows no probe body for the probe rules to judge; the safety "
                "constraint its family actually turns on — never substitute a fake or stub for "
                "the sink — is enforced by tests/test_skills_consistency.py, which this suite "
                "does not duplicate and does not claim credit for",
            )
        summary[skill.name] = entries
    return summary


def format_coverage_notice(
    summary: dict[str, dict[str, Coverage]] | None = None, *, width: int = 92
) -> str:
    """A readable statement of what this suite does and does not establish.

    Deliberately leads with the gaps. A coverage report that has to be read carefully to find
    what is missing is the report that gets misread as completeness.
    """
    summary = summary if summary is not None else coverage_summary()
    rule = "=" * width
    lines = [rule, f"SKILL EVAL COVERAGE: {len(summary)} skills x {len(CASE_TYPES)} case types", ""]
    counts: dict[str, dict[Status, int]] = {
        ct: {s: 0 for s in Status} for ct in CASE_TYPES
    }
    for entries in summary.values():
        for case_type, coverage in entries.items():
            counts[case_type][coverage.status] += 1
    for case_type in CASE_TYPES:
        per = counts[case_type]
        evaluated = per[Status.STATIC] + per[Status.CASES]
        detail = ", ".join(f"{n} {status.value}" for status, n in per.items() if n)
        lines.extend(
            textwrap.wrap(
                f"{case_type:20} {evaluated}/{len(summary)} evaluated  ({detail})",
                width, subsequent_indent=" " * 23,
            )
        )
    lines.append("")
    not_evaluated = sorted(
        {
            coverage.reason
            for entries in summary.values()
            for coverage in entries.values()
            if not coverage.is_evaluated
        }
    )
    if not_evaluated:
        lines.append("Not evaluated, and why:")
        for reason in not_evaluated:
            lines.extend("  " + ln for ln in textwrap.wrap(reason, width - 2))
    lines.append("")
    lines.extend(textwrap.wrap(AMBIGUITY_RESIDUE.format(n=len(COMPETING_PAIRS)), width))
    lines.append("")
    lines.extend(
        textwrap.wrap(
            "The counts above are what *this* suite establishes, so they read low on purpose. "
            "'elsewhere' is genuine coverage owned by another suite and not claimed here; "
            "'live_only' and 'not_applicable', wherever they appear, are gaps this suite "
            "deliberately does not fill. Do not read either as a pass.", width,
        )
    )
    lines.append(rule)
    return "\n".join(lines)
