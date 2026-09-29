"""Static activation, ambiguity, and structural checks for skill documents."""

from __future__ import annotations

import re
from dataclasses import dataclass

from pydantic_ai_harness.compaction._shared import estimate_text_tokens

from .skill_documents import Relation, SkillDoc

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


def non_activation_problems(skill: SkillDoc) -> list[str]:
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
        "build-maven",
        "build-gradle",
        "a repository carrying both a pom.xml and a build.gradle — a Gradle build kept beside "
        "a published pom, or a migration half done — satisfies each skill's positive criteria "
        "while each skill's negative criteria send the reader to the other",
    ),
    CompetingPair(
        "cwe-78-os-command-injection",
        "cwe-94-code-injection",
        "an eval of a string that the evaluated code then hands to a shell is both 'evaluated "
        "as program source' and 'reaches a shell', which is the exact wording of the two "
        "skills' mutual redirects",
    ),
    CompetingPair(
        "cwe-78-os-command-injection",
        "cwe-89-sql-injection",
        "a query issued through a command-line database client (psql -c, mysql -e) puts the "
        "same untrusted value into a shell command and into SQL, and each skill's negative "
        "criteria point at the other",
    ),
    CompetingPair(
        "cwe-22-path-traversal",
        "cwe-918-ssrf",
        "a caller-chosen URL resolved by a fetcher that accepts file: both chooses a request "
        "destination and names a filesystem path",
    ),
    CompetingPair(
        "cwe-502-deserialization",
        "cwe-611-xxe",
        "XML handed to a reader that instantiates the types the document names (XMLDecoder, "
        "XStream) is untrusted XML and untrusted serialized bytes at once, and cwe-502's "
        "negative criteria send every XML payload to cwe-611",
    ),
    CompetingPair(
        "cwe-89-sql-injection",
        "probe-oracle-protocol",
        "the protocol forbids mocking the sink while cwe-89's structure oracle needs to see the "
        "statement the driver received; the more specific skill won and a wrapped cursor the "
        "target never used reported a clean negative on an exploitable finding "
        "(docs/LIVE_VALIDATION.md)",
    ),
    CompetingPair(
        "cwe-918-ssrf",
        "probe-oracle-protocol",
        "an SSRF probe has to substitute the transport because the sandbox has no egress, which "
        "is precisely what the protocol's 'do not mock the sink' rule forbids",
    ),
    CompetingPair(
        "test-junit4",
        "test-junit5",
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
    **{
        _pair(lang, build): _COMPOSE_LANG_BUILD
        for lang, build in (
            ("lang-python", "build-python"),
            ("lang-java", "build-maven"),
            ("lang-java", "build-gradle"),
            ("lang-javascript", "build-npm"),
            ("lang-perl", "build-cpanm"),
        )
    },
    **{
        _pair("partial-build", build): _COMPOSE_PARTIAL
        for build in ("build-python", "build-maven", "build-gradle", "build-npm", "build-cpanm")
    },
    **{
        _pair("probe-oracle-protocol", test): _COMPOSE_PROTOCOL_TEST
        for test in (
            "test-pytest",
            "test-junit4",
            "test-junit5",
            "test-jest",
            "test-perl-test-more",
        )
    },
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
