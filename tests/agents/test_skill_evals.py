"""The skill eval suite: everything about a skill that can be decided without a model.

Scope, and why it is not 24 x 9
-------------------------------
The playbook asks for nine case types per skill. Most of the 216 cells that implies could not
fail, and a suite padded to fill them would report "every skill fully evaluated" while testing
four things — the decorative-coverage failure `evals/inert_gates.py` exists to name. The
triage lives in `evals/skills.py` and is *reported* by `test_the_coverage_summary_names_its_own_gaps`
below, so the gaps are part of the output rather than an absence a reader has to notice.

What this file does not establish
---------------------------------
Nothing here says a model will load the right skill, follow a procedure it has read, or obey a
precedence rule when two skills fire at once. Skill *evocation* is measured live by
`evals/trajectory.py`. Ambiguity splits: whether the library *states* which of two competing
skills wins is a property of the files and is checked below; whether a model then follows the
rule is live-only and still measured nowhere. These tests establish that a skill is
well-formed, affordable, internally consistent, unambiguous against its neighbours, and — for
the skills that carry a recipe — that the recipe is one this harness would actually accept.
"""

from __future__ import annotations

import re

import pytest

from infosec_harness.evals.skills import (
    AMBIGUITY_RESIDUE,
    CASE_TYPES,
    COMPETING_PAIRS,
    COMPOSING_PAIRS,
    MAX_AGENT_SKILL_SHARE,
    MAX_BODY_TOKENS,
    MAX_DESCRIPTION_CHARS,
    UPSTREAM_DESCRIPTION_LIMIT,
    SkillDoc,
    Status,
    Verdict,
    activation_problems,
    agent_skill_costs,
    ambiguity_problems,
    body_substance_problems,
    body_tokens,
    capability_include,
    command_violations,
    competing_pairs_for,
    completion_problems,
    context_cost_problems,
    coverage_summary,
    enumeration_problems,
    extract_commands,
    extract_exemplar_specs,
    extract_probe_exemplars,
    format_coverage_notice,
    illustrative_commands,
    load_cases,
    load_skills,
    mutual_redirects,
    non_activation_problems,
    orphan_skills,
    probe_exemplar_violations,
    resolve_placeholders,
    run_case,
    skill_enablement,
    spec_violations,
)

SKILLS = load_skills()
SKILL_NAMES = frozenset(s.name for s in SKILLS)
IDS = [s.name for s in SKILLS]


# --- Known defects ---------------------------------------------------------------------------
#
# Real findings this suite made that could not be fixed from here: the fix belongs in
# skills/*/SKILL.md, outside this change's boundary. They are recorded
# as strict xfails rather than skipped, quietly allowlisted, or softened into a warning: strict
# means that the moment somebody applies the fix, the xfail itself fails and forces its own
# removal. A defect parked this way cannot rot into a permanent exemption.
KNOWN_DEFECTS: dict[tuple[str, str], str] = {
    # Empty, and that is the point. Six defects were parked here when this suite was written --
    # two probe exemplars that omitted HARNESS_SINK_RETURNED (jest's awaited the sink, so a
    # rejected promise reported the precondition and nothing else: the exact false negative the
    # marker was introduced to prevent), two Maven command exemplars missing
    # -Dmaven.repo.local, and two test skills with no anti-skip guidance for idioms
    # `_skipping_probe_violations` also could not see. All six are fixed, in the skills and in
    # validators.py, so the entries are gone rather than left as permanent exemptions.
    #
    # The xfails are strict on purpose: a fix makes the xfail itself fail and forces its own
    # removal, so nothing can rot here quietly. Add an entry only to park a defect you intend
    # to fix, with the exact fix in the reason.
}


def _mark(kind: str, name: str):
    """Attach the strict xfail for a known defect, so it is visible and self-clearing."""
    reason = KNOWN_DEFECTS.get((kind, name))
    marks = [pytest.mark.xfail(strict=True, reason=reason)] if reason else []
    return pytest.param(name, marks=marks, id=name)


# --- Activation and non-activation -----------------------------------------------------------


@pytest.mark.parametrize("skill", SKILLS, ids=IDS)
def test_a_skill_says_when_it_applies(skill):
    """The positive criteria are the signal a model decides on; vagueness there is expensive.

    Making the choice explicit rather than implied is what moved context's skill evocation from
    19% to 100% (docs/validation/LIVE_VALIDATION.md), so this is a behavioural requirement, not a
    conformance one.
    """
    assert not activation_problems(skill), activation_problems(skill)


@pytest.mark.parametrize("skill", SKILLS, ids=IDS)
def test_a_skill_says_when_it_does_not_apply_without_contradicting_itself(skill):
    assert not non_activation_problems(skill), non_activation_problems(skill)


# --- Ambiguity: which skill wins when two of them fire -------------------------------------
#
# What is established here is narrow and worth stating precisely: that the library *has* a rule
# for every pair one input can satisfy on both sides, that the rule is in the skill rather than
# in a test, and that the two skills do not name different winners. Whether a model follows the
# rule needs a live run and is measured nowhere; before this, there was no rule for it to
# follow, so the guessing could not have been scored either.


def _synthetic(relations: dict[str, list[str]]) -> tuple[SkillDoc, ...]:
    """The real skill names with synthetic precedence sections, to exercise the checker itself.

    A gate that has only ever been run against a passing input is the failure mode
    `evals/inert_gates.py` names. These fixtures are the evidence that `ambiguity_problems`
    would actually object to the mistakes it claims to prevent.
    """
    from pathlib import Path

    return tuple(
        SkillDoc(
            name=name,
            path=Path(name),
            description="",
            body=f"# {name}\n\n## When another skill also applies\n\n"
            + "\n".join(relations.get(name, ()))
            + "\n",
        )
        for name in sorted(SKILL_NAMES)
    )


def test_two_skills_one_input_can_satisfy_both_say_which_of_them_wins():
    """The gap this closes: `build-maven` and `build-gradle` each told the reader of a
    repository carrying both a pom.xml and a build.gradle to use the other one, and `cwe-78`
    and `cwe-94` did the same for an eval of a string that runs a shell command. A circular
    redirect is not a rule, so the agent guessed and no measurement could say which way."""
    assert not ambiguity_problems(SKILLS), ambiguity_problems(SKILLS)


def test_a_competing_pair_names_two_real_skills_and_the_input_that_fires_both():
    """A pair without a concrete situation is an assertion of ambiguity rather than a finding of
    one, and would inflate this case type exactly the way filler does."""
    seen = set()
    for pair in COMPETING_PAIRS:
        assert pair.a in SKILL_NAMES and pair.b in SKILL_NAMES, pair
        assert pair.a != pair.b, pair
        assert pair.key not in seen, f"{pair.key} is listed twice"
        assert pair.key not in COMPOSING_PAIRS, f"{pair.key} is classified both ways"
        seen.add(pair.key)
        assert len(pair.situation) > 60, (
            f"{pair.key} gives no concrete situation that fires both skills: {pair.situation!r}"
        )


def test_every_circular_redirect_is_classified():
    """Derived, not listed: a pair whose negative criteria point at each other is the structural
    signature of an unresolved ambiguity, so a redirect added later cannot slip in untriaged."""
    found = mutual_redirects(SKILLS)
    assert found, (
        "no skill redirects to a skill that redirects back, so the derivation that feeds the "
        "ambiguity triage is measuring nothing"
    )
    classified = set(COMPOSING_PAIRS) | {p.key for p in COMPETING_PAIRS}
    assert found <= classified, sorted(found - classified)


def test_the_one_sanctioned_exception_to_the_protocol_is_declared_from_both_ends():
    """`cwe-918` must substitute the sink because the sandbox has no egress, and the protocol
    forbids substituting the sink. Both skills now name the exception, and they name it the same
    way round — the shape of disagreement that cost a corpus run when `cwe-89` and the protocol
    silently differed (docs/validation/LIVE_VALIDATION.md)."""
    ssrf = next(s for s in SKILLS if s.name == "cwe-918-ssrf")
    protocol = next(s for s in SKILLS if s.name == "probe-oracle-protocol")
    outward = {r.target: r for r in ssrf.relations}
    inward = {r.target: r for r in protocol.relations}
    assert outward["probe-oracle-protocol"].verdict is Verdict.WINS
    assert inward["cwe-918-ssrf"].verdict is Verdict.YIELDS
    assert outward["probe-oracle-protocol"].winner == inward["cwe-918-ssrf"].winner


def test_the_ambiguity_check_objects_to_the_mistakes_it_claims_to_prevent():
    """Five synthetic libraries, each broken one way, and the reason each must be reported."""
    unresolved = ambiguity_problems(_synthetic({}))
    assert len(unresolved) == len(COMPETING_PAIRS), unresolved
    assert all("neither declares which one wins" in p for p in unresolved)

    both_claim = ambiguity_problems(_synthetic({
        "build-maven": ["- `build-gradle` x **this skill wins** y"],
        "build-gradle": ["- `build-maven` x **this skill wins** y"],
    }))
    assert any("disagree about which of them wins" in p for p in both_claim), both_claim

    unknown = ambiguity_problems(_synthetic({
        "build-maven": ["- `build-bazel` x **this skill wins** y"],
    }))
    assert any("not a skill in this library" in p for p in unknown), unknown

    composing = ambiguity_problems(_synthetic({
        "lang-python": ["- `build-python` x **this skill wins** y"],
    }))
    assert any("classified as composing" in p for p in composing), composing

    unclassified = ambiguity_problems(_synthetic({
        "lang-python": ["- `lang-java` x **this skill wins** y"],
    }))
    assert any("does not classify" in p for p in unclassified), unclassified

    verdictless = ambiguity_problems(_synthetic({
        "build-maven": ["- `build-gradle` is also a JVM build tool."],
    }))
    assert any("names no skill or no verdict" in p for p in verdictless), verdictless


# --- Stopping ---------------------------------------------------------------------------------


@pytest.mark.parametrize("skill", SKILLS, ids=IDS)
def test_a_skill_says_when_it_is_done(skill):
    assert not completion_problems(skill), completion_problems(skill)


# --- Internal consistency ---------------------------------------------------------------------


@pytest.mark.parametrize("skill", SKILLS, ids=IDS)
def test_a_stated_count_matches_what_the_skill_enumerates(skill):
    """`probe-oracle-protocol` defines three markers and two agent prompts said "two" for long
    enough to be measured. A heading that promises a count and a list that delivers another is
    how that survives review."""
    assert not enumeration_problems(skill), enumeration_problems(skill)


@pytest.mark.parametrize("skill", SKILLS, ids=IDS)
def test_a_skill_still_has_a_body(skill):
    """Cheap insurance against the incident where a faulty generator deleted all 24 skill bodies
    and every structural test still passed, because the required sections were all present."""
    assert not body_substance_problems(skill), body_substance_problems(skill)


# --- Context cost -----------------------------------------------------------------------------


@pytest.mark.parametrize("skill", SKILLS, ids=IDS)
def test_a_skill_stays_within_its_context_budget(skill):
    """A skill is paid for twice, and the two prices differ.

    Its description is a catalog entry resident in the prompt of every agent that enables the
    skill, loaded or not; its body is paid on load. The description limit is upstream's own
    (the Skills capability warns above 1024 characters, and the suite runs with warnings off,
    so the warning is invisible); the body budget is measured-plus-headroom, and exists so that
    a skill doubling in size is a decision rather than a drift.
    """
    assert not context_cost_problems(skill), context_cost_problems(skill)


def test_no_agent_spends_most_of_its_prompt_on_skills():
    """Priced against the ceiling each agent declares for itself, not one invented here.

    The worst case is the honest one: the catalog is always resident, and every enabled skill
    might be loaded in a single run. `intake` is the pressure point at ~37%, because its
    per-request ceiling is deliberately small (20k) while it enables all eight CWE skills. It
    was ~31% before those skills declared which of them wins when two fire on one finding —
    precedence that intake is the agent most likely to need, and the clearest example of this
    budget doing its job, since the same text costs nothing at all against probe-repair's 120k.
    """
    costs = agent_skill_costs(SKILLS)
    assert costs, "no agent enables any skill; the cost model is measuring nothing"
    over = [
        f"{c.agent}: {c.total_tokens} tokens of skills ({c.catalog_tokens} catalog + "
        f"{c.body_tokens} bodies) against a {c.ceiling}-token per-request ceiling = "
        f"{c.share:.0%}, over the {MAX_AGENT_SKILL_SHARE:.0%} budget"
        for c in costs
        if c.share > MAX_AGENT_SKILL_SHARE
    ]
    assert not over, over


def test_the_context_budgets_are_not_set_above_anything_they_could_bind():
    """A budget above every conceivable value is not a budget.

    `inert_gates` calls this BOUND_VACUOUS and treats it as a defect, for the reason that
    applies here too: a ceiling nothing could reach reads as governance and enforces nothing.
    These assertions fail if somebody "fixes" a budget breach by raising the ceiling past the
    point where it constrains anything.
    """
    widest_description = max(len(s.description) for s in SKILLS)
    assert MAX_DESCRIPTION_CHARS < UPSTREAM_DESCRIPTION_LIMIT, (
        "the house description budget is at or above the Agent Skills limit, so it can never "
        "bind before upstream's own does"
    )
    assert widest_description <= MAX_DESCRIPTION_CHARS
    assert 2 * max(body_tokens(s) for s in SKILLS) > MAX_BODY_TOKENS, (
        "the body budget is more than double the largest skill, so no realistic growth trips it"
    )
    assert 0 < MAX_AGENT_SKILL_SHARE < 1


# --- Wiring ------------------------------------------------------------------------------------


def test_every_skill_is_enabled_by_some_agent():
    """A skill nothing enables is not unused, it is invisible.

    It passes every structural check in this file, costs nothing, and delivers nothing, so
    adding a skill and forgetting to wire it into an agent is a silent no-op rather than a
    failure. This is the skill-library form of the inert gate.
    """
    assert not orphan_skills(SKILLS), (
        f"skills no agent enables: {orphan_skills(SKILLS)} — either wire them into an agent's "
        "enabled_skills and Skills capability, or delete them"
    )


def test_an_agents_declared_skills_are_the_skills_it_is_actually_given():
    """`metadata.enabled_skills` documents the intent; the `Skills` capability's `include` is
    what the runtime applies. If they drift, the agent is reading a set of skills nobody
    described, and every cost figure in this file is measuring the wrong list."""
    declared = skill_enablement()
    applied = capability_include()
    for agent, names in declared.items():
        include = applied.get(agent)
        if include is None:  # no include: the whole library is exposed
            assert not names, (
                f"{agent} lists enabled_skills but its Skills capability has no include, so it is "
                "given every skill in the library instead of the ones it names"
            )
            continue
        assert sorted(include) == sorted(names), (
            f"{agent}: metadata.enabled_skills and the Skills capability's include disagree — "
            f"declared {sorted(names)}, applied {sorted(include)}"
        )


@pytest.mark.parametrize("skill", SKILLS, ids=IDS)
def test_every_skill_a_negative_criterion_names_exists(skill):
    """Unknown skill names are checked here only for the ones this file resolves; redirect
    targets in prose are covered by tests/agents/test_skills_consistency.py and not duplicated."""
    referenced = set(
        re.findall(r"`((?:cwe|lang|build|test|probe|partial)-[a-z0-9-]+)`", " ".join(skill.avoid_when))
    )
    assert referenced <= SKILL_NAMES, sorted(referenced - SKILL_NAMES)


# --- Procedure adherence: the recipes a skill shows --------------------------------------------

_COMMAND_SKILLS = [s for s in SKILLS if extract_commands(s)]
_PROBE_SKILLS = [s for s in SKILLS if extract_probe_exemplars(s)]
_SPEC_SKILLS = [s for s in SKILLS if extract_exemplar_specs(s)]


@pytest.mark.parametrize("name", [_mark("exemplar_command", s.name) for s in _COMMAND_SKILLS])
def test_every_command_a_skill_shows_is_one_the_harness_would_accept(name):
    """The regression this exists for: build-maven and test-junit5 both once showed a worked
    example omitting -Dmaven.repo.local=/work/home/.m2/repository while build-maven's own prose
    required it. An agent that copied the example was rejected for a rule the same skill had
    just taught it, and java-sqli-vulnerable burned its output retries oscillating between the
    two before recording environment_unbuildable.

    Judged by the production validators, not a restatement of them, so this cannot drift from
    what a live agent's output is actually measured against.
    """
    skill = next(s for s in SKILLS if s.name == name)
    exempt = illustrative_commands(skill)
    problems = []
    for command in extract_commands(skill):
        if command.text in exempt:
            continue
        if violations := command_violations(command):
            problems.append(f"{command.kind.value} command {command.text!r}: {'; '.join(violations)}")
    assert not problems, problems


@pytest.mark.parametrize("skill", _SPEC_SKILLS, ids=[s.name for s in _SPEC_SKILLS])
def test_every_environment_spec_a_skill_shows_is_accepted_whole(skill):
    """A spec shown complete can be judged on the coherence *between* its fields — an install
    path against the env that has to resolve it at probe time — which no single command can be."""
    problems = [
        f"{spec.test_command!r}: {'; '.join(v)}"
        for spec in extract_exemplar_specs(skill)
        if (v := spec_violations(spec))
    ]
    assert not problems, problems


@pytest.mark.parametrize("name", [_mark("exemplar_probe", s.name) for s in _PROBE_SKILLS])
def test_every_probe_a_skill_shows_is_one_the_harness_would_accept(name):
    """Same contract as the command check, for the probe body a skill shows. An exemplar the
    harness rejects costs an output retry every time an agent follows its own skill."""
    skill = next(s for s in SKILLS if s.name == name)
    problems = [
        f"{lang} exemplar: {'; '.join(v)}"
        for lang, path, code in extract_probe_exemplars(skill)
        if (v := probe_exemplar_violations(path, resolve_placeholders(code)))
    ]
    assert not problems, problems


# --- Cross-skill consistency -------------------------------------------------------------------

_TEST_SKILLS = sorted(s.name for s in SKILLS if s.name.startswith("test-"))
# Each framework's own way of declining to run. A probe that can skip itself produces no
# markers, which the harness cannot tell from a broken probe, so probe repair is handed a
# correct probe and exhausts its budget on it.
_ANTI_SKIP = re.compile(r"never skip|do not (?:use|call).{0,40}skip|skip_all|@Disabled|assume",
                        re.I)


@pytest.mark.parametrize("name", [_mark("anti_skip_guidance", n) for n in _TEST_SKILLS])
def test_every_test_skill_tells_the_author_not_to_let_the_probe_skip_itself(name):
    """The protocol names a zero-test run for all four runners — prove's `skipped`, pytest's
    `collected 0 items`, Surefire's `Tests run: 0`, Jest's `No tests found` — and classifies
    every one of them as a probe defect rather than a negative result. A framework skill that
    does not say how to avoid causing it leaves the author with the hazard named and no
    remedy, and the two skills missing it are exactly the two whose idioms validators.py also
    does not detect.
    """
    skill = next(s for s in SKILLS if s.name == name)
    assert _ANTI_SKIP.search(skill.procedure), (
        f"{name} gives no guidance against a probe that declines to run, while its sibling "
        "test-* skills each carry a 'Never skip' section"
    )


def test_the_build_and_test_skills_agree_about_the_maven_test_command():
    """Two skills describing the same command is how they drift apart. Both must show the flags
    that the other's prose calls load-bearing, and both must satisfy the validator."""
    from infosec_harness.agents.validators import MAVEN_TEST_COMMAND

    required = ["-Dmaven.repo.local=/work/home/.m2/repository",
                "-Dmaven.test.redirectTestOutputToFile=false",
                "maven-surefire-plugin:3.2.5:test", "test-compile"]
    for flag in required:
        assert flag in MAVEN_TEST_COMMAND, f"the canonical command lost {flag!r}"
    for name in ("build-maven", "test-junit5"):
        skill = next(s for s in SKILLS if s.name == name)
        collapsed = " ".join(skill.body.split())
        for flag in required:
            assert flag in collapsed, (
                f"{name} no longer shows {flag!r} in its Maven command. Both skills describe the "
                "same command, and an exemplar that drops one of these is the regression that "
                "cost java-sqli-vulnerable its whole retry budget"
            )


# --- The authored cases -------------------------------------------------------------------------

_CASES = [(s, c) for s in SKILLS for c in load_cases(s)]


@pytest.mark.parametrize(
    ("skill", "case"), _CASES, ids=[f"{s.name}/{c.id}" for s, c in _CASES]
)
def test_authored_case(skill, case):
    assert not run_case(case, skill), run_case(case, skill)


def test_the_cases_include_ones_that_prove_the_validators_reject_mistakes():
    """A suite of only-positive cases cannot distinguish a working validator from a missing one.

    Every `expect_violations` case is an assertion that the harness *would* refuse a specific
    mistake — which is the half of the evidence that says the passing cases mean something.
    """
    negatives = [c for _, c in _CASES if not c.expects_clean]
    positives = [c for _, c in _CASES if c.expects_clean]
    assert positives, "no case checks that a correct recipe is accepted"
    assert len(negatives) >= len(positives), (
        f"only {len(negatives)} of {len(_CASES)} cases check that a mistake is rejected; a suite "
        "weighted towards positives is measuring that nothing crashed"
    )


def test_a_case_file_belongs_to_the_skill_it_lives_under():
    for skill in SKILLS:
        load_cases(skill)  # raises if the declared skill and the directory disagree


def test_an_illustrative_command_exemption_carries_a_reason():
    """The escape hatch has to stay narrow and reviewable; `load` raises on a missing reason."""
    for skill in SKILLS:
        for command, reason in illustrative_commands(skill).items():
            assert len(reason) > 40, (
                f"{skill.name} exempts {command!r} from validation with a reason too short to "
                "review; an unexplained exemption is indistinguishable from a bug being hidden"
            )


# --- The coverage summary itself -----------------------------------------------------------------


def test_the_coverage_summary_names_its_own_gaps():
    """The summary is the deliverable that keeps this suite honest, so it is asserted, not just
    printed: every skill accounts for every case type, and the two that no static suite can
    establish say so rather than being silently absent."""
    summary = coverage_summary(SKILLS)
    assert set(summary) == SKILL_NAMES
    for name, entries in summary.items():
        assert set(entries) == set(CASE_TYPES), (
            f"{name} does not account for {set(CASE_TYPES) - set(entries)}"
        )
        competing = competing_pairs_for(name)
        expected = Status.STATIC if competing else Status.NOT_APPLICABLE
        assert entries["ambiguity"].status is expected, (
            f"{name} reports ambiguity as {entries['ambiguity'].status.value} while competing "
            f"with {[p.key for p in competing]}. A skill nothing competes with must say so "
            "rather than claim coverage, and one that competes must have declared a winner"
        )
        assert entries["tool_use"].status is Status.NOT_APPLICABLE
        for coverage in entries.values():
            assert coverage.reason.strip(), f"{name}/{coverage.case_type} gives no reason"


def test_the_skills_that_carry_a_recipe_are_the_ones_with_behavioural_cases():
    """A skill without cases has to be a decision, not an oversight.

    The `lang-*` and `cwe-*` skills orient a reader in a codebase; they prescribe no command and
    no probe, so there is no artifact for a procedure case to judge, and text-containment
    assertions about them would duplicate tests/agents/test_skills_consistency.py. The skills that do
    prescribe an artifact are required to have cases.
    """
    with_cases = {s.name for s in SKILLS if load_cases(s)}
    should_have = {s.name for s in SKILLS if extract_probe_exemplars(s) or extract_exemplar_specs(s)}
    assert should_have <= with_cases, (
        f"these skills show an artifact the harness can judge but have no cases: "
        f"{sorted(should_have - with_cases)}"
    )
    for name in with_cases:
        skill = next(s for s in SKILLS if s.name == name)
        assert skill.carries_a_recipe, (
            f"{name} has behavioural cases but carries no recipe; if the cases are text "
            "assertions they belong in tests/agents/test_skills_consistency.py instead"
        )


def test_the_summary_does_not_claim_coverage_another_suite_owns(capsys):
    """Credit for a check belongs to the suite that performs it.

    A `lang-*` or `cwe-*` skill shows no probe body, so nothing here judges its safety
    constraints — tests/agents/test_skills_consistency.py does. Marking those STATIC would have this
    file reporting 24/24 on safety while testing 11, which is the same overstatement as an
    inert gate, arrived at by a different route.
    """
    summary = coverage_summary(SKILLS)
    for name, entries in summary.items():
        safety = entries["safety"]
        skill = next(s for s in SKILLS if s.name == name)
        if not (extract_probe_exemplars(skill) or load_cases(skill)):
            assert safety.status is Status.ELSEWHERE, (
                f"{name} has no probe body and no cases, so this suite checks nothing about its "
                f"safety, but the summary reports {safety.status.value}"
            )
    notice = format_coverage_notice(summary)
    assert "Not evaluated, and why:" in notice
    # Ambiguity now counts for the ten skills something competes with, so the notice has to keep
    # saying what that number does *not* include: adherence to the declared rule is live-only.
    assert AMBIGUITY_RESIDUE.split("{n}")[0] in notice
    assert "no eval scores it yet" in notice
    evaluated = sum(
        1 for entries in summary.values() if entries["ambiguity"].status is Status.STATIC
    )
    assert 0 < evaluated < len(summary), (
        f"ambiguity reports {evaluated}/{len(summary)}; a number at either extreme means the "
        "pairs stopped being triaged one at a time"
    )
    print(notice)
    assert capsys.readouterr().out
