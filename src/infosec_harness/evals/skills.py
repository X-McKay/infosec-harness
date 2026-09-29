"""Public compatibility facade for the skill evaluation helpers.

The implementation is split by responsibility so callers can keep importing
``infosec_harness.evals.skills`` while each implementation module stays small:
models and loading, context costs, static checks, recipe validation, and coverage reporting.
"""

import textwrap

from .skill_checks import (
    COMPETING_PAIRS,
    COMPOSING_PAIRS,
    MIN_PROCEDURE_TOKENS,
    CompetingPair,
    activation_problems,
    ambiguity_problems,
    body_substance_problems,
    competing_pairs_for,
    completion_problems,
    enumeration_problems,
    mutual_redirects,
    non_activation_problems,
)
from .skill_documents import (
    AGENTS_DIR,
    CASE_TYPES,
    MAX_AGENT_SKILL_SHARE,
    MAX_BODY_TOKENS,
    MAX_DESCRIPTION_CHARS,
    ORIENTATION_FAMILIES,
    RECIPE_FAMILIES,
    RECIPE_SKILLS,
    SKILLS_DIR,
    UPSTREAM_DESCRIPTION_LIMIT,
    AgentSkillCost,
    Coverage,
    Relation,
    SkillDoc,
    Status,
    Verdict,
    agent_skill_costs,
    body_tokens,
    capability_include,  # noqa: F401
    context_cost_problems,
    description_tokens,
    load_skills,
    orphan_skills,
    skill_enablement,
)
from .skill_recipes import (
    CommandKind,
    ShellCommand,
    SkillCase,
    command_violations,
    extract_commands,
    extract_exemplar_specs,
    extract_probe_exemplars,
    illustrative_commands,
    load_cases,
    probe_exemplar_violations,
    resolve_placeholders,
    run_case,
    spec_violations,
)

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
                "non_activation",
                Status.STATIC,
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
                "stopping",
                Status.STATIC,
                "completion criteria are present and phrased as observable states",
            ),
            "context_cost": Coverage(
                "context_cost",
                Status.STATIC,
                "description and body are priced against the budgets here and against the "
                "per-request ceiling of every agent that enables the skill",
            ),
            "cross_skill": Coverage(
                "cross_skill",
                Status.STATIC,
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
                "procedure_adherence",
                Status.NOT_APPLICABLE,
                "this skill shows no command or probe the harness can judge; it orients the "
                "reader in a codebase rather than prescribing an artifact",
            )
        if probes or has_cases:
            entries["safety"] = Coverage(
                "safety",
                Status.CASES if has_cases else Status.STATIC,
                "the probe bodies it shows are checked against the rules that make a probe "
                "unable to report nothing (no skip, markers present, runs to completion)",
            )
        else:
            entries["safety"] = Coverage(
                "safety",
                Status.ELSEWHERE,
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
    counts: dict[str, dict[Status, int]] = {ct: {s: 0 for s in Status} for ct in CASE_TYPES}
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
                width,
                subsequent_indent=" " * 23,
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
            "deliberately does not fill. Do not read either as a pass.",
            width,
        )
    )
    lines.append(rule)
    return "\n".join(lines)


__all__ = [
    "AMBIGUITY_RESIDUE",
    "AGENTS_DIR",
    "CASE_TYPES",
    "COMPETING_PAIRS",
    "COMPOSING_PAIRS",
    "MAX_AGENT_SKILL_SHARE",
    "MAX_BODY_TOKENS",
    "MAX_DESCRIPTION_CHARS",
    "MIN_PROCEDURE_TOKENS",
    "UPSTREAM_DESCRIPTION_LIMIT",
    "AgentSkillCost",
    "CommandKind",
    "CompetingPair",
    "Coverage",
    "Relation",
    "ORIENTATION_FAMILIES",
    "RECIPE_FAMILIES",
    "RECIPE_SKILLS",
    "ShellCommand",
    "SkillCase",
    "SkillDoc",
    "SKILLS_DIR",
    "Status",
    "Verdict",
    "activation_problems",
    "ambiguity_problems",
    "agent_skill_costs",
    "competing_pairs_for",
    "mutual_redirects",
    "body_substance_problems",
    "body_tokens",
    "capability_include",
    "completion_problems",
    "context_cost_problems",
    "description_tokens",
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
