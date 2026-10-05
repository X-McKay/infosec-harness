"""Skills must not contradict the probe-oracle protocol they all defer to.

`probe-oracle-protocol` is the contract every probe is written against, and one of its rules
is "Reach the real sink. Call the smallest real callable that owns the sink. Do not mock the
sink." A per-CWE skill that recommends substituting a fake connection/client for the sink
therefore tells the author to break the contract — and because the per-CWE skill is the more
specific one, that is the advice that wins.

This is not hypothetical: `cwe-89` used to present "capture the SQL via a fake/stub
connection" as its *preferred* oracle. Against the live model probe-author duly wrapped the
sqlite cursor, the wrapper was not the object `get_user` actually used, the oracle could
never fire, and probe-diagnosis correctly called the probe defective — a silent false
negative dressed up as a clean run.
"""

from __future__ import annotations

import re

import pytest
import yaml
from skill_support.documents import procedure_text

from infosec_harness.resources import skills_dir

SKILLS = skills_dir()
PROTOCOL = SKILLS / "probe-oracle-protocol" / "SKILL.md"
# A skill may only talk about substituting the sink in order to rule it out.
SUBSTITUTE = re.compile(r"fake|stub|mock", re.I)
REAL_SINK = re.compile(r"real (?:callable|sink|driver|connection)|never substitute|do not mock", re.I)


def _cwe_skills() -> list:
    return sorted(SKILLS.glob("cwe-*/SKILL.md"))


def test_the_protocol_still_states_the_rule_these_tests_defend():
    """If the rule is ever relaxed, this test should be the thing that notices."""
    text = " ".join(PROTOCOL.read_text().split())  # the rule wraps across lines
    assert "Do not mock the sink" in text
    assert "Call the smallest real callable that owns the sink" in text


@pytest.mark.parametrize("skill", _cwe_skills(), ids=lambda p: p.parent.name)
def test_a_cwe_skill_that_mentions_substituting_the_sink_also_constrains_it(skill):
    text = skill.read_text()
    if not SUBSTITUTE.search(text):
        return
    assert REAL_SINK.search(text), (
        f"{skill.parent.name} raises substituting a fake/stub for the sink without stating the "
        "protocol's constraint that the probe must drive the real callable. The per-CWE skill "
        "is the more specific advice, so it is the one the author will follow."
    )


def test_cwe_89_prefers_an_oracle_that_does_not_replace_the_sink():
    """A real in-memory database is always available for SQL, so prefer observing behaviour."""
    text = (SKILLS / "cwe-89-sql-injection" / "SKILL.md").read_text()
    preferred = re.search(r"\*\*Preferred \(([^)]+)\)", text)
    assert preferred, "cwe-89 no longer marks a preferred oracle"
    assert "result" in preferred.group(1).lower(), (
        f"cwe-89 prefers the {preferred.group(1)!r} oracle. Capturing the statement requires "
        "instrumenting the driver; preferring it invites replacing the connection outright."
    )
    assert "Never substitute a fake or stub connection" in text


# --- The skill standard's required structure (agent-playbook §4) -------------------------
#
# Every SKILL.md is hand-maintained and self-contained: its frontmatter carries the name,
# description, owner and version, and its body carries the standard sections around its own
# procedure. These tests are what hold that shape, now that nothing regenerates it.

REQUIRED_SECTIONS = ("## Use this skill when", "## Do not use this skill when", "## Procedure",
                     "## Safety constraints", "## Completion criteria")


def _all_skills() -> list:
    return sorted(SKILLS.glob("*/SKILL.md"))


def _frontmatter_and_body(skill) -> tuple[dict, str]:
    _, frontmatter, body = skill.read_text().split("---\n", 2)
    return (yaml.safe_load(frontmatter) or {}), body


@pytest.mark.parametrize("skill", _all_skills(), ids=lambda p: p.parent.name)
def test_every_skill_states_when_to_use_it_and_when_not_to(skill):
    text = skill.read_text()
    for section in REQUIRED_SECTIONS:
        assert text.count(section) == 1, f"{skill.parent.name}: '{section}' must appear exactly once"


@pytest.mark.parametrize("skill", _all_skills(), ids=lambda p: p.parent.name)
def test_every_description_says_when_the_skill_applies(skill):
    """The description is what a model reads before deciding to load anything.

    Making that choice explicit rather than implied is what moved context's skill evocation
    from 19% to 100% (docs/evidence/2026-09-25-live-model-validation/LIVE_VALIDATION.md), so this is a behavioural requirement and not
    only a conformance one.
    """
    frontmatter, _ = _frontmatter_and_body(skill)
    description = frontmatter.get("description", "")
    assert re.search(r"\buse\b|\bwhen\b", description, re.I), (
        f"{skill.parent.name}: description does not say when it applies: {description!r}"
    )


@pytest.mark.parametrize("skill", _all_skills(), ids=lambda p: p.parent.name)
def test_every_skill_has_an_owner_and_a_semantic_version(skill):
    frontmatter, _ = _frontmatter_and_body(skill)
    assert frontmatter.get("name") == skill.parent.name
    metadata = frontmatter.get("metadata") or {}
    assert metadata.get("owner"), skill.parent.name
    assert re.fullmatch(r"\d+\.\d+\.\d+", str(metadata.get("version", ""))), skill.parent.name


@pytest.mark.parametrize("skill", _all_skills(), ids=lambda p: p.parent.name)
def test_negative_criteria_point_somewhere_real(skill):
    """'Use X instead' is only useful if X exists."""
    text = skill.read_text()
    section = text.split("## Do not use this skill when", 1)[1].split("\n## ", 1)[0]
    referenced = set(re.findall(r"`((?:cwe|lang|build|test|probe|partial)-[a-z0-9-]+)`", section))
    on_disk = {p.parent.name for p in _all_skills()}
    assert referenced <= on_disk, (
        f"{skill.parent.name} redirects to skills that do not exist: {sorted(referenced - on_disk)}"
    )


@pytest.mark.parametrize("skill", _all_skills(), ids=lambda p: p.parent.name)
def test_a_skill_has_a_procedure_and_not_only_the_standard_sections(skill):
    """Structure is added around the content, never instead of it.

    An earlier generator inferred its regions from heading positions, and on a second run it
    deleted the body of every skill whose procedure had no `## ` heading of its own — all 24
    of them to some degree, and the build-*, lang-* and test-* skills entirely. Nothing
    failed: the tests checked that the required sections were present, which they were.
    """
    _, body = _frontmatter_and_body(skill)
    remaining = [ln for ln in procedure_text(body).splitlines() if ln.strip()]
    assert len(remaining) >= 4, (
        f"{skill.parent.name} has almost no content of its own outside the standard "
        f"sections ({len(remaining)} lines) — the procedure was probably eaten"
    )


def test_python_build_and_test_skills_still_mandate_unbuffered_output():
    """`pytest -s` is load-bearing, not a style preference.

    Without it pytest captures stdout, the probe's oracle markers never reach the runner, and
    every Python probe reports `precondition_reached=false` while exiting 0 — which
    probe_diagnosis correctly calls a probe defect and probe_repair cannot fix, because the
    fault is in the EnvironmentSpec's test_command rather than the probe. Observed live: it
    cost a whole sandboxed corpus run.
    """
    for name in ("build-python", "test-pytest"):
        text = (SKILLS / name / "SKILL.md").read_text()
        assert "-s" in text and "pytest" in text, f"{name} lost its unbuffered-output guidance"
    build = (SKILLS / "build-python" / "SKILL.md").read_text()
    assert "pytest -q -s" in build, (
        "build-python must show the -s flag in the test_command it recommends"
    )


def test_each_skill_family_kept_its_substantive_guidance():
    """Spot-check one load-bearing fact per family, so a silent content loss is caught."""
    expectations = {
        "cwe-89-sql-injection": "bound parameter",
        "cwe-78-os-command-injection": "shell=False",
        "build-maven": "mvn",
        "build-npm": "package.json",
        "lang-python": "pyproject.toml",
        "test-junit5": "System.out",
        "partial-build": "conftest",
        "probe-oracle-protocol": "HARNESS_PRECONDITION",
    }
    for name, needle in expectations.items():
        text = (SKILLS / name / "SKILL.md").read_text()
        assert needle in text, f"{name} no longer mentions {needle!r}"


def test_cwe_78_says_how_to_match_the_sinks_quoting_context():
    """The most common silent failure of a canary probe, measured twice.

    A payload that opens a quote the sink never opened makes the command a syntax error: the
    shell rejects it, the canary is absent, and a genuinely exploitable target is recorded as
    having resisted. Both javascript-cmdi false negatives were this.
    """
    text = (SKILLS / "cwe-78-os-command-injection" / "SKILL.md").read_text()
    assert "quoting context" in text
    for context in ("bare", "single quotes", "double quotes"):
        assert context in text, f"cwe-78 does not say what to do for a {context} sink"
    assert "unmatched" in text or "syntax error" in text
