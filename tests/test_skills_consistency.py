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

from infosec_harness.settings import REPO_ROOT

SKILLS = REPO_ROOT / "skills"
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

REQUIRED_SECTIONS = ("## Use this skill when", "## Do not use this skill when",
                     "## Safety constraints", "## Completion criteria")


def _all_skills() -> list:
    return sorted(SKILLS.glob("*/SKILL.md"))


@pytest.mark.parametrize("skill", _all_skills(), ids=lambda p: p.parent.name)
def test_every_skill_states_when_to_use_it_and_when_not_to(skill):
    text = skill.read_text()
    for section in REQUIRED_SECTIONS:
        assert section in text, f"{skill.parent.name} is missing '{section}'"


@pytest.mark.parametrize("skill", _all_skills(), ids=lambda p: p.parent.name)
def test_every_description_says_when_the_skill_applies(skill):
    """The description is what a model reads before deciding to load anything.

    Making that choice explicit rather than implied is what moved context's skill evocation
    from 19% to 100% (docs/LIVE_VALIDATION.md), so this is a behavioural requirement and not
    only a conformance one.
    """
    import yaml

    _, frontmatter, _ = skill.read_text().split("---\n", 2)
    description = (yaml.safe_load(frontmatter) or {}).get("description", "")
    assert re.search(r"\buse\b|\bwhen\b", description, re.I), (
        f"{skill.parent.name}: description does not say when it applies: {description!r}"
    )


@pytest.mark.parametrize("skill", _all_skills(), ids=lambda p: p.parent.name)
def test_every_skill_has_an_owner_and_a_semantic_version(skill):
    import yaml

    _, frontmatter, _ = skill.read_text().split("---\n", 2)
    metadata = (yaml.safe_load(frontmatter) or {}).get("metadata") or {}
    assert metadata.get("owner"), skill.parent.name
    assert re.fullmatch(r"\d+\.\d+\.\d+", str(metadata.get("version", ""))), skill.parent.name


@pytest.mark.parametrize("skill", _all_skills(), ids=lambda p: p.parent.name)
def test_negative_criteria_point_somewhere_real(skill):
    """'Use X instead' is only useful if X exists."""
    text = skill.read_text()
    section = text.split("## Do not use this skill when", 1)[1].split("\n## ", 1)[0]
    referenced = set(re.findall(r"`((?:cwe|lang|build|test|probe)-[a-z0-9-]+)`", section))
    on_disk = {p.parent.name for p in _all_skills()}
    assert referenced <= on_disk, (
        f"{skill.parent.name} redirects to skills that do not exist: {sorted(referenced - on_disk)}"
    )


def test_the_structure_is_regenerable():
    import subprocess
    import sys

    before = {p: p.read_text() for p in _all_skills()}
    subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "restructure_skills.py")],
                   check=True, capture_output=True, cwd=REPO_ROOT)
    assert {p: p.read_text() for p in _all_skills()} == before, (
        "skills are out of date with scripts/skill_specs.py — run "
        "`uv run python scripts/restructure_skills.py`"
    )
