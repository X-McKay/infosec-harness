"""The packaged skill catalog: frontmatter, size, safety wording and the model-facing budget.

Every rule is generic over whatever ``skills/*/SKILL.md`` exist, so skills added later are
checked without editing this module. Exemptions name known gaps in older skills; each one is
a ratchet that fails once the gap is closed, so the list can only shrink.
"""

import re
import warnings

import pytest
import yaml
from pydantic_ai_harness import Skills

from infosec_harness.agents.investigator import SKILLS

SKILL_FILES = sorted(SKILLS.glob("*/SKILL.md"))
SKILL_NAMES = frozenset(path.parent.name for path in SKILL_FILES)

# The largest skill before the language-coverage work was 4,854 bytes (probe); the largest
# new one is 5,279 bytes (lang-rust). 7 KiB is the smallest round ceiling that leaves
# headroom over both (about 36% over the largest).
MAX_SKILL_BYTES = 7 * 1024
MAX_DESCRIPTION_CHARS = 400
# The deferred-capability catalog the model sees before loading any skill: one
# "- name: description" line per skill. Measured at 4,827 characters over 25 skills on
# 2026-10-06; the ceiling is 2.5 times that.
CATALOG_BUDGET_CHARS = 12_067

# Language skills written with the toolchain-absent rule; the four older ones lack it.
LANGUAGE_SKILLS_WITH_ABSENT_RULE = frozenset({
    "lang-c-cpp", "lang-dotnet", "lang-go", "lang-jvm-other", "lang-php", "lang-ruby",
    "lang-rust", "lang-shell",
})
# The workspace image ships none of these toolchains, so each skill leads with that check.
TOOLCHAIN_NOT_IN_IMAGE = frozenset({"lang-dotnet", "lang-go", "lang-php", "lang-ruby", "lang-rust"})
TRIAGE_SKILLS = frozenset({"triage-unknown-cwe", "triage-unknown-language"})

# Known gaps in skills that predate these rules (ratchets: remove an entry once fixed).
WITHOUT_METADATA = frozenset({"environment", "investigate", "probe"})
WITHOUT_VERDICT_GUIDANCE = frozenset({
    "cwe-22-path-traversal", "cwe-502-deserialization", "cwe-611-xxe",
    "cwe-78-os-command-injection", "cwe-79-xss", "cwe-89-sql-injection", "cwe-918-ssrf",
    "cwe-94-code-injection",
})
CWE_SECTIONS = ("Use this skill when", "Do not use this skill when", "Oracle", "Verdict guidance")

# Installing packages or fetching installers is the environment skill's decision under the
# operator's policy; any other mention must be a prohibition.
INSTALL = re.compile(
    r"\bpip3? install\b|\bnpm install\b|\bcpanm\b|\bapt(?:-get)?\b|\bgem install\b"
    r"|\bcargo install\b|\bgo (?:install|get)\b|\bdotnet tool install\b|\bbrew install\b"
    r"|\b(?:curl|wget)\b[^\n]*\|\s*(?:ba|z)?sh\b",
    re.IGNORECASE,
)
# Editing tracked files invalidates the probe's source check; skills may only forbid it.
SOURCE_EDIT = re.compile(
    r"\bsed -i\b|\bgit (?:apply|checkout|reset|stash|commit)\b|\bpatch -p\d", re.IGNORECASE
)
PROHIBITION = re.compile(r"\bdo not\b|\bnever\b|\bnot a route\b", re.IGNORECASE)
# The environment skill's workspace-local pip route, confined to a dependency folder.
SANCTIONED_INSTALL = {"environment": ("python -m pip install --target .harness-deps",)}
SKILL_REFERENCE = re.compile(r"`((?:lang|cwe|triage)-[a-z0-9-]+)`")


def split(path):
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), f"{path} has no YAML frontmatter"
    header, _, body = text[4:].partition("\n---\n")
    assert body, f"{path} has unclosed YAML frontmatter"
    frontmatter = yaml.safe_load(header)
    assert isinstance(frontmatter, dict), f"{path} frontmatter is not a mapping"
    return frontmatter, body


def headings(body):
    return re.findall(r"^#{2,6}\s+(.+?)\s*$", body, re.MULTILINE)


def section(body, title):
    """The text under one heading, up to the next heading of any level."""
    match = re.search(
        rf"^#{{2,6}}\s+{re.escape(title)}\s*$(.*?)(?=^#{{1,6}}\s|\Z)", body, re.MULTILINE | re.DOTALL
    )
    return match.group(1) if match else None


def by_name(names):
    return [path for path in SKILL_FILES if path.parent.name in names]


def ids(paths):
    return [path.parent.name for path in paths]


def test_every_skill_directory_holds_a_skill_and_the_named_groups_exist():
    children = {path.name for path in SKILLS.iterdir() if path.is_dir()}
    assert children == SKILL_NAMES, "a skill directory without SKILL.md is silently ignored"
    named = (
        LANGUAGE_SKILLS_WITH_ABSENT_RULE | TOOLCHAIN_NOT_IN_IMAGE | TRIAGE_SKILLS
        | WITHOUT_METADATA | WITHOUT_VERDICT_GUIDANCE | set(SANCTIONED_INSTALL)
    )
    assert named <= SKILL_NAMES, f"stale names in this module: {sorted(named - SKILL_NAMES)}"


@pytest.mark.parametrize("path", SKILL_FILES, ids=ids(SKILL_FILES))
def test_frontmatter_names_its_directory_and_describes_when_to_use_it(path):
    frontmatter, body = split(path)
    assert frontmatter.get("name") == path.parent.name
    assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", frontmatter["name"])
    description = frontmatter.get("description")
    assert isinstance(description, str) and description.strip()
    assert len(description) < MAX_DESCRIPTION_CHARS, f"{len(description)} characters"
    assert body.strip()
    metadata = frontmatter.get("metadata")
    if path.parent.name in WITHOUT_METADATA:
        assert not metadata, f"{path.parent.name} gained metadata: remove it from WITHOUT_METADATA"
    else:
        assert isinstance(metadata, dict)
        assert str(metadata.get("owner", "")).strip()
        assert re.fullmatch(r"\d+\.\d+\.\d+", str(metadata.get("version", "")))


@pytest.mark.parametrize("path", SKILL_FILES, ids=ids(SKILL_FILES))
def test_skill_stays_under_the_size_ceiling(path):
    assert path.stat().st_size < MAX_SKILL_BYTES


@pytest.mark.parametrize("path", SKILL_FILES, ids=ids(SKILL_FILES))
def test_install_and_source_edit_commands_appear_only_as_prohibitions(path):
    sanctioned = SANCTIONED_INSTALL.get(path.parent.name, ())
    offending = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if (INSTALL.search(line) or SOURCE_EDIT.search(line))
        and not PROHIBITION.search(line)
        and not any(allowed in line for allowed in sanctioned)
    ]
    assert not offending, offending


@pytest.mark.parametrize("path", SKILL_FILES, ids=ids(SKILL_FILES))
def test_skill_references_name_packaged_skills(path):
    references = set(SKILL_REFERENCE.findall(path.read_text(encoding="utf-8")))
    assert references <= SKILL_NAMES, sorted(references - SKILL_NAMES)


CWE_SKILLS = by_name({name for name in SKILL_NAMES if name.startswith("cwe-")})


@pytest.mark.parametrize("path", CWE_SKILLS, ids=ids(CWE_SKILLS))
def test_cwe_skill_has_the_oracle_sections(path):
    _, body = split(path)
    present = set(headings(body))
    required = set(CWE_SECTIONS)
    if path.parent.name in WITHOUT_VERDICT_GUIDANCE:
        assert "Verdict guidance" not in present, (
            f"{path.parent.name} gained Verdict guidance: remove it from WITHOUT_VERDICT_GUIDANCE"
        )
        required.discard("Verdict guidance")
    assert required <= present, sorted(required - present)


NEW_LANGUAGE = by_name(LANGUAGE_SKILLS_WITH_ABSENT_RULE)


@pytest.mark.parametrize("path", NEW_LANGUAGE, ids=ids(NEW_LANGUAGE))
def test_language_skill_says_what_to_do_without_its_toolchain(path):
    frontmatter, body = split(path)
    assert "Use this when" in frontmatter["description"]
    absent = section(body, "When the toolchain is absent")
    assert absent, "missing the 'When the toolchain is absent' section"
    assert "command -v" in absent and "inconclusive" in absent
    assert "HARNESS_PROBE" in body
    if path.parent.name in TOOLCHAIN_NOT_IN_IMAGE:
        first = headings(body)[0]
        assert first == "First: check the toolchain", first
        assert "does **not** include" in section(body, first)


def test_older_language_skills_without_the_absent_rule_are_known():
    older = {name for name in SKILL_NAMES if name.startswith("lang-")}
    older -= LANGUAGE_SKILLS_WITH_ABSENT_RULE
    assert older == {"lang-java", "lang-javascript", "lang-perl", "lang-python"}
    for path in by_name(older):
        assert section(split(path)[1], "When the toolchain is absent") is None, (
            f"{path.parent.name} gained the section: add it to LANGUAGE_SKILLS_WITH_ABSENT_RULE"
        )


@pytest.mark.parametrize("path", by_name(TRIAGE_SKILLS), ids=ids(by_name(TRIAGE_SKILLS)))
def test_triage_skills_restate_the_permission_and_evidence_boundaries(path):
    text = " ".join(path.read_text(encoding="utf-8").split())
    assert "grant no permissions" in text
    assert "configured name is not execution evidence" in text
    assert "`inconclusive`" in text


def test_loader_accepts_every_skill_and_the_catalog_fits_its_budget():
    """Mirror pydantic-ai's deferred-capability catalog: one '- id: description' entry each."""
    capabilities = []
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        Skills(SKILLS).apply(capabilities.append)
    assert {capability.id for capability in capabilities} == SKILL_NAMES
    catalog = "\n".join(
        f"- {capability.id}: {capability.get_description()}" for capability in capabilities
    )
    assert len(catalog) <= CATALOG_BUDGET_CHARS, f"{len(catalog)} characters"
