"""The evaluation corpus must not tell the agent its own answer.

What reaches the investigator from a case is the finding (title, description, file path,
CWE) and the variant's repository snapshot. Ground truth stays in the manifest's `truth`
and in the case name. These checks keep label-bearing words out of everything the agent
can read: fixture paths, fixture file contents and finding text. Labels found here are a
corpus defect, not something to allowlist away.
"""

import json
import re
from collections import defaultdict
from pathlib import Path

import pytest

from infosec_harness.contracts import Finding
from infosec_harness.workflows.snapshot import EXCLUDED

CHECKOUT = Path(__file__).resolve().parents[2]
CORPUS = CHECKOUT / "eval-corpus"
MANIFEST = CORPUS / "manifest.json"
# Maintainer-only files and historical datasets that never enter a snapshot.
NOT_FIXTURES = {"README.md", "manifest.json", "external"}

_STEMS = ("vuln", "fixed", "insecure", "secure", "unsafe", "safe", "exploit", "patch",
          "mitigat", "sanitiz", "unsanitiz")
# Word boundary for code as well as prose: `_`, `-`, digits and camelCase humps all
# separate words, so `is_fixed`, `cmdi-vuln` and `isSafe` are caught along with `FIXED:`.
LABEL = re.compile(
    r"(?<![A-Za-z])(?i:" + "|".join(_STEMS) + r")[A-Za-z]*"
    r"|(?<=[a-z])(?:" + "|".join(stem.capitalize() for stem in _STEMS) + r")[A-Za-z]*"
)
# Directory names that state a case's outcome rather than its subject.
OUTCOME_NAMES = {"vulnerable", "fixed", "unreachable", "testonly", "safe", "unsafe"}
# Whole identifiers that contain a label stem but name a tool or API, never an outcome.
# Each entry needs a reason; add one only when the real name cannot be avoided.
ALLOWLIST = {
    # The compiler's memory-error detector, named identically in both C variants' Makefile
    # comment; it says which tool builds the test, not what the test finds.
    "AddressSanitizer": "tool name",
}


def manifest_cases() -> list[dict]:
    return json.loads(MANIFEST.read_text())["cases"]


def fixture_files() -> list[Path]:
    files = []
    for path in sorted(CORPUS.rglob("*")):
        relative = path.relative_to(CORPUS)
        if relative.parts[0] in NOT_FIXTURES or EXCLUDED.intersection(relative.parts):
            continue
        if path.is_file():
            files.append(path)
    return files


def label_words(text: str) -> list[str]:
    for identifier in ALLOWLIST:
        text = re.sub(rf"(?<![A-Za-z]){identifier}(?![A-Za-z])", " ", text)
    return [match.group(0) for match in LABEL.finditer(text)]


def test_fixture_tree_is_present():
    assert len(manifest_cases()) > 0
    assert len(fixture_files()) > len(manifest_cases())


def test_fixture_paths_carry_no_label():
    leaks = {}
    for path in fixture_files():
        relative = path.relative_to(CORPUS).as_posix()
        words = label_words(relative)
        outcome = OUTCOME_NAMES.intersection(part.lower() for part in Path(relative).parts)
        if words or outcome:
            leaks[relative] = sorted(set(words) | outcome)
    assert not leaks


def test_fixture_contents_carry_no_label():
    leaks = defaultdict(list)
    for path in fixture_files():
        relative = path.relative_to(CORPUS).as_posix()
        text = path.read_bytes().decode("utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), 1):
            for word in label_words(line):
                leaks[relative].append(f"{number}: {word}")
    assert not dict(leaks)


@pytest.mark.parametrize("case", manifest_cases(), ids=lambda case: case["name"])
def test_finding_text_and_location_carry_no_label(case):
    finding = case["finding"]
    Finding(**{key: value for key, value in finding.items() if key in Finding.model_fields})
    for field in ("title", "description", "file_path", "repo_url"):
        assert not label_words(finding[field]), field
    repo = (CHECKOUT / finding["repo_url"]).resolve(strict=True)
    assert repo.is_relative_to(CORPUS)
    assert repo.name in {"a", "b"}
    parts = {part.lower() for part in repo.relative_to(CORPUS).parts}
    assert not OUTCOME_NAMES & parts
    assert (repo / finding["file_path"]).is_file()
    assert (repo / case["truth"]["sink_file"]).is_file()


def test_no_variant_directory_is_named_for_its_outcome():
    named = [
        path.relative_to(CORPUS).as_posix()
        for path in CORPUS.rglob("*")
        if path.is_dir() and path.name.lower() in OUTCOME_NAMES
    ]
    assert not named


def test_paired_findings_differ_only_in_location():
    topics = defaultdict(list)
    for case in manifest_cases():
        topics[case["finding"]["repo_url"].rsplit("/", 1)[0]].append(case)
    paired = {topic: cases for topic, cases in topics.items() if len(cases) > 1}
    assert paired
    for topic, cases in paired.items():
        assert len(cases) == 2, topic
        first, second = (case["finding"] for case in cases)
        assert {first["repo_url"], second["repo_url"]} == {f"{topic}/a", f"{topic}/b"}
        differing = {key for key in first.keys() | second.keys() if first.get(key) != second.get(key)}
        assert differing <= {"repo_url", "start_line"}, (topic, differing)
        verdicts = {case["truth"]["expected_verdict"] for case in cases}
        assert verdicts == {"potentially_exploitable", "likely_not_exploitable"}, topic


def test_label_pattern_catches_the_leaks_it_exists_for():
    for leak in ("# VULNERABLE: x", "FIXED: y", "cmdi-vuln", "is_fixed", "isSafe",
                 "unsanitized input", "properly sanitized", "exploitable", "patched",
                 "mitigation", "insecure", "safely"):
        assert LABEL.search(leak), leak
    for neutral in ("dispatch", "security", "resolved path", "Render a comment"):
        assert not LABEL.search(neutral), neutral
    assert label_words("built under AddressSanitizer") == []
    assert label_words("AddressSanitizer passed; the input was sanitized") == ["sanitized"]
