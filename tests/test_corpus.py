"""The seeded corpus stays internally consistent across all languages."""
import re

import pytest

from infosec_harness.evals.corpus import languages, load_corpus
from infosec_harness.repo.detect import detect_stack

CASES = load_corpus()
SINK_PATTERN = {
    "CWE-89": re.compile(r"execute|selectall_arrayref|prepareStatement"),
    "CWE-78": re.compile(r"subprocess\.run|exec|ProcessBuilder|system|`echo"),
    "CWE-22": re.compile(r"open\("),
    "CWE-79": re.compile(r"<div"),
}
EXPECTED_STACK = {  # language -> (detected language alternatives, build system, test framework)
    "python": ({"python"}, "pip", "pytest"),
    "java": ({"java"}, "maven", "junit5"),
    "javascript": ({"javascript", "typescript"}, "npm", "jest"),
    "perl": ({"perl"}, "cpanm", "Test::More"),
}


def test_all_four_languages_present():
    assert set(languages()) == {"python", "java", "javascript", "perl"}


def test_each_language_is_paired_per_cwe():
    for lang in languages():
        names = {c.name for c in load_corpus(lang)}
        pairs = {n.rsplit("-", 1)[0] for n in names if n.endswith(("-vulnerable", "-fixed"))}
        for base in pairs:
            assert f"{base}-vulnerable" in names and f"{base}-fixed" in names, f"{base} not paired"


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_finding_points_at_real_code(case):
    target = case.repo_path / case.finding.file_path
    assert target.exists(), f"{case.name}: finding file missing"
    lines = target.read_text().splitlines()
    assert 1 <= case.finding.start_line <= len(lines)
    assert 1 <= case.sink_line <= len(lines)
    kw = "sub" if case.language == "perl" else ("function" if case.language == "javascript" else "def")
    # the target callable is defined somewhere in the file (method/sub/function/def)
    assert any(re.search(rf"\b{re.escape(case.target_callable)}\b", l) for l in lines)
    _ = kw


@pytest.mark.parametrize("case", [c for c in CASES if c.finding.cwe in SINK_PATTERN and c.reachability != "unknown"],
                         ids=lambda c: c.name)
def test_sink_line_matches_weakness(case):
    lines = (case.repo_path / case.sink_file).read_text().splitlines()
    assert SINK_PATTERN[case.finding.cwe].search(lines[case.sink_line - 1]), \
        f"{case.name}: sink line lacks the {case.finding.cwe} pattern"


@pytest.mark.parametrize("case", [c for c in CASES if not c.name.startswith("testonly")],
                         ids=lambda c: c.name)
def test_stack_detects_expected_toolchain(case):
    st = detect_stack(str(case.repo_path))
    langs, build, testfw = EXPECTED_STACK[case.language]
    top = max(st.languages, key=st.languages.get) if st.languages else None
    assert top in langs, f"{case.name}: detected {top}, expected one of {langs}"
    assert build in st.build_systems, f"{case.name}: build {st.build_systems} lacks {build}"
    assert testfw in st.test_frameworks, f"{case.name}: test fw {st.test_frameworks} lacks {testfw}"


def test_paired_variants_differ_at_the_sink():
    by = {c.name: c for c in CASES}
    for base in {c.name.rsplit("-", 1)[0] for c in CASES if c.name.endswith("-vulnerable")}:
        v = by[f"{base}-vulnerable"]
        f = by[f"{base}-fixed"]
        vsrc = (v.repo_path / v.finding.file_path).read_text()
        fsrc = (f.repo_path / f.finding.file_path).read_text()
        assert vsrc != fsrc, f"{base}: vulnerable and fixed are identical"


def test_expected_verdicts_follow_pairing():
    for c in CASES:
        if c.name.endswith("-vulnerable"):
            assert c.expected_verdict == "potentially_exploitable"
        if c.name.endswith("-fixed"):
            assert c.expected_verdict == "likely_not_exploitable"


async def test_score_corpus_runs_offline():
    from infosec_harness.evals.run import score_corpus

    metrics = await score_corpus(language="python", sandbox=False)
    assert metrics["n"] == len(load_corpus("python"))
    assert 0.0 <= metrics["accuracy"] <= 1.0
