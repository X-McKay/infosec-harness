"""The seeded corpus stays internally consistent (a stale/mislabeled corpus is a bug)."""
import re

import pytest

from infosec_harness.evals.corpus import load_corpus

CASES = load_corpus("python")
SINK_PATTERN = {
    "CWE-89": re.compile(r"execute\("),
    "CWE-78": re.compile(r"subprocess\.run\("),
    "CWE-22": re.compile(r"open\("),
    "CWE-79": re.compile(r"<div"),
}


def test_corpus_nonempty_and_paired():
    names = {c.name for c in CASES}
    for cwe in ("sqli", "cmdi", "pathtraversal", "xss"):
        assert f"{cwe}-vulnerable" in names and f"{cwe}-fixed" in names


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_finding_points_at_real_code(case):
    target = case.repo_path / case.finding.file_path
    assert target.exists(), f"{case.name}: finding file missing"
    lines = target.read_text().splitlines()
    # The reported line and the truth sink line are within the file.
    assert 1 <= case.finding.start_line <= len(lines)
    assert 1 <= case.sink_line <= len(lines)
    # The named target callable is defined in the file.
    assert any(re.search(rf"def {re.escape(case.target_callable)}\b", l) for l in lines)


@pytest.mark.parametrize("case", [c for c in CASES if c.finding.cwe in SINK_PATTERN and c.reachability != "unknown"],
                         ids=lambda c: c.name)
def test_sink_line_matches_weakness(case):
    lines = (case.repo_path / case.sink_file).read_text().splitlines()
    assert SINK_PATTERN[case.finding.cwe].search(lines[case.sink_line - 1]), \
        f"{case.name}: sink line does not contain the {case.finding.cwe} sink pattern"


def test_paired_variants_differ_at_the_sink():
    """Vulnerable and fixed variants must actually differ (else the labels are meaningless)."""
    by = {c.name: c for c in CASES}
    for cwe in ("sqli", "cmdi", "pathtraversal", "xss"):
        vuln = (by[f"{cwe}-vulnerable"].repo_path / "app.py").read_text()
        fixed = (by[f"{cwe}-fixed"].repo_path / "app.py").read_text()
        assert vuln != fixed, f"{cwe}: vulnerable and fixed variants are identical"


def test_expected_verdicts_are_valid_labels():
    ok = {"potentially_exploitable", "likely_not_exploitable", "inconclusive"}
    assert all(c.expected_verdict in ok for c in CASES)
    # The paired design: every -vulnerable is exploitable, every -fixed is not.
    for c in CASES:
        if c.name.endswith("-vulnerable"):
            assert c.expected_verdict == "potentially_exploitable"
        if c.name.endswith("-fixed"):
            assert c.expected_verdict == "likely_not_exploitable"


async def test_score_corpus_runs_and_testonly_is_deterministic():
    from infosec_harness.evals.run import score_corpus

    metrics = await score_corpus(sandbox=False)  # offline; verdicts not meaningful except deterministic paths
    assert metrics["n"] == len(CASES)
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert "confusion" in metrics
