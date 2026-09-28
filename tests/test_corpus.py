"""The seeded corpus stays internally consistent across all languages."""
import pathlib
import re

import pytest

from infosec_harness.evals.corpus import languages, load_corpus
from infosec_harness.repo.detect import detect_stack

CASES = load_corpus()
SINK_PATTERN = {
    "CWE-89": re.compile(r"execute|selectall_arrayref|prepareStatement"),
    # `'-|'` is Perl's list-form pipe open: still a command-execution sink, but argv-form,
    # so it is what a correct CWE-78 fix looks like rather than an absence of a sink.
    "CWE-78": re.compile(r"subprocess\.run|exec|ProcessBuilder|system|`echo|'-\|'"),
    "CWE-22": re.compile(r"open\("),
    "CWE-79": re.compile(r"<div"),
    "CWE-94": re.compile(r"eval\("),  # eval / ast.literal_eval
    "CWE-502": re.compile(r"pickle\.loads|Unpickler"),
    "CWE-611": re.compile(r"\.parse\("),
    "CWE-918": re.compile(r"urlopen\("),
}
DEFINITION_PATTERN = {  # language -> regex (with a {name} slot) for "this callable is defined here"
    "python": r"def\s+{name}\s*\(",
    "perl": r"sub\s+{name}\b",
    "javascript": r"(?:function\s+{name}\s*\(|\b{name}\s*[:=]\s*(?:async\s*)?(?:function\b|\())",
    "java": r"\b{name}\s*\(",  # methods carry a return type/modifiers, not a keyword
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
    # the target callable is defined somewhere in the file (def/sub/function, or a Java method)
    definition = DEFINITION_PATTERN[case.language].format(name=re.escape(case.target_callable))
    assert any(re.search(definition, line) for line in lines), \
        f"{case.name}: no definition of {case.target_callable} in {case.finding.file_path}"


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


def test_fixed_variant_keeps_every_public_callable_the_vulnerable_one_exposes():
    """A pair must differ only in the vulnerability, never in its callable contract.

    One probe has to observe both variants: it establishes the precondition, calls the sink,
    records that the sink returned, and lets the oracle decide. If `fixed` renames a sub,
    changes its arity, or (the case this caught, in perl/cmdi) returns an exit status where
    `vulnerable` returned the command's stdout, no single probe can call both. The probe that
    is correct for one then fails on the other and is scored a probe defect -- the harness
    blames the agent for the corpus's own asymmetry.

    The check is deliberately one-directional: a real fix often *adds* a private helper
    (python/deserialization adds an allowlisting Unpickler subclass), which breaks nothing.
    What it may not do is drop, rename, or re-sign anything public. Reuses the extractors
    behind the `describe_callables` tool, so this asserts what an agent is actually told.
    """
    from infosec_harness.agents.capabilities import _EXTRACTORS

    def public(sigs):
        return {(n, params) for n, params in sigs if not n.split(".")[-1].startswith("_")}

    by = {c.name: c for c in CASES}
    bases = sorted({c.name.rsplit("-", 1)[0] for c in CASES if c.name.endswith("-vulnerable")})
    assert bases, "no vulnerable/fixed pairs found; the pairing convention changed"
    for base in bases:
        v, f = by[f"{base}-vulnerable"], by[f"{base}-fixed"]
        extract = _EXTRACTORS[v.language]
        sigs = []
        for case in (v, f):
            rel = pathlib.Path(case.finding.file_path)
            symbols, _ = extract((case.repo_path / rel).read_text(), rel)
            sigs.append({(sym.name, sym.params) for sym in symbols})
        missing = public(sigs[0]) - sigs[1]
        assert not missing, (
            f"{base}: the fixed variant no longer exposes {sorted(missing)} the way the "
            f"vulnerable one does, so no single probe can observe both. Fixed exposes: "
            f"{sorted(sigs[1])}"
        )
        names = {n.split("::")[-1].split(".")[-1] for n, _ in sigs[1]}
        assert v.target_callable in names, (
            f"{base}: the manifest names target_callable {v.target_callable!r}, which a probe "
            f"will try to call, but the fixed variant defines only {sorted(names)}"
        )


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


async def test_trajectory_report_includes_prepare_agents():
    """The trajectory report covers prepare-phase agents (recon, env-planner), not just
    per-finding agents — proving prepare invocations are wired in."""
    from infosec_harness.evals.run import score_corpus

    metrics = await score_corpus(language="python", sandbox=False)
    traj = metrics["trajectory"]
    assert {"recon", "env-planner"} <= set(traj), "prepare-phase agents missing from trajectory"
    assert {"context", "probe-author"} <= set(traj), "per-finding agents missing from trajectory"
    # recon/env-planner run once per repo (10 python cases -> 10 repos).
    assert traj["recon"]["n"] == len(load_corpus("python"))


async def test_a_label_reached_without_probing_is_reported_separately():
    """`accuracy` counts labels; `accuracy_with_evidence` counts labels the pipeline earned.

    An early exit the manifest did not ask for means no build, no probe and no oracle ran, so
    the label came from reasoning alone. Measured on the Perl pair: both `fixed` cases returned
    `likely_not_exploitable` via `unreachable_by_context` and scored as clean passes. That is
    the same reasoning path that, applied to a vulnerable case, produces a false negative, so it
    must not be invisible in the headline number.
    """
    from infosec_harness.evals.run import score_corpus

    metrics = await score_corpus(language="python", sandbox=False)
    assert "accuracy_with_evidence" in metrics
    assert "unexpected_early_exits" in metrics
    assert isinstance(metrics["unexpected_early_exits"], list)
    # Only `testonly` declares an expected early exit, so an undeclared one is never silent.
    declared = {c.name for c in load_corpus() if c.early_exit}
    assert declared == {"testonly"}, (
        f"the manifest's early-exit expectations changed ({declared}); this metric's meaning "
        "depends on undeclared exits being the exception"
    )


def test_the_only_declared_early_exit_is_the_one_case_that_should_not_be_probed():
    """`testonly` is test/vendored code: exiting before a probe is the correct behaviour there,
    which is why it is declared. Every other case must earn its label by probing."""
    by = {c.name: c for c in CASES}
    assert by["testonly"].early_exit == "test_or_vendored"
    assert all(c.early_exit is None for c in CASES if c.name != "testonly")
