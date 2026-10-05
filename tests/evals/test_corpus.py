"""The seeded corpus stays internally consistent across all languages."""
import pathlib
import re

import pytest

from infosec_harness.evals.corpus import corpus_path, is_remote, languages, load_corpus
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
# language -> (detected language alternatives, build system, acceptable test frameworks).
#
# The frameworks are a *set* because the corpus deliberately spans more than one runner per
# ecosystem: a jest + CommonJS Node case alongside a vitest + ESM + TypeScript one, and a
# Test::More distribution alongside a Test2::V0 Module::Build one. Pinning a single framework per
# language is how the corpus came to assert that every Node repo is a jest repo and every Perl
# repo a Test::More repo, which is exactly the assumption the harness had to stop making.
# `test_the_corpus_spans_more_than_one_runner_per_ecosystem` keeps the breadth from regressing.
EXPECTED_STACK = {
    "python": ({"python"}, "pip", {"pytest"}),
    "java": ({"java"}, "maven", {"junit5"}),
    "javascript": ({"javascript", "typescript"}, "npm", {"jest", "vitest", "mocha", "node:test"}),
    "perl": ({"perl"}, "cpanm", {"Test::More", "Test2::V0"}),
}
# Per-pair overrides, because the JVM is the one place where the corpus deliberately carries two
# frameworks. The seeded Java cases were 100% JUnit 5 on release 17, and 50 of the 51 Maven
# entries harvested from Vul4J are JUnit 4 on Java 7 or 8 — so every Java case here used to
# exercise a recipe that fits one harvested entry in 51. `java-xxe` is the JUnit 4 / source 1.7
# shape. The override is a map rather than a widened set on purpose: a widened set would let a
# JUnit 5 case pass while being detected as JUnit 4, which is the mistake being guarded against.
# A set, because the surrounding assertion intersects. Still exact per case: `{"junit4"}`
# fails if the case is detected as junit5, which is the mistake being guarded against --
# 50 of the 51 harvested Maven entries are JUnit 4 and were being reported as JUnit 5.
EXPECTED_TEST_FRAMEWORK = {"java-xxe": {"junit4"}}


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
    testfw = EXPECTED_TEST_FRAMEWORK.get(case.name.rsplit("-", 1)[0], testfw)
    top = max(st.languages, key=st.languages.get) if st.languages else None
    assert top in langs, f"{case.name}: detected {top}, expected one of {langs}"
    assert build in st.build_systems, f"{case.name}: build {st.build_systems} lacks {build}"
    assert set(st.test_frameworks) & testfw, \
        f"{case.name}: test fw {st.test_frameworks} names none of {sorted(testfw)}"


def test_the_corpus_spans_more_than_one_runner_per_ecosystem():
    """The harness has to work on *any* JS or Perl codebase, so the corpus must contain more than
    one shape of each. A single-runner corpus cannot catch a plan hardcoded to that runner —
    which is how `npx jest --runTestsByPath` survived as the only Node command for so long.
    """
    seen: dict[str, set[str]] = {}
    for case in CASES:
        if case.language in ("javascript", "perl") and not is_remote(case.finding.repo_url):
            seen.setdefault(case.language, set()).update(
                detect_stack(str(case.repo_path)).test_frameworks)
    for language in ("javascript", "perl"):
        assert len(seen.get(language, set())) > 1, (
            f"every {language} case in the corpus reports the same test framework "
            f"({sorted(seen.get(language, set()))}); a plan hardcoded to it would score perfectly"
        )


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
    from infosec_harness.tools.symbols import _EXTRACTORS

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


async def test_score_corpus_runs_offline_and_writes_its_report(tmp_path):
    import json

    from infosec_harness.evals.corpus_run import score_corpus

    report = tmp_path / "corpus.json"
    metrics = await score_corpus(language="python", sandbox=False, limit=2, report=report)
    assert metrics["n"] == 2  # the first pair, kept together
    assert 0.0 <= metrics["accuracy"] <= 1.0
    written = json.loads(report.read_text())
    assert written["metrics"] == json.loads(json.dumps(metrics))
    assert written["selection"] == {"language": "python", "limit": 2, "repeat": 1,
                                    "manifest": str(corpus_path())}
    assert written["provenance"]["source_digest"]


async def test_trajectory_report_includes_prepare_agents():
    """The trajectory report covers prepare-phase agents (recon, env-planner), not just
    per-finding agents — proving prepare invocations are wired in."""
    from infosec_harness.evals.corpus_run import score_corpus

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
    from infosec_harness.evals.corpus_run import score_corpus

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


def _case_and_output(*, reachability="reachable", sink_line=None, verdict="potentially_exploitable",
                     precondition=True, sink_returned=True, oracle=True, status="ready"):
    """One corpus case plus a synthetic run output, for scoring a single stage in isolation."""
    from infosec_harness.domain.models import (
        CodeRef,
        Finding,
        FindingContext,
        PriorityBand,
        ProbeExecution,
        Reachability,
        TriageResult,
        TriageRunOutput,
        Verdict,
        VerdictLabel,
    )

    case = next(c for c in CASES if c.name == "sqli-vulnerable")
    finding = Finding.from_input(case.finding)
    ctx = FindingContext(
        summary="s", reachability=Reachability(reachability), reachability_rationale="r",
        sink=CodeRef(file_path=case.sink_file, start_line=sink_line or case.sink_line,
                     end_line=sink_line or case.sink_line),
        target_callable=case.target_callable,
    )
    execution = ProbeExecution(attempt=1, exit_code=0, oracle_fired=oracle,
                               precondition_reached=precondition, sink_returned=sink_returned)
    result = TriageResult(fingerprint=finding.fingerprint,
                          verdict=Verdict(label=VerdictLabel(verdict), confidence=0.9, rationale="x"),
                          priority_score=1.0, priority=PriorityBand.p1)
    return case, TriageRunOutput(finding=finding, result=result, prepared_status=status,
                                 context=ctx, executions=[execution])


def test_the_stage_funnel_locates_a_failure_instead_of_only_reporting_one():
    """A single accuracy number says a case failed; it cannot say where.

    Locating that by hand meant reading raw traces for every failure, which is what this
    replaces. Here the context misreads reachability while every later stage is fine.
    """
    from infosec_harness.evals.corpus_run import _stage_results

    case, out = _case_and_output(reachability="unreachable")
    stages = dict(_stage_results(case, out))
    assert stages["context: reachability"] is False
    assert stages["environment built"] is True
    assert stages["probe reached the sink"] is True
    assert stages["verdict"] is True


def test_a_stage_that_never_ran_is_not_scored_as_a_pass():
    """The session's recurring lesson, applied to the funnel itself: a silent oracle behind a
    probe that never reached the sink is not agreement. On the `fixed` half it would otherwise
    score as a pass for exactly the reason a zero-test run once scored as a clean negative.
    """
    from infosec_harness.evals.corpus_run import _stage_results

    case, out = _case_and_output(sink_returned=False, oracle=False)
    stages = dict(_stage_results(case, out))
    assert stages["oracle agreed with truth"] is None, "must be 'not reached', not a pass"
    assert stages["probe's sink returned"] is False


def test_the_sink_location_accepts_a_ref_spanning_the_statement_but_not_a_wrong_one():
    from infosec_harness.evals.corpus_run import _stage_results

    case, _ = _case_and_output()
    _, spanning = _case_and_output(sink_line=case.sink_line)
    assert dict(_stage_results(case, spanning))["context: sink located"] is True
    _, wrong = _case_and_output(sink_line=case.sink_line + 40)
    assert dict(_stage_results(case, wrong))["context: sink located"] is False


async def test_the_funnel_blames_the_first_broken_stage_not_the_last():
    """A late stage inherits every earlier mistake, so unattributed counts would put the blame
    on `verdict` for a case whose context went wrong three stages earlier."""
    from infosec_harness.evals.corpus_run import score_corpus

    metrics = await score_corpus(language="python", sandbox=False)
    assert metrics["stages"], "no stages were scored"
    blamed = [n for st in metrics["stages"].values() for n in st["first_failed_here"]]
    assert len(blamed) == len(set(blamed)), "a case was blamed at more than one stage"
    # Under stub models the context agent returns placeholders, so the funnel must locate the
    # loss there rather than at the verdict it ultimately produced.
    assert metrics["stages"]["environment built"]["rate"] == 1.0
    assert not metrics["stages"]["verdict"]["first_failed_here"], (
        "every failure was attributed to the final stage; the attribution is not working"
    )


def test_a_provider_outage_is_not_filed_as_an_unbuildable_environment():
    """The 502 that voided a live validation run, classified.

    The self-hosted gateway returned `upstream_unreachable` mid-run. Every case was bucketed as
    `environment_unbuildable` and the stage funnel duly reported "environment built 1/4" --
    blaming the one stage that had actually worked. An outage says nothing about the repository.
    """
    import httpx
    from pydantic_ai.exceptions import ModelHTTPError

    from infosec_harness.graph.failures import is_infrastructure_failure

    outage = ModelHTTPError(status_code=502, model_name="Qwen3.6-35B-A3B-NVFP4",
                            body={"type": "upstream_unreachable"})
    assert is_infrastructure_failure(outage)
    assert is_infrastructure_failure(httpx.ConnectError("refused"))
    assert is_infrastructure_failure(TimeoutError("agent run timed out"))
    # A genuine build failure is the pipeline's own business and must stay attributable.
    assert not is_infrastructure_failure(RuntimeError("mvn exited 1"))
    assert not is_infrastructure_failure(ValueError("bad spec"))


async def test_infrastructure_failures_are_excluded_from_the_stage_funnel():
    """They are reported on their own line instead, because a run full of them measures nothing."""
    from infosec_harness.domain.models import InconclusiveReason
    from infosec_harness.evals.corpus_run import score_corpus

    metrics = await score_corpus(language="python", sandbox=False)
    assert "infrastructure_failures" in metrics
    # The stub path never hits the provider, so a clean run must report none — otherwise the
    # exclusion would be silently swallowing real stage failures.
    assert metrics["infrastructure_failures"] == []
    assert metrics["stages"]["environment built"]["scored"] == metrics["n"]
    assert InconclusiveReason.infrastructure_error != InconclusiveReason.environment_unbuildable
