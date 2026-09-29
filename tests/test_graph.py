"""The prepare orchestrator and triage graph run standalone (LocalOps, stub models)."""
import shutil
import tempfile
from pathlib import Path

import pytest

from infosec_harness.domain.models import FindingInput, ProbeExecution, RepoSnapshot, VerdictLabel
from infosec_harness.graph.ops import LocalOps
from infosec_harness.graph.prepare import run_prepare
from infosec_harness.graph.triage import TRIAGE_GRAPH, PreFilter, TriageDeps, TriageState
from infosec_harness.intake.adapters import to_finding
from infosec_harness.repo.detect import detect_stack


@pytest.fixture
def repo():
    d = tempfile.mkdtemp()
    Path(d, "requirements.txt").write_text("")
    Path(d, "app.py").write_text("def lookup(db, n):\n    return db.execute('SELECT '+n)\n")
    Path(d, "tests").mkdir()
    return d


def test_detect_stack(repo):
    stack = detect_stack(repo)
    assert stack.languages.get("python") == 1
    assert "requirements.txt" in stack.manifests
    assert "pytest" in stack.test_frameworks


async def _prepared(repo):
    ops = LocalOps(sandbox=False)
    stack = detect_stack(repo)
    snap = RepoSnapshot(repo_url=repo, revision="HEAD", path=repo, content_hash="h" * 8)
    prep = await run_prepare(ops, snap, stack)
    return ops, prep.prepared


async def test_prepare_runs_recon_and_planner(repo):
    _, prepared = await _prepared(repo)
    assert prepared.status == "ready"


async def test_triage_full_path(repo):
    ops, prepared = await _prepared(repo)

    async def fake_exec(image, probe, spec, nonce, attempt):
        return ProbeExecution(attempt=attempt, exit_code=0, oracle_fired=False,
                              precondition_reached=True, sink_returned=True,
                              stdout_tail=f"HARNESS_PRECONDITION::{nonce}\n"
                                          f"HARNESS_SINK_RETURNED::{nonce}")

    ops.execute_probe = fake_exec
    finding = to_finding(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
                                      start_line=2, cwe="CWE-89", severity="high"))
    state = TriageState(finding=finding, prepared=prepared)
    result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())
    assert result.verdict.label in set(VerdictLabel)
    assert [i.agent for i in state.invocations] == [
        "context", "probe-planner", "probe-author", "probe-diagnosis", "verdict"]


async def test_triage_prefilter_missing_file(repo):
    ops, prepared = await _prepared(repo)
    finding = to_finding(FindingInput(title="x", repo_url=repo, file_path="ghost.py", cwe="CWE-89"))
    state = TriageState(finding=finding, prepared=prepared)
    result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())
    assert result.verdict.label == VerdictLabel.likely_not_exploitable
    assert result.early_exit == "file_missing"
    assert state.invocations == []


async def test_triage_prefilter_test_dir(repo):
    ops, prepared = await _prepared(repo)
    Path(repo, "tests", "t_probe.py").write_text("x=1\n")
    finding = to_finding(FindingInput(title="x", repo_url=repo, file_path="tests/t_probe.py", cwe="CWE-89"))
    state = TriageState(finding=finding, prepared=prepared)
    result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())
    assert result.early_exit == "test_or_vendored"


def _probe_source():
    from infosec_harness.domain.models import ProbeSource

    return ProbeSource(test_file_path="tests/test_probe.py", content="def test_x(): pass")


def _env_spec():
    from infosec_harness.domain.models import EnvironmentSpec

    return EnvironmentSpec(base_image="python:3.12-slim", test_command="pytest {test_file}")


# --- The Docker-free path must stand in for the real one, not contradict it ---

async def test_no_sandbox_probe_reports_that_it_never_ran():
    """`--no-sandbox` must not fabricate a clean execution.

    Reporting exit_code=0 / precondition_reached=True describes a probe that ran and found
    nothing. probe-diagnosis then reads the probe source next to those markers, concludes
    the probe must be defective, and the graph repairs it — every case, to the repair
    limit. The honest shape is the one the real activity returns when the isolation runtime
    is missing.
    """
    from infosec_harness.graph.ops import LocalOps

    ops = LocalOps(sandbox=False)
    execution = await ops.execute_probe("img", _probe_source(), _env_spec(), "nonce", 1)

    assert execution.exit_code is None
    assert execution.precondition_reached is False
    assert execution.oracle_fired is False
    assert "sandbox disabled" in execution.stderr_tail


async def test_no_sandbox_probe_matches_the_real_sandbox_unavailable_shape():
    """The offline stub and the activity's fail-closed path must agree."""
    from infosec_harness.domain.models import ProbeExecution
    from infosec_harness.graph.ops import LocalOps

    ops = LocalOps(sandbox=False)
    offline = await ops.execute_probe("img", _probe_source(), _env_spec(), "nonce", 1)
    # What execute_probe_activity returns on SandboxUnavailable.
    unavailable = ProbeExecution(attempt=1, exit_code=None, oracle_fired=False,
                                 precondition_reached=False, stderr_tail="runsc missing")
    for field in ("exit_code", "oracle_fired", "precondition_reached"):
        assert getattr(offline, field) == getattr(unavailable, field), field


async def test_a_judge_that_cannot_satisfy_the_contract_yields_inconclusive(repo):
    """The evidence contract must never be able to kill a finding.

    The verdict agent can exhaust its output retries against the deterministic contract —
    observed live, repeating an `inconclusive` verdict that omitted the required
    `inconclusive_reason`. Raising from here fails the finding and, in a batch, every
    finding behind it. `inconclusive` is exactly the answer the three-way contract reserves
    for "the evidence does not support a call", so return that instead.
    """
    from pydantic_ai.exceptions import UnexpectedModelBehavior

    from infosec_harness.domain.models import InconclusiveReason

    ops, prepared = await _prepared(repo)

    async def fake_exec(image, probe, spec, nonce, attempt):
        return ProbeExecution(attempt=attempt, exit_code=0, oracle_fired=False,
                              precondition_reached=True, sink_returned=True,
                              stdout_tail=f"HARNESS_PRECONDITION::{nonce}\n"
                                          f"HARNESS_SINK_RETURNED::{nonce}")

    ops.execute_probe = fake_exec
    real_run_agent = ops.run_agent

    async def flaky_run_agent(name, prompt, deps):
        if name == "verdict":
            raise UnexpectedModelBehavior("Exceeded maximum output retries (4)")
        return await real_run_agent(name, prompt, deps)

    ops.run_agent = flaky_run_agent
    finding = to_finding(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
                                      start_line=2, cwe="CWE-89", severity="high"))
    state = TriageState(finding=finding, prepared=prepared)
    result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())

    assert result.verdict.label is VerdictLabel.inconclusive
    assert result.verdict.inconclusive_reason is InconclusiveReason.error
    assert result.early_exit == "verdict_contract_unsatisfied"
    # It must never be mistaken for a judgement the evidence supported.
    assert result.verdict.confidence == 0.0


async def test_one_failing_finding_does_not_sink_the_batch(repo):
    """A batch shares a process here; in the durable path each finding is its own workflow.

    An agent that exhausts a retry budget on one finding used to raise out of
    triage_batch_local and discard every result in the run, including findings already
    triaged. Observed live: `load_capability` exceeded its retries on one case and took the
    whole all-language sweep with it.
    """
    from pydantic_ai.exceptions import UnexpectedModelBehavior

    from infosec_harness.domain.models import InconclusiveReason
    from infosec_harness.graph import local

    findings = [
        FindingInput(title="SQLi", repo_url=repo, file_path="app.py", start_line=2,
                     cwe="CWE-89", severity="high"),
        FindingInput(title="Second", repo_url=repo, file_path="app.py", start_line=2,
                     cwe="CWE-78", severity="low"),
    ]
    calls = {"n": 0}
    real_triage_one = local.triage_one

    async def flaky(ops, inp, prepared):
        calls["n"] += 1
        if calls["n"] == 1:
            raise UnexpectedModelBehavior("Tool 'load_capability' exceeded max retries count of 2")
        return await real_triage_one(ops, inp, prepared)

    local.triage_one = flaky
    try:
        outputs = await local.triage_batch_local(findings, sandbox=False)
    finally:
        local.triage_one = real_triage_one

    assert len(outputs) == 2, "the surviving finding must still be reported"
    # Which of the two fails is a property of the schedule, not of the containment: the batch
    # runs a repo's findings in the same (cwe, file_path) order the durable workflow uses, and
    # warms on the first. So this asserts that exactly one failed with the right reason and the
    # other was triaged, rather than pinning the failure to an index.
    failed = [o for o in outputs
              if o.result.verdict.inconclusive_reason is InconclusiveReason.error]
    assert len(failed) == 1, [o.result.verdict.inconclusive_reason for o in outputs]
    assert failed[0].result.verdict.label is VerdictLabel.inconclusive
    assert "load_capability" in failed[0].result.verdict.rationale
    survivor = next(o for o in outputs if o is not failed[0])
    assert survivor.result.verdict.label in set(VerdictLabel)
    assert survivor.result.verdict.inconclusive_reason is not InconclusiveReason.error


async def test_a_repo_that_cannot_be_prepared_does_not_sink_the_batch(repo, monkeypatch):
    """Preparation is shared by a repo's findings, so its failure decides those and no others.

    Observed live with the sandbox enabled: build-repair exhausted its token budget on real
    build logs, and because run_prepare sat outside the per-finding guard the exception left
    the batch loop and discarded every finding in the run — including repos already triaged.
    """
    from infosec_harness.domain.models import InconclusiveReason
    from infosec_harness.graph import local

    good = FindingInput(title="SQLi", repo_url=repo, file_path="app.py", start_line=2,
                        cwe="CWE-89", severity="high")
    bad_repo = tempfile.mkdtemp(prefix="harness-bad-")
    Path(bad_repo, "app.py").write_text("def f(): pass\n")
    Path(bad_repo, "requirements.txt").write_text("")
    bad = FindingInput(title="Other", repo_url=bad_repo, file_path="app.py", start_line=1,
                       cwe="CWE-78", severity="low")

    real_prepare = local.run_prepare

    async def flaky_prepare(ops, snapshot, stack):
        # keyed on repo_url: checkout() relocates the tree, so `path` is not the input path
        if snapshot.repo_url == bad_repo:
            from pydantic_ai.exceptions import UsageLimitExceeded
            raise UsageLimitExceeded("Exceeded the input_tokens_limit of 250000")
        return await real_prepare(ops, snapshot, stack)

    local.run_prepare = flaky_prepare
    try:
        outputs = await local.triage_batch_local([bad, good], sandbox=False)
    finally:
        local.run_prepare = real_prepare
        shutil.rmtree(bad_repo, ignore_errors=True)

    assert len(outputs) == 2, "the healthy repo's finding must still be reported"
    failed = outputs[0]
    assert failed.result.verdict.label is VerdictLabel.inconclusive
    assert failed.result.verdict.inconclusive_reason is InconclusiveReason.environment_unbuildable
    assert "input_tokens_limit" in failed.result.verdict.rationale
    assert outputs[1].result.verdict.label in set(VerdictLabel)


async def test_a_hung_agent_run_is_bounded(repo, monkeypatch):
    """A hung provider request never fails, so nothing else ends it.

    The client's retries do not fire (nothing errored), no budget trips (no tokens arrive),
    and the run simply sits. Observed repeatedly against the test endpoint, once for twenty
    minutes on a single request. Under Temporal the activity's start_to_close_timeout covers
    this; outside it, LocalOps must.
    """
    import asyncio

    from infosec_harness.graph.ops import LocalOps
    from infosec_harness.settings import get_settings

    monkeypatch.setenv("HARNESS_AGENT_RUN_TIMEOUT_S", "1")
    get_settings.cache_clear()
    try:
        ops = LocalOps(sandbox=False)
        from infosec_harness.agents import registry

        class _Hang:
            async def run(self, *a, **kw):
                await asyncio.sleep(30)

        monkeypatch.setattr(registry, "build_agent", lambda *a, **kw: _Hang(), raising=True)
        with pytest.raises(TimeoutError, match="HARNESS_AGENT_RUN_TIMEOUT_S=1s"):
            await ops.run_agent("verdict", ["go"], _deps_for_timeout())
    finally:
        get_settings.cache_clear()


def _deps_for_timeout():
    from infosec_harness.agents.deps import AgentDeps

    return AgentDeps(repo_path="/nonexistent")


# --- A clean negative requires the sink call to have returned -----------------------------

def test_a_negative_without_a_returned_sink_becomes_a_probe_defect():
    """"The code resisted the payload" needs the call to have happened.

    Measured false negative on javascript-cmdi-vulnerable: the corpus module uses a named
    export, the probe imported it as a default, the call threw inside a promise that resolved
    anyway, jest exited 0, and the run looked exactly like a clean negative. The diagnosis was
    not unreasonable — the evidence it saw did look like one. The precondition marker is printed
    *before* the call, so only a second marker after it can tell the two apart.
    """
    from infosec_harness.domain.models import DiagnosisKind, ProbeDiagnosis, ProbeExecution
    from infosec_harness.graph.triage import _correct_unsupported_negative

    execution = ProbeExecution(attempt=1, exit_code=0, oracle_fired=False,
                               precondition_reached=True, sink_returned=False)
    diagnosis = ProbeDiagnosis(kind=DiagnosisKind.valid_negative,
                               explanation="the code resisted the payload")
    corrected = _correct_unsupported_negative(diagnosis, execution)
    assert corrected.kind is DiagnosisKind.probe_defect
    assert "sink-returned marker" in corrected.explanation
    assert "the code resisted the payload" in corrected.explanation  # original reading kept
    assert "HARNESS_SINK_RETURNED" in corrected.fix_hint


def test_a_negative_whose_sink_returned_is_left_alone():
    from infosec_harness.domain.models import DiagnosisKind, ProbeDiagnosis, ProbeExecution
    from infosec_harness.graph.triage import _correct_unsupported_negative

    execution = ProbeExecution(attempt=1, exit_code=0, oracle_fired=False,
                               precondition_reached=True, sink_returned=True)
    diagnosis = ProbeDiagnosis(kind=DiagnosisKind.valid_negative, explanation="resisted")
    assert _correct_unsupported_negative(diagnosis, execution) is diagnosis


def test_the_guard_only_touches_negatives():
    """A positive, a defect, or an environment issue is left exactly as diagnosed."""
    from infosec_harness.domain.models import DiagnosisKind, ProbeDiagnosis, ProbeExecution
    from infosec_harness.graph.triage import _correct_unsupported_negative

    execution = ProbeExecution(attempt=1, exit_code=1, oracle_fired=False,
                               precondition_reached=False, sink_returned=False)
    for kind in (DiagnosisKind.valid_positive, DiagnosisKind.probe_defect,
                 DiagnosisKind.environment_issue):
        diagnosis = ProbeDiagnosis(kind=kind, explanation="x")
        assert _correct_unsupported_negative(diagnosis, execution) is diagnosis


def test_a_fired_oracle_implies_the_sink_returned():
    """The exploit condition cannot be observed without the call producing something."""
    from infosec_harness.sandbox.docker import sink_returned

    assert sink_returned("HARNESS_ORACLE::n1", "n1") is True
    assert sink_returned("HARNESS_CANARY_PRESENT::n1", "n1") is True
    assert sink_returned("HARNESS_PRECONDITION::n1", "n1") is False
    assert sink_returned("HARNESS_SINK_RETURNED::n1", "n1") is True


def test_a_zero_test_run_gets_the_runners_own_reason_not_the_models_guess():
    """The measured perl-cmdi-vulnerable failure, end to end through the correction.

    The diagnosis reached the right *kind* for the wrong *reason*, and the reason is what the
    repair agent acts on: it rewrote the probe file that was never the problem. The runner's own
    words must displace the guess, and the speculative fix_hint must be replaced rather than
    kept, because keeping it is what sent three repair attempts the wrong way.
    """
    from infosec_harness.domain.models import DiagnosisKind, ProbeDiagnosis, ProbeExecution
    from infosec_harness.graph.triage import _ground_zero_test_diagnosis
    from infosec_harness.sandbox import docker

    reason = docker.no_tests_executed("t/x.t .. skipped: (no reason given)\nResult: FAIL\n")
    execution = ProbeExecution(attempt=1, exit_code=1, oracle_fired=False,
                               precondition_reached=False, sink_returned=False,
                               runner_reported_no_tests=reason)
    diagnosis = ProbeDiagnosis(kind=DiagnosisKind.probe_defect,
                               explanation="the file was probably not written correctly",
                               fix_hint="rewrite the probe file")
    corrected = _ground_zero_test_diagnosis(diagnosis, execution)
    assert corrected.kind is DiagnosisKind.probe_defect
    assert "executed no tests" in corrected.explanation
    assert "zero-test plan" in corrected.explanation  # the runner's evidence, verbatim
    assert "not written correctly" in corrected.explanation  # original reading still recorded
    assert "rewrite the probe file" not in corrected.fix_hint, "the guess must not steer repair"
    assert "selector matches no test" in corrected.fix_hint


def test_a_run_that_executed_tests_is_left_exactly_as_diagnosed():
    from infosec_harness.domain.models import DiagnosisKind, ProbeDiagnosis, ProbeExecution
    from infosec_harness.graph.triage import _ground_zero_test_diagnosis

    execution = ProbeExecution(attempt=1, exit_code=0, oracle_fired=False,
                               precondition_reached=True, sink_returned=True)
    for kind in (DiagnosisKind.valid_positive, DiagnosisKind.valid_negative,
                 DiagnosisKind.probe_defect, DiagnosisKind.environment_issue):
        diagnosis = ProbeDiagnosis(kind=kind, explanation="x", fix_hint="y")
        assert _ground_zero_test_diagnosis(diagnosis, execution) is diagnosis


def test_a_zero_test_run_can_never_come_back_as_a_positive_or_a_negative():
    """Nothing exercised the sink, so neither verdict direction is sayable from this run."""
    from infosec_harness.domain.models import DiagnosisKind, ProbeDiagnosis, ProbeExecution
    from infosec_harness.graph.triage import _ground_zero_test_diagnosis

    execution = ProbeExecution(attempt=1, exit_code=1, oracle_fired=False,
                               precondition_reached=False, sink_returned=False,
                               runner_reported_no_tests="pytest: collected 0 items")
    for kind in (DiagnosisKind.valid_positive, DiagnosisKind.valid_negative):
        diagnosis = ProbeDiagnosis(kind=kind, explanation="x")
        assert _ground_zero_test_diagnosis(diagnosis, execution).kind is DiagnosisKind.probe_defect


def _diagnosis_ops(ops, kinds):
    """Wrap `ops` so probe-diagnosis returns `kinds` in order (last value repeats).

    Everything else still goes to the stub models, so the rest of the graph is exercised
    normally rather than mocked out around the edge under test.
    """
    from infosec_harness.domain.models import AgentOutcome, DiagnosisKind, ProbeDiagnosis

    real = ops.run_agent
    seen = []

    async def run_agent(name, prompt, deps):
        seen.append(name)
        if name == "probe-diagnosis":
            nth = seen.count("probe-diagnosis") - 1
            kind = kinds[min(nth, len(kinds) - 1)]
            return AgentOutcome(
                output=ProbeDiagnosis(kind=DiagnosisKind(kind),
                                      explanation="missing driver", fix_hint=""),
                agent=name, model_name="stub")
        return await real(name, prompt, deps)

    ops.run_agent = run_agent
    return seen


async def test_an_environment_issue_found_at_probe_time_rebuilds_and_retries(repo):
    """The edge that did not exist: a probe-time environment failure used to end the finding.

    Measured on java-sqli, where `No suitable driver found` meant a missing test dependency.
    The probe was correct; only build-repair could act, and it was never reached.
    """
    ops, prepared = await _prepared(repo)
    seen = _diagnosis_ops(ops, ["environment_issue", "valid_negative"])
    rebuilt = []
    real_build = ops.build_environment

    async def build(snapshot, spec):
        rebuilt.append(spec)
        return await real_build(snapshot, spec)

    ops.build_environment = build
    probes = []

    async def fake_exec(image, probe, spec, nonce, attempt):
        # Attempt 1 hits the missing dependency; after the rebuild the same probe runs clean.
        # The second execution must genuinely reach the sink, or `_correct_unsupported_negative`
        # rewrites the negative into a probe defect and the graph keeps repairing the probe.
        probes.append(probe.content)
        if attempt == 1:
            return ProbeExecution(attempt=attempt, exit_code=1, oracle_fired=False,
                                  precondition_reached=False, sink_returned=False,
                                  stderr_tail="No suitable driver found")
        return ProbeExecution(attempt=attempt, exit_code=0, oracle_fired=False,
                              precondition_reached=True, sink_returned=True)

    ops.execute_probe = fake_exec
    finding = to_finding(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
                                      start_line=2, cwe="CWE-89", severity="high"))
    state = TriageState(finding=finding, prepared=prepared)
    await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())

    assert "build-repair" in seen, "the environment issue never reached the agent that owns specs"
    assert len(rebuilt) == 1, "the environment was not rebuilt from the probe's evidence"
    assert len(probes) == 2, f"the probe was not re-run after the rebuild (ran {len(probes)}x)"
    # The premise of this edge: the probe was fine, its environment was not.
    assert probes[0] == probes[1], "the probe source was changed; only the environment should be"
    assert state.environment_repairs == 1


async def test_the_environment_repair_is_spent_at_most_once(repo):
    """A rebuild is the most expensive edge in the graph, so it must not become a loop."""
    ops, prepared = await _prepared(repo)
    seen = _diagnosis_ops(ops, ["environment_issue"])

    async def fake_exec(image, probe, spec, nonce, attempt):
        return ProbeExecution(attempt=attempt, exit_code=1, oracle_fired=False,
                              precondition_reached=False, sink_returned=False,
                              stderr_tail="No suitable driver found")

    ops.execute_probe = fake_exec
    finding = to_finding(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
                                      start_line=2, cwe="CWE-89", severity="high"))
    state = TriageState(finding=finding, prepared=prepared)
    result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())

    assert seen.count("build-repair") == 1, f"rebuilt {seen.count('build-repair')} times"
    assert state.environment_repairs == 1
    assert result.verdict.label in set(VerdictLabel)  # it still terminates with a verdict


async def test_a_failed_environment_rebuild_ends_the_finding_honestly(repo):
    """If the rebuild does not work, say so rather than re-running against the old image."""
    ops, prepared = await _prepared(repo)
    _diagnosis_ops(ops, ["environment_issue"])
    original_image = prepared.build.image_tag

    async def failed_build(snapshot, spec):
        from infosec_harness.domain.models import BuildResult

        return BuildResult(ok=False, image_tag="", spec=spec, error_excerpt="still broken")

    ops.build_environment = failed_build

    async def fake_exec(image, probe, spec, nonce, attempt):
        assert image == original_image, "a failed rebuild must not change the image being used"
        return ProbeExecution(attempt=attempt, exit_code=1, oracle_fired=False,
                              precondition_reached=False, sink_returned=False,
                              stderr_tail="No suitable driver found")

    ops.execute_probe = fake_exec
    finding = to_finding(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
                                      start_line=2, cwe="CWE-89", severity="high"))
    state = TriageState(finding=finding, prepared=prepared)
    result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())

    assert result.early_exit == "environment_repair_failed"
    # The recorded spec must still describe the image the probe actually ran in.
    assert state.prepared.build.image_tag == original_image


async def test_a_probe_defect_does_not_trigger_an_environment_rebuild(repo):
    """Guards against over-firing: only an environment_issue may take this edge."""
    ops, prepared = await _prepared(repo)
    seen = _diagnosis_ops(ops, ["probe_defect"])

    async def fake_exec(image, probe, spec, nonce, attempt):
        return ProbeExecution(attempt=attempt, exit_code=1, oracle_fired=False,
                              precondition_reached=False, sink_returned=False)

    ops.execute_probe = fake_exec
    finding = to_finding(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
                                      start_line=2, cwe="CWE-89", severity="high"))
    state = TriageState(finding=finding, prepared=prepared)
    await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())

    assert "build-repair" not in seen
    assert state.environment_repairs == 0
    assert "probe-repair" in seen, "a probe defect must still go to probe repair"


def test_a_neutralized_finding_must_name_the_control_it_rests_on():
    """Without a named control, `neutralized` degrades into a softer `unreachable`.

    "Something probably stops it" is the vagueness the split exists to remove, and an unnamed
    control cannot be checked by a probe — which is the whole reason this value does not
    early-exit.
    """
    import pytest

    from infosec_harness.domain.models import FindingContext, Reachability

    with pytest.raises(ValueError, match="requires at least one entry in `sanitizers`"):
        FindingContext(summary="s", reachability=Reachability.neutralized,
                       reachability_rationale="a sanitizer handles it")


async def test_neutralized_code_is_probed_while_unreachable_code_is_not(repo):
    """The behavioural half of the split, and the measured defect it fixes.

    Both Java `fixed` cases returned likely_not_exploitable through `unreachable_by_context` —
    no build, no probe, no oracle — and the label happened to be right. The same reasoning on a
    vulnerable case is a false negative. `neutralized` says the path exists and a control stops
    it; whether the control holds is exactly what a probe establishes.
    """
    from infosec_harness.domain.models import (
        AgentOutcome,
        CodeRef,
        FindingContext,
        Reachability,
    )

    async def run_with(reachability, sanitizers):
        ops, prepared = await _prepared(repo)
        real = ops.run_agent
        probed = []

        async def run_agent(name, prompt, deps):
            if name == "context":
                return AgentOutcome(
                    output=FindingContext(
                        summary="s", reachability=reachability,
                        reachability_rationale="r",
                        sink=CodeRef(file_path="app.py", start_line=2, end_line=2),
                        sanitizers=sanitizers, target_callable="lookup"),
                    agent=name, model_name="stub")
            return await real(name, prompt, deps)

        ops.run_agent = run_agent

        async def fake_exec(image, probe, spec, nonce, attempt):
            probed.append(attempt)
            return ProbeExecution(attempt=attempt, exit_code=0, oracle_fired=False,
                                  precondition_reached=True, sink_returned=True)

        ops.execute_probe = fake_exec
        finding = to_finding(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
                                          start_line=2, cwe="CWE-89", severity="high"))
        state = TriageState(finding=finding, prepared=prepared)
        result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())
        return result, probed

    bound = [CodeRef(file_path="app.py", start_line=2, end_line=2, note="parameter binding")]
    neutralized, probed = await run_with(Reachability.neutralized, bound)
    assert probed, "a neutralized finding must be probed: the control is a claim, not evidence"
    assert neutralized.early_exit != "unreachable_by_context"

    unreachable, probed = await run_with(Reachability.unreachable, [])
    assert not probed, "an unreachable finding has nothing to probe"
    assert unreachable.early_exit == "unreachable_by_context"


def test_a_neutralized_finding_outranks_an_unreachable_one():
    """The path exists, so a wrong control or a later change makes it live. It ranks above
    `unreachable` for that reason, and below `unknown` because a control has been named."""
    from infosec_harness.domain.models import Reachability
    from infosec_harness.graph.scoring import REACHABILITY_WEIGHT

    assert (REACHABILITY_WEIGHT[Reachability.reachable]
            > REACHABILITY_WEIGHT[Reachability.unknown]
            > REACHABILITY_WEIGHT[Reachability.neutralized]
            > REACHABILITY_WEIGHT[Reachability.unreachable])
