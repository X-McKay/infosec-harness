"""The prepare orchestrator and triage graph run standalone (LocalOps, stub models)."""
import shutil
import tempfile
from pathlib import Path

import pytest

from infosec_harness.domain.models import (
    Finding,
    FindingInput,
    ProbeExecution,
    RepoSnapshot,
    VerdictLabel,
)
from infosec_harness.graph.ops import LocalOps
from infosec_harness.graph.prepare import run_prepare
from infosec_harness.graph.triage import TRIAGE_GRAPH, PreFilter, TriageDeps, TriageState
from infosec_harness.repo.detect import detect_stack


def _recorded(record, outcome):
    """What an Ops implementation does with a call's outcome: record it, then return it."""
    if record is not None:
        record.append(outcome)
    return outcome


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
    finding = Finding.from_input(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
                                      start_line=2, cwe="CWE-89", severity="high"))
    state = TriageState(finding=finding, prepared=prepared)
    result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())
    assert result.verdict.label in set(VerdictLabel)
    assert [i.agent for i in state.invocations] == [
        "context", "probe-planner", "probe-author", "probe-diagnosis", "verdict"]


async def test_triage_prefilter_missing_file(repo):
    ops, prepared = await _prepared(repo)
    finding = Finding.from_input(FindingInput(title="x", repo_url=repo, file_path="ghost.py", cwe="CWE-89"))
    state = TriageState(finding=finding, prepared=prepared)
    result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())
    assert result.verdict.label == VerdictLabel.inconclusive
    assert result.early_exit == "file_missing"
    assert state.invocations == []


async def test_triage_prefilter_test_dir(repo):
    ops, prepared = await _prepared(repo)
    Path(repo, "tests", "t_probe.py").write_text("x=1\n")
    finding = Finding.from_input(FindingInput(title="x", repo_url=repo, file_path="tests/t_probe.py", cwe="CWE-89"))
    state = TriageState(finding=finding, prepared=prepared)
    result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())
    assert result.early_exit != "test_or_vendored"
    assert state.invocations, "a directory name alone must not establish a safety verdict"


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

    async def flaky_run_agent(name, prompt, deps, *, record=None):
        if name == "verdict":
            raise UnexpectedModelBehavior("Exceeded maximum output retries (4)")
        return await real_run_agent(name, prompt, deps, record=record)

    ops.run_agent = flaky_run_agent
    finding = Finding.from_input(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
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

    async def flaky_prepare(ops, snapshot, stack, *, component_root="."):
        # keyed on repo_url: checkout() relocates the tree, so `path` is not the input path
        if snapshot.repo_url == bad_repo:
            from pydantic_ai.exceptions import UsageLimitExceeded
            raise UsageLimitExceeded("Exceeded the input_tokens_limit of 250000")
        return await real_prepare(ops, snapshot, stack, component_root=component_root)

    local.run_prepare = flaky_prepare
    try:
        outputs = await local.triage_batch_local([bad, good], sandbox=False)
    finally:
        local.run_prepare = real_prepare
        shutil.rmtree(bad_repo, ignore_errors=True)

    assert len(outputs) == 2, "the healthy repo's finding must still be reported"
    failed = outputs[0]
    assert failed.result.verdict.label is VerdictLabel.inconclusive
    # `budget_exhausted`, not `environment_unbuildable`: this repository may build perfectly
    # well, and an agent that ran out of tokens is a different problem with a different fix.
    # Lumping the two together is what made a live run's failures unreadable -- six cases filed
    # as "unbuildable" when every one of them had hit a request limit.
    assert failed.result.verdict.inconclusive_reason is InconclusiveReason.budget_exhausted
    assert "input_tokens_limit" in failed.result.verdict.rationale
    assert outputs[1].result.verdict.label in set(VerdictLabel)


async def test_a_failed_preparation_still_reports_the_agent_calls_it_made(repo):
    """The evidence must survive the failure that needs explaining.

    Preparation makes up to a dozen agent calls. A live run over harvested repositories failed
    all six cases in this phase and its metrics contained `"trajectory": {}` and `"budget": {}` —
    nothing about what recon or env-planner had done. The per-agent request/loop report and the
    stage funnel were built to answer "is this a loop or is it large work", and they were blind
    on exactly the failures that raised the question.
    """
    from infosec_harness.graph import local
    from infosec_harness.graph.prepare import PrepareFailed

    real_prepare = local.run_prepare

    async def fail_after_recon(ops, snapshot, stack, *, component_root="."):
        outcome = await real_prepare(ops, snapshot, stack, component_root=component_root)
        raise PrepareFailed(RuntimeError("boom after recon"), outcome.invocations)

    # Recorded in `prepare_sink`, keyed per repo, exactly as the success path does: preparation
    # is shared across a repo's findings, so attaching it to each finding would count it twice.
    # This is the dict `score_corpus` reads prepare-phase invocations from.
    sink: dict[tuple[str, str], list] = {}
    local.run_prepare = fail_after_recon
    try:
        outputs = await local.triage_batch_local(
            [FindingInput(title="SQLi", repo_url=repo, file_path="app.py", start_line=2,
                          cwe="CWE-89", severity="high")], sandbox=False, prepare_sink=sink)
    finally:
        local.run_prepare = real_prepare

    assert len(outputs) == 1
    assert sink, "a failed preparation recorded nothing in the prepare sink"
    agents = [i.agent for calls in sink.values() for i in calls]
    assert "recon" in agents, f"the calls that did run must survive the failure (got {agents})"
    # And the wrapper must not hide the cause: classification keys on the original type.
    assert isinstance(PrepareFailed(ValueError("x"), []).cause, ValueError)


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


def test_a_fired_oracle_outranks_the_runners_test_count():
    """The exploit condition was observed; the runner's bookkeeping cannot unmake that.

    Not hypothetical. Measured on perl 5.34 + prove 3.43: a `.t` script that prints all three
    markers and declares no plan makes prove report `No subtests run` / `Tests: 0` with exit 1 —
    a run whose oracle fired and whose runner says it ran nothing. Overriding that to
    probe_defect sends a true positive into a repair loop it cannot end and it lands
    `inconclusive`, which is the cost this whole function exists to avoid, in the other
    direction. Every runner signature added to `no_tests_executed` widens this surface, so the
    guard belongs here rather than in each signature's phrasing.
    """
    from infosec_harness.domain.models import DiagnosisKind, ProbeDiagnosis, ProbeExecution
    from infosec_harness.graph.triage import _ground_zero_test_diagnosis

    execution = ProbeExecution(
        attempt=1, exit_code=1, oracle_fired=True, precondition_reached=True, sink_returned=True,
        runner_reported_no_tests="prove: no tests were run. Zero tests ran, so this is not a "
                                 "negative result.")
    diagnosis = ProbeDiagnosis(kind=DiagnosisKind.valid_positive, explanation="oracle fired")
    assert _ground_zero_test_diagnosis(diagnosis, execution) is diagnosis


def _diagnosis_ops(ops, kinds):
    """Wrap `ops` so probe-diagnosis returns `kinds` in order (last value repeats).

    Everything else still goes to the stub models, so the rest of the graph is exercised
    normally rather than mocked out around the edge under test.
    """
    from infosec_harness.domain.models import AgentOutcome, DiagnosisKind, ProbeDiagnosis

    real = ops.run_agent
    seen = []

    async def run_agent(name, prompt, deps, *, record=None):
        seen.append(name)
        if name == "probe-diagnosis":
            nth = seen.count("probe-diagnosis") - 1
            kind = kinds[min(nth, len(kinds) - 1)]
            return _recorded(record, AgentOutcome(
                output=ProbeDiagnosis(kind=DiagnosisKind(kind),
                                      explanation="missing driver", fix_hint=""),
                agent=name, model_name="stub"))
        return await real(name, prompt, deps, record=record)

    ops.run_agent = run_agent
    return seen


def _make_build_repair_change_the_plan(ops):
    """The stub may repeat the old plan; these tests specifically exercise the rebuild path."""
    from infosec_harness.domain.models import AgentOutcome

    real = ops.run_agent

    async def run_agent(name, prompt, deps, *, record=None):
        if name != "build-repair":
            return await real(name, prompt, deps, record=record)
        outcome = await real(name, prompt, deps)
        output = outcome.output.model_copy(update={"env": {"HARNESS_REPAIRED": "1"}})
        return _recorded(record, AgentOutcome(**{**outcome.model_dump(), "output": output}))

    ops.run_agent = run_agent


async def test_an_environment_issue_found_at_probe_time_rebuilds_and_retries(repo):
    """The edge that did not exist: a probe-time environment failure used to end the finding.

    Measured on java-sqli, where `No suitable driver found` meant a missing test dependency.
    The probe was correct; only build-repair could act, and it was never reached.
    """
    ops, prepared = await _prepared(repo)
    seen = _diagnosis_ops(ops, ["environment_issue", "valid_negative"])
    _make_build_repair_change_the_plan(ops)
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
    finding = Finding.from_input(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
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
    finding = Finding.from_input(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
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
    _make_build_repair_change_the_plan(ops)
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
    finding = Finding.from_input(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
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
    finding = Finding.from_input(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
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


async def test_context_only_reachability_claims_are_probed(repo):
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

        async def run_agent(name, prompt, deps, *, record=None):
            if name == "context":
                return _recorded(record, AgentOutcome(
                    output=FindingContext(
                        summary="s", reachability=reachability,
                        reachability_rationale="r",
                        sink=CodeRef(file_path="app.py", start_line=2, end_line=2),
                        sanitizers=sanitizers, target_callable="lookup"),
                    agent=name, model_name="stub"))
            return await real(name, prompt, deps, record=record)

        ops.run_agent = run_agent

        async def fake_exec(image, probe, spec, nonce, attempt):
            probed.append(attempt)
            return ProbeExecution(attempt=attempt, exit_code=0, oracle_fired=False,
                                  precondition_reached=True, sink_returned=True)

        ops.execute_probe = fake_exec
        finding = Finding.from_input(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
                                          start_line=2, cwe="CWE-89", severity="high"))
        state = TriageState(finding=finding, prepared=prepared)
        result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())
        return result, probed

    bound = [CodeRef(file_path="app.py", start_line=2, end_line=2, note="parameter binding")]
    neutralized, probed = await run_with(Reachability.neutralized, bound)
    assert probed, "a neutralized finding must be probed: the control is a claim, not evidence"
    assert neutralized.early_exit != "unreachable_by_context"

    unreachable, probed = await run_with(Reachability.unreachable, [])
    assert probed, "a static model assertion must not create a negative security verdict"
    assert unreachable.early_exit != "unreachable_by_context"


def test_a_neutralized_finding_outranks_an_unreachable_one():
    """The path exists, so a wrong control or a later change makes it live. It ranks above
    `unreachable` for that reason, and below `unknown` because a control has been named."""
    from infosec_harness.domain.models import Reachability
    from infosec_harness.graph.scoring import REACHABILITY_WEIGHT

    assert (REACHABILITY_WEIGHT[Reachability.reachable]
            > REACHABILITY_WEIGHT[Reachability.unknown]
            > REACHABILITY_WEIGHT[Reachability.neutralized]
            > REACHABILITY_WEIGHT[Reachability.unreachable])


def test_infrastructure_uncertainty_does_not_demote_critical_security_priority():
    from infosec_harness.domain.models import (
        InconclusiveReason,
        PriorityBand,
        Reachability,
        Verdict,
    )
    from infosec_harness.graph.scoring import (
        priority,
        priority_band,
        priority_score,
    )

    finding = Finding.from_input(FindingInput(title="critical", repo_url="repo", severity="critical"))
    verdict = Verdict(label=VerdictLabel.inconclusive, confidence=0.0,
                      rationale="provider unavailable",
                      inconclusive_reason=InconclusiveReason.infrastructure_error)
    score, band = priority(finding, verdict, Reachability.unknown)
    assert band is PriorityBand.p1
    assert priority_band(priority_score(finding, verdict, Reachability.unknown)) is PriorityBand.p1
    assert score >= 0.6


async def test_context_citations_are_validated_against_snapshot_bytes(repo):
    from infosec_harness.domain.models import CodeRef, FindingContext, Reachability
    from infosec_harness.graph.triage import _validate_context_citations

    _, prepared = await _prepared(repo)
    finding = Finding.from_input(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
                                      start_line=2, cwe="CWE-89"))
    state = TriageState(finding=finding, prepared=prepared)
    context = FindingContext(
        summary="claimed path",
        sink=CodeRef(file_path="app.py", start_line=2, end_line=2),
        source=CodeRef(file_path="ghost.py", start_line=1, end_line=1),
        reachability=Reachability.unreachable,
        reachability_rationale="the model says so",
    )

    validated = _validate_context_citations(state, context)

    assert validated.sink and validated.sink.source_digest
    assert validated.source is None
    assert validated.reachability is Reachability.unknown
    assert "Citation validation failed" in validated.reachability_rationale


async def test_an_environment_repair_does_not_consume_the_probe_repair_budget(repo):
    """Regression: re-running the unchanged probe after an environment rebuild advanced the
    execution count that also gated probe repair, so a later genuine probe defect got one repair
    fewer than `max_probe_repairs` (none at all when the budget is 1)."""
    ops, prepared = await _prepared(repo)
    seen = _diagnosis_ops(ops, ["environment_issue", "probe_defect"])
    _make_build_repair_change_the_plan(ops)

    async def fake_exec(image, probe, spec, nonce, attempt):
        return ProbeExecution(attempt=attempt, exit_code=1, oracle_fired=False,
                              precondition_reached=False, sink_returned=False,
                              stderr_tail="still broken")

    ops.execute_probe = fake_exec
    finding = Finding.from_input(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
                                      start_line=2, cwe="CWE-89", severity="high"))
    state = TriageState(finding=finding, prepared=prepared)
    result = await TRIAGE_GRAPH.run(
        state=state, deps=TriageDeps(ops=ops, max_probe_repairs=1, max_environment_repairs=1),
        inputs=PreFilter())

    assert state.environment_repairs == 1
    assert seen.count("probe-repair") == 1, "the probe-repair budget was spent by the rebuild"
    assert state.probe_repairs == 1
    assert result.early_exit == "probe_unrepairable"


def _negative_ops(ops, verdict_label="likely_not_exploitable"):
    """Diagnosis says valid_negative; the verdict agent returns ``verdict_label``."""
    from infosec_harness.domain.models import AgentOutcome, DiagnosisKind, ProbeDiagnosis, Verdict

    real = ops.run_agent

    async def run_agent(name, prompt, deps, *, record=None):
        if name == "probe-diagnosis":
            return _recorded(record, AgentOutcome(
                output=ProbeDiagnosis(kind=DiagnosisKind.valid_negative, explanation="resisted",
                                      fix_hint=""), agent=name))
        if name == "verdict":
            return _recorded(record, AgentOutcome(
                output=Verdict(label=VerdictLabel(verdict_label), confidence=0.8,
                               rationale="The sink returned safely."), agent=name))
        return await real(name, prompt, deps, record=record)

    async def fake_exec(image, probe, spec, nonce, attempt):
        return ProbeExecution(attempt=attempt, exit_code=0, oracle_fired=False,
                              precondition_reached=True, sink_returned=True)

    ops.run_agent = run_agent
    ops.execute_probe = fake_exec


@pytest.mark.parametrize("record", [None, "HARNESS_CONTROL_RESULT::{not json"])
async def test_a_negative_without_a_readable_control_record_is_not_accepted(repo, record):
    """Regression: a missing or unparseable adapter-control record was treated as passed, so a
    negative judgment could stand on an adapter nobody had shown can report a positive."""
    from infosec_harness.domain.models import InconclusiveReason, SmokeResult

    ops, prepared = await _prepared(repo)
    _negative_ops(ops)
    excerpt = "runner ok" if record is None else "runner ok\n" + record
    prepared = prepared.model_copy(update={"smoke": SmokeResult(ok=True, output_excerpt=excerpt)})
    finding = Finding.from_input(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
                                      start_line=2, cwe="CWE-89", severity="high"))
    state = TriageState(finding=finding, prepared=prepared)
    result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())

    assert result.verdict.label is VerdictLabel.inconclusive
    assert result.verdict.inconclusive_reason is InconclusiveReason.conflicting_evidence
    assert result.early_exit == "unsupported_negative"


async def test_a_negative_with_passing_controls_stands(repo):
    from infosec_harness.domain.models import SmokeResult
    from infosec_harness.sandbox.canary import ControlResult, encode_control_result

    ops, prepared = await _prepared(repo)
    _negative_ops(ops)
    record = encode_control_result(ControlResult(positive=True, negative=True))
    prepared = prepared.model_copy(update={"smoke": SmokeResult(ok=True, output_excerpt=record)})
    finding = Finding.from_input(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
                                      start_line=2, cwe="CWE-89", severity="high"))
    state = TriageState(finding=finding, prepared=prepared)
    result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())

    assert result.verdict.label is VerdictLabel.likely_not_exploitable


async def test_a_failed_verdict_call_is_recorded_with_its_usage(repo):
    """Regression: a verdict call that exhausted its retries vanished from the record, so its
    requests and tokens were missing from every cost and trajectory figure."""
    from pydantic_ai.exceptions import UnexpectedModelBehavior

    from infosec_harness.domain.models import AgentOutcome

    ops, prepared = await _prepared(repo)
    _negative_ops(ops)
    negative_run_agent = ops.run_agent

    async def failing(name, prompt, deps, *, record=None):
        if name == "verdict":
            # What run_recorded does: the failed call's partial outcome, then the error.
            _recorded(record, AgentOutcome(output=None, agent="verdict", requests=5,
                                           input_tokens=900, output_tokens=40,
                                           failure="UnexpectedModelBehavior"))
            raise UnexpectedModelBehavior("Exceeded maximum output retries (4)")
        return await negative_run_agent(name, prompt, deps, record=record)

    ops.run_agent = failing
    finding = Finding.from_input(FindingInput(title="SQLi", repo_url=repo, file_path="app.py",
                                      start_line=2, cwe="CWE-89", severity="high"))
    state = TriageState(finding=finding, prepared=prepared)
    result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())

    assert result.early_exit == "verdict_contract_unsatisfied"
    failed = state.invocations[-1]
    assert (failed.agent, failed.failure, failed.output) == ("verdict", "UnexpectedModelBehavior",
                                                             None)
    assert failed.requests == 5
    assert [i.agent for i in state.invocations].count("verdict") == 1


@pytest.mark.parametrize("failing_agent", ["context", "probe-planner", "probe-author",
                                           "probe-diagnosis", "probe-repair", "build-repair"])
async def test_every_failed_agent_call_keeps_its_partial_usage(repo, monkeypatch,
                                                               failing_agent):
    """Regression: only the verdict node recorded a failed call. A context, planner, author,
    diagnosis or repair call that raised dropped the requests and tokens it had spent, so the
    inconclusive record of the finding understated its cost."""
    from pydantic_ai.messages import ModelResponse, ToolCallPart
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.usage import RequestUsage

    from infosec_harness.graph.pipeline import triage_finding

    ops, prepared = await _prepared(repo)
    if failing_agent in {"probe-repair", "build-repair"}:
        _diagnosis_ops(ops, ["probe_defect" if failing_agent == "probe-repair"
                             else "environment_issue", "valid_negative"])
    agent, _config = ops._agent(failing_agent)

    def respond(messages, info):
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {"bogus": 1})],
                             usage=RequestUsage(input_tokens=100, output_tokens=7))

    with agent.override(model=FunctionModel(respond)):
        output = await triage_finding(ops, FindingInput(
            title="SQLi", repo_url=repo, file_path="app.py", start_line=2, cwe="CWE-89",
            severity="high"), prepared)
    failed = [i for i in output.invocations if i.failure is not None]
    assert [i.agent for i in failed] == [failing_agent]
    assert failed[0].requests >= 2 and failed[0].input_tokens == 100 * failed[0].requests
    assert output.result.verdict.label is VerdictLabel.inconclusive


async def test_local_ops_records_the_partial_usage_of_a_failed_call(repo, monkeypatch):
    """The in-process path measures a failed run from the messages it exchanged."""
    from pydantic_ai.exceptions import UnexpectedModelBehavior
    from pydantic_ai.messages import ModelResponse, ToolCallPart
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.usage import RequestUsage

    from infosec_harness.agents.deps import AgentDeps

    ops = LocalOps(sandbox=False)
    agent, _config = ops._agent("verdict")

    def respond(messages, info):
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {"bogus": 1})],
                             usage=RequestUsage(input_tokens=100, output_tokens=7))

    record = []
    with agent.override(model=FunctionModel(respond)), \
            pytest.raises(UnexpectedModelBehavior) as error:
        await ops.run_agent("verdict", ["Decide."], AgentDeps(repo_path=repo), record=record)
    assert not hasattr(error.value, "agent_outcome")
    [outcome] = record
    assert outcome.failure == "UnexpectedModelBehavior" and outcome.agent == "verdict"
    assert outcome.requests >= 2 and outcome.input_tokens == 100 * outcome.requests


async def test_an_executed_probe_carries_the_controller_record_origins(monkeypatch, tmp_path):
    """The origins the controller records travel with the execution itself, not only inside
    the encoded log artifact: the process is the controller's, the markers are self-reported."""
    from infosec_harness.domain.models import EnvironmentSpec, ProbeSource
    from infosec_harness.graph import workloads
    from infosec_harness.sandbox import docker
    from infosec_harness.sandbox.process import ProcessResult

    async def available(purpose):
        return None

    async def run_probe(image, path, content, command, nonce, module_path=""):
        return ProcessResult(exit_code=0, stdout=f"HARNESS_PRECONDITION::{nonce}\n",
                             stderr="", timed_out=False, duration_s=0.5)

    monkeypatch.setattr(docker, "ensure_runtime_available", available)
    monkeypatch.setattr(docker, "run_probe", run_probe)
    execution = await workloads.execute_probe(
        "image", ProbeSource(test_file_path="tests/test_probe.py", content="probe"),
        EnvironmentSpec(base_image="python:3.12", test_command="pytest {test_file}"), "n0nce", 1)
    origins = execution.origins
    assert origins is not None
    assert origins.process.origin == "controller" and origins.process.exit_code == 0
    assert origins.observations.origin == "self_reported_marker"
    assert origins.observations.precondition_reached is True
    assert origins.runner.origin == "parsed_untrusted_output"


async def test_an_unexecuted_probe_records_no_origins(monkeypatch):
    """Nothing ran, so nothing is observed: the record carries no origin to be verified."""
    from infosec_harness.domain.models import EnvironmentSpec, ProbeSource
    from infosec_harness.graph import workloads
    from infosec_harness.sandbox import docker
    from infosec_harness.sandbox.errors import SandboxUnavailable

    async def unavailable(purpose):
        raise SandboxUnavailable("no runtime")

    monkeypatch.setattr(docker, "ensure_runtime_available", unavailable)
    execution = await workloads.execute_probe(
        "image", ProbeSource(test_file_path="tests/test_probe.py", content="probe"),
        EnvironmentSpec(base_image="python:3.12", test_command="pytest {test_file}"), "n", 1)
    assert execution.origins is None and execution.exit_code is None
    offline = await LocalOps(sandbox=False).execute_probe("i", None, None, "n", 1)
    assert offline.origins is None


@pytest.mark.parametrize("failing_agent", ["recon", "env-planner"])
async def test_a_failed_preparation_call_keeps_its_partial_usage(repo, failing_agent):
    """Regression: a preparation agent call that raised was dropped from PrepareFailed's
    invocations, so a repository that failed to prepare under-reported what it spent."""
    from pydantic_ai.messages import ModelResponse, ToolCallPart
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.usage import RequestUsage

    from infosec_harness.graph.prepare import PrepareFailed

    ops = LocalOps(sandbox=False, recipe_cache=False)
    agent, _config = ops._agent(failing_agent)

    def respond(messages, info):
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {"bogus": 1})],
                             usage=RequestUsage(input_tokens=50, output_tokens=3))

    stack = detect_stack(repo)
    snapshot = RepoSnapshot(repo_url=repo, revision="HEAD", path=repo, content_hash="h" * 8)
    with agent.override(model=FunctionModel(respond)), pytest.raises(PrepareFailed) as failed:
        await run_prepare(ops, snapshot, stack)
    recorded = failed.value.invocations
    assert recorded[-1].agent == failing_agent and recorded[-1].failure is not None
    assert recorded[-1].input_tokens == 50 * recorded[-1].requests > 0
    assert [i.agent for i in recorded].count(failing_agent) == 1
