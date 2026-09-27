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
                              precondition_reached=True, stdout_tail=f"HARNESS_PRECONDITION::{nonce}")

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
                              precondition_reached=True, stdout_tail=f"HARNESS_PRECONDITION::{nonce}")

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
    failed = outputs[0]
    assert failed.result.verdict.label is VerdictLabel.inconclusive
    assert failed.result.verdict.inconclusive_reason is InconclusiveReason.error
    assert "load_capability" in failed.result.verdict.rationale
    # The second finding was triaged normally rather than discarded.
    assert outputs[1].result.verdict.label in set(VerdictLabel)


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
