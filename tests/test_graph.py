"""The prepare orchestrator and triage graph run standalone (LocalOps, stub models)."""
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
        "context", "probe_planner", "probe_author", "probe_diagnosis", "verdict"]


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
    nothing. probe_diagnosis then reads the probe source next to those markers, concludes
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
