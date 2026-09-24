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
