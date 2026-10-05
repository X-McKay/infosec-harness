import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from infosec_harness import evaluation
from infosec_harness.models import Finding, InvestigationResult, Verdict


def test_real_corpus_labels_and_sources_are_preserved():
    path = Path("eval-corpus/manifest.json")
    original = json.loads(path.read_text())["cases"]
    cases = evaluation.corpus_cases(path)
    assert len(cases) == len(original) > 0
    assert [expected for _, expected, _ in cases] == [
        case["truth"]["expected_verdict"] for case in original
    ]
    assert all(finding.source_mode == "working_snapshot" for finding, _, _ in cases)


async def test_failed_external_effect_is_not_retried_or_hidden(tmp_path, monkeypatch):
    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(evaluation, "source_identity", lambda: "commit")
    monkeypatch.setattr(
        evaluation,
        "corpus_cases",
        lambda path: [
            (finding, "potentially_exploitable", "a"),
            (finding, "likely_not_exploitable", "b"),
        ],
    )
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    settings = evaluation.get_settings()
    settings.openshell_config = config
    client = SimpleNamespace(start_workflow=AsyncMock(side_effect=RuntimeError("unknown effect")))
    monkeypatch.setattr(evaluation, "connect", AsyncMock(return_value=client))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    report = tmp_path / "report.json"
    result = await evaluation.evaluate_corpus(manifest, report)
    assert result["status"] == "failed"
    assert [case["status"] for case in result["cases"]] == ["failed", "unstarted"]
    client.start_workflow.assert_awaited_once()
    assert client.start_workflow.call_args.kwargs[
        "execution_timeout"
    ] == evaluation.execution_timeout(settings.limits)
    with pytest.raises(ValueError, match="preserve"):
        await evaluation.evaluate_corpus(manifest, report)


async def test_false_negative_blocks_release_even_above_accuracy_threshold(
    tmp_path, monkeypatch, fixture_worker_identity
):
    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(evaluation, "source_identity", lambda: "commit")
    cases = [(finding, "likely_not_exploitable", str(i)) for i in range(4)]
    cases[-1] = (finding, "potentially_exploitable", "3")
    monkeypatch.setattr(evaluation, "corpus_cases", lambda path: cases)
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    evaluation.get_settings().openshell_config = config
    result = InvestigationResult(
        finding=finding,
        verdict=Verdict(label="likely_not_exploitable", summary="fixture"),
        evidence=[],
        source_digest="hash",
        model=evaluation.get_settings().model_name,
        worker_identity=fixture_worker_identity,
    )
    client = SimpleNamespace(
        start_workflow=AsyncMock(
            return_value=SimpleNamespace(result=AsyncMock(return_value=result))
        )
    )
    monkeypatch.setattr(evaluation, "connect", AsyncMock(return_value=client))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    report = await evaluation.evaluate_corpus(manifest, tmp_path / "report.json")
    assert report["task_success_rate"] == 0.75 and report["unsafe_negatives"] == 1
    assert report["status"] == "failed"


async def test_cancellation_preserves_report_and_cancels_owned_workflow(tmp_path, monkeypatch):
    import asyncio

    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(evaluation, "source_identity", lambda: "commit")
    monkeypatch.setattr(
        evaluation, "corpus_cases", lambda path: [(finding, "inconclusive", "case")]
    )
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    evaluation.get_settings().openshell_config = config
    handle = SimpleNamespace(
        result=AsyncMock(side_effect=asyncio.CancelledError()), cancel=AsyncMock()
    )
    client = SimpleNamespace(
        start_workflow=AsyncMock(return_value=handle), get_workflow_handle=lambda run_id: handle
    )
    monkeypatch.setattr(evaluation, "connect", AsyncMock(return_value=client))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    output = tmp_path / "report.json"
    with pytest.raises(asyncio.CancelledError):
        await evaluation.evaluate_corpus(manifest, output)
    persisted = json.loads(output.read_text())
    assert persisted["status"] == "failed"
    assert persisted["cases"][0]["cancellation"] == "requested"
    assert persisted["cases"][0]["error_type"] == "CancelledError"
    client.start_workflow.assert_awaited_once()
    handle.cancel.assert_awaited_once()


def test_source_identity_ignores_caller_directory_and_ambient_git_configuration(
    tmp_path, monkeypatch
):
    calls = []

    def read(argv, **kwargs):
        calls.append((argv, kwargs))
        if "--show-toplevel" in argv:
            return str(Path(evaluation.__file__).resolve().parents[2]) + "\n"
        if "status" in argv:
            return ""
        return "commit\n"

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setattr(evaluation.subprocess, "check_output", read)
    assert evaluation.source_identity() == "commit"
    assert all(
        kwargs["cwd"] == Path(evaluation.__file__).resolve().parents[2] for _, kwargs in calls
    )
    assert all("GIT_CONFIG_COUNT" not in kwargs["env"] for _, kwargs in calls)
    assert all("core.fsmonitor=false" in argv for argv, _ in calls)


def test_release_policy_preserves_existing_gates_and_has_content_identity():
    import hashlib

    policy, digest = evaluation.release_policy()
    assert policy.minimum_task_success_rate == 0.75
    assert policy.maximum_unsafe_negatives == 0
    assert (
        digest
        == hashlib.sha256(
            Path(evaluation.__file__).with_name("release-policy.yaml").read_bytes()
        ).hexdigest()
    )


async def test_unavailable_temporal_preserves_failed_cohort_and_unchecked_quality(
    tmp_path, monkeypatch
):
    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(evaluation, "source_identity", lambda: "commit")
    monkeypatch.setattr(
        evaluation, "corpus_cases", lambda path: [(finding, "inconclusive", "case")]
    )
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    evaluation.get_settings().openshell_config = config
    monkeypatch.setattr(evaluation, "connect", AsyncMock(side_effect=RuntimeError("unavailable")))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    output = tmp_path / "report.json"
    with pytest.raises(RuntimeError, match="unavailable"):
        await evaluation.evaluate_corpus(manifest, output)
    persisted = json.loads(output.read_text())
    assert persisted["status"] == "failed"
    assert persisted["cases"][0]["status"] == "unstarted"
    assert persisted["gates"] == {
        "complete_corpus": "failed",
        "task_success_rate": "not_checked",
        "unsafe_negatives": "not_checked",
    }


@pytest.fixture(autouse=True)
def fixture_worker_identity(monkeypatch):
    from infosec_harness.models import WorkerIdentity

    identity = WorkerIdentity(
        fingerprint="a" * 64,
        code_sha256="b" * 64,
        config_sha256="c" * 64,
        dependencies={"fixture": "1"},
    )
    monkeypatch.setattr(evaluation, "worker_identity", lambda settings: identity)
    return identity


@pytest.mark.parametrize("mismatch", ["model", "worker"])
async def test_mismatched_worker_cannot_qualify_candidate(
    tmp_path, monkeypatch, fixture_worker_identity, mismatch
):
    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(evaluation, "source_identity", lambda: "commit")
    monkeypatch.setattr(evaluation, "corpus_cases", lambda path: [(finding, "inconclusive", "a")])
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    settings = evaluation.get_settings()
    settings.openshell_config = config
    result = InvestigationResult(
        finding=finding,
        verdict=Verdict(label="inconclusive", summary="fixture"),
        evidence=[],
        source_digest="hash",
        model="wrong" if mismatch == "model" else settings.model_name,
        worker_identity=None if mismatch == "worker" else fixture_worker_identity,
    )
    client = SimpleNamespace(
        start_workflow=AsyncMock(
            return_value=SimpleNamespace(result=AsyncMock(return_value=result))
        )
    )
    monkeypatch.setattr(evaluation, "connect", AsyncMock(return_value=client))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    report = await evaluation.evaluate_corpus(manifest, tmp_path / "report.json")
    assert report["status"] == "failed"
    assert report["cases"][0]["error_type"] == "ValueError"
    assert report["gates"]["task_success_rate"] == "not_checked"
    assert (
        client.start_workflow.call_args.args[1].expected_worker_identity
        == fixture_worker_identity.fingerprint
    )


@pytest.mark.parametrize("cancellation_unavailable", [False, True])
async def test_result_transport_outage_is_bounded_and_cancelled_once(
    tmp_path, monkeypatch, cancellation_unavailable
):
    import asyncio
    from datetime import timedelta

    finding = Finding(title="case", repo_url="repo")
    monkeypatch.setattr(evaluation, "source_identity", lambda: "commit")
    monkeypatch.setattr(
        evaluation,
        "corpus_cases",
        lambda path: [(finding, "inconclusive", "first"), (finding, "inconclusive", "second")],
    )
    monkeypatch.setattr(evaluation, "execution_timeout", lambda limits: timedelta(seconds=0.02))
    monkeypatch.setattr(evaluation, "RPC_TIMEOUT", timedelta(seconds=0.01))
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    evaluation.get_settings().openshell_config = config
    result_wait_stopped = asyncio.Event()

    async def unavailable_result():
        try:
            await asyncio.Event().wait()
        finally:
            result_wait_stopped.set()

    async def unavailable_cancel(**kwargs):
        await asyncio.Event().wait()

    handle = SimpleNamespace(
        result=AsyncMock(side_effect=unavailable_result),
        cancel=AsyncMock(side_effect=unavailable_cancel if cancellation_unavailable else None),
    )
    client = SimpleNamespace(
        start_workflow=AsyncMock(return_value=handle), get_workflow_handle=lambda run_id: handle
    )
    monkeypatch.setattr(evaluation, "connect", AsyncMock(return_value=client))
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    output = tmp_path / "report.json"
    report = await asyncio.wait_for(evaluation.evaluate_corpus(manifest, output), 1)
    assert result_wait_stopped.is_set()
    assert report == json.loads(output.read_text())
    assert report["status"] == "failed"
    assert report["cases"][0]["error_type"] == "TimeoutError"
    assert report["cases"][0]["cancellation"] == (
        "unconfirmed" if cancellation_unavailable else "requested"
    )
    assert report["cases"][1]["status"] == "unstarted"
    assert report["gates"]["task_success_rate"] == "not_checked"
    if cancellation_unavailable:
        assert report["cases"][0]["cancellation_error_type"] == "TimeoutError"
    client.start_workflow.assert_awaited_once()
    handle.result.assert_awaited_once()
    handle.cancel.assert_awaited_once()
