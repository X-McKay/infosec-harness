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
    with pytest.raises(ValueError, match="preserve"):
        await evaluation.evaluate_corpus(manifest, report)


async def test_false_negative_blocks_release_even_above_accuracy_threshold(tmp_path, monkeypatch):
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
        model="fixture",
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
