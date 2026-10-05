import pytest
from test_agent import FakeOpenShell

from infosec_harness.config import Settings
from infosec_harness.identity import worker_identity
from infosec_harness.models import Finding, InvestigationRequest, WorkerIdentity
from infosec_harness.workflow import CleanupInvestigation, InvestigationActivities


def test_identity_binds_policy_contents_dependencies_and_configuration(tmp_path):
    import json

    policy = tmp_path / "policy.yaml"
    policy.write_text("network: deny")
    config = tmp_path / "runtime.json"
    config.write_text(json.dumps({"profiles": {"probe": {"policy": str(policy)}}}))
    settings = Settings(openshell_config=config, temporal_api_key="do-not-report")
    first = worker_identity(settings)
    assert "do-not-report" not in first.model_dump_json()
    assert first.dependencies["openshell"] == "0.1.2"
    settings.temporal_api_key = "another-secret"
    assert worker_identity(settings) == first
    policy.write_text("network: allow")
    second = worker_identity(settings)
    assert second.code_sha256 == first.code_sha256
    assert second.config_sha256 != first.config_sha256
    settings.model_name = "other-model"
    assert worker_identity(settings).fingerprint != second.fingerprint


async def test_prepare_refuses_mismatched_candidate_before_any_side_effect():
    identity = WorkerIdentity(
        fingerprint="a" * 64, code_sha256="b" * 64, config_sha256="c" * 64, dependencies={}
    )
    shell = FakeOpenShell()

    async def snapshot(*args):
        raise AssertionError("mismatch must refuse before source capture")

    activities = InvestigationActivities(shell, snapshot, "fixture", identity=lambda: identity)
    with pytest.raises(ValueError, match="does not match"):
        await activities.prepare(
            InvestigationRequest(
                finding=Finding(title="case", repo_url="fixture"), expected_worker_identity="d" * 64
            )
        )
    assert shell.executions == []


def test_worker_refuses_configuration_drift():
    first = WorkerIdentity(
        fingerprint="a" * 64, code_sha256="b" * 64, config_sha256="c" * 64, dependencies={}
    )
    current = [first]
    activities = InvestigationActivities(
        FakeOpenShell(), None, "fixture", identity=lambda: current[0]
    )
    current[0] = first.model_copy(update={"config_sha256": "d" * 64})
    with pytest.raises(ValueError, match="changed; restart"):
        activities.check_identity()


@pytest.mark.parametrize("mode", ["different", "drift", "unknown"])
async def test_cleanup_requires_original_bound_identity_but_allows_current_drift(mode):
    from temporalio.exceptions import ApplicationError

    original = WorkerIdentity(
        fingerprint="a" * 64, code_sha256="b" * 64, config_sha256="c" * 64, dependencies={}
    )
    current = [original]
    shell = FakeOpenShell()
    activities = InvestigationActivities(shell, None, "fixture", identity=lambda: current[0])
    current[0] = original.model_copy(update={"fingerprint": "d" * 64})
    expected = "e" * 64 if mode == "different" else None if mode == "unknown" else "a" * 64
    payload = CleanupInvestigation(run_id="owned", expected_worker_identity=expected)
    if mode == "drift":
        await activities.cleanup(payload)
        assert shell.closed == ["owned"]
    else:
        with pytest.raises(ApplicationError, match="different worker|cleanup unverified") as error:
            await activities.cleanup(payload)
        assert error.value.non_retryable
        assert shell.closed == ([] if mode == "different" else ["owned"])


@pytest.mark.parametrize("stage", ["create", "upload"])
async def test_failed_prepare_closes_on_receiving_worker(monkeypatch, tmp_path, stage):
    from types import SimpleNamespace

    import infosec_harness.workflow as module

    shell = FakeOpenShell()

    async def fail(*args, **kwargs):
        raise ValueError("bounded native staging failed")

    setattr(shell, stage, fail)
    monkeypatch.setattr(module.activity, "info", lambda: SimpleNamespace(workflow_id="owned"))

    async def snapshot(*args):
        return SimpleNamespace(path=str(tmp_path), digest="digest")

    activities = InvestigationActivities(shell, snapshot, "fixture")
    with pytest.raises(ValueError, match="bounded native staging failed"):
        await activities.prepare(
            InvestigationRequest(finding=Finding(title="case", repo_url="fixture"))
        )
    assert shell.closed == ["owned"]


async def test_prepare_waits_for_cleanup_through_repeated_cancellation(monkeypatch, tmp_path):
    import asyncio
    from types import SimpleNamespace

    import infosec_harness.workflow as module

    uploading, cleaning, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    shell = FakeOpenShell()

    async def upload(*args):
        uploading.set()
        await asyncio.Event().wait()

    async def cleanup(run_id):
        cleaning.set()
        await release.wait()
        shell.closed.append(run_id)

    shell.upload, shell.close_run = upload, cleanup
    monkeypatch.setattr(module.activity, "info", lambda: SimpleNamespace(workflow_id="owned"))

    async def snapshot(*args):
        return SimpleNamespace(path=str(tmp_path), digest="digest")

    activities = InvestigationActivities(shell, snapshot, "fixture")
    task = asyncio.create_task(
        activities.prepare(InvestigationRequest(finding=Finding(title="case", repo_url="fixture")))
    )
    await uploading.wait()
    task.cancel()
    await cleaning.wait()
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done() and shell.closed == []
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert shell.closed == ["owned"]
