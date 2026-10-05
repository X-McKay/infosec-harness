import pytest
from test_agent import FakeOpenShell

from infosec_harness.config import Settings
from infosec_harness.identity import worker_identity
from infosec_harness.models import Finding, InvestigationRequest, WorkerIdentity
from infosec_harness.workflow import InvestigationActivities


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
