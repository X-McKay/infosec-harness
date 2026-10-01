"""Offline regressions for real-provider provenance, grading and worker boundaries."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml
from broker_real_provider_fixture import (
    CASES,
    ROOT,
    RealProviderManifest,
    phase_environment,
    prepare_case,
    score_output,
    workflow_input,
)
from pydantic import ValidationError


def manifest(tmp_path):
    datasets = {}
    for agent, case in CASES.items():
        path = ROOT / "src/infosec_harness/agents" / agent / "evals/dataset.yaml"
        datasets[agent] = {"path": str(path), "case": case, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                           "version": str(yaml.safe_load(path.read_text())["version"])}
    private = tmp_path / "database.env"
    private.write_text("HARNESS_DATABASE_URL=sqlite+aiosqlite:///:memory:\n")
    private.chmod(0o600)
    secret = tmp_path / "worker.key"
    secret.write_text("offline-test-key-never-in-workflow")
    secret.chmod(0o600)
    return RealProviderManifest.model_validate({"direct_models_config": "direct.yaml",
        "broker_models_config": "broker.yaml", "broker_config": "catalog.yaml",
        "database_env_file": str(private), "worker_hmac_file": str(secret),
        "worker_hmac_env": "HARNESS_BROKER_WORKER_KEY", "report_directory": str(tmp_path),
        "datasets": datasets, "frozen_at": "2026-10-01", "source_commit": "0" * 40,
        "pricing": {"basis": "self-hosted", "input_per_mtok": 0.0, "output_per_mtok": 0.0},
        "hypothesis": "transport equivalence", "phases": ["direct", "native-local", "native-temporal"],
        "maximum_pilot_agent_trials": 33, "runtime_bounds": "unchanged", "abort_conditions": [],
        "acceptance": "existing scores unchanged", "rollout": "qualification only"})


@pytest.mark.parametrize("agent", tuple(CASES))
def test_frozen_case_inputs_keep_ground_truth_and_credentials_host_only(tmp_path, agent):
    config = manifest(tmp_path)
    inputs, _predict, expected, case_digest = prepare_case(agent, config)
    public = workflow_input(inputs)
    assert set(public) == {"agent", "prompt", "deps"}
    assert set(inputs) == {"agent", "prompt", "deps"}
    assert len(case_digest) == 64 and expected
    assert "expected" not in public and "predict" not in public
    assert "offline-test-key-never-in-workflow" not in json.dumps(public)
    assert "broker_binding" not in public["deps"] and "broker_contract" not in public["deps"]


def test_changed_dataset_hash_fails_before_any_execution(tmp_path):
    config = manifest(tmp_path)
    datasets = dict(config.datasets)
    datasets["context"] = datasets["context"].model_copy(update={"sha256": "0" * 64})
    with pytest.raises(ValueError, match="provenance changed"):
        prepare_case("context", config.model_copy(update={"datasets": datasets}))


def test_pilot_cannot_drop_an_agent_or_add_concurrency(tmp_path):
    value = manifest(tmp_path).model_dump(mode="json")
    value["cases"].pop("verdict")
    with pytest.raises(ValidationError):
        RealProviderManifest.model_validate(value)
    value = manifest(tmp_path).model_dump(mode="json")
    value["max_concurrency"] = 2
    with pytest.raises(ValidationError):
        RealProviderManifest.model_validate(value)


def test_worker_environment_removes_provider_keys_and_native_admin(tmp_path, monkeypatch):
    config = manifest(tmp_path)
    for key in ("HARNESS_OPENAI_API_KEY", "OPENAI_API_KEY", "HARNESS_BROKER_NATIVE_CONFIG"):
        monkeypatch.setenv(key, "must-not-reach-worker")
    values = phase_environment(config, "local")
    assert not any(key in values for key in ("HARNESS_OPENAI_API_KEY", "OPENAI_API_KEY", "HARNESS_BROKER_NATIVE_CONFIG"))
    assert values["HARNESS_BROKER_WORKER_KEY"] == "offline-test-key-never-in-workflow"
    assert values["HARNESS_SANDBOX_RUNTIME"] == "runsc"
    assert values["HARNESS_ALLOW_INSECURE_RUNTIME"] == "false"
    assert values["PATH"].split(":")[0] == str(ROOT / ".harness/bin")


def test_semantic_failure_keeps_original_expected_and_typed_output(tmp_path):
    from infosec_harness.domain.models import RepoProfile
    _inputs, predict, expected, _digest = prepare_case("recon", manifest(tmp_path))
    output = RepoProfile(summary="a Python repository", primary_language="python",
                         test_framework="unknown", test_layout="tests")
    result = score_output("recon", output, predict, expected)
    assert result["semantic_score"] == "failed"
    assert result["expected"] == "python/pytest"
    assert result["predicted"] == "python/unknown"
    assert result["typed_output"]["test_framework"] == "unknown"


async def test_temporal_connect_failure_reaps_its_real_owned_worker(tmp_path, monkeypatch):
    import subprocess
    import sys

    import broker_real_provider_fixture as fixture
    from temporalio.client import Client

    original_popen = subprocess.Popen
    children = []

    def start_owned_child(*_args, **kwargs):
        child = original_popen([sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=kwargs["stdout"], stderr=kwargs["stderr"], start_new_session=True)
        children.append(child)
        return child

    async def disconnected(*_args, **_kwargs):
        raise ConnectionError("offline startup failure")

    from infosec_harness.agents import durable
    configuration = manifest(tmp_path)
    configs = {name: value.model_copy(update={"model": value.model.model_copy(
        update={"endpoint": configuration.endpoint})}) for name, value in durable.CONFIGS.items()}
    monkeypatch.setattr(durable, "CONFIGS", configs)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"phase": "direct", "status": "passed", "cases": [
        {"agent": name, "case": CASES[name], "case_digest": prepare_case(name, configuration)[3],
         "config": value.model_dump(mode="json")} for name, value in configs.items()]}))
    monkeypatch.setenv("HARNESS_REAL_PROVIDER_BASELINE", str(baseline))
    monkeypatch.setenv("HARNESS_REAL_PROVIDER_MANIFEST", "offline-manifest")
    monkeypatch.setattr(fixture.subprocess, "Popen", start_owned_child)
    monkeypatch.setattr(Client, "connect", disconnected)
    report_path = tmp_path / "temporal.json"
    result = await fixture.run_temporal(manifest(tmp_path), report_path)
    assert result["status"] == "failed"
    assert result["worker_cleanup"] == "passed"
    assert result["cases"] == []
    assert len(children) == 1 and children[0].poll() is not None
    assert json.loads(report_path.read_text())["execution_status"] == "failed"



def test_direct_baseline_never_receives_broker_authority(tmp_path, monkeypatch):
    config = manifest(tmp_path)
    monkeypatch.setenv(config.worker_hmac_env, "inherited-broker-authority")
    values = phase_environment(config, "direct")
    assert config.worker_hmac_env not in values
    assert "HARNESS_BROKER_CONFIG" not in values
    assert values["HARNESS_DATABASE_URL"] == "sqlite+aiosqlite:///:memory:"



def test_native_comparison_rejects_changed_settings_and_authored_budget(tmp_path, monkeypatch):
    from copy import deepcopy

    from broker_real_provider_fixture import COMPARISON_MODEL_FIELDS, compare_baseline
    configuration = {"model": dict.fromkeys(COMPARISON_MODEL_FIELDS, "frozen"),
                     "budget": {"requested": {"max_requests": 16}}}
    config = manifest(tmp_path)
    rows = [{"agent": agent, "case": name, "case_digest": prepare_case(agent, config)[3],
             "config": configuration} for agent, name in CASES.items()]
    baseline = tmp_path / "direct.json"
    baseline.write_text(json.dumps({"phase": "direct", "status": "passed", "cases": rows}))
    monkeypatch.setenv("HARNESS_REAL_PROVIDER_BASELINE", str(baseline))
    case_digest = rows[0]["case_digest"]
    assert compare_baseline("intake", configuration, case_digest)["status"] == "passed"
    changed = deepcopy(configuration)
    changed["model"]["effective_settings"] = "different"
    with pytest.raises(ValueError, match="settings or pricing"):
        compare_baseline("intake", changed, case_digest)
    changed = deepcopy(configuration)
    changed["model"]["endpoint"] = "https://other.invalid/v1"
    with pytest.raises(ValueError, match="settings or pricing"):
        compare_baseline("intake", changed, case_digest)
    changed = deepcopy(configuration)
    changed["budget"]["requested"]["max_requests"] = 17
    with pytest.raises(ValueError, match="safety budget"):
        compare_baseline("intake", changed, case_digest)


def test_native_comparison_preserves_catalog_provenance_and_rejects_price_drift(tmp_path, monkeypatch):
    from copy import deepcopy

    from broker_real_provider_fixture import COMPARISON_MODEL_FIELDS, compare_baseline
    configuration = {"model": dict.fromkeys(COMPARISON_MODEL_FIELDS, "frozen"),
                     "budget": {"requested": {"max_requests": 16}}}
    configuration["model"]["pricing_table"] = "genai-prices:1:abc;models:direct;backend:gateway;custom:zero"
    config = manifest(tmp_path)
    rows = [{"agent": agent, "case": name, "case_digest": prepare_case(agent, config)[3],
             "config": configuration} for agent, name in CASES.items()]
    baseline = tmp_path / "direct.json"
    baseline.write_text(json.dumps({"phase": "direct", "status": "passed", "cases": rows}))
    monkeypatch.setenv("HARNESS_REAL_PROVIDER_BASELINE", str(baseline))
    changed = deepcopy(configuration)
    changed["model"]["pricing_table"] = "genai-prices:1:abc;models:native;backend:gateway;custom:zero"
    result = compare_baseline("intake", changed, rows[0]["case_digest"])
    assert result["pricing_catalog_provenance"]["direct"] == configuration["model"]["pricing_table"]
    assert result["pricing_catalog_provenance"]["native"] == changed["model"]["pricing_table"]
    for identity in ("genai-prices:1:abc;models:native;backend:gateway;custom:paid",
                     "genai-prices:2:abc;models:native;backend:gateway;custom:zero",
                     "genai-prices:1:abc;models:native;backend:other;custom:zero"):
        changed["model"]["pricing_table"] = identity
        with pytest.raises(ValueError, match="settings or pricing"):
            compare_baseline("intake", changed, rows[0]["case_digest"])


def corrected_amendment(tmp_path):
    from broker_real_provider_fixture import CorrectedPilotAmendment
    identities = [str(i) * 64 for i in range(4)]
    failed = tmp_path / "failed.json"
    failed.write_text(json.dumps({"status": "failed", "cases": [
        {"ledger": {"requests": [{"request_id": identity, "state": "completion_unknown"}]}}
        for identity in identities]}))
    return CorrectedPilotAmendment.model_validate({
        "original_manifest_sha256": "b41fb7a2bd695825bd2eff8b613f052e8c1319ad35bd053997c1a58cc1a20745",
        "baseline_report_sha256": "a" * 64, "failed_report_file": str(failed),
        "failed_report_sha256": hashlib.sha256(failed.read_bytes()).hexdigest(),
        "retained_unknown_request_ids": identities, "original_trials": 33,
        "original_started_trials": 15, "additional_trials": 22, "cumulative_authorized_trials": 37,
        "reason": "known SDK reasoning usage counter codec correction; no unknown resend"})


def test_corrected_pilot_is_explicitly_native_only_and_finite(tmp_path):
    from broker_real_provider_fixture import verify_retained_failure
    amendment = corrected_amendment(tmp_path)
    verify_retained_failure(amendment)
    data = manifest(tmp_path).model_dump()
    data.update(amendment=amendment.model_dump(), maximum_pilot_agent_trials=22,
                phases=["native-local", "native-temporal"])
    assert RealProviderManifest.model_validate(data).amendment.additional_trials == 22
    for changed in ({"maximum_pilot_agent_trials": 33},
                    {"phases": ["direct", "native-local", "native-temporal"]}):
        with pytest.raises(ValidationError):
            RealProviderManifest.model_validate({**data, **changed})


@pytest.mark.parametrize("changed", [{"additional_trials": 23}, {"cumulative_authorized_trials": 38},
                                     {"original_started_trials": 14},
                                     {"retained_unknown_request_ids": ["a" * 64] * 4}])
def test_corrected_pilot_rejects_implicit_trial_extensions_or_unknown_reuse(tmp_path, changed):
    from broker_real_provider_fixture import CorrectedPilotAmendment
    with pytest.raises(ValidationError):
        CorrectedPilotAmendment.model_validate({**corrected_amendment(tmp_path).model_dump(), **changed})


def test_corrected_pilot_retains_failure_bytes_and_exact_unknown_set(tmp_path):
    from broker_real_provider_fixture import verify_retained_failure
    amendment = corrected_amendment(tmp_path)
    foreign = amendment.model_copy(update={"retained_unknown_request_ids": ["b" * 64] + amendment.retained_unknown_request_ids[1:]})
    with pytest.raises(ValueError, match="exact four unknown"):
        verify_retained_failure(foreign)
    failed = Path(amendment.failed_report_file)
    failed.write_text(failed.read_text() + " ")
    with pytest.raises(ValueError, match="report differs"):
        verify_retained_failure(amendment)
