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
    expected_fields = {"agent", "prompt", "deps"}
    if agent == "intake":
        expected_fields.add("intake_source_guidance")
        assert public["intake_source_guidance"] is True
    assert set(public) == expected_fields
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
    import os
    import subprocess
    import sys

    import broker_real_provider_fixture as fixture
    from temporalio.client import Client

    original_popen = subprocess.Popen
    children = []

    def start_owned_child(*_args, **kwargs):
        assert not kwargs.get("start_new_session", False)
        child = original_popen([sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=kwargs["stdout"], stderr=kwargs["stderr"])
        assert os.getpgid(child.pid) == os.getpgrp()
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


def native_rerun(tmp_path):
    from broker_real_provider_fixture import NativeRerunAmendment
    unknown = [str(i) * 64 for i in range(10)]
    completed = [letter * 64 for letter in 'abc']
    def evidence(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value))
        return str(path), hashlib.sha256(path.read_bytes()).hexdigest()
    prior, prior_sha = evidence('prior.json', {'ledger': {'requests': [
        {'request_id': identity, 'state': state}
        for state, identities in [('completion_unknown', unknown), ('completed', completed)]
        for identity in identities]}})
    proof, proof_sha = evidence('ledger.json', {'status': 'passed', 'unknown_request_ids': unknown,
        'completed_request_ids': completed, 'unknown_holds_retained': True})
    cause, cause_sha = evidence('cause.json', {'status': 'passed', 'reviewed': True,
        'boundary': 'native-policy-generation', 'evidence_sha256': 'f' * 64})
    candidates = {}
    for name in ('broker.yaml', 'catalog.yaml', 'native.yaml'):
        path, checksum = evidence(name, {'qualification_fixture': name})
        candidates[path] = checksum
    return NativeRerunAmendment.model_validate({
        'original_manifest_sha256': 'b41fb7a2bd695825bd2eff8b613f052e8c1319ad35bd053997c1a58cc1a20745',
        'baseline_report_sha256': 'e' * 64, 'prior_reports': {prior: prior_sha}, 'candidate_files': candidates,
        'native_config_file': str(tmp_path / 'native.yaml'),
        'ledger_proof_file': proof, 'ledger_proof_sha256': proof_sha,
        'cause_resolution_file': cause, 'cause_resolution_sha256': cause_sha,
        'retained_unknown_request_ids': unknown, 'retained_completed_request_ids': completed,
        'reason': 'reviewed native generation correction; retain all outcomes; no unknown resend'})


def test_native_rerun_preserves_evidence_and_native_only_scope(tmp_path):
    from broker_real_provider_fixture import verify_native_rerun
    rerun = native_rerun(tmp_path)
    verify_native_rerun(rerun)
    data = manifest(tmp_path).model_dump()
    data.update(rerun=rerun.model_dump(), broker_models_config=str(tmp_path / 'broker.yaml'),
                broker_config=str(tmp_path / 'catalog.yaml'), maximum_pilot_agent_trials=22,
                phases=['native-local', 'native-temporal'])
    assert RealProviderManifest.model_validate(data).rerun.additional_graph_trials == 1
    with pytest.raises(ValidationError):
        RealProviderManifest.model_validate({**data, 'amendment': corrected_amendment(tmp_path).model_dump()})


@pytest.mark.parametrize('changed', [{'additional_trials': 23}, {'additional_graph_trials': 2},
    {'retained_unknown_request_ids': ['a' * 64] * 10}, {'retained_completed_request_ids': ['b' * 64]}])
def test_native_rerun_denies_extra_trials_or_lost_outcomes(tmp_path, changed):
    from broker_real_provider_fixture import NativeRerunAmendment
    with pytest.raises(ValidationError):
        NativeRerunAmendment.model_validate({**native_rerun(tmp_path).model_dump(), **changed})


@pytest.mark.parametrize('which', ['prior', 'ledger', 'cause'])
def test_native_rerun_pins_every_evidence_file(tmp_path, which):
    from broker_real_provider_fixture import verify_native_rerun
    rerun = native_rerun(tmp_path)
    path = {'prior': next(iter(rerun.prior_reports)), 'ledger': rerun.ledger_proof_file,
            'cause': rerun.cause_resolution_file}[which]
    Path(path).write_text(Path(path).read_text() + ' ')
    with pytest.raises(ValueError, match='evidence differs'):
        verify_native_rerun(rerun)


@pytest.mark.parametrize('change', ['foreign_request', 'unreviewed', 'holds_released'])
def test_native_rerun_denies_consistently_rehashed_bad_proofs(tmp_path, change):
    from broker_real_provider_fixture import verify_native_rerun
    rerun = native_rerun(tmp_path)
    if change == 'foreign_request':
        path = next(iter(rerun.prior_reports))
        value = json.loads(Path(path).read_text())
        value['ledger']['requests'][0]['request_id'] = 'f' * 64
        Path(path).write_text(json.dumps(value))
        rerun = rerun.model_copy(update={'prior_reports': {path: hashlib.sha256(Path(path).read_bytes()).hexdigest()}})
    else:
        prefix = 'cause_resolution' if change == 'unreviewed' else 'ledger_proof'
        path = getattr(rerun, prefix + '_file')
        value = json.loads(Path(path).read_text())
        value['reviewed' if change == 'unreviewed' else 'unknown_holds_retained'] = False
        Path(path).write_text(json.dumps(value))
        rerun = rerun.model_copy(update={prefix + '_sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest()})
    with pytest.raises(ValueError):
        verify_native_rerun(rerun)


def test_phase_claim_is_single_use_and_keeps_other_phase_available(tmp_path):
    from broker_real_provider_fixture import claim_phase
    claim_phase(tmp_path, 'a' * 64, 'local')
    with pytest.raises(FileExistsError):
        claim_phase(tmp_path, 'a' * 64, 'local')
    claim_phase(tmp_path, 'a' * 64, 'temporal')
    with pytest.raises(ValueError):
        claim_phase(tmp_path, 'a' * 64, 'graph')


def test_phase_claim_has_one_concurrent_winner(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from broker_real_provider_fixture import claim_phase

    barrier = Barrier(4)
    def attempt():
        barrier.wait()
        try:
            claim_phase(tmp_path, 'c' * 64, 'local')
        except FileExistsError:
            return False
        return True
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(lambda _: attempt(), range(4))).count(True) == 1


def test_untrusted_output_cannot_replace_retained_ledger_rows(tmp_path):
    from broker_real_provider_fixture import verify_native_rerun

    rerun = native_rerun(tmp_path)
    path = next(iter(rerun.prior_reports))
    value = json.loads(Path(path).read_text())
    value['typed_output'] = value.pop('ledger')
    Path(path).write_text(json.dumps(value))
    rerun = rerun.model_copy(update={'prior_reports': {path: hashlib.sha256(Path(path).read_bytes()).hexdigest()}})
    with pytest.raises(ValueError, match='exact prior request union'):
        verify_native_rerun(rerun)


def test_native_rerun_rejects_candidate_catalog_drift(tmp_path):
    from broker_real_provider_fixture import verify_native_rerun

    rerun = native_rerun(tmp_path)
    catalog = tmp_path / 'catalog.yaml'
    catalog.write_text(catalog.read_text() + ' ')
    with pytest.raises(ValueError, match='candidate file changed'):
        verify_native_rerun(rerun)


def test_native_rerun_denies_unrelated_third_candidate_file(tmp_path):
    rerun = native_rerun(tmp_path)
    unrelated = tmp_path / 'unrelated.yaml'
    unrelated.write_text('irrelevant artifact')
    candidates = dict(rerun.candidate_files)
    candidates[str(unrelated)] = candidates.pop(rerun.native_config_file)
    data = manifest(tmp_path).model_dump()
    data.update(rerun=rerun.model_copy(update={'candidate_files': candidates}).model_dump(),
                broker_models_config=str(tmp_path / 'broker.yaml'), broker_config=str(tmp_path / 'catalog.yaml'),
                maximum_pilot_agent_trials=22, phases=['native-local', 'native-temporal'])
    with pytest.raises(ValidationError, match='exactly the declared'):
        RealProviderManifest.model_validate(data)


def reviewed_transport_rerun(tmp_path):
    rerun = native_rerun(tmp_path)
    unknown = rerun.retained_unknown_request_ids + [hashlib.sha256(f'unknown-{i}'.encode()).hexdigest() for i in range(3)]
    completed = rerun.retained_completed_request_ids + [hashlib.sha256(f'saved-{i}'.encode()).hexdigest() for i in range(51)]
    path = next(iter(rerun.prior_reports))
    Path(path).write_text(json.dumps({'ledger': {'requests': [
        {'request_id': identity, 'state': state}
        for state, identities in [('completion_unknown', unknown), ('completed', completed)] for identity in identities]}}))
    proof = Path(rerun.ledger_proof_file)
    proof.write_text(json.dumps({'status': 'passed', 'unknown_request_ids': unknown,
        'completed_request_ids': completed, 'unknown_holds_retained': True}))
    cause = Path(rerun.cause_resolution_file)
    value = json.loads(cause.read_text())
    value['boundary'] = 'native-response-acknowledgement'
    cause.write_text(json.dumps(value))
    values = rerun.model_dump()
    values.update(review_version=2, retained_unknown_count=13, retained_completed_count=54,
        retained_unknown_request_ids=unknown, retained_completed_request_ids=completed,
        prior_reports={path: hashlib.sha256(Path(path).read_bytes()).hexdigest()},
        ledger_proof_sha256=hashlib.sha256(proof.read_bytes()).hexdigest(),
        cause_resolution_sha256=hashlib.sha256(cause.read_bytes()).hexdigest(),
        reason='reviewed native transport correction; retain all outcomes; no unknown resend')
    return type(rerun).model_validate(values)


def test_new_review_retains_declared_current_outcomes_without_changing_historical_scope(tmp_path):
    from broker_real_provider_fixture import verify_native_rerun
    rerun = reviewed_transport_rerun(tmp_path)
    verify_native_rerun(rerun)
    assert len(rerun.retained_unknown_request_ids) == 13
    assert len(rerun.retained_completed_request_ids) == 54
    assert (rerun.additional_trials, rerun.additional_graph_trials) == (22, 1)
    with pytest.raises(ValidationError):
        type(rerun).model_validate({**rerun.model_dump(), 'review_version': 1})


@pytest.mark.parametrize('changed', [{'retained_unknown_count': 12}, {'retained_completed_count': 53},
    {'retained_unknown_count': None}, {'additional_trials': 23}, {'additional_graph_trials': 2}])
def test_new_review_rejects_dropped_outcomes_or_scope_extension(tmp_path, changed):
    rerun = reviewed_transport_rerun(tmp_path)
    with pytest.raises(ValidationError):
        type(rerun).model_validate({**rerun.model_dump(), **changed})


def test_new_review_requires_new_boundary_not_old_cause_attestation(tmp_path):
    from broker_real_provider_fixture import verify_native_rerun
    rerun = reviewed_transport_rerun(tmp_path)
    path = Path(rerun.cause_resolution_file)
    value = json.loads(path.read_text())
    value['boundary'] = 'native-policy-generation'
    path.write_text(json.dumps(value))
    rerun = rerun.model_copy(update={'cause_resolution_sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    with pytest.raises(ValueError, match='cause resolution'):
        verify_native_rerun(rerun)


@pytest.mark.parametrize("before_handle_return", [False, True])
async def test_cancelled_temporal_trial_terminates_current_workflow_reaps_real_worker_and_reports_terminal(tmp_path, monkeypatch, before_handle_return):
    import asyncio
    import subprocess
    import sys
    from types import SimpleNamespace

    import broker_real_provider_fixture as fixture
    from temporalio.client import Client
    from temporalio.worker import Replayer

    from infosec_harness.agents import durable

    configuration = manifest(tmp_path)
    configs = {name: value.model_copy(update={'model': value.model.model_copy(
        update={'endpoint': configuration.endpoint})}) for name, value in durable.CONFIGS.items()}
    monkeypatch.setattr(durable, 'CONFIGS', configs)
    baseline = tmp_path / 'baseline.json'
    baseline.write_text(json.dumps({'phase': 'direct', 'status': 'passed', 'cases': [
        {'agent': name, 'case': CASES[name], 'case_digest': prepare_case(name, configuration)[3],
         'config': value.model_dump(mode='json')} for name, value in configs.items()]}))
    monkeypatch.setenv('HARNESS_REAL_PROVIDER_BASELINE', str(baseline))
    monkeypatch.setenv('HARNESS_REAL_PROVIDER_MANIFEST', 'offline-manifest')
    children = []
    real_popen = subprocess.Popen
    def start_owned_child(*_args, **_kwargs):
        child = real_popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)
        children.append(child)
        return child
    monkeypatch.setattr(fixture.subprocess, 'Popen', start_owned_child)
    started = asyncio.Event()
    terminated = []
    class Handle:
        id = 'batch:owned-cancelled-fixture'
        first_execution_run_id = 'owned-run-id'
        async def result(self):
            started.set()
            await asyncio.Future()
        async def terminate(self, _reason):
            terminated.append(self.id)
        async def fetch_history(self):
            return SimpleNamespace(to_json=lambda: '{}', events=[])
    submissions = {}
    async def start(*_args, **kwargs):
        submissions.update(kwargs)
        if before_handle_return:
            started.set()
            await asyncio.Future()
        return Handle()
    async def describe():
        return SimpleNamespace(id=submissions['id'], task_queue=submissions['task_queue'],
                               workflow_type='BrokerRealProviderQualificationWorkflow', run_id=Handle.first_execution_run_id)
    def get_handle(workflow_id, **kwargs):
        assert workflow_id == submissions['id']
        if not kwargs:
            return SimpleNamespace(describe=describe)
        assert kwargs == {'run_id': Handle.first_execution_run_id,
                          'first_execution_run_id': Handle.first_execution_run_id}
        return Handle()
    async def connect(*_args, **_kwargs):
        return SimpleNamespace(start_workflow=start, get_workflow_handle=get_handle)
    async def seed(*_args, **_kwargs):
        return None
    async def snapshot(root):
        return {'root_id': root, 'root_state': {'operations': {}}, 'requests': [], 'request_states': {}}
    async def replay(*_args, **_kwargs):
        return None
    monkeypatch.setattr(Client, 'connect', connect)
    monkeypatch.setattr(fixture, 'seed_root', seed)
    monkeypatch.setattr(fixture, 'ledger_snapshot', snapshot)
    monkeypatch.setattr(Replayer, 'replay_workflow', replay)
    path = tmp_path / 'temporal.json'
    task = asyncio.create_task(fixture.run_temporal(configuration, path))
    await asyncio.wait_for(started.wait(), 10)
    task.cancel()
    result = await asyncio.wait_for(task, 10)
    assert terminated == [Handle.id]
    assert result['status'] == result['execution_status'] == 'failed'
    assert result['interrupted'] is True and result['worker_cleanup'] == 'passed'
    assert len(result['cases']) == 1 and result['cases'][0]['failure_type'] == 'CancelledError'
    assert len(children) == 1 and children[0].poll() is not None
    if before_handle_return:
        assert result['cases'][0]['submission_recovery'] == 'passed'
    assert json.loads(path.read_bytes())['status'] == 'failed'


def test_outer_sigint_checkpoints_failed_report_and_reaps_owned_phase(tmp_path, monkeypatch):
    import importlib.util
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location('qualification_runner_interrupt_test', root / 'scripts/broker_real_provider_check.py')
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    configuration = manifest(tmp_path)
    frozen = tmp_path / 'manifest.json'
    frozen.write_text(configuration.model_dump_json())
    monkeypatch.setattr(runner, 'ROOT', tmp_path)
    monkeypatch.setattr(runner, 'phase_environment', lambda *_: {})
    children = []
    real_popen = subprocess.Popen
    class InterruptOnce:
        def __init__(self, child):
            self.child, self.pid, self.interrupted = child, child.pid, False
        def wait(self, timeout):
            if not self.interrupted:
                self.interrupted = True
                raise KeyboardInterrupt
            return self.child.wait(timeout=timeout)
        def poll(self):
            return self.child.poll()
        def terminate(self):
            return self.child.terminate()
        def kill(self):
            return self.child.kill()
    def start(*_args, **_kwargs):
        child = real_popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)
        children.append(child)
        return InterruptOnce(child)
    monkeypatch.setattr(runner.subprocess, 'Popen', start)
    monkeypatch.setattr(sys, 'argv', ['qualification', '--manifest', str(frozen), '--manifest-sha256',
        hashlib.sha256(frozen.read_bytes()).hexdigest(), '--phase', 'direct', '--allow-inference'])
    assert runner.main() == 1
    report = json.loads(next(tmp_path.glob('pilot-*/report.json')).read_bytes())
    assert report['status'] == 'failed'
    assert report['phases'] == [{'phase': 'direct', 'status': 'failed',
        'failure_type': 'QualificationInterrupted', 'child_reaped': True}]
    assert len(children) == 1 and children[0].poll() is not None


@pytest.mark.parametrize('key', ['unknown_request_ids', 'completed_request_ids'])
def test_new_review_rejects_duplicate_authoritative_proof_rows(tmp_path, key):
    from broker_real_provider_fixture import verify_native_rerun
    rerun = reviewed_transport_rerun(tmp_path)
    path = Path(rerun.ledger_proof_file)
    value = json.loads(path.read_text())
    value[key].append(value[key][0])
    path.write_text(json.dumps(value))
    rerun = rerun.model_copy(update={'ledger_proof_sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    with pytest.raises(ValueError, match='Authoritative retained ledger proof'):
        verify_native_rerun(rerun)


@pytest.mark.parametrize('field,value', [('id', 'foreign'), ('task_queue', 'foreign'),
    ('workflow_type', 'ForeignWorkflow'), ('run_id', '')])
async def test_submission_recovery_rejects_foreign_scope_before_creating_mutation_handle(field, value):
    from types import SimpleNamespace

    from broker_real_provider_fixture import recover_owned_submission
    values = {'id': 'batch:owned', 'task_queue': 'owned-queue',
              'workflow_type': 'BrokerRealProviderQualificationWorkflow', 'run_id': 'owned-run'}
    values[field] = value
    async def describe():
        return SimpleNamespace(**values)
    def get_handle(workflow_id, **kwargs):
        assert workflow_id == 'batch:owned' and not kwargs
        return SimpleNamespace(describe=describe)
    with pytest.raises(ValueError, match='ownership differs'):
        await recover_owned_submission(SimpleNamespace(get_workflow_handle=get_handle), 'batch:owned', 'owned-queue')


def reviewed_output_rerun(tmp_path):
    rerun = native_rerun(tmp_path)
    unknown = rerun.retained_unknown_request_ids + [hashlib.sha256(f'v3-unknown-{i}'.encode()).hexdigest() for i in range(5)]
    completed = rerun.retained_completed_request_ids + [hashlib.sha256(f'v3-saved-{i}'.encode()).hexdigest() for i in range(77)]
    rows = [{'request_id': identity, 'state': state} for state, ids in
            [('completion_unknown', unknown), ('completed', completed)] for identity in ids]
    reports = {}
    for number in range(12):
        path = tmp_path / f'output-review-{number}.json'
        path.write_text(json.dumps({'ledger': {'requests': rows[number::12]}}))
        reports[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    proof = Path(rerun.ledger_proof_file)
    proof.write_text(json.dumps({'status': 'passed', 'unknown_request_ids': unknown,
        'completed_request_ids': completed, 'unknown_holds_retained': True}))
    cause = Path(rerun.cause_resolution_file)
    cause.write_text(json.dumps({'status': 'passed', 'reviewed': True,
        'boundary': 'native-inference-deadlines-and-output-shaping', 'evidence_sha256': 'd' * 64}))
    return type(rerun).model_validate({**rerun.model_dump(), 'review_version': 3,
        'strict_closed_output_tools': True, 'retained_unknown_count': 15, 'retained_completed_count': 80,
        'retained_unknown_request_ids': unknown, 'retained_completed_request_ids': completed,
        'prior_reports': reports, 'ledger_proof_sha256': hashlib.sha256(proof.read_bytes()).hexdigest(),
        'cause_resolution_sha256': hashlib.sha256(cause.read_bytes()).hexdigest(),
        'baseline_report_sha256': '78eac315f11c52b8e3202b4d5cc595c57888d1107a2e5d2a4f63a6d404bd4ce5',
        'reason': 'reviewed native deadlines and closed-output shaping correction; retain all outcomes; no unknown resend'})


def test_review3_preserves_exact_current_union_and_finite_scope(tmp_path):
    from broker_real_provider_fixture import verify_native_rerun
    value = reviewed_output_rerun(tmp_path)
    verify_native_rerun(value)
    assert (len(value.prior_reports), len(value.retained_unknown_request_ids),
            len(value.retained_completed_request_ids)) == (12, 15, 80)
    assert (value.additional_trials, value.additional_graph_trials) == (22, 1)
    assert value.model_dump()['strict_closed_output_tools'] is True


@pytest.mark.parametrize('change', [{'strict_closed_output_tools': False}, {'strict_closed_output_tools': 'true'},
    {'retained_unknown_count': 14}, {'retained_completed_count': 79}, {'additional_trials': 23},
    {'additional_graph_trials': 2}, {'baseline_report_sha256': 'a' * 64}, {'reason': 'output quality accepted'}])
def test_review3_rejects_undeclared_shaping_lost_retention_or_scope_drift(tmp_path, change):
    value = reviewed_output_rerun(tmp_path)
    with pytest.raises(ValidationError):
        type(value).model_validate({**value.model_dump(), **change})


def test_review3_rejects_old_boundary_and_missing_retained_report(tmp_path):
    from broker_real_provider_fixture import verify_native_rerun
    value = reviewed_output_rerun(tmp_path)
    reports = dict(value.prior_reports)
    reports.pop(next(iter(reports)))
    with pytest.raises(ValidationError):
        type(value).model_validate({**value.model_dump(), 'prior_reports': reports})
    path = Path(value.cause_resolution_file)
    cause = json.loads(path.read_bytes())
    cause['boundary'] = 'native-response-acknowledgement'
    path.write_text(json.dumps(cause))
    value = value.model_copy(update={'cause_resolution_sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    with pytest.raises(ValueError, match='cause resolution'):
        verify_native_rerun(value)


@pytest.mark.parametrize('factory', [native_rerun, reviewed_transport_rerun])
def test_historical_review_payloads_omit_false_shaping_and_deny_true(tmp_path, factory):
    value = factory(tmp_path)
    before = value.model_dump_json()
    assert 'strict_closed_output_tools' not in value.model_dump()
    roundtrip = type(value).model_validate({**value.model_dump(), 'strict_closed_output_tools': False})
    assert roundtrip.model_dump_json() == before
    with pytest.raises(ValidationError):
        type(value).model_validate({**value.model_dump(), 'strict_closed_output_tools': True})


def output_comparison_fixture(tmp_path, monkeypatch):
    from copy import deepcopy

    from broker_real_provider_fixture import COMPARISON_MODEL_FIELDS
    config = manifest(tmp_path)
    previous = {'model': dict.fromkeys(COMPARISON_MODEL_FIELDS, 'frozen'),
        'budget': {'requested': {'max_requests': 4}, 'effective': {'max_requests': 4}}}
    previous['model']['capability_profile'] = {'structured_output': 'tool', 'reasoning_accounting': 'inside_output'}
    rows = [{'agent': agent, 'case': name, 'case_digest': prepare_case(agent, config)[3],
             'config': previous} for agent, name in CASES.items()]
    path = tmp_path / 'output-direct.json'
    path.write_text(json.dumps({'phase': 'direct', 'status': 'passed', 'cases': rows}))
    monkeypatch.setenv('HARNESS_REAL_PROVIDER_BASELINE', str(path))
    current = deepcopy(previous)
    current['model']['capability_profile']['strict_closed_output_tools'] = True
    current['model']['broker_contract'] = {'strict_closed_output_tools': True}
    return config, current, rows[0]['case_digest']


def test_only_manifest_declared_output_change_passes_and_is_reported(tmp_path, monkeypatch):
    from broker_real_provider_fixture import compare_baseline, compare_manifest_baseline
    config, current, case_digest = output_comparison_fixture(tmp_path, monkeypatch)
    monkeypatch.setenv('HARNESS_REAL_PROVIDER_STRICT_CLOSED_OUTPUT_TOOLS', 'true')
    with pytest.raises(ValueError, match='explicitly reviewed'):
        compare_baseline('intake', current, case_digest)
    with pytest.raises(ValueError, match='explicitly reviewed'):
        compare_manifest_baseline(config, 'intake', current, case_digest)
    config = config.model_copy(update={'rerun': reviewed_output_rerun(tmp_path)})
    result = compare_manifest_baseline(config, 'intake', current, case_digest)
    assert result['declared_output_shaping_difference'] == {'review_version': 3,
        'field': 'strict_closed_output_tools', 'direct': False, 'native': True,
        'scope': 'closed model output tools only; typed output contracts, scorer and expected outcome unchanged'}


@pytest.mark.parametrize('change', ['false_candidate', 'false_contract', 'other_capability', 'settings',
    'authored_budget', 'effective_budget', 'other_model', 'case'])
def test_review3_comparison_rejects_every_other_change(tmp_path, monkeypatch, change):
    from broker_real_provider_fixture import compare_manifest_baseline
    config, current, case_digest = output_comparison_fixture(tmp_path, monkeypatch)
    config = config.model_copy(update={'rerun': reviewed_output_rerun(tmp_path)})
    if change == 'false_candidate':
        current['model']['capability_profile']['strict_closed_output_tools'] = False
    elif change == 'false_contract':
        current['model']['broker_contract']['strict_closed_output_tools'] = False
    elif change == 'other_capability':
        current['model']['capability_profile']['reasoning_accounting'] = 'separate'
    elif change == 'settings':
        current['model']['effective_settings'] = 'different'
    elif change == 'authored_budget':
        current['budget']['requested']['max_requests'] = 5
    elif change == 'effective_budget':
        current['budget']['effective']['max_requests'] = 5
    elif change == 'other_model':
        current['model']['requested_model'] = 'different'
    else:
        case_digest = 'f' * 64
    with pytest.raises(ValueError):
        compare_manifest_baseline(config, 'intake', current, case_digest)


def test_phase_environment_strips_ambient_shaping_and_only_installs_declared_expectation(tmp_path, monkeypatch):
    config = manifest(tmp_path)
    monkeypatch.setenv('HARNESS_REAL_PROVIDER_STRICT_CLOSED_OUTPUT_TOOLS', 'true')
    assert 'HARNESS_REAL_PROVIDER_STRICT_CLOSED_OUTPUT_TOOLS' not in phase_environment(config, 'local')
    assert 'HARNESS_REAL_PROVIDER_STRICT_CLOSED_OUTPUT_TOOLS' not in phase_environment(config, 'direct')
    config = config.model_copy(update={'rerun': reviewed_output_rerun(tmp_path)})
    assert phase_environment(config, 'local')['HARNESS_REAL_PROVIDER_STRICT_CLOSED_OUTPUT_TOOLS'] == 'true'
    assert phase_environment(config, 'temporal')['HARNESS_REAL_PROVIDER_STRICT_CLOSED_OUTPUT_TOOLS'] == 'true'
    assert 'HARNESS_REAL_PROVIDER_STRICT_CLOSED_OUTPUT_TOOLS' not in phase_environment(config, 'direct')


def test_temporal_case_config_keeps_full_source_size_budget_comparison(tmp_path, monkeypatch):
    from copy import deepcopy

    from broker_real_provider_fixture import compare_baseline, temporal_case_config

    from infosec_harness.agents.budgets import BASELINE_SOURCE_FILES
    from infosec_harness.agents.durable import CONFIGS

    config = manifest(tmp_path)
    inputs, _, _, case_digest = prepare_case("recon", config)
    scoped = temporal_case_config("recon", inputs)
    assert scoped == CONFIGS["recon"].for_source_files(inputs["deps"].source_files)
    assert scoped.budget.source_files == inputs["deps"].source_files
    previous = scoped.model_dump(mode="json")
    previous["model"]["capability_profile"].pop("strict_closed_output_tools", None)
    rows = [{"agent": agent, "case": case, "case_digest": prepare_case(agent, config)[3],
             "config": previous} for agent, case in CASES.items()]
    path = tmp_path / "scoped-budget-baseline.json"
    path.write_text(json.dumps({"phase": "direct", "status": "passed", "cases": rows}))
    monkeypatch.setenv("HARNESS_REAL_PROVIDER_BASELINE", str(path))

    def candidate(value):
        current = deepcopy(value.model_dump(mode="json"))
        current["model"]["capability_profile"]["strict_closed_output_tools"] = True
        current["model"]["broker_contract"] = {"strict_closed_output_tools": True}
        return current

    assert compare_baseline("recon", candidate(scoped), case_digest,
                            reviewed_strict_closed_output_tools=True)["authored_budget"] == "matched"
    with pytest.raises(ValueError, match="Authored agent safety budget"):
        compare_baseline("recon", candidate(CONFIGS["recon"]), case_digest,
                         reviewed_strict_closed_output_tools=True)
    changed = CONFIGS["recon"].for_source_files(BASELINE_SOURCE_FILES * 4)
    assert changed.budget.effective != scoped.budget.effective
    with pytest.raises(ValueError, match="Authored agent safety budget"):
        compare_baseline("recon", candidate(changed), case_digest,
                         reviewed_strict_closed_output_tools=True)


def reviewed_temporal_only_rerun(tmp_path):
    from broker_real_provider_fixture import NativeRerunAmendment

    value = reviewed_output_rerun(tmp_path)
    base = manifest(tmp_path)
    previous = type(base).model_validate({**base.model_dump(), 'rerun': value.model_dump(),
        'broker_models_config': str(tmp_path / 'broker.yaml'), 'broker_config': str(tmp_path / 'catalog.yaml'),
        'maximum_pilot_agent_trials': 22, 'phases': ['native-local', 'native-temporal']})
    previous_path = tmp_path / 'passed-v3-manifest.json'
    previous_path.write_text(previous.model_dump_json())
    new = [hashlib.sha256(f'local-saved-{i}'.encode()).hexdigest() for i in range(40)]
    rows = [{'agent': agent, 'case': case, 'case_digest': prepare_case(agent, previous)[3],
             'execution': 'passed', 'semantic_score': 'passed', 'cleanup': 'passed',
             'ledger': {'requests': [{'request_id': identity, 'state': 'completed'} for identity in new[i::11]]}}
            for i, (agent, case) in enumerate(CASES.items())]
    local = tmp_path / 'local.json'
    local.write_text(json.dumps({'phase': 'local', 'status': 'passed', 'execution_status': 'passed',
                                'semantic_status': 'passed', 'cases': rows}))
    failed = tmp_path / 'temporal.json'
    failed.write_text(json.dumps({'status': 'failed', 'failure_type': 'ValueError'}))
    completed = value.retained_completed_request_ids + new
    proof = Path(value.ledger_proof_file)
    proof.write_text(json.dumps({'status': 'passed', 'unknown_request_ids': value.retained_unknown_request_ids,
                                'completed_request_ids': completed, 'unknown_holds_retained': True}))
    cause = Path(value.cause_resolution_file)
    cause.write_text(json.dumps({'status': 'passed', 'reviewed': True,
        'boundary': 'native-temporal-case-budget-preflight', 'evidence_sha256': 'a' * 64}))
    return NativeRerunAmendment.model_validate({**value.model_dump(), 'review_version': 4,
        'retained_completed_count': 120, 'retained_completed_request_ids': completed, 'additional_trials': 11,
        'prior_reports': {**value.prior_reports, str(local): hashlib.sha256(local.read_bytes()).hexdigest(),
                          str(failed): hashlib.sha256(failed.read_bytes()).hexdigest()},
        'retained_local_report_file': str(local), 'retained_local_report_sha256': hashlib.sha256(local.read_bytes()).hexdigest(),
        'retained_local_manifest_file': str(previous_path),
        'retained_local_manifest_sha256': hashlib.sha256(previous_path.read_bytes()).hexdigest(),
        'ledger_proof_sha256': hashlib.sha256(proof.read_bytes()).hexdigest(),
        'cause_resolution_sha256': hashlib.sha256(cause.read_bytes()).hexdigest(),
        'reason': 'reviewed case-scoped Temporal preflight correction; retain passed Local evidence and all outcomes; no unknown resend'})


def temporal_only_manifest(tmp_path):
    base = manifest(tmp_path)
    return type(base).model_validate({**base.model_dump(), 'rerun': reviewed_temporal_only_rerun(tmp_path).model_dump(),
        'broker_models_config': str(tmp_path / 'broker.yaml'), 'broker_config': str(tmp_path / 'catalog.yaml'),
        'maximum_pilot_agent_trials': 11, 'phases': ['native-temporal']})


def test_review4_verifies_exact_retained_local_and_empty_temporal_union(tmp_path):
    from broker_real_provider_fixture import verify_native_rerun
    config = temporal_only_manifest(tmp_path)
    verify_native_rerun(config.rerun)
    assert (len(config.rerun.prior_reports), len(config.rerun.retained_unknown_request_ids),
            len(config.rerun.retained_completed_request_ids)) == (14, 15, 120)
    assert (config.rerun.additional_trials, config.rerun.additional_graph_trials) == (11, 1)


@pytest.mark.parametrize('change', ['hash', 'execution', 'semantic', 'cleanup', 'case_digest', 'case', 'duplicate',
                                   'missing_failed', 'failed_has_case', 'failed_has_worker', 'previous_manifest_hash'])
def test_review4_rejects_bad_local_or_failed_temporal_provenance(tmp_path, change):
    from broker_real_provider_fixture import verify_native_rerun
    value = reviewed_temporal_only_rerun(tmp_path)
    if change == 'hash':
        value = value.model_copy(update={'retained_local_report_sha256': 'a' * 64})
    elif change == 'previous_manifest_hash':
        value = value.model_copy(update={'retained_local_manifest_sha256': 'a' * 64})
    elif change == 'missing_failed':
        reports = dict(value.prior_reports)
        reports.pop(str(tmp_path / 'temporal.json'))
        value = value.model_copy(update={'prior_reports': reports})
    elif change in ('failed_has_case', 'failed_has_worker'):
        path = tmp_path / 'temporal.json'
        report = json.loads(path.read_text())
        report['cases' if change == 'failed_has_case' else 'worker_pid'] = [{}] if change == 'failed_has_case' else 123
        path.write_text(json.dumps(report))
        value = value.model_copy(update={'prior_reports': {**value.prior_reports,
                                str(path): hashlib.sha256(path.read_bytes()).hexdigest()}})
    else:
        path = Path(value.retained_local_report_file)
        report = json.loads(path.read_text())
        if change == 'duplicate':
            report['cases'][1]['agent'] = report['cases'][0]['agent']
        else:
            report['cases'][0][{'semantic': 'semantic_score'}.get(change, change)] = 'failed'
        path.write_text(json.dumps(report))
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        value = value.model_copy(update={'retained_local_report_sha256': checksum,
                                'prior_reports': {**value.prior_reports, str(path): checksum}})
    with pytest.raises(ValueError):
        verify_native_rerun(value)


@pytest.mark.parametrize('change', [{'additional_trials': 22}, {'additional_graph_trials': 2},
    {'strict_closed_output_tools': False}, {'retained_completed_count': 119},
    {'retained_local_report_file': None}])
def test_review4_rejects_trial_count_and_retention_drift(tmp_path, change):
    value = reviewed_temporal_only_rerun(tmp_path)
    with pytest.raises(ValidationError):
        type(value).model_validate({**value.model_dump(), **change})


@pytest.mark.parametrize('change', [{'maximum_pilot_agent_trials': 22}, {'phases': ['native-local', 'native-temporal']},
                                  {'phases': ['native-local']}, {'phases': ['direct']}])
def test_review4_manifest_rejects_extra_or_wrong_phases(tmp_path, change):
    config = temporal_only_manifest(tmp_path)
    with pytest.raises(ValidationError):
        type(config).model_validate({**config.model_dump(), **change})


@pytest.mark.parametrize('factory', [native_rerun, reviewed_transport_rerun, reviewed_output_rerun])
def test_old_reviews_omit_and_reject_new_local_reuse_links(tmp_path, factory):
    value = factory(tmp_path)
    original = value.model_dump_json()
    assert not any(key.startswith('retained_local') for key in value.model_dump())
    assert type(value).model_validate(value.model_dump()).model_dump_json() == original
    with pytest.raises(ValidationError):
        type(value).model_validate({**value.model_dump(), 'retained_local_report_file': 'new'})


def test_review4_only_temporal_selection_and_claim_cannot_repeat(tmp_path):
    from broker_real_provider_fixture import claim_phase, selected_phases
    config = temporal_only_manifest(tmp_path)
    assert selected_phases(config, 'all') == selected_phases(config, 'temporal') == ('temporal',)
    assert selected_phases(config, 'validate') == ()
    for phase in ('direct', 'local'):
        with pytest.raises(ValueError, match='only a fresh Temporal'):
            selected_phases(config, phase)
    checksum = hashlib.sha256(config.model_dump_json().encode()).hexdigest()
    claim_phase(Path(config.report_directory), checksum, 'temporal')
    with pytest.raises(FileExistsError):
        claim_phase(Path(config.report_directory), checksum, 'temporal')


@pytest.mark.parametrize('phase', ['direct', 'local'])
def test_review4_runner_rejects_forbidden_phase_before_case_claim_or_child(tmp_path, monkeypatch, phase):
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location('temporal_only_runner', ROOT / 'scripts/broker_real_provider_check.py')
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    config = temporal_only_manifest(tmp_path)
    frozen = tmp_path / 'fresh.json'
    frozen.write_text(config.model_dump_json())
    def denied(*_args, **_kwargs):
        pytest.fail('Forbidden phase reached case preparation, claim or process construction')
    monkeypatch.setattr(runner, 'prepare_case', denied)
    monkeypatch.setattr(runner, 'claim_phase', denied)
    monkeypatch.setattr(runner.subprocess, 'Popen', denied)
    monkeypatch.setattr(sys, 'argv', ['runner', '--manifest', str(frozen), '--manifest-sha256',
        hashlib.sha256(frozen.read_bytes()).hexdigest(), '--phase', phase, '--allow-inference'])
    with pytest.raises(SystemExit) as error:
        runner.main()
    assert error.value.code == 2
    assert not list(tmp_path.glob('pilot-*')) and not (tmp_path / 'execution-claims').exists()


def test_review4_baseline_still_rejects_effective_budget_drift_and_reports_v4(tmp_path, monkeypatch):
    from broker_real_provider_fixture import compare_manifest_baseline
    config, current, case_digest = output_comparison_fixture(tmp_path, monkeypatch)
    config = config.model_copy(update={'rerun': reviewed_temporal_only_rerun(tmp_path)})
    result = compare_manifest_baseline(config, 'intake', current, case_digest)
    assert result['declared_output_shaping_difference']['review_version'] == 4
    current['budget']['effective']['max_requests'] = 5
    with pytest.raises(ValueError, match='Authored agent safety budget'):
        compare_manifest_baseline(config, 'intake', current, case_digest)


@pytest.mark.parametrize('class_name_alias', [False, True])
async def test_submission_recovery_uses_actual_registered_workflow_name(class_name_alias):
    from types import SimpleNamespace

    from broker_real_provider_fixture import recover_owned_submission
    from temporalio import workflow
    from test_broker_real_provider_temporal import RealProviderWorkflow

    definition = workflow._Definition.must_from_class(RealProviderWorkflow)
    assert definition.name == "BrokerRealProviderQualificationWorkflow"
    calls = []
    description = SimpleNamespace(id="batch:owned", task_queue="own-queue", run_id="own-run",
        workflow_type=RealProviderWorkflow.__name__ if class_name_alias else definition.name)
    async def describe():
        return description
    recovered = object()
    def get_handle(workflow_id, **kwargs):
        calls.append((workflow_id, kwargs))
        return recovered if kwargs else SimpleNamespace(describe=describe)
    client = SimpleNamespace(get_workflow_handle=get_handle)
    if class_name_alias:
        with pytest.raises(ValueError, match="ownership differs"):
            await recover_owned_submission(client, "batch:owned", "own-queue")
        assert len(calls) == 1
    else:
        assert await recover_owned_submission(client, "batch:owned", "own-queue") is recovered
        assert calls[-1] == ("batch:owned", {"run_id": "own-run", "first_execution_run_id": "own-run"})


@pytest.mark.parametrize('phase', ['direct', 'local'])
async def test_review4_internal_phase_entrypoint_rejects_forbidden_dispatch(tmp_path, monkeypatch, phase):
    from types import SimpleNamespace

    import broker_real_provider_fixture as fixture

    async def denied(*_args, **_kwargs):
        pytest.fail("Forbidden internal phase reached provider case body")
    monkeypatch.setattr(fixture, "run_local", denied)
    with pytest.raises(ValueError, match="only a fresh Temporal"):
        await fixture.phase_main(temporal_only_manifest(tmp_path), SimpleNamespace(phase=phase))


@pytest.mark.parametrize("agent", tuple(CASES))
def test_native_output_matcher_covers_all_current_agent_contracts(agent):
    from broker_real_provider_fixture import output_class

    from infosec_harness.agents.outputs import (
        ContextOutput,
        InconclusiveOutput,
        PartialEnvironmentOutput,
        PlannedEnvironmentOutput,
    )
    from infosec_harness.domain.models import (
        EnvironmentSpec,
        ExtractedFinding,
        ProbeDiagnosis,
        ProbePlan,
        ProbeSource,
        RepoProfile,
    )
    expected = {
        "intake": ExtractedFinding, "recon": RepoProfile,
        "env-planner": PlannedEnvironmentOutput, "build-repair": EnvironmentSpec,
        "partial-build": PartialEnvironmentOutput, "context": ContextOutput,
        "probe-planner": ProbePlan, "probe-author": ProbeSource,
        "probe-diagnosis": ProbeDiagnosis, "probe-repair": ProbeSource,
        "verdict": InconclusiveOutput,
    }
    assert set(expected) == set(CASES)
    assert output_class(agent) is expected[agent]


def test_native_env_planner_accepts_current_required_install_output():
    from infosec_harness.agents.outputs import PlannedEnvironmentOutput
    from infosec_harness.evals.adapters import _ecosystem_label

    output = PlannedEnvironmentOutput(base_image="python:3.12-slim", install_commands=[],
                                      test_command="python -m pytest {test_file}")
    result = score_output("env-planner", output, _ecosystem_label, "python/pytest")
    assert result["output_type"] == "PlannedEnvironmentOutput"
    assert result["semantic_score"] == "passed"
    assert result["expected"] == result["predicted"] == "python/pytest"
    assert result["typed_output"]["install_commands"] == []


def test_native_env_planner_rejects_legacy_domain_type_despite_equal_fields():
    from infosec_harness.domain.models import EnvironmentSpec
    from infosec_harness.evals.adapters import _ecosystem_label

    output = EnvironmentSpec(base_image="python:3.12-slim", install_commands=[],
                             test_command="python -m pytest {test_file}")
    with pytest.raises(ValueError, match="Registered output type differs"):
        score_output("env-planner", output, _ecosystem_label, "python/pytest")



def test_temporal_env_planner_reconstruction_preserves_required_install_contract():
    from broker_real_provider_fixture import output_class

    from infosec_harness.agents.outputs import PlannedEnvironmentOutput
    from infosec_harness.evals.adapters import _ecosystem_label

    serialized = {"base_image": "python:3.12-slim", "install_commands": [],
                  "test_command": "python -m pytest {test_file}"}
    output = output_class("env-planner").model_validate(serialized)
    assert type(output) is PlannedEnvironmentOutput
    assert "install_commands" in output.model_fields_set
    assert score_output("env-planner", output, _ecosystem_label,
                        "python/pytest")["semantic_score"] == "passed"
    incomplete = dict(serialized)
    del incomplete["install_commands"]
    with pytest.raises(ValidationError) as error:
        output_class("env-planner").model_validate(incomplete)
    assert [(entry["loc"], entry["type"]) for entry in error.value.errors()] == [
        (("install_commands",), "missing")]



@pytest.mark.parametrize("source_guidance", [None, False, True])
async def test_qualification_intake_input_pins_agent_and_accounting_generation(monkeypatch, source_guidance):
    import test_broker_real_provider_temporal as worker

    from infosec_harness.agents.durable import CONFIGS, INTAKE_GENERATIONS
    from infosec_harness.workflows.accounting import RootAccounting

    class AccountingObserved(Exception):
        pass

    selected = INTAKE_GENERATIONS["atomic" if source_guidance is True else "atomic_v3"]
    observed = []
    original_ops = worker.TemporalOps

    class ObservedOps(original_ops):
        async def run_agent(self, name, prompt, deps):
            assert self._agent_for(name) is selected.agent
            return await super().run_agent(name, prompt, deps)

    async def observe_reserve(self, config, *, configuration_digest=None):
        observed.append((config.digest, configuration_digest))
        raise AccountingObserved

    monkeypatch.setattr(worker, "TemporalOps", ObservedOps)
    monkeypatch.setattr(RootAccounting, "reserve", observe_reserve)
    inputs = {"agent": "intake", "prompt": ["synthetic input"], "deps": {"repo_path": "/snapshot"}}
    if source_guidance is not None:
        inputs["intake_source_guidance"] = source_guidance
    with pytest.raises(AccountingObserved):
        await worker.RealProviderWorkflow().run(inputs)
    assert observed == [(selected.config.digest, selected.config.digest)]
    assert (selected.config.digest == CONFIGS["intake"].digest) is (source_guidance is True)


@pytest.mark.parametrize("invalid", [1, "false", None, []])
async def test_qualification_intake_generation_rejects_nonboolean_before_accounting(monkeypatch, invalid):
    import test_broker_real_provider_temporal as worker

    def forbidden_ops(**_kwargs):
        raise AssertionError("Invalid generation must fail before accounting construction")

    monkeypatch.setattr(worker, "TemporalOps", forbidden_ops)
    with pytest.raises(ValueError, match="Intake source guidance must be a boolean"):
        await worker.RealProviderWorkflow().run({"intake_source_guidance": invalid})
