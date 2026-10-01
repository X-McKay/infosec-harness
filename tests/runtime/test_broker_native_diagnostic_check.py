"""Offline checks for bounded diagnostics that never qualify native execution."""
from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import broker_native_diagnostic_fixture as diagnostic
import broker_real_provider_fixture as fixture
import pytest
from pydantic import ValidationError
from test_broker_real_provider_check import manifest, native_rerun

from infosec_harness.inference.protocol import BrokerError


def runner():
    spec = importlib.util.spec_from_file_location('native_diagnostic_runner', fixture.ROOT / 'scripts/broker_native_diagnostic_check.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def minimal(tmp_path):
    return diagnostic.NativeDiagnosticManifest(candidate_manifest_file=str(tmp_path / 'candidate.json'),
        candidate_manifest_sha256='a' * 64, baseline_report_file=str(tmp_path / 'baseline.json'),
        source_proof_file=str(tmp_path / 'source.json'), source_proof_sha256='b' * 64,
        readiness_proof_file=str(tmp_path / 'ready.json'), readiness_proof_sha256='c' * 64,
        report_directory=str(tmp_path / 'diagnostic'))


@pytest.mark.parametrize('changes', [dict(agents=['partial-build', 'recon']), dict(agents=['recon']),
    dict(maximum_trials=3), dict(concurrency=2), dict(case_wall_seconds=601),
    dict(qualification_status='passed'), dict(scope='native-temporal')])
def test_diagnostic_scope_cannot_promote_expand_or_reorder(tmp_path, changes):
    with pytest.raises(ValidationError):
        diagnostic.NativeDiagnosticManifest.model_validate({**minimal(tmp_path).model_dump(), **changes})


def proof_fixture(tmp_path, monkeypatch):
    original = manifest(tmp_path)
    rerun = native_rerun(tmp_path)
    unknown = [hashlib.sha256(f'unknown-{i}'.encode()).hexdigest() for i in range(15)]
    completed = [hashlib.sha256(f'completed-{i}'.encode()).hexdigest() for i in range(72)]
    rows = [{'request_id': identity, 'state': state} for state, ids in
            [('completion_unknown', unknown), ('completed', completed)] for identity in ids]
    reports = {}
    for i in range(10):
        p = tmp_path / f'prior-{i}.json'
        p.write_text(json.dumps({'ledger': {'requests': rows[i::10]}}))
        reports[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
    ledger = Path(rerun.ledger_proof_file)
    ledger.write_text(json.dumps({'status': 'passed', 'unknown_request_ids': unknown,
        'completed_request_ids': completed, 'unknown_holds_retained': True}))
    cause = Path(rerun.cause_resolution_file)
    cause.write_text(json.dumps({'status': 'passed', 'reviewed': True,
        'boundary': 'native-response-acknowledgement', 'evidence_sha256': 'd' * 64}))
    rerun = type(rerun).model_validate({**rerun.model_dump(), 'review_version': 2,
        'retained_unknown_count': 15, 'retained_completed_count': 72,
        'retained_unknown_request_ids': unknown, 'retained_completed_request_ids': completed,
        'prior_reports': reports, 'ledger_proof_sha256': hashlib.sha256(ledger.read_bytes()).hexdigest(),
        'cause_resolution_sha256': hashlib.sha256(cause.read_bytes()).hexdigest(),
        'baseline_report_sha256': '78eac315f11c52b8e3202b4d5cc595c57888d1107a2e5d2a4f63a6d404bd4ce5',
        'reason': 'reviewed native transport correction; retain all outcomes; no unknown resend'})
    candidate = fixture.RealProviderManifest.model_validate({**original.model_dump(), 'rerun': rerun.model_dump(),
        'source_commit': '1' * 40, 'broker_models_config': str(tmp_path / 'broker.yaml'),
        'broker_config': str(tmp_path / 'catalog.yaml'), 'report_directory': str(tmp_path / 'qualification'),
        'maximum_pilot_agent_trials': 22, 'phases': ['native-local', 'native-temporal']})
    m = minimal(tmp_path)
    source = {'status': 'passed', 'provider_calls': 0, 'source_end_commit': '1' * 40,
        'image_source_unchanged_through_final_commit': True, 'native_readiness_proof_sha256': m.readiness_proof_sha256,
        'executor_image': 'sha256:' + 'e' * 64,
        'executor_source_files_sha256': {p: hashlib.sha256((fixture.ROOT / p).read_bytes()).hexdigest()
                                       for p in diagnostic.EXECUTOR_SOURCES},
        'loaded_module_sha256_start_end_equal': {p: hashlib.sha256((fixture.ROOT / 'src/infosec_harness/inference' / p).read_bytes()).hexdigest()
                                                for p in ['controller.py', 'openshell.py']}}
    readiness = {'status': 'passed', 'registered_contracts': 11, 'owned_test_leases_deleted': True,
        'ledger_rows_before': 87, 'ledger_rows_after': 87,
        'native_observations': {agent: {'state': 'ready', 'executor_image': source['executor_image']}
                                for agent in fixture.CASES}}
    baseline = {'phase': 'direct', 'status': 'passed', 'cases': [{'agent': agent, 'case': case,
        'case_digest': fixture.prepare_case(agent, original)[3]} for agent, case in fixture.CASES.items()]}
    # Immutable historical hashes are operator pins, not regenerated test data.
    pinned = {m.candidate_manifest_file: candidate.model_dump(mode='json'),
        m.baseline_report_file: baseline, str(Path(m.baseline_report_file).parent / 'manifest.json'): original.model_dump(mode='json'),
        m.source_proof_file: source, m.readiness_proof_file: readiness}
    monkeypatch.setattr(diagnostic, '_read', lambda path, _expected: pinned[path])
    monkeypatch.setattr(diagnostic.subprocess, 'check_output', lambda *_a, **_k: '1' * 40)
    return m, candidate, source, readiness, pinned


def test_exact_retained_union_fresh_source_and_readiness_are_required(tmp_path, monkeypatch):
    m, candidate, _source, _ready, _pins = proof_fixture(tmp_path, monkeypatch)
    assert diagnostic.verify_diagnostic(m).rerun.retained_unknown_request_ids == candidate.rerun.retained_unknown_request_ids
    path = Path(next(iter(candidate.rerun.prior_reports)))
    content = json.loads(path.read_bytes())
    content['ledger']['requests'].pop()
    path.write_text(json.dumps(content))
    with pytest.raises(ValueError, match='retained evidence differs'):
        diagnostic.verify_diagnostic(m)


@pytest.mark.parametrize('mutation', ['missing_source', 'wrong_source', 'not_ready', 'wrong_image', 'pending_ledger', 'source_commit'])
def test_source_and_readiness_negatives_prevent_execution(tmp_path, monkeypatch, mutation):
    m, _candidate, source, ready, _pins = proof_fixture(tmp_path, monkeypatch)
    if mutation == 'missing_source':
        source['executor_source_files_sha256'].pop(next(iter(diagnostic.EXECUTOR_SOURCES)))
    elif mutation == 'wrong_source':
        source['executor_source_files_sha256'][next(iter(diagnostic.EXECUTOR_SOURCES))] = '0' * 64
    elif mutation == 'not_ready':
        ready['native_observations']['recon']['state'] = 'quarantined'
    elif mutation == 'wrong_image':
        ready['native_observations']['recon']['executor_image'] = 'sha256:' + '0' * 64
    elif mutation == 'pending_ledger':
        ready['ledger_rows_after'] = 88
    else:
        source['source_end_commit'] = '0' * 40
    with pytest.raises(ValueError):
        diagnostic.verify_diagnostic(m)
    assert not Path(m.report_directory).exists()


async def test_cancelled_case_retains_checkpoint_cleanup_and_ledger(tmp_path, monkeypatch):
    from infosec_harness.agents import registry
    from infosec_harness.graph import ops

    m = minimal(tmp_path)
    candidate = manifest(tmp_path)
    entered = asyncio.Event()
    calls = []

    class OwnedOps:
        _broker_run_id = 'fresh-offline-owned-run'
        def __init__(self, **_kwargs):
            pass
        async def run_agent(self, agent, *_args):
            calls.append(agent)
            entered.set()
            await asyncio.Future()
        async def close(self):
            calls.append('cleanup')

    async def snapshot(_root):
        calls.append('ledger')
        return {'request_states': {'completion_unknown': 1}}

    monkeypatch.setattr(ops, 'LocalOps', OwnedOps)
    monkeypatch.setattr(fixture, 'prepare_case', lambda agent, _m: ({'deps': SimpleNamespace(source_files=[]), 'prompt': []}, None, None, 'f' * 64))
    monkeypatch.setattr(registry, 'load_spec', lambda _agent: None)
    config = SimpleNamespace(model=SimpleNamespace(endpoint=candidate.endpoint), model_dump=lambda **_kw: {})
    monkeypatch.setattr(registry, 'resolve_agent_config', lambda *_a, **_k: config)
    monkeypatch.setattr(fixture, 'compare_baseline', lambda *_a: {})
    monkeypatch.setattr(fixture, 'ledger_snapshot', snapshot)
    monkeypatch.setattr(diagnostic, 'verify_diagnostic', lambda _m: candidate)
    monkeypatch.setattr(diagnostic, 'validate_native_config', lambda *_a: None)
    path = tmp_path / 'case.json'
    task = asyncio.create_task(diagnostic.run_diagnostic_case(m, 'a' * 64, 'recon', path))
    await entered.wait()
    task.cancel()
    result = await task
    assert calls == ['recon', 'cleanup', 'ledger']
    assert result['status'] == 'failed' and result['interrupted'] is True
    assert result['qualification_status'] == 'not_checked'
    assert len(result['cases']) == 1
    assert result['cases'][0]['failure_type'] == 'CancelledError'
    assert result['cases'][0]['cleanup'] == 'passed'
    assert result['cases'][0]['ledger']['request_states'] == {'completion_unknown': 1}
    assert json.loads(path.read_bytes()) == result
    with pytest.raises(FileExistsError):
        await diagnostic.run_diagnostic_case(m, 'a' * 64, 'recon', path)
    assert calls == ['recon', 'cleanup', 'ledger']


@pytest.mark.parametrize('wrong', ['direct', 'digest', 'image', 'supervisor', 'policy', 'profile', 'missing'])
def test_wrong_native_contract_fails_before_provider(tmp_path, monkeypatch, wrong):
    from infosec_harness.agents import models

    m = minimal(tmp_path)
    expected = dict(contract_digest='digest', executor_image='image', supervisor_image='supervisor', policy_digest='policy', profile='profile')
    monkeypatch.setattr(diagnostic, '_read', lambda *_a: {'native_observations': {'recon': expected}})
    backend = SimpleNamespace(transport='direct' if wrong == 'direct' else 'brokered')
    monkeypatch.setattr(models, 'load_models_config', lambda: SimpleNamespace(backends={'selected': backend}))
    values = dict(digest='digest', executor_image='image', supervisor_image='supervisor', policy_digest='policy', profile='profile')
    if wrong in values:
        values[wrong] = 'different'
    elif wrong == 'image':
        values['executor_image'] = 'different'
    elif wrong == 'supervisor':
        values['supervisor_image'] = 'different'
    elif wrong == 'policy':
        values['policy_digest'] = 'different'
    config = SimpleNamespace(model=SimpleNamespace(backend_name='selected', broker_contract=None if wrong == 'missing' else SimpleNamespace(**values)))
    with pytest.raises(BrokerError, match='policy'):
        diagnostic.validate_native_config(m, 'recon', config)


def test_child_requires_global_claim_order_and_reaped_prior_case(tmp_path):
    module = runner()
    m = minimal(tmp_path)
    directory = Path(m.report_directory)
    fixture.claim_phase(directory, 'a' * 64, 'local')
    report = {'scope': m.scope, 'qualification_status': 'not_checked', 'status': 'running', 'cases': []}
    fixture.private_write(directory / 'report.json', report)
    module.verify_child_launch(m, 'a' * 64, 'recon')
    with pytest.raises((ValueError, FileNotFoundError)):
        module.verify_child_launch(m, 'a' * 64, 'partial-build')
    report['cases'] = [{'agent': 'recon', 'child_reaped': True, 'status': 'completed'}]
    fixture.private_write(directory / 'report.json', report)
    prior = {'scope': m.scope, 'status': 'completed', 'qualification_status': 'not_checked', 'cases': [{'agent': 'recon'}]}
    fixture.private_write(directory / 'recon.json', prior)
    module.verify_child_launch(m, 'a' * 64, 'partial-build')
    prior['cases'][0]['broker_error_code'] = 'policy'
    fixture.private_write(directory / 'recon.json', prior)
    with pytest.raises(ValueError):
        module.verify_child_launch(m, 'a' * 64, 'partial-build')
    with pytest.raises(FileExistsError):
        fixture.claim_phase(directory, 'a' * 64, 'local')


@pytest.mark.parametrize('first_outcome,second_code,expected_count', [('success', None, 2),
    ('cancelled', None, 1), ('policy', None, 1), ('success', 'policy', 2)])
def test_wrapper_preserves_two_case_limit_interruption_and_never_qualifies(tmp_path, monkeypatch, first_outcome, second_code, expected_count):
    module = runner()
    m = minimal(tmp_path)
    candidate = manifest(tmp_path)
    path = tmp_path / 'diagnostic-manifest.json'
    path.write_text(m.model_dump_json())
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(sys, 'argv', ['runner', '--manifest', str(path), '--manifest-sha256', digest, '--execute'])
    monkeypatch.setattr(module, 'verify_diagnostic', lambda _m: candidate)
    monkeypatch.setattr(module, 'phase_environment', lambda *_a: {})
    monkeypatch.setattr(module.signal, 'signal', lambda *_a: None)
    children = []
    waits = []

    class Child:
        pid = 12345
        def __init__(self, argv, **_kwargs):
            agent = argv[-1]
            children.append(agent)
            cancelled = agent == 'recon' and first_outcome == 'cancelled'
            code = ('policy' if first_outcome == 'policy' else None) if agent == 'recon' else second_code
            result = {'scope': m.scope, 'qualification_status': 'not_checked',
                'status': 'failed' if cancelled else 'completed', 'interrupted': cancelled,
                'cases': [{'agent': agent, 'broker_error_code': code, 'cleanup': 'passed', 'ledger': {}}]}
            fixture.private_write(Path(m.report_directory) / f'{agent}.json', result)
        def wait(self, timeout):
            waits.append(timeout)
            return 0
        def poll(self):
            return 0

    monkeypatch.setattr(module.subprocess, 'Popen', Child)
    expected = 0 if first_outcome == 'success' and second_code is None else 1
    assert module.main() == expected
    assert children == list(diagnostic.AGENTS)[:expected_count]
    assert waits == [645] * expected_count
    report = json.loads((Path(m.report_directory) / 'report.json').read_bytes())
    assert report['qualification_status'] == 'not_checked'
    assert report['status'] == ('completed' if expected == 0 else 'failed')
    assert len(report['cases']) == expected_count
    with pytest.raises(FileExistsError):
        module.main()
    assert len(children) == expected_count


async def test_ambient_direct_configuration_rejected_before_production_ops_run(tmp_path, monkeypatch):
    from infosec_harness.agents import models, registry
    from infosec_harness.graph import ops

    m = minimal(tmp_path)
    candidate = manifest(tmp_path)
    sends = []
    closed = []
    class OwnedOps:
        _broker_run_id = 'fresh-offline-policy-rejection'
        def __init__(self, **_kwargs):
            pass
        async def run_agent(self, *_args):
            sends.append('provider')
            raise AssertionError('direct fallback must never be invoked')
        async def close(self):
            closed.append('closed')
    async def snapshot(_root):
        return {'requests': []}
    monkeypatch.setattr(ops, 'LocalOps', OwnedOps)
    monkeypatch.setattr(fixture, 'prepare_case', lambda *_a: ({'deps': SimpleNamespace(source_files=[]), 'prompt': []}, None, None, 'f' * 64))
    monkeypatch.setattr(registry, 'load_spec', lambda _agent: None)
    config = SimpleNamespace(model=SimpleNamespace(endpoint=candidate.endpoint, backend_name='ambient', broker_contract=None))
    monkeypatch.setattr(registry, 'resolve_agent_config', lambda *_a, **_k: config)
    monkeypatch.setattr(models, 'load_models_config', lambda: SimpleNamespace(backends={'ambient': SimpleNamespace(transport='direct')}))
    monkeypatch.setattr(diagnostic, '_read', lambda *_a: {'native_observations': {'recon': {}}})
    monkeypatch.setattr(fixture, 'ledger_snapshot', snapshot)
    rows = []
    await fixture.run_local_case(candidate, 'local', 'recon', checkpoint=rows.append,
        validate_config=lambda cfg: diagnostic.validate_native_config(m, 'recon', cfg))
    assert sends == [] and closed == ['closed']
    assert len(rows) == 1 and rows[0]['broker_error_code'] == 'policy'
    assert rows[0]['cleanup'] == 'passed' and rows[0]['ledger'] == {'requests': []}


def test_fresh_child_bootstrap_first_runtime_load_uses_broker_candidate_without_network(tmp_path):
    candidate = manifest(tmp_path)
    broker = tmp_path / 'broker-bootstrap.yaml'
    broker.write_text("backends:\n  verified:\n    transport: brokered\n    kind: openai_compatible\n    base_url: https://provider.invalid/v1\n    max_retries: 0\n    max_retries_under_temporal: 0\ndefault_backend: verified\nmodel_catalog: {}\n")
    candidate = candidate.model_copy(update={'broker_models_config': str(broker)})
    candidate_path = tmp_path / 'candidate-bootstrap.json'
    candidate_path.write_text(candidate.model_dump_json())
    m = minimal(tmp_path).model_copy(update={'candidate_manifest_file': str(candidate_path),
        'candidate_manifest_sha256': hashlib.sha256(candidate_path.read_bytes()).hexdigest()})
    path = tmp_path / 'diagnostic-bootstrap.json'
    path.write_text(m.model_dump_json())
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    script = r"""
import importlib.util,json,socket,sys
from pathlib import Path
calls=[]
def forbidden(*_args,**_kwargs):
 calls.append('network')
 raise AssertionError('bootstrap must not open a connection')
socket.socket.connect=forbidden
spec=importlib.util.spec_from_file_location('fresh_runner',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
assert 'infosec_harness.settings' not in sys.modules
manifest_path,digest=sys.argv[2:4]
order=[]
def verify(manifest):
 order.append('verify')
 from infosec_harness.settings import get_settings
 from infosec_harness.agents.models import load_models_config
 candidate=module.RealProviderManifest.model_validate_json(Path(manifest.candidate_manifest_file).read_bytes())
 settings=get_settings();models=load_models_config()
 assert settings.models_config==Path(candidate.broker_models_config)
 assert settings.model_mode=='live'
 assert models.default_backend=='verified' and models.backends['verified'].transport=='brokered'
 assert module.os.environ['HARNESS_BROKER_CONFIG']==candidate.broker_config
 assert module.os.environ['HARNESS_REAL_PROVIDER_BASELINE']==manifest.baseline_report_file
 assert 'HARNESS_MODEL_BACKEND' not in module.os.environ
 assert 'HARNESS_BROKER_NATIVE_CONFIG' not in module.os.environ
 return candidate
async def child(*_args):
 order.append('child')
 return {'status':'completed','qualification_status':'not_checked'}
module.verify_diagnostic=verify
module.verify_child_launch=lambda *_args:order.append('launch_guard')
module.child=child
sys.argv=['runner','--manifest',manifest_path,'--manifest-sha256',digest,'--execute','--case','recon']
assert module.main()==0
assert order==['verify','launch_guard','child'] and calls==[]
print(json.dumps({'status':'passed','network_calls':0,'qualification_status':'not_checked'}))
"""
    env = dict(os.environ, PYTHONPATH=os.pathsep.join((str(fixture.ROOT / 'src'), str(fixture.ROOT / 'tests/runtime'))),
        HARNESS_MODEL_MODE='stub', HARNESS_MODELS_CONFIG='hostile-missing-direct.yaml',
        HARNESS_MODEL_BACKEND='hostile-direct', HARNESS_BROKER_NATIVE_CONFIG='private-admin-never-forwarded')
    result = subprocess.run([sys.executable, '-c', script, str(fixture.ROOT / 'scripts/broker_native_diagnostic_check.py'),
        str(path), digest], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {'status': 'passed', 'network_calls': 0, 'qualification_status': 'not_checked'}
