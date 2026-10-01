"""Two fresh LocalOps diagnostic invocations; never a qualification result."""
from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Literal

from broker_real_provider_fixture import (
    ROOT,
    RealProviderManifest,
    claim_phase,
    prepare_case,
    private_write,
    run_local_case,
    verify_native_rerun,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator

AGENTS = ('recon', 'partial-build')
SCOPE = 'observability correction; upstream/category and intake bound unresolved'
EXECUTOR_SOURCES = {
    'src/infosec_harness/agents/intake_schema.py',
    *(f'src/infosec_harness/inference/{name}.py' for name in
      ('auth', 'codec', 'compat', 'diagnostics', 'executor', 'http_service', 'protocol', 'timing')),
}


class NativeDiagnosticManifest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    version: Literal[1] = 1
    scope: Literal['native-local-diagnostic-only'] = 'native-local-diagnostic-only'
    qualification_status: Literal['not_checked'] = 'not_checked'
    agents: list[str] = Field(default_factory=lambda: list(AGENTS))
    maximum_trials: Literal[2] = 2
    concurrency: Literal[1] = 1
    case_wall_seconds: Literal[600] = 600
    candidate_manifest_file: str
    candidate_manifest_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    baseline_report_file: str
    source_proof_file: str
    source_proof_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    readiness_proof_file: str
    readiness_proof_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    evidence_scope: Literal['observability correction; upstream/category and intake bound unresolved'] = SCOPE
    report_directory: str

    @model_validator(mode='after')
    def exactly_two(self):
        if self.agents != list(AGENTS) or type(self.concurrency) is not int or type(self.version) is not int:
            raise ValueError('Diagnostics permit recon and partial-build once each in order')
        return self


def _read(path: str, expected: str):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('Diagnostic evidence differs from its frozen digest')
    return json.loads(data)


def verify_diagnostic(manifest: NativeDiagnosticManifest) -> RealProviderManifest:
    candidate = RealProviderManifest.model_validate(_read(
        manifest.candidate_manifest_file, manifest.candidate_manifest_sha256))
    if (candidate.rerun is None or candidate.rerun.review_version != 2
            or candidate.rerun.retained_unknown_count != 15 or candidate.rerun.retained_completed_count != 72
            or len(candidate.rerun.prior_reports) != 10
            or candidate.rerun.baseline_report_sha256 != "78eac315f11c52b8e3202b4d5cc595c57888d1107a2e5d2a4f63a6d404bd4ce5"):
        raise ValueError('Diagnostics must preserve the exact reviewed15unknown/72saved ten-report union')
    verify_native_rerun(candidate.rerun)
    baseline_path = Path(manifest.baseline_report_file)
    baseline = _read(str(baseline_path), candidate.rerun.baseline_report_sha256)
    original = RealProviderManifest.model_validate(_read(
        str(baseline_path.parent / 'manifest.json'), candidate.rerun.original_manifest_sha256))
    if (candidate.datasets != original.datasets or candidate.cases != original.cases
            or candidate.case_digests != original.case_digests or candidate.pricing != original.pricing
            or baseline.get('phase') != 'direct' or baseline.get('status') != 'passed'
            or len(baseline.get('cases', [])) != 11
            or {row['agent'] for row in baseline['cases']} != set(original.cases)):
        raise ValueError('Diagnostic baseline or frozen cases differ')
    for row in baseline['cases']:
        if row['case'] != original.cases[row['agent']] or row['case_digest'] != prepare_case(row['agent'], original)[3]:
            raise ValueError('Diagnostic baseline case evidence differs')
    for agent in AGENTS:
        prepare_case(agent, candidate)
    source = _read(manifest.source_proof_file, manifest.source_proof_sha256)
    readiness = _read(manifest.readiness_proof_file, manifest.readiness_proof_sha256)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if (candidate.source_commit != head or source.get('source_end_commit') != head
            or source.get('status') != 'passed' or source.get('provider_calls') != 0
            or source.get('image_source_unchanged_through_final_commit') is not True
            or source.get('native_readiness_proof_sha256') != manifest.readiness_proof_sha256
            or readiness.get('status') != 'passed' or readiness.get('registered_contracts') != 11
            or readiness.get('owned_test_leases_deleted') is not True
            or readiness.get('ledger_rows_before') != 87 or readiness.get('ledger_rows_after') != 87):
        raise ValueError('Fresh source/image/zero-inference readiness proof is required')
    hashes = source.get('executor_source_files_sha256', {})
    if set(hashes) != EXECUTOR_SOURCES or any(not path.startswith('src/infosec_harness/') or '..' in Path(path).parts
                         or hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != expected
                         for path, expected in hashes.items()):
        raise ValueError('Executor source differs from the qualified image')
    modules = source.get('loaded_module_sha256_start_end_equal', {})
    if set(modules) != {'controller.py', 'openshell.py'} or any(
            hashlib.sha256((ROOT / 'src/infosec_harness/inference' / name).read_bytes()).hexdigest() != expected
            for name, expected in modules.items()):
        raise ValueError('Controller source differs from readiness')
    observations = readiness.get('native_observations', {})
    if (set(observations) != set(original.cases) or any(
            item.get('state') != 'ready' or item.get('executor_image') != source.get('executor_image')
            for item in observations.values())):
        raise ValueError('Ready contracts differ from the diagnostic image')
    for phase in ('local', 'temporal'):
        if (Path(candidate.report_directory) / 'execution-claims' / f'{manifest.candidate_manifest_sha256}-{phase}.started').exists():
            raise ValueError('An executed qualification manifest cannot authorize diagnostics')
    if Path(manifest.report_directory).resolve() == Path(candidate.report_directory).resolve():
        raise ValueError('Diagnostic evidence must have a separate fresh directory')
    return candidate


def validate_native_config(manifest: NativeDiagnosticManifest, agent: str, config) -> None:
    """Refuse ambient direct fallback and require the entire verified native contract."""
    from infosec_harness.agents.models import load_models_config
    from infosec_harness.inference.protocol import BrokerError

    observed = _read(manifest.readiness_proof_file, manifest.readiness_proof_sha256)['native_observations'][agent]
    contract = config.model.broker_contract
    backend = load_models_config().backends[config.model.backend_name]
    if (backend.transport != 'brokered' or contract is None
            or contract.digest != observed['contract_digest']
            or contract.executor_image != observed['executor_image']
            or contract.supervisor_image != observed['supervisor_image']
            or contract.policy_digest != observed['policy_digest']
            or contract.profile != observed['profile']):
        raise BrokerError('policy', 'Diagnostic requires the exact verified native contract')


async def run_diagnostic_case(manifest: NativeDiagnosticManifest, manifest_sha: str,
                              agent: str, report_path: Path) -> dict:
    if agent not in AGENTS:
        raise ValueError('Unknown diagnostic case')
    candidate = verify_diagnostic(manifest)
    claim_phase(Path(manifest.report_directory) / agent, manifest_sha, 'local')
    report = {'scope': manifest.scope, 'qualification_status': 'not_checked', 'status': 'running',
              'evidence_scope': SCOPE, 'agent': agent, 'cases': []}
    def checkpoint(row):
        report['cases'].append(row)
        private_write(report_path, report)
    private_write(report_path, report)
    try:
        async with asyncio.timeout(manifest.case_wall_seconds):
            await run_local_case(candidate, 'local', agent, checkpoint=checkpoint,
                                 validate_config=lambda config: validate_native_config(manifest, agent, config))
        report['status'] = 'completed'
    except (Exception, asyncio.CancelledError) as error:
        report.update(status='failed', failure_type=type(error).__name__,
                      interrupted=isinstance(error, asyncio.CancelledError))
    finally:
        private_write(report_path, report)
    return report
