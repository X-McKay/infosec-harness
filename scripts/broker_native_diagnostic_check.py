#!/usr/bin/env python3
"""Exactly two fresh LocalOps diagnostics; no qualification or lifecycle authority."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import signal
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tests/runtime'))
from broker_native_diagnostic_fixture import (  # noqa: E402
    AGENTS,
    NativeDiagnosticManifest,
    _read,
    run_diagnostic_case,
    verify_diagnostic,
)
from broker_real_provider_fixture import (  # noqa: E402
    RealProviderManifest,
    claim_phase,
    phase_environment,
    private_write,
)


async def child(manifest, digest, agent, path):
    loop, task = asyncio.get_running_loop(), asyncio.current_task()
    for number in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(number, task.cancel)
    return await run_diagnostic_case(manifest, digest, agent, path)


def stop_owned(process):
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def install_child_environment(manifest):
    # Hash/schema parsing is pure: install before prepare_case can initialize runtime caches.
    candidate = RealProviderManifest.model_validate(_read(
        manifest.candidate_manifest_file, manifest.candidate_manifest_sha256))
    values = phase_environment(candidate, 'local')
    values['HARNESS_REAL_PROVIDER_BASELINE'] = manifest.baseline_report_file
    values['TMPDIR'] = str(Path(manifest.report_directory) / os.environ['IH_DIAGNOSTIC_CASE'] / 'tmp')
    for key in set(os.environ) - set(values):
        del os.environ[key]
    os.environ.update(values)


def verify_child_launch(manifest, digest, agent):
    directory = Path(manifest.report_directory)
    claim = directory / 'execution-claims' / f'{digest}-local.started'
    report = json.loads((directory / 'report.json').read_bytes())
    if (not claim.is_file() or report.get('scope') != manifest.scope
            or report.get('qualification_status') != 'not_checked' or report.get('status') != 'running'):
        raise ValueError('Diagnostic child requires its active frozen phase claim')
    rows = report.get('cases', [])
    if agent == AGENTS[0]:
        valid = rows == []
    else:
        prior = json.loads((directory / f'{AGENTS[0]}.json').read_bytes())
        valid = (len(rows) == 1 and rows[0].get('agent') == AGENTS[0]
                 and rows[0].get('child_reaped') is True and rows[0].get('status') == 'completed'
                 and prior.get('scope') == manifest.scope and prior.get('status') == 'completed'
                 and prior.get('qualification_status') == 'not_checked'
                 and len(prior.get('cases', [])) == 1 and prior['cases'][0].get('agent') == AGENTS[0]
                 and prior['cases'][0].get('broker_error_code') not in {'auth', 'identity', 'policy', 'expired', 'conflict'})
    if not valid:
        raise ValueError('Diagnostic child order or prior terminal evidence differs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--case', choices=AGENTS, help=argparse.SUPPRESS)
    args = parser.parse_args()
    data = args.manifest.read_bytes()
    if hashlib.sha256(data).hexdigest() != args.manifest_sha256:
        parser.error('Diagnostic manifest differs from the explicitly reviewed digest')
    manifest = NativeDiagnosticManifest.model_validate_json(data)
    if args.case is not None:
        if not args.execute:
            parser.error("A diagnostic child requires explicit execution")
        os.environ["IH_DIAGNOSTIC_CASE"] = args.case
        install_child_environment(manifest)
    candidate = verify_diagnostic(manifest)
    if not args.execute:
        print(json.dumps({'status': 'passed', 'scope': manifest.scope,
                          'qualification_status': 'not_checked', 'provider_calls': 0,
                          'maximum_trials': 2, 'agents': list(AGENTS)}))
        return 0
    directory = Path(manifest.report_directory)
    if args.case is not None:
        verify_child_launch(manifest, args.manifest_sha256, args.case)
        result = asyncio.run(child(manifest, args.manifest_sha256, args.case, directory / f'{args.case}.json'))
        return 0 if result['status'] == 'completed' else 1
    claim_phase(directory, args.manifest_sha256, 'local')
    report_path = directory / 'report.json'
    report = {'scope': manifest.scope, 'qualification_status': 'not_checked', 'status': 'running',
              'evidence_scope': manifest.evidence_scope, 'maximum_trials': 2, 'cases': []}
    private_write(report_path, report)
    values = phase_environment(candidate, 'local')
    values['HARNESS_REAL_PROVIDER_BASELINE'] = manifest.baseline_report_file
    def interrupted(_number, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    aborted = False
    for agent in AGENTS:
        path = directory / f'{agent}.json'
        temporary = directory / agent / 'tmp'
        temporary.mkdir(parents=True, exist_ok=True, mode=0o700)
        environment = {**values, 'TMPDIR': str(temporary)}
        process = None
        try:
            with (directory / f'{agent}.log').open('wb') as log:
                os.chmod(log.name, 0o600)
                process = subprocess.Popen([sys.executable, __file__, '--manifest', str(args.manifest),
                    '--manifest-sha256', args.manifest_sha256, '--execute', '--case', agent],
                    cwd=ROOT, env=environment, stdout=log, stderr=log, start_new_session=True)
                return_code = process.wait(timeout=manifest.case_wall_seconds + 45)
            result = json.loads(path.read_bytes()) if path.exists() else {'status': 'failed', 'cases': []}
            if (result.get('scope') != manifest.scope or result.get('qualification_status') != 'not_checked'
                    or len(result.get('cases', [])) != 1 or result['cases'][0].get('agent') != agent):
                raise ValueError('Diagnostic child did not retain its exact attempted case')
            report['cases'].append({'agent': agent, 'status': result['status'], 'exit_code': return_code,
                                    'report': str(path), 'child_reaped': process.poll() is not None})
            if result.get('interrupted') or result['cases'][0].get('broker_error_code') in {
                    'auth', 'identity', 'policy', 'expired', 'conflict'}:
                aborted = True
                report['status'] = 'failed'
                private_write(report_path, report)
                break
        except (Exception, KeyboardInterrupt) as error:
            if process is not None:
                stop_owned(process)
            report['cases'].append({'agent': agent, 'status': 'failed', 'failure_type': type(error).__name__,
                                    'report': str(path), 'child_reaped': process is None or process.poll() is not None})
            aborted = True
            report['status'] = 'failed'
            private_write(report_path, report)
            break
        private_write(report_path, report)
    report['status'] = ('completed' if not aborted and len(report['cases']) == 2 and all(
        row['status'] == 'completed' and row['child_reaped'] for row in report['cases']) else 'failed')
    private_write(report_path, report)
    print(json.dumps({'status': report['status'], 'scope': manifest.scope,
                      'qualification_status': 'not_checked', 'report': str(report_path)}))
    return 0 if report['status'] == 'completed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
