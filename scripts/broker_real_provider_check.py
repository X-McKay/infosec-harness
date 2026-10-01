#!/usr/bin/env python3
"""Finite direct/native-local/native-Temporal real-provider qualification pilot.

The operator provisions native services and a private dedicated database separately.
This runner neither starts native lifecycle services nor deletes ledger evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests/runtime"))
from broker_real_provider_fixture import (  # noqa: E402
    CASES,
    RealProviderManifest,
    phase_environment,
    prepare_case,
    private_write,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--phase", choices=("validate", "direct", "local", "temporal", "all"), default="validate")
    parser.add_argument("--allow-inference", action="store_true")
    parser.add_argument("--baseline-report", type=Path)
    parser.add_argument("--manifest-sha256", default="b41fb7a2bd695825bd2eff8b613f052e8c1319ad35bd053997c1a58cc1a20745")
    args = parser.parse_args()
    manifest_bytes = args.manifest.read_bytes()
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    if manifest_sha != args.manifest_sha256:
        parser.error("Manifest differs from the explicitly frozen digest")
    manifest = RealProviderManifest.model_validate_json(manifest_bytes)
    if args.phase != "validate" and not args.allow_inference:
        parser.error("Inference requires the explicit frozen-manifest handoff and --allow-inference")
    if args.phase in {"local", "temporal"} and args.baseline_report is None:
        parser.error("Native phases require --baseline-report from the completed direct pilot")
    cases = {agent: prepare_case(agent, manifest)[3] for agent in CASES}
    if args.phase == "validate":
        print(json.dumps({"status": "passed", "scope": "manifest and frozen cases only", "case_digests": cases,
                          "provider_calls": 0}, sort_keys=True))
        return 0
    directory = Path(manifest.report_directory) / ("pilot-" + uuid.uuid4().hex)
    directory.mkdir(parents=True, mode=0o700)
    frozen_path = directory / "manifest.json"
    frozen_path.write_bytes(manifest_bytes)
    frozen_path.chmod(0o400)
    report = {"manifest_sha256": manifest_sha, "status": "running", "scope": "11 frozen cases per selected phase", "case_digests": cases,
              "provider": manifest.endpoint, "model": manifest.model, "phases": [],
              "database_lifecycle_owner": "operator; evidence retained", "native_lifecycle_owner": "P4"}
    report_path = directory / "report.json"
    private_write(report_path, report)
    deadline = time.monotonic() + manifest.root_duration_seconds
    for phase in ("direct", "local", "temporal") if args.phase == "all" else (args.phase,):
        values = phase_environment(manifest, phase)
        values["HARNESS_REAL_PROVIDER_MANIFEST"] = str(frozen_path)
        if phase != "direct":
            baseline_path = args.baseline_report if args.baseline_report else directory / "direct.json"
            baseline_copy = directory / "baseline.json"
            if not baseline_copy.exists():
                baseline_manifest = baseline_path.parent / "manifest.json"
                if (not baseline_manifest.is_file()
                        or hashlib.sha256(baseline_manifest.read_bytes()).hexdigest() != manifest_sha):
                    parser.error("Baseline manifest/dataset provenance differs from the frozen pilot")
                baseline_copy.write_bytes(baseline_path.read_bytes())
                baseline_copy.chmod(0o400)
            values["HARNESS_REAL_PROVIDER_BASELINE"] = str(baseline_copy)
        phase_path = directory / f"{phase}.json"
        log_path = directory / f"{phase}.log"
        with log_path.open("wb") as log:
            log_path.chmod(0o600)
            try:
                process = subprocess.Popen([sys.executable, str(ROOT / "tests/runtime/broker_real_provider_fixture.py"),
                    phase, "--manifest", str(frozen_path), "--report", str(phase_path)],
                    cwd=ROOT, env=values, stdout=log, stderr=log, start_new_session=True)
                return_code = process.wait(timeout=max(1, deadline - time.monotonic()))
                phase_report = json.loads(phase_path.read_text()) if phase_path.exists() else {"status": "failed"}
                report["phases"].append({"phase": phase, "exit_code": return_code,
                    "status": phase_report.get("status", "failed"), "report": str(phase_path)})
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                report["phases"].append({"phase": phase, "status": "failed", "failure_type": "RootDeadlineExceeded"})
                break
        private_write(report_path, report)
    expected_phases = 3 if args.phase == "all" else 1
    report["status"] = "passed" if len(report["phases"]) == expected_phases and all(item["status"] == "passed" for item in report["phases"]) else "failed"
    private_write(report_path, report)
    print(json.dumps({"status": report["status"], "report": str(report_path)}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
