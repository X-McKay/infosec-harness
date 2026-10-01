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
    verify_retained_failure,
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
    if manifest.amendment:
        if args.phase == "direct" or args.baseline_report is None:
            parser.error("Corrected pilot permits only native phases and requires the original direct baseline")
        amendment = manifest.amendment
        baseline_manifest = args.baseline_report.parent / "manifest.json"
        if (hashlib.sha256(args.baseline_report.read_bytes()).hexdigest() != amendment.baseline_report_sha256
                or hashlib.sha256(baseline_manifest.read_bytes()).hexdigest() != amendment.original_manifest_sha256):
            parser.error("Corrected pilot baseline evidence differs")
        original = RealProviderManifest.model_validate_json(baseline_manifest.read_bytes())
        if (manifest.datasets != original.datasets or manifest.cases != original.cases
                or manifest.pricing != original.pricing):
            parser.error("Corrected pilot changed frozen cases, datasets or prices")
        baseline = json.loads(args.baseline_report.read_bytes())
        rows = baseline.get("cases", [])
        if (baseline.get("phase") != "direct" or baseline.get("status") != "passed"
                or len(rows) != 11 or {row["agent"] for row in rows} != set(CASES)
                or any(row["case"] != CASES[row["agent"]] or row["case_digest"] != prepare_case(row["agent"], original)[3]
                       for row in rows)):
            parser.error("Original direct baseline must cover every unchanged frozen case")
        try:
            verify_retained_failure(amendment)
        except ValueError as error:
            parser.error(str(error))
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
              "database_lifecycle_owner": "operator; evidence retained", "native_lifecycle_owner": "operator", "amendment": manifest.amendment.model_dump() if manifest.amendment else None}
    report_path = directory / "report.json"
    private_write(report_path, report)
    deadline = time.monotonic() + manifest.root_duration_seconds
    selected_phases = (("local", "temporal") if manifest.amendment else ("direct", "local", "temporal")) if args.phase == "all" else (args.phase,)
    for phase in selected_phases:
        values = phase_environment(manifest, phase)
        temporary_directory = directory / (phase + "-tmp")
        if not temporary_directory.resolve().is_relative_to(ROOT.resolve()):
            parser.error("Sandbox temporary files must be visible through the checkout mount")
        temporary_directory.mkdir(mode=0o700)
        values["TMPDIR"] = str(temporary_directory)
        report.setdefault("sandbox_temporary_directories", {})[phase] = str(temporary_directory)
        values["HARNESS_REAL_PROVIDER_MANIFEST"] = str(frozen_path)
        if phase != "direct":
            baseline_path = args.baseline_report if args.baseline_report else directory / "direct.json"
            baseline_copy = directory / "baseline.json"
            if not baseline_copy.exists():
                baseline_manifest = baseline_path.parent / "manifest.json"
                if (not baseline_manifest.is_file()
                        or hashlib.sha256(baseline_manifest.read_bytes()).hexdigest() != (
                            manifest.amendment.original_manifest_sha256 if manifest.amendment else manifest_sha)):
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
    expected_phases = len(selected_phases)
    report["status"] = "passed" if len(report["phases"]) == expected_phases and all(item["status"] == "passed" for item in report["phases"]) else "failed"
    private_write(report_path, report)
    print(json.dumps({"status": report["status"], "report": str(report_path)}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
