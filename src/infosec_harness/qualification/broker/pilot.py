"""Finite direct / native LocalOps / native Temporal real-provider qualification pilot.

The operator provisions native services and a private dedicated database separately. This
orchestrator never starts native lifecycle services and never deletes ledger evidence. Each
phase of a frozen manifest is claimed once and runs in its own reaped child process.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

from infosec_harness.qualification.broker.runner import phase_environment, prepare_case
from infosec_harness.qualification.broker.support import private_write, reap
from infosec_harness.qualification.broker.validators import (
    CASES,
    ROOT,
    SELECTOR_FOR_PHASE,
    RealProviderManifest,
    claim_phase,
    selected_phases,
    sha256_file,
    verify_baseline_report,
    verify_configuration,
    verify_source,
)


def run_phase(phase: str, frozen_path: Path, phase_path: Path, values: dict, deadline: float) -> dict:
    """Run one claimed phase child; it is always reaped before this returns."""
    log_path = phase_path.with_suffix(".log")
    process = None
    entry = {"phase": phase, "status": "failed"}
    try:
        with log_path.open("wb") as log:
            log_path.chmod(0o600)
            process = subprocess.Popen([sys.executable, "-m", "infosec_harness.qualification.broker.runner",
                SELECTOR_FOR_PHASE[phase], "--manifest", str(frozen_path), "--report", str(phase_path)],
                cwd=ROOT, env=values, stdout=log, stderr=log)
            entry["exit_code"] = process.wait(timeout=max(1, deadline - time.monotonic()))
        phase_report = json.loads(phase_path.read_text()) if phase_path.exists() else {}
        entry.update(status=phase_report.get("status", "failed"), report=str(phase_path))
    except subprocess.TimeoutExpired:
        entry["failure_type"] = "RootDeadlineExceeded"
    except KeyboardInterrupt:
        entry["failure_type"] = "QualificationInterrupted"
    finally:
        if process is not None:
            entry["child_reaped"] = reap(process, grace=20) if process.poll() is None else True
    return entry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True,
                        help="SHA256 of the reviewed manifest bytes; execution refuses any other bytes")
    parser.add_argument("--phase", choices=("validate", "direct", "local", "temporal", "all"), default="validate")
    parser.add_argument("--allow-inference", action="store_true")
    parser.add_argument("--baseline-report", type=Path,
                        help="direct.json from an earlier direct phase of this same frozen manifest")
    args = parser.parse_args(argv)
    manifest_bytes = args.manifest.read_bytes()
    manifest_sha = sha256_file(args.manifest)
    if manifest_sha != args.manifest_sha256:
        parser.error("Manifest differs from the explicitly frozen digest")
    manifest = RealProviderManifest.model_validate_json(manifest_bytes)
    try:
        phases = selected_phases(manifest, args.phase)
    except ValueError as error:
        parser.error(str(error))
    if args.phase != "validate" and not args.allow_inference:
        parser.error("Inference requires the explicit frozen-manifest handoff and --allow-inference")
    native = [phase for phase in phases if phase != "direct"]
    if native and "direct" not in phases and args.baseline_report is None:
        parser.error("Native phases require --baseline-report from this manifest's completed direct phase")
    if "direct" in phases and args.baseline_report is not None:
        parser.error("A run with a direct phase uses its own baseline; omit --baseline-report")
    if not Path(manifest.report_directory).resolve().is_relative_to(ROOT.resolve()):
        parser.error("Report directory must be inside the checkout so sandbox temporary files are guest-visible")
    try:
        verify_source(manifest)
        verify_configuration(manifest)
        cases = {agent: prepare_case(agent, manifest)[3] for agent in CASES}
        if args.baseline_report is not None:
            verify_baseline_report(manifest, manifest_sha, args.baseline_report, cases)
    except ValueError as error:
        parser.error(str(error))
    if args.phase == "validate":
        print(json.dumps({"status": "passed", "scope": "manifest, source, configuration and frozen cases only",
                          "case_digests": cases, "provider_calls": 0}, sort_keys=True))
        return 0
    directory = Path(manifest.report_directory) / ("pilot-" + uuid.uuid4().hex)
    directory.mkdir(parents=True, mode=0o700)
    frozen_path = directory / "manifest.json"
    frozen_path.write_bytes(manifest_bytes)
    frozen_path.chmod(0o400)
    report = {"manifest_sha256": manifest_sha, "status": "running", "case_digests": cases,
              "scope": "one frozen case per agent per selected phase", "provider": manifest.endpoint,
              "model": manifest.model, "phases": [], "database_lifecycle_owner": "operator; evidence retained",
              "native_lifecycle_owner": "operator"}
    report_path = directory / "report.json"
    private_write(report_path, report)
    deadline = time.monotonic() + manifest.root_duration_seconds
    for phase in phases:
        values = phase_environment(manifest, phase)
        temporary_directory = directory / (phase + "-tmp")
        temporary_directory.mkdir(mode=0o700)
        values["TMPDIR"] = str(temporary_directory)
        values["HARNESS_REAL_PROVIDER_MANIFEST"] = str(frozen_path)
        report.setdefault("sandbox_temporary_directories", {})[phase] = str(temporary_directory)
        if phase != "direct":
            baseline_copy = directory / "baseline.json"
            if not baseline_copy.exists():
                source = args.baseline_report or directory / "direct.json"
                baseline_copy.write_bytes(source.read_bytes())
                baseline_copy.chmod(0o400)
            values["HARNESS_REAL_PROVIDER_BASELINE"] = str(baseline_copy)
        claim_phase(Path(manifest.report_directory), manifest_sha, phase)
        entry = run_phase(phase, frozen_path, directory / f"{phase}.json", values, deadline)
        report["phases"].append(entry)
        private_write(report_path, report)
        if entry["status"] != "passed":
            break
    complete = [entry["phase"] for entry in report["phases"]] == list(phases)
    report["status"] = "passed" if complete and all(entry["status"] == "passed" for entry in report["phases"]) else "failed"
    private_write(report_path, report)
    print(json.dumps({"status": report["status"], "report": str(report_path)}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
