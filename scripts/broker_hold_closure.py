#!/usr/bin/env python3
"""Explicit operator loss acceptance; no inference, recovery dispatch or lease changes."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field
from service_validation import output_path

from infosec_harness.api.evidence_io import read_bytes, reject_duplicate_fields
from infosec_harness.persistence.reconciliation import ClosureRequest, close_unknown, plan_closure
from infosec_harness.settings import get_settings


class Reference(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    file: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class ClosureManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: int = Field(ge=1, le=1)
    source_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    evidence: dict[str, Reference]
    operations: list[ClosureRequest] = Field(min_length=1, max_length=100)


def frozen_manifest(path: Path, expected_sha256: str) -> ClosureManifest:
    content = read_bytes(path)
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise ValueError("Manifest bytes changed")
    manifest = ClosureManifest.model_validate(
        json.loads(content, object_pairs_hook=reject_duplicate_fields)
    )
    if manifest.source_commit != get_settings().git_commit_sha:
        raise ValueError("Configured source differs")
    evidence = {}
    for name, ref in manifest.evidence.items():
        data = read_bytes(Path(ref.file))
        if hashlib.sha256(data).hexdigest() != ref.sha256:
            raise ValueError("Evidence bytes changed")
        evidence[name] = ref.sha256
    if not evidence:
        raise ValueError("Evidence required")
    identities = [(op.root_id, op.operation_id) for op in manifest.operations]
    if len(set(identities)) != len(identities):
        raise ValueError("Duplicate operation")
    if len({op.root_id for op in manifest.operations}) != len(manifest.operations):
        raise ValueError(
            "Use one operation per root per manifest; explicitly replan further operations"
        )
    for op in manifest.operations:
        if op.source_commit != manifest.source_commit or op.evidence_sha256 != evidence:
            raise ValueError("Authorization differs from frozen evidence")
    return manifest


async def execute(manifest: ClosureManifest, *, apply: bool) -> dict:
    # Verify the whole allowlist before any accounting write. A raced root still fails
    # its transaction CAS; already-applied operations can be repeated with identical audit.
    planned = [await plan_closure(op) for op in manifest.operations]
    report = {
        "version": 1,
        "status": "passed",
        "source_commit": manifest.source_commit,
        "mode": "apply" if apply else "dry_run",
        "operations": planned,
        "provider_calls": 0,
        "request_row_mutations": 0,
        "lease_mutations": 0,
        "qualification": "not_checked",
    }
    if not apply:
        return report
    results = []
    for op in manifest.operations:
        try:
            results.append(await close_unknown(op))
        except Exception:
            report.update(
                status="failed",
                operations=results,
                partial_application=True,
                detail="Closure stopped; inspect retained audit and explicitly replan remaining operations.",
            )
            return report
    report["operations"] = results
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Explicitly accept unknown outcomes and charge full reservations.",
    )
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    claim = temporary = None
    execution_started = False
    report = {
        "version": 1,
        "status": "failed",
        "detail": "Frozen closure preflight failed; no implicit retry.",
        "provider_calls": 0,
        "qualification": "not_checked",
    }
    try:
        destination = output_path(args.report)
        if destination.exists() or destination == args.manifest.absolute():
            raise ValueError("Report must be a fresh distinct path")
        destination.parent.mkdir(parents=True, exist_ok=True)
        claim_path = destination.with_name("." + destination.name + ".claim")
        descriptor = os.open(claim_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        claim = claim_path
        descriptor, name = tempfile.mkstemp(prefix=".closure-", dir=destination.parent)
        temporary = Path(name)
        # Establish actual private file creation/write/fsync before accounting mutation.
        with os.fdopen(descriptor, "w") as stream:
            stream.write('{"status":"preflight"}\n')
            stream.flush()
            os.fsync(stream.fileno())
        manifest = frozen_manifest(args.manifest, args.manifest_sha256)
        execution_started = True
        report = asyncio.run(execute(manifest, apply=args.apply))
    except Exception:
        report["accounting_may_have_been_applied"] = bool(args.apply and execution_started)
    try:
        if temporary is None:
            raise ValueError("Output was not reserved")
        with temporary.open("w") as stream:
            json.dump(report, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        # Hard-link publication is atomic and exclusive; a raced report is never replaced.
        output_path(args.report)
        os.link(temporary, args.report.absolute())
        temporary.unlink()
        temporary = None
    except (OSError, ValueError):
        report.update(
            status="failed",
            detail="Private report publication failed; inspect persisted closure audits before any retry.",
            accounting_may_have_been_applied=bool(args.apply and execution_started),
            retained_report_file=str(temporary) if temporary else None,
        )
    finally:
        if claim is not None:
            claim.unlink(missing_ok=True)
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
