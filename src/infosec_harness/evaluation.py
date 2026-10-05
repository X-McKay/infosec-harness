"""One frozen end-to-end corpus, through the production Temporal workflow."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import yaml
from pydantic import BaseModel, ConfigDict, Field
from temporalio.common import WorkflowIDReusePolicy

from infosec_harness._io import write_json
from infosec_harness.config import get_settings
from infosec_harness.identity import worker_identity
from infosec_harness.models import Finding, InvestigationRequest, InvestigationResult
from infosec_harness.openshell import OpenShellConfig, native_operation_accounting
from infosec_harness.process import _finish
from infosec_harness.web import PREFIX, RPC_TIMEOUT, WORKFLOW, connect, execution_timeout


class ReleasePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    minimum_task_success_rate: float = Field(ge=0, le=1)
    maximum_unsafe_negatives: int = Field(ge=0)


def release_policy() -> tuple[ReleasePolicy, str]:
    data = Path(__file__).with_name("release-policy.yaml").read_bytes()
    return ReleasePolicy.model_validate(yaml.safe_load(data)), hashlib.sha256(data).hexdigest()


def source_identity() -> str:
    # Qualification is checkout-owned. Caller directories and Git configuration are untrusted.
    root = Path(__file__).resolve().parents[2]
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "LC_ALL": "C",
    }
    git = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"]

    def read(*args):
        return subprocess.check_output([*git, *args], text=True, cwd=root, env=env).strip()

    if Path(read("rev-parse", "--show-toplevel")).resolve() != root:
        raise ValueError("Qualification requires the harness source checkout")
    if read("status", "--porcelain", "--untracked-files=normal"):
        raise ValueError("Qualification requires a clean committed source tree")
    return read("rev-parse", "HEAD")


def corpus_cases(manifest: Path) -> list[tuple[Finding, str, str]]:
    root = Path(__file__).resolve().parents[2]
    allowed = manifest.resolve().parent
    document = json.loads(manifest.read_text())
    cases = []
    names = set()
    for case in document["cases"]:
        raw = case["finding"]
        repo = (root / raw["repo_url"]).resolve(strict=True)
        if not repo.is_relative_to(allowed):
            raise ValueError("Corpus source escapes its manifest directory")
        name = case["name"]
        if name in names:
            raise ValueError("Duplicate corpus case")
        names.add(name)
        finding = Finding(
            **{key: value for key, value in raw.items() if key in Finding.model_fields},
        )
        finding = finding.model_copy(
            update={"repo_url": str(repo), "source_mode": "working_snapshot", "revision": "HEAD"}
        )
        cases.append((finding, case["truth"]["expected_verdict"], name))
    if not cases:
        raise ValueError("An empty corpus cannot qualify a candidate")
    return cases


async def cancel_owned(client, run_id: str) -> None:
    # The RPC timeout and local bound also cover a persistently unavailable transport.
    async with asyncio.timeout(RPC_TIMEOUT.total_seconds()):
        await client.get_workflow_handle(run_id).cancel(rpc_timeout=RPC_TIMEOUT)


def operation_observation(config_path: Path, run_id: str) -> dict:
    try:
        return native_operation_accounting(OpenShellConfig.load(config_path).state_dir, run_id)
    except Exception as error:
        return {"status": "not_checked", "error_type": type(error).__name__,
                "native_ledger_occupancy": "not_checked"}


def cohort_operation_estimate(rows: list[dict]) -> dict:
    samples = [row["native_operations"]["total"] for row in rows
               if row["status"] == "completed"
               and row.get("native_operations", {}).get("status") == "observed"]
    observed = [row["native_operations"]["total"] for row in rows
                if row.get("native_operations", {}).get("status") == "observed"]
    report = {
        "status": "estimate" if samples else "not_checked",
        "completed_case_samples": len(samples),
        "planned_cases": len(rows),
        "observed_totals": {key: sum(sample[key] for sample in observed)
                            for key in ("completed", "unknown")},
        "native_capacity": "not_checked",
        "limitations": ["Actual observed attempts plus completed-case range extrapolated to unobserved cases; not a capacity gate.",
                        "Unsampled cases can exceed this range; unknown dispatch and native retention remain unresolved."],
    }
    if samples:
        counts = [sample["completed"] + sample["unknown"] for sample in samples]
        report["observed_attempt_range_per_case"] = [min(counts), max(counts)]
        unobserved = len(rows) - len(observed)
        actual = sum(sample["completed"] + sample["unknown"] for sample in observed)
        report["unobserved_cases"] = unobserved
        report["estimated_cohort_attempt_range"] = [actual + min(counts) * unobserved,
                                                     actual + max(counts) * unobserved]
    return report


async def evaluate_corpus(manifest: Path, output: Path) -> dict:
    if output.exists():
        raise ValueError("Report exists; preserve the previous cohort and choose a new path")
    settings = get_settings()
    commit = source_identity()
    cases = corpus_cases(manifest)
    policy, policy_digest = release_policy()
    identity = worker_identity(settings)
    candidate = {
        "version": 1,
        "commit": commit,
        "generation": "v11",
        "model": settings.model_name,
        "worker_identity": identity.model_dump(),
        "dataset_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "runtime_config_sha256": hashlib.sha256(settings.openshell_config.read_bytes()).hexdigest(),
        "limits": settings.limits.model_dump(),
        "native_operation_budget": {"status": "not_checked", "limit": None,
                                    "reason": "No native ledger capacity budget is configured or proven."},
        "started_at": datetime.now(UTC).isoformat(),
        "status": "running",
        "gates": {
            "complete_corpus": "not_checked",
            "task_success_rate": "not_checked",
            "unsafe_negatives": "not_checked",
        },
        "threshold": policy.minimum_task_success_rate,
        "release_policy_sha256": policy_digest,
        "release_policy": policy.model_dump(),
        "cases": [
            {"name": name, "expected": expected, "status": "unstarted"}
            for _, expected, name in cases
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    write_json(output, candidate, exclusive=True)
    try:
        client = await connect()
    except BaseException as error:
        candidate.update(status="failed", error_type=type(error).__name__)
        candidate["gates"]["complete_corpus"] = "failed"
        write_json(output, candidate)
        raise
    for (finding, expected, _), record in zip(cases, candidate["cases"], strict=True):
        run_id = PREFIX + "eval-" + uuid4().hex
        record.update(status="starting", workflow_id=run_id)
        write_json(output, candidate)
        try:
            handle = await client.start_workflow(
                WORKFLOW,
                InvestigationRequest(
                    finding=finding,
                    limits=settings.limits,
                    expected_worker_identity=identity.fingerprint,
                ),
                id=run_id,
                task_queue=settings.task_queue,
                result_type=InvestigationResult,
                id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
                memo={"finding": finding.model_dump(mode="json")},
                rpc_timeout=RPC_TIMEOUT,
                execution_timeout=execution_timeout(settings.limits),
            )
            wait_seconds = (execution_timeout(settings.limits) + RPC_TIMEOUT).total_seconds()
            async with asyncio.timeout(wait_seconds):
                result = InvestigationResult.model_validate(await handle.result())
            if result.model != settings.model_name or result.worker_identity != identity:
                raise ValueError(
                    "Evaluation result does not match the requested worker/model identity"
                )
            record.update(
                status="completed",
                predicted=result.verdict.label,
                passed=result.verdict.label == expected,
                source_digest=result.source_digest,
                usage=result.usage,
                limitations=result.limitations,
                worker_identity=result.worker_identity.model_dump(),
            )
            record["native_operations"] = operation_observation(settings.openshell_config, run_id)
        except BaseException as exc:
            # A failed workflow may have completed an external request. Never silently resend it.
            record.update(status="failed", error_type=type(exc).__name__)
            record["native_operations"] = operation_observation(settings.openshell_config, run_id)
            candidate["status"] = "failed"
            candidate["gates"]["complete_corpus"] = "failed"
            write_json(output, candidate)
            interrupted = isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt, SystemExit))
            if interrupted or isinstance(exc, TimeoutError):
                # Reconcile the one owned ID; never resend an uncertain start or inference.
                try:
                    await _finish(asyncio.ensure_future(cancel_owned(client, run_id)))
                    record["cancellation"] = "requested"
                except Exception as cancellation_error:
                    record["cancellation"] = "unconfirmed"
                    record["cancellation_error_type"] = type(cancellation_error).__name__
                record["native_operations"] = operation_observation(settings.openshell_config, run_id)
                candidate["native_operation_estimate"] = cohort_operation_estimate(candidate["cases"])
                write_json(output, candidate)
                if interrupted:
                    raise
            break
        write_json(output, candidate)
    rows = candidate["cases"]
    candidate["native_operation_estimate"] = cohort_operation_estimate(rows)
    complete = sum(row["status"] == "completed" for row in rows)
    passed = sum(row.get("passed", False) for row in rows)
    unsafe_negatives = sum(
        row.get("predicted") == "likely_not_exploitable"
        and row["expected"] == "potentially_exploitable"
        for row in rows
    )
    candidate["gates"] = {
        "complete_corpus": "passed" if complete == len(rows) else "failed",
        "task_success_rate": (
            "passed" if passed / len(rows) >= policy.minimum_task_success_rate else "failed"
        )
        if complete == len(rows)
        else "not_checked",
        "unsafe_negatives": (
            "passed" if unsafe_negatives <= policy.maximum_unsafe_negatives else "failed"
        )
        if complete == len(rows)
        else "not_checked",
    }
    candidate.update(
        completed=complete,
        planned=len(rows),
        task_success_rate=passed / len(rows),
        unsafe_negatives=unsafe_negatives,
        finished_at=datetime.now(UTC).isoformat(),
        status="passed"
        if complete == len(rows)
        and passed / len(rows) >= policy.minimum_task_success_rate
        and unsafe_negatives <= policy.maximum_unsafe_negatives
        else "failed",
    )
    write_json(output, candidate)
    return candidate
