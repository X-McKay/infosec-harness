"""One frozen end-to-end corpus, through the production Temporal workflow."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import sys
from contextlib import AsyncExitStack, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import yaml
from pydantic import BaseModel, ConfigDict, Field
from temporalio.client import WorkflowExecutionStatus, WorkflowFailureError
from temporalio.exceptions import ApplicationError

from infosec_harness._io import write_json
from infosec_harness.api import PREFIX, RPC_TIMEOUT, connect, execution_timeout, start_investigation
from infosec_harness.contracts import Finding, InvestigationResult
from infosec_harness.sandbox import OpenShell, OpenShellConfig, native_operation_accounting
from infosec_harness.sandbox.process import _finish
from infosec_harness.workflows.worker import worker_identity

# The harness checkout: src/infosec_harness/evals/ is three levels below it.
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
# Covers prepare's waited cancellation and three bounded cleanup attempts of an owned run.
DRAIN = timedelta(minutes=30)
# Terminal agent-level failures that --keep-going may continue past: budgets and invalid model
# output (raised by workflow code), and ModelExecutorError, an executor that exited without a
# response under a complete receipt (e.g. a sandbox DNS/connect failure, or a kill at the
# budget). Unknown dispatch (OpenShellError/ExecutionUnknown) is never in this set, and
# `agent_level` also scans the embedded chain text for those markers and for cleanup.
AGENT_FAILURES = frozenset({"UsageLimitExceeded", "UnexpectedModelBehavior", "ModelExecutorError"})


class ReleasePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    minimum_task_success_rate: float = Field(ge=0, le=1)
    maximum_unsafe_negatives: int = Field(ge=0)


def release_policy() -> tuple[ReleasePolicy, str]:
    data = Path(__file__).with_name("release-policy.yaml").read_bytes()
    return ReleasePolicy.model_validate(yaml.safe_load(data)), hashlib.sha256(data).hexdigest()


def source_identity() -> str:
    # Qualification is checkout-owned. Caller directories and Git configuration are untrusted.
    root = REPOSITORY_ROOT
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
    root = REPOSITORY_ROOT
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


async def cancel_owned(client, run_id: str, drain: timedelta | None = None) -> None:
    # The RPC timeout and local bound also cover a persistently unavailable transport.
    handle = client.get_workflow_handle(run_id)
    async with asyncio.timeout(RPC_TIMEOUT.total_seconds()):
        await handle.cancel(rpc_timeout=RPC_TIMEOUT)
    if drain is not None:
        # An owned worker must outlive the run's cleanup activity: wait for a terminal state.
        async with asyncio.timeout(drain.total_seconds()):
            with suppress(WorkflowFailureError):
                await handle.result()


def failure_chain(error: BaseException | None, limit: int = 5) -> list[dict]:
    chain = []
    while error is not None and len(chain) < limit:
        kind = error.type if isinstance(error, ApplicationError) else None
        chain.append({"type": kind or type(error).__name__, "message": str(error)[:500]})
        error = getattr(error, "cause", None) or error.__cause__
    return chain


def agent_level(error: BaseException) -> bool:
    """A terminal workflow failure whose whole cause chain is agent/model-level."""
    chain = failure_chain(error, limit=10)
    # The workflow embeds every wrapped type in its message, so a native or unknown-dispatch
    # link anywhere in the original chain still stops the cohort.
    text = " ".join(link["message"] for link in chain).lower()
    return (
        isinstance(error, WorkflowFailureError)
        and 1 < len(chain) < 10
        and all(link["type"] in AGENT_FAILURES for link in chain[1:])
        and not any(marker in text for marker in ("cleanup", "executionunknown", "openshellerror"))
    )


def receipt_summary(config_path: Path, run_id: str) -> dict:
    # Local durable receipts only; reading them dispatches nothing.
    try:
        receipts = OpenShell(OpenShellConfig.load(config_path)).receipts(run_id)
    except Exception as error:
        return {"status": "not_checked", "error_type": type(error).__name__}
    return {"status": "observed", "count": len(receipts), "items": [
        {"operation_id": receipt.operation_id, "exit_code": receipt.result.exit_code,
         "output_truncated": receipt.result.output_truncated} for receipt in receipts[:10]]}


def case_end(started: datetime) -> dict:
    """UTC end time and duration for a case record, stamped when its outcome is known."""
    now = datetime.now(UTC)
    return {"finished_at": now.isoformat(),
            "duration_seconds": round((now - started).total_seconds(), 3)}


def progress(index: int, total: int, record: dict) -> None:
    print(f"[{index}/{total}] {record['name']} {record.get('workflow_id', '-')} {record['status']}",
          file=sys.stderr, flush=True)


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


async def evaluate_corpus(manifest: Path, output: Path, settings, *, names=(),
                          owned_worker: bool = False, keep_going: bool = False) -> dict:
    """Run the frozen corpus once through the production workflow; never resend a case.

    ``names`` selects a diagnostic subset: every gate stays ``not_checked`` and it never passes.
    ``owned_worker`` runs ``create_worker`` in this process on a fresh task queue, recorded in
    the report, and keeps it up until each owned workflow, cleanup included, is terminal. If
    this process is killed, run ``harness worker`` on that queue to drain cleanup.

    ``keep_going`` does not conflict with "never blindly retry": each case has a fresh workflow
    ID under REJECT_DUPLICATE, a failed case is never re-run and nothing it dispatched is resent.
    It continues only after a terminal failure whose cause chain is agent-level. Timeouts,
    transport errors, identity mismatch, native/dispatch or cleanup failures still stop the
    cohort, because the next case would compete with unknown work. The gates are unchanged.
    """
    if output.exists():
        raise ValueError("Report exists; preserve the previous cohort and choose a new path")
    if owned_worker:
        settings = settings.model_copy(update={"task_queue": f"{PREFIX}eval-{uuid4().hex}"})
    commit = source_identity()
    cases = corpus_cases(manifest)
    if unknown := set(names) - {name for _, _, name in cases}:
        raise ValueError(f"Unknown corpus case: {', '.join(sorted(unknown))}")
    cases = [case for case in cases if not names or case[2] in names]
    policy, policy_digest = release_policy()
    identity = worker_identity(settings)
    candidate = {
        "version": 1,
        "kind": "diagnostic" if names else "cohort",
        "commit": commit,
        "generation": "v11",
        "model": settings.model_name,
        "task_queue": settings.task_queue,
        "owned_worker": owned_worker,
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
    async with AsyncExitStack() as stack:
        try:
            client = await connect(settings)
            if owned_worker:
                from infosec_harness.workflows.worker import create_worker

                await stack.enter_async_context(create_worker(client, settings))
        except BaseException as error:
            candidate.update(status="failed", error_type=type(error).__name__)
            candidate["gates"]["complete_corpus"] = "failed"
            write_json(output, candidate)
            raise
        for index, ((finding, expected, _), record) in enumerate(
            zip(cases, candidate["cases"], strict=True), 1
        ):
            run_id = PREFIX + "eval-" + uuid4().hex
            started = datetime.now(UTC)
            record.update(status="starting", workflow_id=run_id, started_at=started.isoformat())
            write_json(output, candidate)
            progress(index, len(cases), record)
            failure = None
            terminal = False
            try:
                handle = await start_investigation(
                    client, finding, settings, run_id, identity.fingerprint
                )
                wait_seconds = (execution_timeout(settings.limits) + RPC_TIMEOUT).total_seconds()
                async with asyncio.timeout(wait_seconds):
                    raw = await handle.result()
                terminal = True
                result = InvestigationResult.model_validate(raw)
                if result.model != settings.model_name or result.worker_identity != identity:
                    raise ValueError(
                        "Evaluation result does not match the requested worker/model identity"
                    )
                record.update(
                    **case_end(started),
                    status="completed",
                    predicted=result.verdict.label,
                    passed=result.verdict.label == expected,
                    source_digest=result.source_digest,
                    usage=result.usage,
                    limitations=result.limitations,
                    worker_identity=result.worker_identity.model_dump(),
                )
            except BaseException as exc:
                # A failed workflow may have completed an external request. Never silently resend it.
                failure = exc
                record.update(status="failed", error_type=type(exc).__name__,
                              failure_chain=failure_chain(exc), **case_end(started))
                candidate["status"] = "failed"
                candidate["gates"]["complete_corpus"] = "failed"
                write_json(output, candidate)
                if not (terminal or isinstance(exc, WorkflowFailureError)):
                    # Reconcile the one owned ID; never resend an uncertain start or inference.
                    try:
                        await _finish(asyncio.ensure_future(
                            cancel_owned(client, run_id, DRAIN if owned_worker else None)))
                        record["cancellation"] = "terminal" if owned_worker else "requested"
                    except Exception as cancellation_error:
                        record["cancellation"] = "unconfirmed"
                        record["cancellation_error_type"] = type(cancellation_error).__name__
                record["receipts"] = receipt_summary(settings.openshell_config, run_id)
            record["native_operations"] = operation_observation(settings.openshell_config, run_id)
            candidate["native_operation_estimate"] = cohort_operation_estimate(candidate["cases"])
            write_json(output, candidate)
            progress(index, len(cases), record)
            if isinstance(failure, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
                raise failure
            if failure is not None and not (keep_going and agent_level(failure)):
                break
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
    if names:
        # A partial cohort can never qualify a candidate.
        candidate["gates"] = dict.fromkeys(candidate["gates"], "not_checked")
        candidate["status"] = "completed" if complete == len(rows) else "failed"
    write_json(output, candidate)
    return candidate


class _NoDispatch:
    def __getattr__(self, name):
        raise AssertionError(f"Replay attempted native operation: {name}")


async def replay_history(run_id: str, settings, client=None) -> dict:
    """Replay one recorded history against current workflow code with zero dispatch."""
    import pydantic_ai.models
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.worker import Replayer
    from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

    from infosec_harness.agents.inference import OpenShellModel
    from infosec_harness.agents.investigator import build_agent
    from infosec_harness.workflows.investigation import InvestigationWorkflow, bind_investigator

    pydantic_ai.models.ALLOW_MODEL_REQUESTS = False
    client = client or await connect(settings)
    handle = client.get_workflow_handle(run_id, result_type=InvestigationResult)
    history = await handle.fetch_history(rpc_timeout=RPC_TIMEOUT)
    data = history.to_json()
    shell = _NoDispatch()
    bind_investigator(build_agent(shell, OpenShellModel(
        shell, settings.model_name, provider=settings.model_provider,
        base_url=settings.model_base_url, region=settings.model_region)))
    report = {"status": "passed", "workflow_id": run_id, "history_events": len(history.events),
              "history_sha256": hashlib.sha256(data.encode()).hexdigest(), "verdict": None}
    try:
        # Same passthrough modules as create_worker's sandboxed workflow runner.
        await Replayer(
            workflows=[InvestigationWorkflow],
            plugins=[PydanticAIPlugin()],
            workflow_runner=SandboxedWorkflowRunner(
                restrictions=SandboxRestrictions.default.with_passthrough_modules(
                    "infosec_harness.workflows.investigation",
                    "annotated_types",
                    "typing_inspection",
                )
            ),
        ).replay_workflow(history)
    except Exception as error:
        report.update(status="failed", failure_chain=failure_chain(error))
    description = await handle.describe(rpc_timeout=RPC_TIMEOUT)
    if description.status == WorkflowExecutionStatus.COMPLETED:
        result = await handle.result(rpc_timeout=RPC_TIMEOUT)
        report["verdict"] = result.verdict.label
    return report
