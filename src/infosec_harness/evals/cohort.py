"""One frozen end-to-end corpus, through the production Temporal workflow."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
from collections.abc import Callable
from contextlib import AsyncExitStack, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, NamedTuple
from uuid import uuid4

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from temporalio.client import Client, WorkflowExecutionStatus, WorkflowFailureError
from temporalio.exceptions import ApplicationError, TerminatedError
from temporalio.exceptions import TimeoutError as TemporalTimeoutError

from infosec_harness._io import write_json

# TODO(merge): import GENERATION from contracts.py once the toplevel owner adds it there.
from infosec_harness.api import (
    GENERATION,
    PREFIX,
    RPC_TIMEOUT,
    connect,
    execution_timeout,
    start_investigation,
)
from infosec_harness.config import Settings
from infosec_harness.contracts import Finding, InvestigationResult, Limits, WorkerIdentity
from infosec_harness.sandbox import OpenShell, OpenShellConfig, native_operation_accounting
from infosec_harness.sandbox.process import finish, run_bounded
from infosec_harness.workflows.investigation import (
    CLEANUP_RESERVE,
    FAILURE_CHAIN_LINKS,
    FAILURE_WRAPPERS,
)
from infosec_harness.workflows.worker import worker_identity, workflow_runner

# The harness checkout: src/infosec_harness/evals/ is three levels below it.
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
# Covers prepare's waited cancellation and every bounded cleanup attempt of an owned run.
DRAIN = CLEANUP_RESERVE
# Terminal agent-level failures that --keep-going may continue past: budgets and invalid model
# output (raised by workflow code), and ModelExecutorError, an executor that exited without a
# response under a complete receipt (e.g. a sandbox DNS/connect failure, or a kill at the
# budget). Unknown dispatch (OpenShellError/ExecutionUnknown) is never in this set.
AGENT_FAILURES = frozenset({"UsageLimitExceeded", "UnexpectedModelBehavior", "ModelExecutorError"})
# Every link inside an agent-level failure must be one of these: the agent-level types, the
# ModelRetry an exhausted output correction wraps, and Temporal's wrappers. An allowlist, so
# an unknown inner type (a timeout, an RPC error, any OpenShellError subclass) stops a cohort.
AGENT_CHAIN = AGENT_FAILURES | FAILURE_WRAPPERS | {"ModelRetry"}
# Second check over the whole untruncated chain text; never a reason to continue.
STOP_MARKERS = ("cleanup", "executionunknown", "openshellerror")
# Client-side cause links examined; a deeper chain is not classified as agent-level.
CLASSIFIED_LINKS = 10
# One "<Label>: " segment of the workflow's " <- "-joined failure message.
_SEGMENT_LABEL = re.compile(r"([A-Za-z_][A-Za-z0-9_.]*): ")
# Native mutation admissions one case may retain beyond one exec per model request and per
# tool call: sandbox creates, admission execs, captures and snapshot delivery parts (900 kB
# each). Live run 8 retained at most 96 admissions per case under 40 requests / 100 calls.
CASE_LIFECYCLE_OPERATIONS = 40
OCCUPANCY_TIMEOUT = 60
GATES = ("complete_corpus", "task_success_rate", "unsafe_negatives")
# The observation is one JSON line; anything beyond this tail is not read.
OCCUPANCY_CAPTURE = 64_000
# Bound on an error message or stderr tail recorded in a report.
ERROR_CHARS = 300

log = logging.getLogger(__name__)


class ReleasePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    minimum_task_success_rate: float = Field(ge=0, le=1)
    maximum_unsafe_negatives: int = Field(ge=0)


class Occupancy(BaseModel):
    """One read-only observation of the native admission ledger, printed by an operator command."""

    # Strict: "5" is not a count and 1 is not ``true``; a read-only claim must be literal.
    model_config = ConfigDict(extra="ignore", strict=True)
    retained: int = Field(ge=0)
    quota: int = Field(ge=1)
    read_only: Literal[True]
    observed_at_ms: int | None = None

    @field_validator("read_only", mode="before")
    @classmethod
    def literal_true(cls, value: object) -> object:
        # Literal matching compares by equality even in strict mode, and 1 == True.
        if value is not True:
            raise ValueError("read_only must be the JSON literal true")
        return value


def case_operation_ceiling(limits: Limits) -> int:
    return limits.max_requests + limits.max_tool_calls + CASE_LIFECYCLE_OPERATIONS


def printable(text: str) -> str:
    """Control characters (terminal escapes, newlines) become spaces."""
    return "".join(char if char.isprintable() else " " for char in text)


def bounded(error: BaseException) -> str:
    """A report-safe error message: harness-authored text, cut to ERROR_CHARS."""
    return printable(str(error))[:ERROR_CHARS]


async def native_capacity_preflight(settings: Settings, planned: int) -> dict:
    """Refuse to start a cohort into a saturated admission ledger.

    The operator names a read-only command (``native_occupancy_command``) whose last stdout
    line is JSON with ``retained``, ``quota`` and ``read_only: true``; the harness never reads
    the ledger itself. A failed, slow or non-read-only observation fails closed. Unconfigured,
    the budget stays ``not_checked`` and the cohort proceeds as before.
    """
    ceiling = case_operation_ceiling(settings.limits)
    report = {
        "status": "not_checked",
        "planned_cases": planned,
        "per_case_ceiling": ceiling,
        "required_headroom": planned * ceiling,
        "limitations": [
            "The ceiling allows about 27 MB of snapshot archive per case; larger sources need more delivery parts.",
            "One ledger snapshot: other callers and 24 h retention expiry change occupancy during the run.",
        ],
    }
    command = list(settings.native_occupancy_command)
    if not command:
        report["reason"] = "No read-only native occupancy command is configured."
        log.info("event=capacity_preflight status=not_checked planned=%d", planned)
        return report
    try:
        observed = await _observe_occupancy(command, report)
    except Exception as error:
        report.update(status="failed", error_type=type(error).__name__, error=bounded(error),
                      reason="The occupancy command did not return a read-only observation.")
        log.warning("event=capacity_preflight status=failed error_type=%s exit_code=%s",
                    report["error_type"], report.get("exit_code"))
        return report
    headroom = observed.quota - observed.retained
    report.update(
        status="passed" if headroom >= report["required_headroom"] else "failed",
        retained=observed.retained, quota=observed.quota, headroom=headroom,
        observed_at_ms=observed.observed_at_ms,
        source="operator-configured read-only occupancy command",
    )
    if report["status"] == "failed":
        report["reason"] = "Insufficient native admission headroom for the planned cases."
    log.info("event=capacity_preflight status=%s planned=%d required=%d headroom=%d",
             report["status"], planned, report["required_headroom"], headroom)
    return report


async def _observe_occupancy(command: list[str], report: dict) -> Occupancy:
    """Run the operator command once (bounded, group-killed) and parse its last stdout line.

    Records ``exit_code`` and a bounded ``stderr_tail`` in ``report``; raises on any outcome
    that is not one strict read-only observation.
    """
    # The operator command inherits the environment it was configured in (its VM or cluster
    # tooling may need it), minus the harness's own settings, which can carry credentials.
    env = {key: value for key, value in os.environ.items() if not key.startswith("HARNESS_")}
    result = await run_bounded(command, env=env, timeout=OCCUPANCY_TIMEOUT,
                               capture_limit=OCCUPANCY_CAPTURE)
    report["exit_code"] = result.exit_code
    if result.stderr.strip():
        report["stderr_tail"] = printable(result.stderr.strip())[-ERROR_CHARS:]
    if result.timed_out:
        raise TimeoutError(f"occupancy command exceeded {OCCUPANCY_TIMEOUT} s and was killed")
    if result.exit_code != 0:
        raise RuntimeError(f"occupancy command exited {result.exit_code}; expected 0")
    lines = result.stdout.strip().splitlines()
    if not lines:
        raise ValueError("occupancy command printed no observation line")
    try:
        return Occupancy.model_validate_json(lines[-1])
    except ValidationError as error:
        problems = sorted({f"{'.'.join(map(str, item['loc'])) or '<root>'}: {item['type']}"
                           for item in error.errors()})
        raise ValueError("occupancy observation rejected: " + "; ".join(problems)) from None


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


class CorpusCase(NamedTuple):
    finding: Finding
    expected: str
    name: str


def corpus_cases(manifest: Path) -> list[CorpusCase]:
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
        cases.append(CorpusCase(finding, case["truth"]["expected_verdict"], name))
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


SERVER_ENDED_STEP = (
    "The Temporal server ended this run before its cleanup activity; its owned sandboxes may "
    "remain open. Close them with OpenShell.close_run(<workflow_id>) under this runtime "
    "configuration before reusing the native admission quota."
)


def server_ended(error: BaseException) -> bool:
    """The server timed out or terminated the run, so workflow cleanup never ran."""
    return isinstance(error, WorkflowFailureError) and isinstance(
        error.cause, (TemporalTimeoutError, TerminatedError)
    )


def failure_label(error: BaseException) -> str:
    kind = error.type if isinstance(error, ApplicationError) else None
    return kind or type(error).__name__


def cause_links(error: BaseException | None, limit: int) -> tuple[list[BaseException], bool]:
    """The first ``limit`` links of a cause chain, and whether more links remain."""
    chain = []
    while error is not None and len(chain) < limit:
        chain.append(error)
        error = getattr(error, "cause", None) or error.__cause__
    return chain, error is not None


def failure_chain(error: BaseException | None, limit: int = 5) -> list[dict]:
    """A bounded view of a cause chain for reports; never used to classify a failure."""
    return [{"type": failure_label(link), "message": str(link)[:500]}
            for link in cause_links(error, limit)[0]]


def _embedded_labels_allowed(message: str) -> bool:
    """Every link label the workflow embedded in ``message`` is in AGENT_CHAIN.

    The workflow writes ``Label: text`` links joined by `` <- ``. A first segment without a
    label is a plain message. Every later segment must carry an allowed label: text that only
    looks like a separator fails closed, and a message with the workflow's full link count
    may have lost deeper links, so it fails closed too.
    """
    segments = message.split(" <- ")
    if len(segments) >= FAILURE_CHAIN_LINKS:
        return False
    for position, segment in enumerate(segments):
        label = _SEGMENT_LABEL.match(segment)
        if label is None:
            if position:
                return False
        elif label[1] not in AGENT_CHAIN:
            return False
    return True


def agent_level(error: BaseException) -> bool:
    """A terminal workflow failure whose whole, untruncated cause chain is agent/model-level.

    Classified from the raw exceptions, never from the bounded ``failure_chain`` report view:
    the outermost typed cause must be an AGENT_FAILURES type, every further typed link and
    every link label the workflow embedded in a message must be in AGENT_CHAIN, and no stop
    marker may appear anywhere in the chain text.
    """
    if not isinstance(error, WorkflowFailureError):
        return False
    chain, deeper = cause_links(error, CLASSIFIED_LINKS)
    if deeper or len(chain) < 2 or failure_label(chain[1]) not in AGENT_FAILURES:
        return False
    if any(failure_label(link) not in AGENT_CHAIN for link in chain[2:]):
        return False
    if not all(_embedded_labels_allowed(str(link)) for link in chain[1:]):
        return False
    text = " ".join(str(link) for link in chain).lower()
    return not any(marker in text for marker in STOP_MARKERS)


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


async def _run_case(
    client: Client,
    settings: Settings,
    identity: WorkerIdentity,
    case: CorpusCase,
    record: dict,
    candidate: dict,
    persist: Callable[[], None],
    *,
    owned_worker: bool,
    index: int,
    total: int,
) -> BaseException | None:
    """Run one case once on a fresh workflow ID and reconcile what it owns.

    Returns the failure (cancellation included) instead of raising it, so the caller alone
    decides whether to stop. A failed case is never re-run and nothing it dispatched is resent.
    """
    run_id = PREFIX + "eval-" + uuid4().hex
    started = datetime.now(UTC)
    record.update(status="starting", workflow_id=run_id, started_at=started.isoformat())
    persist()
    progress(index, total, record)
    failure = None
    terminal = False
    try:
        handle = await start_investigation(
            client, case.finding, settings, run_id, identity.fingerprint
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
            passed=result.verdict.label == case.expected,
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
        persist()
        if not (terminal or isinstance(exc, WorkflowFailureError)):
            # Reconcile the one owned ID; never resend an uncertain start or inference.
            try:
                await finish(asyncio.ensure_future(
                    cancel_owned(client, run_id, DRAIN if owned_worker else None)))
                record["cancellation"] = "terminal" if owned_worker else "requested"
            except Exception as cancellation_error:
                record["cancellation"] = "unconfirmed"
                record["cancellation_error_type"] = type(cancellation_error).__name__
        elif server_ended(exc):
            # The workflow's `finally` never ran, so nothing closed its sandboxes.
            record.update(cleanup="unconfirmed", cleanup_next_step=SERVER_ENDED_STEP)
        record["receipts"] = receipt_summary(settings.openshell_config, run_id)
    record["native_operations"] = operation_observation(settings.openshell_config, run_id)
    candidate["native_operation_estimate"] = cohort_operation_estimate(candidate["cases"])
    persist()
    progress(index, total, record)
    return failure


def _derive_gates(rows: list[dict], policy: ReleasePolicy, *, diagnostic: bool) -> dict:
    """Gates, counts and status for the recorded rows; the status follows from the gates."""
    complete = sum(row["status"] == "completed" for row in rows)
    passed = sum(row.get("passed", False) for row in rows)
    unsafe_negatives = sum(
        row.get("predicted") == "likely_not_exploitable"
        and row["expected"] == "potentially_exploitable"
        for row in rows
    )
    rate = passed / len(rows)
    if diagnostic:
        # A partial cohort can never qualify a candidate.
        gates = dict.fromkeys(GATES, "not_checked")
    elif complete != len(rows):
        gates = {"complete_corpus": "failed", "task_success_rate": "not_checked",
                 "unsafe_negatives": "not_checked"}
    else:
        gates = {
            "complete_corpus": "passed",
            "task_success_rate": (
                "passed" if rate >= policy.minimum_task_success_rate else "failed"
            ),
            "unsafe_negatives": (
                "passed" if unsafe_negatives <= policy.maximum_unsafe_negatives else "failed"
            ),
        }
    if diagnostic:
        status = "completed" if complete == len(rows) else "failed"
    else:
        status = "passed" if all(value == "passed" for value in gates.values()) else "failed"
    return {"gates": gates, "completed": complete, "planned": len(rows),
            "task_success_rate": rate, "unsafe_negatives": unsafe_negatives, "status": status}


async def evaluate_corpus(
    manifest: Path,
    output: Path,
    settings: Settings,
    *,
    names: tuple[str, ...] = (),
    owned_worker: bool = False,
    keep_going: bool = False,
) -> dict:
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
    cases = [CorpusCase(*case) for case in corpus_cases(manifest)]
    if unknown := set(names) - {case.name for case in cases}:
        raise ValueError(f"Unknown corpus case: {', '.join(sorted(unknown))}")
    cases = [case for case in cases if not names or case.name in names]
    policy, policy_digest = release_policy()
    identity = worker_identity(settings)
    candidate = {
        "version": 1,
        "kind": "diagnostic" if names else "cohort",
        "commit": commit,
        "generation": GENERATION,
        "model": settings.model_name,
        "task_queue": settings.task_queue,
        "owned_worker": owned_worker,
        "worker_identity": identity.model_dump(),
        "dataset_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "runtime_config_sha256": hashlib.sha256(settings.openshell_config.read_bytes()).hexdigest(),
        "limits": settings.limits.model_dump(),
        "native_operation_budget": await native_capacity_preflight(settings, len(cases)),
        "started_at": datetime.now(UTC).isoformat(),
        "status": "running",
        "gates": dict.fromkeys(GATES, "not_checked"),
        "threshold": policy.minimum_task_success_rate,
        "release_policy_sha256": policy_digest,
        "release_policy": policy.model_dump(),
        "cases": [
            {"name": case.name, "expected": case.expected, "status": "unstarted"}
            for case in cases
        ],
    }
    write_json(output, candidate, exclusive=True)

    def persist() -> None:
        # The one report writer. Writes are synchronous, so a document is never interleaved.
        write_json(output, candidate)

    if candidate["native_operation_budget"]["status"] == "failed":
        error = ValueError("Native admission capacity preflight failed; no case was started")
        candidate.update(status="failed", error_type=type(error).__name__)
        candidate["gates"]["complete_corpus"] = "failed"
        persist()
        raise error
    async with AsyncExitStack() as stack:
        try:
            client = await connect(settings)
            if owned_worker:
                # Looked up at call time so tests can substitute the worker factory.
                from infosec_harness.workflows.worker import create_worker

                await stack.enter_async_context(create_worker(client, settings))
        except BaseException as error:
            candidate.update(status="failed", error_type=type(error).__name__)
            candidate["gates"]["complete_corpus"] = "failed"
            persist()
            raise
        for index, (case, record) in enumerate(zip(cases, candidate["cases"], strict=True), 1):
            failure = await _run_case(
                client, settings, identity, case, record, candidate, persist,
                owned_worker=owned_worker, index=index, total=len(cases),
            )
            if isinstance(failure, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
                raise failure
            if failure is not None and not (keep_going and agent_level(failure)):
                break
    candidate["native_operation_estimate"] = cohort_operation_estimate(candidate["cases"])
    derived = _derive_gates(candidate["cases"], policy, diagnostic=bool(names))
    candidate.update(derived, finished_at=datetime.now(UTC).isoformat())
    persist()
    return candidate


class _NoDispatch:
    def __getattr__(self, name):
        raise AssertionError(f"Replay attempted native operation: {name}")


async def replay_history(run_id: str, settings, client=None) -> dict:
    """Replay one recorded history against current workflow code with zero dispatch."""
    import pydantic_ai.models
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.worker import Replayer

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
        await Replayer(
            workflows=[InvestigationWorkflow],
            plugins=[PydanticAIPlugin()],
            workflow_runner=workflow_runner(),
        ).replay_workflow(history)
    except Exception as error:
        report.update(status="failed", failure_chain=failure_chain(error))
    description = await handle.describe(rpc_timeout=RPC_TIMEOUT)
    if description.status == WorkflowExecutionStatus.COMPLETED:
        result = await handle.result(rpc_timeout=RPC_TIMEOUT)
        report["verdict"] = result.verdict.label
    return report
