"""Small HTTP projection of Temporal investigations; no duplicate job database.

Also the Temporal client connection shared by the API, the CLI and workers; connection
options never enter workflow history.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import math
import os
import re
import stat
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError
from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
from temporalio.api.enums.v1 import EventType, TimeoutType
from temporalio.api.workflowservice.v1 import GetSystemInfoRequest
from temporalio.client import Client, WorkflowExecutionStatus
from temporalio.common import WorkflowIDReusePolicy
from temporalio.service import RPCError, RPCStatusCode, TLSConfig

from infosec_harness.config import Settings, get_settings
from infosec_harness.contracts import (
    Finding,
    Health,
    InvestigationRequest,
    InvestigationResult,
    Limits,
    ReportList,
    ReportSummary,
    RunEvent,
    RunEvents,
    RunPage,
    RunState,
    RunSummary,
)

WORKFLOW = "InvestigationWorkflow"
GENERATION = "v11"
PREFIX = "investigate-v11-"
RPC_TIMEOUT = timedelta(seconds=10)
PAGE_SIZE = 50
# Run-list verdicts: bounded concurrency, a short per-run RPC and an overall deadline.
VERDICT_CONCURRENCY = 8
VERDICT_RPC_TIMEOUT = timedelta(seconds=3)
VERDICT_DEADLINE_SECONDS = 8.0
MAX_EVENTS = 500
MAX_DETAIL = 200
MAX_REPORTS = 200
MAX_REPORT_BYTES = 16 * 1024 * 1024
# Bytes parsed for one listing; later files are listed without a summary.
REPORT_LISTING_BUDGET = 64 * 1024 * 1024
REPORT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.json")
REPORT_KINDS = ("model", "diagnostic", "openshell", "replay")


def execution_timeout(limits: Limits) -> timedelta:
    # Starts at submission, including time queued without a worker. Reserve cleanup time.
    return timedelta(seconds=limits.timeout_seconds + 600)


def temporal_connection_options(settings: Settings) -> dict[str, Any]:
    options: dict[str, Any] = {}
    if settings.temporal_tls:
        if any(
            (
                settings.temporal_tls_ca_file,
                settings.temporal_tls_client_cert,
                settings.temporal_tls_server_name,
            )
        ):
            options["tls"] = TLSConfig(
                server_root_ca_cert=settings.temporal_tls_ca_file.read_bytes()
                if settings.temporal_tls_ca_file
                else None,
                client_cert=settings.temporal_tls_client_cert.read_bytes()
                if settings.temporal_tls_client_cert
                else None,
                client_private_key=settings.temporal_tls_client_key.read_bytes()
                if settings.temporal_tls_client_key
                else None,
                domain=settings.temporal_tls_server_name,
            )
        else:
            options["tls"] = True
    key = settings.temporal_api_key
    if settings.temporal_api_key_file:
        key = settings.temporal_api_key_file.read_text().strip()
        if not key:
            raise ValueError("Temporal API key file is empty")
    if key:
        options["api_key"] = key
    return options


async def connect(settings=None) -> Client:
    settings = settings or get_settings()
    return await Client.connect(
        settings.temporal_address,
        namespace=settings.temporal_namespace,
        plugins=[PydanticAIPlugin()],
        **temporal_connection_options(settings),
    )


async def start_investigation(client: Client, finding: Finding, settings, run_id: str,
                              expected_identity: str | None = None):
    """Start one fresh workflow ID; a duplicate is rejected rather than resent."""
    return await client.start_workflow(
        WORKFLOW,
        InvestigationRequest(
            finding=finding, limits=settings.limits, expected_worker_identity=expected_identity
        ),
        id=run_id,
        task_queue=settings.task_queue,
        result_type=InvestigationResult,
        id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
        memo={"finding": finding.model_dump(mode="json")},
        rpc_timeout=RPC_TIMEOUT,
        execution_timeout=execution_timeout(settings.limits),
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.temporal = await connect()
    yield


app = FastAPI(title="InfoSec Harness", version="3.0.0.dev0", lifespan=lifespan)


def temporal() -> Client:
    return app.state.temporal


TemporalClient = Annotated[Client, Depends(temporal)]


@app.exception_handler(RPCError)
async def temporal_error(_request, exc: RPCError):
    status = 404 if exc.status == RPCStatusCode.NOT_FOUND else 503
    return JSONResponse(
        status_code=status,
        content={
            "detail": "Investigation not found" if status == 404 else "Workflow service unavailable"
        },
    )


@app.get(
    "/api/health",
    response_model=Health,
    responses={503: {"model": Health, "description": "Temporal is unreachable"}},
)
async def health(client: TemporalClient):
    """Temporal connectivity only; sandbox, worker and model execution stay not_checked."""
    task_queue = get_settings().task_queue
    try:
        await client.workflow_service.get_system_info(GetSystemInfoRequest(), timeout=RPC_TIMEOUT)
    except RPCError:
        unavailable = Health(
            status="temporal_unavailable",
            temporal=False,
            generation=GENERATION,
            task_queue=task_queue,
        )
        return JSONResponse(status_code=503, content=unavailable.model_dump())
    return Health(
        status="control_plane_ready", temporal=True, generation=GENERATION, task_queue=task_queue
    )


@app.post("/api/runs", response_model=RunState, status_code=202)
async def submit(finding: Finding, client: TemporalClient) -> RunState:
    run_id = PREFIX + uuid4().hex
    await start_investigation(client, finding, get_settings(), run_id)
    return RunState(id=run_id, status="pending", phase="queued", finding=finding)


@app.get("/api/runs", response_model=RunPage)
async def runs(
    client: TemporalClient, page_token: Annotated[str | None, Query(max_length=8192)] = None
) -> RunPage:
    try:
        token = base64.b64decode(page_token, validate=True) if page_token else None
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(400, "Invalid page token") from exc
    iterator = client.list_workflows(
        f"WorkflowType = '{WORKFLOW}' AND WorkflowId STARTS_WITH '{PREFIX}'",
        page_size=PAGE_SIZE,
        next_page_token=token,
        rpc_timeout=RPC_TIMEOUT,
    )
    await iterator.fetch_next_page()
    page = list(iterator.current_page)[:PAGE_SIZE]
    verdicts = await completed_verdicts(client, page)
    items = []
    for entry in page:
        memo = await entry.memo()
        finding = memo.get("finding", {})
        if not isinstance(finding, dict):
            finding = {}
        try:
            recorded = Finding.model_validate(finding)
        except ValidationError:
            recorded = None
        items.append(
            RunSummary(
                id=entry.id,
                title=str(finding.get("title", entry.id)),
                status=entry.status.name.lower() if entry.status else "unknown",
                started_at=entry.start_time.isoformat(),
                closed_at=entry.close_time.isoformat() if entry.close_time else None,
                verdict=verdicts.get(entry.id),
                cwe=recorded.cwe if recorded else None,
                repo_url=recorded.repo_url if recorded else None,
            )
        )
    following = (
        base64.b64encode(iterator.next_page_token).decode() if iterator.next_page_token else None
    )
    return RunPage(items=items, next_page_token=following)


async def completed_verdicts(client: Client, page) -> dict[str, str]:
    """Verdict labels for completed runs; a failed or slow result fetch leaves the run out."""
    gate = asyncio.Semaphore(VERDICT_CONCURRENCY)

    async def verdict(entry) -> tuple[str, str | None]:
        async with gate:
            try:
                handle = client.get_workflow_handle(
                    entry.id,
                    run_id=getattr(entry, "run_id", None),
                    result_type=InvestigationResult,
                )
                result = await asyncio.wait_for(
                    handle.result(follow_runs=False, rpc_timeout=VERDICT_RPC_TIMEOUT),
                    VERDICT_RPC_TIMEOUT.total_seconds(),
                )
                return entry.id, InvestigationResult.model_validate(result).verdict.label
            except Exception:
                return entry.id, None

    tasks = [
        asyncio.create_task(verdict(entry))
        for entry in page
        if entry.status == WorkflowExecutionStatus.COMPLETED
    ]
    if not tasks:
        return {}
    done, pending = await asyncio.wait(tasks, timeout=VERDICT_DEADLINE_SECONDS)
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    labels = (task.result() for task in done)
    return {run_id: label for run_id, label in labels if label is not None}


def run_handle(client: Client, run_id: str):
    if not run_id.startswith(PREFIX) or len(run_id) > 100:
        raise HTTPException(404, "Investigation not found")
    return client.get_workflow_handle(run_id, result_type=InvestigationResult)


@app.get("/api/runs/{run_id}", response_model=RunState)
async def run(run_id: str, client: TemporalClient) -> RunState:
    handle = run_handle(client, run_id)
    description = await handle.describe(rpc_timeout=RPC_TIMEOUT)
    if description.status == WorkflowExecutionStatus.RUNNING:
        return RunState.model_validate(await handle.query("state", rpc_timeout=RPC_TIMEOUT))
    memo = await description.memo()
    finding = Finding.model_validate(memo["finding"])
    if description.status == WorkflowExecutionStatus.COMPLETED:
        result = InvestigationResult.model_validate(await handle.result(rpc_timeout=RPC_TIMEOUT))
        return RunState(
            id=run_id, finding=finding, status="completed", phase="finished", result=result
        )
    cancelled = description.status == WorkflowExecutionStatus.CANCELED
    return RunState(
        id=run_id,
        finding=finding,
        status="cancelled" if cancelled else "failed",
        phase="finished",
        error=description.status.name.lower() if description.status else "unknown",
    )


@app.post("/api/runs/{run_id}/cancel", status_code=202)
async def cancel(run_id: str, client: TemporalClient) -> dict[str, str]:
    handle = run_handle(client, run_id)
    description = await handle.describe(rpc_timeout=RPC_TIMEOUT)
    if description.status == WorkflowExecutionStatus.RUNNING:
        await handle.cancel(rpc_timeout=RPC_TIMEOUT)
        return {"status": "cancellation_requested"}
    return {"status": description.status.name.lower() if description.status else "unknown"}


def bounded(value: Any, limit: int = MAX_DETAIL) -> str:
    """One printable line of at most ``limit`` characters."""
    return "".join(char if char.isprintable() else " " for char in str(value)[:limit])


def enum_label(enum, value: int, prefix: str, default: str) -> str:
    try:
        return enum.Name(value).removeprefix(prefix).lower()
    except ValueError:
        return default


def failure_type(failure) -> str:
    """The failure's type, never its message: messages can carry untrusted output."""
    if failure.HasField("application_failure_info") and failure.application_failure_info.type:
        return failure.application_failure_info.type
    if failure.HasField("timeout_failure_info"):
        return enum_label(
            TimeoutType, failure.timeout_failure_info.timeout_type, "TIMEOUT_TYPE_", "timeout"
        )
    which = failure.WhichOneof("failure_info")
    return which.removesuffix("_failure_info") if which else "failure"


def exit_code(payloads) -> str:
    """``exit_code=N`` when a small JSON result records an integer exit code, else ``""``."""
    if not payloads.payloads:
        return ""
    payload = payloads.payloads[0]
    if payload.metadata.get("encoding") != b"json/plain" or len(payload.data) > 64 * 1024:
        return ""
    try:
        layer = [json.loads(payload.data)]
    except (ValueError, RecursionError):
        return ""
    for _ in range(3):
        following = []
        for item in layer:
            if not isinstance(item, dict):
                continue
            if type(code := item.get("exit_code")) is int:
                return f"exit_code={code}"
            following.extend(value for value in item.values() if isinstance(value, dict))
        layer = following[:32]
    return ""


ACTIVITY_OUTCOMES = {
    EventType.EVENT_TYPE_ACTIVITY_TASK_STARTED: "activity_task_started_event_attributes",
    EventType.EVENT_TYPE_ACTIVITY_TASK_COMPLETED: "activity_task_completed_event_attributes",
    EventType.EVENT_TYPE_ACTIVITY_TASK_FAILED: "activity_task_failed_event_attributes",
    EventType.EVENT_TYPE_ACTIVITY_TASK_TIMED_OUT: "activity_task_timed_out_event_attributes",
    EventType.EVENT_TYPE_ACTIVITY_TASK_CANCELED: "activity_task_canceled_event_attributes",
}
TIMERS = (
    EventType.EVENT_TYPE_TIMER_STARTED,
    EventType.EVENT_TYPE_TIMER_FIRED,
    EventType.EVENT_TYPE_TIMER_CANCELED,
)


def project_event(event, activities: dict[int, str]) -> RunEvent:
    """Map one history event to a kind and bounded labels; payloads are never copied."""
    kind_of = event.event_type
    label = enum_label(EventType, kind_of, "EVENT_TYPE_", "unknown")
    kind, name, detail = "other", None, label
    if kind_of == EventType.EVENT_TYPE_WORKFLOW_EXECUTION_STARTED:
        attributes = event.workflow_execution_started_event_attributes
        kind, name, detail = "workflow_started", attributes.workflow_type.name, ""
    elif kind_of == EventType.EVENT_TYPE_ACTIVITY_TASK_SCHEDULED:
        attributes = event.activity_task_scheduled_event_attributes
        activities[event.event_id] = attributes.activity_type.name
        kind, name, detail = "activity_scheduled", attributes.activity_type.name, ""
    elif kind_of in ACTIVITY_OUTCOMES:
        attributes = getattr(event, ACTIVITY_OUTCOMES[kind_of])
        name = activities.get(attributes.scheduled_event_id)
        if kind_of == EventType.EVENT_TYPE_ACTIVITY_TASK_STARTED:
            detail = f"{label} attempt={attributes.attempt}"
        elif kind_of == EventType.EVENT_TYPE_ACTIVITY_TASK_COMPLETED:
            kind, detail = "activity_completed", exit_code(attributes.result)
        elif kind_of == EventType.EVENT_TYPE_ACTIVITY_TASK_FAILED:
            kind, detail = "activity_failed", failure_type(attributes.failure)
        elif kind_of == EventType.EVENT_TYPE_ACTIVITY_TASK_TIMED_OUT:
            kind, detail = "activity_timed_out", failure_type(attributes.failure)
    elif kind_of in TIMERS:
        kind, detail = "timer", label.removeprefix("timer_")
    elif kind_of == EventType.EVENT_TYPE_WORKFLOW_EXECUTION_COMPLETED:
        kind, detail = "workflow_completed", ""
    elif kind_of == EventType.EVENT_TYPE_WORKFLOW_EXECUTION_FAILED:
        attributes = event.workflow_execution_failed_event_attributes
        kind, detail = "workflow_failed", failure_type(attributes.failure)
    elif kind_of == EventType.EVENT_TYPE_WORKFLOW_EXECUTION_TIMED_OUT:
        kind, detail = "workflow_failed", "timed_out"
    elif kind_of == EventType.EVENT_TYPE_WORKFLOW_EXECUTION_TERMINATED:
        kind, detail = "workflow_failed", "terminated"
    elif kind_of == EventType.EVENT_TYPE_WORKFLOW_EXECUTION_CANCELED:
        kind, detail = "workflow_cancelled", ""
    return RunEvent(
        at=event.event_time.ToDatetime(tzinfo=UTC).isoformat(),
        kind=kind,
        name=bounded(name) if name else None,
        detail=bounded(detail),
    )


@app.get("/api/runs/{run_id}/events", response_model=RunEvents)
async def run_events(run_id: str, client: TemporalClient) -> RunEvents:
    """At most ``MAX_EVENTS`` history events as kinds, activity names and bounded labels."""
    handle = run_handle(client, run_id)
    activities: dict[int, str] = {}
    events: list[RunEvent] = []
    truncated = False
    history = handle.fetch_history_events(page_size=MAX_EVENTS, rpc_timeout=RPC_TIMEOUT)
    async for event in history:
        if len(events) == MAX_EVENTS:
            truncated = True
            break
        events.append(project_event(event, activities))
    return RunEvents(run_id=run_id, events=events, truncated=truncated)


def reports_root() -> Path:
    return get_settings().reports_dir.resolve()


def report_path(name: str) -> Path:
    """A regular file directly inside ``reports_dir``; anything else is not found."""
    if len(name) > 255 or not REPORT_NAME.fullmatch(name):
        raise HTTPException(404, "Report not found")
    root = reports_root()
    try:
        path = (root / name).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise HTTPException(404, "Report not found") from exc
    if path.parent != root or not path.is_file():
        raise HTTPException(404, "Report not found")
    return path


def reject_constant(value: str):
    raise ValueError(f"non-finite number {value}")


def read_report(path: Path, size: int) -> tuple[bytes, dict[str, Any]]:
    """Read and parse one regular-file report object of at most ``size`` bytes.

    Raises ``OSError`` or ``ValueError``; a symlink or special file is never opened for reading.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("report is not a regular file")
        data = stream.read(size + 1)
    if len(data) > size:
        raise ValueError("report grew while reading")
    document = json.loads(data, parse_constant=reject_constant)
    if not isinstance(document, dict):
        raise ValueError("report is not a JSON object")
    return data, document


def text_field(document: dict, key: str, limit: int = 200) -> str | None:
    value = document.get(key)
    return bounded(value, limit) if isinstance(value, str) else None


def count_field(document: dict, key: str) -> int | None:
    value = document.get(key)
    return value if type(value) is int and value >= 0 else None


def summarize_report(document: dict[str, Any]) -> dict[str, Any]:
    """Known fields of an untrusted report; anything of an unexpected type is omitted."""
    rate = document.get("task_success_rate")
    gates = document.get("gates")
    return {
        "status": text_field(document, "status", 64),
        "started_at": text_field(document, "started_at", 64),
        "finished_at": text_field(document, "finished_at", 64),
        "commit": text_field(document, "commit", 100),
        "model": text_field(document, "model"),
        "planned": count_field(document, "planned"),
        "completed": count_field(document, "completed"),
        "task_success_rate": float(rate)
        if type(rate) in (int, float) and math.isfinite(rate)
        else None,
        "unsafe_negatives": count_field(document, "unsafe_negatives"),
        "gates": {
            bounded(key, 64): bounded(value, 64)
            for key, value in list(gates.items())[:32]
            if isinstance(value, str)
        }
        if isinstance(gates, dict)
        else {},
    }


def report_kind(name: str) -> str:
    prefix = name.split("-", 1)[0]
    return prefix if prefix in REPORT_KINDS else "unknown"


@app.get("/api/reports", response_model=ReportList)
def reports() -> ReportList:
    """Newest report files first; one unreadable file never fails the listing."""
    root = reports_root()
    found = []
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                if len(entry.name) > 255 or not REPORT_NAME.fullmatch(entry.name):
                    continue
                try:
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                found.append((info.st_mtime, entry.name, info.st_size))
    except OSError:
        return ReportList(items=[])
    found.sort(reverse=True)
    budget = REPORT_LISTING_BUDGET
    items = []
    for modified, name, size in found[:MAX_REPORTS]:
        fields: dict[str, Any] = {}
        if size > MAX_REPORT_BYTES:
            fields["status"] = "too_large"
        elif size > budget:
            fields["status"] = "not_summarized"
        else:
            budget -= size
            try:
                fields = summarize_report(read_report(root / name, size)[1])
            except (OSError, ValueError, RecursionError):
                fields["status"] = "unreadable"
        items.append(
            ReportSummary(
                name=name,
                kind=report_kind(name),
                bytes=size,
                modified_at=datetime.fromtimestamp(modified, UTC).isoformat(),
                **fields,
            )
        )
    return ReportList(items=items, truncated=len(found) > MAX_REPORTS)


@app.get(
    "/api/reports/{name}",
    response_model=dict[str, Any],
    responses={
        404: {"description": "No such report"},
        413: {"description": "Report exceeds 16 MiB"},
        422: {"description": "Report is not a readable JSON object"},
    },
)
def report(name: str):
    """One report document, validated as a JSON object. Its content is untrusted data."""
    path = report_path(name)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise HTTPException(404, "Report not found") from exc
    if size > MAX_REPORT_BYTES:
        raise HTTPException(413, "Report exceeds 16 MiB")
    try:
        data, _document = read_report(path, size)
    except OSError as exc:
        raise HTTPException(404, "Report not found") from exc
    except (ValueError, RecursionError) as exc:
        raise HTTPException(422, "Report is not a readable JSON object") from exc
    # The validated bytes as stored: no re-encoding of an arbitrarily nested document.
    return Response(content=data, media_type="application/json")
