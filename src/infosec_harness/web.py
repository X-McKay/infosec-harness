"""Small HTTP projection of Temporal investigations; no duplicate job database."""

from __future__ import annotations

import base64
import binascii
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Annotated
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
from temporalio.api.workflowservice.v1 import GetSystemInfoRequest
from temporalio.client import Client, WorkflowExecutionStatus
from temporalio.common import WorkflowIDReusePolicy
from temporalio.service import RPCError, RPCStatusCode

from infosec_harness.config import get_settings
from infosec_harness.models import (
    Finding,
    InvestigationRequest,
    InvestigationResult,
    RunPage,
    RunState,
    RunSummary,
)
from infosec_harness.services import temporal_connection_options

WORKFLOW = "InvestigationWorkflow"
PREFIX = "investigate-v9-"
RPC_TIMEOUT = timedelta(seconds=10)


async def connect() -> Client:
    settings = get_settings()
    return await Client.connect(
        settings.temporal_address,
        namespace=settings.temporal_namespace,
        plugins=[PydanticAIPlugin()],
        **temporal_connection_options(settings),
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
    from fastapi.responses import JSONResponse

    status = 404 if exc.status == RPCStatusCode.NOT_FOUND else 503
    return JSONResponse(
        status_code=status,
        content={
            "detail": "Investigation not found" if status == 404 else "Workflow service unavailable"
        },
    )


@app.get("/api/health")
async def health(client: TemporalClient) -> dict[str, str]:
    await client.workflow_service.get_system_info(
        GetSystemInfoRequest(),
        timeout=RPC_TIMEOUT,
    )
    return {"status": "control_plane_ready", "runtime": "not_checked", "generation": "v9"}


@app.post("/api/runs", response_model=RunState, status_code=202)
async def submit(finding: Finding, client: TemporalClient) -> RunState:
    settings = get_settings()
    run_id = PREFIX + uuid4().hex
    request = InvestigationRequest(finding=finding, limits=settings.limits)
    await client.start_workflow(
        WORKFLOW,
        request,
        id=run_id,
        task_queue=settings.task_queue,
        id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
        memo={"finding": finding.model_dump(mode="json")},
        rpc_timeout=RPC_TIMEOUT,
    )
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
        f"WorkflowType = '{WORKFLOW}'", page_size=50, next_page_token=token, rpc_timeout=RPC_TIMEOUT
    )
    await iterator.fetch_next_page()
    items = []
    for entry in iterator.current_page:
        memo = await entry.memo()
        finding = memo.get("finding", {})
        items.append(
            RunSummary(
                id=entry.id,
                title=str(finding.get("title", entry.id)),
                status=entry.status.name.lower() if entry.status else "unknown",
                started_at=entry.start_time.isoformat(),
                closed_at=entry.close_time.isoformat() if entry.close_time else None,
            )
        )
    following = (
        base64.b64encode(iterator.next_page_token).decode() if iterator.next_page_token else None
    )
    return RunPage(items=items, next_page_token=following)


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
