"""FastAPI service: submit findings, read results, post reviews, browse experiments.

The CLI and the React app both use this API; the OpenAPI schema it emits generates the
front-end's typed client.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from importlib.metadata import PackageNotFoundError, version
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from infosec_harness.api.contracts import (
    AdoBatchAccepted,
    BatchAccepted,
    BatchDetail,
    BatchSummary,
    CancelResponse,
    ConfigResponse,
    ExperimentSummary,
    HealthResponse,
    ReviewSaved,
    RunDetail,
    RunSummary,
)
from infosec_harness.api.observations import router
from infosec_harness.api.status import router as status_router
from infosec_harness.domain.models import FindingInput, VerdictLabel
from infosec_harness.persistence import db, store
from infosec_harness.persistence.population import Population, experiment_population
from infosec_harness.settings import get_settings

SubmissionMode = Literal["local", "temporal"]


def _api_version() -> str:
    try:
        return version("infosec-harness")
    except PackageNotFoundError:  # pragma: no cover - editable/test installs have metadata
        return "0.0.0"


class SubmitRequest(BaseModel):
    findings: list[FindingInput]
    label: str = ""
    # `local` is stub-only test and development scaffolding; real assessments are durable.
    mode: SubmissionMode = "temporal"


class SubmitADORequest(BaseModel):
    work_item_ids: list[int]
    label: str = ""


class ReviewRequest(BaseModel):
    reviewer: str = ""
    decision: Literal["confirm", "override"]
    override_label: VerdictLabel | None = None
    reason: str = ""


@asynccontextmanager
async def lifespan(app: FastAPI):
    from infosec_harness import telemetry

    telemetry.configure("api")
    await db.create_all()
    from infosec_harness.workflows.submission import reconcile_submissions
    async def reconcile_loop() -> None:
        while True:
            try:
                await reconcile_submissions()
            except Exception:
                logging.getLogger(__name__).exception("Submission reconciliation failed; retrying")
            await asyncio.sleep(30)
    task = asyncio.create_task(reconcile_loop())
    try:
        yield
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


app = FastAPI(title="InfoSec Harness", version=_api_version(), lifespan=lifespan)

app.include_router(router)
app.include_router(status_router)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


async def _submit(findings: list[FindingInput], label: str, mode: SubmissionMode) -> str:
    if mode == "local":
        from infosec_harness.workflows.local_run import LocalModeUnavailable, run_local

        try:
            batch_id, _ = await run_local(findings, label=label)
        except LocalModeUnavailable as exc:
            raise HTTPException(422, str(exc)) from exc
        return batch_id
    from infosec_harness.workflows.submission import submit_via_temporal

    return await submit_via_temporal(findings, label=label)


@app.post("/api/batches", response_model=BatchAccepted)
async def submit(req: SubmitRequest) -> BatchAccepted:
    if not req.findings:
        raise HTTPException(400, "no findings supplied")
    batch_id = await _submit(req.findings, req.label, req.mode)
    return BatchAccepted(batch_id=batch_id)


@app.post("/api/batches/ado", response_model=AdoBatchAccepted)
async def submit_ado(req: SubmitADORequest) -> AdoBatchAccepted:
    from infosec_harness.integrations import ado

    s = get_settings()
    if not s.ado_org_url:
        raise HTTPException(400, "Azure DevOps is not configured")
    items = await ado.fetch_work_items(req.work_item_ids)
    findings = [ado.work_item_to_finding(i, s.ado_field_map) for i in items]
    batch_id = await _submit(findings, req.label or "ado", "temporal")
    return AdoBatchAccepted(batch_id=batch_id, imported=len(findings))


@app.get("/api/batches", response_model=list[BatchSummary])
async def batches(population: Population | None = None) -> list[BatchSummary]:
    from infosec_harness.api.batch_progress import batch_progress

    summaries = await store.list_batches(population=population)
    progress = await batch_progress([row["id"] for row in summaries], population)
    return [{**row, **progress[row["id"]]} for row in summaries]


@app.get("/api/batches/{batch_id}", response_model=BatchDetail)
async def batch(batch_id: str, population: Population | None = None) -> BatchDetail:
    summary = await store.batch_summary(batch_id, population)
    if summary is None:
        raise HTTPException(404, "batch not found")
    return summary


@app.get("/api/runs", response_model=list[RunSummary])
async def runs(batch_id: str | None = None, verdict: str | None = None,
               limit: int = Query(200, ge=1, le=1000), population: Population | None = None) -> list[RunSummary]:
    return await store.list_runs(batch_id=batch_id, verdict=verdict, limit=limit,
                                 population=population)


@app.get("/api/runs/{run_id}", response_model=RunDetail)
async def run(run_id: str, population: Population | None = None) -> RunDetail:
    detail = await store.get_run(run_id, population)
    if detail is None:
        raise HTTPException(404, "run not found")
    return detail


@app.post("/api/runs/{run_id}/review", response_model=ReviewSaved)
async def review(run_id: str, req: ReviewRequest) -> ReviewSaved:
    if req.decision == "override" and req.override_label is None:
        raise HTTPException(400, "override requires override_label")
    ok = await store.save_review(run_id, reviewer=req.reviewer, decision=req.decision,
                                 override_label=req.override_label.value if req.override_label else None,
                                 reason=req.reason)
    if not ok:
        raise HTTPException(404, "run not found")
    return ReviewSaved(ok=True)


@app.get("/api/experiments", response_model=list[ExperimentSummary])
async def experiments(population: Population | None = None) -> list[ExperimentSummary]:
    from sqlalchemy import select

    async with db.session() as s:
        statement = select(db.EvalExperiment)
        if population is not None:
            statement = statement.where(experiment_population(population))
        rows = (await s.execute(statement.order_by(db.EvalExperiment.created_at.desc()).limit(100))).scalars().all()
        return [{"id": e.id, "agent": e.agent, "dataset": e.dataset, "dataset_version": e.dataset_version,
                 "git_sha": e.git_sha, "overlay": e.overlay, "repetitions": e.repetitions,
                 "metrics": e.metrics, "config_hash": e.config_hash, "git_dirty": e.git_dirty,
                 "model_name": e.model_name, "backend": e.backend, "pricing": e.pricing,
                 "harness_version": e.harness_version, "created_at": e.created_at.isoformat()} for e in rows]


@app.get("/api/config", response_model=ConfigResponse)
async def config() -> ConfigResponse:
    from infosec_harness.agents.registry import resolved_agent_configs

    agents = [{"name": name, "model_tier": cfg.model.requested_model,
               "config_hash": cfg.digest, "resolved_model": cfg.model.resolved_model}
              for name, cfg in resolved_agent_configs().items()]
    return {"model_mode": get_settings().model_mode, "agents": agents}


@app.get("/api/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post("/api/batches/{batch_id}/cancel", response_model=CancelResponse)
async def cancel_batch(batch_id: str) -> CancelResponse:
    from infosec_harness.workflows.submission import cancel_durable_batch
    try:
        return CancelResponse(status=await cancel_durable_batch(batch_id))
    except KeyError as exc:
        raise HTTPException(404, "batch not found") from exc
