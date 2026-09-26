"""FastAPI service: submit findings, read results, post reviews, browse experiments.

The CLI and the React app both use this API; the OpenAPI schema it emits generates the
front-end's typed client.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from infosec_harness.domain.models import FindingInput, VerdictLabel
from infosec_harness.persistence import db, store
from infosec_harness.settings import get_settings


class SubmitRequest(BaseModel):
    findings: list[FindingInput]
    label: str = ""
    mode: str = "auto"  # auto -> temporal if reachable else local; or "local"/"temporal"


class SubmitADORequest(BaseModel):
    work_item_ids: list[int]
    label: str = ""


class ReviewRequest(BaseModel):
    reviewer: str = ""
    decision: str  # confirm | override
    override_label: VerdictLabel | None = None
    reason: str = ""


@asynccontextmanager
async def lifespan(app: FastAPI):
    from infosec_harness import telemetry

    telemetry.configure("api")
    await db.create_all()
    yield


app = FastAPI(title="InfoSec Harness", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


async def _submit(findings: list[FindingInput], label: str, mode: str) -> str:
    from infosec_harness.workflows import runner

    if mode == "local":
        batch_id, _ = await runner.run_local(findings, label=label)
        return batch_id
    return await runner.submit_via_temporal(findings, label=label)


@app.post("/api/batches")
async def submit(req: SubmitRequest) -> dict:
    if not req.findings:
        raise HTTPException(400, "no findings supplied")
    batch_id = await _submit(req.findings, req.label, req.mode)
    return {"batch_id": batch_id}


@app.post("/api/batches/ado")
async def submit_ado(req: SubmitADORequest) -> dict:
    from infosec_harness.integrations import ado

    s = get_settings()
    if not s.ado_org_url:
        raise HTTPException(400, "Azure DevOps is not configured")
    items = await ado.fetch_work_items(req.work_item_ids)
    findings = [ado.work_item_to_finding(i, s.ado_field_map) for i in items]
    batch_id = await _submit(findings, req.label or "ado", "auto")
    return {"batch_id": batch_id, "imported": len(findings)}


@app.get("/api/batches")
async def batches() -> list[dict]:
    return await store.list_batches()


@app.get("/api/batches/{batch_id}")
async def batch(batch_id: str) -> dict:
    summary = await store.batch_summary(batch_id)
    if summary is None:
        raise HTTPException(404, "batch not found")
    return summary


@app.get("/api/runs")
async def runs(batch_id: str | None = None, verdict: str | None = None, limit: int = 200) -> list[dict]:
    return await store.list_runs(batch_id=batch_id, verdict=verdict, limit=limit)


@app.get("/api/runs/{run_id}")
async def run(run_id: str) -> dict:
    detail = await store.get_run(run_id)
    if detail is None:
        raise HTTPException(404, "run not found")
    return detail


@app.post("/api/runs/{run_id}/review")
async def review(run_id: str, req: ReviewRequest) -> dict:
    if req.decision not in ("confirm", "override"):
        raise HTTPException(400, "decision must be 'confirm' or 'override'")
    if req.decision == "override" and req.override_label is None:
        raise HTTPException(400, "override requires override_label")
    ok = await store.save_review(run_id, reviewer=req.reviewer, decision=req.decision,
                                 override_label=req.override_label.value if req.override_label else None,
                                 reason=req.reason)
    if not ok:
        raise HTTPException(404, "run not found")
    return {"ok": True}


@app.get("/api/experiments")
async def experiments() -> list[dict]:
    from sqlalchemy import select

    async with db.session() as s:
        rows = (await s.execute(
            select(db.EvalExperiment).order_by(db.EvalExperiment.created_at.desc()).limit(100))).scalars().all()
        return [{"id": e.id, "agent": e.agent, "dataset": e.dataset, "dataset_version": e.dataset_version,
                 "git_sha": e.git_sha, "overlay": e.overlay, "repetitions": e.repetitions,
                 "metrics": e.metrics, "created_at": e.created_at.isoformat()} for e in rows]


@app.get("/api/config")
async def config() -> dict:
    from infosec_harness.agents import models as model_factory
    from infosec_harness.agents.registry import AGENT_BINDINGS, agent_config_hashes, load_spec

    agents = []
    for name in AGENT_BINDINGS:
        spec = load_spec(name)
        agents.append({"name": name, "model_tier": spec.model,
                       "config_hash": agent_config_hashes()[name],
                       "resolved_model": model_factory.resolved_model_name(name, spec.model or "sonnet")})
    return {"model_mode": get_settings().model_mode, "agents": agents}


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok"}
