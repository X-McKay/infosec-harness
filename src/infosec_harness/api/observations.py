"""Read-only paginated findings, complete metrics, and evaluation observations."""
from datetime import UTC, datetime
from math import isfinite
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, or_, select

from infosec_harness.api.contracts import ExperimentDetail, MetricsResponse, RunPage
from infosec_harness.persistence import db, store
from infosec_harness.persistence.metrics import aggregate_metrics
from infosec_harness.persistence.population import (
    Population,
    experiment_population,
    run_population,
)

router = APIRouter(prefix="/api")


@router.get("/run-page", response_model=RunPage)
async def run_page(batch_id: str | None = None, verdict: str | None = None,
                   population: Population | None = None,
                   metric: Literal["total_tokens", "input_tokens", "output_tokens", "cost_usd", "wall_time_s"] | None = None,
                   lower: float | None = None, upper: float | None = None,
                   upper_inclusive: bool = False,
                   search: str = "", offset: int = Query(0, ge=0),
                   limit: int = Query(50, ge=1, le=200)) -> RunPage:
    if any(value is not None and (not isfinite(value) or value < 0) for value in (lower, upper)):
        raise HTTPException(422, "Metric bounds must be finite and non-negative")
    if lower is not None and upper is not None and lower > upper:
        raise HTTPException(422, "lower must not exceed upper")
    if metric is None and (lower is not None or upper is not None):
        raise HTTPException(422, "metric is required with distribution bounds")
    statement = select(db.TriageRun)
    if population is not None:
        statement = statement.where(run_population(population))
    if metric:
        value = db.TriageRun.telemetry[metric].as_float()
        statement = statement.where(value.is_not(None))
        if lower is not None:
            statement = statement.where(value >= lower)
        if upper is not None:
            statement = statement.where(value <= upper if upper_inclusive else value < upper)
    if batch_id:
        statement = statement.where(db.TriageRun.batch_id == batch_id)
    if verdict:
        statement = statement.where(db.TriageRun.verdict == verdict)
    if search:
        statement = statement.where(or_(*(field.icontains(search, autoescape=True) for field in (db.TriageRun.title, db.TriageRun.cwe, db.TriageRun.repo_url))))
    async with db.session() as session:
        total = await session.scalar(select(func.count()).select_from(statement.subquery()))
        rows = (await session.execute(statement.order_by(db.TriageRun.priority_score.desc().nullslast(), db.TriageRun.created_at.desc(), db.TriageRun.id)
                                      .offset(offset).limit(limit))).scalars().all()
    return RunPage(items=[store.run_summary(r) for r in rows], total=total or 0,
                   offset=offset, limit=limit, as_of=datetime.now(UTC).isoformat())


@router.get("/metrics", response_model=MetricsResponse)
async def metrics(batch_id: str | None = None,
                  population: Population = "operational",
                  since: datetime | None = None, until: datetime | None = None) -> MetricsResponse:
    if since and until and since >= until:
        raise HTTPException(422, "since must precede until")
    return await aggregate_metrics(batch_id=batch_id, population=population, since=since, until=until)


@router.get("/experiments/{experiment_id}", response_model=ExperimentDetail)
async def experiment_detail(experiment_id: str, population: Population | None = None) -> ExperimentDetail:
    async with db.session() as session:
        statement = select(db.EvalExperiment).where(db.EvalExperiment.id == experiment_id)
        if population is not None:
            statement = statement.where(experiment_population(population))
        experiment = await session.scalar(statement)
        if experiment is None:
            raise HTTPException(404, "experiment not found")
        cases = (await session.execute(select(db.EvalCaseResult).where(
            db.EvalCaseResult.experiment_id == experiment_id).order_by(db.EvalCaseResult.id))).scalars().all()
    return {"id": experiment.id, "agent": experiment.agent, "metrics": experiment.metrics,
            "cases": [{"case_name": c.case_name, "repetition": c.repetition,
                       "passed": c.passed, "scores": c.scores,
                       "cost_usd": c.scores.get("cost_usd") if "cost_status" in c.scores else None,
                       "latency_s": c.latency_s if "outcome" in c.scores else None} for c in cases]}
