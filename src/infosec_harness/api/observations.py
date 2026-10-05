"""Read-only paginated findings and evaluations, and complete metrics."""
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query

from infosec_harness.api.contracts import ExperimentDetail, ExperimentPage, RunPage
from infosec_harness.persistence import store
from infosec_harness.persistence.metrics import MetricsResponse, aggregate_metrics
from infosec_harness.persistence.population import Population
from infosec_harness.persistence.run_telemetry import MetricField

router = APIRouter(prefix="/api")


@router.get("/run-page", response_model=RunPage)
async def run_page(batch_id: str | None = None, verdict: str | None = None,
                   population: Population | None = None,
                   metric: MetricField | None = None,
                   lower: float | None = None, upper: float | None = None,
                   upper_inclusive: bool = False,
                   search: str = "", offset: int = Query(0, ge=0),
                   limit: int = Query(50, ge=1, le=200)) -> RunPage:
    try:
        return await store.run_page(offset=offset, limit=limit, batch_id=batch_id,
                                    verdict=verdict, population=population, metric=metric,
                                    lower=lower, upper=upper, upper_inclusive=upper_inclusive,
                                    search=search)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/metrics", response_model=MetricsResponse)
async def metrics(batch_id: str | None = None,
                  population: Population = "operational",
                  since: datetime | None = None, until: datetime | None = None) -> MetricsResponse:
    if since and until and since >= until:
        raise HTTPException(422, "since must precede until")
    return await aggregate_metrics(batch_id=batch_id, population=population, since=since, until=until)


@router.get("/experiments", response_model=ExperimentPage)
async def experiments(population: Population | None = None, offset: int = Query(0, ge=0),
                      limit: int = Query(50, ge=1, le=100)) -> ExperimentPage:
    """Newest first. Summaries carry headline measurements; full metrics are per experiment."""
    return await store.experiment_page(offset=offset, limit=limit, population=population)


@router.get("/experiments/{experiment_id}", response_model=ExperimentDetail)
async def experiment_detail(experiment_id: str, population: Population | None = None) -> ExperimentDetail:
    detail = await store.experiment_detail(experiment_id, population)
    if detail is None:
        raise HTTPException(404, "experiment not found")
    return detail
