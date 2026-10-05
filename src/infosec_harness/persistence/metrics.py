"""Whole-population metrics. Missing measurements never become zeros.

Nearest-rank percentiles include known observations only; coverage always reports the
full filtered population, including active, failed and cancelled runs.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import UTC, datetime
from statistics import mean

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import load_only

from infosec_harness.persistence import db
from infosec_harness.persistence.population import Population, run_population
from infosec_harness.persistence.run_telemetry import MetricField, RunTelemetry


class Bin(BaseModel):
    lower: float
    upper: float
    count: int


class Distribution(BaseModel):
    count: int
    population: int
    coverage: float | None
    mean: float | None = None
    p50: float | None = None
    p95: float | None = None
    maximum: float | None = None
    bins: list[Bin] = Field(default_factory=list)


class TrendPoint(BaseModel):
    date: str
    runs: int
    tokens: float | None
    cost_usd: float | None
    wall_time_s: float | None


class StageMetric(BaseModel):
    agent: str
    invocations: int
    agent_time_s: float
    tokens: int
    known_cost_usd: float
    cost_coverage: float


class MetricsResponse(BaseModel):
    schema_version: int = 1
    as_of: str
    population: str
    total_runs: int
    status_counts: dict[str, int]
    verdict_counts: dict[str, int]
    tokens: Distribution
    input_tokens: Distribution
    output_tokens: Distribution
    cost_usd: Distribution
    wall_time_s: Distribution
    agent_time_s: Distribution
    trends: list[TrendPoint]
    stages: list[StageMetric]
    definitions: dict[str, str]


def distribution(values: list[float | None], bins: int = 12) -> Distribution:
    known = sorted(float(v) for v in values if v is not None and math.isfinite(v) and v >= 0)
    result = Distribution(count=len(known), population=len(values),
                          coverage=len(known) / len(values) if values else None)
    if not known:
        return result
    result.mean = mean(known)
    result.p50 = known[math.ceil(len(known) * .5) - 1]
    result.p95 = known[math.ceil(len(known) * .95) - 1]
    result.maximum = known[-1]
    width = (known[-1] or 1) / bins
    counts = [0] * bins
    for value in known:
        counts[min(int(value / width), bins - 1)] += 1
    result.bins = [Bin(lower=i * width, upper=(i + 1) * width, count=n)
                   for i, n in enumerate(counts)]
    return result


def _value(telemetry: RunTelemetry | None, field: MetricField) -> float | None:
    value = getattr(telemetry, field) if telemetry is not None else None
    return float(value) if value is not None and math.isfinite(value) else None


async def aggregate_metrics(*, batch_id: str | None = None, population: Population = "operational",
                            since: datetime | None = None, until: datetime | None = None) -> MetricsResponse:
    statement = select(db.TriageRun).where(run_population(population))
    if batch_id:
        statement = statement.where(db.TriageRun.batch_id == batch_id)
    if since:
        statement = statement.where(db.TriageRun.created_at >= since)
    if until:
        statement = statement.where(db.TriageRun.created_at < until)
    async with db.session() as session:
        # Never hydrate findings, output evidence or repository content for aggregates.
        rows = (await session.execute(statement.options(load_only(
            db.TriageRun.id, db.TriageRun.status, db.TriageRun.verdict,
            db.TriageRun.created_at, db.TriageRun.telemetry)))).scalars().all()
        selected_ids = statement.with_only_columns(db.TriageRun.id)
        invocations = (await session.execute(select(db.AgentInvocation).where(
            db.AgentInvocation.run_id.in_(selected_ids)).options(load_only(
                db.AgentInvocation.agent, db.AgentInvocation.latency_s,
                db.AgentInvocation.input_tokens, db.AgentInvocation.output_tokens,
                db.AgentInvocation.cost_usd)))).scalars().all()
    telemetry = {row.id: RunTelemetry.read(row.telemetry) for row in rows}
    days: dict[str, list[db.TriageRun]] = defaultdict(list)
    for row in rows:
        days[row.created_at.date().isoformat()].append(row)

    def values(group: list[db.TriageRun], key: MetricField) -> list[float | None]:
        return [_value(telemetry[r.id], key) for r in group]

    def day_mean(group: list[db.TriageRun], key: MetricField) -> float | None:
        known = [v for v in values(group, key) if v is not None]
        return mean(known) if known else None
    stages: dict[str, list[db.AgentInvocation]] = defaultdict(list)
    for inv in invocations:
        stages[inv.agent].append(inv)
    return MetricsResponse(
        as_of=datetime.now(UTC).isoformat(), population=population, total_runs=len(rows),
        status_counts=dict(Counter(r.status for r in rows)),
        verdict_counts=dict(Counter(r.verdict or "unassessed" for r in rows)),
        tokens=distribution(values(rows, "total_tokens")),
        input_tokens=distribution(values(rows, "input_tokens")),
        output_tokens=distribution(values(rows, "output_tokens")),
        cost_usd=distribution(values(rows, "cost_usd")),
        wall_time_s=distribution(values(rows, "wall_time_s")),
        agent_time_s=distribution(values(rows, "agent_time_s")),
        trends=[TrendPoint(date=day, runs=len(group), tokens=day_mean(group, "total_tokens"),
                    cost_usd=day_mean(group, "cost_usd"), wall_time_s=day_mean(group, "wall_time_s"))
                for day, group in sorted(days.items())],
        stages=[StageMetric(agent=name, invocations=len(group),
                    agent_time_s=sum(i.latency_s for i in group),
                    tokens=sum(i.input_tokens + i.output_tokens for i in group),
                    known_cost_usd=sum(i.cost_usd for i in group if i.cost_usd is not None),
                    cost_coverage=sum(i.cost_usd is not None for i in group) / len(group))
                for name, group in sorted(stages.items())],
        definitions={"percentiles": "Nearest rank over observed values; UTC days; until is exclusive.",
            "coverage": "Observed values / all selected runs, including active, failed and cancelled.",
            "cost": "Only runs with complete invocation cost enter cost mean; unknown is not zero.",
            "time": "Wall time is acceptance to terminal. Agent time sums calls and can overlap.",
            "preparation": "Shared preparation is attributed once, to the first finding in each repository group."})
