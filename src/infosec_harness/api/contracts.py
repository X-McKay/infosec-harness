"""Versioned read models shared by OpenAPI and the browser."""
from __future__ import annotations

from pydantic import BaseModel, Field


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


class RunSummary(BaseModel):
    id: str
    batch_id: str
    fingerprint: str
    title: str
    repo_url: str
    revision: str
    cwe: str | None
    severity: str
    status: str
    verdict: str | None
    confidence: float | None
    inconclusive_reason: str | None
    priority: str | None
    priority_score: float | None
    environment_scope: str
    early_exit: str | None
    cost_usd: float | None
    total_tokens: int
    cache_read_tokens: int
    latency_s: float
    created_at: str
    telemetry: dict | None
    phase: str


class RunPage(BaseModel):
    items: list[RunSummary]
    total: int
    offset: int
    limit: int
    as_of: str
