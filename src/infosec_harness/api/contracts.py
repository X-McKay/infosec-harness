"""Versioned read models shared by OpenAPI and the browser."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

JsonObject = dict[str, JsonValue]


class _OpenPayload(BaseModel):
    """Typed known fields while retaining versioned JSON added by older/newer producers."""

    model_config = ConfigDict(extra="allow")


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


class RunTelemetry(_OpenPayload):
    schema_version: int | None = None
    phase: str | None = None
    accepted_at: str | None = None
    completed_at: str | None = None
    wall_time_s: float | None = None
    agent_time_s: float | None = None
    cost_usd: float | None = None
    known_cost_usd: float | None = None
    accounting_complete: bool | None = None
    cost_accounting_complete: bool | None = None
    known_tokens: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_coverage: float | None = None
    total_tokens: int | None = None


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
    telemetry: RunTelemetry | None
    phase: str


class RunPage(BaseModel):
    items: list[RunSummary]
    total: int
    offset: int
    limit: int
    as_of: str


class BatchSummary(BaseModel):
    id: str
    status: str
    label: str
    source_kind: str
    finding_count: int
    created_at: str


class BatchDetail(BatchSummary):
    budget: JsonObject | None
    status_counts: dict[str, int]
    verdict_counts: dict[str, int]


class RunEvent(BaseModel):
    id: str
    phase: str
    detail: str
    created_at: str


class ReviewRecord(BaseModel):
    reviewer: str = ""
    decision: str
    override_label: str | None = None
    reason: str = ""
    created_at: str


class InvocationRecord(BaseModel):
    agent: str
    model_name: str
    config_hash: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    cost_usd: float | None
    cost_estimated: bool
    latency_s: float
    requests: int
    repeated_tool_calls: dict[str, int]
    tools_called: list[str]
    skills_loaded: list[str]


class RunDetail(RunSummary):
    evidence: JsonObject | None
    events: list[RunEvent]
    review_history: list[ReviewRecord]
    finding: JsonObject
    result: JsonObject | None
    invocations: list[InvocationRecord]
    review: ReviewRecord | None


class ExperimentSummary(BaseModel):
    id: str
    agent: str
    dataset: str
    dataset_version: str
    git_sha: str
    overlay: str
    repetitions: int
    metrics: JsonObject
    config_hash: str
    git_dirty: bool
    model_name: str
    backend: str
    pricing: str
    harness_version: str
    created_at: str


class ExperimentCase(BaseModel):
    case_name: str
    repetition: int
    passed: bool
    scores: JsonObject
    cost_usd: float | None
    latency_s: float | None


class ExperimentDetail(BaseModel):
    id: str
    agent: str
    metrics: JsonObject
    cases: list[ExperimentCase]


class AgentConfig(BaseModel):
    name: str
    model_tier: str
    config_hash: str
    resolved_model: str


class ConfigResponse(BaseModel):
    model_mode: str
    agents: list[AgentConfig]


class BatchAccepted(BaseModel):
    batch_id: str


class AdoBatchAccepted(BatchAccepted):
    imported: int


class ReviewSaved(BaseModel):
    ok: bool


class HealthResponse(BaseModel):
    status: str


class CancelResponse(BaseModel):
    status: str


GateStatus = Literal["passed", "failed", "not_checked"]


class BrokerStatus(BaseModel):
    configured: bool
    status: GateStatus
    checked_at: str | None = None
    stale: bool = True
    unresolved_requests: int | None = None
    detail: str


class RuntimeStatus(BaseModel):
    environment: str
    model_mode: str
    assessment_transport: str
    api_source_commit: str | None = None
    as_of: str
    database_backend: str
    temporal_mode: str
    broker: BrokerStatus


class QualifiedComponent(BaseModel):
    agent: str
    scope: str
    status: GateStatus
    measured_commit: str | None = None
    freshness: Literal["fresh", "reused", "stale", "unavailable"]
    reason: str
    cases: int | None = None
    passed_cases: int | None = None


class QualificationStatus(BaseModel):
    as_of: str
    candidate_commit: str | None = None
    status: GateStatus
    detail: str
    components: list[QualifiedComponent]
    limitations: list[str]
