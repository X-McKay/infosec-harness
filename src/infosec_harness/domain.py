"""Stable, provider-neutral domain contracts.  These models contain no authority."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TerminalState(StrEnum):
    COMPLETE = "complete"
    MALFORMED_MODEL_OUTPUT = "malformed_model_output"
    PROVIDER_REFUSAL = "provider_refusal"
    POLICY_BLOCKED = "policy_blocked"
    BUDGET_EXHAUSTED = "budget_exhausted"
    INFRA_ERROR = "infra_error"
    CANCELLED = "cancelled"
    RESTRICTED_EVIDENCE = "restricted_evidence"
    AUTHORIZATION_FAILED = "authorization_failed"


class WorkflowState(StrEnum):
    CREATED = "created"
    PREFLIGHTED = "preflighted"
    PLANNED = "planned"
    INVESTIGATING = "investigating"
    ADJUDICATING = "adjudicating"
    REVIEW_REQUIRED = "review_required"
    COMPLETE = "complete"


class DispositionKind(StrEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNLIKELY = "unlikely"
    FALSE_POSITIVE = "false_positive"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    NEEDS_REVIEW = "needs_review"


class Location(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)


class Citation(Location):
    reason: str = Field(min_length=1, max_length=600)


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_id: str
    rule_id: str
    level: str
    message: str
    locations: list[Location]
    code_flow: list[Location] = Field(default_factory=list)
    fingerprints: dict[str, str] = Field(default_factory=dict)
    suppressions: list[dict[str, Any]] = Field(default_factory=list)
    scanner: dict[str, Any]
    revision: str | None = None
    raw_artifact: str
    occurrence_count: int = Field(default=1, ge=1)
    occurrence_artifacts: list[str] = Field(default_factory=list)


class EvidenceSlice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_id: str
    revision: str
    locations: list[Location]
    excerpts: list[dict[str, Any]]
    provenance: dict[str, str]
    coverage: list[str]
    deferred_surfaces: list[str]
    proof_gaps: list[str]


class Disposition(BaseModel):
    """Visible structured conclusion; never a provider's hidden reasoning."""

    model_config = ConfigDict(extra="forbid")
    disposition: DispositionKind
    confidence: float = Field(ge=0, le=1)
    summary: str = Field(min_length=1, max_length=2000)
    supporting: list[Citation] = Field(default_factory=list)
    counter: list[Citation] = Field(default_factory=list)
    proof_gaps: list[str] = Field(default_factory=list)
    human_review_required: bool


class Usage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cache_read_tokens: int = Field(default=0, ge=0)


class Budget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_input_tokens: int = Field(default=4000, ge=1)
    max_output_tokens: int = Field(default=1000, ge=1)
    max_cost_usd: float = Field(default=1.0, ge=0)
    max_tool_calls: int = Field(default=20, ge=0)


class AuthorizationManifest(BaseModel):
    """Controller-authored scope; repository and model content cannot amend it."""

    model_config = ConfigDict(extra="forbid")
    schema_version: int = 1
    engagement_id: str = Field(min_length=1)
    target_repository: str = Field(min_length=1)
    revision: str = Field(min_length=1)
    paths: list[str] = Field(min_length=1)
    allowed_actions: list[str] = Field(min_length=1)
    expires_at: datetime
    requested_by: str = Field(min_length=1)
    signature: str = Field(min_length=32)


class ModelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str
    system: str
    evidence: EvidenceSlice
    output_schema: dict[str, Any]
    budget: Budget
    provider_options: dict[str, Any] = Field(default_factory=dict)


class ModelResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    visible_output: dict[str, Any]
    usage: Usage
    provider: str
    model_version: str
    provider_request_id: str | None = None
    replay_fixture_id: str | None = None


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision_id: str
    allowed: bool
    action: str
    reason: str
    subject_hash: str


class EgressPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str
    expires_at: datetime
    default_deny: bool = True
    allowed_edges: list[str] = Field(default_factory=list)
    signature: str


class NetworkEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str
    verdict: str
    collector_health: bool
    observed_at: datetime
    detail: str


class TelemetryEvent(BaseModel):
    """Redacted controller event contract; payload bodies are artifact references only."""

    model_config = ConfigDict(extra="forbid")
    event_type: str
    run_id: str
    at: datetime
    fields: dict[str, Any] = Field(default_factory=dict)


class SecurityContextBundle(BaseModel):
    """Pinned context shape for a future reviewed connector; no live connector is enabled."""

    model_config = ConfigDict(extra="forbid")
    bundle_id: str
    as_of: datetime
    expires_at: datetime
    facts: list[dict[str, Any]] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)


class RunSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str
    terminal_state: TerminalState
    workflow_state: WorkflowState
    revision: str
    authorization_hash: str
    backend: str
    dependency_closure_hash: str
    model_provenance: list[dict[str, str | None]]
    findings: list[Finding]
    evidence: list[EvidenceSlice]
    dispositions: list[Disposition]
    policy_decisions: list[PolicyDecision]
    coverage: list[str]
    deferred_surfaces: list[str]
    safety_summary: dict[str, Any]
    usage: Usage
    reserved_cost_usd: float
    estimated_cost_usd: float
    artifact_hashes: list[str]
    created_at: datetime
    error_class: str | None = None
