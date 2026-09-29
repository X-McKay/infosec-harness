"""SQLAlchemy models and async engine/session for the run store (§9).

Pydantic models are the source of truth; JSONB columns hold ``model_dump()`` output and SQL
columns hold what we filter and aggregate on.
"""

from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from infosec_harness.settings import get_settings


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Batch(Base):
    __tablename__ = "batches"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    source_kind: Mapped[str] = mapped_column(String(32), default="generic_json")
    label: Mapped[str] = mapped_column(String(256), default="")
    status: Mapped[str] = mapped_column(String(32), default="running")
    workflow_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    runs: Mapped[list[TriageRun]] = relationship(back_populates="batch")


class TriageRun(Base):
    __tablename__ = "triage_runs"
    __table_args__ = (UniqueConstraint("batch_id", "fingerprint", name="uq_batch_fingerprint"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("batches.id"))
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    repo_url: Mapped[str] = mapped_column(Text)
    revision: Mapped[str] = mapped_column(String(255))
    title: Mapped[str] = mapped_column(Text, default="")
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="unknown")
    status: Mapped[str] = mapped_column(String(32), default="pending")
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    inconclusive_reason: Mapped[str | None] = mapped_column(String(48), nullable=True)
    priority: Mapped[str | None] = mapped_column(String(4), nullable=True, index=True)
    priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    environment_scope: Mapped[str] = mapped_column(String(16), default="none")
    early_exit: Mapped[str | None] = mapped_column(String(48), nullable=True)
    finding: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_read_tokens: Mapped[int] = mapped_column(Integer, default=0)
    latency_s: Mapped[float] = mapped_column(Float, default=0.0)

    batch: Mapped[Batch] = relationship(back_populates="runs")
    invocations: Mapped[list[AgentInvocation]] = relationship(back_populates="run")
    review: Mapped[VerdictReview | None] = relationship(back_populates="run", uselist=False)


class AgentInvocation(Base):
    __tablename__ = "agent_invocations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("triage_runs.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    agent: Mapped[str] = mapped_column(String(48), index=True)
    model_name: Mapped[str] = mapped_column(String(128), default="")
    config_hash: Mapped[str] = mapped_column(String(32), default="")
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_read_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_write_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    cost_estimated: Mapped[bool] = mapped_column(default=True)
    latency_s: Mapped[float] = mapped_column(Float, default=0.0)
    tools_called: Mapped[list] = mapped_column(JSON, default=list)
    skills_loaded: Mapped[list] = mapped_column(JSON, default=list)
    run: Mapped[TriageRun] = relationship(back_populates="invocations")


class VerdictReview(Base):
    __tablename__ = "verdict_reviews"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("triage_runs.id"), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    reviewer: Mapped[str] = mapped_column(String(128), default="")
    decision: Mapped[str] = mapped_column(String(16))  # confirm | override
    override_label: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    run: Mapped[TriageRun] = relationship(back_populates="review")


class AdoSync(Base):
    __tablename__ = "ado_sync"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("triage_runs.id"), unique=True)
    work_item_id: Mapped[int] = mapped_column(Integer)
    comment_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    payload_hash: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvalExperiment(Base):
    __tablename__ = "eval_experiments"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    agent: Mapped[str] = mapped_column(String(48), index=True)
    dataset: Mapped[str] = mapped_column(String(128))
    dataset_version: Mapped[str] = mapped_column(String(32), default="")
    git_sha: Mapped[str] = mapped_column(String(40), default="")
    # A SHA alone cannot say whether the tree matched it. Without this, a run over uncommitted
    # edits is stored as if it measured the commit, and no later reader can tell.
    git_dirty: Mapped[bool] = mapped_column(default=False)
    harness_version: Mapped[str] = mapped_column(String(32), default="")
    overlay: Mapped[str] = mapped_column(String(256), default="")
    config_hash: Mapped[str] = mapped_column(String(32), default="")
    # The model, as its own columns rather than only inside `config_hash`. Comparing models is
    # the main reason to run the same dataset twice, and a hash cannot be grouped by, filtered
    # on, or read. `model_name` is the resolved "<backend>:<id>"; `model_tier` is what the spec
    # asked for; `pricing` records whether the cost figures are real money, a self-hosted zero,
    # or unknown -- so a cost comparison is never read across models priced differently.
    model_tier: Mapped[str] = mapped_column(String(32), default="", index=True)
    model_name: Mapped[str] = mapped_column(String(128), default="", index=True)
    backend: Mapped[str] = mapped_column(String(32), default="")
    pricing: Mapped[str] = mapped_column(String(16), default="")
    repetitions: Mapped[int] = mapped_column(Integer, default=1)
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    cases: Mapped[list[EvalCaseResult]] = relationship(back_populates="experiment")


class EvalCaseResult(Base):
    __tablename__ = "eval_case_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    experiment_id: Mapped[str] = mapped_column(ForeignKey("eval_experiments.id"), index=True)
    case_name: Mapped[str] = mapped_column(String(128))
    repetition: Mapped[int] = mapped_column(Integer, default=0)
    passed: Mapped[bool] = mapped_column(default=False)
    scores: Mapped[dict] = mapped_column(JSON, default=dict)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    latency_s: Mapped[float] = mapped_column(Float, default=0.0)
    experiment: Mapped[EvalExperiment] = relationship(back_populates="cases")


@lru_cache
def _engine():
    return create_async_engine(get_settings().database_url, pool_pre_ping=True)


@lru_cache
def _sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(_engine(), expire_on_commit=False)


def session() -> AsyncSession:
    return _sessionmaker()()


async def create_all() -> None:
    async with _engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
