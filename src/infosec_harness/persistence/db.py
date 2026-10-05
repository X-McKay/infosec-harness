"""SQLAlchemy models and async engine/session for the run store (§9).

Pydantic models are the source of truth; JSONB columns hold ``model_dump()`` output and SQL
columns hold what we filter and aggregate on.
"""

from __future__ import annotations

import ssl
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
from sqlalchemy.engine import make_url
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
    submission: Mapped[dict | None] = mapped_column(JSON, nullable=True)
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

    telemetry: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    batch: Mapped[Batch] = relationship(back_populates="runs")
    invocations: Mapped[list[AgentInvocation]] = relationship(
        back_populates="run", order_by=lambda: AgentInvocation.seq)
    review: Mapped[VerdictReview | None] = relationship(back_populates="run", uselist=False)
    events: Mapped[list[RunEventRecord]] = relationship(
        order_by=lambda: [RunEventRecord.created_at, RunEventRecord.id], viewonly=True)
    review_history: Mapped[list[ReviewHistory]] = relationship(
        order_by=lambda: ReviewHistory.id, viewonly=True)


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
    # Request accounting: what a `request_limit` breach is measured against, and the
    # repeated `tool(args)` calls that explain where the requests went.
    requests: Mapped[int] = mapped_column(Integer, default=0)
    repeated_tool_calls: Mapped[dict] = mapped_column(JSON, default=dict)
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


class BudgetLedger(Base):
    __tablename__ = "budget_ledgers"
    root_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, default=0)
    state: Mapped[dict] = mapped_column(JSON)


class InferenceRequestRecord(Base):
    """Controller-owned durable dispatch fence; terminal identities are retained."""
    __tablename__ = "inference_requests"
    request_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    root_id: Mapped[str] = mapped_column(ForeignKey("budget_ledgers.root_id"), index=True)
    operation_id: Mapped[str] = mapped_column(String(512))
    lease_id: Mapped[str] = mapped_column(String(128))
    state: Mapped[str] = mapped_column(String(32))
    revision: Mapped[int] = mapped_column(Integer, default=0)
    request: Mapped[dict] = mapped_column(JSON)
    allocation: Mapped[dict] = mapped_column(JSON)
    overrun: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    fence: Mapped[str | None] = mapped_column(String(128), nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunEventRecord(Base):
    """Idempotent activity-written state transitions of one run."""
    __tablename__ = "run_events"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("triage_runs.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    phase: Mapped[str] = mapped_column(String(48))
    detail: Mapped[str] = mapped_column(Text, default="")


class ReviewHistory(Base):
    __tablename__ = "review_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("triage_runs.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    record: Mapped[dict] = mapped_column(JSON)


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


def database_connect_args(url: str, settings=None) -> dict:
    """Use the same verified PostgreSQL TLS policy for runtime and migrations."""
    settings = settings or get_settings()
    driver = make_url(url).drivername
    if driver.startswith("sqlite") or not settings.database_tls:
        return {}
    if driver != "postgresql+asyncpg":
        raise ValueError("Database TLS requires the postgresql+asyncpg driver")
    ca = settings.database_tls_ca_file
    cert = settings.database_tls_client_cert
    key = settings.database_tls_client_key
    if bool(cert) != bool(key):
        raise ValueError("Database TLS client certificate and key must be configured together")
    context = ssl.create_default_context(cafile=str(ca) if ca else None)
    if cert:
        context.load_cert_chain(str(cert), str(key))
    return {"ssl": context}


@lru_cache
def _engine():
    url = get_settings().database_url
    return create_async_engine(url, pool_pre_ping=True, connect_args=database_connect_args(url))


@lru_cache
def _sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(_engine(), expire_on_commit=False)


def session() -> AsyncSession:
    return _sessionmaker()()


def alembic_config():
    """Alembic pointed at the packaged migrations, whether this runs from a checkout or a wheel.

    Built in code rather than read from ``alembic.ini``: an installed wheel has no repository
    to find the ini in, and the migrations ship inside the package precisely so that
    ``harness migrate`` works wherever the harness does. The ini at the repository root is
    for running the ``alembic`` CLI directly and points at the same directory.
    """
    from alembic.config import Config

    from infosec_harness.resources import package_root

    cfg = Config()
    cfg.set_main_option("script_location", str(package_root() / "persistence" / "migrations"))
    cfg.set_main_option("path_separator", "os")
    return cfg


class SchemaNotAtHead(RuntimeError):
    """The database is versioned but not at the code's migration head; it must be migrated."""


def _head_revision() -> str:
    from alembic.script import ScriptDirectory

    head = ScriptDirectory.from_config(alembic_config()).get_current_head()
    if head is None:  # pragma: no cover - the package always ships its migrations
        raise RuntimeError("No migration head is packaged")
    return head


def _schema_state(connection) -> tuple[set[str], str | None]:
    from alembic.runtime.migration import MigrationContext
    from sqlalchemy import inspect

    tables = set(inspect(connection).get_table_names())
    return tables, MigrationContext.configure(connection).get_current_revision()


def _bootstrap(connection) -> None:
    """Create an empty database at head, or accept one already at head; refuse anything else.

    ``create_all`` runs only on an empty database, which is then stamped at head: it has exactly
    the schema the migrations produce, so a later ``harness migrate`` is the no-op it should be.
    It never runs over a versioned database -- creating the newest tables there would make the
    pending migrations that create them fail. A database behind head is refused with the
    command that brings it forward; one with tables but no version row is not ours to guess at.
    """
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory

    tables, revision = _schema_state(connection)
    head = _head_revision()
    if revision == head:
        return
    if revision is None and not (tables - {"alembic_version"}):
        Base.metadata.create_all(connection)
        MigrationContext.configure(connection).stamp(
            ScriptDirectory.from_config(alembic_config()), "head")
        return
    if revision is None:
        raise SchemaNotAtHead(
            "The database has tables but no migration version; it was not created by this "
            "harness. Use an empty database, or bring it under migration control explicitly.")
    raise SchemaNotAtHead(
        f"The database schema is at revision {revision}, not {head}. Run `harness migrate` "
        "to upgrade it before starting the service.")


async def create_all() -> None:
    """Bootstrap the schema for tests, CI, and a fresh local database (see ``_bootstrap``).

    Deployments migrate instead (``upgrade_to_head``).
    """
    async with _engine().begin() as conn:
        await conn.run_sync(_bootstrap)


def upgrade_to_head(url: str | None = None) -> str:
    """Migrate the database to the latest revision. Synchronous because alembic drives its own
    event loop through ``migrations/env.py``."""
    import asyncio

    from alembic import command

    target = url or get_settings().database_url

    async def _state():
        engine = create_async_engine(target, connect_args=database_connect_args(target))
        try:
            async with engine.connect() as conn:
                return await conn.run_sync(_schema_state)
        finally:
            await engine.dispose()

    cfg = alembic_config()
    cfg.set_main_option("sqlalchemy.url", target.replace("%", "%%"))
    command.upgrade(cfg, "head")
    _, revision = asyncio.run(_state())
    return revision or ""
