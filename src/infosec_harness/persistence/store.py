"""Repository layer: persist triage outputs and answer every query the API, CLI and workflows make.

SQL lives here and in the other persistence modules only; the API and workflow layers call these
functions.
"""

from __future__ import annotations

import hashlib
import math
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.orm import selectinload

from infosec_harness.domain.models import (
    TERMINAL_BATCH_STATUSES,
    TERMINAL_RUN_STATUSES,
    BatchStatus,
    ExperimentStatus,
    RunStatus,
    TriageRunOutput,
)
from infosec_harness.persistence import db
from infosec_harness.persistence.identity import persisted_manifest
from infosec_harness.persistence.population import (
    Population,
    batch_population,
    experiment_population,
    run_population,
)
from infosec_harness.persistence.run_telemetry import MetricField, RunTelemetry, telemetry_field

_FAILED_OR_CANCELLED = (RunStatus.failed, RunStatus.cancelled)
_INVOCATION_FIELDS = ("agent", "model_name", "config_hash", "input_tokens", "output_tokens",
                      "cache_read_tokens", "cache_write_tokens", "cost_usd", "cost_estimated",
                      "latency_s", "requests", "repeated_tool_calls", "tools_called",
                      "skills_loaded")


class MissingDurableRecord(LookupError):
    """A write named a batch, run or ledger that was never durably accepted."""


def run_id(batch_id: str, fingerprint: str) -> str:
    """The deterministic id of one finding's run within one batch."""
    return hashlib.sha256(f"{batch_id}:{fingerprint}".encode()).hexdigest()[:24]


def payload_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Run outputs
# ---------------------------------------------------------------------------


def _output_values(out: TriageRunOutput, telemetry: RunTelemetry) -> dict[str, Any]:
    """Construct one atomic result update without mutating a loaded ORM record."""
    verdict = out.result.verdict
    return dict(repo_url=out.finding.repo_url, revision=out.finding.revision,
        title=out.finding.title, cwe=out.finding.cwe, severity=out.finding.severity.value,
        status=RunStatus.needs_info if out.needs_info else RunStatus.complete,
        verdict=verdict.label.value,
        confidence=verdict.confidence,
        inconclusive_reason=verdict.inconclusive_reason.value if verdict.inconclusive_reason else None,
        priority=out.result.priority.value, priority_score=out.result.priority_score,
        environment_scope=out.result.environment_scope, early_exit=out.result.early_exit,
        finding=out.finding.model_dump(mode="json"), result=out.result.model_dump(mode="json"),
        evidence={"schema_version": 1, "manifest": out.manifest,
            "context": out.context.model_dump(mode="json") if out.context else None,
            "executions": [e.model_dump(mode="json") for e in out.executions],
            "invocations": [i.model_dump(mode="json") for i in out.invocations]},
        telemetry=telemetry.stored(), cost_usd=telemetry.known_cost_usd or 0.0,
        total_tokens=telemetry.known_tokens or 0,
        cache_read_tokens=sum(i.cache_read_tokens for i in out.invocations),
        latency_s=telemetry.agent_time_s or 0.0)


def agent_operations(ledger_state: dict, fingerprint: str) -> list[dict]:
    """The ledger's agent operations spent on one finding, by their recorded attribution."""
    return [op for op in ledger_state.get("operations", {}).values()
            if op.get("fingerprint") == fingerprint and op["kind"] == "agent"]


async def save_run_output(batch_id: str, out: TriageRunOutput) -> str:
    """Persist one accepted run's output atomically; a cancellation/failure fences late writes.

    The run and its batch's budget ledger must already exist: an output that was never
    accepted, or whose spend has no ledger, cannot be recorded as accounted.
    """
    out = out.model_copy(update={"manifest": persisted_manifest(out.manifest)})
    fingerprint = out.finding.fingerprint
    identity = run_id(batch_id, fingerprint)
    async with db.session() as session:
        run = await session.get(db.TriageRun, identity)
        if run is None:
            raise MissingDurableRecord(f"run {identity} of batch {batch_id} was never accepted")
        if run.status in _FAILED_OR_CANCELLED:
            return identity
        ledger = await session.get(db.BudgetLedger, batch_id)
        if ledger is None:
            raise MissingDurableRecord(f"batch {batch_id} has no budget ledger")
        accepted = RunTelemetry.read(run.telemetry)
        if accepted is None:
            raise MissingDurableRecord(f"run {identity} has no accepted telemetry")
        telemetry = accepted.with_usage(
            out.invocations, agent_operations(ledger.state, fingerprint), datetime.now(UTC))
        result = await session.execute(update(db.TriageRun).where(
            db.TriageRun.id == identity, db.TriageRun.status.notin_(_FAILED_OR_CANCELLED)
        ).values(**_output_values(out, telemetry)))
        if result.rowcount == 0:
            await session.rollback()
            return identity
        # The conditional result write holds the row lock until replacement is committed.
        await session.execute(delete(db.AgentInvocation).where(
            db.AgentInvocation.run_id == identity))
        for seq, invocation in enumerate(out.invocations):
            session.add(db.AgentInvocation(run_id=identity, seq=seq,
                                           **invocation.model_dump(include=set(_INVOCATION_FIELDS))))
        await session.commit()
    return identity


async def run_status(run_id: str) -> RunStatus:
    async with db.session() as session:
        status = await session.scalar(select(db.TriageRun.status).where(db.TriageRun.id == run_id))
    if status is None:
        raise MissingDurableRecord(f"run {run_id} does not exist")
    return RunStatus(status)


async def finish_batch(batch_id: str, status: BatchStatus = BatchStatus.complete) -> None:
    """First terminal transition wins; delayed retries cannot resurrect cancelled batches."""
    async with db.session() as session:
        await session.execute(update(db.Batch).where(db.Batch.id == batch_id,
            db.Batch.status.notin_(TERMINAL_BATCH_STATUSES)).values(status=status))
        await session.commit()


# ---------------------------------------------------------------------------
# Run queries
# ---------------------------------------------------------------------------


def _run_filters(*, batch_id: str | None = None, verdict: str | None = None,
                 population: Population | None = None, metric: MetricField | None = None,
                 lower: float | None = None, upper: float | None = None,
                 upper_inclusive: bool = False, search: str = "") -> list:
    """The one definition of which runs a listing selects."""
    if any(value is not None and (not math.isfinite(value) or value < 0) for value in (lower, upper)):
        raise ValueError("Metric bounds must be finite and non-negative")
    if lower is not None and upper is not None and lower > upper:
        raise ValueError("lower must not exceed upper")
    if metric is None and (lower is not None or upper is not None):
        raise ValueError("metric is required with distribution bounds")
    filters = []
    if population is not None:
        filters.append(run_population(population))
    if metric is not None:
        value = telemetry_field(metric).as_float()
        filters.append(value.is_not(None))
        if lower is not None:
            filters.append(value >= lower)
        if upper is not None:
            filters.append(value <= upper if upper_inclusive else value < upper)
    if batch_id:
        filters.append(db.TriageRun.batch_id == batch_id)
    if verdict:
        filters.append(db.TriageRun.verdict == verdict)
    if search:
        filters.append(or_(*(field.icontains(search, autoescape=True) for field in
                             (db.TriageRun.title, db.TriageRun.cwe, db.TriageRun.repo_url))))
    return filters


_RUN_ORDER = (db.TriageRun.priority_score.desc().nullslast(), db.TriageRun.created_at.desc(),
              db.TriageRun.id)


async def list_runs(*, batch_id: str | None = None, verdict: str | None = None,
                    limit: int = 200, population: Population | None = None) -> list[dict]:
    statement = (select(db.TriageRun)
                 .where(*_run_filters(batch_id=batch_id, verdict=verdict, population=population))
                 .order_by(*_RUN_ORDER).limit(limit))
    async with db.session() as s:
        return [run_summary(r) for r in (await s.scalars(statement)).all()]


async def run_page(*, offset: int, limit: int, **filters: Any) -> dict:
    """One page of runs and the total under the same filters (see :func:`_run_filters`)."""
    selected = _run_filters(**filters)
    async with db.session() as session:
        total = await session.scalar(select(func.count(db.TriageRun.id)).where(*selected))
        rows = (await session.scalars(select(db.TriageRun).where(*selected)
                                      .order_by(*_RUN_ORDER).offset(offset).limit(limit))).all()
    return {"items": [run_summary(r) for r in rows], "total": total or 0, "offset": offset,
            "limit": limit, "as_of": datetime.now(UTC).isoformat()}


async def get_run(run_id: str, population: Population | None = None) -> dict | None:
    statement = select(db.TriageRun).where(db.TriageRun.id == run_id).options(
        selectinload(db.TriageRun.invocations), selectinload(db.TriageRun.review),
        selectinload(db.TriageRun.events), selectinload(db.TriageRun.review_history))
    if population is not None:
        statement = statement.where(run_population(population))
    async with db.session() as s:
        run = await s.scalar(statement)
        if run is None:
            return None
        review = run.review
        return {
            **run_summary(run),
            "evidence": run.evidence,
            "events": [{"id": e.id, "phase": e.phase, "detail": e.detail,
                        "created_at": e.created_at.isoformat()} for e in run.events],
            "review_history": [{**h.record, "created_at": h.created_at.isoformat()}
                               for h in run.review_history],
            "finding": run.finding,
            "result": run.result,
            "invocations": [{name: getattr(i, name) for name in _INVOCATION_FIELDS}
                            for i in run.invocations],
            "review": None if review is None else {
                "reviewer": review.reviewer, "decision": review.decision,
                "override_label": review.override_label, "reason": review.reason,
                "created_at": review.created_at.isoformat()},
        }


async def save_review(run_id: str, *, reviewer: str, decision: str, override_label: str | None,
                      reason: str) -> bool:
    async with db.session() as s:
        run = await s.get(db.TriageRun, run_id)
        if run is None:
            return False
        existing = (await s.execute(
            select(db.VerdictReview).where(db.VerdictReview.run_id == run_id))).scalar_one_or_none()
        if existing is None:
            existing = db.VerdictReview(run_id=run_id)
            s.add(existing)
        s.add(db.ReviewHistory(run_id=run_id, record={"reviewer": reviewer, "decision": decision,
              "override_label": override_label, "reason": reason}))
        existing.created_at = datetime.now(UTC)
        existing.reviewer = reviewer
        existing.decision = decision
        existing.override_label = override_label
        existing.reason = reason
        await s.commit()
        return True


def run_summary(r: db.TriageRun) -> dict:
    telemetry = RunTelemetry.read(r.telemetry)
    return {
        "id": r.id, "batch_id": r.batch_id, "fingerprint": r.fingerprint, "title": r.title,
        "repo_url": r.repo_url, "revision": r.revision, "cwe": r.cwe, "severity": r.severity,
        "status": r.status, "verdict": r.verdict, "confidence": r.confidence,
        "inconclusive_reason": r.inconclusive_reason, "priority": r.priority,
        "priority_score": r.priority_score, "environment_scope": r.environment_scope,
        "early_exit": r.early_exit, "cost_usd": telemetry.cost_usd if telemetry else None,
        "total_tokens": r.total_tokens, "cache_read_tokens": r.cache_read_tokens,
        "latency_s": r.latency_s, "created_at": r.created_at.isoformat(),
        "telemetry": telemetry.stored() if telemetry else None,
        "phase": (r.status if r.status in TERMINAL_RUN_STATUSES or telemetry is None
                  else telemetry.phase),
    }


# ---------------------------------------------------------------------------
# Batches
# ---------------------------------------------------------------------------


async def _batch_counts(session, batch_ids: list[str], population: Population | None
                        ) -> tuple[dict[str, dict[str, int]], dict[str, dict[str, int]]]:
    """Per-batch run status and verdict counts, under the same optional population filter.

    A batch's finding count is always the number of its runs under that filter: one definition,
    whether or not a population is selected.
    """
    selected = [db.TriageRun.batch_id.in_(batch_ids)]
    if population is not None:
        selected.append(run_population(population))
    states: dict[str, dict[str, int]] = {identity: {} for identity in batch_ids}
    verdicts: dict[str, dict[str, int]] = {identity: {} for identity in batch_ids}
    for identity, status, count in (await session.execute(
            select(db.TriageRun.batch_id, db.TriageRun.status, func.count()).where(*selected)
            .group_by(db.TriageRun.batch_id, db.TriageRun.status))).all():
        states[identity][status] = count
    for identity, verdict, count in (await session.execute(
            select(db.TriageRun.batch_id, db.TriageRun.verdict, func.count()).where(*selected)
            .where(db.TriageRun.verdict.is_not(None))
            .group_by(db.TriageRun.batch_id, db.TriageRun.verdict))).all():
        verdicts[identity][verdict] = count
    return states, verdicts


def _batch_row(batch: db.Batch, states: dict[str, int]) -> dict:
    return {"id": batch.id, "status": batch.status, "label": batch.label,
            "source_kind": batch.source_kind, "finding_count": sum(states.values()),
            "created_at": batch.created_at.isoformat()}


async def batch_summary(batch_id: str, population: Population | None = None) -> dict | None:
    async with db.session() as s:
        statement = select(db.Batch).where(db.Batch.id == batch_id)
        if population is not None:
            statement = statement.where(batch_population(population))
        batch = await s.scalar(statement)
        if batch is None:
            return None
        states, verdicts = await _batch_counts(s, [batch_id], population)
        ledger = await s.get(db.BudgetLedger, batch_id)
        return {**_batch_row(batch, states[batch_id]), "status_counts": states[batch_id],
                "verdict_counts": verdicts[batch_id],
                "budget": ledger.state if ledger else None}


async def list_batches(limit: int = 100, population: Population | None = None) -> list[dict]:
    async with db.session() as s:
        statement = select(db.Batch)
        if population is not None:
            statement = statement.where(batch_population(population))
        rows = (await s.execute(statement.order_by(db.Batch.created_at.desc())
                                .limit(limit))).scalars().all()
        states, _ = await _batch_counts(s, [b.id for b in rows], population)
        return [_batch_row(b, states[b.id]) for b in rows]


# ---------------------------------------------------------------------------
# Eval experiments
# ---------------------------------------------------------------------------

HeadlineMetric = Literal["task_success_rate", "average_cost_usd", "p50_latency_s",
                         "p95_latency_s", "passed", "n", "cases_completed", "n_planned",
                         "budget_exhausted_count"]


def _metric(metrics: dict, *keys: HeadlineMetric) -> float | None:
    """A recorded finite metric, read directly or from the report's distributions block."""
    distributions = metrics.get("distributions")
    distributions = distributions if isinstance(distributions, dict) else {}
    for key in keys:
        for value in (metrics.get(key), distributions.get(key)):
            if (isinstance(value, int | float) and not isinstance(value, bool)
                    and math.isfinite(value)):
                return float(value)
    return None


def _experiment_summary(e: db.EvalExperiment) -> dict:
    metrics = e.metrics if isinstance(e.metrics, dict) else {}
    gate = metrics.get("gate_evaluation")
    gate_status = gate.get("status") if isinstance(gate, dict) else None
    known = {s.value for s in ExperimentStatus}
    return {"id": e.id, "agent": e.agent, "dataset": e.dataset,
            "status": metrics.get("status") if metrics.get("status") in known else None,
            "dataset_version": e.dataset_version, "git_sha": e.git_sha, "overlay": e.overlay,
            "repetitions": e.repetitions, "config_hash": e.config_hash,
            "git_dirty": e.git_dirty, "model_name": e.model_name, "backend": e.backend,
            "pricing": e.pricing, "harness_version": e.harness_version,
            "created_at": e.created_at.isoformat(),
            "task_success_rate": _metric(metrics, "task_success_rate"),
            "average_cost_usd": _metric(metrics, "average_cost_usd"),
            "p50_latency_s": _metric(metrics, "p50_latency_s"),
            "p95_latency_s": _metric(metrics, "p95_latency_s"),
            "passed": _metric(metrics, "passed"),
            "cases_completed": _metric(metrics, "n", "cases_completed"),
            "cases_planned": _metric(metrics, "n_planned"),
            "budget_exhausted_count": _metric(metrics, "budget_exhausted_count"),
            "gate_status": gate_status if isinstance(gate_status, str) else None}


async def experiment_page(*, offset: int, limit: int,
                          population: Population | None = None) -> dict:
    """Newest-first experiment summaries; full metrics are read per experiment."""
    selected = [experiment_population(population)] if population is not None else []
    async with db.session() as s:
        total = await s.scalar(select(func.count(db.EvalExperiment.id)).where(*selected))
        rows = (await s.scalars(select(db.EvalExperiment).where(*selected).order_by(
            db.EvalExperiment.created_at.desc(), db.EvalExperiment.id)
            .offset(offset).limit(limit))).all()
    return {"items": [_experiment_summary(e) for e in rows], "total": total or 0,
            "offset": offset, "limit": limit}


async def experiment_detail(experiment_id: str,
                            population: Population | None = None) -> dict | None:
    statement = (select(db.EvalExperiment).where(db.EvalExperiment.id == experiment_id)
                 .options(selectinload(db.EvalExperiment.cases)))
    if population is not None:
        statement = statement.where(experiment_population(population))
    async with db.session() as session:
        experiment = await session.scalar(statement)
    if experiment is None:
        return None
    return {"id": experiment.id, "agent": experiment.agent, "metrics": experiment.metrics,
            "cases": [{"case_name": c.case_name, "repetition": c.repetition,
                       "passed": c.passed, "scores": c.scores,
                       "cost_usd": c.scores.get("cost_usd") if "cost_status" in c.scores else None,
                       "latency_s": c.latency_s if "outcome" in c.scores else None}
                      for c in sorted(experiment.cases, key=lambda c: c.id)]}


# ---------------------------------------------------------------------------
# Tracker write-back and broker observation
# ---------------------------------------------------------------------------


async def ado_sync(work_item_id: int) -> tuple[int | None, str] | None:
    """The comment id and payload hash last written to a work item, if any."""
    async with db.session() as session:
        row = await session.scalar(select(db.AdoSync).where(
            db.AdoSync.work_item_id == work_item_id))
        return (row.comment_id, row.payload_hash) if row is not None else None


async def record_ado_sync(run_id: str, work_item_id: int, comment_id: int | None,
                          digest: str) -> None:
    async with db.session() as session:
        row = await session.scalar(select(db.AdoSync).where(
            db.AdoSync.work_item_id == work_item_id))
        if row is None:
            row = db.AdoSync(run_id=run_id, work_item_id=work_item_id)
            session.add(row)
        row.comment_id = comment_id
        row.payload_hash = digest
        await session.commit()


async def completion_unknown_requests() -> tuple[int, int]:
    """Broker requests whose outcome is unknown: (unresolved, conservatively closed)."""
    from infosec_harness.persistence.reconciliation import is_conservatively_closed

    async with db.session() as session:
        rows = (await session.execute(
            select(db.InferenceRequestRecord, db.BudgetLedger)
            .outerjoin(db.BudgetLedger,
                       db.InferenceRequestRecord.root_id == db.BudgetLedger.root_id)
            .where(db.InferenceRequestRecord.state == "completion_unknown"))).all()
    closed = sum(is_conservatively_closed(root, request) for request, root in rows)
    return len(rows) - closed, closed
