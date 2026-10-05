"""Repository layer: persist triage outputs and answer queries for the API/CLI."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update

from infosec_harness.domain.models import (
    TERMINAL_BATCH_STATUSES,
    TERMINAL_RUN_STATUSES,
    BatchStatus,
    RunStatus,
    TriageRunOutput,
)
from infosec_harness.persistence import db
from infosec_harness.persistence.identity import persisted_manifest
from infosec_harness.persistence.population import (
    Population,
    batch_population,
    recorded_population,
    run_population,
)

_FAILED_OR_CANCELLED = (RunStatus.failed, RunStatus.cancelled)


def run_id(batch_id: str, fingerprint: str) -> str:
    """The deterministic id of one finding's run within one batch."""
    return hashlib.sha256(f"{batch_id}:{fingerprint}".encode()).hexdigest()[:24]


async def create_batch(batch_id: str, *, source_kind: str, label: str, count: int,
                       workflow_id: str | None = None,
                       status: BatchStatus = BatchStatus.running) -> None:
    async with db.session() as s:
        s.add(db.Batch(id=batch_id, source_kind=source_kind, label=label, status=status,
                       finding_count=count, workflow_id=workflow_id))
        await s.commit()


def _output_values(out: TriageRunOutput, previous: dict, operations: dict) -> dict[str, Any]:
    """Construct one atomic result update without mutating a loaded ORM record."""
    verdict = out.result.verdict
    total_tokens = sum(i.input_tokens + i.output_tokens for i in out.invocations)
    cost = sum(i.cost_usd or 0.0 for i in out.invocations)
    latency = sum(i.latency_s for i in out.invocations)
    # Execution operations account wall-clock workload reservations. They deliberately stay
    # uncertain when a worker cannot observe the full external runtime, but that says nothing
    # about provider token/cost usage returned by a settled agent operation.
    agent_operations = [op for op in operations.values()
                        if op.get("fingerprint") == out.finding.fingerprint
                        and op["kind"] == "agent"]
    accounting_complete = all(op["status"] == "settled" for op in agent_operations)
    cost_complete = all(op["status"] == "settled" or
        op.get("record", {}).get("pricing_status") == "known_zero" for op in agent_operations)
    accepted = previous.get("accepted_at")
    elapsed = max(0.0, (datetime.now(UTC) - datetime.fromisoformat(accepted)).total_seconds()) if accepted else None
    costs = [i.cost_usd for i in out.invocations]
    telemetry = {**previous, "schema_version": 1,
        "completed_at": previous.get("completed_at") or datetime.now(UTC).isoformat(),
        "wall_time_s": previous.get("wall_time_s", elapsed), "agent_time_s": latency,
        "cost_usd": cost if cost_complete and costs and all(c is not None for c in costs) else None,
        "known_cost_usd": cost, "accounting_complete": accounting_complete,
        "cost_accounting_complete": cost_complete, "known_tokens": total_tokens,
        "input_tokens": sum(i.input_tokens for i in out.invocations) if out.invocations and accounting_complete else None,
        "output_tokens": sum(i.output_tokens for i in out.invocations) if out.invocations and accounting_complete else None,
        "cost_coverage": sum(c is not None for c in costs) / len(costs) if costs else None,
        "total_tokens": total_tokens if out.invocations and accounting_complete else None}
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
        telemetry=telemetry, cost_usd=cost, total_tokens=total_tokens,
        cache_read_tokens=sum(i.cache_read_tokens for i in out.invocations), latency_s=latency)


async def save_run_output(batch_id: str, out: TriageRunOutput, *,
                          population: Population | None = None) -> str:
    """Persist one output atomically; a cancellation/failure fences every late write.

    ``population`` labels a run that was not accepted through the durable lifecycle (which
    labels its runs at acceptance).
    """
    out = out.model_copy(update={"manifest": persisted_manifest(out.manifest)})
    identity = run_id(batch_id, out.finding.fingerprint)
    async with db.session() as session:
        run = await session.get(db.TriageRun, identity)
        if run is not None and run.status in _FAILED_OR_CANCELLED:
            return identity
        ledger = await session.get(db.BudgetLedger, batch_id)
        previous = dict(run.telemetry or {}) if run else {}
        if population is not None:
            previous["population"] = population
        values = _output_values(out, previous,
                                ledger.state.get("operations", {}) if ledger else {})
        if run is None:
            session.add(db.TriageRun(id=identity, batch_id=batch_id,
                                    fingerprint=out.finding.fingerprint, **values))
            await session.flush()
        else:
            result = await session.execute(update(db.TriageRun).where(
                db.TriageRun.id == identity, db.TriageRun.status.notin_(_FAILED_OR_CANCELLED)
            ).values(**values))
            if result.rowcount == 0:
                await session.rollback()
                return identity
        # The conditional result write holds the row lock until replacement is committed.
        for invocation in (await session.scalars(select(db.AgentInvocation).where(
                db.AgentInvocation.run_id == identity))).all():
            await session.delete(invocation)
        for seq, invocation in enumerate(out.invocations):
            session.add(db.AgentInvocation(run_id=identity, seq=seq,
                **invocation.model_dump(include={"agent", "model_name", "config_hash", "input_tokens",
                    "output_tokens", "cache_read_tokens", "cache_write_tokens", "cost_usd", "cost_estimated",
                    "latency_s", "requests", "repeated_tool_calls", "tools_called", "skills_loaded"})))
        await session.commit()
    return identity


async def finish_batch(batch_id: str, status: BatchStatus = BatchStatus.complete) -> None:
    """First terminal transition wins; delayed retries cannot resurrect cancelled batches."""
    async with db.session() as session:
        await session.execute(update(db.Batch).where(db.Batch.id == batch_id,
            db.Batch.status.notin_(TERMINAL_BATCH_STATUSES)).values(status=status))
        await session.commit()


async def list_runs(*, batch_id: str | None = None, verdict: str | None = None,
                    limit: int = 200, population: Population | None = None) -> list[dict]:
    stmt = select(db.TriageRun).order_by(db.TriageRun.priority_score.desc().nullslast())
    if population is not None:
        stmt = stmt.where(run_population(population))
    if batch_id:
        stmt = stmt.where(db.TriageRun.batch_id == batch_id)
    if verdict:
        stmt = stmt.where(db.TriageRun.verdict == verdict)
    stmt = stmt.limit(limit)
    async with db.session() as s:
        rows = (await s.execute(stmt)).scalars().all()
        return [run_summary(r) for r in rows]


async def get_run(run_id: str, population: Population | None = None) -> dict | None:
    async with db.session() as s:
        run = await s.get(db.TriageRun, run_id)
        if run is None or (population is not None
                           and recorded_population(run.telemetry) != population):
            return None
        invs = (await s.execute(
            select(db.AgentInvocation).where(db.AgentInvocation.run_id == run_id)
            .order_by(db.AgentInvocation.seq))).scalars().all()
        review = (await s.execute(
            select(db.VerdictReview).where(db.VerdictReview.run_id == run_id))).scalar_one_or_none()
        detail = run_summary(run)
        detail["evidence"] = run.evidence
        events = (await s.execute(select(db.RunEventRecord).where(db.RunEventRecord.run_id == run_id)
                                  .order_by(db.RunEventRecord.created_at, db.RunEventRecord.id))).scalars().all()
        detail["events"] = [{"id": e.id, "phase": e.phase, "detail": e.detail,
                              "created_at": e.created_at.isoformat()} for e in events]
        history = (await s.execute(select(db.ReviewHistory).where(db.ReviewHistory.run_id == run_id)
                                   .order_by(db.ReviewHistory.id))).scalars().all()
        detail["review_history"] = [{**h.record, "created_at": h.created_at.isoformat()} for h in history]
        detail["finding"] = run.finding
        detail["result"] = run.result
        detail["invocations"] = [{
            "agent": i.agent, "model_name": i.model_name, "config_hash": i.config_hash,
            "input_tokens": i.input_tokens, "output_tokens": i.output_tokens,
            "cache_read_tokens": i.cache_read_tokens, "cache_write_tokens": i.cache_write_tokens,
            "cost_usd": i.cost_usd, "cost_estimated": i.cost_estimated, "latency_s": i.latency_s,
            "requests": i.requests, "repeated_tool_calls": i.repeated_tool_calls,
            "tools_called": i.tools_called, "skills_loaded": i.skills_loaded,
        } for i in invs]
        detail["review"] = None if review is None else {
            "reviewer": review.reviewer, "decision": review.decision,
            "override_label": review.override_label, "reason": review.reason,
            "created_at": review.created_at.isoformat()}
        return detail


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


def run_summary(r: db.TriageRun) -> dict:
    return {
        "id": r.id, "batch_id": r.batch_id, "fingerprint": r.fingerprint, "title": r.title,
        "repo_url": r.repo_url, "revision": r.revision, "cwe": r.cwe, "severity": r.severity,
        "status": r.status, "verdict": r.verdict, "confidence": r.confidence,
        "inconclusive_reason": r.inconclusive_reason, "priority": r.priority,
        "priority_score": r.priority_score, "environment_scope": r.environment_scope,
        "early_exit": r.early_exit, "cost_usd": (r.telemetry or {}).get("cost_usd"), "total_tokens": r.total_tokens,
        "cache_read_tokens": r.cache_read_tokens, "latency_s": r.latency_s,
        "created_at": r.created_at.isoformat(), "telemetry": r.telemetry,
        "phase": (r.status if r.status in TERMINAL_RUN_STATUSES
                  else (r.telemetry or {}).get("phase", r.status)),
    }


def payload_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
