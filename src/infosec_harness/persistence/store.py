"""Repository layer: persist triage outputs and answer queries for the API/CLI."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update

from infosec_harness.domain.models import TriageRunOutput, canonical_json
from infosec_harness.graph.manifests import persisted_manifest
from infosec_harness.persistence import db


def _run_id(batch_id: str, fingerprint: str) -> str:
    return hashlib.sha256(f"{batch_id}:{fingerprint}".encode()).hexdigest()[:24]


async def create_batch(batch_id: str, *, source_kind: str, label: str, count: int,
                       workflow_id: str | None = None) -> None:
    async with db.session() as s:
        s.add(db.Batch(id=batch_id, source_kind=source_kind, label=label,
                       finding_count=count, workflow_id=workflow_id))
        await s.commit()


def _output_values(out: TriageRunOutput, previous: dict, operations: dict) -> dict[str, Any]:
    """Construct one atomic result update without mutating a loaded ORM record."""
    verdict = out.result.verdict
    total_tokens = sum(i.input_tokens + i.output_tokens for i in out.invocations)
    cost = sum(i.cost_usd or 0.0 for i in out.invocations)
    latency = sum(i.latency_s for i in out.invocations)
    own_operations = [operation for key, operation in operations.items()
                      if out.finding.fingerprint in key]
    # Execution operations account wall-clock workload reservations. They deliberately stay
    # uncertain when a worker cannot observe the full external runtime, but that says nothing
    # about provider token/cost usage returned by a settled agent operation. Records written
    # before operation kinds existed are agent operations by definition.
    agent_operations = [op for op in own_operations if op.get("kind", "agent") == "agent"]
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
        status="needs_info" if out.needs_info else "complete", verdict=verdict.label.value,
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


async def save_run_output(batch_id: str, out: TriageRunOutput) -> str:
    """Persist one output atomically; a cancellation/failure fences every late write."""
    out = out.model_copy(update={"manifest": persisted_manifest(out.manifest)})
    run_id = _run_id(batch_id, out.finding.fingerprint)
    async with db.session() as session:
        run = await session.get(db.TriageRun, run_id)
        if run is not None and run.status in {"cancelled", "failed"}:
            return run_id
        ledger = await session.get(db.BudgetLedger, batch_id)
        values = _output_values(out, (run.telemetry or {}) if run else {},
                                ledger.state.get("operations", {}) if ledger else {})
        if run is None:
            session.add(db.TriageRun(id=run_id, batch_id=batch_id,
                                    fingerprint=out.finding.fingerprint, **values))
            await session.flush()
        else:
            result = await session.execute(update(db.TriageRun).where(
                db.TriageRun.id == run_id, db.TriageRun.status.notin_(["cancelled", "failed"])
            ).values(**values))
            if result.rowcount == 0:
                await session.rollback()
                return run_id
        # The conditional result write holds the row lock until replacement is committed.
        for invocation in (await session.scalars(select(db.AgentInvocation).where(
                db.AgentInvocation.run_id == run_id))).all():
            await session.delete(invocation)
        for seq, invocation in enumerate(out.invocations):
            session.add(db.AgentInvocation(run_id=run_id, seq=seq,
                **invocation.model_dump(include={"agent", "model_name", "config_hash", "input_tokens",
                    "output_tokens", "cache_read_tokens", "cache_write_tokens", "cost_usd", "cost_estimated",
                    "latency_s", "requests", "repeated_tool_calls", "tools_called", "skills_loaded"})))
        await session.commit()
    return run_id


async def finish_batch(batch_id: str, status: str = "complete") -> None:
    """First terminal transition wins; delayed retries cannot resurrect cancelled batches."""
    async with db.session() as session:
        await session.execute(update(db.Batch).where(db.Batch.id == batch_id,
            db.Batch.status.notin_(["complete", "failed", "cancelled"])).values(status=status))
        await session.commit()


async def list_runs(*, batch_id: str | None = None, verdict: str | None = None,
                    limit: int = 200) -> list[dict]:
    stmt = select(db.TriageRun).order_by(db.TriageRun.priority_score.desc().nullslast())
    if batch_id:
        stmt = stmt.where(db.TriageRun.batch_id == batch_id)
    if verdict:
        stmt = stmt.where(db.TriageRun.verdict == verdict)
    stmt = stmt.limit(limit)
    async with db.session() as s:
        rows = (await s.execute(stmt)).scalars().all()
        return [_run_summary(r) for r in rows]


async def get_run(run_id: str) -> dict | None:
    async with db.session() as s:
        run = await s.get(db.TriageRun, run_id)
        if run is None:
            return None
        invs = (await s.execute(
            select(db.AgentInvocation).where(db.AgentInvocation.run_id == run_id)
            .order_by(db.AgentInvocation.seq))).scalars().all()
        review = (await s.execute(
            select(db.VerdictReview).where(db.VerdictReview.run_id == run_id))).scalar_one_or_none()
        detail = _run_summary(run)
        detail["evidence"] = run.evidence
        events = (await s.execute(select(db.RunEvent).where(db.RunEvent.run_id == run_id)
                                  .order_by(db.RunEvent.created_at, db.RunEvent.id))).scalars().all()
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


async def batch_summary(batch_id: str) -> dict | None:
    async with db.session() as s:
        batch = await s.get(db.Batch, batch_id)
        if batch is None:
            return None
        counts = dict((await s.execute(
            select(db.TriageRun.verdict, func.count()).where(db.TriageRun.batch_id == batch_id)
            .where(db.TriageRun.verdict.is_not(None))
            .group_by(db.TriageRun.verdict))).all())
        states = dict((await s.execute(select(db.TriageRun.status, func.count())
            .where(db.TriageRun.batch_id == batch_id).group_by(db.TriageRun.status))).all())
        ledger = await s.get(db.BudgetLedger, batch_id)
        return {"budget": ledger.state if ledger else None, "status_counts": states, "id": batch.id, "status": batch.status, "label": batch.label,
                "source_kind": batch.source_kind, "finding_count": batch.finding_count,
                "created_at": batch.created_at.isoformat(), "verdict_counts": counts}


async def list_batches(limit: int = 100) -> list[dict]:
    async with db.session() as s:
        rows = (await s.execute(select(db.Batch).order_by(db.Batch.created_at.desc()).limit(limit))).scalars().all()
        return [{"id": b.id, "status": b.status, "label": b.label, "source_kind": b.source_kind,
                 "finding_count": b.finding_count, "created_at": b.created_at.isoformat()} for b in rows]


def _run_summary(r: db.TriageRun) -> dict:
    return {
        "id": r.id, "batch_id": r.batch_id, "fingerprint": r.fingerprint, "title": r.title,
        "repo_url": r.repo_url, "revision": r.revision, "cwe": r.cwe, "severity": r.severity,
        "status": r.status, "verdict": r.verdict, "confidence": r.confidence,
        "inconclusive_reason": r.inconclusive_reason, "priority": r.priority,
        "priority_score": r.priority_score, "environment_scope": r.environment_scope,
        "early_exit": r.early_exit, "cost_usd": (r.telemetry or {}).get("cost_usd"), "total_tokens": r.total_tokens,
        "cache_read_tokens": r.cache_read_tokens, "latency_s": r.latency_s,
        "created_at": r.created_at.isoformat(), "telemetry": r.telemetry,
        "phase": r.status if r.status in {"complete", "needs_info", "failed", "cancelled"} else (r.telemetry or {}).get("phase", r.status),
    }


def payload_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def run_config_signature(out: TriageRunOutput) -> str:
    return payload_hash(canonical_json({i.agent: i.config_hash for i in out.invocations}))
