"""Repository layer: persist triage outputs and answer queries for the API/CLI."""

from __future__ import annotations

import hashlib

from sqlalchemy import func, select

from infosec_harness.domain.models import TriageRunOutput, canonical_json
from infosec_harness.persistence import db


def _run_id(batch_id: str, fingerprint: str) -> str:
    return hashlib.sha256(f"{batch_id}:{fingerprint}".encode()).hexdigest()[:24]


async def create_batch(batch_id: str, *, source_kind: str, label: str, count: int,
                       workflow_id: str | None = None) -> None:
    async with db.session() as s:
        s.add(db.Batch(id=batch_id, source_kind=source_kind, label=label,
                       finding_count=count, workflow_id=workflow_id))
        await s.commit()


async def save_run_output(batch_id: str, out: TriageRunOutput) -> str:
    run_id = _run_id(batch_id, out.finding.fingerprint)
    v = out.result.verdict
    total_tokens = sum(i.input_tokens + i.output_tokens for i in out.invocations)
    cache_read = sum(i.cache_read_tokens for i in out.invocations)
    cost = sum(i.cost_usd or 0.0 for i in out.invocations)
    latency = sum(i.latency_s for i in out.invocations)
    async with db.session() as s:
        run = await s.get(db.TriageRun, run_id)
        if run is None:
            run = db.TriageRun(id=run_id, batch_id=batch_id, fingerprint=out.finding.fingerprint)
            s.add(run)
        run.repo_url = out.finding.repo_url
        run.revision = out.finding.revision
        run.title = out.finding.title
        run.cwe = out.finding.cwe
        run.severity = out.finding.severity.value
        run.status = "needs_info" if out.needs_info else "complete"
        run.verdict = v.label.value
        run.confidence = v.confidence
        run.inconclusive_reason = v.inconclusive_reason.value if v.inconclusive_reason else None
        run.priority = out.result.priority.value
        run.priority_score = out.result.priority_score
        run.environment_scope = out.result.environment_scope
        run.early_exit = out.result.early_exit
        run.finding = out.finding.model_dump(mode="json")
        run.result = out.result.model_dump(mode="json")
        run.cost_usd = cost
        run.total_tokens = total_tokens
        run.cache_read_tokens = cache_read
        run.latency_s = latency
        # replace invocations
        for inv in list(await s.execute(select(db.AgentInvocation).where(db.AgentInvocation.run_id == run_id))):
            await s.delete(inv[0])
        for seq, i in enumerate(out.invocations):
            s.add(db.AgentInvocation(
                run_id=run_id, seq=seq, agent=i.agent, model_name=i.model_name, config_hash=i.config_hash,
                input_tokens=i.input_tokens, output_tokens=i.output_tokens,
                cache_read_tokens=i.cache_read_tokens, cache_write_tokens=i.cache_write_tokens,
                cost_usd=i.cost_usd, cost_estimated=i.cost_estimated, latency_s=i.latency_s,
                requests=i.requests, repeated_tool_calls=i.repeated_tool_calls,
                tools_called=i.tools_called, skills_loaded=i.skills_loaded))
        await s.commit()
    return run_id


async def finish_batch(batch_id: str, status: str = "complete") -> None:
    async with db.session() as s:
        batch = await s.get(db.Batch, batch_id)
        if batch:
            batch.status = status
            await s.commit()


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
            .group_by(db.TriageRun.verdict))).all())
        return {"id": batch.id, "status": batch.status, "label": batch.label,
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
        "early_exit": r.early_exit, "cost_usd": r.cost_usd, "total_tokens": r.total_tokens,
        "cache_read_tokens": r.cache_read_tokens, "latency_s": r.latency_s,
        "created_at": r.created_at.isoformat(),
    }


def payload_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def run_config_signature(out: TriageRunOutput) -> str:
    return payload_hash(canonical_json({i.agent: i.config_hash for i in out.invocations}))
