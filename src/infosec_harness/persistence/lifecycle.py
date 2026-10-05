"""Durable submission intent and idempotent finding progress, shared by API and activities."""
from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from infosec_harness.domain.models import (
    TERMINAL_BATCH_STATUSES,
    TERMINAL_RUN_STATUSES,
    BatchStatus,
    Finding,
    FindingInput,
    RunStatus,
)
from infosec_harness.persistence import db, store
from infosec_harness.persistence.budgets import initial_state
from infosec_harness.persistence.run_telemetry import RunTelemetry
from infosec_harness.settings import get_settings


async def accept_batch(batch_id: str, findings: list[FindingInput], label: str,
                       submission: Mapping[str, Any] | None, *,
                       agent_config_digests: Mapping[str, str]) -> None:
    """Atomically record start intent, the root budget and all findings.

    Duplicate fingerprints coalesce. ``agent_config_digests`` pins the agent configurations a
    worker must run for this batch; the submitter resolves them. ``submission`` is the workflow
    start payload reconciliation retries; None for a batch run in-process.
    """
    settings = get_settings()
    normalized = {f.fingerprint: f for f in map(Finding.from_input, findings)}
    now = datetime.now(UTC)
    population = "demo" if settings.model_mode == "stub" else "operational"
    async with db.session() as session:
        if await session.get(db.Batch, batch_id):
            return
        budget_state = initial_state({
            "requests": settings.root_max_requests, "tokens": settings.root_max_tokens,
            "cost_usd": settings.root_max_cost_usd,
            "tool_calls": settings.root_max_tool_calls, "agent_runs": settings.root_max_agent_runs,
            "execution_seconds": settings.root_max_execution_seconds},
            elapsed_seconds=settings.root_max_elapsed_seconds)
        budget_state["agent_config_digests"] = dict(agent_config_digests)
        session.add(db.BudgetLedger(root_id=batch_id, state=budget_state))
        session.add(db.Batch(id=batch_id, label=label, source_kind=_source_kind(findings),
                            status=BatchStatus.accepted, workflow_id=f"batch:{batch_id}",
                            finding_count=len(normalized),
                            submission=dict(submission) if submission is not None else None))
        await session.flush()
        for finding in normalized.values():
            run_id = store.run_id(batch_id, finding.fingerprint)
            session.add(db.TriageRun(id=run_id, batch_id=batch_id,
                fingerprint=finding.fingerprint, repo_url=finding.repo_url,
                revision=finding.revision, title=finding.title, cwe=finding.cwe,
                severity=finding.severity.value, finding=finding.model_dump(mode="json"),
                status=RunStatus.pending,
                telemetry=RunTelemetry.accepted(population, now).stored()))
            await session.flush()
            session.add(db.RunEventRecord(id=f"{run_id}:accepted", run_id=run_id, phase="accepted",
                                          detail="Accepted durably; waiting for workflow execution."))
        await session.commit()


def _source_kind(findings: list[FindingInput]) -> str:
    kinds = {f.source_kind.value for f in findings}
    return kinds.pop() if len(kinds) == 1 else "mixed"


async def record_progress(batch_id: str, fingerprint: str, phase: str,
                          event_key: str, detail: str = "") -> None:
    """Record one idempotent progress event; a run that was never accepted is an error."""
    run_id = store.run_id(batch_id, fingerprint)
    async with db.session() as session:
        run = await session.get(db.TriageRun, run_id)
        if run is None:
            raise store.MissingDurableRecord(f"run {run_id} of batch {batch_id} was never accepted")
        existing_event = await session.get(db.RunEventRecord, f"{run_id}:{event_key}")
        if existing_event and not (phase in TERMINAL_RUN_STATUSES and run.status not in TERMINAL_RUN_STATUSES):
            return
        if not existing_event:
            session.add(db.RunEventRecord(id=f"{run_id}:{event_key}", run_id=run_id,
                                          phase=phase, detail=detail[:4000]))
        previous_status = run.status
        status = previous_status
        can_update = previous_status not in TERMINAL_RUN_STATUSES or phase == previous_status
        telemetry = RunTelemetry.read(run.telemetry)
        if telemetry is None:
            raise store.MissingDurableRecord(f"run {run_id} has no accepted telemetry")
        if can_update:
            status = phase if phase in TERMINAL_RUN_STATUSES else RunStatus.running
            telemetry = telemetry.progressed(phase, datetime.now(UTC),
                                             terminal=phase in TERMINAL_RUN_STATUSES)
        try:
            if can_update:
                # A terminal write that wins after the read must never be resurrected.
                await session.execute(update(db.TriageRun).where(
                    db.TriageRun.id == run_id,
                    db.TriageRun.status.notin_(TERMINAL_RUN_STATUSES) if phase in TERMINAL_RUN_STATUSES and previous_status not in TERMINAL_RUN_STATUSES
                    else db.TriageRun.status == previous_status
                ).values(status=status, telemetry=telemetry.stored()))
            await session.commit()
        except IntegrityError:
            await session.rollback()
            if await session.get(db.RunEventRecord, f"{run_id}:{event_key}") is None:
                raise
            # Concurrent delivery of the same event already committed successfully.


async def pending_submissions() -> list[tuple[str, dict]]:
    async with db.session() as session:
        batches = (await session.execute(select(db.Batch).where(
            db.Batch.status == BatchStatus.accepted, db.Batch.submission.is_not(None)))).scalars().all()
        return [(b.id, b.submission) for b in batches if isinstance(b.submission, dict)]


async def mark_started(batch_id: str) -> bool:
    """Record that the workflow start was acknowledged; True when cancellation was requested
    meanwhile, so the caller must deliver it to the started workflow."""
    async with db.session() as session:
        await session.execute(update(db.Batch).where(
            db.Batch.id == batch_id, db.Batch.status == BatchStatus.accepted
        ).values(status=BatchStatus.running))
        await session.commit()
        batch = await session.get(db.Batch, batch_id)
        return batch is not None and batch.status in {BatchStatus.cancellation_requested,
                                                       BatchStatus.cancelled}


async def request_cancellation(batch_id: str) -> BatchStatus:
    """Durably record cancellation intent; a terminal batch keeps (and returns) its status.

    Raises ``KeyError`` for an unknown batch.
    """
    async with db.session() as session:
        batch = await session.get(db.Batch, batch_id)
        if batch is None:
            raise KeyError(batch_id)
        if batch.status in TERMINAL_BATCH_STATUSES:
            return BatchStatus(batch.status)
        batch.status = BatchStatus.cancellation_requested
        await session.commit()
    return BatchStatus.cancellation_requested


async def cancellation_requested() -> list[str]:
    async with db.session() as session:
        return list((await session.scalars(select(db.Batch.id).where(
            db.Batch.status == BatchStatus.cancellation_requested))).all())


async def finish_pending(batch_id: str, status: BatchStatus | str, detail: str) -> None:
    """Preserve completed siblings when a batch is cancelled or fails."""
    status = BatchStatus(status)
    async with db.session() as session:
        pending = list((await session.scalars(select(db.TriageRun.fingerprint).where(
            db.TriageRun.batch_id == batch_id,
            db.TriageRun.status.notin_(TERMINAL_RUN_STATUSES)))).all())
    if pending and status == BatchStatus.complete:
        status = BatchStatus.failed
        detail = "Workflow finished without persisting every accepted finding."
    for fingerprint in pending:
        await record_progress(batch_id, fingerprint, status, f"terminal:{status}", detail)
    await store.finish_batch(batch_id, status)
