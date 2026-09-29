"""Durable submission intent and idempotent finding progress, shared by API and activities."""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from infosec_harness.domain.models import FindingInput
from infosec_harness.intake.adapters import to_finding
from infosec_harness.persistence import db, store

TERMINAL = frozenset({"complete", "needs_info", "failed", "cancelled"})


async def accept_batch(batch_id: str, findings: list[FindingInput], label: str,
                       payload: dict) -> None:
    """Atomically record start intent and all findings. Duplicate fingerprints coalesce."""
    from infosec_harness.agents.registry import resolved_agent_configs
    from infosec_harness.persistence.budgets import initial_state
    from infosec_harness.settings import get_settings
    settings = get_settings()
    normalized = {f.fingerprint: f for f in map(to_finding, findings)}
    now = datetime.now(UTC).isoformat()
    async with db.session() as session:
        if await session.get(db.Batch, batch_id):
            return
        budget_state = initial_state({
            "requests": settings.root_max_requests, "tokens": settings.root_max_tokens,
            "cost_usd": settings.root_max_cost_usd,
            "tool_calls": settings.root_max_tool_calls, "agent_runs": settings.root_max_agent_runs,
            "execution_seconds": settings.root_max_execution_seconds},
            elapsed_seconds=settings.root_max_elapsed_seconds)
        budget_state["agent_config_digests"] = {name: config.digest
            for name, config in resolved_agent_configs().items()}
        session.add(db.BudgetLedger(root_id=batch_id, state=budget_state))
        session.add(db.Batch(id=batch_id, label=label, source_kind="generic_json",
                            status="accepted", workflow_id=f"batch:{batch_id}",
                            finding_count=len(normalized), submission=payload))
        await session.flush()
        for finding in normalized.values():
            run_id = store._run_id(batch_id, finding.fingerprint)
            session.add(db.TriageRun(id=run_id, batch_id=batch_id,
                fingerprint=finding.fingerprint, repo_url=finding.repo_url,
                revision=finding.revision, title=finding.title, cwe=finding.cwe,
                severity=finding.severity.value, finding=finding.model_dump(mode="json"),
                status="pending", telemetry={"schema_version": 1, "accepted_at": now,
                    "phase": "accepted", "population": "demo" if settings.model_mode == "stub" else "operational"}))
            await session.flush()
            session.add(db.RunEvent(id=f"{run_id}:accepted", run_id=run_id, phase="accepted",
                                    detail="Accepted durably; waiting for workflow execution."))
        await session.commit()


async def record_progress(batch_id: str, fingerprint: str, phase: str,
                          event_key: str, detail: str = "") -> None:
    run_id = store._run_id(batch_id, fingerprint)
    async with db.session() as session:
        run = await session.get(db.TriageRun, run_id)
        if run is None:
            return
        existing_event = await session.get(db.RunEvent, f"{run_id}:{event_key}")
        if existing_event and not (phase in TERMINAL and run.status not in TERMINAL):
            return
        if not existing_event:
            session.add(db.RunEvent(id=f"{run_id}:{event_key}", run_id=run_id,
                                    phase=phase, detail=detail[:4000]))
        previous_status = run.status
        telemetry = dict(run.telemetry or {})
        status = previous_status
        can_update = previous_status not in TERMINAL or phase == previous_status
        if can_update:
            status = phase if phase in TERMINAL else "running"
            telemetry.update(phase=phase, updated_at=datetime.now(UTC).isoformat())
            if phase in TERMINAL and telemetry.get("completed_at") is None:
                now = datetime.now(UTC)
                accepted = telemetry.get("accepted_at")
                telemetry.update(completed_at=now.isoformat(),
                    wall_time_s=max(0.0, (now - datetime.fromisoformat(accepted)).total_seconds()) if accepted else None)
        try:
            if can_update:
                # A terminal write that wins after the read must never be resurrected.
                await session.execute(update(db.TriageRun).where(
                    db.TriageRun.id == run_id,
                    db.TriageRun.status.notin_(TERMINAL) if phase in TERMINAL and previous_status not in TERMINAL
                    else db.TriageRun.status == previous_status
                ).values(status=status, telemetry=telemetry))
            await session.commit()
        except IntegrityError:
            await session.rollback()
            if await session.get(db.RunEvent, f"{run_id}:{event_key}") is None:
                raise
            # Concurrent delivery of the same event already committed successfully.



async def pending_submissions() -> list[tuple[str, dict]]:
    async with db.session() as session:
        batches = (await session.execute(select(db.Batch).where(
            db.Batch.status == "accepted", db.Batch.submission.is_not(None)))).scalars().all()
        return [(b.id, b.submission) for b in batches]


async def finish_pending(batch_id: str, status: str, detail: str) -> None:
    """Preserve completed siblings when a batch is cancelled or fails."""
    async with db.session() as session:
        runs = (await session.execute(select(db.TriageRun).where(
            db.TriageRun.batch_id == batch_id))).scalars().all()
        pending = [(r.fingerprint, r.id) for r in runs if r.status not in TERMINAL]
    if pending and status == "complete":
        status = "failed"
        detail = "Workflow finished without persisting every accepted finding."
    for fingerprint, _ in pending:
        await record_progress(batch_id, fingerprint, status, f"terminal:{status}", detail)
    await store.finish_batch(batch_id, status)
