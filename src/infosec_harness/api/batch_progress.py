"""Read-only batch progress from selected persisted finding records; no inferred execution."""

from collections import defaultdict
from datetime import UTC, datetime

from sqlalchemy import func, select

from infosec_harness.domain.models import TERMINAL_BATCH_STATUSES, TERMINAL_RUN_STATUSES
from infosec_harness.persistence import db
from infosec_harness.persistence.population import Population, run_population


def timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.astimezone(UTC) if parsed.tzinfo is not None else None
    except ValueError:
        return None


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


async def batch_progress(batch_ids: list[str], population: Population | None = None) -> dict:
    if not batch_ids:
        return {}
    predicate = [db.TriageRun.batch_id.in_(batch_ids)]
    if population is not None:
        predicate.append(run_population(population))
    async with db.session() as session:
        rows = (
            await session.execute(
                select(
                    db.TriageRun.batch_id,
                    db.TriageRun.status,
                    db.TriageRun.telemetry["phase"].as_string(),
                    db.TriageRun.telemetry["accepted_at"].as_string(),
                    db.TriageRun.telemetry["completed_at"].as_string(),
                    db.TriageRun.created_at,
                    db.Batch.status,
                )
                .join(db.Batch, db.Batch.id == db.TriageRun.batch_id)
                .where(*predicate)
            )
        ).all()
        events = dict(
            (
                await session.execute(
                    select(db.TriageRun.batch_id, func.max(db.RunEventRecord.created_at))
                    .join(db.RunEventRecord, db.RunEventRecord.run_id == db.TriageRun.id)
                    .where(*predicate)
                    .group_by(db.TriageRun.batch_id)
                )
            ).all()
        )
    by_batch: dict[str, list] = defaultdict(list)
    for row in rows:  # grouped once: linear in the selected runs, not runs x batches
        by_batch[row[0]].append(row)
    result = {}
    for identity in batch_ids:
        selected = by_batch.get(identity, [])
        states, phases, starts, ends, activity = {}, {}, [], [], []
        all_finished = bool(selected)
        for _, state, phase, accepted, completed, created, batch_state in selected:
            states[state] = states.get(state, 0) + 1
            if state not in TERMINAL_RUN_STATUSES:
                label = phase if isinstance(phase, str) and phase else state
                phases[label] = phases.get(label, 0) + 1
            start, end = timestamp(accepted), timestamp(completed)
            if start:
                starts.append(start)
            if end:
                ends.append(end)
            all_finished &= (state in TERMINAL_RUN_STATUSES
                             and batch_state in TERMINAL_BATCH_STATUSES and end is not None)
            activity.extend(x for x in (start, end, _utc(created)) if x)
        if identity in events:
            activity.append(_utc(events[identity]))
        result[identity] = {
            "status_counts": states,
            "current_phases": phases,
            "started_at": min(starts).isoformat()
            if starts and len(starts) == len(selected)
            else None,
            "completed_at": max(ends).isoformat() if all_finished else None,
            "last_activity_at": max(activity).isoformat() if activity else None,
        }
    return result
