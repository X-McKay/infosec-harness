"""Submit a batch: start the Temporal workflow, persist results, optionally write back to ADO.

Also provides a Temporal-free local runner (LocalOps + the graph) for the CLI's offline
demo and for environments without a Temporal server.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime

from infosec_harness.domain.models import FindingInput, TriageRunOutput
from infosec_harness.persistence import store
from infosec_harness.settings import get_settings


def new_batch_id(label: str) -> str:
    seed = f"{label}:{datetime.now(UTC).isoformat()}:{uuid.uuid4()}"
    return "batch-" + hashlib.sha256(seed.encode()).hexdigest()[:16]


async def submit_via_temporal(findings: list[FindingInput], *, label: str = "") -> str:
    """Persist acceptance before starting Temporal; reconciliation retries interrupted starts."""
    from infosec_harness.persistence.lifecycle import accept_batch
    batch_id = new_batch_id(label)
    payload = {"findings": [f.model_dump(mode="json") for f in findings],
               "per_repo_concurrency": get_settings().per_repo_concurrency,
               "batch_id": batch_id}
    await accept_batch(batch_id, findings, label, payload)
    await start_accepted_batch(batch_id, payload)
    return batch_id


async def start_accepted_batch(batch_id: str, payload: dict) -> None:
    import logging

    from temporalio.exceptions import WorkflowAlreadyStartedError

    from infosec_harness.workflows.worker import connect
    from infosec_harness.workflows.workflows import TriageBatchWorkflow
    try:
        client = await connect()
        await client.start_workflow(TriageBatchWorkflow.run, payload,
            id=f"batch:{batch_id}", task_queue=get_settings().task_queue)
    except WorkflowAlreadyStartedError:
        pass  # An earlier start succeeded before its acknowledgement was persisted.
    except Exception:
        logging.getLogger(__name__).exception("Batch %s accepted; workflow start will be retried", batch_id)
        return
    from sqlalchemy import update

    from infosec_harness.persistence import db
    async with db.session() as session:
        await session.execute(update(db.Batch).where(db.Batch.id == batch_id,
                              db.Batch.status == "accepted").values(status="running"))
        await session.commit()
        batch = await session.get(db.Batch, batch_id)
        cancel_requested = batch is not None and batch.status in {"cancellation_requested", "cancelled"}
    if cancel_requested:
        await client.get_workflow_handle(f"batch:{batch_id}").cancel()


async def cancel_durable_batch(batch_id: str) -> str:
    """Cancellation intent survives API loss and races with acceptance/start reconciliation."""
    from temporalio.service import RPCError, RPCStatusCode

    from infosec_harness.persistence import db, lifecycle
    from infosec_harness.workflows.worker import connect
    async with db.session() as session:
        batch = await session.get(db.Batch, batch_id)
        if batch is None:
            raise KeyError(batch_id)
        if batch.status in {"complete", "failed", "cancelled"}:
            return batch.status
        batch.status = "cancellation_requested"
        await session.commit()
    client = await connect()
    try:
        await client.get_workflow_handle(f"batch:{batch_id}").cancel()
    except RPCError as exc:
        if exc.status != RPCStatusCode.NOT_FOUND:
            raise
        await lifecycle.finish_pending(batch_id, "cancelled", "Cancelled before workflow start")
        return "cancelled"
    return "cancellation_requested"


async def reconcile_submissions() -> None:
    from infosec_harness.persistence.lifecycle import pending_submissions
    for batch_id, payload in await pending_submissions():
        await start_accepted_batch(batch_id, payload)
    from sqlalchemy import select

    from infosec_harness.persistence import db
    async with db.session() as session:
        ids = (await session.scalars(select(db.Batch.id).where(
            db.Batch.status == "cancellation_requested"))).all()
    for batch_id in ids:
        await cancel_durable_batch(batch_id)


async def run_local(findings: list[FindingInput], *, label: str = "", persist: bool = True,
                    sandbox: bool | None = None) -> tuple[str, list[TriageRunOutput]]:
    """Run the full pipeline in-process (no Temporal). Used by the CLI demo and tests.

    When ``sandbox`` is None, the gVisor sandbox is used only if its runtime is available;
    otherwise builds/probes are skipped so the pipeline still runs offline.
    """
    if get_settings().model_mode != "stub":
        raise ValueError("Real assessments require Temporal; local mode is for stub demos.")
    from infosec_harness.graph.local import triage_batch_local
    from infosec_harness.sandbox import docker

    if sandbox is None:
        sandbox = await docker.docker_available() and await docker.runtime_available()
    batch_id = new_batch_id(label)
    outputs = await triage_batch_local(findings, sandbox=sandbox)
    if persist:
        await store.create_batch(batch_id, source_kind=_kind(findings), label=label, count=len(findings))
        await _persist_and_writeback(batch_id, outputs)
        from sqlalchemy import select

        from infosec_harness.persistence import db
        async with db.session() as session:
            rows = (await session.execute(select(db.TriageRun).where(db.TriageRun.batch_id == batch_id))).scalars().all()
            for row in rows:
                row.telemetry = {**(row.telemetry or {}), "population": "demo"}
            await session.commit()
    return batch_id, outputs


async def _persist_and_writeback(batch_id: str, outputs: list[TriageRunOutput]) -> None:
    run_ids = {}
    for out in outputs:
        run_ids[out.finding.fingerprint] = await store.save_run_output(batch_id, out)
    await store.finish_batch(batch_id)
    if get_settings().ado_writeback_enabled:
        await _writeback(outputs, run_ids)


async def _writeback(outputs: list[TriageRunOutput], run_ids: dict[str, str]) -> None:
    from sqlalchemy import select

    from infosec_harness.integrations import ado
    from infosec_harness.persistence import db

    s = get_settings()
    for out in outputs:
        wi = out.finding.ado_work_item_id
        if wi is None:
            continue
        text = ado.render_comment(out, s.ui_base_url)
        payload_hash = store.payload_hash(text)
        async with db.session() as session:
            row = (await session.execute(
                select(db.AdoSync).where(db.AdoSync.work_item_id == wi))).scalar_one_or_none()
            if row and row.payload_hash == payload_hash:
                continue  # nothing changed since last write-back
            comment_id = await ado.post_or_update_comment(wi, text, row.comment_id if row else None)
            if row is None:
                row = db.AdoSync(run_id=run_ids[out.finding.fingerprint], work_item_id=wi)
                session.add(row)
            row.comment_id = comment_id
            row.payload_hash = payload_hash
            await session.commit()


def _kind(findings: list[FindingInput]) -> str:
    kinds = {f.source_kind.value for f in findings}
    return kinds.pop() if len(kinds) == 1 else "mixed"
