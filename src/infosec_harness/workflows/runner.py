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
    """Start TriageBatchWorkflow, await it, persist every run. Returns the batch id."""
    from infosec_harness.workflows.worker import connect
    from infosec_harness.workflows.workflows import TriageBatchWorkflow

    s = get_settings()
    batch_id = new_batch_id(label)
    workflow_id = f"batch:{batch_id}"
    await store.create_batch(batch_id, source_kind=_kind(findings), label=label,
                             count=len(findings), workflow_id=workflow_id)
    client = await connect()
    outputs: list[TriageRunOutput] = await client.execute_workflow(
        TriageBatchWorkflow.run,
        {"findings": [f.model_dump() for f in findings], "per_repo_concurrency": s.per_repo_concurrency},
        id=workflow_id, task_queue=s.task_queue,
    )
    await _persist_and_writeback(batch_id, outputs)
    return batch_id


async def run_local(findings: list[FindingInput], *, label: str = "", persist: bool = True,
                    sandbox: bool | None = None) -> tuple[str, list[TriageRunOutput]]:
    """Run the full pipeline in-process (no Temporal). Used by the CLI demo and tests.

    When ``sandbox`` is None, the gVisor sandbox is used only if its runtime is available;
    otherwise builds/probes are skipped so the pipeline still runs offline.
    """
    from infosec_harness.graph.local import triage_batch_local
    from infosec_harness.sandbox import docker

    if sandbox is None:
        sandbox = await docker.docker_available() and await docker.runtime_available()
    batch_id = new_batch_id(label)
    outputs = await triage_batch_local(findings, sandbox=sandbox)
    if persist:
        await store.create_batch(batch_id, source_kind=_kind(findings), label=label, count=len(findings))
        await _persist_and_writeback(batch_id, outputs)
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
