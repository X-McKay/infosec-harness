"""Durable submission: accept a batch, start its Temporal workflow, deliver cancellation.

Acceptance is persisted before Temporal is contacted; ``reconcile_submissions`` retries any
start (or cancellation) whose acknowledgement was lost.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime

from pydantic import ValidationError

from infosec_harness.domain.models import BatchStatus, FindingInput
from infosec_harness.persistence import lifecycle
from infosec_harness.settings import get_settings
from infosec_harness.workflows.payloads import BatchArgs

logger = logging.getLogger(__name__)


def new_batch_id(label: str) -> str:
    seed = f"{label}:{datetime.now(UTC).isoformat()}:{uuid.uuid4()}"
    return "batch-" + hashlib.sha256(seed.encode()).hexdigest()[:16]


def workflow_id(batch_id: str) -> str:
    return f"batch:{batch_id}"


def accepted_agent_config_digests() -> dict[str, str]:
    """The agent configurations a batch accepted now must be run with, by digest."""
    from infosec_harness.agents.registry import resolved_agent_configs

    return {name: config.digest for name, config in resolved_agent_configs().items()}


async def accept(findings: list[FindingInput], *, label: str,
                 durable: bool = True) -> tuple[str, BatchArgs]:
    """Durably accept a batch: its runs, its root budget and, when durable, its start payload."""
    batch_id = new_batch_id(label)
    args = BatchArgs(batch_id=batch_id, findings=findings,
                     per_repo_concurrency=get_settings().per_repo_concurrency)
    await lifecycle.accept_batch(batch_id, findings, label,
                                 args.model_dump(mode="json") if durable else None,
                                 agent_config_digests=accepted_agent_config_digests())
    return batch_id, args


async def submit_via_temporal(findings: list[FindingInput], *, label: str = "") -> str:
    """Persist acceptance before starting Temporal; reconciliation retries interrupted starts."""
    batch_id, args = await accept(findings, label=label)
    await start_accepted_batch(args)
    return batch_id


async def start_accepted_batch(args: BatchArgs) -> None:
    from temporalio.exceptions import WorkflowAlreadyStartedError

    from infosec_harness.workflows.worker import connect
    from infosec_harness.workflows.workflows import TriageBatchWorkflow
    batch_id = args.batch_id
    try:
        client = await connect()
        await client.start_workflow(TriageBatchWorkflow.run, args,
            id=workflow_id(batch_id), task_queue=get_settings().task_queue)
    except WorkflowAlreadyStartedError:
        pass  # An earlier start succeeded before its acknowledgement was persisted.
    except Exception:
        logger.exception("Batch %s accepted; workflow start will be retried", batch_id)
        return
    if await lifecycle.mark_started(batch_id):
        await client.get_workflow_handle(workflow_id(batch_id)).cancel()


async def cancel_durable_batch(batch_id: str) -> BatchStatus:
    """Cancellation intent survives API loss and races with acceptance/start reconciliation."""
    from temporalio.service import RPCError, RPCStatusCode

    from infosec_harness.workflows.worker import connect
    status = await lifecycle.request_cancellation(batch_id)
    if status != BatchStatus.cancellation_requested:
        return status
    client = await connect()
    try:
        await client.get_workflow_handle(workflow_id(batch_id)).cancel()
    except RPCError as exc:
        if exc.status != RPCStatusCode.NOT_FOUND:
            raise
        await lifecycle.finish_pending(batch_id, BatchStatus.cancelled,
                                       "Cancelled before workflow start")
        return BatchStatus.cancelled
    return BatchStatus.cancellation_requested


async def reconcile_submissions() -> None:
    for batch_id, payload in await lifecycle.pending_submissions():
        try:
            args = BatchArgs.model_validate(payload)
        except ValidationError:
            # Not startable as recorded: fail it rather than retrying it forever.
            logger.exception("Batch %s has an invalid start payload; failing it", batch_id)
            await lifecycle.finish_pending(batch_id, BatchStatus.failed,
                                           "The accepted start payload is invalid.")
            continue
        await start_accepted_batch(args)
    for batch_id in await lifecycle.cancellation_requested():
        await cancel_durable_batch(batch_id)
