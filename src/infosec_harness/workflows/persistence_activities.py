"""Activities that write the durable record: run progress, outputs, write-back and the ledger."""
from temporalio import activity

from infosec_harness.persistence import budgets, lifecycle, store
from infosec_harness.settings import get_settings
from infosec_harness.workflows.payloads import (
    FinishBatchArgs,
    ProgressArgs,
    ReserveArgs,
    SaveOutputArgs,
    SettleArgs,
    WritebackArgs,
)


@activity.defn
async def progress_activity(args: ProgressArgs) -> None:
    await lifecycle.record_progress(args.batch_id, args.fingerprint, args.phase, args.event_key,
                                    args.detail)


@activity.defn
async def save_output_activity(args: SaveOutputArgs) -> str:
    out = args.output
    run_id = await store.save_run_output(args.batch_id, out)
    # A fenced (failed or cancelled) run keeps its own terminal status.
    phase = await store.run_status(run_id)
    await lifecycle.record_progress(args.batch_id, out.finding.fingerprint,
                                    phase, f"terminal:{phase}")
    return run_id


@activity.defn
async def writeback_output_activity(args: WritebackArgs) -> None:
    """Restore optional ADO writeback after the output itself is durable."""
    if not get_settings().ado_writeback_enabled or args.output.finding.ado_work_item_id is None:
        return
    from infosec_harness.workflows.writeback import write_back
    await write_back([args.output], {args.output.finding.fingerprint: args.run_id})


@activity.defn
async def finish_batch_activity(args: FinishBatchArgs) -> None:
    await lifecycle.finish_pending(args.batch_id, args.status, args.detail)


@activity.defn
async def reserve_budget_activity(args: ReserveArgs) -> dict:
    return await budgets.reserve(**args.model_dump())


@activity.defn
async def settle_budget_activity(args: SettleArgs) -> dict:
    return await budgets.settle(**args.model_dump())


@activity.defn
async def remaining_budget_time_activity(root_id: str) -> float | None:
    return await budgets.remaining_time(root_id)


ACTIVITIES = [progress_activity, save_output_activity, writeback_output_activity,
              finish_batch_activity,
              reserve_budget_activity, settle_budget_activity, remaining_budget_time_activity]
