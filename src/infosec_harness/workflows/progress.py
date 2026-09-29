"""Activity boundary for durable progress and output persistence."""
from temporalio import activity

from infosec_harness.domain.models import TriageRunOutput
from infosec_harness.persistence import lifecycle, store
from infosec_harness.settings import get_settings


@activity.defn
async def progress_activity(args: dict) -> None:
    await lifecycle.record_progress(**args)


@activity.defn
async def save_output_activity(args: dict) -> str:
    out = TriageRunOutput.model_validate(args["output"])
    run_id = await store.save_run_output(args["batch_id"], out)
    stored = await store.get_run(run_id)
    phase = stored["status"] if stored else ("needs_info" if out.needs_info else "complete")
    await lifecycle.record_progress(args["batch_id"], out.finding.fingerprint,
                                    phase, f"terminal:{phase}")
    return run_id


@activity.defn
async def writeback_output_activity(args: dict) -> None:
    """Restore optional ADO writeback after the output itself is durable."""
    if not get_settings().ado_writeback_enabled:
        return
    out = TriageRunOutput.model_validate(args["output"])
    if out.finding.ado_work_item_id is None:
        return
    from infosec_harness.workflows.runner import _writeback
    await _writeback([out], {out.finding.fingerprint: args["run_id"]})


@activity.defn
async def finish_batch_activity(args: dict) -> None:
    await lifecycle.finish_pending(args["batch_id"], args.get("status", "complete"),
                                   args.get("detail", ""))


@activity.defn
async def reserve_budget_activity(args: dict) -> dict | None:
    from infosec_harness.persistence.budgets import reserve
    return await reserve(**args)


@activity.defn
async def settle_budget_activity(args: dict) -> dict | None:
    from infosec_harness.persistence.budgets import settle
    return await settle(**args)


@activity.defn
async def remaining_budget_time_activity(root_id: str) -> float | None:
    from infosec_harness.persistence.budgets import remaining_time
    return await remaining_time(root_id)


ACTIVITIES = [progress_activity, save_output_activity, writeback_output_activity,
              finish_batch_activity,
              reserve_budget_activity, settle_budget_activity, remaining_budget_time_activity]
