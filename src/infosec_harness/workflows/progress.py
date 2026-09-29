"""Activity boundary for durable progress and output persistence."""
from temporalio import activity

from infosec_harness.domain.models import TriageRunOutput
from infosec_harness.persistence import lifecycle, store


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


ACTIVITIES = [progress_activity, save_output_activity, finish_batch_activity,
              reserve_budget_activity, settle_budget_activity]
