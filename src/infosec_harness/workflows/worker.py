"""Temporal worker entrypoint: registers the workflows and activities.

Model/tool calls inside the durable agents are registered automatically by the
PydanticAIPlugin from each workflow's ``__pydantic_ai_agents__``.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from temporalio.client import Client
from temporalio.worker import Worker

from infosec_harness.settings import get_settings
from infosec_harness.workflows.activities import ALL_ACTIVITIES
from infosec_harness.workflows.workflows import (
    ComponentPreparationWorkflow,
    FindingTriageWorkflow,
    TriageBatchWorkflow,
)

# TriageBatchWorkflow.__pydantic_ai_agents__ carries the durable agents; PydanticAIPlugin
# registers their model/tool activities on the worker (once, worker-global).
WORKFLOWS = [TriageBatchWorkflow, ComponentPreparationWorkflow, FindingTriageWorkflow]


async def connect() -> Client:
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin

    from infosec_harness.services import temporal_connection_options

    s = get_settings()
    return await Client.connect(s.temporal_address, namespace=s.temporal_namespace,
                                plugins=[PydanticAIPlugin()], **temporal_connection_options(s))


async def run_worker() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logger = logging.getLogger(__name__)
    s = get_settings()
    from infosec_harness.agents import models
    if (s.model_mode == "live" and s.task_queue == "triage"
            and any(b.transport == "brokered" for b in models.load_models_config().backends.values())):
        raise RuntimeError("Brokered deployment requires a new explicit task queue; drain legacy direct workers separately")
    from infosec_harness import telemetry

    # Installs the tracer provider and turns on the agents' `instrument: true`. The
    # workflow itself must not touch a tracer (nondeterministic under replay); Temporal
    # emits workflow/activity spans, and the model/tool activities run in this process.
    if telemetry.configure("worker"):
        logger.info("Tracing enabled for worker")
    from infosec_harness.sandbox import docker
    try:
        await docker.ensure_builder()
    except Exception:  # noqa: BLE001 - retain worker access to status/recovery activities
        logger.exception("Sandbox builder unavailable; environment builds will fail closed until runtime setup succeeds")
    client = await connect()
    worker = Worker(client, task_queue=s.task_queue, workflows=WORKFLOWS, activities=ALL_ACTIVITIES,
                    max_heartbeat_throttle_interval=timedelta(seconds=5))
    logger.info("Worker listening on task queue %s at %s", s.task_queue, s.temporal_address)
    await worker.run()


def main() -> None:
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
