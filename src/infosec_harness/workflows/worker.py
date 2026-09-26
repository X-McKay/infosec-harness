"""Temporal worker entrypoint: registers the workflows and activities.

Model/tool calls inside the durable agents are registered automatically by the
PydanticAIPlugin from each workflow's ``__pydantic_ai_agents__``.
"""

from __future__ import annotations

import asyncio

from temporalio.client import Client
from temporalio.worker import Worker

from infosec_harness.settings import get_settings
from infosec_harness.workflows.activities import ALL_ACTIVITIES
from infosec_harness.workflows.workflows import (
    FindingTriageWorkflow,
    RepoPreparationWorkflow,
    TriageBatchWorkflow,
)

# TriageBatchWorkflow.__pydantic_ai_agents__ carries the durable agents; PydanticAIPlugin
# registers their model/tool activities on the worker (once, worker-global).
WORKFLOWS = [TriageBatchWorkflow, RepoPreparationWorkflow, FindingTriageWorkflow]


async def connect() -> Client:
    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin

    s = get_settings()
    return await Client.connect(s.temporal_address, namespace=s.temporal_namespace,
                                plugins=[PydanticAIPlugin()])


async def run_worker() -> None:
    s = get_settings()
    from infosec_harness import telemetry

    # Installs the tracer provider and turns on the agents' `instrument: true`. The
    # workflow itself must not touch a tracer (nondeterministic under replay); Temporal
    # emits workflow/activity spans, and the model/tool activities run in this process.
    if telemetry.configure("worker"):
        print(f"tracing to {s.otel_exporter_otlp_endpoint}")
    from infosec_harness.sandbox import docker
    try:
        await docker.ensure_builder()  # best-effort; builds still work without buildx
    except Exception as e:  # noqa: BLE001
        print(f"buildx builder setup skipped: {e}")
    client = await connect()
    worker = Worker(client, task_queue=s.task_queue, workflows=WORKFLOWS, activities=ALL_ACTIVITIES)
    print(f"worker listening on task queue {s.task_queue!r} at {s.temporal_address}")
    await worker.run()


def main() -> None:
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
