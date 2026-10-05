"""Temporal workflow and worker for the broker service qualification (layer D).

The test host and the fixture worker both import this module so they register the same
workflow. Under an explicit service qualification manifest, only the model activity timeout is
shortened so a killed worker's retry is observed promptly; retry policy and the real registered
model/tool construction are unchanged.
"""
from __future__ import annotations

import os
from pathlib import Path

from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from datetime import timedelta

    from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
    from temporalio.client import Client
    from temporalio.worker import Worker
    from temporalio.workflow import ActivityConfig

    from infosec_harness.agents import registry
    from infosec_harness.agents.deps import AgentDeps

    # Must precede the durable agent import, which captures the activity configuration.
    if os.environ.get("HARNESS_BROKER_SERVICE_MANIFEST"):
        registry.MODEL_ACTIVITY = ActivityConfig(start_to_close_timeout=timedelta(seconds=20),
                                                 retry_policy=registry.ACTIVITY_RETRY)
    from infosec_harness.agents.durable import AGENT_LIST
    from infosec_harness.qualification.broker.service import AGENTS
    from infosec_harness.workflows.activities import ALL_ACTIVITIES
    from infosec_harness.workflows.temporal_ops import TemporalOps

WORKFLOW_NAME = "BrokerServiceQualificationWorkflow"


@workflow.defn(name=WORKFLOW_NAME)
class BrokerQualificationWorkflow:
    __pydantic_ai_agents__ = AGENT_LIST

    @workflow.run
    async def run(self, args: dict) -> dict:
        ops = TemporalOps(root_id=args["root_id"], fingerprint="service-qualification")
        try:
            if args.get("all_agents"):
                outputs = {}
                for name in AGENTS:
                    result = await ops.run_agent(name, [
                        f"<broker-qualification-agent>{name}</broker-qualification-agent>\n"
                        "Qualification contains no concrete weakness evidence."
                    ], AgentDeps(repo_path=args["repo"], report_text="No concrete weakness evidence."))
                    outputs[name] = {"output": result.output.model_dump(mode="json"),
                        "output_type": type(result.output).__name__, "requests": result.requests,
                        "input_tokens": result.input_tokens, "output_tokens": result.output_tokens}
                return outputs
            result = await ops.run_agent("context", ["Inspect sample.py; return unknown reachability."],
                AgentDeps(repo_path=args["repo"]))
            return {"summary": result.output.summary, "requests": result.requests,
                    "tools": result.tools_called}
        finally:
            await ops.close()


async def serve_worker(manifest: dict) -> None:
    client = await Client.connect(manifest["temporal_address"], plugins=[PydanticAIPlugin()])
    worker = Worker(client, task_queue=manifest["task_queue"], workflows=[BrokerQualificationWorkflow],
                    activities=ALL_ACTIVITIES)
    (Path(manifest["directory"]) / "temporal-worker-ready").write_text(str(os.getpid()))
    await worker.run()
