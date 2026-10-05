"""Temporal workflow and worker for the broker service qualification (layer D).

The test host and the fixture worker both import this module so they register the same
workflow. Both first call ``service.use_service_activity_timeout()``, because importing this
module builds the durable agents.
"""
from __future__ import annotations

from pathlib import Path

from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from infosec_harness.qualification.broker.service import AGENTS
    from infosec_harness.qualification.broker.support import serve_worker as serve
    from infosec_harness.runtime.deps import AgentDeps
    from infosec_harness.runtime.durable import AGENT_LIST
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
    await serve(manifest["temporal_address"], manifest["task_queue"], [BrokerQualificationWorkflow],
                activities=ALL_ACTIVITIES, ready=Path(manifest["directory"]) / "temporal-worker-ready")
