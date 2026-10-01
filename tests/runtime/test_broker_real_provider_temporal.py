"""Production registered-model activities for the real-provider pilot."""
from __future__ import annotations

from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from pydantic_ai.messages import CachePoint

    from infosec_harness.agents.deps import AgentDeps
    from infosec_harness.agents.durable import AGENT_LIST
    from infosec_harness.workflows.temporal_ops import TemporalOps


@workflow.defn(name="BrokerRealProviderQualificationWorkflow")
class RealProviderWorkflow:
    __pydantic_ai_agents__ = AGENT_LIST

    @workflow.run
    async def run(self, inputs: dict) -> dict:
        ops = TemporalOps(intake_atomic_inline=True)
        try:
            deps = inputs["deps"]
            if isinstance(deps, dict):
                deps = AgentDeps.model_validate(deps)
            prompt = []
            for part in inputs["prompt"]:
                if isinstance(part, str):
                    prompt.append(part)
                elif (isinstance(part, dict) and set(part) == {"kind", "ttl"}
                      and part["kind"] == "cache-point" and part["ttl"] in {"5m", "1h"}):
                    prompt.append(CachePoint(ttl=part["ttl"]))
                else:
                    raise ValueError("Unexpected public prompt content")
            result = await ops.run_agent(inputs["agent"], prompt, deps)
            return {"output": result.output.model_dump(mode="json"), "output_type": type(result.output).__name__,
                    "requests": result.requests, "input_tokens": result.input_tokens,
                    "output_tokens": result.output_tokens, "tools_called": result.tools_called}
        finally:
            await ops.close()
