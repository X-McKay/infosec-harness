"""Temporal workflow for the native Temporal qualification phase: production registered agents."""
from __future__ import annotations

from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from pydantic_ai.messages import CachePoint

    from infosec_harness.agents.deps import AgentDeps
    from infosec_harness.agents.durable import AGENT_LIST
    from infosec_harness.qualification.broker.validators import ROOT_PREFIX, WORKFLOW_NAME
    from infosec_harness.workflows.temporal_ops import TemporalOps


def prompt_from_input(parts: list) -> list:
    """Rebuild the public prompt; only text and the SDK's exact cache marker are admitted."""
    prompt = []
    for part in parts:
        if isinstance(part, str):
            prompt.append(part)
        elif (isinstance(part, dict) and set(part) == {"kind", "ttl"}
              and part["kind"] == "cache-point" and part["ttl"] in {"5m", "1h"}):
            prompt.append(CachePoint(ttl=part["ttl"]))
        else:
            raise ValueError("Unexpected public prompt content")
    return prompt


@workflow.defn(name=WORKFLOW_NAME)
class RealProviderWorkflow:
    __pydantic_ai_agents__ = AGENT_LIST

    @workflow.run
    async def run(self, inputs: dict) -> dict:
        root_id = inputs["root_id"]
        if not isinstance(root_id, str) or not root_id.startswith(ROOT_PREFIX):
            raise ValueError("Qualification workflow requires its owned qualification root")
        prompt = prompt_from_input(inputs["prompt"])
        deps = AgentDeps.model_validate(inputs["deps"])
        # Production accounting against the seeded qualification root, attributed per case.
        ops = TemporalOps(root_id=root_id, fingerprint="qualification:" + inputs["agent"])
        try:
            result = await ops.run_agent(inputs["agent"], prompt, deps)
            return {"output": result.output.model_dump(mode="json"), "output_type": type(result.output).__name__,
                    "requests": result.requests, "input_tokens": result.input_tokens,
                    "output_tokens": result.output_tokens, "tools_called": result.tools_called}
        finally:
            await ops.close()
