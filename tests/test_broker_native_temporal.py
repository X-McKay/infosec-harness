"""Explicit native lane qualification only; no automatic native lifecycle actions."""
import os
from pathlib import Path

import pytest
from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from broker_native_temporal_fixture import NATIVE_AGENT
    from pydantic_ai.messages import ModelResponse


@workflow.defn(name="NativeBrokerTemporalRecoveryQualification")
class NativeBrokerTemporalWorkflow:
    __pydantic_ai_agents__ = [NATIVE_AGENT]

    @workflow.run
    async def run(self, prompt: str) -> dict:
        result = await NATIVE_AGENT.run(prompt)
        responses = [message for message in result.all_messages() if isinstance(message, ModelResponse)]
        usage = result.usage
        return {"output": result.output, "requests": usage.requests,
                "input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens,
                "broker": responses[-1].metadata.get("harness_broker") if responses[-1].metadata else None}




async def test_actual_native_agent_string_temporal_saved_retry_and_replay():
    config_path = os.environ.get("HARNESS_NATIVE_TEMPORAL_CONFIG")
    if not config_path:
        pytest.skip("native lane operator handoff required")
    from broker_native_temporal_fixture import qualify
    report = await qualify(Path(config_path))
    assert report["status"] == "passed", report.get("failure_class")
    assert report["provider_dispatches"] == 1
    assert report["maximum_activity_attempt"] == 2
    assert report["same_persisted_request"] is True
    assert report["replay_provider_dispatches"] == 0
    assert report["history_replay"] == report["secret_history_log_scan"] == "passed"
    assert report["worker_cleanup"] == report["workflow_cleanup"] == "passed"
