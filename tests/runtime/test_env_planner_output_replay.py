"""Recorded environment outputs retain their parser, identity and spec provenance."""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic_ai.usage import RunUsage

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.durable import (
    AGENTS,
    CONFIGS,
    LEGACY_ENV_PLANNER_CONFIG,
    LEGACY_OUTPUT_AGENTS,
)
from infosec_harness.agents.outputs import PlannedEnvironmentOutput
from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.workflows import temporal_ops
from infosec_harness.workflows.temporal_ops import TemporalOps


@pytest.mark.parametrize("enabled", [False, True])
def test_env_independent_marker_selects_matching_agent_and_spec_once(monkeypatch, enabled):
    calls = []
    def patched(marker):
        calls.append(marker)
        return marker in {"agent-output-contracts-v2", "build-serial-tool-settings-v1"} or (marker == "env-planner-output-v2" and enabled)
    monkeypatch.setattr(temporal_ops.workflow, "patched", patched)
    monkeypatch.setattr(temporal_ops.workflow.unsafe, "is_replaying", lambda: True)
    ops = TemporalOps()
    expected_agent = AGENTS["env-planner"] if enabled else LEGACY_OUTPUT_AGENTS["env-planner"]
    expected_config = CONFIGS["env-planner"] if enabled else LEGACY_ENV_PLANNER_CONFIG
    assert ops._agent_for("env-planner") is expected_agent
    assert ops._config_for("env-planner") is expected_config
    assert ops._agent_for("env-planner") is expected_agent
    assert calls == ["env-planner-output-v2"]
    assert expected_agent.name == ("env-planner-output-v2" if enabled else "env-planner")
    assert expected_config.effective_spec["metadata"]["version"] == ("1.0.5" if enabled else "1.0.4")
    assert ops._agent_for("partial-build") is AGENTS["partial-build"]


@pytest.mark.parametrize("enabled", [False, True])
async def test_mock_recorded_response_retains_generation_accounting_and_output(monkeypatch, enabled):
    # This is a replay-selection regression, not a real Temporal history or provider run.
    events = []
    def patched(marker):
        events.append(marker)
        return marker == "env-planner-output-v2" and enabled
    monkeypatch.setattr(temporal_ops.workflow, "patched", patched)
    monkeypatch.setattr(temporal_ops.workflow.unsafe, "is_replaying", lambda: True)
    from datetime import UTC, datetime
    monkeypatch.setattr(temporal_ops.workflow, "now", lambda: datetime(2026, 1, 1, tzinfo=UTC))
    ops = TemporalOps()
    agent = ops._agent_for("env-planner")
    # The old saved response omitted install_commands; its shared parser supplied [].
    payload = {"base_image": "python:3.12-slim", "test_command": "python -m pytest {test_file}"}
    if enabled:
        payload["install_commands"] = []
    output = agent.output_type.model_validate(payload)
    result = SimpleNamespace(output=output, usage=RunUsage(), all_messages=lambda: [])
    async def recorded_response(*_args, **_kwargs):
        events.append("recorded-model-response")
        return result
    run = AsyncMock(side_effect=recorded_response)
    monkeypatch.setattr(agent, "run", run)
    async def reserve_result(*_args, **_kwargs):
        events.append("reserve")
        return None
    async def settle_result(*_args, **_kwargs):
        events.append("settle")
    reserve = AsyncMock(side_effect=reserve_result)
    settle = AsyncMock(side_effect=settle_result)
    monkeypatch.setattr(ops._accounting, "reserve", reserve)
    monkeypatch.setattr(ops._accounting, "settle", settle)
    outcome = await ops.run_agent("env-planner", ["recorded prompt"], AgentDeps(repo_path="/snapshot"))
    config = CONFIGS["env-planner"] if enabled else LEGACY_ENV_PLANNER_CONFIG
    assert reserve.await_args.args[0].effective_spec["metadata"]["version"] == ("1.0.5" if enabled else "1.0.4")
    assert reserve.await_args.kwargs["configuration_digest"] == config.digest
    assert outcome.effective_config["effective_spec"] == config.effective_spec
    assert outcome.config_hash == config.digest
    assert type(outcome.output) is (PlannedEnvironmentOutput if enabled else EnvironmentSpec)
    assert outcome.output.install_commands == []
    run.assert_awaited_once()
    settle.assert_awaited_once()
    assert events == ["env-planner-output-v2", "reserve", "recorded-model-response", "settle"]


async def test_old_env_live_frontier_stops_before_budget_or_request(monkeypatch):
    monkeypatch.setattr(temporal_ops.workflow, "patched", lambda marker: marker == "agent-output-contracts-v2")
    monkeypatch.setattr(temporal_ops.workflow.unsafe, "is_replaying", lambda: False)
    ops = TemporalOps()
    reserve = AsyncMock(side_effect=AssertionError("Must not reserve under legacy provenance"))
    monkeypatch.setattr(ops._accounting, "reserve", reserve)
    with pytest.raises(RuntimeError, match="legacy env-planner execution has no recorded model activity"):
        await ops.run_agent("env-planner", ["new frontier"], AgentDeps(repo_path="/snapshot"))
    reserve.assert_not_awaited()


def test_retained_spec_config_preserves_original_budget_and_shared_parser():
    old, new = LEGACY_ENV_PLANNER_CONFIG, CONFIGS["env-planner"]
    assert old.effective_spec["metadata"]["version"] == "1.0.4"
    assert old.digest != new.digest
    assert old.budget == new.budget
    assert LEGACY_OUTPUT_AGENTS["env-planner"].output_type is EnvironmentSpec
    assert AGENTS["env-planner"].output_type is PlannedEnvironmentOutput
