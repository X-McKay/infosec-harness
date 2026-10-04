"""Serial tool settings must not rewrite authenticated historical activity contracts."""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.durable import (
    AGENTS,
    CONFIGS,
    LEGACY_OUTPUT_AGENTS,
    RETAINED_BUILD_AGENTS,
    RETAINED_BUILD_CONFIGS,
)
from infosec_harness.workflows import temporal_ops
from infosec_harness.workflows.temporal_ops import TemporalOps


@pytest.mark.parametrize("name", ["build-repair", "partial-build"])
@pytest.mark.parametrize("enabled", [False, True])
def test_settings_generation_pairs_config_and_activity(monkeypatch, name, enabled):
    calls = []

    def patched(marker):
        calls.append(marker)
        return enabled if marker == "build-serial-tool-settings-v1" else True

    monkeypatch.setattr(temporal_ops.workflow, "patched", patched)
    monkeypatch.setattr(temporal_ops.workflow.unsafe, "is_replaying", lambda: True)
    ops = TemporalOps()
    agent = AGENTS[name] if enabled else RETAINED_BUILD_AGENTS[name]
    config = CONFIGS[name] if enabled else RETAINED_BUILD_CONFIGS[name]
    assert ops._agent_for(name) is agent
    assert ops._config_for(name) is config
    assert ops._agent_for(name) is agent
    assert calls.count("build-serial-tool-settings-v1") == 1
    assert agent.name == f"{name}-{'serial-tools-v1' if enabled else 'output-v2'}"
    assert ("parallel_tool_calls" in config.model.requested_settings) is enabled
    if enabled:
        assert config.model.requested_settings["parallel_tool_calls"] is False
    else:
        assert "parallel_tool_calls" not in agent.model_settings


@pytest.mark.parametrize("name", ["build-repair", "partial-build"])
def test_original_parser_also_keeps_pre_serial_model_settings(monkeypatch, name):
    monkeypatch.setattr(temporal_ops.workflow, "patched", lambda _marker: False)
    monkeypatch.setattr(temporal_ops.workflow.unsafe, "is_replaying", lambda: True)
    ops = TemporalOps()
    assert ops._agent_for(name) is LEGACY_OUTPUT_AGENTS[name]
    assert ops._config_for(name) is RETAINED_BUILD_CONFIGS[name]
    assert "parallel_tool_calls" not in LEGACY_OUTPUT_AGENTS[name].model_settings


@pytest.mark.parametrize("name", ["build-repair", "partial-build"])
async def test_absent_marker_live_frontier_cannot_reserve_or_issue(monkeypatch, name):
    monkeypatch.setattr(temporal_ops.workflow, "patched",
                        lambda marker: marker != "build-serial-tool-settings-v1")
    monkeypatch.setattr(temporal_ops.workflow.unsafe, "is_replaying", lambda: False)
    ops = TemporalOps()
    reserve = AsyncMock()
    monkeypatch.setattr(ops._accounting, "reserve", reserve)
    with pytest.raises(RuntimeError):
        await ops.run_agent(name, ["unrecorded prompt"], AgentDeps(repo_path="/snapshot"))
    reserve.assert_not_awaited()


def test_all_serial_and_retained_activity_identities_are_registered():
    from infosec_harness.agents.durable import AGENT_LIST

    for name in ("build-repair", "partial-build"):
        assert AGENTS[name] in AGENT_LIST
        assert RETAINED_BUILD_AGENTS[name] in AGENT_LIST
        assert LEGACY_OUTPUT_AGENTS[name] in AGENT_LIST
        assert len({AGENTS[name].name, RETAINED_BUILD_AGENTS[name].name,
                    LEGACY_OUTPUT_AGENTS[name].name}) == 3


@pytest.mark.parametrize("name", ["build-repair", "partial-build"])
async def test_current_generation_preserves_config_through_issue_and_model(monkeypatch, name):
    from infosec_harness.inference.protocol import ExecutorContract, ReservationBinding

    contract = ExecutorContract(
        backend="mock", model="mock-model", profile="inference-only",
        profile_digest="a" * 64, endpoint="https://provider.test/v1",
        provider_binding="mock-provider", executor_image="sha256:" + "a" * 64,
        supervisor_image="sha256:" + "b" * 64, policy_digest="c" * 64,
        model_settings={"max_tokens": 16000, "parallel_tool_calls": False},
    )
    selected = CONFIGS[name].model_copy(update={
        "model": CONFIGS[name].model.model_copy(update={"broker_contract": contract})
    })
    ops = TemporalOps()
    ops._configs = {**ops._configs, name: selected}
    events = []
    markers = []

    def patched(marker):
        markers.append(marker)
        return True

    monkeypatch.setattr(temporal_ops.workflow, "patched", patched)
    monkeypatch.setattr(temporal_ops.workflow.unsafe, "is_replaying", lambda: False)
    monkeypatch.setattr(temporal_ops.workflow, "info", lambda: SimpleNamespace(run_id="run"))

    async def reserve(config, *, configuration_digest):
        events.append("reserve")
        assert "build-serial-tool-settings-v1" in markers
        assert config.model.broker_contract == contract
        assert configuration_digest == selected.digest
        return "root", "operation"

    async def issue(_activity, request, **_kwargs):
        events.append("issue")
        assert ExecutorContract.model_validate(request["contract"]).digest == contract.digest
        return ReservationBinding(root_id="root", run_id="run", invocation_id="operation",
                                  operation_id="operation", agent=name,
                                  contract_digest=contract.digest,
                                  expires_at=9999999999.0).model_dump(mode="json")

    result = object()

    async def run(_name, _prompt, deps):
        events.append("model")
        assert ops._agent_for(name) is AGENTS[name]
        assert ops._config_for(name) is selected
        assert deps.broker_contract.digest == deps.broker_binding.contract_digest == contract.digest
        return result

    async def settle(_identity, outcome):
        events.append("settle")
        assert outcome is result

    monkeypatch.setattr(ops._accounting, "reserve", reserve)
    monkeypatch.setattr(ops._accounting, "settle", settle)
    monkeypatch.setattr(ops, "_run_agent", run)
    monkeypatch.setattr(temporal_ops.workflow, "execute_activity", issue)
    assert await ops.run_agent(name, ["synthetic prompt"], AgentDeps(repo_path="/snapshot")) is result
    assert events == ["reserve", "issue", "model", "settle"]
    assert markers.count("build-serial-tool-settings-v1") == 1
