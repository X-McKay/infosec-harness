"""Durable registration boundary for model-facing output contract revisions."""

from __future__ import annotations

import pytest

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.durable import (
    AGENT_LIST,
    AGENTS,
    INTAKE_GENERATIONS,
    LEGACY_OUTPUT_AGENTS,
    RETAINED_BUILD_AGENTS,
)
from infosec_harness.agents.intake_claims import AtomicFinding
from infosec_harness.agents.outputs import (
    VERDICT_OUTPUTS,
    ContextOutput,
    PartialEnvironmentOutput,
    PlannedEnvironmentOutput,
)
from infosec_harness.domain.models import EnvironmentSpec, ExtractedFinding, FindingContext, Verdict
from infosec_harness.workflows import temporal_ops
from infosec_harness.workflows.temporal_ops import TemporalOps

_REVISED = {"partial-build", "context", "verdict", "build-repair", "intake", "env-planner"}


def test_both_output_contract_generations_are_registered_with_distinct_identities() -> None:
    assert set(LEGACY_OUTPUT_AGENTS) == _REVISED
    assert set(RETAINED_BUILD_AGENTS) == {"build-repair", "partial-build"}
    assert len(AGENT_LIST) == len(AGENTS) + len(_REVISED) + len(RETAINED_BUILD_AGENTS) + 2
    assert len({agent.name for agent in AGENT_LIST}) == len(AGENT_LIST)
    for name in _REVISED:
        assert LEGACY_OUTPUT_AGENTS[name].name == name
        assert AGENTS[name].name == (
            f"{name}-serial-tools-v1" if name in RETAINED_BUILD_AGENTS else
            "intake-output-v4" if name == "intake" else f"{name}-output-v2")
    for name, retained in RETAINED_BUILD_AGENTS.items():
        assert retained.name == f"{name}-output-v2"
        assert "parallel_tool_calls" not in retained.model_settings
        assert "parallel_tool_calls" not in LEGACY_OUTPUT_AGENTS[name].model_settings
        assert AGENTS[name].model_settings["parallel_tool_calls"] is False


def test_all_generation_activity_names_are_unique_in_the_pinned_sdk() -> None:
    from pydantic_ai.durable_exec.temporal import TemporalDurability
    from temporalio import activity

    registered = {}
    for agent in AGENT_LIST:
        capability = TemporalDurability.from_agent(agent)
        assert capability is not None
        names = [activity._Definition.from_callable(fn).name
                 for fn in capability.temporal_activities]
        assert names, agent.name
        registered[agent.name] = names
    names = [name for generation in registered.values() for name in generation]
    assert len(names) == len(set(names)), "generation activities must not overwrite one another"
    for name in RETAINED_BUILD_AGENTS:
        for identity in (name, f"{name}-output-v2", f"{name}-serial-tools-v1"):
            assert f"agent__{identity}__model_request" in registered[identity]


@pytest.mark.parametrize(
    "name, legacy_type, current_type",
    [
        ("partial-build", EnvironmentSpec, PartialEnvironmentOutput),
        ("env-planner", EnvironmentSpec, PlannedEnvironmentOutput),
        ("build-repair", EnvironmentSpec, EnvironmentSpec),
        ("intake", ExtractedFinding, AtomicFinding),
        ("context", FindingContext, ContextOutput),
        ("verdict", Verdict, VERDICT_OUTPUTS),
    ],
)
def test_legacy_registration_keeps_original_parser(
    name: str,
    legacy_type: object,
    current_type: object,
) -> None:
    assert LEGACY_OUTPUT_AGENTS[name].output_type == legacy_type
    assert AGENTS[name].output_type == current_type


@pytest.mark.parametrize("patched", [False, True])
def test_temporal_patch_selects_one_contract_generation(monkeypatch, patched: bool) -> None:
    monkeypatch.setattr(temporal_ops.workflow, "patched", lambda _patch: patched)
    monkeypatch.setattr(temporal_ops.workflow.unsafe, "is_replaying", lambda: True)
    ops = TemporalOps()
    for name in _REVISED:
        selected = ops._agent_for(name)
        expected = (INTAKE_GENERATIONS["quoted"].agent if name == "intake" else AGENTS[name]) if patched else LEGACY_OUTPUT_AGENTS[name]
        assert selected is expected
    # Unchanged agents retain their existing identity on both sides of the patch.
    assert ops._agent_for("recon") is AGENTS["recon"]


def test_unrecorded_legacy_model_request_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(temporal_ops.workflow, "patched", lambda _patch: False)
    monkeypatch.setattr(temporal_ops.workflow.unsafe, "is_replaying", lambda: False)
    with pytest.raises(RuntimeError, match="retry the triage as a new workflow"):
        TemporalOps()._agent_for("context")


async def test_live_legacy_frontier_stops_before_accounting_activity(monkeypatch) -> None:
    monkeypatch.setattr(temporal_ops.workflow, "patched", lambda _patch: False)
    monkeypatch.setattr(temporal_ops.workflow.unsafe, "is_replaying", lambda: False)
    ops = TemporalOps()

    async def unexpected_reserve(*_args, **_kwargs):
        raise AssertionError("budget reservation must not precede compatibility selection")

    monkeypatch.setattr(ops._accounting, "reserve", unexpected_reserve)
    with pytest.raises(RuntimeError, match="retry the triage as a new workflow"):
        await ops.run_agent("context", ["prompt"], AgentDeps(repo_path="/snapshot"))
