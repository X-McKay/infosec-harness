"""Durable registration boundary for model-facing output contract revisions."""

from __future__ import annotations

import pytest

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.durable import (
    AGENT_LIST,
    AGENTS,
    INTAKE_GENERATIONS,
    LEGACY_OUTPUT_AGENTS,
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
    assert len(AGENT_LIST) == len(AGENTS) + len(_REVISED) + 2
    assert len({agent.name for agent in AGENT_LIST}) == len(AGENT_LIST)
    for name in _REVISED:
        assert LEGACY_OUTPUT_AGENTS[name].name == name
        assert AGENTS[name].name == ("intake-output-v4" if name == "intake" else f"{name}-output-v2")


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
