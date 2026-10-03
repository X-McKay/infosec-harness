"""Intake generation selects prompt, accounting and model provenance as one unit."""

from __future__ import annotations

import inspect

import pytest

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.durable import AGENT_LIST, INTAKE_GENERATIONS
from infosec_harness.agents.intake_contracts import retained_intake_spec
from infosec_harness.agents.registry import resolve_agent_config
from infosec_harness.agents.render import prompt_text
from infosec_harness.domain.models import AgentOutcome
from infosec_harness.workflows import temporal_ops
from infosec_harness.workflows.temporal_ops import TemporalOps
from infosec_harness.workflows.workflows import FindingTriageWorkflow


def test_four_distinct_host_built_generations_and_retained_config():
    assert {v.agent.name for v in INTAKE_GENERATIONS.values()} == {
        "intake",
        "intake-output-v2",
        "intake-output-v3",
        "intake-output-v4",
    }
    assert {v.agent.name for v in INTAKE_GENERATIONS.values()} <= {a.name for a in AGENT_LIST}
    retained = resolve_agent_config("intake", retained_intake_spec(), durable=True)
    assert INTAKE_GENERATIONS["bare"].config == retained
    assert INTAKE_GENERATIONS["quoted"].config == retained
    assert INTAKE_GENERATIONS["atomic"].config != retained


@pytest.mark.parametrize(
    "atomic,evidence,key",
    [(True, False, "atomic_v3"), (False, True, "quoted"), (False, False, "bare")],
)
def test_generation_selector_preserves_recorded_branch(monkeypatch, atomic, evidence, key):
    monkeypatch.setattr(
        temporal_ops.workflow, "patched", lambda patch: evidence and patch == "intake-evidence-v1"
    )
    monkeypatch.setattr(temporal_ops.workflow.unsafe, "is_replaying", lambda: True)
    ops = TemporalOps(intake_atomic_inline=atomic)
    assert ops._agent_for("intake") is INTAKE_GENERATIONS[key].agent
    assert ops._config_for("intake") is INTAKE_GENERATIONS[key].config
    prompt = prompt_text(ops.intake_prompt("synthetic", {"report": "line one\nline two\r\n"}))
    assert ("report_source_lines" in prompt) is atomic


@pytest.mark.parametrize("evidence", [False, True])
async def test_retained_initial_frontier_stops_before_accounting(monkeypatch, evidence):
    monkeypatch.setattr(
        temporal_ops.workflow, "patched", lambda patch: evidence and patch == "intake-evidence-v1"
    )
    monkeypatch.setattr(temporal_ops.workflow.unsafe, "is_replaying", lambda: False)
    ops = TemporalOps(intake_atomic_inline=False)

    async def forbidden(*args, **kwargs):
        pytest.fail("retained frontier may not reserve or invoke")

    monkeypatch.setattr(ops._accounting, "reserve", forbidden)
    monkeypatch.setattr(ops, "_run_agent", forbidden)
    with pytest.raises(RuntimeError, match="new workflow"):
        await ops.run_agent("intake", [], AgentDeps(repo_path="/synthetic"))


@pytest.mark.parametrize("source_guidance", [False, True])
async def test_current_reservation_uses_same_bundle_and_three_argument_seam(monkeypatch, source_guidance):
    ops = TemporalOps(intake_atomic_inline=True, intake_source_guidance=source_guidance)
    chosen = INTAKE_GENERATIONS["atomic" if source_guidance else "atomic_v3"]
    calls = []

    async def reserve(config, *, configuration_digest):
        calls.append((config, configuration_digest))
        return None

    async def execute(name, prompt, deps):
        assert name == "intake"
        return AgentOutcome(output=None, agent=name, model_name=chosen.model_name)

    async def settle(identity, outcome, *args):
        assert identity is None

    monkeypatch.setattr(ops._accounting, "reserve", reserve)
    monkeypatch.setattr(ops._accounting, "settle", settle)
    monkeypatch.setattr(ops, "_run_agent", execute)
    await ops.run_agent("intake", [], AgentDeps(repo_path="/synthetic"))
    assert calls == [(chosen.config.for_source_files(None), chosen.config.digest)]
    assert list(inspect.signature(TemporalOps._run_agent).parameters) == [
        "self",
        "name",
        "prompt",
        "deps",
    ]


def test_atomic_marker_is_first_workflow_entry_action():
    source = inspect.getsource(FindingTriageWorkflow.run)
    assert source.index('workflow.patched("intake-atomic-inline-v1")') < source.index(
        "FindingInput.model_validate"
    )
    assert source.index('workflow.patched("intake-atomic-inline-v1")') < source.index(
        "normalize_finding_activity"
    )
