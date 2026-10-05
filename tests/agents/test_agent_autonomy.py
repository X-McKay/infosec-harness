"""Agents choose their tool turns; budgets and executed evidence govern acceptance."""

from types import SimpleNamespace

import pytest
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.function import FunctionModel

from infosec_harness.domain.models import (
    DiagnosisKind,
    ProbeSource,
    Verdict,
    VerdictFacts,
    VerdictLabel,
)
from infosec_harness.inference import models
from infosec_harness.runtime.deps import AgentDeps
from infosec_harness.runtime.registry import build_agent, load_spec, resolve_agent_config
from infosec_harness.runtime.validators import validate_probe, verdict_violations
from infosec_harness.sandbox.output import no_tests_executed, oracle_signals, sink_returned


def observing_model(observations, finish_after=None):
    def respond(messages, info):
        names = {tool.name for tool in info.function_tools}
        observations.append(names)
        if finish_after is not None and len(observations) > finish_after:
            return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {
                "base_image": "python:3.12-slim",
                "install_commands": [],
                "test_command": "python -m pytest -s {test_file}",
                "rationale": "Synthetic bounded planning result",
            })])
        return ModelResponse(parts=[ToolCallPart("list_files", {"directory": "."})])

    return FunctionModel(respond)


async def test_build_repair_can_observe_past_the_former_half_budget_cutoff(tmp_path, monkeypatch):
    observations = []
    model = observing_model(observations, finish_after=10)
    monkeypatch.setattr(models, "resolve", lambda *args, **kwargs: model)
    config = resolve_agent_config("build-repair", load_spec("build-repair"))
    result = await build_agent("build-repair", durable=False).run(
        "Prepare the synthetic environment.",
        deps=AgentDeps(repo_path=str(tmp_path)),
        usage_limits=config.budget.to_usage_limits(),
    )
    assert result.usage.requests == 11
    assert all("list_files" in tools for tools in observations)


async def test_agent_autonomy_still_stops_at_the_declared_request_limit(tmp_path, monkeypatch):
    observations = []
    model = observing_model(observations)
    monkeypatch.setattr(models, "resolve", lambda *args, **kwargs: model)
    config = resolve_agent_config("build-repair", load_spec("build-repair"))
    with pytest.raises(UsageLimitExceeded):
        await build_agent("build-repair", durable=False).run(
            "Prepare the synthetic environment.",
            deps=AgentDeps(repo_path=str(tmp_path)),
            usage_limits=config.budget.to_usage_limits(),
        )
    assert len(observations) == config.budget.effective.max_requests


@pytest.mark.parametrize("path,reference", [
    ("tests/test_probe.py", "# Do not use pytest.skip or pytest.importorskip here."),
    ("probe.test.js", "// Avoid test.skip, test.only and describe.skip."),
    ("t/probe.t", "# A missing dependency should fail, not skip_all or SKIP:."),
    ("HarnessProbeTest.java", "// @Disabled, assumeTrue, and var are examples only."),
])
def test_source_comments_do_not_preempt_probe_execution(path, reference):
    probe = ProbeSource(test_file_path=path, content=reference + "\n"
                        "HARNESS_PRECONDITION::n\nHARNESS_SINK_RETURNED::n\nHARNESS_ORACLE::n")
    assert validate_probe(SimpleNamespace(deps=AgentDeps(repo_path="/tmp")), probe) is probe


@pytest.mark.parametrize("observed", [
    "collected 0 items", "Result: NOTESTS", "Tests run: 0", "No tests found",
])
def test_skipped_or_undiscovered_execution_cannot_support_a_definitive_verdict(observed):
    assert no_tests_executed(observed)
    fired, reached = oracle_signals(observed, "n")
    facts = VerdictFacts(
        environment_ready=True, oracle_fired=fired, precondition_reached=reached,
        sink_returned=sink_returned(observed, "n"), last_diagnosis=DiagnosisKind.valid_negative,
    )
    for label in (VerdictLabel.potentially_exploitable, VerdictLabel.likely_not_exploitable):
        assert verdict_violations(Verdict(label=label, confidence=1, rationale="Unsupported"), facts)
