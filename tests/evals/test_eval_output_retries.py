"""Retry observations are bounded and private, without claiming a terminal cause."""
from __future__ import annotations

import json

import pytest
import yaml
from pydantic_ai import Agent, capture_run_messages
from pydantic_ai.exceptions import UnexpectedModelBehavior
from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    RetryPromptPart,
    ToolCallPart,
    UserPromptPart,
)
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.usage import UsageLimits
from sqlalchemy import select

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.registry import build_agent
from infosec_harness.agents.validators import validate_intake_evidence
from infosec_harness.domain.models import ExtractedFinding
from infosec_harness.evals.output_retries import output_retry_summary

PREFIX = "Extraction violates its evidence contract:\n- "
REPORT = "Caller input is interpolated into a shell command."
BAD = {"cwe": None, "evidence": [{"field": "cwe", "quote": REPORT, "confidence": 1}]}
VALID = {"cwe": "CWE-78", "evidence": BAD["evidence"]}


def retry(content, tool_name="final_result"):
    return ModelRequest(parts=[RetryPromptPart(content=content, tool_name=tool_name,
                                              tool_call_id="SECRET_ID")])


@pytest.mark.parametrize("message,category", [
    ("Exact source report is unavailable; extraction cannot be validated.", "source_unavailable"),
    ("Evidence names an unknown extraction field.", "unknown_field"),
    ("An evidence quote is not a nonempty verbatim report span.", "quote_not_verbatim"),
    ("Positive evidence requires a nonempty verbatim report span.", "positive_quote_missing"),
    ("Positive evidence cannot support an unset extraction field.", "positive_value_missing"),
    ("A literal location value is absent from its evidence quote.", "literal_location_missing"),
    ("A literal line number is absent from its evidence quote.", "literal_line_missing"),
    ("Every nonempty extraction field requires positive grounded evidence.", "positive_support_missing"),
])
def test_exact_closed_feedback_category_is_observed(message, category):
    summary = output_retry_summary([retry(PREFIX + message)], agent="intake")
    assert summary["retry_parts_observed"] == summary["intake_guard_retry_parts"] == 1
    assert len(summary["intake_guard_category_counts"]) == 8
    assert summary["intake_guard_category_counts"][category] == 1
    assert sum(summary["intake_guard_category_counts"].values()) == 1


def test_unknown_provider_tool_schema_and_model_strings_are_not_exported():
    messages = [
        retry(PREFIX + "Evidence names an unknown extraction field.\n- SECRET_FIELD"),
        retry("SECRET_PROVIDER_BODY"),
        retry("SECRET_TOOL_BODY", "SECRET_TOOL_NAME"),
        retry([{"type": "SECRET_TYPE", "loc": ["SECRET_PATH"], "msg": "SECRET_MSG",
                "input": "SECRET_INPUT", "ctx": {"SECRET_CONTEXT": "SECRET_VALUE"}}]),
        retry("SECRET_NO_TOOL", None),
        ModelResponse(parts=[ToolCallPart("SECRET_MODEL", {"SECRET_ARGS": "SECRET_QUOTE"})]),
    ]
    summary = output_retry_summary(messages, agent="intake")
    assert summary["intake_guard_retry_parts"] == 0
    assert summary["output_schema_retry_parts"] == summary["function_tool_retry_parts"] == 1
    assert summary["unclassified_retry_parts"] == 3
    assert summary["retry_parts_observed"] == 5
    assert "SECRET" not in json.dumps(summary)
    assert "terminal" not in json.dumps(summary) and "cause" not in json.dumps(summary)


def test_guard_rules_followed_by_host_repair_guidance_are_classified():
    """The intake output validator appends repair guidance after the guard's own message.
    Regression: v1 matched whole items, so the current protocol's retries were never
    classified."""
    content = (PREFIX + "A literal line number is absent from its evidence quote.\n"
               "Fix only unsupported start_line or end_line claims.")
    summary = output_retry_summary([retry(content)], agent="intake")
    assert summary["version"] == "output-retries/v2"
    assert summary["intake_guard_retry_parts"] == 1
    assert summary["intake_guard_category_counts"]["literal_line_missing"] == 1
    unknown_first_line = PREFIX + "SECRET_RULE\nA literal line number is absent from its evidence quote."
    assert output_retry_summary([retry(unknown_first_line)], agent="intake")[
        "unclassified_retry_parts"] == 1


def test_empty_capture_is_unknown_and_other_agent_output_names_are_not_guessed():
    assert output_retry_summary([], agent="intake")["capture_status"] == "unknown"
    summary = output_retry_summary([retry(PREFIX + "Evidence names an unknown extraction field.")],
                                   agent="context")
    assert summary["capture_status"] == "observed"
    assert summary["intake_guard_retry_parts"] == 0 and summary["unclassified_retry_parts"] == 1


@pytest.mark.parametrize("messages,count", [
    ([retry("SECRET")] * 33, 32),
    ([ModelRequest(parts=[])] * 128 + [retry("SECRET")], 0),
    ([ModelRequest(parts=[RetryPromptPart(content="SECRET")] * 513)], 32),
    ([retry("SECRET" * 1000)], 1),
    ([ModelRequest(parts=[UserPromptPart("SECRET")] * 512 + [RetryPromptPart(content="SECRET")])], 0),
])
def test_scan_bounds_and_truncation_are_explicit(messages, count):
    summary = output_retry_summary(messages, agent="intake")
    assert summary["truncated"] and summary["retry_parts_observed"] == count
    assert "SECRET" not in json.dumps(summary)


@pytest.mark.parametrize("exhausted", [False, True])
async def test_real_sdk_guard_retry_then_valid_or_four_response_exhaustion(exhausted):
    """The production evidence guard, run by the real SDK retry loop, on flat proposals."""
    calls = []

    def respond(_messages, info):
        calls.append(1)
        value = BAD if exhausted or len(calls) == 1 else VALID
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, value)])

    agent = Agent(FunctionModel(respond), deps_type=AgentDeps, output_type=ExtractedFinding,
                  retries=3)
    agent.output_validator(validate_intake_evidence)
    deps = AgentDeps(repo_path="/nonexistent", report_text=REPORT)
    with capture_run_messages() as messages:
        if exhausted:
            with pytest.raises(UnexpectedModelBehavior):
                await agent.run("synthetic", deps=deps, usage_limits=UsageLimits(request_limit=4))
        else:
            result = await agent.run("synthetic", deps=deps,
                                     usage_limits=UsageLimits(request_limit=4))
            assert result.output.cwe == "CWE-78" and result.usage.requests == 2
    summary = output_retry_summary(messages, agent="intake")
    assert len(calls) == (4 if exhausted else 2)
    # The SDK raises before materializing the last exhausted retry prompt: observed parts
    # are preceding retries, not a count or attribution of all validator calls/terminal cause.
    assert summary["intake_guard_retry_parts"] == (3 if exhausted else 1)
    assert summary["intake_guard_category_counts"]["positive_value_missing"] == (3 if exhausted else 1)
    assert "terminal" not in summary and "cause" not in summary


@pytest.mark.parametrize("protocol_failure", [False, True])
async def test_eval_persists_observations_for_accepted_and_protocol_failed_output(
    tmp_path, monkeypatch, protocol_failure,
):
    from infosec_harness.agents import registry
    from infosec_harness.evals import run
    from infosec_harness.persistence import db

    path = tmp_path / "dataset.yaml"
    path.write_text(yaml.safe_dump({"version": "synthetic-retry-regression", "cases": [
        {"name": "synthetic-finding", "category": "smoke", "payload": {"report": REPORT},
         "expected": "CWE-78"}]}))
    calls = []

    def respond(_messages, info):
        calls.append(1)
        if len(calls) == 2 and protocol_failure:
            raise UnexpectedModelBehavior("SECRET_PROVIDER", body="SECRET_PROVIDER_BODY")
        # First an atomic claim citing a source line the report does not have, then a valid one.
        source = "S999999" if len(calls) == 1 else "S000001"
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {"cwe": {
            "value": "CWE-78", "source": {"start_id": source}, "confidence": 1}})])

    agent = build_agent("intake", durable=False, production_transport=True)
    monkeypatch.setattr(registry, "build_agent", lambda *_args, **_kwargs: agent)
    with agent.override(model=FunctionModel(respond)):
        exp_id = await run.run_experiment("intake", dataset=path)
    async with db.session() as session:
        experiment = await session.get(db.EvalExperiment, exp_id)
        row = (await session.execute(select(db.EvalCaseResult).where(
            db.EvalCaseResult.experiment_id == exp_id))).scalar_one()
    summary = row.scores["output_retry_summary"]
    assert summary == experiment.metrics["attempts"][0]["output_retry_summary"]
    assert summary["retry_parts_observed"] == 1
    assert row.passed is (not protocol_failure)
    assert run.EVALUATOR_VERSION == "deterministic-agent-output-v12"
    if protocol_failure:
        assert row.scores["error_category"] == "no_accepted_output"
        assert row.scores["usage_status"] == "unknown"
        assert "SECRET" not in json.dumps(row.scores)
    assert "SECRET" not in json.dumps(summary)
