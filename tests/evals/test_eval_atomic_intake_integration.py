"""Canonical evals use the same atomic prompt and guard as the production agent."""

import json

import pytest
import yaml
from pydantic_ai.exceptions import UnexpectedModelBehavior
from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from sqlalchemy import select

from infosec_harness.agents import registry
from infosec_harness.evals import run
from infosec_harness.persistence import db

REPORT = "Caller input is interpolated into a shell command."


@pytest.mark.parametrize("provider_failure", [False, True])
async def test_canonical_eval_persists_atomic_guard_correction_and_failure(
    tmp_path, monkeypatch, provider_failure,
):
    path = tmp_path / "dataset.yaml"
    path.write_text(yaml.safe_dump({"version": "synthetic-atomic-integration", "cases": [{
        "name": "synthetic", "category": "smoke", "payload": {"report": REPORT},
        "expected": "CWE-78",
    }]}))
    calls = []

    def respond(messages, info):
        calls.append(1)
        if len(calls) == 1:
            prompt = str(messages)
            assert "<report_source_lines>" in prompt and "<report>" not in prompt
        if len(calls) == 2 and provider_failure:
            raise UnexpectedModelBehavior("SECRET_PROVIDER", body="SECRET_BODY")
        args = ({"start_line": {
            "value": 999, "source": {"start_id": "S000001"}, "confidence": 1,
        }} if len(calls) == 1 else {"cwe": {
            "value": "CWE-78", "source": {"start_id": "S000001"}, "confidence": 1,
        }})
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, args)])

    agent = registry.build_agent("intake", durable=False, production_transport=True)
    monkeypatch.setattr(registry, "build_agent", lambda *_args, **_kwargs: agent)
    with agent.override(model=FunctionModel(respond)):
        experiment_id = await run.run_experiment("intake", dataset=path)
    async with db.session() as session:
        experiment = await session.get(db.EvalExperiment, experiment_id)
        row = (await session.execute(select(db.EvalCaseResult).where(
            db.EvalCaseResult.experiment_id == experiment_id
        ))).scalar_one()
    summary = row.scores["intake_field_summary"]
    assert summary == experiment.metrics["attempts"][0]["intake_field_summary"]
    assert summary["version"] == "intake-atomic-claim-proposals/v2"
    assert summary["reconstructed_proposals"] == (1 if provider_failure else 2)
    assert summary["materialized_guard_summary"]["proposals_with_guard_violations"] == 1
    assert row.passed is (not provider_failure)
    assert len(calls) == 2
    if provider_failure:
        assert row.scores["usage_status"] == "unknown"
        assert row.scores["error_category"] == "no_accepted_output"
    else:
        assert row.scores["usage"]["requests"] == 2
    assert REPORT not in json.dumps(summary)
    assert "SECRET" not in json.dumps(row.scores)
