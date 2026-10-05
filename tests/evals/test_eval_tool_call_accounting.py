"""Tool-call percentiles include every scored trajectory exactly once."""

from __future__ import annotations

from pydantic_ai import Agent
from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from sqlalchemy import select

from infosec_harness.evals.run import run_experiment
from infosec_harness.runtime.deps import AgentDeps
from infosec_harness.runtime.outputs import PartialEnvironmentOutput


async def _experiment_and_rows(exp_id):
    from infosec_harness.persistence import db

    async with db.session() as session:
        experiment = await session.get(db.EvalExperiment, exp_id)
        rows = (await session.execute(
            select(db.EvalCaseResult).where(db.EvalCaseResult.experiment_id == exp_id)
        )).scalars().all()
    return experiment, rows


def _tool_agent(*, finish: bool):
    async def observe(value: int) -> str:
        return f"observed {value}"

    def respond(messages, info):
        observed = sum(
            isinstance(part, ToolCallPart) and part.tool_name == "observe"
            for message in messages for part in message.parts
        )
        if not finish or observed == 0:
            return ModelResponse(parts=[ToolCallPart("observe", {"value": observed + 1})])
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {
            "base_image": "python:3.12-slim",
            "system_packages": [],
            "install_commands": ["python -m pip install --user pytest"],
            "test_command": "python -m pytest -q -s {test_file}",
            "scope": "partial",
            "module_path": ".",
        })])

    return Agent(
        FunctionModel(respond), deps_type=AgentDeps,
        output_type=PartialEnvironmentOutput, tools=[observe],
    )


async def test_budget_stops_contribute_observed_partial_tool_calls(monkeypatch):
    from infosec_harness.runtime import registry

    monkeypatch.setattr(registry, "build_agent", lambda *args, **kwargs: _tool_agent(finish=False))
    experiment, rows = await _experiment_and_rows(await run_experiment("partial-build"))
    observed = [row.scores["call_summary"]["tool_call_count"] for row in rows]

    assert experiment.metrics["budget_exhausted_count"] == len(rows)
    assert min(observed) > 0
    assert experiment.metrics["distributions"]["p95_tool_calls"] == max(observed)
    assert all(row.scores["usage_status"] == "unknown" for row in rows)


async def test_successful_tool_calls_are_not_double_counted(monkeypatch):
    from infosec_harness.runtime import registry

    monkeypatch.setattr(registry, "build_agent", lambda *args, **kwargs: _tool_agent(finish=True))
    experiment, rows = await _experiment_and_rows(await run_experiment("partial-build"))

    assert {row.scores["call_summary"]["tool_call_count"] for row in rows} == {1}
    assert experiment.metrics["distributions"]["p95_tool_calls"] == 1
