"""A model endpoint that dies partway through an experiment must not cost the whole run.

The endpoint we run against returns 502 `upstream_unreachable` under load and sometimes just
drops the connection, which surfaces as an `openai.APIConnectionError` out of the agent call —
not as one of the pydantic-ai exceptions `run_experiment` classifies per case. These tests pin
the two halves of the contract: the cases already scored are persisted, and the run still
fails loudly with the truncation on the record.
"""

from __future__ import annotations

import httpx
import openai
import pytest
import yaml
from sqlalchemy import func, select

from infosec_harness.evals.run import TruncatedExperiment, compare_experiments, run_experiment
from infosec_harness.settings import get_settings

AGENT = "probe-diagnosis"


def _dataset_cases() -> list[dict]:
    path = get_settings().agents_dir / AGENT / "evals" / "dataset.yaml"
    return yaml.safe_load(path.read_text())["cases"]


class _FlakyAgent:
    """Wraps a built agent so the Nth `run` raises a transport error, as the endpoint does."""

    def __init__(self, inner, fail_after: int) -> None:
        self._inner = inner
        self._fail_after = fail_after
        self.calls = 0

    async def run(self, *args, **kwargs):
        self.calls += 1
        if self.calls > self._fail_after:
            raise openai.APIConnectionError(
                request=httpx.Request("POST", "http://llm.example/v1/chat/completions"))
        return await self._inner.run(*args, **kwargs)


def _break_endpoint_after(monkeypatch, fail_after: int) -> None:
    from infosec_harness.agents import registry

    real_build = registry.build_agent

    def build_agent(*args, **kwargs):
        return _FlakyAgent(real_build(*args, **kwargs), fail_after)

    monkeypatch.setattr(registry, "build_agent", build_agent)


async def _case_row_count(exp_id: str) -> int:
    from infosec_harness.persistence import db

    async with db.session() as s:
        return (await s.execute(
            select(func.count()).select_from(db.EvalCaseResult)
            .where(db.EvalCaseResult.experiment_id == exp_id))).scalar_one()


async def _experiment(exp_id: str):
    from infosec_harness.persistence import db

    async with db.session() as s:
        return await s.get(db.EvalExperiment, exp_id)


async def test_transport_failure_keeps_the_scored_cases_and_fails_the_run(monkeypatch):
    planned = len(_dataset_cases()) * 2
    _break_endpoint_after(monkeypatch, 3)

    with pytest.raises(TruncatedExperiment) as excinfo:
        await run_experiment(AGENT, repeat=2)

    exp_id = excinfo.value.experiment_id
    # A failure, not a quiet partial success: non-zero exit, and the message names the count.
    assert excinfo.value.code and "TRUNCATED" in str(excinfo.value.code)
    assert f"3/{planned}" in str(excinfo.value.code)

    exp = await _experiment(exp_id)
    assert exp is not None, "the partial experiment must be persisted, not discarded"
    assert exp.metrics["status"] == "truncated"
    assert exp.metrics["n"] == 3 and exp.metrics["n_planned"] == planned
    # Scores cover exactly the case runs that completed, and the rows survive with them.
    assert await _case_row_count(exp_id) == 3
    assert sum(exp.metrics["confusion"].values()) == 3

    truncation = exp.metrics["truncated"]
    assert truncation == excinfo.value.truncation
    assert truncation["error_type"] == "APIConnectionError"
    assert truncation["completed_runs"] == 3 and truncation["planned_runs"] == planned
    # The failure happened on the second repetition of case 2 (1 case done = 2 runs, then one
    # more), so the reader can see where to resume.
    assert truncation["failed_case"] == _dataset_cases()[1]["name"]
    assert truncation["failed_repetition"] == 1
    assert truncation["completed_cases"] == 1


async def test_truncated_run_writes_no_release_report(monkeypatch, tmp_path, capsys):
    _break_endpoint_after(monkeypatch, 1)
    report = tmp_path / "release.json"

    with pytest.raises(TruncatedExperiment):
        await run_experiment(AGENT, report=report)

    # Gates measured on a fraction of the dataset are not gates.
    assert not report.exists()
    assert "no release report written" in capsys.readouterr().out


async def test_complete_run_is_marked_complete_and_fully_covered():
    exp_id = await run_experiment(AGENT)
    exp = await _experiment(exp_id)
    assert exp.metrics["status"] == "complete"
    assert exp.metrics["n"] == exp.metrics["n_planned"] == len(_dataset_cases())
    assert "truncated" not in exp.metrics


async def test_compare_flags_a_truncated_side(monkeypatch, capsys):
    baseline = await run_experiment(AGENT)
    _break_endpoint_after(monkeypatch, 2)
    with pytest.raises(TruncatedExperiment) as excinfo:
        await run_experiment(AGENT)
    capsys.readouterr()

    await compare_experiments([baseline, excinfo.value.experiment_id])
    out = capsys.readouterr().out
    assert "TRUNCATED" in out and "candidate" in out
    assert "NOT a like-for-like comparison" in out
    assert "coverage" in out
    # The baseline is clean, so only the candidate is called out.
    warnings = [line for line in out.splitlines() if "!!" in line]
    assert any(excinfo.value.experiment_id in line for line in warnings)
    assert not any(baseline in line for line in warnings)
