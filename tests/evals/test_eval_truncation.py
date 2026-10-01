"""A model endpoint that dies partway through an experiment must not cost the whole run.

The endpoint we run against returns 502 `upstream_unreachable` under load and sometimes just
drops the connection, which surfaces as an `openai.APIConnectionError` out of the agent call —
not as one of the pydantic-ai exceptions `run_experiment` classifies per case. These tests pin
the two halves of the contract: the cases already scored are persisted, and the run still
fails loudly with the truncation on the record.
"""

from __future__ import annotations

import json

import httpx
import openai
import pytest
import yaml
from pydantic import BaseModel
from pydantic_ai.exceptions import UnexpectedModelBehavior
from sqlalchemy import func, select

from infosec_harness.evals.run import (
    IncomparableExperiments,
    TruncatedExperiment,
    _bounded_typed_output,
    _usage_metrics,
    compare_experiments,
    run_experiment,
)
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


async def _case_rows(exp_id: str):
    from infosec_harness.persistence import db

    async with db.session() as s:
        return (await s.execute(
            select(db.EvalCaseResult)
            .where(db.EvalCaseResult.experiment_id == exp_id)
            .order_by(db.EvalCaseResult.id))).scalars().all()


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
    assert exp.metrics["avg_tokens"] is None
    assert exp.metrics["cache_hit_ratio"] is None
    observations = exp.metrics["usage_observations"]
    assert observations["attempts_observed"] == 3
    assert observations["attempts_total"] == 4
    assert observations["attempt_coverage_rate"] == 0.75


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


def test_complete_observed_zero_usage_remains_numeric_zero():
    unknown = _usage_metrics([], 0, 0)
    assert unknown["avg_tokens"] is None
    assert unknown["cache_hit_ratio"] is None
    assert unknown["usage_observations"]["attempt_coverage_rate"] is None

    metrics = _usage_metrics([{"usage_status": "observed"}], 0, 0)
    assert metrics["avg_tokens"] == 0.0
    assert metrics["cache_hit_ratio"] == 0.0
    assert metrics["usage_observations"]["attempt_coverage_rate"] == 1.0


async def test_complete_case_retains_bounded_typed_output_without_the_prompt():
    exp_id = await run_experiment(AGENT)
    first = (await _case_rows(exp_id))[0].scores
    diagnostic = first["typed_output"]
    assert diagnostic["type"] == "ProbeDiagnosis"
    assert diagnostic["value"]["kind"] == first["predicted"] == "valid_positive"
    assert not diagnostic["truncated"]
    assert "prompt" not in first and "messages" not in first


def test_typed_output_is_bounded_and_sensitive_keys_are_redacted():
    class DiagnosticFixture(BaseModel):
        visible: str
        payload: dict

    diagnostic = _bounded_typed_output(DiagnosticFixture(
        visible="x" * 20_000,
        payload={"Authorization": "Bearer secret", "nested": {"api-key": "secret-2"}},
    ))
    encoded = json.dumps(diagnostic)
    assert diagnostic["truncated"] and len(diagnostic["json_prefix"]) == 16_000
    assert "Bearer secret" not in encoded and "secret-2" not in encoded
    assert "[REDACTED]" in encoded


async def test_invalid_output_retains_category_but_not_exception_text(monkeypatch, capsys):
    from infosec_harness.agents import registry

    class InvalidOutputAgent:
        async def run(self, *args, **kwargs):
            raise UnexpectedModelBehavior(
                "sensitive reason should-not-be-stored",
                body='{"authorization":"Bearer should-not-be-stored"}',
            )

    monkeypatch.setattr(registry, "build_agent", lambda *args, **kwargs: InvalidOutputAgent())
    exp_id = await run_experiment(AGENT)
    exp = await _experiment(exp_id)
    rows = await _case_rows(exp_id)

    assert exp.metrics["status"] == "complete"
    assert exp.metrics["schema_validity_rate"] == 0.0
    assert len(rows) == len(_dataset_cases())
    assert {row.scores["error_type"] for row in rows} == {"UnexpectedModelBehavior"}
    encoded = json.dumps([row.scores for row in rows])
    assert "should-not-be-stored" not in encoded and "sensitive reason" not in encoded
    assert {row.scores["error_category"] for row in rows} == {"output_contract_invalid"}
    assert all(row.scores["provider_body_retained"] is False for row in rows)
    assert exp.metrics["avg_tokens"] is None
    assert exp.metrics["cache_hit_ratio"] is None
    assert exp.metrics["usage_observations"]["attempts_observed"] == 0
    assert "cache_hit=unknown" in capsys.readouterr().out


async def test_answered_and_invalid_attempts_do_not_publish_partial_usage(monkeypatch):
    from infosec_harness.agents import registry

    real_build = registry.build_agent

    class InvalidAfterOne:
        def __init__(self, inner):
            self.inner = inner
            self.calls = 0

        async def run(self, *args, **kwargs):
            self.calls += 1
            if self.calls > 1:
                raise UnexpectedModelBehavior("not retained", body="not retained")
            return await self.inner.run(*args, **kwargs)

    monkeypatch.setattr(
        registry, "build_agent", lambda *args, **kwargs: InvalidAfterOne(
            real_build(*args, **kwargs)
        )
    )
    exp = await _experiment(await run_experiment(AGENT))
    observations = exp.metrics["usage_observations"]
    assert observations["attempts_observed"] == 1
    assert observations["attempts_total"] == len(_dataset_cases())
    assert observations["observed_avg_tokens"] > 0
    assert exp.metrics["avg_tokens"] is None
    assert exp.metrics["cache_hit_ratio"] is None


async def test_compare_flags_a_truncated_side(monkeypatch, capsys):
    baseline = await run_experiment(AGENT)
    _break_endpoint_after(monkeypatch, 2)
    with pytest.raises(TruncatedExperiment) as excinfo:
        await run_experiment(AGENT)
    capsys.readouterr()

    with pytest.raises(IncomparableExperiments) as compare_error:
        await compare_experiments([baseline, excinfo.value.experiment_id])
    assert "incomplete coverage" in str(compare_error.value)

    await compare_experiments(
        [baseline, excinfo.value.experiment_id], descriptive=True
    )
    out = capsys.readouterr().out
    assert "TRUNCATED" in out and "candidate" in out
    assert "NOT a like-for-like comparison" in out
    assert "DESCRIPTIVE ONLY" in out
    assert "coverage" in out
    # The baseline is clean, so only the candidate is called out.
    warnings = [line for line in out.splitlines() if "!!" in line]
    assert any(excinfo.value.experiment_id in line for line in warnings)
    assert not any(baseline in line for line in warnings)


async def test_truncated_default_export_never_creates_a_release_report(tmp_path, monkeypatch):
    from infosec_harness.agents import registry

    monkeypatch.setattr(get_settings(), "reports_dir", tmp_path)
    original = registry.build_agent
    monkeypatch.setattr(registry, "build_agent",
                        lambda *args, **kwargs: _FlakyAgent(original(*args, **kwargs), 1))
    with pytest.raises(TruncatedExperiment) as caught:
        await run_experiment(AGENT)
    assert not (tmp_path / "evals" / f"{caught.value.experiment_id}.json").exists()
