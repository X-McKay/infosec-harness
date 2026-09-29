"""Declared execution checks remain visible when no typed output reaches them."""

from __future__ import annotations

import httpx
import openai
import pytest
from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded
from sqlalchemy import select

from infosec_harness.evals.run import TruncatedExperiment, run_experiment


async def _experiment(exp_id):
    from infosec_harness.persistence import db

    async with db.session() as session:
        return await session.get(db.EvalExperiment, exp_id)


async def _rows(exp_id):
    from infosec_harness.persistence import db

    async with db.session() as session:
        return (await session.execute(
            select(db.EvalCaseResult).where(db.EvalCaseResult.experiment_id == exp_id)
        )).scalars().all()


@pytest.mark.parametrize(
    ("error", "primary_category", "reason"),
    [
        (UsageLimitExceeded("request ceiling"), "budget_exhausted", "budget stop"),
        (UnexpectedModelBehavior("no accepted output"), "invalid_output", "no accepted output"),
    ],
)
async def test_unavailable_agent_output_preserves_primary_failure_and_execution_gap(
    monkeypatch, error, primary_category, reason
):
    from infosec_harness.agents import registry

    class NoOutputAgent:
        async def run(self, *args, **kwargs):
            raise error

    monkeypatch.setattr(registry, "build_agent", lambda *args, **kwargs: NoOutputAgent())
    exp = await _experiment(await run_experiment("build-repair"))
    categories = exp.metrics["distributions"]["failure_categories"]

    assert exp.metrics["execution_checks_planned"] == 1
    assert exp.metrics["execution_checks_passed"] == 0
    assert exp.metrics["execution_not_checked_count"] == 1
    assert categories[primary_category] == exp.metrics["n"]
    assert categories["execution_not_checked"] == 0
    assert categories["wrong_answer"] == 0
    assert sum(categories.values()) == exp.metrics["n"]

    declared = next(row for row in await _rows(exp.id)
                    if row.case_name == "perl-dbi-driver-not-installed")
    assert declared.scores["outcome"] == primary_category
    assert declared.scores["execution_check"] == {
        "status": "not_checked",
        "check": "perl_dbd_sqlite_v1",
        "reason": f"agent output unavailable after {reason}",
        "execution_mode": "not-run-no-typed-output-v1",
    }


async def test_truncation_reports_all_unreached_declared_checks(monkeypatch):
    from infosec_harness.agents import registry

    class TransportFailure:
        async def run(self, *args, **kwargs):
            raise openai.APIConnectionError(
                request=httpx.Request("POST", "http://llm.example/v1/chat/completions")
            )

    monkeypatch.setattr(registry, "build_agent", lambda *args, **kwargs: TransportFailure())
    with pytest.raises(TruncatedExperiment) as caught:
        await run_experiment("build-repair")

    exp = await _experiment(caught.value.experiment_id)
    assert exp.metrics["status"] == "truncated"
    assert exp.metrics["n"] == 0
    assert exp.metrics["execution_checks_planned"] == 1
    assert exp.metrics["execution_checks_passed"] == 0
    assert exp.metrics["execution_not_checked_count"] == 1
    assert sum(exp.metrics["distributions"]["failure_categories"].values()) == 0
