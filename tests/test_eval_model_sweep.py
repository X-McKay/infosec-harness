"""Running one dataset against several models, and storing the result so it can be found again.

Comparing models is the most common experiment there is, and before this it meant hand-writing
an overlay YAML per model, running them one at a time, copying experiment ids out of the
console, and comparing them two at a time. Worse, the model was recorded *only* inside
`config_hash` — so "how did verdict do on opus last month" was not a question the store could
answer, however many times it had been run.

These tests run against the stub model (no endpoint, no cost), which is enough to pin the
plumbing: that `--model` reaches the spec, that each run is stored under the model it used,
and that the query finds them.
"""
from __future__ import annotations

from infosec_harness.evals.run import (
    compare_models_for,
    list_experiments,
    run_experiment,
    sweep_models,
)
from infosec_harness.persistence import db

AGENT = "probe-diagnosis"


async def _experiment(exp_id: str):
    async with db.session() as s:
        return await s.get(db.EvalExperiment, exp_id)


async def test_the_model_a_run_used_is_stored_as_data_not_only_inside_a_hash():
    """`config_hash` fingerprints the model but cannot be grouped by, filtered on, or read."""
    exp = await _experiment(await run_experiment(AGENT, model="haiku"))
    assert exp.model_tier == "haiku"
    assert exp.model_name, "the resolved model id was not recorded"
    assert exp.pricing, "no cost basis recorded, so a cost column cannot be interpreted"


async def test_two_models_produce_two_experiments_with_different_configs():
    """If the override did not reach the spec, both runs would carry the same config hash and
    the comparison would be of one model against itself."""
    first = await _experiment(await run_experiment(AGENT, model="sonnet"))
    second = await _experiment(await run_experiment(AGENT, model="haiku"))
    assert first.id != second.id
    assert first.model_tier != second.model_tier
    assert first.config_hash != second.config_hash, (
        "both runs resolved to the same configuration, so --model changed nothing")


async def test_every_run_records_the_code_it_measured():
    exp = await _experiment(await run_experiment(AGENT))
    # In CI the tree may legitimately be clean or dirty; what must hold is that the answer is
    # recorded at all, because it cannot be reconstructed afterwards.
    assert exp.git_dirty in (True, False)
    assert exp.harness_version, "no distribution version recorded"


async def test_a_sweep_runs_every_model_and_reports_them_together(capsys):
    rows = await sweep_models(AGENT, ["sonnet", "haiku"])
    assert [r["label"] for r in rows] == ["sonnet", "haiku"]
    assert all(not r["failed"] for r in rows)
    out = capsys.readouterr().out
    # The three things a model choice turns on, in one place.
    for column in ("accuracy", "p95 lat", "$/case"):
        assert column in out
    for row in rows:
        assert row["experiment_id"] in out, "the sweep must name its experiments to follow up on"


async def test_the_comparison_can_be_asked_for_after_the_fact(capsys):
    """A sweep printed to a terminal that has scrolled away is not a stored result."""
    await run_experiment(AGENT, model="sonnet")
    await run_experiment(AGENT, model="haiku")
    capsys.readouterr()

    # The test worktree is intentionally dirty, so this is an exploratory view rather than a
    # release comparison. Strict mode rejects dirty source snapshots.
    found = await compare_models_for(AGENT, descriptive=True)
    assert {row.model_tier for row in found} >= {"sonnet", "haiku"}
    out = capsys.readouterr().out
    assert "accuracy" in out and "$/case" in out


async def test_only_the_latest_run_per_model_is_compared(capsys):
    """Otherwise the same model appears twice and the table stops being a comparison."""
    await run_experiment(AGENT, model="sonnet")
    newest = await run_experiment(AGENT, model="sonnet")
    capsys.readouterr()

    found = await compare_models_for(AGENT, descriptive=True)
    sonnet = [row for row in found if row.model_tier == "sonnet"]
    assert len(sonnet) == 1
    assert sonnet[0].id == newest


async def test_results_can_be_filtered_to_one_agent_and_one_commit(capsys):
    exp = await _experiment(await run_experiment(AGENT, model="sonnet"))
    capsys.readouterr()

    rows = await list_experiments(agent=AGENT, limit=50)
    assert all(row.agent == AGENT for row in rows)
    assert exp.id in {row.id for row in rows}

    if exp.git_sha:
        at_commit = await list_experiments(commit=exp.git_sha[:8], limit=50)
        assert exp.id in {row.id for row in at_commit}
    assert await list_experiments(commit="0" * 12, limit=50) == []
