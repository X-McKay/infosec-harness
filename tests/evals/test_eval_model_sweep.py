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

from infosec_harness.evals.reporting import compare_models_for, list_experiments, run_evals
from infosec_harness.evals.run import run_experiment
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
    rows = await run_evals([AGENT], ["sonnet", "haiku"])
    assert [r.model for r in rows] == ["sonnet", "haiku"]
    assert all(r.status == "complete" for r in rows)
    out = capsys.readouterr().out
    # The three things a model choice turns on, in one place.
    for column in ("accuracy", "p95 lat", "$/case"):
        assert column in out
    for row in rows:
        assert row.experiment_id in out, "the sweep must name its experiments to follow up on"


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


async def test_reports_are_written_only_where_asked_and_never_overwrite_each_other(tmp_path):
    import json

    assert await run_experiment(AGENT)  # no report requested, none written anywhere
    first = await run_experiment(AGENT, report_dir=tmp_path / "reports")
    second = await run_experiment(AGENT, report_dir=tmp_path / "reports")
    for experiment_id in (first, second):
        path = tmp_path / "reports" / f"{experiment_id}.json"
        assert json.loads(path.read_text())["provenance"]["experiment_id"] == experiment_id
    explicit = tmp_path / "custom" / "report.json"
    third = await run_experiment(AGENT, report=explicit)
    assert json.loads(explicit.read_text())["provenance"]["experiment_id"] == third
    assert sorted(p.name for p in (tmp_path / "reports").iterdir()) == sorted(
        f"{experiment_id}.json" for experiment_id in (first, second))


async def test_a_sweep_writes_and_audits_one_report_per_model(tmp_path, capsys):
    import json

    rows = await run_evals([AGENT], ["sonnet", "haiku"], report_dir=tmp_path)
    for row in rows:
        assert row.report == tmp_path / f"{row.experiment_id}.json"
        report = json.loads(row.report.read_text())
        assert "inert_checks" in report and "gate_evaluation" in report
    assert capsys.readouterr().out.count("INERT RELEASE GATES") == 2


async def test_one_failing_model_does_not_abort_the_sweep(monkeypatch, capsys):
    """A truncated run is an ordinary exception now; the sweep records it and moves on."""
    from infosec_harness.evals import reporting

    real = reporting.run_experiment

    async def flaky(agent, **kwargs):
        if kwargs["model"] == "sonnet":
            raise RuntimeError("endpoint down")
        return await real(agent, **kwargs)

    monkeypatch.setattr(reporting, "run_experiment", flaky)
    rows = await run_evals([AGENT], ["sonnet", "haiku"])
    assert [(r.model, r.status) for r in rows] == [("sonnet", "error"), ("haiku", "complete")]
    assert f"{AGENT}: FAILED -- RuntimeError" in capsys.readouterr().out
