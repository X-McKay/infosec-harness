"""A stored eval result must say what it measured, and refuse to claim more than it can.

Two properties, both of which a result can violate silently:

* **Attribution.** `git rev-parse HEAD` answers the same SHA whether or not the tree matches
  it, so before `CodeVersion` a run over uncommitted edits was filed against a commit that
  never contained the code it measured — and no later reader could tell.
* **Comparability.** The cost column is only meaningful between models priced the same way. A
  self-hosted model with a declared zero rate always "wins" on cost against a billed one, for
  a reason that has nothing to do with either model.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from infosec_harness.evals import baselines as baseline_store
from infosec_harness.evals.provenance import CodeVersion
from infosec_harness.evals.reporting import comparison_table


def version(**kw) -> CodeVersion:
    base = {"git_commit": "a" * 40, "git_dirty": False, "harness_version": "2.0.0",
            "python": "3.12.0"}
    return CodeVersion(**{**base, **kw})


def experiment(**kw) -> SimpleNamespace:
    """An experiment row of the shape the baseline store reads."""
    base = {
        "id": "exp-1", "agent": "verdict", "model_tier": "sonnet",
        "model_name": "bedrock:anthropic.claude-sonnet-5", "pricing": "priced",
        "git_sha": "b" * 40, "git_dirty": False, "harness_version": "2.0.0",
        "config_hash": "c" * 16, "dataset_version": "2", "repetitions": 3,
        "metrics": {"status": "complete", "task_success_rate": 0.9, "n": 30, "n_planned": 30,
                    "schema_validity_rate": 1.0, "average_cost_usd": 0.01,
                    "p95_model_requests": 4, "budget_exhausted_count": 0,
                    "comparison_identity": {"split": "full"},
                    "distributions": {"p50_latency_s": 2.0}},
    }
    return SimpleNamespace(**{**base, **kw})


# --- attribution -------------------------------------------------------------------------

def test_a_dirty_tree_is_not_treated_as_describing_its_commit():
    assert version().describes_a_commit
    assert not version(git_dirty=True).describes_a_commit


def test_the_dirty_marker_is_visible_in_the_short_label():
    """The label is what gets printed next to every number, so the marker has to be in it —
    a bare SHA is precisely the thing that hides this."""
    assert version(git_dirty=True).label().endswith("-dirty")
    assert not version().label().endswith("-dirty")


def test_no_checkout_reports_no_commit_rather_than_a_wrong_one():
    """Off a source tree there is no repository. Empty is the honest answer; inventing a path
    or a SHA is how the packaging bug stayed invisible for so long."""
    absent = version(git_commit="", git_dirty=False)
    assert not absent.describes_a_commit
    assert "no checkout" in absent.label()


# --- baselines refuse what they cannot honestly claim -------------------------------------

def test_a_dirty_run_cannot_become_a_baseline():
    with pytest.raises(baseline_store.BaselineRefused, match="dirty working tree"):
        baseline_store.from_experiment(experiment(git_dirty=True))


def test_a_truncated_run_cannot_become_a_baseline():
    """Its metrics cover only the cases that ran, so pinning it silently redefines the
    denominator every later comparison is read against."""
    row = experiment(metrics={**experiment().metrics, "status": "truncated", "n": 7})
    with pytest.raises(baseline_store.BaselineRefused, match="truncated"):
        baseline_store.from_experiment(row)


def test_a_run_with_no_recorded_status_cannot_become_a_baseline():
    """Nothing says every planned case ran, so it must not be read as complete."""
    metrics = {k: v for k, v in experiment().metrics.items() if k != "status"}
    with pytest.raises(baseline_store.BaselineRefused, match="records no status"):
        baseline_store.from_experiment(experiment(metrics=metrics))


@pytest.mark.parametrize("split", ["calibration", "held_out", None])
def test_a_partial_split_cannot_become_a_baseline(split):
    """A baseline promises the agent's whole dataset; a split is a different denominator."""
    metrics = {**experiment().metrics, "comparison_identity": {"split": split}}
    with pytest.raises(baseline_store.BaselineRefused, match="not the full dataset"):
        baseline_store.from_experiment(experiment(metrics=metrics))


def test_a_stub_run_cannot_become_a_baseline():
    with pytest.raises(baseline_store.BaselineRefused, match="stub model"):
        baseline_store.from_experiment(experiment(pricing="stub",
                                                  model_name="stub:verdict:sonnet"))


def test_a_run_with_no_commit_cannot_become_a_baseline():
    with pytest.raises(baseline_store.BaselineRefused, match="no commit"):
        baseline_store.from_experiment(experiment(git_sha=""))


def test_a_clean_complete_run_is_accepted_and_keeps_its_identity():
    baseline = baseline_store.from_experiment(experiment())
    assert baseline.git_commit == "b" * 40
    assert baseline.model_tier == "sonnet"
    assert baseline.pricing == "priced"
    assert baseline.metrics["task_success_rate"] == 0.9


def test_a_baseline_round_trips_through_the_file_it_is_stored_in(tmp_path, monkeypatch):
    monkeypatch.setattr(baseline_store, "baselines_dir", lambda: tmp_path)
    saved = baseline_store.from_experiment(experiment())
    path = baseline_store.save(saved)
    assert path == tmp_path / "verdict" / "sonnet.json"
    assert baseline_store.load("verdict", "sonnet") == saved
    # Stable on disk, so a re-save with the same numbers is not a diff to review.
    assert json.loads(path.read_text())["git_commit"] == "b" * 40


def test_drift_names_the_metrics_that_moved_and_nothing_else():
    previous = baseline_store.from_experiment(experiment())
    moved = baseline_store.drift(previous, {**previous.metrics, "task_success_rate": 0.8})
    assert moved == [("task_success_rate", 0.9, 0.8)]
    assert baseline_store.drift(previous, dict(previous.metrics)) == []


def test_a_baseline_measured_at_another_commit_says_so():
    """Silence would be a claim that the number still holds."""
    stale = baseline_store.from_experiment(experiment(git_sha="f" * 40))
    note = baseline_store.staleness(stale)
    assert note is None or "the code has moved" in note


# --- comparability ------------------------------------------------------------------------

def row(label: str, pricing: str, cost: float) -> dict:
    return {"label": label, "experiment_id": f"exp-{label}", "pricing": pricing,
            "metrics": {"task_success_rate": 0.9, "average_cost_usd": cost,
                        "distributions": {"p50_latency_s": 1.0}}}


def test_mixing_priced_and_self_hosted_models_warns_that_cost_is_not_comparable():
    table = comparison_table([row("sonnet", "priced", 0.02),
                              row("selfhosted", "zero_priced", 0.0)])
    assert "not priced on the same basis" in table
    assert "zero_priced" in table


def test_models_priced_the_same_way_carry_no_warning():
    table = comparison_table([row("sonnet", "priced", 0.02), row("opus", "priced", 0.09)])
    assert "not priced on the same basis" not in table


def test_a_single_unpriced_model_still_states_its_cost_basis():
    """One row cannot be 'not comparable', but a zero that is a missing price table rather
    than a cheap model is still the reader's problem."""
    table = comparison_table([row("selfhosted", "zero_priced", 0.0)])
    assert "cost basis" in table
    assert "not priced on the same basis" not in table


def test_the_table_renders_every_column_a_model_choice_turns_on():
    table = comparison_table([row("sonnet", "priced", 0.02)])
    for column in ("accuracy", "p50 lat", "p95 lat", "$/case", "p95 req", "budget"):
        assert column in table, f"the comparison table has no {column!r} column"


def test_an_empty_sweep_renders_rather_than_raising():
    assert comparison_table([]) == "(no experiments)"
