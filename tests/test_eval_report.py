"""The eval report carries what the playbook's Provenance and Multi-run sections require.

A release gate is only as good as the report it reads. agent-playbook 07-evaluation asks for
distributions rather than means ("pass rate and worst-case score / p50/p95 latency and cost /
tool-call and model-request distributions / failure-category distribution") and enumerates what
provenance must record. A mean alone hides the tail a budget exists to brake, and a pass nobody
can reproduce is a claim rather than evidence.
"""
import inspect
from types import SimpleNamespace

import pytest

from infosec_harness.evals import run as run_module


def _report(**overrides):
    """Build a report through the real writer, with a metrics dict of the shape it consumes."""
    metrics = {
        "schema_validity_rate": 1.0,
        "budget_exhausted_count": 0,
        "task_success_rate": 0.9,
        "average_cost_usd": 0.01,
        "p95_model_requests": 3,
        "distributions": {
            "worst_repetition_pass_rate": 0.8,
            "p50_latency_s": 1.0, "p95_latency_s": 4.0,
            "p50_cost_usd": 0.01, "p95_cost_usd": 0.03,
            "p50_model_requests": 2, "p95_model_requests": 3,
            "p50_tool_calls": 1, "p95_tool_calls": 4,
            "failure_categories": {"wrong_answer": 1, "budget_exhausted": 0, "invalid_output": 0},
        },
    }
    metrics.update(overrides)
    return metrics


def test_the_writer_records_every_provenance_field_the_playbook_enumerates(tmp_path):
    path = tmp_path / "r.json"
    run_module.write_release_report(
        path, agent="verdict", metrics=_report(), cfg_hash="abc", model_name="stub",
        dataset_version="1", agent_version="1.0.0", experiment_id="exp-1", repeat=3,
    )
    import json

    provenance = json.loads(path.read_text())["provenance"]
    for field in ("git_commit", "agent_version", "config_hash", "model", "dataset_version",
                  "recorded_at", "run_count", "dataset", "execution_mode", "evaluators", "model_settings",
                  "skills", "toolsets", "case_results"):
        assert field in provenance, f"provenance is missing {field!r}"
    assert provenance["run_count"] == 3
    # The absence of an LLM judge is a stated fact, not an omission: the playbook forbids a
    # judge as the sole evaluator for schema validity and safety, and every gate here is
    # deterministic. A reader must be able to see that rather than infer it.
    assert "judge_rubric" in provenance and provenance["judge_rubric"] is None


def test_the_report_carries_distributions_not_only_means(tmp_path):
    import json

    path = tmp_path / "r.json"
    run_module.write_release_report(
        path, agent="verdict", metrics=_report(), cfg_hash="abc", model_name="stub",
        dataset_version="1", agent_version="1.0.0",
    )
    dist = json.loads(path.read_text())["distributions"]
    for field in ("worst_repetition_pass_rate", "p50_latency_s", "p95_latency_s",
                  "p50_cost_usd", "p95_cost_usd", "p50_model_requests", "p95_model_requests",
                  "p50_tool_calls", "p95_tool_calls", "failure_categories"):
        assert field in dist, f"distributions missing {field!r}"


def test_the_failure_categories_distinguish_three_different_problems():
    """A wrong answer, a run stopped by its budget, and an output that never validated are not
    the same failure and must not be summed into one rate."""
    categories = _report()["distributions"]["failure_categories"]
    assert set(categories) == {"wrong_answer", "budget_exhausted", "invalid_output"}


def test_the_percentile_helper_is_defined_on_an_empty_series():
    """Reports are written for runs that scored nothing (an outage, a truncated run), and a
    percentile that raised there would lose the report along with the run."""
    assert run_module._pct([], 0.95) == 0.0
    assert run_module._pct([1.0], 0.5) == 1.0
    assert run_module._pct([1.0, 2.0, 3.0, 4.0], 0.5) == 2.0


def test_percentiles_use_versioned_nearest_rank_semantics():
    """The API/report label and implementation must describe the same calculation."""
    from infosec_harness.evals import run as run_module

    values = [1.0, 2.0, 3.0, 4.0]
    assert run_module.PERCENTILE_METHOD == "nearest-rank-v1"
    assert run_module._pct(values, 0.0) == 1.0
    assert run_module._pct(values, 0.5) == 2.0
    assert run_module._pct(values, 0.95) == 4.0
    assert run_module._p95([1, 2, 3, 4]) == 4
    with pytest.raises(ValueError, match="between 0 and 1"):
        run_module._pct(values, 1.01)


def test_worst_case_is_reported_rather_than_the_mean_across_repetitions():
    """With --repeat, averaging launders a bad run into an acceptable number, so the worst
    repetition is what the report quotes. Pinned as source, since computing it needs a live run.
    """
    source = inspect.getsource(run_module.run_experiment)
    assert "worst_repetition_pass_rate" in source
    assert "min(" in source, "the worst repetition must be a minimum, not a mean"


def test_latency_is_recorded_even_for_cases_that_failed():
    """A run stopped by its budget still took time. Excluding it would make the latency
    distribution describe only the cases that behaved."""
    source = inspect.getsource(run_module.run_experiment)
    budget_branch = source.index("budget_exhausted += 1")
    latency_append = source.index("latencies.append")
    assert latency_append > budget_branch, (
        "latency is appended before the failure branches, so failed cases are not timed"
    )


def _comparable_row(identifier: str, *, digest: str = "source-a", dirty: bool = False):
    metrics = {
        "status": "complete", "n": 2, "n_planned": 2, "passed": 2,
        "accuracy": 1.0, "task_success_rate": 1.0, "schema_validity_rate": 1.0,
        "p95_model_requests": 2, "average_cost_usd": 0.1, "cost_unknown": 0,
        "comparison_identity": {
            "case_set_digest": "cases", "evaluator_version": "evaluator-v1",
            "execution_mode": run_module.EVAL_EXECUTION_MODE,
            "repetitions": 1, "split": "full",
        },
        "code_identity": {"source_digest": digest},
    }
    return SimpleNamespace(
        id=identifier, agent="verdict", dataset="dataset.yaml", dataset_version="1",
        git_sha="abc", git_dirty=dirty, harness_version="1", pricing="configured",
        metrics=metrics,
    )


def test_release_comparisons_require_exact_clean_source_and_execution_identity():
    from infosec_harness.evals.reporting import comparability_issues

    baseline = _comparable_row("baseline")
    assert comparability_issues([baseline, _comparable_row("candidate")]) == []
    assert any("source digest" in issue for issue in comparability_issues([
        baseline, _comparable_row("code-change", digest="source-b")
    ]))
    assert any("dirty" in issue for issue in comparability_issues([
        baseline, _comparable_row("dirty", dirty=True)
    ]))
    changed_execution = _comparable_row("runtime-change")
    changed_execution.metrics["comparison_identity"]["execution_mode"] = "temporal-v2"
    assert any("execution mode" in issue for issue in comparability_issues([
        baseline, changed_execution
    ]))
