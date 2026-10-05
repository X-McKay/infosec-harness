"""The eval report carries what the playbook's Provenance and Multi-run sections require.

A release gate is only as good as the report it reads. agent-playbook 07-evaluation asks for
distributions rather than means ("pass rate and worst-case score / p50/p95 latency and cost /
tool-call and model-request distributions / failure-category distribution") and enumerates what
provenance must record. A mean alone hides the tail a budget exists to brake, and a pass nobody
can reproduce is a claim rather than evidence.
"""
import json
import os
from types import SimpleNamespace

import pytest

from infosec_harness.evals import release_report
from infosec_harness.evals.gates import load_policy
from infosec_harness.evals.metrics import (
    GATEABLE_METRICS,
    PERCENTILE_METHOD,
    UNEVIDENCED_SAFETY_METRIC,
    RunPlan,
    experiment_metrics,
    percentile,
)
from infosec_harness.evals.run import EVAL_EXECUTION_MODE


def attempt(*, passed=True, outcome="answered", repetition=0, latency=1.0, cost=0.01,
            requests=2, tools=1, expected="x", predicted=None, execution=None, unevidenced=False):
    usage = None if outcome in {"budget_exhausted", "invalid_output", "failed"} else {
        "requests": requests, "input_tokens": 100, "output_tokens": 10,
        "cache_read_tokens": 0, "cache_write_tokens": 0}
    record = {
        "case": "c", "group": "c", "repetition": repetition, "expected": expected,
        "outcome": outcome, "latency_s": latency, "usage": usage,
        "usage_status": "observed" if usage else "unknown", "cost_usd": cost,
        "cost_status": "observed", "call_summary": {"tool_call_count": tools},
    }
    if outcome != "failed":
        record.update(passed=passed, unevidenced_safe=unevidenced,
                      predicted=predicted or (expected if passed else "y"))
    if execution:
        record["execution_check"] = {"status": execution}
    return record


def plan(cases=1, repetitions=1, execution_checks=0, unevidenced=True, uncovered=0):
    return RunPlan(cases=cases, repetitions=repetitions, execution_checks=execution_checks,
                   unevidenced_safety=unevidenced, uncovered_material_scenarios=uncovered)


def complete_metrics(attempts, run_plan, **identity):
    metrics = experiment_metrics(attempts, run_plan, status="complete",
                                 cases_completed=run_plan.cases)
    metrics["comparison_identity"] = {
        "case_set_digest": "digest", "dataset_version": "3", "split": "full",
        "repetitions": run_plan.repetitions, "execution_mode": EVAL_EXECUTION_MODE,
        "evaluator_version": "v", **identity}
    metrics["code_identity"] = {"git_commit": "a" * 40, "git_dirty": False,
                                "source_digest": "s"}
    metrics["scenario_coverage"] = {"scenarios_uncovered_material": []}
    return metrics


DATASET = "src/infosec_harness/agents/verdict/evals/dataset.yaml"


def provenance(metrics, **changes):
    spec = SimpleNamespace(metadata={"enabled_skills": ["cwe-89-sql-injection"]},
                           model_settings={"temperature": 0})
    recorded = release_report.report_provenance(
        code_identity=metrics["code_identity"],
        comparison_identity={**metrics["comparison_identity"], "dataset": DATASET},
        agent_version="1.1.0", cfg_hash="abc", model_name="stub:verdict:sonnet",
        pricing="stub", experiment_id="exp-1", spec=spec)
    return {**recorded, **changes}


def write(path, metrics, **changes):
    lines: list[str] = []
    report = release_report.write_release_report(
        path, agent="verdict", metrics=metrics, provenance=provenance(metrics, **changes),
        policy=load_policy("verdict"), echo=lines.append)
    return report, lines


# --- the release report -------------------------------------------------------------------


def test_the_writer_records_every_provenance_field_the_playbook_enumerates(tmp_path):
    metrics = complete_metrics([attempt()] * 3, plan(cases=1, repetitions=3))
    report, _ = write(tmp_path / "r.json", metrics)
    written = json.loads((tmp_path / "r.json").read_text())
    recorded = written["provenance"]
    for field in ("git_commit", "agent_version", "config_hash", "model", "dataset_version",
                  "recorded_at", "dataset", "execution_mode", "evaluator_version",
                  "model_settings", "skills", "toolsets", "model_pricing", "experiment_id"):
        assert field in recorded, f"provenance is missing {field!r}"
    assert recorded["dataset"] == DATASET
    assert recorded["skills"] == ["cwe-89-sql-injection"]
    # What the numbers are over is recorded once, in `run`, not again in provenance.
    assert written["run"]["repetitions"] == 3
    assert not {"case_set_digest", "split", "run_count"} & set(recorded)


def test_a_report_missing_required_provenance_cannot_pass(tmp_path):
    """The policy names the provenance that makes a pass attributable; without it, the gates
    are not_checked however good the numbers are."""
    metrics = complete_metrics([attempt()], plan())
    passing, _ = write(tmp_path / "ok.json", metrics)
    assert passing["gate_evaluation"]["status"] == "passed"
    assert passing["gate_evaluation"]["missing_provenance"] == []
    for key in load_policy("verdict").required_provenance:
        report, lines = write(tmp_path / f"{key}.json", metrics, **{key: ""})
        assert report["gate_evaluation"]["status"] == "not_checked", key
        assert report["gate_evaluation"]["missing_provenance"] == [key]
        assert any("gates not_checked" in line for line in lines)


def test_the_report_says_what_its_numbers_are_over(tmp_path):
    """A pass over a calibration split or a truncated run is not a pass over the dataset."""
    metrics = complete_metrics([attempt(), attempt()], plan(cases=2), split="held_out")
    report, _ = write(tmp_path / "r.json", metrics)
    assert report["run"] == {"status": "complete", "split": "held_out", "n": 2, "n_planned": 2,
                             "cases_planned": 2, "repetitions": 1, "case_set_digest": "digest"}


def test_the_report_gates_are_exactly_the_policys_and_carry_its_verdict(tmp_path):
    policy = load_policy("verdict")
    metrics = complete_metrics([attempt(), attempt(passed=False)], plan(cases=2))
    report, lines = write(tmp_path / "r.json", metrics)
    assert set(report["hard_gates"]) == set(policy.hard_gates)
    assert set(report["metrics"]) == set(policy.thresholds)
    # 1/2 is below the 0.75 floor: the policy's own verdict travels with the numbers.
    assert report["gate_evaluation"]["status"] == "failed"
    failed = [c for c in report["gate_evaluation"]["checks"] if c["status"] == "failed"]
    assert [(c["metric"], c["bound"]) for c in failed] == [("task_success_rate", "min")]
    assert any("gates failed" in line for line in lines)


def test_every_report_written_carries_its_inert_gate_audit(tmp_path):
    """Stub cost is 0.0 by construction, so the cost ceiling is inert -- said in the report
    and on the console, not only when someone remembers to run the audit command."""
    metrics = complete_metrics([attempt(cost=0.0)], plan())
    report, lines = write(tmp_path / "r.json", metrics)
    assert [(c["metric"], c["reason"], c["is_defect"]) for c in report["inert_checks"]] == [
        ("average_cost_usd", "COST_STUB_MODEL", False)]
    assert "INERT RELEASE GATES" in lines[0]
    assert json.loads((tmp_path / "r.json").read_text())["inert_checks"] == report["inert_checks"]


def test_the_report_carries_distributions_not_only_means(tmp_path):
    report, _ = write(tmp_path / "r.json", complete_metrics([attempt()], plan()))
    for field in ("worst_repetition_pass_rate", "p50_latency_s", "p95_latency_s",
                  "p50_cost_usd", "p95_cost_usd", "p50_model_requests",
                  "p50_tool_calls", "p95_tool_calls", "failure_categories"):
        assert field in report["distributions"], f"distributions missing {field!r}"
    # Published once, where the policy gates it.
    assert "p95_model_requests" not in report["distributions"]
    assert report["metrics"]["p95_model_requests"] == 2


def test_failed_atomic_report_publish_preserves_previous_evidence(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    path.write_text("previous evidence\n")

    def fail_replace(source, target):
        raise OSError("publish interrupted")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError, match="publish interrupted"):
        write(path, complete_metrics([attempt()], plan()))
    assert path.read_text() == "previous evidence\n"
    assert list(tmp_path.iterdir()) == [path]


# --- metrics are a function of the attempts --------------------------------------------------


def test_failure_categories_partition_the_failed_attempts():
    """A wrong answer, a budget stop and an output that never validated are three problems."""
    attempts = [attempt(passed=False), attempt(passed=False, outcome="budget_exhausted"),
                attempt(passed=False, outcome="invalid_output"), attempt()]
    metrics = experiment_metrics(attempts, plan(cases=4), status="complete", cases_completed=4)
    assert metrics["distributions"]["failure_categories"] == {
        "wrong_answer": 1, "budget_exhausted": 1, "invalid_output": 1,
        "execution_not_checked": 0, "execution_failed": 0}


def test_an_outcome_that_matched_its_expectation_is_not_a_failure():
    """Regression: categories were `total - passed - stops - ...`, so a budget stop or a failed
    execution that was itself the expected label was subtracted twice and `wrong_answer` went
    negative."""
    attempts = [attempt(outcome="budget_exhausted", expected="budget_exhausted"),
                attempt(outcome="execution_failed", expected="unaddressed",
                        predicted="unaddressed", execution="failed")]
    metrics = experiment_metrics(attempts, plan(cases=2, execution_checks=1),
                                 status="complete", cases_completed=2)
    categories = metrics["distributions"]["failure_categories"]
    assert all(count >= 0 for count in categories.values())
    assert sum(categories.values()) == metrics["n"] - metrics["passed"] == 0
    # The gate still sees the failed execution: a passing label does not launder it.
    assert metrics["execution_failed_count"] == 1
    assert metrics["budget_exhausted_count"] == 1


def test_worst_case_is_reported_rather_than_the_mean_across_repetitions():
    attempts = [attempt(repetition=0), attempt(repetition=0),
                attempt(repetition=1), attempt(repetition=1, passed=False)]
    metrics = experiment_metrics(attempts, plan(cases=2, repetitions=2), status="complete",
                                 cases_completed=2)
    assert metrics["task_success_rate"] == 0.75
    assert "accuracy" not in metrics, "task_success_rate is the one pass-rate metric"
    assert metrics["distributions"]["worst_repetition_pass_rate"] == 0.5


def test_latency_is_recorded_even_for_cases_that_failed():
    """A run stopped by its budget still took time; excluding it would make the distribution
    describe only the cases that behaved."""
    attempts = [attempt(latency=1.0), attempt(latency=30.0, outcome="budget_exhausted",
                                              passed=False)]
    metrics = experiment_metrics(attempts, plan(cases=2), status="complete", cases_completed=2)
    assert metrics["distributions"]["p95_latency_s"] == 30.0


def test_an_attempt_the_run_fell_over_on_is_counted_but_not_scored():
    attempts = [attempt(), attempt(outcome="failed", cost=None)]
    metrics = experiment_metrics(attempts, plan(cases=2), status="truncated", cases_completed=1)
    assert metrics["n"] == 1 and metrics["attempted_runs"] == 2
    assert metrics["cost_unknown"] == 1 and metrics["cost_usd_total"] is None
    assert metrics["usage_observations"]["attempt_coverage_rate"] == 0.5


def test_unevidenced_safety_is_published_only_where_it_is_defined():
    """A constant zero for an agent with no predicate would read as a safety gate that held."""
    flagged = [attempt(unevidenced=True)]
    assert experiment_metrics(flagged, plan(), status="complete",
                              cases_completed=1)["unevidenced_safe_verdicts"] == 1
    assert "unevidenced_safe_verdicts" not in experiment_metrics(
        flagged, plan(unevidenced=False), status="complete", cases_completed=1)


def test_unreached_declared_execution_checks_stay_not_checked():
    metrics = experiment_metrics([attempt(execution="passed")], plan(cases=3, execution_checks=3),
                                 status="truncated", cases_completed=1)
    assert metrics["execution_checks_passed"] == 1
    assert metrics["execution_not_checked_count"] == 2


@pytest.mark.parametrize("unevidenced", [True, False])
def test_the_gateable_metric_names_are_exactly_the_numbers_a_run_publishes(unevidenced):
    shape = experiment_metrics([], plan(unevidenced=unevidenced), status="complete",
                               cases_completed=0)
    numeric = {name for name, value in shape.items()
               if value is None or (isinstance(value, int | float)
                                    and not isinstance(value, bool))}
    assert numeric == GATEABLE_METRICS | ({UNEVIDENCED_SAFETY_METRIC} if unevidenced else set())


def test_the_percentile_helper_is_defined_on_an_empty_series():
    """Reports are written for runs that scored nothing, and a percentile that raised there
    would lose the report along with the run."""
    assert percentile([], 0.95) == 0.0
    assert percentile([1.0], 0.5) == 1.0


def test_percentiles_use_versioned_nearest_rank_semantics():
    values = [1.0, 2.0, 3.0, 4.0]
    assert PERCENTILE_METHOD == "nearest-rank-v1"
    assert percentile(values, 0.0) == 1.0
    assert percentile(values, 0.5) == 2.0
    assert percentile(values, 0.95) == 4.0
    with pytest.raises(ValueError, match="between 0 and 1"):
        percentile(values, 1.01)


def test_complete_observed_zero_usage_remains_numeric_zero():
    from infosec_harness.evals.metrics import usage_metrics

    unknown = usage_metrics([])
    assert unknown["avg_tokens"] is None and unknown["cache_hit_ratio"] is None
    assert unknown["usage_observations"]["attempt_coverage_rate"] is None
    zero = {"usage_status": "observed", "usage": {"input_tokens": 0, "output_tokens": 0}}
    metrics = usage_metrics([zero])
    assert metrics["avg_tokens"] == 0.0 and metrics["cache_hit_ratio"] == 0.0
    assert metrics["usage_observations"]["attempt_coverage_rate"] == 1.0


# --- comparison -----------------------------------------------------------------------------


def test_pairwise_descriptive_output_handles_unknown_aggregate_usage(capsys):
    from infosec_harness.evals.reporting import _print_pairwise

    baseline = SimpleNamespace(id="baseline", config_hash="a", metrics={
        "status": "complete", "task_success_rate": 1.0, "average_cost_usd": None,
        "avg_tokens": None, "cache_hit_ratio": None})
    candidate = SimpleNamespace(id="candidate", config_hash="b", metrics={
        "status": "complete", "task_success_rate": 1.0, "average_cost_usd": 0.0,
        "avg_tokens": 0.0, "cache_hit_ratio": 0.0})
    _print_pairwise(baseline, candidate)
    assert capsys.readouterr().out.count("(unknown)") == 3


def test_pairwise_output_does_not_read_a_missing_status_as_complete(capsys):
    from infosec_harness.evals.reporting import _print_pairwise

    complete = SimpleNamespace(id="a", config_hash="a", metrics={"status": "complete"})
    unrecorded = SimpleNamespace(id="b", config_hash="b", metrics={})
    _print_pairwise(complete, unrecorded)
    out = capsys.readouterr().out
    assert "candidate b is UNKNOWN" in out and "NOT a like-for-like" in out


def _comparable_row(identifier: str, *, digest: str = "source-a", dirty: bool = False):
    metrics = {
        "status": "complete", "n": 2, "n_planned": 2, "passed": 2,
        "task_success_rate": 1.0, "schema_validity_rate": 1.0,
        "p95_model_requests": 2, "average_cost_usd": 0.1, "cost_unknown": 0,
        "comparison_identity": {
            "case_set_digest": "cases", "evaluator_version": "evaluator-v1",
            "execution_mode": EVAL_EXECUTION_MODE, "repetitions": 1, "split": "full",
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
