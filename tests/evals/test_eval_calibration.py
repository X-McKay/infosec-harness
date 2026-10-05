from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from sqlalchemy import select

from infosec_harness.evals.calibration import (
    CalibrationSpec,
    TrialResult,
    _promotion_eligible,
    _selection_key,
    admissible,
    load_calibration,
    run_calibration,
    write_report,
)
from infosec_harness.evals.dataset import case_group
from infosec_harness.evals.gates import load_policy
from infosec_harness.evals.run import run_experiment
from infosec_harness.persistence import db
from infosec_harness.settings import get_settings

# Every hard gate the verdict and build-repair policies name, at its passing value.
PASSING = {
    "status": "complete",
    "n": 1,
    "n_planned": 1,
    "schema_validity_rate": 1.0,
    "budget_exhausted_count": 0,
    "unevidenced_safe_verdicts": 0,
    "uncovered_material_scenarios": 0,
    "execution_not_checked_count": 0,
    "execution_failed_count": 0,
}


def test_grouping_keeps_related_variants_together():
    assert (
        case_group({"name": "sqli-vulnerable", "repo": "corpus/sqli/vulnerable"}) == "corpus/sqli"
    )
    assert case_group({"name": "sqli-fixed", "repo": "corpus/sqli/fixed"}) == "corpus/sqli"
    assert case_group({"name": "anything", "group": "repo-17"}) == "repo-17"


def test_candidate_ranking_preserves_observed_zero_and_penalizes_unknown_usage():
    def trial(tokens):
        return TrialResult(
            candidate=str(tokens),
            effective_config_digest=str(tokens),
            status="complete",
            metrics={
                "task_success_rate": 1.0,
                "distributions": {"p95_latency_s": 1.0},
                "avg_tokens": tokens,
            },
        )

    assert _selection_key(trial(0)) > _selection_key(trial(1))
    assert _selection_key(trial(1)) > _selection_key(trial(None))


def test_failed_or_missing_execution_evidence_fails_the_build_repair_policy():
    policy = load_policy("build-repair")
    assert admissible(policy, PASSING)
    assert not admissible(policy, {**PASSING, "execution_failed_count": 1})
    missing = dict(PASSING)
    missing.pop("execution_failed_count")
    assert not admissible(policy, missing)


def test_calibration_gates_are_the_agents_own_policy_not_a_private_list():
    """Verdict gates unevidenced safety and coverage; it does not gate execution evidence."""
    policy = load_policy("verdict")
    no_execution = {k: v for k, v in PASSING.items() if not k.startswith("execution_")}
    assert admissible(policy, no_execution)
    assert not admissible(policy, {**no_execution, "unevidenced_safe_verdicts": 1})
    assert not admissible(policy, {**no_execution, "uncovered_material_scenarios": 1})
    assert not admissible(policy, {**no_execution, "budget_exhausted_count": 1})
    assert not admissible(policy, {**no_execution, "status": "truncated"})
    assert not admissible(policy, {**no_execution, "n": 0})


@pytest.mark.parametrize(
    "model_mode, dirty, expected",
    [
        ("stub", False, False),
        ("stub", True, False),
        ("live", False, True),
        ("live", True, False),
    ],
)
def test_promotion_requires_live_evidence_from_a_clean_commit(model_mode, dirty, expected):
    from infosec_harness.evals.provenance import CodeVersion

    gates = dict(PASSING)
    selected = TrialResult(candidate=1, effective_config_digest="digest", status="complete")
    code = CodeVersion("a" * 40, dirty, "test", "3.12", "b" * 64)
    assert (
        _promotion_eligible(
            policy=load_policy("verdict"),
            selected=selected,
            held_out_metrics=gates,
            selected_quality=True,
            held_out_quality=True,
            code=code,
            model_mode=model_mode,
            cost_is_unknown=False,
            maximum_cost_usd=None,
        )
        is expected
    )


def test_calibration_schema_rejects_leakage_and_safety_variables():
    base = {
        "experiment": "x",
        "subject": "verdict",
        "hypothesis": "bounded hypothesis",
        "variable": "metadata.budgets.max_requests",
        "candidates": [2, 3],
        "repetitions": 1,
        "dataset": {"calibration": ["a"], "held_out": ["a"]},
        "constraints": {
            "maximum_trials": 2,
            "maximum_duration_seconds": 10,
            "maximum_model_requests": 10,
            "minimum_task_success_rate": 0.8,
        },
    }
    with pytest.raises(ValidationError, match="overlap"):
        CalibrationSpec.model_validate(base)
    base["dataset"] = {"calibration": ["a"], "held_out": ["b"]}
    base["variable"] = "metadata.enabled_toolsets"
    with pytest.raises(ValidationError, match="not calibration variables"):
        CalibrationSpec.model_validate(base)


def test_effective_model_and_budget_provenance_records_backend_adjustments(monkeypatch):
    from infosec_harness.agents import models, registry

    monkeypatch.setenv("HARNESS_MODEL_MODE", "live")
    monkeypatch.setenv("HARNESS_MODEL_BACKEND", "gateway")
    get_settings.cache_clear()
    models.load_models_config.cache_clear()
    try:
        spec = registry.load_spec("probe-diagnosis")
        resolved = registry.resolve_agent_config("probe-diagnosis", spec)
        assert resolved.model.backend_kind == "openai_compatible"
        assert resolved.model.requested_settings["max_tokens"] < 16_000
        assert resolved.model.effective_settings["max_tokens"] == 16_000
        assert resolved.model.capability_profile.message_layout == "single_system"
        assert resolved.budget.provider_output_floor == 16_000
        assert resolved.budget.formula_version == "repo-source-files-log2-v1"
        assert resolved.digest
    finally:
        get_settings.cache_clear()
        models.load_models_config.cache_clear()


def test_floor_equivalent_candidates_share_effective_not_audit_identity(monkeypatch):
    from infosec_harness.agents import models, registry

    monkeypatch.setenv("HARNESS_MODEL_MODE", "live")
    monkeypatch.setenv("HARNESS_MODEL_BACKEND", "gateway")
    get_settings.cache_clear()
    models.load_models_config.cache_clear()
    try:
        first = registry.load_spec("probe-diagnosis", {"model_settings": {"max_tokens": 100}})
        second = registry.load_spec("probe-diagnosis", {"model_settings": {"max_tokens": 200}})
        resolved_first = registry.resolve_agent_config("probe-diagnosis", first, durable=True)
        resolved_second = registry.resolve_agent_config("probe-diagnosis", second, durable=True)
        assert resolved_first.model.effective_settings["max_tokens"] == 16_000
        assert resolved_first.digest != resolved_second.digest
        assert resolved_first.effective_digest == resolved_second.effective_digest
    finally:
        get_settings.cache_clear()
        models.load_models_config.cache_clear()


def test_root_ceiling_only_tightens_the_scaled_member_budget():
    from infosec_harness.agents.budgets import RunBudget, resolve_declared_budget

    member = RunBudget(
        max_requests=8,
        max_tool_calls=12,
        max_input_tokens_per_request=100,
        max_input_tokens=800,
        max_output_tokens=400,
        max_cost_usd=1.0,
    )
    root = RunBudget(
        max_requests=6,
        max_tool_calls=20,
        max_input_tokens_per_request=80,
        max_input_tokens=600,
        max_output_tokens=300,
        max_cost_usd=0.5,
    )
    resolved = resolve_declared_budget("x", member, root_ceiling=root)
    assert resolved.effective.max_requests == 6
    assert resolved.effective.max_tool_calls == 12
    assert set(resolved.binding_root_fields) == {
        "max_requests",
        "max_input_tokens_per_request",
        "max_input_tokens",
        "max_output_tokens",
        "max_cost_usd",
    }


async def test_eval_case_records_effective_limits_raw_latency_and_observed_usage():
    experiment_id = await run_experiment(
        "probe-diagnosis", groups={"positive"}, split="calibration"
    )
    async with db.session() as session:
        rows = list(
            (
                await session.execute(
                    select(db.EvalCaseResult).where(
                        db.EvalCaseResult.experiment_id == experiment_id
                    )
                )
            ).scalars()
        )
        experiment = await session.get(db.EvalExperiment, experiment_id)
    assert rows
    assert experiment is not None
    effective = experiment.metrics["effective_configuration"]
    assert effective["model"]["durable"] is True
    assert effective["budget"]["effective"] == rows[0].scores["effective_budget"]["effective"]
    assert all(row.latency_s > 0 for row in rows)
    for row in rows:
        assert row.scores["usage_status"] == "observed"
        assert row.scores["effective_config_digest"]
        assert row.scores["effective_budget"]["formula_version"] == "repo-source-files-log2-v1"


async def test_runnable_calibration_executes_candidates_then_grouped_holdout(tmp_path):
    from infosec_harness.agents import registry

    spec_path = Path("evals/experiments/calibration/verdict-tool-budget.yaml")
    spec = load_calibration(spec_path)
    report = await run_calibration(spec)

    assert len(report.trials) == 2
    assert all(trial.experiment_id for trial in report.trials if trial.status == "complete")
    assert report.selected_candidate in spec.candidates
    assert report.held_out_experiment_id
    assert report.held_out_metrics["comparison_identity"]["split"] == "held_out"
    assert report.promotion == "review_required"
    assert report.code_identity["source_digest"]
    assert report.thresholds["minimum_task_success_rate"] == 0.30
    assert report.baseline_config_digest == registry.config_hash(
        "verdict", registry.load_spec("verdict"), durable=True
    )
    assert not report.promotion_eligible, "stub evidence must never be promoted"
    assert "stub-model results exercise calibration machinery only" in " ".join(report.limitations)

    # Calibration trials are measurements, not releases: none may write a release report.
    reports = get_settings().reports_dir / "evals"
    for experiment_id in [t.experiment_id for t in report.trials] + [report.held_out_experiment_id]:
        assert not (reports / f"{experiment_id}.json").exists()

    output = tmp_path / "report.json"
    write_report(output, report)
    written = yaml.safe_load(output.read_text())
    assert written["selected_candidate"] == report.selected_candidate
    assert not list(tmp_path.glob(f".{output.name}.*")), "atomic temp file was not cleaned up"


async def test_live_custom_pricing_cost_cap_is_rejected_before_any_call(monkeypatch):
    from infosec_harness.agents import models

    raw = yaml.safe_load(Path("evals/experiments/calibration/verdict-tool-budget.yaml").read_text())
    raw["model"] = "claude-sonnet-5"
    raw["backend_profile"] = "gateway"
    raw["constraints"]["maximum_cost_usd"] = 100.0
    spec = CalibrationSpec.model_validate(raw)
    monkeypatch.setenv("HARNESS_MODEL_MODE", "live")
    monkeypatch.setenv("HARNESS_MODEL_BACKEND", "gateway")
    get_settings.cache_clear()
    models.load_models_config.cache_clear()
    try:
        with pytest.raises(ValueError, match="cannot be enforced before calls.*custom"):
            await run_calibration(spec)
    finally:
        get_settings.cache_clear()
        models.load_models_config.cache_clear()


async def test_live_catalog_cost_cap_reserves_worst_case_before_calls(monkeypatch):
    from infosec_harness.agents import models
    from infosec_harness.evals import calibration

    raw = yaml.safe_load(Path("evals/experiments/calibration/verdict-tool-budget.yaml").read_text())
    raw["backend_profile"] = "bedrock"
    raw["constraints"]["maximum_cost_usd"] = 0.01
    spec = CalibrationSpec.model_validate(raw)

    async def must_not_run(*args, **kwargs):
        raise AssertionError("preflight cost reservation must happen before the first eval call")

    monkeypatch.setenv("HARNESS_MODEL_MODE", "live")
    monkeypatch.setenv("HARNESS_MODEL_BACKEND", "bedrock")
    monkeypatch.setattr(calibration, "run_experiment", must_not_run)
    get_settings.cache_clear()
    models.load_models_config.cache_clear()
    try:
        with pytest.raises(ValueError, match="planned worst-case cost.*exceeds"):
            await run_calibration(spec)
    finally:
        get_settings.cache_clear()
        models.load_models_config.cache_clear()


async def test_stub_cost_cap_has_zero_reserved_exposure():
    raw = yaml.safe_load(Path("evals/experiments/calibration/verdict-tool-budget.yaml").read_text())
    raw["constraints"]["maximum_cost_usd"] = 0.01
    report = await run_calibration(CalibrationSpec.model_validate(raw))
    assert report.planned_cost_ceiling_usd == 0.0


@pytest.mark.parametrize("include_safety_metric", [True, False])
async def test_calibration_skips_provider_floor_equivalent_candidate(
    monkeypatch,
    include_safety_metric,
):
    from types import SimpleNamespace

    from infosec_harness.agents import models
    from infosec_harness.evals import calibration

    raw = yaml.safe_load(Path("evals/experiments/calibration/verdict-tool-budget.yaml").read_text())
    raw["variable"] = "model_settings.max_tokens"
    raw["candidates"] = [100, 200]
    raw["backend_profile"] = "gateway"
    spec = CalibrationSpec.model_validate(raw)
    calls: list[str] = []
    rows: dict[str, object] = {}

    async def fake_run(*args, **kwargs):
        split = kwargs["split"]
        identifier = f"exp-{split}-{len(calls)}"
        calls.append(split)
        metrics = {
            **PASSING,
            "task_success_rate": 1.0,
            "cost_usd_total": 0.0,
            "distributions": {"p95_latency_s": 0.1},
            "avg_tokens": 1,
        }
        if not include_safety_metric:
            # A gate the verdict policy names, absent: unknown evidence fails closed.
            metrics.pop("unevidenced_safe_verdicts")
        rows[identifier] = SimpleNamespace(metrics=metrics)
        return identifier

    async def fake_row(identifier):
        return rows[identifier]

    monkeypatch.setenv("HARNESS_MODEL_MODE", "live")
    monkeypatch.setenv("HARNESS_MODEL_BACKEND", "gateway")
    monkeypatch.setattr(calibration, "run_experiment", fake_run)
    monkeypatch.setattr(calibration, "_experiment_row", fake_row)
    get_settings.cache_clear()
    models.load_models_config.cache_clear()
    try:
        report = await run_calibration(spec)
    finally:
        get_settings.cache_clear()
        models.load_models_config.cache_clear()

    assert calls == (["calibration", "held_out"] if include_safety_metric else ["calibration"])
    assert [trial.status for trial in report.trials] == ["complete", "duplicate_effective"]
    assert report.trials[1].duplicate_of == 100
    if include_safety_metric:
        assert report.selected_candidate == 100
    else:
        assert report.selected_candidate is None
        assert report.held_out_experiment_id is None
        assert "no calibration candidate passed all hard gates" in report.limitations


def test_groups_that_leave_a_material_scenario_uncovered_are_refused_before_any_call():
    """Every run of such groups fails the policy's coverage gate, so nothing could be selected;
    the plan is refused before it spends anything."""
    raw = yaml.safe_load(Path("evals/experiments/calibration/verdict-tool-budget.yaml").read_text())
    spec = CalibrationSpec.model_validate(raw)
    from infosec_harness.evals.calibration import _validate_groups
    from infosec_harness.evals.dataset import load_dataset

    cases = load_dataset("verdict").cases
    assert _validate_groups(spec, cases, load_policy("verdict")) == (3, 2)
    stripped = tuple({**case, "scenarios": []} if case_group(case) in set(spec.dataset.calibration)
                     else case for case in cases)
    with pytest.raises(ValueError, match="calibration groups leave material risk scenarios"):
        _validate_groups(spec, stripped, load_policy("verdict"))
