"""A threshold that could not have failed must be reported, not silently passed.

The live example: every agent policy carries `average_cost_usd: {max: 0.50}`, and the
self-hosted backend has no per-token pricing, so cost is 0.0 for every case and the ceiling
enforces nothing. These tests pin the three cases that matter — priced (live), unpriced
(inert, and correct: a fact about the environment), and a threshold naming a metric the
report never emits (inert, and a defect).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from infosec_harness.agents import models
from infosec_harness.evals.gates import load_policy, parse_policy
from infosec_harness.evals.inert_gates import (
    InertReason,
    find_inert_checks,
    format_inert_notice,
)
from infosec_harness.evals.pricing import PricingStatus, pricing_label, pricing_status

RAW_POLICY = {
    "schema_version": 1,
    "hard_gates": {"schema_validity_rate": 1.0, "budget_exhausted_count": 0},
    "thresholds": {
        "task_success_rate": {"min": 0.85},
        "average_cost_usd": {"max": 0.50},
        "p95_model_requests": {"max": 12},
    },
}


def _policy(**changes):
    return parse_policy("context", {**RAW_POLICY, **changes}, Path("release-policy.yaml"))


POLICY = _policy()


def _report(*, model: str, cost: float | None = 0.0, metrics: dict | None = None,
            gates: dict | None = None) -> dict:
    return {
        "schema_version": 1,
        "subject": {"kind": "agent", "name": "context"},
        "agent": "context",
        # Mirrors what `write_release_report` really writes. A gate the report omits is
        # correctly audited as inert, so this fixture has to keep up with the writer --
        # which is how the missing entry here was found.
        "hard_gates": {"schema_validity_rate": 1.0, "budget_exhausted_count": 0,
                       "uncovered_material_scenarios": 0,
                       **(gates or {})},
        "metrics": {"task_success_rate": 0.9, "average_cost_usd": cost,
                    "p95_model_requests": 4, **(metrics or {})},
        "provenance": {"git_commit": "abc", "agent_version": "1.0.0", "config_hash": "h",
                       "model": model, "dataset_version": "1"},
    }


def _priced(_model: str) -> PricingStatus:
    return PricingStatus.PRICED


def _unpriced(_model: str) -> PricingStatus:
    return PricingStatus.UNKNOWN_MODEL


# --- the cost threshold: live, or inert? -------------------------------------------------

def test_a_priced_model_with_real_cost_leaves_the_cost_ceiling_live():
    report = _report(model="anthropic:claude-sonnet-5", cost=0.0731)
    assert find_inert_checks(report, POLICY, pricing=_priced) == []


def test_an_unpriced_model_makes_the_cost_ceiling_inert_but_not_a_defect():
    report = _report(model="gateway:Qwen3.6-35B-A3B-NVFP4", cost=0.0)
    (check,) = find_inert_checks(report, POLICY, pricing=_unpriced)
    assert (check.metric, check.bound, check.limit) == ("average_cost_usd", "max", 0.50)
    assert check.reason is InertReason.COST_UNPRICED_MODEL
    assert not check.is_defect, "the deployment not pricing the model is an environment fact"
    assert "Qwen3.6-35B-A3B-NVFP4" in check.detail
    # And the same run's other thresholds are untouched.
    assert [c.metric for c in find_inert_checks(report, POLICY, pricing=_unpriced)] == [
        "average_cost_usd"]


def test_a_self_hosted_model_priced_at_zero_is_inert_for_its_own_stated_reason():
    report = _report(model="gateway:Qwen3.6-35B-A3B-NVFP4")
    (check,) = find_inert_checks(report, POLICY,
                                pricing=lambda _m: PricingStatus.ZERO_PRICED)
    assert check.reason is InertReason.COST_ZERO_PRICED_MODEL
    assert not check.is_defect
    assert "zero per token" in check.detail


def test_stub_mode_says_no_model_was_called_rather_than_blaming_the_report():
    report = _report(model="stub:context:sonnet")
    (check,) = find_inert_checks(report, POLICY, pricing=lambda _m: PricingStatus.STUB)
    assert check.reason is InertReason.COST_STUB_MODEL
    assert not check.is_defect
    assert "stub mode" in check.detail


def test_an_unpriced_model_reporting_no_cost_is_an_environment_fact_not_a_defect():
    """An unpriced model reports cost as unknown (None), not 0.0. That absence is the same
    environment fact as a zero price, and must not be filed as a broken report."""
    report = _report(model="gateway:no-such-model", cost=None)
    (check,) = find_inert_checks(report, POLICY, pricing=_unpriced)
    assert check.reason is InertReason.COST_UNPRICED_MODEL
    assert not check.is_defect
    assert check.value is None


def test_unknown_cost_under_a_priced_model_is_still_a_defect():
    report = _report(model="anthropic:claude-sonnet-5", cost=None)
    (check,) = find_inert_checks(report, POLICY, pricing=_priced)
    assert check.reason is InertReason.METRIC_NOT_NUMERIC
    assert check.is_defect


def test_the_cost_basis_the_run_recorded_is_the_one_audited():
    """The audit must describe the run, not whatever the price table says today."""
    report = _report(model="gateway:Qwen3.6-35B-A3B-NVFP4", cost=None)
    report["provenance"]["model_pricing"] = "unknown_model"
    (check,) = find_inert_checks(report, POLICY)
    assert check.reason is InertReason.COST_UNPRICED_MODEL


def test_zero_cost_under_a_priced_model_is_reported_as_a_defect():
    """The environment excuse does not apply, so the zero is unexplained and suspect."""
    report = _report(model="anthropic:claude-sonnet-5", cost=0.0)
    (check,) = find_inert_checks(report, POLICY, pricing=_priced)
    assert check.reason is InertReason.COST_ZERO_UNEXPLAINED
    assert check.is_defect


# --- a policy naming a metric nobody emits ----------------------------------------------

def test_a_threshold_on_a_metric_the_report_never_emits_is_an_inert_defect():
    policy = _policy(thresholds={**RAW_POLICY["thresholds"], "cache_hit_ratio": {"min": 0.30}})
    report = _report(model="anthropic:claude-sonnet-5", cost=0.12)
    (check,) = find_inert_checks(report, policy, pricing=_priced)
    assert (check.kind, check.metric, check.bound) == ("threshold", "cache_hit_ratio", "min")
    assert check.reason is InertReason.METRIC_ABSENT
    assert check.is_defect
    assert check.value is None


def test_a_hard_gate_on_a_metric_the_report_never_emits_is_an_inert_defect():
    policy = _policy(hard_gates={**RAW_POLICY["hard_gates"],
                                 "unevidenced_exploitable_verdicts": 0})
    (check,) = find_inert_checks(_report(model="m", cost=0.2), policy, pricing=_priced)
    assert check.kind == "hard_gate"
    assert check.metric == "unevidenced_exploitable_verdicts"
    assert check.reason is InertReason.METRIC_ABSENT
    assert check.is_defect


@pytest.mark.parametrize("value", [None, "0.9", True, float("nan"), float("inf")])
def test_a_non_numeric_metric_cannot_be_compared_and_is_inert(value):
    """Exactly what the gate evaluation cannot compare, non-finite numbers included."""
    report = _report(model="m", cost=0.2, metrics={"task_success_rate": value})
    reasons = {c.reason for c in find_inert_checks(report, POLICY, pricing=_priced)}
    assert reasons == {InertReason.METRIC_NOT_NUMERIC}
    assert POLICY.evaluate({**report["metrics"], **report["hard_gates"]}).status == "not_checked"


def test_a_bound_no_run_could_violate_is_reported_as_vacuous():
    policy = _policy(thresholds={"task_success_rate": {"min": 0.0},
                                 "schema_validity_rate": {"max": 1.0}})
    report = _report(model="m", cost=0.2, metrics={"schema_validity_rate": 1.0})
    checks = find_inert_checks(report, policy, pricing=_priced)
    assert {c.reason for c in checks} == {InertReason.BOUND_VACUOUS}
    assert {c.metric for c in checks} == {"task_success_rate", "schema_validity_rate"}


# --- the notice a human or CI reads ------------------------------------------------------

def test_the_notice_is_unmissable_and_says_it_is_not_a_gate():
    report = _report(model="gateway:Qwen3.6-35B-A3B-NVFP4")
    checks = find_inert_checks(report, POLICY, pricing=_unpriced)
    text = format_inert_notice(checks, subject="context", policy=POLICY)
    assert "INERT RELEASE GATES" in text
    assert "1 of 5 checks" in text, text
    assert "====" in text
    assert "information, not a gate" in text
    assert "[environment]" in text


def test_the_notice_flags_defects_separately_from_environment_facts():
    policy = _policy(thresholds={**RAW_POLICY["thresholds"], "made_up": {"min": 1}})
    report = _report(model="gateway:unpriced")
    text = format_inert_notice(find_inert_checks(report, policy, pricing=_unpriced),
                              subject="context", policy=policy)
    assert "[DEFECT]" in text and "[environment]" in text
    assert "1 of these is a defect" in text


def test_an_all_live_policy_still_prints_a_confirming_line():
    report = _report(model="anthropic:claude-sonnet-5", cost=0.11)
    text = format_inert_notice(find_inert_checks(report, POLICY, pricing=_priced),
                              subject="context", policy=POLICY)
    assert text == "inert-gate audit: all 5 policy checks for context were live for this run."


# --- the real pricing probe, and the real policies --------------------------------------

# One model per price source the deployment can report, with the label every experiment row
# and report has recorded for it. The labels are persisted and compared, so they must not move.
PRICE_SOURCES = [
    ("stub:context:sonnet", "stub", "stub"),
    ("gpt-4o", "genai-prices", "priced"),
    ("gateway:claude-sonnet-5", "custom", "priced"),
    # config/models.yaml prices the self-hosted vLLM model at zero on purpose.
    ("gateway:Qwen3.6-35B-A3B-NVFP4", "custom-zero", "zero_priced"),
    ("gateway:no-such-model-anywhere", "unknown", "unknown_model"),
]


@pytest.mark.parametrize(("model", "source", "label"), PRICE_SOURCES)
def test_the_pricing_label_is_the_deployments_own_price_source(model, source, label):
    assert models.pricing_source(model) == source
    assert pricing_status(model).value == label
    assert pricing_label(label) is pricing_status(model)


@pytest.mark.parametrize(("model", "source", "label"), PRICE_SOURCES)
def test_the_pricing_label_agrees_with_what_the_estimator_charges(model, source, label):
    """A model labelled priced is charged; any other label never yields a nonzero cost."""
    class Million:
        input_tokens = output_tokens = 1_000_000
        cache_read_tokens = cache_write_tokens = None

    cost, _ = models.estimate_cost(model, Million())
    assert bool(cost) is pricing_status(model).can_move
    assert (cost is None) is (pricing_status(model) is PricingStatus.UNKNOWN_MODEL)


@pytest.mark.parametrize("agent", ["context", "verdict", "intake"])
def test_the_shipped_policies_audit_cleanly_against_a_priced_report(agent):
    """The shipped thresholds are all live *given* a priced model — the inertness is the
    deployment's, not the policy's. This is what makes the cost ceiling worth keeping."""
    policy = load_policy(agent)
    report = _report(model="anthropic:claude-sonnet-5", cost=0.08,
                     gates={"unevidenced_safe_verdicts": 0})
    assert find_inert_checks(report, policy, pricing=_priced) == []
