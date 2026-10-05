"""Build-repair scorers measure the named property without proxy drift."""

from __future__ import annotations

from copy import deepcopy

import pytest
import yaml
from pydantic import ValidationError

from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.evals.adapters import build_repair_adapter
from infosec_harness.settings import get_settings


def _no_progress_case() -> dict:
    path = get_settings().agents_dir / "build-repair" / "evals" / "dataset.yaml"
    cases = yaml.safe_load(path.read_text())["cases"]
    return next(case for case in cases if case["name"] ==
                "a-spec-that-already-failed-must-not-be-returned-again")


@pytest.mark.parametrize("attempt_index", [0, 1])
def test_no_progress_scorer_rejects_an_exact_previous_attempt(attempt_index):
    case = _no_progress_case()
    predict = build_repair_adapter(case).predict
    attempted = case["payload"]["previous_attempts"][attempt_index]

    assert predict(EnvironmentSpec.model_validate(attempted)) == "addressed"
    assert case["expected"] == "unaddressed"


def test_no_progress_scorer_accepts_distinct_spec_without_claiming_it_builds():
    case = _no_progress_case()
    predict = build_repair_adapter(case).predict
    candidate = deepcopy(case["payload"]["failed_spec"])
    candidate["system_packages"].append("libpq-dev")

    # This establishes only that the candidate does not repeat a failed spec. Whether it
    # builds belongs to an execution check, not this durability scorer.
    assert predict(EnvironmentSpec.model_validate(candidate)) == "unaddressed"


def test_no_progress_scorer_rejects_a_rationale_only_rewrite():
    case = _no_progress_case()
    predict = build_repair_adapter(case).predict
    candidate = deepcopy(case["payload"]["failed_spec"])
    candidate["rationale"] = "Different prose with the same executable configuration"

    assert predict(EnvironmentSpec.model_validate(candidate)) == "addressed"


def test_no_progress_scorer_ignores_system_package_order_only():
    case = _no_progress_case()
    attempted = deepcopy(case["payload"]["failed_spec"])
    attempted["system_packages"] = ["postgresql-client", "libpq-dev"]
    case["payload"]["previous_attempts"].append(attempted)
    predict = build_repair_adapter(case).predict
    reordered = deepcopy(attempted)
    reordered["system_packages"].reverse()

    assert predict(EnvironmentSpec.model_validate(reordered)) == "addressed"


def test_no_progress_scorer_cannot_turn_a_malformed_spec_into_progress():
    case = _no_progress_case()
    predict = build_repair_adapter(case).predict
    malformed = deepcopy(case["payload"]["failed_spec"])
    del malformed["test_command"]

    with pytest.raises(ValidationError):
        predict(malformed)
