"""Committed experiment inputs stay runnable against the committed specs and datasets."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from infosec_harness.evals.calibration import _validate_groups, load_calibration
from infosec_harness.evals.dataset import load_dataset
from infosec_harness.evals.gates import load_policy
from infosec_harness.evals.overlays import StaleOverlay, load_overlay
from infosec_harness.settings import REPO_ROOT

EXPERIMENTS = REPO_ROOT / "evals" / "experiments"
CALIBRATIONS = sorted((EXPERIMENTS / "calibration").glob("*.yaml"))
OVERLAYS = sorted((EXPERIMENTS / "overlays").glob("*.yaml"))


@pytest.mark.parametrize("path", CALIBRATIONS, ids=lambda p: p.name)
def test_every_calibration_plan_validates_against_its_subjects_dataset_and_policy(path):
    spec = load_calibration(path)
    calibration_n, held_out_n = _validate_groups(
        spec, load_dataset(spec.subject).cases, load_policy(spec.subject))
    assert calibration_n and held_out_n


@pytest.mark.parametrize("path", OVERLAYS, ids=lambda p: p.name)
def test_every_overlay_is_a_spec_fragment_pinned_to_the_current_spec(path):
    """A calibration plan filed under overlays/ would be read as an agent named `version`."""
    overlay = load_overlay(path)
    assert overlay and all(isinstance(fragment, dict) for fragment in overlay.values())


def _overlay(tmp_path: Path, fragment: dict) -> Path:
    path = tmp_path / "overlay.yaml"
    path.write_text(yaml.safe_dump({"probe-planner": fragment}))
    return path


def test_an_overlay_written_against_another_spec_version_is_refused(tmp_path):
    with pytest.raises(StaleOverlay, match="written against spec version 0.9.0"):
        load_overlay(_overlay(tmp_path, {"base_version": "0.9.0", "model": "haiku"}))


def test_an_overlay_without_a_base_version_is_refused(tmp_path):
    with pytest.raises(StaleOverlay, match="declares no base_version"):
        load_overlay(_overlay(tmp_path, {"model": "haiku"}))


def test_a_current_overlay_loads_without_its_pin(tmp_path):
    from infosec_harness.agents.registry import load_spec

    current = load_spec("probe-planner").metadata["version"]
    loaded = load_overlay(_overlay(tmp_path, {"base_version": current, "model": "haiku"}))
    assert loaded == {"probe-planner": {"model": "haiku"}}


async def test_the_runner_refuses_a_stale_overlay_before_any_call(tmp_path):
    from infosec_harness.evals.run import run_experiment

    with pytest.raises(StaleOverlay):
        await run_experiment("probe-planner",
                             overlay=_overlay(tmp_path, {"base_version": "0.0.1"}))
