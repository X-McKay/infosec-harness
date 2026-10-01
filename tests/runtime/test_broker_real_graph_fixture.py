"""Independent preflight and evidence controls for the production live graph runner."""
from copy import deepcopy
from pathlib import Path

import pytest
from broker_real_graph_fixture import claim_execution, oracle_passed


def positive():
    return {"evidence": {"manifest": {"environment": {"status": "ready"}}, "executions": [{
        "exit_code": 0, "timed_out": False, "oracle_fired": True,
        "precondition_reached": True, "sink_returned": True}]}}


def test_complete_actual_oracle_accepts():
    assert oracle_passed(positive(), "ready")


@pytest.mark.parametrize("missing", ["oracle_fired", "precondition_reached", "sink_returned"])
def test_partial_marker_evidence_never_establishes_success(missing):
    detail = deepcopy(positive())
    detail["evidence"]["executions"][0][missing] = False
    assert not oracle_passed(detail, "ready")


@pytest.mark.parametrize("field,value", [("exit_code", 1), ("exit_code", None), ("timed_out", True)])
def test_failed_execution_cannot_be_promoted_by_printed_markers(field, value):
    detail = deepcopy(positive())
    detail["evidence"]["executions"][0][field] = value
    assert not oracle_passed(detail, "ready")


def test_unready_environment_does_not_pass_from_labels():
    detail = positive()
    detail["evidence"]["manifest"]["environment"]["status"] = "failed"
    assert not oracle_passed(detail, "ready")


def test_frozen_trial_cannot_dispatch_twice(tmp_path: Path):
    claim_execution(tmp_path)
    with pytest.raises(FileExistsError):
        claim_execution(tmp_path)
    assert (tmp_path / "execution.started").stat().st_mode & 0o077 == 0


def test_persisted_evidence_cannot_invent_workflow_preparation_status():
    assert "prepared_status" not in positive()["evidence"]
    assert not oracle_passed(positive())
    assert not oracle_passed(positive(), "failed")
