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


def test_host_worker_temporary_files_stay_in_the_guest_visible_trial(tmp_path, monkeypatch):
    import broker_real_graph_fixture as fixture

    root = tmp_path / "checkout"
    (root / ".harness").mkdir(parents=True)
    managed = root / ".harness/dev.env"
    managed.write_text("HARNESS_SANDBOX_RUNTIME=runsc\n")
    managed.chmod(0o600)
    database = tmp_path / "database.env"
    database.write_text("HARNESS_DATABASE_URL=sqlite+aiosqlite:///owned-test.db\n")
    database.chmod(0o600)
    directory = root / ".harness/trial"
    directory.mkdir()
    monkeypatch.setattr(fixture, "ROOT", root)
    monkeypatch.setenv("TMPDIR", "/unshared/host-only")
    value = {"directory": str(directory), "phase": "direct", "database_env_file": str(database),
             "models_config": str(root / "models.yaml"), "task_queue": "broker-real-graph-test",
             "temporal_address": "127.0.0.1:7365"}
    env = fixture.environment(value)
    temporary = Path(env["TMPDIR"])
    assert temporary.is_dir()
    assert temporary.is_relative_to(directory)
    assert temporary.stat().st_mode & 0o077 == 0
    assert env["HARNESS_ALLOW_INSECURE_RUNTIME"] == "false"
    assert env["HARNESS_SANDBOX_RUNTIME"] == "runsc"


@pytest.mark.parametrize("status", ["running", "passed", "failed"])
def test_corrected_trial_requires_failed_terminal_replayed_and_cleaned_previous(tmp_path, monkeypatch, status):
    import json

    import broker_real_graph_fixture as fixture

    root = tmp_path / "checkout"
    parent = root / ".harness/openshell-spike/live-qualification"
    parent.mkdir(parents=True)
    directory = parent / "prior"
    directory.mkdir()
    previous = parent / "previous.json"
    previous.write_text(json.dumps({"directory": str(directory)}))
    (directory / "report.json").write_text(json.dumps({"graph": status,
        "replay": "passed", "workflow_cleanup": "passed", "worker_cleanup": "failed"}))
    (parent / "graph-direct-manifest.frozen").write_text(json.dumps({
        "manifest": str(previous), "sha256": fixture.sha(previous)}))
    monkeypatch.setattr(fixture, "ROOT", root)
    with pytest.raises(ValueError, match="terminal, replayed, and cleaned"):
        fixture.freeze(parent / "pilot.json", parent / "retry.json", "direct",
            infrastructure_correction="guest-visible-tmpdir")
    assert not (parent / "retry.json").exists()


@pytest.fixture
def frozen_graph(tmp_path, monkeypatch):
    import json

    import broker_real_graph_fixture as fixture

    root = tmp_path / "checkout"
    parent = root / ".harness/openshell-spike/live-qualification"
    parent.mkdir(parents=True)
    source = root / "source"
    source.mkdir()
    (source / "app.py").write_text("fixture source")
    (source / "requirements.txt").write_text("pytest")
    models = root / "models.json"
    models.write_text('{"temperature":0}')
    pilot = parent / "pilot.json"
    pilot.write_text(json.dumps({"direct_models_config": str(models), "broker_models_config": str(models),
        "broker_config": str(root / "broker.json"), "database_env_file": str(root / "db.env"),
        "worker_hmac_file": str(root / "key"), "worker_hmac_env": "TEST_KEY",
        "temporal_address": "127.0.0.1:7365"}))
    monkeypatch.setattr(fixture, "ROOT", root)
    monkeypatch.setattr(fixture, "SOURCE", source)
    previous = fixture.freeze(pilot, parent / "previous.json", "direct")
    report = Path(previous["directory"]) / "report.json"
    report.write_text(json.dumps({"graph": "failed", "replay": "passed", "workflow_cleanup": "passed",
                                 "worker_cleanup": "passed"}))
    return fixture, parent, pilot, previous, report, models, source


def test_unchanged_infrastructure_correction_retains_prior_trial(frozen_graph):
    fixture, parent, pilot, previous, report, _models, _source = frozen_graph
    result = fixture.freeze(pilot, parent / "corrected.json", "direct",
                           infrastructure_correction="guest-visible-tmpdir")
    assert result["pilot_sha256"] == previous["pilot_sha256"]
    assert result["models_sha256"] == previous["models_sha256"]
    assert result["directory"] != previous["directory"]
    assert result["supersedes_infrastructure_failure"]["sha256"] == fixture.sha(parent / "previous.json")
    assert report.exists()
    with pytest.raises(ValueError, match="already has a frozen trial"):
        fixture.freeze(pilot, parent / "third.json", "direct", infrastructure_correction="guest-visible-tmpdir")


@pytest.mark.parametrize("change", ["model_settings", "pilot", "source", "finding", "runtime_scope"])
def test_infrastructure_correction_rejects_changed_candidate_before_creating_artifacts(frozen_graph, change):
    import json

    fixture, parent, pilot, previous, _report, models, source = frozen_graph
    if change == "model_settings":
        models.write_text('{"temperature":1}')
    elif change == "pilot":
        values = json.loads(pilot.read_text())
        values["temporal_address"] = "127.0.0.1:9999"
        pilot.write_text(json.dumps(values))
    elif change == "source":
        (source / "app.py").write_text("different source")
    else:
        # Keep registry provenance internally consistent while changing the old scope;
        # correction equivalence must independently check it, not trust the digest alone.
        if change == "finding":
            previous["finding"]["severity"] = "critical"
        else:
            previous["maximum_trials"] = 2
        previous_file = parent / "previous.json"
        previous_file.write_text(json.dumps(previous))
        (parent / "graph-direct-manifest.frozen").write_text(json.dumps({
            "manifest": str(previous_file), "sha256": fixture.sha(previous_file)}))
    before = set(parent.iterdir())
    with pytest.raises(ValueError, match="frozen candidate or runtime scope"):
        fixture.freeze(pilot, parent / "corrected.json", "direct", infrastructure_correction="guest-visible-tmpdir")
    assert set(parent.iterdir()) == before


@pytest.mark.parametrize("field", ["replay", "workflow_cleanup", "worker_cleanup"])
def test_infrastructure_correction_requires_each_terminal_evidence_gate(frozen_graph, field):
    import json

    fixture, parent, pilot, _previous, report, _models, _source = frozen_graph
    values = json.loads(report.read_text())
    values[field] = "not_checked"
    report.write_text(json.dumps(values))
    with pytest.raises(ValueError, match="terminal, replayed, and cleaned"):
        fixture.freeze(pilot, parent / "corrected.json", "direct", infrastructure_correction="guest-visible-tmpdir")
