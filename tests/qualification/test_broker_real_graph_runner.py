"""Preflight, evidence and process-ownership controls for the live production graph runner."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from broker_qualification_support import manifest, models_config, reap, sleeping_child

from infosec_harness.qualification.broker import graph
from infosec_harness.qualification.broker.graph import claim_execution, oracle_passed
from infosec_harness.qualification.broker.validators import sha256_file

# --- Oracle evidence ------------------------------------------------------------------------


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


def test_persisted_evidence_cannot_invent_workflow_preparation_status():
    assert "prepared_status" not in positive()["evidence"]
    assert not oracle_passed(positive())
    assert not oracle_passed(positive(), "failed")


def test_frozen_trial_cannot_dispatch_twice(tmp_path: Path):
    claim_execution(tmp_path)
    with pytest.raises(FileExistsError):
        claim_execution(tmp_path)
    assert (tmp_path / "execution.started").stat().st_mode & 0o077 == 0


def test_host_worker_temporary_files_stay_in_the_guest_visible_trial(tmp_path, monkeypatch):
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
    monkeypatch.setattr(graph, "ROOT", root)
    monkeypatch.setenv("TMPDIR", "/unshared/host-only")
    monkeypatch.setenv("HARNESS_BROKER_CONFIG", "inherited-catalog")
    value = {"directory": str(directory), "phase": "direct", "database_env_file": str(database),
             "models_config": str(root / "models.yaml"), "task_queue": "broker-real-graph-test",
             "temporal_address": "127.0.0.1:7365"}
    env = graph.environment(value)
    temporary = Path(env["TMPDIR"])
    assert temporary.is_dir() and temporary.is_relative_to(directory)
    assert temporary.stat().st_mode & 0o077 == 0
    assert env["HARNESS_ALLOW_INSECURE_RUNTIME"] == "false"
    assert env["HARNESS_SANDBOX_RUNTIME"] == "runsc"
    assert "HARNESS_BROKER_CONFIG" not in env
    assert env["PYTHONPATH"] == str(root / "src")


# --- Freeze and preflight -------------------------------------------------------------------


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    root = tmp_path / "checkout"
    parent = root / ".harness/openshell-spike/live-qualification"
    parent.mkdir(parents=True)
    source = root / "source"
    source.mkdir()
    (source / "app.py").write_text("fixture source")
    (source / "requirements.txt").write_text("pytest")
    pilot = parent / "pilot.json"
    pilot.write_text(manifest(tmp_path).model_dump_json())
    monkeypatch.setattr(graph, "ROOT", root)
    monkeypatch.setattr(graph, "SOURCE", source)
    return parent, pilot, source


def test_freeze_binds_one_read_only_trial_that_preflight_accepts(checkout):
    parent, pilot, _source = checkout
    frozen = graph.freeze(pilot, parent / "direct.json", "direct")
    repo = Path(frozen["repo"])
    assert frozen["pilot_sha256"] == sha256_file(pilot)
    assert frozen["broker_sha256"] is None and frozen["maximum_trials"] == 1
    assert {p.name for p in repo.iterdir()} == {"app.py", "requirements.txt", "tests"}
    assert repo.stat().st_mode & 0o222 == 0
    assert (parent / "direct.json").stat().st_mode & 0o077 == 0
    value = graph.preflight(parent / "direct.json", sha256_file(parent / "direct.json"))
    assert value["finding"]["repo_url"] == str(repo)


def test_each_pilot_freezes_one_trial_per_phase(checkout):
    parent, pilot, _source = checkout
    graph.freeze(pilot, parent / "direct.json", "direct")
    with pytest.raises(ValueError, match="already has a frozen direct graph trial"):
        graph.freeze(pilot, parent / "direct-again.json", "direct")
    native = graph.freeze(pilot, parent / "native.json", "native")
    assert native["broker_sha256"] == sha256_file(native["broker_config"])


@pytest.mark.parametrize("destination,phase,message", [
    ("trial.json", "temporal", "Graph phase must be direct or native"),
    ("pilot.json", "direct", "Graph manifest destination already exists"),
    ("../../elsewhere.json", "direct", "Graph artifacts must remain checkout-owned"),
])
def test_freeze_rejects_unowned_or_undeclared_scope(checkout, destination, phase, message):
    parent, pilot, _source = checkout
    with pytest.raises(ValueError, match=message):
        graph.freeze(pilot, parent / destination, phase)
    assert not list(parent.glob("graph-*"))


def test_freeze_verifies_the_pilot_configuration_before_creating_artifacts(checkout):
    parent, pilot, _source = checkout
    reviewed = json.loads(pilot.read_text())
    Path(reviewed["broker_models_config"]).write_text(
        yaml.safe_dump(models_config("brokered", endpoint="https://other.test/v1")))
    with pytest.raises(ValueError, match="native backend 'gateway' endpoint differs"):
        graph.freeze(pilot, parent / "native.json", "native")
    assert not list(parent.glob("graph-*")) and not (parent / "native.json").exists()


def _frozen(checkout):
    parent, pilot, source = checkout
    graph.freeze(pilot, parent / "direct.json", "direct")
    path = parent / "direct.json"
    return path, sha256_file(path), pilot, source


def test_preflight_requires_the_exact_reviewed_digest(checkout):
    path, _digest, _pilot, _source = _frozen(checkout)
    with pytest.raises(ValueError, match="exact frozen manifest SHA256"):
        graph.preflight(path, "f" * 64)


def _change_pilot(path, pilot, source):
    pilot.write_text(pilot.read_text() + "\n")


def _change_models(path, pilot, source):
    models = Path(json.loads(path.read_text())["models_config"])
    models.write_text(models.read_text() + "\n# drift\n")


def _change_source(path, pilot, source):
    (source / "app.py").write_text("changed source")


def _add_golden_probe(path, pilot, source):
    tests = Path(json.loads(path.read_text())["repo"]) / "tests"
    tests.chmod(0o755)
    (tests / "test_probe.py").write_text("assert True")


def _foreign_registry(path, pilot, source):
    registry = path.parent / f"graph-direct-{sha256_file(pilot)}.frozen"
    registry.chmod(0o600)
    registry.write_text(json.dumps({"manifest": str(path.parent / "other.json"), "sha256": "0" * 64}))


@pytest.mark.parametrize("change,message", [
    (_change_pilot, "Pilot manifest changed"),
    (_change_models, "Model configuration changed"),
    (_change_source, "Checkout source fixture differs from the frozen source"),
    (_add_golden_probe, "Golden probes are forbidden"),
    (_foreign_registry, "Graph registry ownership differs"),
])
def test_preflight_rejects_each_changed_input(checkout, change, message):
    path, digest, pilot, source = _frozen(checkout)
    change(path, pilot, source)
    with pytest.raises(ValueError, match=message):
        graph.preflight(path, digest)


# --- Worker process ownership ---------------------------------------------------------------

posix_only = pytest.mark.posix


def _running(pid: int) -> bool:
    result = subprocess.run(["ps", "-p", str(pid), "-o", "stat="], capture_output=True, text=True, timeout=2)
    state = result.stdout.strip()
    return result.returncode == 0 and bool(state) and not state.startswith("Z")


def _until(predicate, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("owned harmless process did not reach its bounded terminal state")


WORKER_CODE = '''import json, os, subprocess, sys, time
from pathlib import Path
leaf = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
Path(sys.argv[1]).write_text(json.dumps({"worker": os.getpid(), "worker_group": os.getpgid(0),
    "leaf": leaf.pid, "leaf_group": os.getpgid(leaf.pid)}))
time.sleep(60)
'''
OUTER_CODE = '''import pathlib, subprocess, sys, time
import infosec_harness.qualification.broker.graph as m
m.ROOT = pathlib.Path(sys.argv[1])
real_popen = subprocess.Popen
def harmless_popen(command, **options):
    assert command == [sys.executable, "-m", "infosec_harness.workflows.worker"]
    assert options.get("start_new_session", False) is False
    return real_popen([sys.executable, "-c", sys.argv[3], sys.argv[2]], **options)
m.subprocess.Popen = harmless_popen
with (m.ROOT / "worker.log").open("ab") as log:
    worker = m._start_worker(log)
time.sleep(60)
'''


@posix_only
def test_external_watchdog_group_covers_worker_and_descendant(tmp_path):
    marker = tmp_path / "owned-pids.json"
    env = {**os.environ, "PYTHONPATH": str(Path(graph.__file__).resolve().parents[3])}
    with (tmp_path / "outer.log").open("ab") as log:
        outer = subprocess.Popen([sys.executable, "-c", OUTER_CODE, str(tmp_path), str(marker), WORKER_CODE],
                                 stdout=log, stderr=log, env=env, start_new_session=True)
    try:
        _until(marker.exists, seconds=30)
        owned = json.loads(marker.read_text())
        assert owned["worker_group"] == owned["leaf_group"] == outer.pid != os.getpgrp()
        os.killpg(outer.pid, signal.SIGKILL)
        outer.wait(timeout=5)
        _until(lambda: not _running(owned["worker"]) and not _running(owned["leaf"]))
    finally:
        if outer.poll() is None:
            os.killpg(outer.pid, signal.SIGKILL)
        outer.wait(timeout=5)


@posix_only
async def test_successful_inner_cleanup_stops_only_its_retained_pid():
    worker = sleeping_child()
    try:
        assert os.getpgid(worker.pid) == os.getpgrp()
        assert await graph._stop_worker(worker) is True
        assert worker.poll() is not None
    finally:
        reap([worker])


async def test_inner_cleanup_retains_bounded_exact_pid_escalation():
    class OwnedProcess:
        def __init__(self):
            self.calls = []

        def terminate(self):
            self.calls.append("terminate")

        def kill(self):
            self.calls.append("kill")

        def wait(self, *, timeout):
            self.calls.append(("wait", timeout))
            if len(self.calls) == 2:
                raise subprocess.TimeoutExpired("owned", timeout)
            return 0

        def poll(self):
            return 0

    worker = OwnedProcess()
    assert await graph._stop_worker(worker) is True
    assert worker.calls == ["terminate", ("wait", 10), "kill", ("wait", 10)]
