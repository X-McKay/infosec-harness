"""Harmless real processes exercise graph watchdog ownership; no graph is executed."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from contextlib import suppress

import broker_real_graph_fixture as fixture
import pytest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="native watchdog uses POSIX process groups")


def _running(pid: int) -> bool:
    result = subprocess.run(["ps", "-p", str(pid), "-o", "stat="],
                            capture_output=True, text=True, timeout=2)
    state = result.stdout.strip()
    return result.returncode == 0 and bool(state) and not state.startswith("Z")


def _until(predicate, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("owned harmless process did not reach its bounded terminal state")


@pytest.mark.parametrize("historical_detach", [True, False])
def test_external_watchdog_covers_worker_and_descendant(tmp_path, historical_detach):
    marker = tmp_path / "owned-pids.json"
    worker_code = '''import json, os, subprocess, sys, time
from pathlib import Path
from contextlib import suppress
leaf = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
Path(sys.argv[1]).write_text(json.dumps({"worker":os.getpid(), "worker_group":os.getpgid(0), "leaf":leaf.pid, "leaf_group":os.getpgid(leaf.pid)}))
time.sleep(60)
'''
    outer_code = '''import importlib.util, pathlib, subprocess, sys, time
spec = importlib.util.spec_from_file_location("tested_graph_fixture", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.ROOT = pathlib.Path(sys.argv[2])
real_popen = subprocess.Popen
worker_code = sys.argv[4]
def harmless_popen(command, **options):
    assert command == [sys.executable, "-m", "infosec_harness.workflows.worker"]
    assert options.get("start_new_session", False) is False
    if sys.argv[5] == "historical": options["start_new_session"] = True
    return real_popen([sys.executable, "-c", worker_code, sys.argv[3]], **options)
m.subprocess.Popen = harmless_popen
with (m.ROOT / "worker.log").open("ab") as log: worker=m._start_worker(log)
time.sleep(60)
'''
    mode = "historical" if historical_detach else "current"
    with (tmp_path / "outer.log").open("ab") as log:
        outer = subprocess.Popen([sys.executable, "-c", outer_code,
            fixture.__file__, str(tmp_path), str(marker), worker_code, mode],
            stdout=log, stderr=log, start_new_session=True)
    owned = None
    try:
        _until(marker.exists)
        owned = json.loads(marker.read_text())
        expected_group = owned["worker"] if historical_detach else outer.pid
        assert owned["worker_group"] == owned["leaf_group"] == expected_group
        assert expected_group != os.getpgrp()
        os.killpg(outer.pid, signal.SIGKILL)
        outer.wait(timeout=5)
        if historical_detach:
            assert _running(owned["worker"]) and _running(owned["leaf"])
        else:
            _until(lambda: not _running(owned["worker"]) and not _running(owned["leaf"]))
    finally:
        if outer.poll() is None:
            os.killpg(outer.pid, signal.SIGKILL)
        outer.wait(timeout=5)
        if owned is not None and historical_detach:
            with suppress(ProcessLookupError):
                os.killpg(owned["worker_group"], signal.SIGKILL)
            _until(lambda: not _running(owned["worker"]) and not _running(owned["leaf"]))


@pytest.mark.asyncio
async def test_successful_inner_cleanup_stops_only_its_retained_pid():
    worker = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        assert os.getpgid(worker.pid) == os.getpgrp()
        assert await fixture._stop_worker(worker) is True
        assert worker.poll() is not None
    finally:
        if worker.poll() is None:
            worker.kill()
        worker.wait(timeout=5)


@pytest.mark.asyncio
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
    assert await fixture._stop_worker(worker) is True
    assert worker.calls == ["terminate", ("wait", 10), "kill", ("wait", 10)]
