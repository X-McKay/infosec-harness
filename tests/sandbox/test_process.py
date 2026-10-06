import asyncio
import os
import sys

import pytest

from infosec_harness.sandbox.process import run_bounded


async def test_timeout_is_reported_and_output_bound_keeps_tail():
    result = await run_bounded(
        [sys.executable, "-c", "import sys; sys.stdout.write('a' * 50 + 'END')"],
        env={},
        timeout=10,
        capture_limit=10,
    )
    assert result.exit_code == 0 and result.truncated and result.stdout == "aaaaaaaEND"
    slow = await run_bounded(
        [sys.executable, "-c", "import time; time.sleep(5)"], env={}, timeout=0.2
    )
    assert slow.timed_out and slow.exit_code is None


async def test_child_receives_only_the_explicit_environment(monkeypatch):
    monkeypatch.setenv("IH_AMBIENT_SECRET", "must-not-leak")
    result = await run_bounded(
        [sys.executable, "-c", "import os; print(sorted(os.environ))"],
        env={"ONLY": "1"},
        timeout=10,
    )
    assert "IH_AMBIENT_SECRET" not in result.stdout and "ONLY" in result.stdout


async def test_cancellation_reaps_child_before_it_can_mutate(tmp_path):
    ready, late = tmp_path / "ready", tmp_path / "late"
    script = "import pathlib,os,time;pathlib.Path(os.environ['READY']).write_text(str(os.getpid()));time.sleep(1);pathlib.Path(os.environ['LATE']).write_text('bad')"
    task = asyncio.create_task(
        run_bounded(
            [sys.executable, "-c", script], env={"READY": str(ready), "LATE": str(late)}, timeout=10
        )
    )
    for _ in range(100):
        if ready.exists():
            break
        await asyncio.sleep(0.01)
    assert ready.exists()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with pytest.raises(ProcessLookupError):
        os.kill(int(ready.read_text()), 0)
    await asyncio.sleep(1.1)
    assert not late.exists()
