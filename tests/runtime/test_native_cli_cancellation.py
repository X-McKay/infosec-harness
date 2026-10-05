import asyncio
import hashlib
import os
import sys

import pytest

from infosec_harness.inference import openshell as m
from infosec_harness.inference.protocol import BrokerError
from infosec_harness.sandbox.process import run_bounded


@pytest.fixture
def cli(tmp_path):
    binary = tmp_path / "owned-cli"
    binary.write_text(
        "#!"
        + sys.executable
        + "\n"
        + """import os,sys,time,pathlib
mode=os.environ.get("IH_MODE","success")
if mode=="failure":
 print("secret-provider-body",file=sys.stderr);sys.exit(3)
if mode=="sleep":
 pathlib.Path(os.environ["IH_READY"]).write_text(str(os.getpid()))
 time.sleep(.3)
 pathlib.Path(os.environ["IH_MUTATION"]).write_text("late")
print("fixed-output")
"""
    )
    binary.chmod(0o700)
    return m.NativeCLI(
        binary,
        sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        gateway="https://127.0.0.1:18444",
        workspace="test",
        config_home=tmp_path,
        tls_directory=tmp_path,
        docker_socket="unix:///tmp/owned-test.sock",
    )


async def wait_ready(path):
    for _ in range(200):
        if path.exists():
            return
        await asyncio.sleep(0.005)
    raise AssertionError("owned fixture not started")


def sleep_env(tmp_path):
    return {
        "IH_MODE": "sleep",
        "IH_READY": str(tmp_path / "ready"),
        "IH_MUTATION": str(tmp_path / "mutation"),
    }


@pytest.mark.asyncio
async def test_success_returns_stdout_and_nonzero_redacts(cli):
    assert await cli.run(["--version"]) == "fixed-output\n"
    with pytest.raises(BrokerError) as e:
        await cli.run(["fixture"], extra_env={"IH_MODE": "failure"})
    assert e.value.code == "unavailable" and "secret-provider-body" not in str(e.value)


@pytest.mark.asyncio
async def test_checksum_guard_prevents_execution(cli, tmp_path):
    cli.binary.write_text("changed")
    with pytest.raises(BrokerError) as e:
        await cli.run(["fixture"], extra_env=sleep_env(tmp_path))
    assert e.value.code == "identity" and not (tmp_path / "ready").exists()


@pytest.mark.asyncio
async def test_timeout_maps_unavailable_only_after_owned_child_is_reaped(
    cli, tmp_path, monkeypatch
):
    real = m.asyncio.create_subprocess_exec

    async def started(*a, **kw):
        p = await real(*a, **kw)
        await wait_ready(tmp_path / "ready")
        return p

    monkeypatch.setattr(m.asyncio, "create_subprocess_exec", started)
    with pytest.raises(BrokerError) as e:
        await cli.run(["fixture"], extra_env=sleep_env(tmp_path), timeout=0.1)
    assert e.value.code == "unavailable"
    with pytest.raises(ProcessLookupError):
        os.kill(int((tmp_path / "ready").read_text()), 0)
    await asyncio.sleep(0.35)
    assert not (tmp_path / "mutation").exists()


@pytest.mark.asyncio
async def test_cancel_propagates_after_reap_no_delayed_mutation(cli, tmp_path):
    t = asyncio.create_task(cli.run(["fixture"], extra_env=sleep_env(tmp_path)))
    await wait_ready(tmp_path / "ready")
    t.cancel()
    with pytest.raises(asyncio.CancelledError):
        await t
    with pytest.raises(ProcessLookupError):
        os.kill(int((tmp_path / "ready").read_text()), 0)
    await asyncio.sleep(0.35)
    assert not (tmp_path / "mutation").exists()


@pytest.mark.asyncio
async def test_repeated_cancel_during_spawn_reaps_child(cli, tmp_path, monkeypatch):
    real = m.asyncio.create_subprocess_exec
    spawned = asyncio.Event()
    pid = None

    async def delayed(*a, **kw):
        nonlocal pid
        p = await real(*a, **kw)
        pid = p.pid
        spawned.set()
        await asyncio.sleep(0.1)
        return p

    monkeypatch.setattr(m.asyncio, "create_subprocess_exec", delayed)
    t = asyncio.create_task(cli.run(["fixture"], extra_env=sleep_env(tmp_path)))
    await spawned.wait()
    t.cancel()
    await asyncio.sleep(0.02)
    t.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(t, 2)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    await asyncio.sleep(0.35)
    assert not (tmp_path / "mutation").exists()


@pytest.mark.asyncio
async def test_repeated_cancel_during_reap_finishes_owned_cleanup(cli, tmp_path, monkeypatch):
    real = m.asyncio.create_subprocess_exec
    reaped = asyncio.Event()

    async def wrapped(*a, **kw):
        p = await real(*a, **kw)
        wait = p.wait

        async def slow():
            result = await wait()
            reaped.set()
            await asyncio.sleep(0.1)
            return result

        p.wait = slow
        return p

    monkeypatch.setattr(m.asyncio, "create_subprocess_exec", wrapped)
    t = asyncio.create_task(cli.run(["fixture"], extra_env=sleep_env(tmp_path)))
    await wait_ready(tmp_path / "ready")
    t.cancel()
    await reaped.wait()
    t.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(t, 2)
    with pytest.raises(ProcessLookupError):
        os.kill(int((tmp_path / "ready").read_text()), 0)
    assert not (tmp_path / "mutation").exists()


@pytest.mark.asyncio
async def test_preflight_nonzero_and_missing_executable_are_redacted(cli, monkeypatch):
    monkeypatch.setattr(m.shutil, "which", lambda *a, **k: "/nonexistent-owned-fixture")
    with pytest.raises(BrokerError) as e:
        await cli.preflight()
    assert e.value.code == "unavailable"


@pytest.mark.asyncio
async def test_container_inventory_preserves_empty_success_and_redacts_failure(
    cli, monkeypatch, tmp_path
):
    binary = tmp_path / "docker-fixture"
    binary.write_text("#!" + sys.executable + '\nimport sys\nprint("")\n')
    binary.chmod(0o700)
    cli.docker_binary = str(binary)
    assert await cli.containers("owned-fixture-id") == []
    binary.write_text(
        "#!"
        + sys.executable
        + '\nimport sys\nprint("secret-provider-body",file=sys.stderr);sys.exit(3)\n'
    )
    with pytest.raises(BrokerError) as e:
        await cli.containers("owned-fixture-id")
    assert e.value.code == "unavailable" and "secret-provider-body" not in str(e.value)


@pytest.mark.asyncio
async def test_preflight_nonzero_is_redacted(cli, monkeypatch):
    monkeypatch.setattr(m.shutil, "which", lambda *a, **kw: str(cli.binary))
    cli.environment["IH_MODE"] = "failure"
    with pytest.raises(BrokerError) as e:
        await cli.preflight()
    assert e.value.code == "unavailable" and "secret-provider-body" not in str(e.value)


@pytest.mark.asyncio
async def test_cancel_reaps_descendant_after_group_leader_exit(tmp_path):
    ready = tmp_path / "ready"
    marker = tmp_path / "mutation"
    child = f'import time,pathlib;time.sleep(.4);pathlib.Path({str(marker)!r}).write_text("late")'
    code = f'import subprocess,sys,pathlib;subprocess.Popen([sys.executable,"-c",{child!r}]);pathlib.Path({str(ready)!r}).write_text("started")'
    task = asyncio.create_task(run_bounded([sys.executable, "-c", code], env={}, timeout=10))
    await wait_ready(ready)
    await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 2)
    await asyncio.sleep(0.45)
    assert not marker.exists()


@pytest.mark.asyncio
async def test_binary_is_rehashed_only_when_its_file_identity_changes(cli, monkeypatch):
    hashed = []
    real = m.hashlib.sha256

    def counting(data=b""):
        hashed.append(len(data))
        return real(data)

    monkeypatch.setattr(m.hashlib, "sha256", counting)
    await cli.run(["--version"])
    await cli.run(["--version"])
    assert len(hashed) == 1
    cli.binary.write_text(cli.binary.read_text() + "\n")
    with pytest.raises(BrokerError) as e:
        await cli.run(["--version"])
    assert e.value.code == "identity" and len(hashed) == 2


@pytest.mark.asyncio
async def test_timeout_is_reported_and_output_bound_keeps_tail():
    result = await run_bounded(
        [sys.executable, "-c", "import sys; sys.stdout.write('a' * 50 + 'END')"],
        env={}, timeout=10, capture_limit=10,
    )
    assert result.exit_code == 0 and result.truncated and result.stdout == "aaaaaaaEND"
    slow = await run_bounded([sys.executable, "-c", "import time; time.sleep(5)"],
                             env={}, timeout=0.2)
    assert slow.timed_out and slow.exit_code is None


@pytest.mark.asyncio
async def test_stdin_closed_early_by_child_is_not_a_runner_failure():
    result = await run_bounded([sys.executable, "-c", "import os; os.close(0)"],
                               env={}, timeout=10, stdin=b"x" * 4_000_000)
    assert result.exit_code == 0 and not result.timed_out


@pytest.mark.asyncio
async def test_child_receives_only_the_explicit_environment(monkeypatch):
    monkeypatch.setenv("IH_AMBIENT_SECRET", "must-not-leak")
    result = await run_bounded(
        [sys.executable, "-c", "import os; print(sorted(os.environ))"], env={"ONLY": "1"},
        timeout=10,
    )
    assert "IH_AMBIENT_SECRET" not in result.stdout and "ONLY" in result.stdout
