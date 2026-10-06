"""./dev: one subcommand table, a local control plane, and worktrees sharing the main state."""

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from conftest import ROOT, load_script

setup = load_script("dev_setup")
DEV = ROOT / "dev"


def dispatched_commands() -> set[str]:
    """Case labels of the final `case "$COMMAND" in` block: what ./dev actually runs."""
    block = DEV.read_text().rsplit('case "$COMMAND" in', 1)[1].split("\nesac", 1)[0]
    labels = re.findall(r"^  ([a-z|-]+)\)", block, re.MULTILINE)
    return {name for label in labels for name in label.split("|")}


def documented_commands() -> set[str]:
    usage = subprocess.run(["bash", str(DEV), "help"], capture_output=True, text=True, check=True)
    table = usage.stdout.split("Commands:\n", 1)[1].split("\n--settings", 1)[0]
    return set(re.findall(r"^  ([a-z-]+) ", table, re.MULTILINE))


def test_subcommand_table_matches_the_dispatcher_and_readme():
    documented = documented_commands()
    # `env` and `help` answer before the managed toolchain is bootstrapped.
    assert documented == dispatched_commands() | {"env"}
    assert {"start", "worker", "qualify", "eval", "replay", "export-history", "status", "logs",
            "smoke", "doctor", "env", "stop"} <= documented
    readme = (ROOT / "README.md").read_text()
    mentioned = {
        word for line in re.findall(r"\./dev\b([^\n#`]*)", readme)
        for word in re.findall(r"[a-z][a-z-]+", line)
    }
    assert documented - {"start"} <= mentioned, documented - mentioned


def test_compose_stack_squid_and_gvisor_are_gone():
    for path in ("docker-compose.yml", "docker-compose.dev.yml", "Dockerfile", ".dockerignore",
                 "ui/Dockerfile", "ui/nginx.conf", "ui/.dockerignore",
                 "deploy/squid-allowlist.conf", "scripts/dev_sandbox_check.py",
                 "scripts/control_plane_check.py"):
        assert not (ROOT / path).exists(), path
    script = DEV.read_text()
    for retired in ("compose", "runsc", "egress", "BUILDX", "POSTGRES"):
        assert retired not in script, retired
    lima = (ROOT / "deploy/dev-runtime/lima.yaml").read_text()
    assert "gvisor" not in lima.lower() and "runsc" not in lima and "compose" not in lima
    # The original VM daemon only builds trusted images, as plain runc.
    assert re.search(r'"default-runtime": "runc"', lima)
    assert lima.count("= runc") == 2  # provisioning and probe both verify it


def test_dev_env_keeps_ports_and_drops_retired_keys(tmp_path, monkeypatch):
    state = tmp_path / ".harness"
    monkeypatch.setattr(setup, "STATE", state)
    monkeypatch.setattr(setup, "ENV_PATH", state / "dev.env")
    state.mkdir()
    ports = {"HARNESS_API_PORT": "8101", "HARNESS_WEB_PORT": "8181",
             "HARNESS_TEMPORAL_PORT": "7334", "HARNESS_TEMPORAL_UI_PORT": "8334"}
    retired = {"COMPOSE_PROJECT_NAME": "harness-0123456789", "HARNESS_POSTGRES_PORT": "5533",
               "HARNESS_POSTGRES_PASSWORD": "secret", "HARNESS_BUILDX_BUILDER": "b",
               "HARNESS_BUILD_EGRESS_PROXY": "http://172.30.0.2:3128",
               "HARNESS_WEB_TARGET_PORT": "5173", "HARNESS_LOCAL_REPO_ROOTS": '["/x"]'}
    (state / "dev.env").write_text("".join(f"{k}={v}\n" for k, v in {**retired, **ports}.items()))
    monkeypatch.setattr(setup, "ports", lambda: pytest.fail("chosen ports must be kept"))
    setup.ensure_env()
    written = setup._read_env()
    assert written == {**ports, "HARNESS_WORKSPACE_DIR": str((state / "workspace").resolve())}
    assert (state / "dev.env").stat().st_mode & 0o777 == 0o600
    assert (state / "workspace").is_dir()


def test_new_checkout_gets_four_loopback_ports(tmp_path, monkeypatch):
    monkeypatch.setattr(setup, "STATE", tmp_path)
    values = setup.env_values({})
    assert set(values) == set(setup.PORT_BASES) | {"HARNESS_WORKSPACE_DIR"}
    offsets = {int(values[key]) - base for key, base in setup.PORT_BASES.items()}
    assert len(offsets) == 1  # one checkout-specific offset for the whole range


def git(*args: str, cwd: Path) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "init.defaultBranch=main", *args],
        cwd=cwd, check=True, capture_output=True,
    )


FAKE_MISE = """#!/usr/bin/env bash
case "$1" in
  bin-paths) printf '%s\\n' /opt/managed/uv /opt/managed/node/bin ;;
  exec) shift 2; exec "$@" ;;
  *) exit 3 ;;
esac
"""


@pytest.fixture
def checkouts(tmp_path):
    """A main checkout holding ./dev and a fake pinned mise, plus one linked worktree."""
    if shutil.which("git") is None:
        pytest.skip("git is unavailable")
    main = (tmp_path / "main").resolve()
    (main / ".dev-tools").mkdir(parents=True)
    shutil.copy2(DEV, main / "dev")
    digest = hashlib.sha256(FAKE_MISE.encode()).hexdigest()
    (main / ".dev-tools/versions.env").write_text(
        f"MISE_VERSION=0\nMISE_MACOS_ARM64_SHA256={digest}\nMISE_LINUX_X64_SHA256={digest}\n"
    )
    git("init", "-q", cwd=main)
    git("add", "dev", ".dev-tools", cwd=main)
    git("commit", "-q", "-m", "fixture", cwd=main)
    worktree = (tmp_path / "linked").resolve()
    git("worktree", "add", "-q", str(worktree), cwd=main)
    harness = main / ".harness"
    (harness / "bin").mkdir(parents=True)
    (harness / "bin/mise").write_text(FAKE_MISE)
    (harness / "bin/mise").chmod(0o755)
    (harness / "dev.env").write_text(
        "HARNESS_API_PORT=8101\nHARNESS_WEB_PORT=8181\n"
        "HARNESS_TEMPORAL_PORT=7334\nHARNESS_TEMPORAL_UI_PORT=8334\n"
    )
    return {"main": main, "worktree": worktree, "harness": harness}


def dev(checkout: Path, *args: str) -> subprocess.CompletedProcess[str]:
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("HARNESS_", "MISE_"))}
    return subprocess.run(["bash", str(checkout / "dev"), *args], capture_output=True,
                          text=True, timeout=60, env=environment, check=False)


def test_worktree_resolves_the_main_checkout_state(checkouts):
    assert setup.main_checkout(checkouts["worktree"]) == checkouts["main"]
    assert setup.main_checkout(checkouts["main"]) == checkouts["main"]
    plain = checkouts["main"].parent / "plain"
    plain.mkdir()
    assert setup.main_checkout(plain) == plain
    for checkout in (checkouts["main"], checkouts["worktree"]):
        printed = dev(checkout, "env")
        assert printed.returncode == 0, printed.stderr
        assert f"state: {checkouts['harness']})" in printed.stdout
        assert 'export PATH=/opt/managed/uv:/opt/managed/node/bin:"$PATH"' in printed.stdout
        assert ".harness/bin" not in printed.stdout.split("\n", 1)[1]  # never the docker shim


def test_env_needs_the_managed_tools(checkouts):
    (checkouts["harness"] / "bin/mise").unlink()
    printed = dev(checkouts["worktree"], "env")
    assert printed.returncode == 2 and str(checkouts["main"]) in printed.stderr


def test_worktree_never_starts_a_second_stack(checkouts):
    refused = dev(checkouts["worktree"], "start")
    assert refused.returncode == 2
    assert f"run ./dev there: {checkouts['main']}" in refused.stderr
    assert not (checkouts["harness"] / "run").exists()


def orphan_sleeper() -> int:
    """A process in its own process group, reparented to init so it is reaped when killed."""
    started = subprocess.run(
        [sys.executable, "-c",
         "import subprocess as s; print(s.Popen(['sleep', '300'], start_new_session=True,"
         " stdin=s.DEVNULL, stdout=s.DEVNULL, stderr=s.DEVNULL).pid)"],
        capture_output=True, text=True, check=True,
    )
    return int(started.stdout)


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def record(harness: Path, name: str, pid: int, started: str | None = None) -> Path:
    if started is None:
        started = subprocess.run(["ps", "-o", "lstart=", "-p", str(pid)], capture_output=True,
                                 text=True, check=True).stdout.rstrip("\n")
    (harness / "run").mkdir(exist_ok=True)
    path = harness / "run" / f"{name}.pid"
    path.write_text(f"{pid}\n{started}\n")
    return path


def test_status_and_stop_manage_only_recorded_process_groups(checkouts):
    harness = checkouts["harness"]
    service = orphan_sleeper()
    stranger = orphan_sleeper()
    try:
        record(harness, "temporal", service)
        record(harness, "api", stranger, started="Thu Jan  1 00:00:00 1970")  # a reused pid
        (harness / "run/temporal.log").write_text("temporal log line\n")

        status = dev(checkouts["worktree"], "status")
        assert status.returncode == 0, status.stderr
        assert re.search(rf"^temporal +running +pid {service} +127\.0\.0\.1:7334", status.stdout,
                         re.MULTILINE)
        assert re.search(r"^api +stopped$", status.stdout, re.MULTILINE)
        assert re.search(r"^ui +stopped$", status.stdout, re.MULTILINE)
        assert f"Temporal database: {harness}/temporal/temporal.db" in status.stdout
        assert "no longer the process ./dev started" in status.stderr

        logs = dev(checkouts["worktree"], "logs", "temporal")
        assert "temporal log line" in logs.stdout
        assert dev(checkouts["worktree"], "logs", "postgres").returncode == 2

        stopped = dev(checkouts["worktree"], "stop")
        assert stopped.returncode == 0, stopped.stderr
        deadline = time.monotonic() + 10
        while alive(service) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not alive(service)
        assert alive(stranger)  # never signalled: its start time does not match the record
        assert not (harness / "run/temporal.pid").exists()
        assert "preserved" in stopped.stdout
    finally:
        for pid in (service, stranger):
            if alive(pid):
                os.kill(pid, signal.SIGKILL)


STUB_TOOL = """#!/usr/bin/env bash
call="$(basename "$0") $*"
case "$call" in
  "uv run --locked harness "*) call+=" [config=${HARNESS_OPENSHELL_CONFIG-unset}]" ;;
esac
printf '%s\\n' "$call" >>"$STUB_LOG"
case "$(basename "$0") $*" in
  "temporal server start-dev"*|"uv run --locked harness api"*|"npm --prefix ui run dev"*)
    exec sleep 300 ;;
esac
"""


def recorded_pid(harness: Path, name: str) -> int:
    return int((harness / "run" / f"{name}.pid").read_text().split("\n", 1)[0])


def stubbed_dev(main: Path, tmp_path: Path):
    """./dev in ``main`` with every managed tool a logging stub; returns (run, call log)."""
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    (stubs / "tool").write_text(STUB_TOOL)
    (stubs / "tool").chmod(0o755)
    for name in ("python", "just", "temporal", "uv", "npm"):
        (stubs / name).symlink_to(stubs / "tool")
    log = tmp_path / "calls.log"
    log.touch()
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("HARNESS_", "MISE_"))}
    environment |= {"PATH": f"{stubs}:{environment['PATH']}", "STUB_LOG": str(log)}

    def run(*args: str, **extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["bash", str(main / "dev"), *args], capture_output=True,
                              text=True, timeout=60, env=environment | extra, check=False)

    return run, log


def private_config(harness: Path, name: str = "private/native-config.json") -> Path:
    path = harness / "openshell" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}")
    return path


def test_start_runs_three_loopback_processes_and_stop_keeps_the_database(checkouts, tmp_path):
    """Full start with stub tools: the real process supervision, ports and arguments."""
    main, harness = checkouts["main"], checkouts["harness"]
    run, log = stubbed_dev(main, tmp_path)

    try:
        # No private OpenShell configuration yet: the stack starts and qualification is
        # reported not_checked, rather than `harness qualify` failing on a missing file.
        started = run()
        assert started.returncode == 0, started.stderr
        assert "harness qualify" not in log.read_text()
        assert "Native OpenShell qualification: not_checked" in started.stdout
        assert "Traceback" not in started.stdout + started.stderr
        first = {name: recorded_pid(harness, name) for name in ("temporal", "api", "ui")}
        assert all(alive(pid) for pid in first.values())
        calls = log.read_text()
        db = harness / "temporal" / "temporal.db"
        assert (f"temporal server start-dev --db-filename {db} --ip 127.0.0.1 --port 7334 "
                "--ui-ip 127.0.0.1 --ui-port 8334 --ui-disable-news-fetch") in calls
        assert ("temporal operator namespace update --namespace default --retention 720h "
                "--address 127.0.0.1:7334") in calls
        assert "uv run --locked harness api --host 127.0.0.1 --port 8101" in calls
        assert "npm --prefix ui run dev -- --host 127.0.0.1 --port 8181 --strictPort" in calls
        assert ("python scripts/dev_setup.py ready --api-url http://127.0.0.1:8101 "
                "--web-url http://127.0.0.1:8181 --temporal-ui-url http://127.0.0.1:8334") in calls

        config = private_config(harness)
        again = run("start")  # Temporal keeps running; the stateless API and UI restart.
        assert again.returncode == 0, again.stderr
        assert f"uv run --locked harness qualify [config={config}]" in log.read_text()
        assert "Control plane and OpenShell checked" in again.stdout
        assert recorded_pid(harness, "temporal") == first["temporal"]
        for name in ("api", "ui"):
            assert recorded_pid(harness, name) != first[name] and not alive(first[name])

        db.write_text("history")  # stands in for the dev server's SQLite file
        stopped = run("stop")
        assert stopped.returncode == 0, stopped.stderr
        assert not list((harness / "run").glob("*.pid"))
        assert db.read_text() == "history"
        status = run("status")
        assert status.stdout.count("stopped") == 3
    finally:
        for path in (harness / "run").glob("*.pid"):
            pid = int(path.read_text().split("\n", 1)[0])
            if alive(pid):
                os.killpg(pid, signal.SIGKILL)


class Handler(BaseHTTPRequestHandler):
    health = {"status": "control_plane_ready"}

    def do_GET(self):  # noqa: N802
        body = (json.dumps(self.health) if self.path == "/api/health"
                else '<html><body><div id="root"></div></body></html>').encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def control_plane():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    Handler.health = {"status": "control_plane_ready"}


def test_readiness_passes_only_on_a_ready_control_plane(control_plane, capsys):
    assert setup.readiness(control_plane, control_plane, control_plane, interval=0.05) == 0
    assert "not_checked" in capsys.readouterr().out

    Handler.health = {"status": "starting"}
    assert setup.readiness(control_plane, control_plane, control_plane,
                           deadline_seconds=0.3, interval=0.05) == 2
    failure = capsys.readouterr().err
    assert "API and Temporal connectivity" in failure and "Temporal UI" not in failure


def test_readiness_is_bounded_and_loopback_only(capsys):
    closed = "http://127.0.0.1:9"  # discard port; nothing listens
    began = time.monotonic()
    assert setup.readiness(closed, closed, closed, deadline_seconds=0.2, interval=0.05) == 2
    assert time.monotonic() - began < 30
    assert "UI document" in capsys.readouterr().err
    with pytest.raises(ValueError, match="loopback"):
        setup.readiness("http://example.com", closed, closed, deadline_seconds=0)


@pytest.mark.parametrize("layout", ["explicit", "explicit-missing", "private", "runtime", "none"])
def test_harness_commands_resolve_the_private_openshell_configuration(checkouts, tmp_path,
                                                                      layout):
    """An explicit HARNESS_OPENSHELL_CONFIG first, then the private layout, then runtime.json."""
    run, log = stubbed_dev(checkouts["main"], tmp_path)
    harness = checkouts["harness"]
    explicit = tmp_path / "operator" / "explicit.json"
    env = {}
    if layout.startswith("explicit"):
        env["HARNESS_OPENSHELL_CONFIG"] = str(explicit)
        # Both defaults exist: an explicit setting still wins, and is never passed over.
        private_config(harness, "runtime.json")
        private_config(harness)
    if layout == "explicit":
        explicit.parent.mkdir()
        explicit.write_text("{}")
        expected = explicit
    elif layout == "private":
        private_config(harness, "runtime.json")
        expected = private_config(harness)
    elif layout == "runtime":
        expected = private_config(harness, "runtime.json")
    else:
        expected = None

    for verb in ("qualify", "eval", "replay"):
        args = ("replay", "investigate-v11-x") if verb == "replay" else (verb,)
        result = run(*args, **env)
        call = f"uv run --locked harness {' '.join(args)}"
        if expected is not None:
            assert result.returncode == 0, result.stderr
            assert f"OpenShell configuration: {expected}\n" in result.stderr
            assert f"[config={expected}]" in log.read_text().split(call, 1)[1].split("\n", 1)[0]
        elif verb == "replay":  # reads Temporal histories only; still runs
            assert result.returncode == 0, result.stderr
            assert call in log.read_text()
        else:
            assert result.returncode == 2
            if layout == "explicit-missing":
                assert f"HARNESS_OPENSHELL_CONFIG={explicit} does not exist" in result.stderr
            else:
                assert "HARNESS_OPENSHELL_CONFIG is unset" in result.stderr
            assert "Traceback" not in result.stderr and call not in log.read_text()

    # A frozen settings file names its own configuration; nothing is resolved or refused.
    frozen = run("qualify", "--settings", "frozen.json")
    assert frozen.returncode == 0, frozen.stderr
    assert "openshell_config in frozen.json" in frozen.stderr
    assert "harness --settings frozen.json qualify" in log.read_text()

    # smoke (like start and doctor) qualifies only when a configuration exists.
    smoke = run("smoke", **env)
    assert smoke.returncode == 0, smoke.stderr
    if expected is None:
        assert "Native OpenShell qualification: not_checked" in smoke.stdout
        assert "harness qualify" not in log.read_text()
    else:
        assert "not_checked" not in smoke.stdout
        assert log.read_text().count(f"harness qualify [config={expected}]") == 2
