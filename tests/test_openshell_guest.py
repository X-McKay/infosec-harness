from __future__ import annotations

import importlib.util
import json
import subprocess
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "openshell_guest_review", ROOT / "scripts" / "openshell_guest.py"
)
assert SPEC is not None and SPEC.loader is not None
guest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guest)


def test_daemon_contract_is_unix_only_and_separates_owned_state(tmp_path: Path):
    first = guest.daemon_config(tmp_path / "first", "0c3cae03c0")
    second = guest.daemon_config(tmp_path / "second", "123456789a")
    assert first["hosts"] == [f"unix://{tmp_path}/first/run/docker.sock"]
    assert first["default-runtime"] == "runc"
    assert first["bridge"] == "ihos0c3cae03c0"
    assert first["containerd"] == str(tmp_path / "first/run/containerd.sock")
    assert first["fixed-cidr"] == "172.29.255.0/30"
    assert "bip" not in first
    assert "default-address-pools" not in first
    assert all(first[key] is False for key in ("iptables", "ip6tables", "ip-forward", "ip-masq"))
    assert first["live-restore"] is True
    assert len({first[key] for key in ("data-root", "exec-root", "pidfile")}) == 3
    for key in (
        "hosts",
        "data-root",
        "exec-root",
        "pidfile",
        "containerd-namespace",
        "containerd-plugins-namespace",
    ):
        assert first[key] != second[key]
    assert first["containerd-namespace"] != first["containerd-plugins-namespace"]
    encoded = json.dumps(first)
    assert "tcp://" not in encoded
    assert "/var/run/docker.sock" not in encoded
    assert "/var/lib/docker" not in encoded
    assert "/run/containerd/containerd.sock" not in encoded


@pytest.mark.parametrize(
    "identity", ["", "../escape", "0C3CAE03C0", "012345678", "01234567890", "g123456789"]
)
def test_invalid_checkout_identity_refused(tmp_path: Path, identity: str):
    with pytest.raises(guest.RuntimeRefused, match="invalid checkout identity"):
        guest.daemon_config(tmp_path, identity)
    assert list(tmp_path.iterdir()) == []


def pid_fixture(base: Path, proc: Path, command: list[str], pid: int = 23456) -> None:
    (base / "run").mkdir(parents=True, exist_ok=True)
    (base / "run/docker.pid").write_text(str(pid))
    process = proc / str(pid)
    process.mkdir(parents=True, exist_ok=True)
    (process / "cmdline").write_bytes(b"\0".join(part.encode() for part in command) + b"\0")
    (process / "exe").symlink_to(command[0])


def test_owned_pid_matches_exact_daemon_configuration(tmp_path: Path):
    base, proc = tmp_path / "state", tmp_path / "proc"
    pid_fixture(base, proc, ["/usr/local/bin/dockerd", "--config-file", str(base / "daemon.json")])
    assert guest.owned_pid(base, proc_root=proc) == 23456


@pytest.mark.parametrize(
    "variant", ["other_executable", "other_config", "additional_flags", "spoofed_executable"]
)
def test_unrelated_or_overridden_process_cannot_be_owned(tmp_path: Path, variant: str):
    base, proc = tmp_path / "state", tmp_path / "proc"
    command = ["/usr/local/bin/dockerd", "--config-file", str(base / "daemon.json")]
    if variant == "other_executable":
        command[0] = "/usr/local/bin/unrelated"
    elif variant == "other_config":
        command[2] = "/etc/docker/daemon.json"
    elif variant == "additional_flags":
        command.extend(["--host", "unix:///var/run/docker.sock"])
    pid_fixture(base, proc, command)
    if variant == "spoofed_executable":
        executable = proc / "23456/exe"
        executable.unlink()
        executable.symlink_to("/usr/local/bin/unrelated")
    with pytest.raises(guest.RuntimeRefused):
        guest.owned_pid(base, proc_root=proc)


def test_missing_dead_and_invalid_pid_are_distinct(tmp_path: Path):
    base, proc = tmp_path / "state", tmp_path / "proc"
    assert guest.owned_pid(base, proc_root=proc) is None
    (base / "run").mkdir(parents=True)
    pidfile = base / "run/docker.pid"
    pidfile.write_text("23456")
    assert guest.owned_pid(base, proc_root=proc) is None
    for value in ("not-a-pid", "0", "1", "-2"):
        pidfile.write_text(value)
        with pytest.raises(guest.RuntimeRefused):
            guest.owned_pid(base, proc_root=proc)


def test_firewall_snapshot_ignores_comments_but_retains_policy(monkeypatch: pytest.MonkeyPatch):
    values = {
        "iptables-save": '# generated timestamp\n*filter\n:FORWARD DROP [37:900]\n-A FORWARD -m comment --comment "[1:2]" -j DROP\nCOMMIT\n',
        "ip6tables-save": "# timestamp\n*filter\n:FORWARD DROP [0:0]\nCOMMIT\n",
        "net.ipv4.ip_forward": "1\n",
        "net.ipv6.conf.all.forwarding": "0\n",
    }

    def run(argv: list[str], **_kwargs: object) -> str:
        if argv[0] == "sysctl":
            return values[argv[-1]]
        if argv[0] == "nft":
            return "table ip review { chain forward { counter packets 31 bytes 99; policy drop; } }"
        if argv[0] == "ip":
            return "[]"
        return values[argv[0]]

    monkeypatch.setattr(guest, "run", run)
    snapshot = guest.firewall_snapshot()
    assert (
        snapshot["iptables-save"]
        == '*filter\n:FORWARD DROP [0:0]\n-A FORWARD -m comment --comment "[1:2]" -j DROP\nCOMMIT'
    )
    assert snapshot["ip6tables-save"] == "*filter\n:FORWARD DROP [0:0]\nCOMMIT"
    assert snapshot["net.ipv4.ip_forward"] == "1"
    assert snapshot["net.ipv6.conf.all.forwarding"] == "0"
    assert snapshot["nft"] == "table ip review { chain forward { counter; policy drop; } }"
    assert snapshot["routes"] == "[]"
    assert snapshot["bridges"] == "[]"


class OwnedChild:
    pid = 23456

    def __init__(self):
        self.terminations = 0
        self.waits: list[int] = []

    def poll(self) -> None:
        return None

    def terminate(self) -> None:
        self.terminations += 1

    def wait(self, timeout: int) -> int:
        self.waits.append(timeout)
        return 0


def startup_fixture(monkeypatch: pytest.MonkeyPatch, base: Path) -> tuple[OwnedChild, list]:
    child = OwnedChild()
    runtime = OwnedChild()
    child.runtime = runtime
    created: list = []
    monkeypatch.setattr(guest, "provision", lambda *_args: None)
    monkeypatch.setattr(guest, "owned_containerd_pid", lambda *_args: None)
    monkeypatch.setattr(guest, "provision_bridge", lambda *_args: None)

    def start_runtime(*_args: object) -> OwnedChild:
        assert (base / "firewall-before.json").is_file()
        return runtime

    monkeypatch.setattr(guest, "start_containerd", start_runtime)
    identities = iter([None, child.pid])
    monkeypatch.setattr(guest, "owned_pid", lambda *_args, **_kwargs: next(identities, child.pid))
    monkeypatch.setattr(guest, "firewall_snapshot", lambda: {"policy": "unchanged"})
    monkeypatch.setattr(
        guest,
        "run",
        lambda *_args, **_kwargs: json.dumps(
            {"DefaultRuntime": "runc", "DockerRootDir": str(base / "data")}
        ),
    )

    def popen(argv: list[str], **kwargs: object) -> OwnedChild:
        # Independent ordering oracle: recovery state must exist before any process.
        baseline = base / "firewall-before.json"
        assert baseline.is_file()
        assert baseline.stat().st_mode & 0o777 == 0o600
        assert isinstance(json.loads(baseline.read_text()), dict)
        assert not (base / "firewall-before.json.part").exists()
        created.append((argv, kwargs))
        return child

    monkeypatch.setattr(guest.subprocess, "Popen", popen)
    monkeypatch.setattr(
        guest.os, "kill", lambda *_args: pytest.fail("startup signalled by unbound PID")
    )
    return child, created


def test_mock_start_selects_only_owned_daemon_and_records_verified_firewall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    child, created = startup_fixture(monkeypatch, tmp_path)
    guest.start(tmp_path, "0c3cae03c0")
    assert created[0][0] == [
        "/usr/local/bin/dockerd",
        "--config-file",
        str(tmp_path / "daemon.json"),
    ]
    assert created[0][1]["start_new_session"] is True
    assert json.loads((tmp_path / "firewall-before.json").read_text()) == {"policy": "unchanged"}
    assert child.terminations == 0


def test_recovery_snapshot_fsynced_and_published_before_daemon_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    child, created = startup_fixture(monkeypatch, tmp_path)
    events: list[str] = []
    original_fsync = guest.os.fsync
    original_replace = guest.os.replace
    original_popen = guest.subprocess.Popen

    def fsync(fd: int) -> None:
        original_fsync(fd)
        events.append("fsync")

    def replace(source: Path, target: Path) -> None:
        assert "fsync" in events
        original_replace(source, target)
        events.append("publish")

    def popen(*args: object, **kwargs: object) -> OwnedChild:
        assert events == ["fsync", "publish"]
        events.append("process")
        return original_popen(*args, **kwargs)

    monkeypatch.setattr(guest.os, "fsync", fsync)
    monkeypatch.setattr(guest.os, "replace", replace)
    monkeypatch.setattr(guest.subprocess, "Popen", popen)
    guest.start(tmp_path, "0c3cae03c0")
    assert events == ["fsync", "publish", "process"]
    assert len(created) == 1
    assert child.terminations == 0


def test_unpublishable_recovery_snapshot_prevents_process_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    child, created = startup_fixture(monkeypatch, tmp_path)

    def refuse_publish(*_args: object) -> None:
        raise OSError("injected recovery publication failure")

    monkeypatch.setattr(guest.os, "replace", refuse_publish)
    with pytest.raises(OSError, match="recovery publication failure"):
        guest.start(tmp_path, "0c3cae03c0")
    assert created == []
    assert child.terminations == 0


@pytest.mark.parametrize(
    "fault", ["wrong_runtime", "wrong_root", "firewall_drift", "wrong_child_identity"]
)
def test_mock_startup_refuses_faults_and_terminates_only_created_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
):
    child, created = startup_fixture(monkeypatch, tmp_path)
    if fault in {"wrong_runtime", "wrong_root"}:
        info = {
            "DefaultRuntime": "runsc" if fault == "wrong_runtime" else "runc",
            "DockerRootDir": "/var/lib/docker" if fault == "wrong_root" else str(tmp_path / "data"),
        }
        monkeypatch.setattr(guest, "run", lambda *_args, **_kwargs: json.dumps(info))
    elif fault == "firewall_drift":
        snapshots = iter([{"policy": "old"}, {"policy": "new"}])
        monkeypatch.setattr(guest, "firewall_snapshot", lambda: next(snapshots))
    else:
        identities = iter([None, 99999])
        monkeypatch.setattr(guest, "owned_pid", lambda *_args, **_kwargs: next(identities))
    with pytest.raises(guest.RuntimeRefused):
        guest.start(tmp_path, "0c3cae03c0")
    assert len(created) == 1
    assert child.terminations == 1
    assert child.waits == [15]
    assert child.runtime.terminations == 1
    assert child.runtime.waits == [15]
    expected = {"policy": "old" if fault == "firewall_drift" else "unchanged"}
    assert json.loads((tmp_path / "firewall-before.json").read_text()) == expected


def test_mock_stop_firewall_drift_refuses_without_any_signals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    (tmp_path / "firewall-before.json").write_text(json.dumps({"policy": "old"}))
    monkeypatch.setattr(guest, "owned_pid", lambda *_args: 23456)
    monkeypatch.setattr(guest, "owned_containerd_pid", lambda *_args: 23457)
    monkeypatch.setattr(guest, "firewall_snapshot", lambda: {"policy": "changed"})
    signals: list = []
    monkeypatch.setattr(guest.os, "kill", lambda *args: signals.append(args))
    with pytest.raises(guest.RuntimeRefused, match="shared firewall changed"):
        guest.stop(tmp_path)
    assert signals == []


def test_mock_stop_unowned_pid_refuses_without_any_signals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(guest, "owned_pid", lambda *_args: None)
    signals: list = []
    monkeypatch.setattr(guest.os, "kill", lambda *args: signals.append(args))
    with pytest.raises(guest.RuntimeRefused, match="no owned running daemon"):
        guest.stop(tmp_path)
    assert signals == []


def test_live_workloads_prevent_daemon_shutdown_without_any_signals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    (tmp_path / "firewall-before.json").write_text(json.dumps({"policy": "unchanged"}))
    monkeypatch.setattr(guest, "owned_pid", lambda *_args: 23456)
    monkeypatch.setattr(guest, "owned_containerd_pid", lambda *_args: 23457)
    monkeypatch.setattr(guest, "firewall_snapshot", lambda: {"policy": "unchanged"})
    calls: list[list[str]] = []

    def run(argv: list[str], **_kwargs: object) -> str:
        calls.append(argv)
        return "running-owned-container\n"

    monkeypatch.setattr(guest, "run", run)
    monkeypatch.setattr(
        guest.os, "kill", lambda *_args: pytest.fail("daemon signalled before drain")
    )
    monkeypatch.setattr(
        guest.os,
        "pidfd_open",
        lambda *_args: pytest.fail("process pinned before drain"),
        raising=False,
    )
    monkeypatch.setattr(
        guest.signal,
        "pidfd_send_signal",
        lambda *_args: pytest.fail("daemon signalled before drain"),
        raising=False,
    )
    with pytest.raises(guest.RuntimeRefused, match="live workloads"):
        guest.stop(tmp_path)
    assert calls == [
        ["/usr/local/bin/docker", "--host", f"unix://{tmp_path}/run/docker.sock", "ps", "-q"]
    ]


@pytest.mark.parametrize("fault", ["pidfd_unavailable", "identity_changed"])
def test_mock_stop_pins_identity_or_refuses_without_signalling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
):
    (tmp_path / "firewall-before.json").write_text(json.dumps({"policy": "unchanged"}))
    identities = iter([23456, 99999])
    monkeypatch.setattr(guest, "owned_pid", lambda *_args: next(identities))
    monkeypatch.setattr(guest, "owned_containerd_pid", lambda *_args: 23457)
    monkeypatch.setattr(guest, "firewall_snapshot", lambda: {"policy": "unchanged"})
    monkeypatch.setattr(guest, "run", lambda *_args, **_kwargs: "")
    closed: list[int] = []
    sent: list = []
    monkeypatch.setattr(guest.os, "kill", lambda *_args: pytest.fail("PID signal fallback used"))
    monkeypatch.setattr(guest.os, "close", lambda fd: closed.append(fd))
    monkeypatch.setattr(
        guest.signal, "pidfd_send_signal", lambda *args: sent.append(args), raising=False
    )

    def pin(pid: int) -> int:
        assert pid == 23456
        if fault == "pidfd_unavailable":
            raise OSError("injected inability to pin process")
        return 34567

    monkeypatch.setattr(guest.os, "pidfd_open", pin, raising=False)
    with pytest.raises(guest.RuntimeRefused):
        guest.stop(tmp_path)
    assert sent == []
    assert closed == ([] if fault == "pidfd_unavailable" else [34567])


def test_mock_stop_signals_only_pinned_reverified_daemon_and_preserves_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    baseline = tmp_path / "firewall-before.json"
    baseline.write_text(json.dumps({"policy": "unchanged"}))
    marker = tmp_path / "persisted-data"
    marker.write_text("keep")
    monkeypatch.setattr(guest, "owned_pid", lambda *_args: 987654321)
    monkeypatch.setattr(guest, "owned_containerd_pid", lambda *_args: 23457)
    monkeypatch.setattr(guest, "firewall_snapshot", lambda: {"policy": "unchanged"})
    monkeypatch.setattr(guest, "run", lambda *_args, **_kwargs: "")
    monkeypatch.setattr(guest.os, "kill", lambda *_args: pytest.fail("PID signal fallback used"))
    monkeypatch.setattr(guest.os, "pidfd_open", lambda pid: 34567, raising=False)
    sent: list = []
    closed: list = []
    monkeypatch.setattr(
        guest.signal, "pidfd_send_signal", lambda *args: sent.append(args), raising=False
    )
    monkeypatch.setattr(guest.os, "close", lambda fd: closed.append(fd))
    original_exists = Path.exists
    stopped_runtime: list[Path] = []
    monkeypatch.setattr(guest, "signal_owned_containerd", lambda base: stopped_runtime.append(base))
    monkeypatch.setattr(
        Path,
        "exists",
        lambda path: False if path == Path("/proc/987654321") else original_exists(path),
    )
    guest.stop(tmp_path)
    assert sent == [(34567, guest.signal.SIGTERM)]
    assert closed == [34567]
    assert marker.read_text() == "keep"
    assert baseline.exists()
    assert stopped_runtime == [tmp_path]


def test_mock_start_shutdown_timeout_requires_operator_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    child, _ = startup_fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(
        guest,
        "run",
        lambda *_args, **_kwargs: json.dumps(
            {"DefaultRuntime": "runsc", "DockerRootDir": str(tmp_path / "data")}
        ),
    )

    def timeout_wait(timeout: int) -> int:
        raise subprocess.TimeoutExpired("owned-dockerd", timeout)

    monkeypatch.setattr(child, "wait", timeout_wait)
    with pytest.raises(guest.RuntimeRefused, match="operator recovery required"):
        guest.start(tmp_path, "0c3cae03c0")
    assert child.terminations == 1
    assert child.runtime.terminations == 0


def bridge_fixture(monkeypatch: pytest.MonkeyPatch, interfaces: list, bridges: list, routes: list):
    mutations: list[list[str]] = []

    def run(argv: list[str], **_kwargs: object) -> str:
        if argv == ["ip", "-j", "address", "show"]:
            return json.dumps(interfaces)
        if argv == ["ip", "-j", "link", "show", "type", "bridge"]:
            return json.dumps(bridges)
        if argv == ["ip", "-j", "-4", "route", "show", "table", "all"]:
            return json.dumps(routes)
        mutations.append(argv)
        return ""

    monkeypatch.setattr(guest, "run", run)
    return mutations


@pytest.mark.parametrize("destination", ["172.29.255.0/30", "172.29.0.0/16", "172.29.255.2/32"])
def test_bridge_overlap_refuses_before_mutation(monkeypatch: pytest.MonkeyPatch, destination: str):
    mutations = bridge_fixture(monkeypatch, [], [], [{"dst": destination, "dev": "other"}])
    with pytest.raises(guest.RuntimeRefused, match="overlaps"):
        guest.provision_bridge("0c3cae03c0")
    assert mutations == []


@pytest.mark.parametrize("fault", ["wrong_type", "wrong_address", "additional_address"])
def test_preexisting_bridge_mismatch_refuses_before_mutation(
    monkeypatch: pytest.MonkeyPatch, fault: str
):
    name = "ihos0c3cae03c0"
    addresses = [{"family": "inet", "local": "172.29.255.1", "prefixlen": 30}]
    if fault == "wrong_address":
        addresses[0]["local"] = "172.29.255.2"
    elif fault == "additional_address":
        addresses.append({"family": "inet", "local": "10.0.0.1", "prefixlen": 24})
    mutations = bridge_fixture(
        monkeypatch,
        [{"ifname": name, "addr_info": addresses}],
        [] if fault == "wrong_type" else [{"ifname": name}],
        [],
    )
    with pytest.raises(guest.RuntimeRefused, match="unexpected type or address"):
        guest.provision_bridge("0c3cae03c0")
    assert mutations == []


def test_new_bridge_mutations_are_scoped_and_do_not_touch_shared_bridge(
    monkeypatch: pytest.MonkeyPatch,
):
    mutations = bridge_fixture(monkeypatch, [], [], [{"dst": "default"}, {"dst": "172.30.0.0/16"}])
    guest.provision_bridge("0c3cae03c0")
    name = "ihos0c3cae03c0"
    assert mutations == [
        ["ip", "link", "add", "name", name, "type", "bridge"],
        ["ip", "address", "add", "172.29.255.1/30", "dev", name],
        ["sysctl", "-w", f"net.ipv6.conf.{name}.accept_ra=0"],
        ["sysctl", "-w", f"net.ipv6.conf.{name}.disable_ipv6=1"],
        ["ip", "link", "set", name, "up"],
    ]
    assert "docker0" not in json.dumps(mutations)


def test_existing_bridge_rechecks_conflicting_routes_before_any_mutation(
    monkeypatch: pytest.MonkeyPatch,
):
    name = "ihos0c3cae03c0"
    addresses = [{"family": "inet", "local": "172.29.255.1", "prefixlen": 30}]
    mutations = bridge_fixture(
        monkeypatch,
        [{"ifname": name, "addr_info": addresses}],
        [{"ifname": name}],
        [
            {"dst": "172.29.255.0/30", "dev": name},
            {"dst": "172.29.255.2/32", "dev": "other-interface"},
        ],
    )
    with pytest.raises(guest.RuntimeRefused, match="overlaps"):
        guest.provision_bridge("0c3cae03c0")
    assert mutations == []


def test_existing_bridge_own_route_is_valid_on_restart(monkeypatch: pytest.MonkeyPatch):
    name = "ihos0c3cae03c0"
    addresses = [{"family": "inet", "local": "172.29.255.1", "prefixlen": 30}]
    mutations = bridge_fixture(
        monkeypatch,
        [{"ifname": name, "addr_info": addresses}],
        [{"ifname": name}],
        [
            {"dst": "172.29.255.0/30", "dev": name},
        ],
    )
    guest.provision_bridge("0c3cae03c0")
    assert mutations == [
        ["sysctl", "-w", f"net.ipv6.conf.{name}.accept_ra=0"],
        ["sysctl", "-w", f"net.ipv6.conf.{name}.disable_ipv6=1"],
        ["ip", "link", "set", name, "up"],
    ]


@pytest.mark.parametrize("existing", [False, True])
def test_ipv6_dad_disabled_only_on_owned_bridge_before_up(
    monkeypatch: pytest.MonkeyPatch, existing: bool
):
    name = "ihos0c3cae03c0"
    addresses = [{"family": "inet", "local": "172.29.255.1", "prefixlen": 30}]
    mutations = bridge_fixture(
        monkeypatch,
        [{"ifname": name, "addr_info": addresses}] if existing else [],
        [{"ifname": name}] if existing else [],
        [{"dst": "172.29.255.0/30", "dev": name}] if existing else [],
    )
    guest.provision_bridge("0c3cae03c0")
    disable = ["sysctl", "-w", f"net.ipv6.conf.{name}.disable_ipv6=1"]
    up = ["ip", "link", "set", name, "up"]
    assert mutations.index(disable) < mutations.index(up)
    for command in mutations:
        if command[0] == "sysctl":
            assert command[2].startswith(f"net.ipv6.conf.{name}.")
            assert ".all." not in command[2]
            assert ".default." not in command[2]
            assert ".docker0." not in command[2]


def test_private_tasks_outside_docker_prevent_all_shutdown_signals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    (tmp_path / "firewall-before.json").write_text(json.dumps({"policy": "unchanged"}))
    monkeypatch.setattr(guest, "owned_pid", lambda *_args: 23456)
    monkeypatch.setattr(guest, "owned_containerd_pid", lambda *_args: 23457)
    monkeypatch.setattr(guest, "firewall_snapshot", lambda: {"policy": "unchanged"})
    calls: list = []
    address = str(tmp_path / "run/containerd.sock")

    def run(argv: list[str], **_kwargs: object) -> str:
        calls.append(argv)
        if argv[0] == "/usr/local/bin/docker":
            return ""
        if argv[-3:] == ["namespaces", "list", "--quiet"]:
            return "ih-openshell-0c3cae03c0\nunexpected-namespace\n"
        return "hidden-live-task\n" if "unexpected-namespace" in argv else ""

    monkeypatch.setattr(guest, "run", run)
    monkeypatch.setattr(
        guest.os, "pidfd_open", lambda *_args: pytest.fail("task drain not verified"), raising=False
    )
    monkeypatch.setattr(guest.os, "kill", lambda *_args: pytest.fail("unbound signal"))
    monkeypatch.setattr(
        guest.signal,
        "pidfd_send_signal",
        lambda *_args: pytest.fail("live task signalled"),
        raising=False,
    )
    monkeypatch.setattr(
        guest, "signal_owned_containerd", lambda *_args: pytest.fail("runtime stopped before drain")
    )
    with pytest.raises(guest.RuntimeRefused, match="private containerd has live tasks"):
        guest.stop(tmp_path)
    assert calls[-1] == [
        "/usr/local/bin/ctr",
        "--address",
        address,
        "--namespace",
        "unexpected-namespace",
        "tasks",
        "list",
        "--quiet",
    ]
    assert all("/run/containerd/containerd.sock" not in command for command in calls)


def private_proc_fixture(
    monkeypatch: pytest.MonkeyPatch, base: Path, proc: Path, command: list[str]
):
    (base / "run").mkdir(parents=True)
    (base / "run/containerd.pid").write_text("23456")
    process = proc / "23456"
    process.mkdir(parents=True)
    (process / "cmdline").write_bytes(b"\0".join(part.encode() for part in command) + b"\0")
    (process / "exe").symlink_to(command[0])
    monkeypatch.setattr(guest, "Path", lambda value: proc if str(value) == "/proc" else Path(value))
    return process


@pytest.mark.parametrize("fault", [None, "other_config", "additional_flags", "spoofed_executable"])
def test_containerd_ownership_rejects_system_or_overridden_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str | None
):
    base = tmp_path / "state"
    command = guest.containerd_argv(base)
    if fault == "other_config":
        command[2] = "/etc/containerd/config.toml"
    elif fault == "additional_flags":
        command.extend(["--address", "/run/containerd/containerd.sock"])
    process = private_proc_fixture(monkeypatch, base, tmp_path / "proc", command)
    if fault == "spoofed_executable":
        (process / "exe").unlink()
        (process / "exe").symlink_to("/usr/local/bin/unrelated")
    if fault is None:
        assert guest.owned_containerd_pid(base) == 23456
    else:
        with pytest.raises(guest.RuntimeRefused, match="unrelated process"):
            guest.owned_containerd_pid(base)


def test_private_containerd_config_has_independent_paths_and_no_system_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    tmp_path.chmod(0o700)
    original_stat = Path.stat

    def root_owned(path: Path, **kwargs: object):
        stat = original_stat(path, **kwargs)
        if path == tmp_path:
            values = list(stat)
            values[4] = 0
            return guest.os.stat_result(values)
        return stat

    monkeypatch.setattr(Path, "stat", root_owned)
    guest.provision(tmp_path, "0c3cae03c0")
    config_file = tmp_path / "containerd.toml"
    config = tomllib.loads(config_file.read_text())
    assert config["version"] == 3
    assert config["disabled_plugins"] == [
        "io.containerd.cri.v1.images",
        "io.containerd.cri.v1.runtime",
    ]
    assert config["root"] == str(tmp_path / "containerd-data")
    assert config["state"] == str(tmp_path / "containerd-state")
    assert config["grpc"]["address"] == str(tmp_path / "run/containerd.sock")
    assert (
        len({config["root"], config["state"], str(tmp_path / "data"), str(tmp_path / "exec")}) == 4
    )
    assert "/run/containerd/containerd.sock" not in config_file.read_text()
    assert config_file.stat().st_mode & 0o777 == 0o600
    config_file.write_text('version = 3\nroot = "/var/lib/containerd"\n')
    with pytest.raises(guest.RuntimeRefused, match="configuration differs"):
        guest.provision(tmp_path, "0c3cae03c0")
    assert config_file.read_text() == 'version = 3\nroot = "/var/lib/containerd"\n'


def containerd_start_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / "run").mkdir()
    child = OwnedChild()
    identities = iter([None, child.pid])
    monkeypatch.setattr(guest, "owned_containerd_pid", lambda *_args: next(identities))
    monkeypatch.setattr(guest.subprocess, "Popen", lambda *_args, **_kwargs: child)
    calls: list = []
    monkeypatch.setattr(
        guest, "run", lambda argv, **kwargs: calls.append((argv, kwargs)) or "ready"
    )
    return child, calls


def test_containerd_readiness_uses_only_private_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    child, calls = containerd_start_fixture(tmp_path, monkeypatch)
    assert guest.start_containerd(tmp_path) is child
    assert calls == [
        (
            ["/usr/local/bin/ctr", "--address", str(tmp_path / "run/containerd.sock"), "version"],
            {"timeout": 3},
        )
    ]
    assert child.terminations == 0


def test_containerd_identity_fault_cleans_only_returned_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    child, _ = containerd_start_fixture(tmp_path, monkeypatch)
    identities = iter([None, 99999])
    monkeypatch.setattr(guest, "owned_containerd_pid", lambda *_args: next(identities))
    with pytest.raises(guest.RuntimeRefused, match="identity changed"):
        guest.start_containerd(tmp_path)
    assert child.terminations == 1
    assert child.waits == [15]


def test_containerd_pid_publication_failure_cleans_returned_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    child, _ = containerd_start_fixture(tmp_path, monkeypatch)
    original_write = Path.write_text

    def write(path: Path, *args: object, **kwargs: object):
        if path == tmp_path / "run/containerd.pid":
            raise OSError("pidfile publication failed")
        return original_write(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", write)
    with pytest.raises(OSError, match="pidfile publication failed"):
        guest.start_containerd(tmp_path)
    assert child.terminations == 1
    assert child.waits == [15]


def test_dockerd_creation_failure_cleans_private_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    child, _ = startup_fixture(monkeypatch, tmp_path)

    def fail(*_args: object, **_kwargs: object):
        raise OSError("daemon creation failed")

    monkeypatch.setattr(guest.subprocess, "Popen", fail)
    with pytest.raises(OSError, match="daemon creation failed"):
        guest.start(tmp_path, "0c3cae03c0")
    assert child.terminations == 0
    assert child.runtime.terminations == 1
    assert child.runtime.waits == [15]


def test_containerd_shutdown_identity_change_refuses_without_signals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    identities = iter([23456, 99999])
    monkeypatch.setattr(guest, "owned_containerd_pid", lambda *_args: next(identities))
    monkeypatch.setattr(guest.os, "pidfd_open", lambda *_args: 34567, raising=False)
    closed: list = []
    sent: list = []
    monkeypatch.setattr(guest.os, "close", lambda fd: closed.append(fd))
    monkeypatch.setattr(
        guest.signal, "pidfd_send_signal", lambda *args: sent.append(args), raising=False
    )
    with pytest.raises(guest.RuntimeRefused, match="identity changed"):
        guest.signal_owned_containerd(tmp_path)
    assert sent == []
    assert closed == [34567]


def test_running_private_containerd_prevents_duplicate_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(guest, "owned_containerd_pid", lambda *_args: 23456)
    monkeypatch.setattr(
        guest.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("duplicate process created"),
    )
    with pytest.raises(guest.RuntimeRefused, match="already running"):
        guest.start_containerd(tmp_path)


def test_missing_private_containerd_refuses_shutdown_without_any_signals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(guest, "owned_containerd_pid", lambda *_args: None)
    monkeypatch.setattr(
        guest.os, "pidfd_open", lambda *_args: pytest.fail("missing process pinned"), raising=False
    )
    monkeypatch.setattr(
        guest.signal,
        "pidfd_send_signal",
        lambda *_args: pytest.fail("missing process signalled"),
        raising=False,
    )
    with pytest.raises(guest.RuntimeRefused, match="absent"):
        guest.signal_owned_containerd(tmp_path)


def test_partial_start_preserves_recovery_baseline_before_any_guest_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    baseline = tmp_path / "firewall-before.json"
    original = '{"original-recovery":"preserve exact bytes"}\n'
    baseline.write_text(original)
    monkeypatch.setattr(guest, "provision", lambda *_args: None)
    monkeypatch.setattr(guest, "owned_pid", lambda *_args: None)
    monkeypatch.setattr(guest, "owned_containerd_pid", lambda *_args: 23457)
    monkeypatch.setattr(
        guest,
        "provision_bridge",
        lambda *_args: pytest.fail("bridge changed during partial recovery"),
    )
    monkeypatch.setattr(
        guest,
        "firewall_snapshot",
        lambda: pytest.fail("new baseline taken during partial recovery"),
    )
    monkeypatch.setattr(
        guest, "start_containerd", lambda *_args: pytest.fail("duplicate runtime started")
    )
    monkeypatch.setattr(
        guest.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("process started during partial recovery"),
    )
    with pytest.raises(guest.RuntimeRefused, match="already running"):
        guest.start(tmp_path, "0c3cae03c0")
    assert baseline.read_text() == original
    assert not (tmp_path / "firewall-before.json.part").exists()


@pytest.mark.parametrize("fault", ["absent", "spoofed"])
def test_unverified_private_runtime_prevents_any_daemon_shutdown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
):
    monkeypatch.setattr(guest, "owned_pid", lambda *_args: 23456)

    def runtime(*_args: object):
        if fault == "spoofed":
            raise guest.RuntimeRefused("private containerd PID names an unrelated process")
        return None

    monkeypatch.setattr(guest, "owned_containerd_pid", runtime)
    monkeypatch.setattr(
        guest, "run", lambda *_args, **_kwargs: pytest.fail("queried unverified runtime")
    )
    monkeypatch.setattr(
        guest, "firewall_snapshot", lambda: pytest.fail("passed missing-runtime gate")
    )
    monkeypatch.setattr(
        guest.os,
        "pidfd_open",
        lambda *_args: pytest.fail("unverified process pinned"),
        raising=False,
    )
    monkeypatch.setattr(guest.os, "kill", lambda *_args: pytest.fail("unbound process signalled"))
    monkeypatch.setattr(
        guest.signal,
        "pidfd_send_signal",
        lambda *_args: pytest.fail("unverified process signalled"),
        raising=False,
    )
    monkeypatch.setattr(
        guest, "signal_owned_containerd", lambda *_args: pytest.fail("unverified runtime signalled")
    )
    with pytest.raises(guest.RuntimeRefused, match="absent|unrelated"):
        guest.stop(tmp_path)
