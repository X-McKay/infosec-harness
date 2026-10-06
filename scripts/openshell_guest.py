"""Own a dedicated OpenShell Docker daemon inside the checkout-managed Linux guest.

Run through the checkout's Lima shell as root. No TCP API, NAT, forwarding, or reset.
The original daemon is never selected or stopped by this helper.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import signal
import subprocess
import time
from pathlib import Path


class RuntimeRefused(RuntimeError):
    """Ownership or shared-kernel invariants could not be established."""


def daemon_config(base: Path, identity: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{10}", identity):
        raise RuntimeRefused("invalid checkout identity")
    return {
        "hosts": [f"unix://{base}/run/docker.sock"],
        "data-root": str(base / "data"),
        "exec-root": str(base / "exec"),
        "pidfile": str(base / "run/docker.pid"),
        "containerd-namespace": f"ih-openshell-{identity}",
        "containerd-plugins-namespace": f"ih-openshell-plugins-{identity}",
        "default-runtime": "runc",
        "bridge": f"ihos{identity}",
        "containerd": str(base / "run/containerd.sock"),
        "fixed-cidr": "172.29.255.0/30",
        "iptables": False,
        "ip6tables": False,
        "ip-forward": False,
        "ip-masq": False,
        "live-restore": True,
        "firewall-backend": "iptables",
    }


def run(argv: list[str], *, timeout: int = 15) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=True)
    return result.stdout


def firewall_snapshot() -> dict[str, str]:
    # No counters or generated timestamps: ordinary traffic must not change this identity.
    result = {}
    for name in ("iptables-save", "ip6tables-save"):
        content = run([name])
        result[name] = re.sub(
            r"(?m)^(:\S+ \S+) \[\d+:\d+\]$",
            r"\1 [0:0]",
            "\n".join(line for line in content.splitlines() if not line.startswith("#")),
        )
    for name in ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"):
        result[name] = run(["sysctl", "-n", name]).strip()
    nft = run(["nft", "list", "ruleset"])
    result["nft"] = re.sub(r"counter packets \d+ bytes \d+", "counter", nft)
    for name, argv in (
        ("routes", ["ip", "-j", "route", "show", "table", "all"]),
        ("bridges", ["ip", "-j", "link", "show", "type", "bridge"]),
    ):
        result[name] = json.dumps(json.loads(run(argv)), sort_keys=True)
    return result


def owned_pid(base: Path, *, proc_root: Path = Path("/proc")) -> int | None:
    path = base / "run/docker.pid"
    if not path.exists():
        return None
    try:
        pid = int(path.read_text().strip())
        if pid <= 1:
            raise ValueError
        command = (proc_root / str(pid) / "cmdline").read_bytes().split(b"\0")
    except FileNotFoundError:
        return None
    except (ValueError, OSError) as exc:
        raise RuntimeRefused("cannot establish daemon ownership") from exc
    expected = [b"/usr/local/bin/dockerd", b"--config-file", os.fsencode(base / "daemon.json")]
    if command != expected + [b""] or (proc_root / str(pid) / "exe").resolve() != Path(
        "/usr/local/bin/dockerd"
    ):
        raise RuntimeRefused("PID file names an unrelated process; refusing to signal it")
    return pid


def provision_bridge(identity: str) -> None:
    """Precreate a user-managed bridge; bridge=none deletes the shared docker0."""
    name = f"ihos{identity}"
    subnet = ipaddress.ip_network("172.29.255.0/30")
    interfaces = json.loads(run(["ip", "-j", "address", "show"]))
    existing = next((item for item in interfaces if item["ifname"] == name), None)
    routes = json.loads(run(["ip", "-j", "-4", "route", "show", "table", "all"]))
    for route in routes:
        destination = route.get("dst", "default")
        if destination == "default" or route.get("dev") == name:
            continue
        if ipaddress.ip_network(destination, strict=False).overlaps(subnet):
            raise RuntimeRefused("owned bridge subnet overlaps an existing route")
    if existing is not None:
        bridges = json.loads(run(["ip", "-j", "link", "show", "type", "bridge"]))
        addresses = [
            (a["local"], a["prefixlen"])
            for a in existing.get("addr_info", [])
            if a["family"] == "inet"
        ]
        if name not in {item["ifname"] for item in bridges} or addresses != [("172.29.255.1", 30)]:
            raise RuntimeRefused("owned bridge has unexpected type or address")
        run(["sysctl", "-w", f"net.ipv6.conf.{name}.accept_ra=0"])
        run(["sysctl", "-w", f"net.ipv6.conf.{name}.disable_ipv6=1"])
        run(["ip", "link", "set", name, "up"])
        return
    run(["ip", "link", "add", "name", name, "type", "bridge"])
    run(["ip", "address", "add", "172.29.255.1/30", "dev", name])
    run(["sysctl", "-w", f"net.ipv6.conf.{name}.accept_ra=0"])
    run(["sysctl", "-w", f"net.ipv6.conf.{name}.disable_ipv6=1"])
    run(["ip", "link", "set", name, "up"])


def containerd_argv(base: Path) -> list[str]:
    return ["/usr/local/bin/containerd", "--config", str(base / "containerd.toml")]


def owned_containerd_pid(base: Path) -> int | None:
    path = base / "run/containerd.pid"
    if not path.exists():
        return None
    try:
        pid = int(path.read_text())
        if pid <= 1:
            raise ValueError
        process = Path("/proc") / str(pid)
        actual = (process / "cmdline").read_bytes().split(b"\0")
    except FileNotFoundError:
        return None
    except (ValueError, OSError) as exc:
        raise RuntimeRefused("cannot establish private containerd ownership") from exc
    if actual != [os.fsencode(part) for part in containerd_argv(base)] + [b""] or (
        process / "exe"
    ).resolve() != Path("/usr/local/bin/containerd"):
        raise RuntimeRefused("private containerd PID names an unrelated process")
    return pid


def start_containerd(base: Path) -> subprocess.Popen:
    if owned_containerd_pid(base) is not None:
        raise RuntimeRefused("private containerd is already running; reconcile before startup")
    with (base / "containerd.log").open("ab") as log:
        child = subprocess.Popen(
            containerd_argv(base),
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
    try:
        (base / "run/containerd.pid").write_text(str(child.pid))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeRefused("private containerd exited before readiness")
            try:
                run(
                    [
                        "/usr/local/bin/ctr",
                        "--address",
                        str(base / "run/containerd.sock"),
                        "version",
                    ],
                    timeout=3,
                )
                if owned_containerd_pid(base) != child.pid:
                    raise RuntimeRefused("private containerd identity changed")
                return child
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                time.sleep(0.2)
        raise RuntimeRefused("private containerd readiness timed out")
    except BaseException:
        child.terminate()
        child.wait(timeout=15)
        raise


def signal_owned_containerd(base: Path) -> None:
    pid = owned_containerd_pid(base)
    if pid is None:
        raise RuntimeRefused("private containerd is absent; operator reconciliation required")
    pidfd = os.pidfd_open(pid)
    try:
        if owned_containerd_pid(base) != pid:
            raise RuntimeRefused("private containerd identity changed before shutdown")
        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
    finally:
        os.close(pidfd)
    deadline = time.monotonic() + 30
    while (Path("/proc") / str(pid)).exists() and time.monotonic() < deadline:
        time.sleep(0.2)
    if (Path("/proc") / str(pid)).exists():
        raise RuntimeRefused("private containerd shutdown timed out")


def provision(base: Path, identity: str) -> None:
    if base.is_symlink():
        raise RuntimeRefused("guest state directory cannot be a symlink")
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    if base.stat().st_uid != 0 or base.stat().st_mode & 0o077:
        raise RuntimeRefused("guest state must be root-owned and private")
    for name in ("run", "data", "exec"):
        path = base / name
        if path.is_symlink():
            raise RuntimeRefused("guest state subdirectory cannot be a symlink")
        path.mkdir(exist_ok=True, mode=0o700)
    runtime_config = base / "containerd.toml"
    expected_runtime = (
        "version = 3\n"
        'disabled_plugins = ["io.containerd.cri.v1.images", "io.containerd.cri.v1.runtime"]\n'
        f'root = "{base}/containerd-data"\nstate = "{base}/containerd-state"\n'
        f'[grpc]\naddress = "{base}/run/containerd.sock"\n'
    )
    if runtime_config.is_symlink():
        raise RuntimeRefused("private containerd configuration cannot be a symlink")
    if runtime_config.exists() and runtime_config.read_text() != expected_runtime:
        raise RuntimeRefused("private containerd configuration differs")
    if not runtime_config.exists():
        runtime_config.write_text(expected_runtime)
        runtime_config.chmod(0o600)
    config_path = base / "daemon.json"
    expected = daemon_config(base, identity)
    if config_path.is_symlink():
        raise RuntimeRefused("daemon config cannot be a symlink")
    if config_path.exists():
        if json.loads(config_path.read_text()) != expected:
            raise RuntimeRefused("existing daemon configuration differs; refusing to overwrite")
    else:
        config_path.write_text(json.dumps(expected, sort_keys=True, indent=2) + "\n")
        config_path.chmod(0o600)


def start(base: Path, identity: str) -> None:
    provision(base, identity)
    if owned_pid(base) is not None:
        raise RuntimeRefused("owned daemon is already running; use status")
    if owned_containerd_pid(base) is not None:
        raise RuntimeRefused("private containerd is already running; reconcile before startup")
    provision_bridge(identity)
    snapshot = firewall_snapshot()
    # Persist the recovery baseline before creating the daemon process.
    baseline_path = base / "firewall-before.json"
    temporary = base / "firewall-before.json.part"
    with temporary.open("w") as output:
        json.dump(snapshot, output, sort_keys=True)
        output.flush()
        os.fsync(output.fileno())
    temporary.chmod(0o600)
    os.replace(temporary, baseline_path)
    runtime_child = start_containerd(base)
    try:
        with (base / "daemon.log").open("ab") as log:
            child = subprocess.Popen(
                ["/usr/local/bin/dockerd", "--config-file", str(base / "daemon.json")],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
                start_new_session=True,
                env={**os.environ, "PATH": "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
            )
    except BaseException:
        runtime_child.terminate()
        runtime_child.wait(timeout=15)
        raise
    try:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeRefused("dedicated daemon exited before readiness; inspect its log")
            try:
                info = json.loads(
                    run(
                        [
                            "/usr/local/bin/docker",
                            "--host",
                            f"unix://{base}/run/docker.sock",
                            "info",
                            "--format",
                            "{{json .}}",
                        ],
                        timeout=3,
                    )
                )
                if info["DefaultRuntime"] != "runc" or info["DockerRootDir"] != str(base / "data"):
                    raise RuntimeRefused("daemon identity does not match its reviewed contract")
                if owned_pid(base) != child.pid:
                    raise RuntimeRefused("live daemon PID does not match the process started here")
                break
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                time.sleep(0.2)
        else:
            raise RuntimeRefused("dedicated daemon did not become ready")
        if firewall_snapshot() != snapshot:
            raise RuntimeRefused("daemon startup changed harness firewall/forwarding state")
    except BaseException:
        child.terminate()
        try:
            child.wait(timeout=15)
        except subprocess.TimeoutExpired as exc:
            # Do not kill an unknown daemon, reset data, or remove firewall rules.
            raise RuntimeRefused(
                "owned daemon shutdown timed out; operator recovery required"
            ) from exc
        runtime_child.terminate()
        runtime_child.wait(timeout=15)
        raise
    print("dedicated daemon ready; shared firewall and forwarding unchanged")


def stop(base: Path) -> None:
    pid = owned_pid(base)
    if pid is None:
        raise RuntimeRefused("no owned running daemon; no process was signalled")
    if owned_containerd_pid(base) is None:
        raise RuntimeRefused("private containerd is absent; no process was signalled")
    baseline = json.loads((base / "firewall-before.json").read_text())
    if firewall_snapshot() != baseline:
        raise RuntimeRefused("shared firewall changed since startup; operator review required")
    running = run(
        [
            "/usr/local/bin/docker",
            "--host",
            f"unix://{base}/run/docker.sock",
            "ps",
            "-q",
        ]
    ).strip()
    if running:
        raise RuntimeRefused("owned daemon has live workloads; drain/reconcile before shutdown")
    address = str(base / "run/containerd.sock")
    namespaces = run(
        ["/usr/local/bin/ctr", "--address", address, "namespaces", "list", "--quiet"]
    ).splitlines()
    for namespace in namespaces:
        if run(
            [
                "/usr/local/bin/ctr",
                "--address",
                address,
                "--namespace",
                namespace,
                "tasks",
                "list",
                "--quiet",
            ]
        ).strip():
            raise RuntimeRefused(
                "private containerd has live tasks; drain/reconcile before shutdown"
            )
    # Shutdown never touches the original daemon or removes persisted data.
    # A pidfd pins the selected process across identity validation and signalling.
    try:
        pidfd = os.pidfd_open(pid)
    except (AttributeError, OSError) as exc:
        raise RuntimeRefused("cannot pin owned daemon process identity") from exc
    try:
        if owned_pid(base) != pid:
            raise RuntimeRefused("owned daemon identity changed before shutdown")
        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
    finally:
        os.close(pidfd)
    deadline = time.monotonic() + 30
    while (Path("/proc") / str(pid)).exists() and time.monotonic() < deadline:
        time.sleep(0.2)
    if (Path("/proc") / str(pid)).exists():
        raise RuntimeRefused("owned daemon shutdown timed out")
    signal_owned_containerd(base)
    if firewall_snapshot() != baseline:
        raise RuntimeRefused("daemon shutdown changed shared firewall/forwarding state")
    print("dedicated daemon stopped; data preserved; shared firewall unchanged")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("start", "status", "stop"))
    parser.add_argument("--checkout-id", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not Path("/proc").is_dir():
        raise RuntimeRefused("requires root in the checkout-owned Linux guest")
    identity = args.checkout_id
    if not re.fullmatch(r"[0-9a-f]{10}", identity):
        raise RuntimeRefused("invalid checkout identity")
    base = Path("/var/lib/ih-openshell") / identity
    if args.command == "start":
        start(base, identity)
    elif args.command == "stop":
        stop(base)
    else:
        pid = owned_pid(base)
        print(json.dumps({"owned_daemon_running": pid is not None, "guest_state": str(base)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
