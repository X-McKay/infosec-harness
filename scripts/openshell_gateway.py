"""Roll a verified gateway binary into the checkout-owned OpenShell runtime inside the guest.

Run as root through the checkout's Lima shell. Every step is fail-closed: the binary must
match its recorded SHA-256, the configuration must pass the new binary's own preflight, the
running gateway is signalled only after its exe and command line are verified, and the old
binary and configuration stay on disk for rollback. The admission ledger is never touched.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

QUOTA_KEY = "max_mutation_admissions_per_caller"


class RolloutRefused(RuntimeError):
    """An identity, configuration or liveness check failed; nothing further was changed."""


def base_dir(identity: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{10}", identity):
        raise RolloutRefused("invalid checkout identity")
    return Path("/var/lib/ih-openshell") / identity


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def gateway_pid(base: Path) -> int | None:
    """The running gateway's PID, only when the pidfile names this base's gateway binary."""
    pidfile = base / "gateway.pid"
    if not pidfile.exists():
        return None
    pid = int(pidfile.read_text().strip())
    process = Path("/proc") / str(pid)
    if not process.exists():
        return None
    argv = process.joinpath("cmdline").read_bytes().split(b"\0")[:-1]
    exe = os.readlink(process / "exe")
    expected = str(base / "gateway-conf/gateway.toml")
    if (
        not exe.startswith(str(base / "bin/openshell-gateway"))
        or len(argv) < 3
        or argv[1:3] != [b"--config", expected.encode()]
    ):
        raise RolloutRefused("gateway.pid names a process that is not this checkout's gateway")
    return pid


def gateway_argv(base: Path, binary: Path) -> list[str]:
    return [
        str(binary),
        "--config",
        str(base / "gateway-conf/gateway.toml"),
        "--compute-driver",
        "docker",
        "--enable-mtls-auth",
        "true",
    ]


def install(base: Path, source: Path, expected: str, name: str) -> Path:
    if not re.fullmatch(r"openshell-gateway-[A-Za-z0-9._-]+", name):
        raise RolloutRefused("installed binary name must be openshell-gateway-<label>")
    actual = sha256(source)
    if actual != expected:
        raise RolloutRefused(f"binary sha256 {actual} does not match recorded {expected}")
    target = base / "bin" / name
    if target.exists():
        if sha256(target) != expected:
            raise RolloutRefused("a different binary already uses that name")
        return target
    temporary = target.with_suffix(".part")
    temporary.write_bytes(source.read_bytes())
    temporary.chmod(0o755)
    os.replace(temporary, target)
    version = subprocess.run([str(target), "--version"], capture_output=True, text=True, timeout=30)
    if version.returncode != 0 or not version.stdout.startswith("openshell-gateway "):
        target.unlink()
        raise RolloutRefused("installed binary does not report an openshell-gateway version")
    print(json.dumps({"installed": str(target), "sha256": expected, "version": version.stdout.strip()}))
    return target


def set_quota(base: Path, binary: Path, quota: int) -> None:
    """Set the per-caller admission quota in the gateway table, then preflight with ``binary``."""
    if not 1 <= quota <= 1_000_000:
        raise RolloutRefused("quota must be within 1..=1000000")
    config = base / "gateway-conf/gateway.toml"
    text = config.read_text()
    line = f"{QUOTA_KEY} = {quota}\n"
    if re.search(rf"(?m)^{QUOTA_KEY}\s*=", text):
        text = re.sub(rf"(?m)^{QUOTA_KEY}\s*=.*\n", line, text)
    else:
        header = "[openshell.gateway]\n"
        if text.count(header) != 1:
            raise RolloutRefused("gateway.toml must contain exactly one [openshell.gateway] table")
        text = text.replace(header, header + line)
    backup = config.with_name(f"gateway.toml.before-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}")
    backup.write_bytes(config.read_bytes())
    backup.chmod(0o600)
    candidate = config.with_suffix(".candidate.toml")
    candidate.write_text(text)
    candidate.chmod(0o600)
    preflight = subprocess.run(
        [str(binary), "--config", str(candidate), "--compute-driver", "docker",
         "--enable-mtls-auth", "true", "config", "preflight"],
        capture_output=True, text=True, timeout=60,
    )
    if preflight.returncode != 0:
        candidate.unlink()
        raise RolloutRefused("preflight rejected the candidate configuration:\n" + preflight.stdout + preflight.stderr)
    os.replace(candidate, config)
    print(json.dumps({"config": str(config), QUOTA_KEY: quota, "backup": str(backup)}))


def live_workloads(base: Path) -> str:
    return subprocess.run(
        ["/usr/local/bin/docker", "--host", f"unix://{base}/run/docker.sock", "ps", "-q"],
        capture_output=True, text=True, timeout=15, check=True,
    ).stdout.strip()


def healthy(health_address: str) -> bool:
    try:
        with urllib.request.urlopen(f"http://{health_address}/healthz", timeout=2) as response:
            return response.status == 200
    except OSError:
        return False


def health_address(base: Path) -> str:
    match = re.search(r'(?m)^health_bind_address\s*=\s*"([^"]+)"', (base / "gateway-conf/gateway.toml").read_text())
    if not match:
        raise RolloutRefused("gateway.toml has no health_bind_address")
    return match.group(1)


def restart(base: Path, binary: Path) -> None:
    """Stop the verified running gateway and start ``binary`` with the identical arguments."""
    if not binary.is_file() or not str(binary).startswith(str(base / "bin/openshell-gateway")):
        raise RolloutRefused("binary must live under the checkout's bin directory")
    if live_workloads(base):
        raise RolloutRefused("dedicated daemon has live workloads; drain before replacing the gateway")
    pid = gateway_pid(base)
    if pid is not None:
        pidfd = os.pidfd_open(pid)
        try:
            if gateway_pid(base) != pid:
                raise RolloutRefused("gateway identity changed before shutdown")
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        finally:
            os.close(pidfd)
        deadline = time.monotonic() + 30
        while (Path("/proc") / str(pid)).exists() and time.monotonic() < deadline:
            time.sleep(0.2)
        if (Path("/proc") / str(pid)).exists():
            raise RolloutRefused("previous gateway did not stop within 30s; nothing started")
    with (base / "gateway.log").open("ab") as log:
        child = subprocess.Popen(
            gateway_argv(base, binary), stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            start_new_session=True, cwd="/",
        )
    (base / "gateway.pid").write_text(f"{child.pid}\n")
    address = health_address(base)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RolloutRefused("new gateway exited before readiness; inspect gateway.log")
        if healthy(address):
            print(json.dumps({"started": gateway_argv(base, binary), "pid": child.pid, "health": address}))
            return
        time.sleep(0.5)
    raise RolloutRefused("new gateway did not report healthy within 60s")


def status(base: Path) -> None:
    pid = gateway_pid(base)
    exe = os.readlink(f"/proc/{pid}/exe") if pid else None
    config = (base / "gateway-conf/gateway.toml").read_text()
    quota = re.search(rf"(?m)^{QUOTA_KEY}\s*=\s*(\d+)", config)
    print(json.dumps({
        "pid": pid, "exe": exe, "exe_sha256": sha256(Path(exe)) if exe else None,
        "healthy": healthy(health_address(base)), QUOTA_KEY: int(quota.group(1)) if quota else "default",
        "binaries": sorted(p.name for p in (base / "bin").glob("openshell-gateway*")),
    }))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout-id", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    inst = commands.add_parser("install")
    inst.add_argument("--source", required=True, type=Path)
    inst.add_argument("--sha256", required=True)
    inst.add_argument("--name", required=True)
    quota = commands.add_parser("set-quota")
    quota.add_argument("--binary", required=True, type=Path)
    quota.add_argument("--quota", required=True, type=int)
    swap = commands.add_parser("restart")
    swap.add_argument("--binary", required=True, type=Path)
    commands.add_parser("status")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RolloutRefused("requires root in the checkout-owned Linux guest")
    base = base_dir(args.checkout_id)
    if args.command == "install":
        install(base, args.source, args.sha256, args.name)
    elif args.command == "set-quota":
        set_quota(base, args.binary, args.quota)
    elif args.command == "restart":
        restart(base, args.binary)
    else:
        status(base)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RolloutRefused as error:
        print(f"refused: {error}", file=sys.stderr)
        raise SystemExit(2) from None
