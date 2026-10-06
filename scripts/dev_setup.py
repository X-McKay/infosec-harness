#!/usr/bin/env python3
"""Provision the pinned, per-checkout development toolchain and Linux executor."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".harness"
ENV_PATH = STATE / "dev.env"
TOOLS_ENV = ROOT / ".dev-tools" / "versions.env"
MISE_CONFIG = ROOT / ".mise.toml"
RUNTIME_TEMPLATE = ROOT / "deploy" / "dev-runtime" / "lima.yaml"
# Per-checkout VM homes live under one short directory (macOS socket-path limits). Each home
# records the checkout that owns it in OWNER_RECORD so `./dev gc` can find orphaned ones.
RUNTIME_HOMES = Path.home() / ".cache" / "ih"
OWNER_RECORD = "checkout"


def runtime_home_for(checkout: Path) -> Path:
    return RUNTIME_HOMES / hashlib.sha256(str(checkout.resolve()).encode()).hexdigest()[:10]


LIMA_HOME = runtime_home_for(ROOT)
LIMA_INSTANCE = "h"


def pinned_versions() -> dict[str, str]:
    """Artifacts mise cannot manage (the mise binary itself, Lima) and their hashes."""
    values: dict[str, str] = {}
    for line in TOOLS_ENV.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value.strip()
    return values


def mise_tools() -> dict[str, str]:
    """Tool name -> pinned version from .mise.toml, the single source of tool versions."""
    tools = tomllib.loads(MISE_CONFIG.read_text())["tools"]
    return {
        name: value if isinstance(value, str) else value["version"]
        for name, value in tools.items()
    }


def supported_platform() -> tuple[bool, str]:
    system = platform.system()
    machine = platform.machine().lower()
    supported = (system == "Darwin" and machine in {"arm64", "aarch64"}) or (
        system == "Linux" and machine in {"x86_64", "amd64"}
    )
    return supported, f"{system}/{machine}"


def project_identity() -> str:
    digest = hashlib.sha256(str(ROOT.resolve()).encode()).hexdigest()[:10]
    return f"harness-{digest}"


def _port_is_free(port: int) -> bool:
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def ports() -> dict[str, int]:
    offset = int(hashlib.sha256(str(ROOT.resolve()).encode()).hexdigest()[:4], 16) % 300
    bases = {
        "HARNESS_POSTGRES_PORT": 5432,
        "HARNESS_API_PORT": 8000,
        "HARNESS_WEB_PORT": 8080,
        "HARNESS_TEMPORAL_PORT": 7233,
        "HARNESS_TEMPORAL_UI_PORT": 8233,
    }
    for candidate in range(offset, offset + 1200):
        selected = {key: base + candidate for key, base in bases.items()}
        if all(_port_is_free(port) for port in selected.values()):
            return selected
    raise RuntimeError("could not find a free checkout-specific port range")


def _read_env() -> dict[str, str]:
    current: dict[str, str] = {}
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                parsed = shlex.split(value, comments=False, posix=True)
                current[key] = parsed[0] if parsed else ""
    return current


def ensure_env() -> Path:
    STATE.mkdir(parents=True, exist_ok=True)
    current = _read_env()
    values = {"COMPOSE_PROJECT_NAME": current.get("COMPOSE_PROJECT_NAME", project_identity())}
    port_keys = {
        "HARNESS_POSTGRES_PORT",
        "HARNESS_API_PORT",
        "HARNESS_WEB_PORT",
        "HARNESS_TEMPORAL_PORT",
        "HARNESS_TEMPORAL_UI_PORT",
    }
    selected_ports = {} if port_keys <= current.keys() else ports()
    values.update({key: current.get(key, str(value)) for key, value in selected_ports.items()})
    for key in sorted(port_keys):
        if key not in values:
            values[key] = current[key]
    # runsc is used only by the trusted image builder, never as an agent fallback.
    # gVisor's userspace network stack cannot reach Docker's 127.0.0.11 embedded DNS on an
    # Internal=true bridge. Give the only dual-homed service a deterministic address instead
    # of weakening runsc or adding an external DNS path to the build network.
    values["HARNESS_BUILD_EGRESS_HOST_IP"] = "172.30.0.2"
    values["HARNESS_BUILD_EGRESS_SUBNET"] = "172.30.0.0/24"
    values["HARNESS_BUILD_EGRESS_PROXY"] = (
        f"http://{values['HARNESS_BUILD_EGRESS_HOST_IP']}:3128"
    )
    values["HARNESS_BUILD_EGRESS_NETWORK"] = current.get(
        "HARNESS_BUILD_EGRESS_NETWORK", f"{values['COMPOSE_PROJECT_NAME']}-build-egress"
    )
    values["HARNESS_BUILDX_BUILDER"] = current.get(
        "HARNESS_BUILDX_BUILDER", f"{values['COMPOSE_PROJECT_NAME']}-gvisor"
    )
    values["HARNESS_WEB_TARGET_PORT"] = "5173"
    values["HARNESS_WORKSPACE_DIR"] = str((STATE / "workspace").resolve())
    # Only the explicitly approved corpus is readable by the host-side worker.
    values["HARNESS_LOCAL_REPO_ROOTS"] = json.dumps([str((ROOT / "eval-corpus").resolve())])
    values["HARNESS_POSTGRES_PASSWORD"] = current.get(
        "HARNESS_POSTGRES_PASSWORD", secrets.token_urlsafe(24)
    )
    text = "# Generated per checkout by ./dev; contains local credentials; do not commit.\n"
    text += "\n".join(f"{key}={shlex.quote(value)}" for key, value in values.items()) + "\n"
    if not ENV_PATH.exists() or ENV_PATH.read_text() != text:
        ENV_PATH.write_text(text)
        ENV_PATH.chmod(0o600)
    (STATE / "workspace").mkdir(exist_ok=True)
    return ENV_PATH


def command_version(command: str, *args: str) -> str | None:
    path = shutil.which(command)
    if not path:
        return None
    try:
        completed = subprocess.run(
            [path, *args], capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (completed.stdout or completed.stderr).strip().splitlines()
    return output[0] if completed.returncode == 0 and output else None


def install_managed_tools() -> None:
    """Install every tool .mise.toml pins (python, uv, node, just, the Temporal CLI)."""
    mise = shutil.which("mise")
    if not mise:
        raise RuntimeError("managed mise bootstrap is missing; rerun ./dev")
    subprocess.run([mise, "install", "--yes"], cwd=ROOT, check=True)


def run_tool(command: str, args: list[str], *, cwd: Path) -> None:
    mise = shutil.which("mise")
    if not mise:
        raise RuntimeError("managed mise bootstrap is missing; rerun ./dev")
    subprocess.run([mise, "exec", "--", command, *args], cwd=cwd, check=True)


def _download(url: str, destination: Path, checksum: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(destination.suffix + ".part")
    digest = hashlib.sha256()
    print(f"download: {url}", flush=True)
    try:
        with urllib.request.urlopen(url, timeout=60) as response, partial.open("wb") as output:
            total = int(response.headers.get("Content-Length", "0"))
            received = 0
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
                digest.update(chunk)
                received += len(chunk)
                if total:
                    print(
                        f"\rdownloaded {received / (1024**2):.1f}/{total / (1024**2):.1f} MiB",
                        end="",
                        flush=True,
                    )
        print()
    except Exception:
        partial.unlink(missing_ok=True)
        raise
    actual = digest.hexdigest()
    if actual != checksum:
        partial.unlink(missing_ok=True)
        raise RuntimeError(f"checksum mismatch for {url}: expected {checksum}, got {actual}")
    partial.replace(destination)


def lima_paths() -> tuple[Path, Path]:
    version = pinned_versions()["LIMA_VERSION"]
    installation = STATE / "tools" / f"lima-{version}"
    return installation, installation / "bin" / "limactl"


def install_lima() -> Path:
    versions = pinned_versions()
    installation, limactl = lima_paths()
    if limactl.exists():
        return limactl
    system = platform.system()
    if system == "Darwin":
        artifact = f"lima-{versions['LIMA_VERSION']}-Darwin-arm64.tar.gz"
        checksum = versions["LIMA_MACOS_ARM64_SHA256"]
    else:
        artifact = f"lima-{versions['LIMA_VERSION']}-Linux-x86_64.tar.gz"
        checksum = versions["LIMA_LINUX_X64_SHA256"]
    archive = STATE / "downloads" / artifact
    if not archive.exists():
        _download(
            f"https://github.com/lima-vm/lima/releases/download/v{versions['LIMA_VERSION']}/{artifact}",
            archive,
            checksum,
        )
    elif hashlib.sha256(archive.read_bytes()).hexdigest() != checksum:
        archive.unlink()
        return install_lima()
    staging = installation.with_name(installation.name + ".partial")
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    with tarfile.open(archive, "r:gz") as bundle:
        bundle.extractall(staging, filter="data")
    staging.replace(installation)
    return limactl


def _install_linux_qemu() -> None:
    if shutil.which("qemu-system-x86_64"):
        return
    if not shutil.which("sudo"):
        raise RuntimeError(
            "Linux full profile needs QEMU. Install qemu-system-x86/qemu-utils, then rerun ./dev."
        )
    if shutil.which("apt-get"):
        print("host prerequisite: installing QEMU with sudo (no daemon or Docker config is added)")
        subprocess.run(["sudo", "apt-get", "update"], check=True)
        subprocess.run(
            ["sudo", "apt-get", "install", "-y", "qemu-system-x86", "qemu-utils"], check=True
        )
        return
    raise RuntimeError(
        "Linux full profile currently automates QEMU on Debian/Ubuntu x86-64. Install "
        "qemu-system-x86_64 with your package manager, then rerun ./dev."
    )


def _lima_env(limactl: Path, home: Path | None = None) -> dict[str, str]:
    env = dict(os.environ)
    env["LIMA_HOME"] = str(home or LIMA_HOME)
    env["PATH"] = str(limactl.parent) + os.pathsep + env.get("PATH", "")
    return env


def ensure_lima_home() -> None:
    LIMA_HOME.mkdir(parents=True, exist_ok=True)
    pointer = STATE / "runtime-home"
    if not pointer.exists() or pointer.read_text().strip() != str(LIMA_HOME):
        pointer.write_text(str(LIMA_HOME) + "\n")
    owner = LIMA_HOME / OWNER_RECORD
    if not owner.exists() or owner.read_text().strip() != str(ROOT.resolve()):
        owner.write_text(str(ROOT.resolve()) + "\n")


def _lima_status(limactl: Path, home: Path | None = None) -> str | None:
    result = subprocess.run(
        [str(limactl), "list", "--format", "{{.Status}}", LIMA_INSTANCE],
        env=_lima_env(limactl, home),
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None


def write_docker_shim(limactl: Path) -> Path:
    bindir = STATE / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    shim = bindir / "docker"
    text = "#!/bin/sh\nset -eu\n"
    text += f"export LIMA_HOME={shlex.quote(str(LIMA_HOME))}\n"
    text += f"export PATH={shlex.quote(str(limactl.parent))}:\"$PATH\"\n"
    text += (
        f"exec {shlex.quote(str(limactl))} shell --tty=false --workdir \"$PWD\" "
        f"{shlex.quote(LIMA_INSTANCE)} sudo --non-interactive docker \"$@\"\n"
    )
    if not shim.exists() or shim.read_text() != text:
        shim.write_text(text)
        shim.chmod(0o755)
    return shim


def ensure_runtime(*, check_only: bool) -> None:
    _installation, limactl = lima_paths()
    ensure_lima_home()
    if check_only:
        if not limactl.exists():
            raise RuntimeError("managed Lima is not installed; run ./dev")
        status = _lima_status(limactl)
        if status != "Running":
            raise RuntimeError(f"managed Lima instance is {status or 'absent'}; run ./dev")
        write_docker_shim(limactl)
        return
    if platform.system() == "Linux":
        _install_linux_qemu()
    limactl = install_lima()
    status = _lima_status(limactl)
    env = _lima_env(limactl)
    if status != "Running":
        if status is None:
            vm_type = "vz" if platform.system() == "Darwin" else "qemu"
            command = [
                str(limactl),
                "start",
                "--tty=false",
                "--progress",
                "--timeout=20m",
                f"--name={LIMA_INSTANCE}",
                f"--vm-type={vm_type}",
                "--mount",
                f"{ROOT}:w",
                str(RUNTIME_TEMPLATE),
            ]
        else:
            command = [
                str(limactl),
                "start",
                "--tty=false",
                "--progress",
                "--timeout=20m",
                LIMA_INSTANCE,
            ]
        subprocess.run(command, env=env, cwd=ROOT, check=True)
    write_docker_shim(limactl)


def _host_memory_gib() -> float:
    if platform.system() == "Darwin":
        result = subprocess.run(
            ["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, check=False
        )
        if result.returncode == 0:
            return int(result.stdout.strip()) / (1024**3)
    try:
        return (os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")) / (1024**3)
    except (AttributeError, OSError, ValueError):
        return 0


# (tool, version command, index of the version in its first output line). The version must
# equal the .mise.toml pin exactly; a global tool of another version on PATH does not count.
TOOL_CHECKS = {
    "python": (["python", "--version"], 1),  # "Python X.Y.Z"
    "uv": (["uv", "--version"], 1),  # "uv X.Y.Z (...)"
    "just": (["just", "--version"], 1),  # "just X.Y.Z"
    "http:temporal": (["temporal", "--version"], 2),  # "temporal version X.Y.Z (...)"
    "node": (["node", "--version"], 0),  # "vX.Y.Z"
}


def tool_mismatches(names: list[str]) -> list[str]:
    pins = mise_tools()
    missing: list[str] = []
    for name in names:
        command, index = TOOL_CHECKS[name]
        output = command_version(*command)
        words = output.split() if output else []
        found = words[index].removeprefix("v") if len(words) > index else None
        if found != pins[name]:
            label = name.removeprefix("http:")
            missing.append(f"managed {label} {pins[name]} (found {found or 'none'})")
    return missing


def requirements(profile: str) -> list[str]:
    # The offline loop runs `just check` and `just test`; the replay tests need the Temporal CLI.
    missing = tool_mismatches(["python", "uv", "just", "http:temporal"])
    if profile == "full":
        if command_version("docker", "--version") is None:
            missing.append("managed VM Docker endpoint")
        if command_version("docker", "compose", "version") is None:
            missing.append("managed VM Docker Compose plugin")
        missing.extend(tool_mismatches(["node"]))
        free_gib = shutil.disk_usage(ROOT).free / (1024**3)
        if free_gib < 12:
            missing.append(f"at least 12 GiB free disk (found {free_gib:.1f} GiB)")
        memory_gib = _host_memory_gib()
        if memory_gib and memory_gib < 10:
            missing.append(f"at least 10 GiB host memory (found {memory_gib:.1f} GiB)")
    return missing


def setup(profile: str, check_only: bool = False) -> int:
    supported, label = supported_platform()
    if not supported:
        print(
            f"unsupported host {label}; initial support is macOS Apple Silicon and Linux x86-64",
            file=sys.stderr,
        )
        return 2
    try:
        if not check_only:
            install_managed_tools()
        env = ensure_env()
        if profile == "full":
            ensure_runtime(check_only=check_only)
        missing = requirements(profile)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"setup failed: {exc}", file=sys.stderr)
        return 2
    if missing:
        print("setup is incomplete:", file=sys.stderr)
        print("\n".join(f"- {item}" for item in missing), file=sys.stderr)
        return 2
    print(f"host: {label}")
    print(f"profile: {profile}")
    print(f"environment: {env.relative_to(ROOT)}")
    if check_only:
        return 0
    run_tool(
        "uv",
        ["sync", "--locked", "--python", mise_tools()["python"], "--no-python-downloads"],
        cwd=ROOT,
    )
    if profile == "full":
        run_tool("npm", ["ci", "--no-audit", "--no-fund"], cwd=ROOT / "ui")
    return 0


def _is_runtime_home(path: Path) -> bool:
    """Only ever delete a directory that is exactly one of ./dev's per-checkout VM homes."""
    return path.parent == RUNTIME_HOMES and re.fullmatch(r"[0-9a-f]{10}", path.name) is not None


def delete_runtime_home(home: Path) -> None:
    """Delete one VM home, deleting its Lima instance first so no VM process is orphaned."""
    if not _is_runtime_home(home):
        raise RuntimeError(f"refusing to delete {home}: not a ./dev runtime home")
    if not home.exists():
        return
    if (home / LIMA_INSTANCE).exists():
        _installation, limactl = lima_paths()
        if not limactl.exists():
            raise RuntimeError(
                f"{home} holds a Lima instance but managed limactl is not installed; "
                "run ./dev once to reinstall it, then retry"
            )
        if _lima_status(limactl, home) is not None:
            subprocess.run(
                [str(limactl), "delete", "--force", LIMA_INSTANCE],
                env=_lima_env(limactl, home),
                check=True,
            )
    shutil.rmtree(home)


def stop_vm() -> int:
    _installation, limactl = lima_paths()
    status = _lima_status(limactl) if limactl.exists() else None
    if status != "Running":
        print(f"VM: {status or 'absent'}; nothing to stop")
        return 0
    subprocess.run([str(limactl), "stop", LIMA_INSTANCE], env=_lima_env(limactl), check=True)
    print(f"VM: stopped ({LIMA_HOME}); its disk, volumes and data are preserved")
    return 0


# Generated per-checkout state that `reset` deletes. Pinned tools, downloads, logs and
# reports under .harness/ are kept: they are verified caches and evidence, not stack state.
RESET_STATE = ("dev.env", "runtime-home", "bin/docker", "workspace")


def reset(*, assume_yes: bool) -> int:
    identity = _read_env().get("COMPOSE_PROJECT_NAME", project_identity())
    print(f"reset deletes this checkout's ({identity}) stack and local state:")
    print(f"- VM, Docker images and volumes (databases, artifacts, findings): {LIMA_HOME}")
    for name in RESET_STATE:
        print(f"- {(STATE / name).relative_to(ROOT)}")
    print("kept: pinned tools, downloads, logs and reports under .harness/")
    if not assume_yes:
        if not sys.stdin.isatty():
            print("reset needs confirmation: rerun in a terminal or pass --yes", file=sys.stderr)
            return 2
        if input(f"type {identity} to confirm: ").strip() != identity:
            print("reset cancelled; nothing was deleted")
            return 1
    try:
        delete_runtime_home(LIMA_HOME)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"reset failed: {exc}", file=sys.stderr)
        return 2
    for name in RESET_STATE:
        path = STATE / name
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
    print("reset complete; ./dev provisions a fresh VM and stack")
    return 0


def _worktree_homes() -> dict[Path, Path]:
    """VM home -> checkout for every live worktree of this repository (for unrecorded homes)."""
    result = subprocess.run(
        ["git", "worktree", "list", "--porcelain"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    checkouts = [
        Path(line.split(" ", 1)[1]) for line in result.stdout.splitlines()
        if line.startswith("worktree ")
    ]
    return {runtime_home_for(path): path for path in checkouts if path.is_dir()}


def classify_runtime_homes() -> list[tuple[Path, str, Path | None]]:
    """(home, state, owner) for each VM home: current, in-use, orphaned or unknown."""
    if not RUNTIME_HOMES.is_dir():
        return []
    worktrees = _worktree_homes()
    found: list[tuple[Path, str, Path | None]] = []
    for home in sorted(RUNTIME_HOMES.iterdir()):
        if not home.is_dir() or not _is_runtime_home(home):
            continue
        record = home / OWNER_RECORD
        owner = Path(record.read_text().strip()) if record.is_file() else worktrees.get(home)
        if home == LIMA_HOME:
            state = "current"
        elif owner is None:
            state = "unknown"
        elif owner.is_dir() and runtime_home_for(owner) == home:
            state = "in-use"
        else:
            state = "orphaned"
        found.append((home, state, owner))
    return found


def gc(*, delete: bool) -> int:
    homes = classify_runtime_homes()
    if not homes:
        print(f"no VM homes under {RUNTIME_HOMES}")
        return 0
    for home, state, owner in homes:
        print(f"{state:9} {home}  {owner or '(no owner record)'}")
    orphaned = [home for home, state, _owner in homes if state == "orphaned"]
    if any(state == "unknown" for _home, state, _owner in homes):
        print("unknown homes predate ownership records and match no worktree of this repository;")
        print("they may belong to another clone, so gc never deletes them. Remove one by hand with")
        print("  LIMA_HOME=<home> limactl delete --force h && rm -rf <home>")
    if not orphaned:
        print("no orphaned VM homes")
        return 0
    if not delete:
        print(f"{len(orphaned)} orphaned; ./dev gc --delete deletes their VMs and homes")
        return 0
    failed = 0
    for home in orphaned:
        try:
            delete_runtime_home(home)
            print(f"deleted {home}")
        except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
            failed += 1
            print(f"could not delete {home}: {exc}", file=sys.stderr)
    return 2 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", nargs="?", default="setup", choices=("setup", "stop-vm", "reset", "gc")
    )
    parser.add_argument("--profile", choices=("full", "offline"), default="full")
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--yes", action="store_true", help="reset: confirm without a prompt")
    parser.add_argument("--delete", action="store_true", help="gc: delete orphaned homes")
    args = parser.parse_args(argv)
    if args.action == "stop-vm":
        return stop_vm()
    if args.action == "reset":
        return reset(assume_yes=args.yes)
    if args.action == "gc":
        return gc(delete=args.delete)
    return setup(args.profile, args.check_only)


if __name__ == "__main__":
    raise SystemExit(main())
