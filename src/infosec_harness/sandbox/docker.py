"""Docker-backed sandbox (D2): builds target images and runs probes under gVisor.

Every container runs with the configured OCI runtime (``runsc`` = gVisor by default),
as a non-root user, with all capabilities dropped, no new privileges, pid/memory/cpu
limits, and a wall-clock timeout. Probe containers have **no network**.

The worker drives the Docker daemon through its socket. In Kubernetes this module is
replaced by a Job-based runner (phase 5) behind the same functions.
"""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.settings import get_settings

ORACLE_PREFIX = "HARNESS_ORACLE::"
PRECONDITION_PREFIX = "HARNESS_PRECONDITION::"
CANARY_PREFIX = "HARNESS_CANARY_PRESENT::"
SANDBOX_USER = "10001:10001"
MAX_CAPTURE = 64_000


@dataclass
class ProcResult:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_s: float


async def _run(argv: list[str], *, stdin: bytes | None = None, timeout: float) -> ProcResult:
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(stdin), timeout=timeout)
        timed_out = False
    except TimeoutError:
        proc.kill()
        out, err = await proc.communicate()
        timed_out = True
    return ProcResult(
        exit_code=None if timed_out else proc.returncode,
        stdout=out.decode(errors="replace")[-MAX_CAPTURE:],
        stderr=err.decode(errors="replace")[-MAX_CAPTURE:],
        timed_out=timed_out,
        duration_s=time.monotonic() - start,
    )


def _hardening_args(*, network: bool) -> list[str]:
    s = get_settings()
    args = [
        "--rm",
        f"--runtime={s.sandbox_runtime}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--memory={s.sandbox_memory}",
        f"--cpus={s.sandbox_cpus}",
        f"--pids-limit={s.sandbox_pids_limit}",
        f"--user={SANDBOX_USER}",
    ]
    if not network:
        args.append("--network=none")
    return args


def render_dockerfile(spec: EnvironmentSpec) -> str:
    """Deterministic Dockerfile for an EnvironmentSpec. Dependencies are installed at build
    time (network allowed, D14); probes later run with no network."""
    lines = [f"FROM {spec.base_image}"]
    lines.append("USER root")
    if spec.system_packages:
        pkgs = " ".join(shlex.quote(p) for p in sorted(set(spec.system_packages)))
        lines.append(
            "RUN if command -v apt-get >/dev/null; then apt-get update && "
            f"DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {pkgs} "
            "&& rm -rf /var/lib/apt/lists/*; "
            f"elif command -v apk >/dev/null; then apk add --no-cache {pkgs}; "
            "else echo 'no supported package manager' && exit 1; fi"
        )
    for key, value in sorted(spec.env.items()):
        lines.append(f"ENV {key}={shlex.quote(value)}")
    lines.append("WORKDIR /work/repo")
    lines.append(f"COPY --chown={SANDBOX_USER} . /work/repo")
    lines.append(f"RUN mkdir -p /work/home && chown {SANDBOX_USER} /work/home")
    lines.append("ENV HOME=/work/home")
    lines.append(f"USER {SANDBOX_USER}")
    workdir = "/work/repo" + (f"/{spec.module_path.strip('/')}" if spec.scope == "partial" and spec.module_path else "")
    lines.append(f"WORKDIR {workdir}")
    for cmd in spec.install_commands:
        lines.append(f"RUN {cmd}")
    return "\n".join(lines) + "\n"


def image_tag_for(repo_hash: str, spec: EnvironmentSpec) -> str:
    from infosec_harness.domain.models import canonical_json, sha256_text

    return f"harness-target:{repo_hash[:12]}-{sha256_text(canonical_json(spec))[:12]}"


async def image_exists(tag: str) -> bool:
    res = await _run(["docker", "image", "inspect", tag], timeout=30)
    return res.exit_code == 0


async def build_image(snapshot_path: str, spec: EnvironmentSpec, tag: str) -> ProcResult:
    """Build ``tag`` from the snapshot with a Dockerfile we render outside the repo, so the
    repository can supply neither its own Dockerfile nor its own ``.dockerignore``
    (a Dockerfile-specific ignore file takes precedence over the context's)."""
    s = get_settings()
    with tempfile.TemporaryDirectory(prefix="harness-build-") as tmp:
        dockerfile = Path(tmp) / "Dockerfile"
        dockerfile.write_text(render_dockerfile(spec))
        Path(tmp, "Dockerfile.dockerignore").write_text(".git\n")
        argv = ["docker", "build", "-f", str(dockerfile), "-t", tag, "--progress=plain", snapshot_path]
        return await _run(argv, timeout=s.sandbox_build_timeout_s)


async def run_shell(image: str, command: str, *, network: bool, timeout: float | None = None) -> ProcResult:
    """Run a shell command inside ``image`` (used by the sandbox shell tool)."""
    s = get_settings()
    argv = ["docker", "run", "-i", *_hardening_args(network=network), image, "sh", "-c", command]
    return await _run(argv, timeout=timeout or s.sandbox_probe_timeout_s)


async def run_probe(image: str, test_file_path: str, content: str, test_command: str, nonce: str) -> ProcResult:
    """Write the probe into the (ephemeral) container via stdin and run it, with no network."""
    s = get_settings()
    rel = test_file_path.lstrip("/")
    if ".." in Path(rel).parts:
        raise ValueError("probe path must stay inside the repository")
    cmd = test_command.replace("{test_file}", shlex.quote(rel))
    canary = f"/tmp/harness_canary_{nonce}"
    script = (
        f"mkdir -p \"$(dirname {shlex.quote(rel)})\" && cat > {shlex.quote(rel)} && "
        f"( {cmd} ); rc=$?; "
        f"if [ -e {canary} ]; then echo '{CANARY_PREFIX}{nonce}'; fi; exit $rc"
    )
    argv = ["docker", "run", "-i", *_hardening_args(network=False), "--tmpfs=/tmp:rw,size=64m",
            image, "sh", "-c", script]
    return await _run(argv, stdin=content.encode(), timeout=s.sandbox_probe_timeout_s)


def oracle_signals(output: str, nonce: str) -> tuple[bool, bool]:
    """Deterministic oracle detection: (oracle_fired, precondition_reached)."""
    fired = (f"{ORACLE_PREFIX}{nonce}" in output) or (f"{CANARY_PREFIX}{nonce}" in output)
    reached = f"{PRECONDITION_PREFIX}{nonce}" in output or fired
    return fired, reached


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def tail(text: str, limit: int = 4000) -> str:
    text = _ANSI.sub("", text)
    return text[-limit:]


async def docker_available() -> bool:
    try:
        res = await _run(["docker", "info", "--format", "{{json .Runtimes}}"], timeout=20)
    except FileNotFoundError:
        return False
    return res.exit_code == 0


async def runtime_available(runtime: str | None = None) -> bool:
    runtime = runtime or get_settings().sandbox_runtime
    res = await _run(["docker", "info", "--format", "{{json .Runtimes}}"], timeout=20)
    return res.exit_code == 0 and f'"{runtime}"' in res.stdout


def default_workspace() -> Path:
    path = get_settings().workspace_dir.resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


__all__ = [
    "ORACLE_PREFIX",
    "PRECONDITION_PREFIX",
    "ProcResult",
    "build_image",
    "default_workspace",
    "docker_available",
    "image_exists",
    "image_tag_for",
    "oracle_signals",
    "render_dockerfile",
    "run_probe",
    "run_shell",
    "runtime_available",
    "tail",
]

os.environ.setdefault("DOCKER_BUILDKIT", "1")
