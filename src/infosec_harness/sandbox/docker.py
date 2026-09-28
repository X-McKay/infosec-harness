"""Docker-backed sandbox (D2): builds target images and runs probes under gVisor.

Every container runs with the configured OCI runtime (``runsc`` = gVisor by default),
as a non-root user, with all capabilities dropped, no new privileges, pid/memory/cpu
limits, a read-only root filesystem, and a wall-clock timeout. Probe containers have **no
network**. Builds fail closed when gVisor is unavailable (unless explicitly overridden),
validate the base image against an allowlist, and pin egress to the repo-derived registry
allowlist via the proxy (D14). Untrusted install steps run on a buildx builder so they are
gVisor-contained like probes.

The worker drives the Docker daemon through its socket. In Kubernetes this module is
replaced by a Job-based runner (phase 5) behind the same functions.
"""

from __future__ import annotations

import asyncio
import hashlib
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
# The repo is baked in read-only at /opt/repo (with HOME at /opt/home); at probe time it is
# copied to a writable /work tmpfs so the root filesystem can be mounted read-only.
REPO_STAGE = "/opt/repo"
HOME_STAGE = "/opt/home"
WORK = "/work/repo"
WORK_HOME = "/work/home"
IMAGE_LABEL = "harness.image=target"


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


def _hardening_args(*, network: bool, read_only: bool = False) -> list[str]:
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
    if read_only:
        args.append("--read-only")
    if not network:
        args.append("--network=none")
    return args


def render_dockerfile(spec: EnvironmentSpec) -> str:
    """Deterministic Dockerfile for an EnvironmentSpec. Dependencies are installed at build
    time (network allowed, D14); probes later run with no network."""
    lines = [f"FROM {spec.base_image}", f"LABEL {IMAGE_LABEL}", "USER root"]
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
    # Stage the repo read-only at /opt/repo with HOME at /opt/home; installs run here.
    lines.append(f"COPY --chown={SANDBOX_USER} . {REPO_STAGE}")
    lines.append(f"RUN mkdir -p {HOME_STAGE} && chown {SANDBOX_USER} {HOME_STAGE}")
    lines.append(f"ENV HOME={HOME_STAGE}")
    lines.append(f"USER {SANDBOX_USER}")
    build_workdir = REPO_STAGE + module_suffix(spec)
    lines.append(f"WORKDIR {build_workdir}")
    for cmd in spec.install_commands:
        lines.append(f"RUN {cmd}")
    return "\n".join(lines) + "\n"


def module_suffix(spec: EnvironmentSpec) -> str:
    if spec.scope == "partial" and spec.module_path:
        return "/" + spec.module_path.strip("/")
    return ""


def image_tag_for(repo_hash: str, spec: EnvironmentSpec) -> str:
    from infosec_harness.domain.models import canonical_json, sha256_text

    return f"harness-target:{repo_hash[:12]}-{sha256_text(canonical_json(spec))[:12]}"


async def image_exists(tag: str) -> bool:
    res = await _run(["docker", "image", "inspect", tag], timeout=30)
    return res.exit_code == 0


def build_argv(dockerfile: str, tag: str, context: str, egress_hosts: list[str] | None) -> list[str]:
    """Construct the build command. Uses a dedicated buildx builder (whose buildkit runs
    under the sandbox runtime, so untrusted install scripts are gVisor-contained, D2) and
    pins build egress through the allowlisting proxy (D14). Pure so it can be unit-tested."""
    s = get_settings()
    proxy_args: list[str] = []
    if s.build_egress_proxy:
        # Route ALL build egress through the allowlisting proxy; only loopback bypasses it.
        # The proxy enforces which hosts are reachable (its allowlist is seeded from the
        # ecosystem defaults + configured internal registries; egress_hosts is the
        # repo-derived set to add). NO_PROXY must stay minimal or it becomes a bypass.
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            proxy_args += ["--build-arg", f"{var}={s.build_egress_proxy}"]
        proxy_args += ["--build-arg", "NO_PROXY=localhost,127.0.0.1",
                       "--build-arg", "no_proxy=localhost,127.0.0.1"]
    if s.use_buildx:
        return ["docker", "buildx", "build", "--builder", s.buildx_builder, "--load",
                "-f", dockerfile, "-t", tag, "--progress=plain", *proxy_args, context]
    return ["docker", "build", "-f", dockerfile, "-t", tag, "--progress=plain", *proxy_args, context]


async def build_image(snapshot_path: str, spec: EnvironmentSpec, tag: str,
                      egress_hosts: list[str] | None = None) -> ProcResult:
    """Build ``tag`` from the snapshot with a Dockerfile we render outside the repo, so the
    repository can supply neither its own Dockerfile nor its own ``.dockerignore``
    (a Dockerfile-specific ignore file takes precedence over the context's).

    The base image is validated against the allowlist first (raises DisallowedBaseImage),
    and build egress is pinned to the proxy/allowlist (D14)."""
    from infosec_harness.sandbox.policy import validate_base_image

    validate_base_image(spec.base_image)
    s = get_settings()
    with tempfile.TemporaryDirectory(prefix="harness-build-") as tmp:
        dockerfile = Path(tmp) / "Dockerfile"
        dockerfile.write_text(render_dockerfile(spec))
        Path(tmp, "Dockerfile.dockerignore").write_text(".git\n")
        argv = build_argv(str(dockerfile), tag, snapshot_path, egress_hosts)
        return await _run(argv, timeout=s.sandbox_build_timeout_s)


async def ensure_builder() -> None:
    """Create the dedicated buildx builder if missing (idempotent). Its buildkit runs under
    the daemon's runtime; for gVisor coverage of untrusted build steps the host must provide
    gVisor (e.g. dockerd default-runtime=runsc, or a runsc-backed buildkitd). No-op unless
    use_buildx is set."""
    s = get_settings()
    if not s.use_buildx:
        return
    exists = await _run(["docker", "buildx", "inspect", s.buildx_builder], timeout=30)
    if exists.exit_code != 0:
        await _run(["docker", "buildx", "create", "--name", s.buildx_builder,
                    "--driver", "docker-container", "--bootstrap"], timeout=120)


async def prune_images(keep: int | None = None) -> int:
    """Evict oldest cached target images beyond ``keep`` (image cache GC). Returns count removed."""
    keep = keep if keep is not None else get_settings().image_cache_max
    res = await _run(["docker", "images", "--filter", f"label={IMAGE_LABEL}",
                      "--format", "{{.ID}}\t{{.CreatedAt}}"], timeout=30)
    if res.exit_code != 0:
        return 0
    rows = [line.split("\t") for line in res.stdout.splitlines() if "\t" in line]
    # `docker images` lists newest first; keep the first `keep`, remove the rest.
    stale = [r[0] for r in rows[keep:]]
    removed = 0
    for image_id in stale:
        rm = await _run(["docker", "rmi", "-f", image_id], timeout=60)
        removed += int(rm.exit_code == 0)
    return removed


async def run_shell(image: str, command: str, *, network: bool, timeout: float | None = None,
                    idempotency_key: str | None = None) -> ProcResult:
    """Run a shell command inside ``image`` (used by the sandbox shell tool).

    ``idempotency_key`` names the container deterministically. Executing a command is a
    write, so the tool standard (agent-playbook §5/§6) requires a stable key rather than
    assuming a retry is free: with one, a retried attempt is recognisably the same operation
    rather than a second anonymous container, and an orphan left by a crashed worker can be
    found and removed by name.
    """
    s = get_settings()
    argv = ["docker", "run", "-i", *_hardening_args(network=network)]
    if idempotency_key:
        argv += ["--name", container_name(idempotency_key)]
    argv += [image, "sh", "-c", command]
    return await _run(argv, timeout=timeout or s.sandbox_probe_timeout_s)


def container_name(idempotency_key: str) -> str:
    """A stable, Docker-legal container name for one logical sandbox operation."""
    digest = hashlib.sha256(idempotency_key.encode()).hexdigest()[:16]
    return f"harness-shell-{digest}"


async def run_probe(image: str, test_file_path: str, content: str, test_command: str, nonce: str,
                    module_path: str = "") -> ProcResult:
    """Write the probe into an ephemeral, no-network container and run it.

    The container root is mounted read-only (D2); the repo is copied from the read-only
    stage (/opt/repo) into a writable /work tmpfs, the probe file is written there, and the
    test runs from that copy. The oracle/canary markers are detected deterministically.
    """
    s = get_settings()
    rel = test_file_path.lstrip("/")
    if ".." in Path(rel).parts:
        raise ValueError("probe path must stay inside the repository")
    cmd = test_command.replace("{test_file}", shlex.quote(rel))
    canary = f"/tmp/harness_canary_{nonce}"
    workdir = WORK + (("/" + module_path.strip("/")) if module_path else "")
    script = (
        "set -e; "
        f"cp -a {REPO_STAGE} {WORK}; "
        f"if [ -d {HOME_STAGE} ]; then cp -a {HOME_STAGE} {WORK_HOME}; else mkdir -p {WORK_HOME}; fi; "
        f"export HOME={WORK_HOME}; cd {shlex.quote(workdir)}; "
        f"mkdir -p \"$(dirname {shlex.quote(rel)})\"; cat > {shlex.quote(rel)}; "
        f"set +e; ( {cmd} ); rc=$?; "
        f"if [ -e {canary} ]; then echo '{CANARY_PREFIX}{nonce}'; fi; exit $rc"
    )
    argv = ["docker", "run", "-i", *_hardening_args(network=False, read_only=s.sandbox_read_only_root),
            "--tmpfs=/tmp:rw,size=64m,mode=1777",
            "--tmpfs=/work:rw,mode=1777",
            image, "sh", "-c", script]
    return await _run(argv, stdin=content.encode(), timeout=s.sandbox_probe_timeout_s)


# How to ask each known test runner whether it is actually installed. Keyed on the token that
# identifies the runner inside a test command. A runner absent from this table falls back to the
# trivial shell check, so an unfamiliar command can never fail preparation spuriously.
_RUNNER_VERSION_CHECKS: tuple[tuple[str, str], ...] = (
    ("python -m pytest", "python -m pytest --version"),
    ("pytest", "pytest --version"),
    ("npx jest", "npx --no-install jest --version"),
    ("jest", "jest --version"),
    ("npx vitest", "npx --no-install vitest --version"),
    ("prove", "prove --version"),
    ("mvn", "mvn -v"),
    ("gradlew", "./gradlew --offline --version"),
    ("gradle", "gradle --version"),
)


def runner_check_command(test_command: str) -> str | None:
    """A command that proves the test runner in ``test_command`` is installed and invocable.

    The smoke test previously ran `echo`, which proves only that the image starts a shell. A
    missing runner therefore surfaced at *probe* time as exit 127, where the graph routes to
    probe repair — powerless, because the fault is in the environment. Checking it during
    preparation puts the failure where build repair can act on it.

    Returns None for a runner we do not recognise, so preparation is never failed by a command
    this table simply has not learned.
    """
    command = (test_command or "").strip()
    for token, check in _RUNNER_VERSION_CHECKS:
        if token in command:
            return check
    return None


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
