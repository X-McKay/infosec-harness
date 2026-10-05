"""Docker-backed execution (D2): the runtime gate, image builds, and probe/shell containers.

Every container runs with the configured OCI runtime (``runsc`` = gVisor; anything else
requires the explicit insecure-development override), as a non-root user, with all
capabilities dropped, no new privileges, pid/memory/cpu limits, a read-only root filesystem
with tmpfs work directories, no network, and a wall-clock timeout. Builds fail closed when
gVisor is unavailable (unless explicitly overridden), validate the spec and base image before
touching the daemon, and route all egress through the operator's allowlisting proxy on an
internal network (D14). Untrusted install steps run on a buildx builder so they are
gVisor-contained like probes. This is the only execution runner.

Everything else lives where it is defined, and callers import it from there: ``image``
(Dockerfile, build identity, build argv), ``boundary`` (egress network and builder
verification), ``output`` (marker and runner-output parsing), ``markers``, ``engine`` (the
Docker CLI) and ``process`` (the result type).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import shlex
import tempfile
import time
from pathlib import Path

from infosec_harness.domain.canonical import sha256_hex
from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.sandbox import REQUIRED_RUNTIME, engine
from infosec_harness.sandbox.boundary import ensure_build_egress_boundary, ensure_builder
from infosec_harness.sandbox.errors import SandboxUnavailable
from infosec_harness.sandbox.image import (
    HOME_STAGE,
    IMAGE_LABEL,
    PROVENANCE_LABEL,
    REPO_STAGE,
    SANDBOX_USER,
    WORK,
    WORK_HOME,
    build_argv,
    render_dockerfile,
)
from infosec_harness.sandbox.markers import FILE_ORACLE_NAME_PREFIX, FILE_ORACLE_PREFIX
from infosec_harness.sandbox.process import ProcessResult
from infosec_harness.settings import get_settings


async def docker_available() -> bool:
    try:
        res = await engine.run_docker(["docker", "info", "--format", "{{json .Runtimes}}"],
                                      timeout=20)
    except SandboxUnavailable:
        return False
    return res.exit_code == 0


# One JSON document, so the answer is parsed rather than substring-matched: a runtime named
# ``xrunsc`` or a runtime list that merely mentions the name must not pass.
_RUNTIME_INFO = '{"runtimes":{{json .Runtimes}},"default":{{json .DefaultRuntime}}}'


async def runtime_available(runtime: str | None = None) -> bool:
    """True only when the daemon registers ``runtime`` and selects it as its default.

    buildx's docker-container executor inherits the daemon default, so a runtime that is
    advertised but not the default does not contain build steps; probes additionally pass
    ``--runtime`` on every invocation.
    """
    runtime = runtime or get_settings().sandbox_runtime
    try:
        res = await engine.run_docker(["docker", "info", "--format", _RUNTIME_INFO], timeout=20)
    except SandboxUnavailable:
        return False
    if res.exit_code != 0:
        return False
    try:
        info = json.loads(res.stdout)
    except ValueError:
        return False
    return (isinstance(info, dict) and isinstance(info.get("runtimes"), dict)
            and runtime in info["runtimes"] and info.get("default") == runtime)


async def ensure_runtime_available(purpose: str) -> None:
    """Fail closed unless gVisor (runsc) is configured, registered and the daemon default.

    Only the explicit development override may select or skip the runtime. The configured name
    is not evidence by itself: the daemon must advertise it and select it as its default.
    """
    s = get_settings()
    if s.allow_insecure_runtime:
        return
    if s.sandbox_runtime != REQUIRED_RUNTIME:
        raise SandboxUnavailable(
            f"cannot {purpose}: sandbox runtime {s.sandbox_runtime!r} is not gVisor "
            f"({REQUIRED_RUNTIME!r}); only HARNESS_ALLOW_INSECURE_RUNTIME=true may select a "
            f"weaker runtime for local development.")
    if not await runtime_available(s.sandbox_runtime):
        raise SandboxUnavailable(
            f"cannot {purpose}: sandbox runtime {s.sandbox_runtime!r} is not available on this "
            f"host. Install gVisor (runsc), or set HARNESS_ALLOW_INSECURE_RUNTIME=true for local "
            f"development (weaker isolation).")


async def image_exists(tag: str) -> bool:
    """True only for a reusable image this harness built for ``tag``.

    The tag name alone is not provenance: the image must carry the target label and the
    provenance label written by :func:`build_argv` for exactly this tag.
    """
    res = await engine.run_docker(["docker", "image", "inspect", "--format",
                                   "{{json .Config.Labels}}", "--", tag], timeout=30)
    if res.exit_code != 0:
        return False
    try:
        labels = json.loads(res.stdout)
    except ValueError:
        return False
    key, value = IMAGE_LABEL.split("=", 1)
    return (isinstance(labels, dict) and labels.get(key) == value
            and labels.get(PROVENANCE_LABEL) == tag)


async def build_image(snapshot_path: str, spec: EnvironmentSpec, tag: str) -> ProcessResult:
    """Build ``tag`` from the snapshot with a Dockerfile we render outside the repo, so the
    repository can supply neither its own Dockerfile nor its own ``.dockerignore``
    (a Dockerfile-specific ignore file takes precedence over the context's).

    The spec is validated by rendering it before the daemon is touched (raises
    DisallowedBaseImage or InvalidEnvironmentSpec), and build egress is confined to the
    operator's proxy and internal network (D14)."""
    dockerfile_text = render_dockerfile(spec)
    s = get_settings()
    await ensure_runtime_available("build the target environment")
    await ensure_build_egress_boundary()
    await ensure_builder()
    with tempfile.TemporaryDirectory(prefix="harness-build-") as tmp:
        dockerfile = Path(tmp) / "Dockerfile"
        dockerfile.write_text(dockerfile_text)
        Path(tmp, "Dockerfile.dockerignore").write_text(".git\n")
        argv = build_argv(str(dockerfile), tag, snapshot_path)
        return await engine.run_docker(argv, timeout=s.sandbox_build_timeout_s)


def _hardening_args() -> list[str]:
    """Every workload: gVisor (or the explicit insecure runtime), no network, least privilege."""
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
        "--network=none",
        "--tmpfs=/tmp:rw,size=64m,mode=1777",
        "--tmpfs=/work:rw,mode=1777",
    ]
    if s.sandbox_read_only_root:
        args.append("--read-only")
    return args


def _staged(command: str, *, workdir: str, prepare: str = "") -> str:
    """Copy the read-only stage into the /work tmpfs, then run ``command`` from ``workdir``.

    Staging and ``prepare`` abort on the first failure; ``command`` runs with errexit off.
    """
    return (
        "set -e; "
        f"cp -a {REPO_STAGE} {WORK}; "
        f"chmod -R u+rwX {WORK}; "
        f"if [ -d {HOME_STAGE} ]; then cp -a {HOME_STAGE} {WORK_HOME}; else mkdir -p {WORK_HOME}; fi; "
        f"export HOME={WORK_HOME}; cd {workdir}; "
        f"{prepare}set +e; {command}"
    )


def container_name(idempotency_key: str) -> str:
    """A stable, Docker-legal container name for one logical sandbox operation."""
    return f"harness-shell-{sha256_hex(idempotency_key)[:16]}"


async def _remove_container(name: str) -> None:
    with contextlib.suppress(Exception):
        await engine.run_docker(["docker", "rm", "-f", name], timeout=30)


async def _run_container(argv: list[str], *, name: str, timeout: float,
                         stdin: bytes | None = None) -> ProcessResult:
    """Run a named workload and remove the engine-side container on timeout/cancellation.

    Names are deterministic per logical operation, so a stale container left by a crashed
    earlier attempt is removed first instead of failing the retry on a name conflict.
    """
    await _remove_container(name)
    try:
        result = await engine.run_docker(argv, stdin=stdin, timeout=timeout)
    except asyncio.CancelledError:
        await asyncio.shield(_remove_container(name))
        raise
    if result.timed_out:
        await _remove_container(name)
    return result


async def run_shell(image: str, command: str, *, timeout: float | None = None,
                    idempotency_key: str | None = None) -> ProcessResult:
    """Run a shell command inside ``image`` (used by the sandbox shell tool and smoke checks).

    The container is no-network with a read-only root; the repository and home stages are
    copied to the /work tmpfs and the command runs from the image's working directory there.

    ``idempotency_key`` names the container deterministically. Executing a command is a
    write, so the tool standard (agent-playbook §5/§6) requires a stable key rather than
    assuming a retry is free: with one, a retried attempt is recognisably the same operation
    rather than a second anonymous container, and an orphan left by a crashed worker is
    removed by name before the retry starts.
    """
    s = get_settings()
    operation = idempotency_key or f"shell:{time.monotonic_ns()}"
    name = container_name(operation)
    # The image WORKDIR is the staged module directory; run from its /work copy.
    script = _staged(command, workdir=f'"{WORK}${{PWD#{REPO_STAGE}}}"')
    argv = ["docker", "run", "-i", *_hardening_args(), "--name", name, image, "sh", "-c", script]
    return await _run_container(argv, name=name, timeout=timeout or s.sandbox_probe_timeout_s)


async def run_probe(image: str, test_file_path: str, content: str, test_command: str, nonce: str,
                    module_path: str = "") -> ProcessResult:
    """Write the probe into an ephemeral, no-network container and run it.

    The container root is mounted read-only (D2); the repo is copied from the read-only
    stage (/opt/repo) into a writable /work tmpfs, the probe file is written there, and the
    test runs from that copy. The markers are read deterministically by ``output``.
    """
    s = get_settings()
    rel = test_file_path.lstrip("/")
    if ".." in Path(rel).parts:
        raise ValueError("probe path must stay inside the repository")
    cmd = test_command.replace("{test_file}", shlex.quote(rel))
    file_oracle = f"/tmp/{FILE_ORACLE_NAME_PREFIX}{nonce}"
    workdir = WORK + (("/" + module_path.strip("/")) if module_path else "")
    script = _staged(
        f"( {cmd} ); rc=$?; ",
        workdir=shlex.quote(workdir),
        prepare=f"mkdir -p \"$(dirname {shlex.quote(rel)})\"; cat > {shlex.quote(rel)}; ",
    ) + (
        # Surefire can be *configured by the repository* to redirect a test's stdout to
        # target/surefire-reports/<class>-output.txt, and -Dmaven.test.redirectTestOutputToFile=
        # false does not override an explicit plugin-level <configuration> (measured under
        # Surefire 3.2.5, both in <build><plugins> and in <pluginManagement>). The probe then
        # runs, passes, and every HARNESS_ marker lands in that file: exit 0 and nothing on
        # stdout, the one failure shape neither diagnosis nor repair can see the cause of. So
        # the files are read back here. Additive and cheap: nothing matches for a non-Maven
        # project, and for a Maven one whose output was not redirected there is no such file.
        "for f in target/surefire-reports/*-output.txt */target/surefire-reports/*-output.txt; "
        "do [ -f \"$f\" ] && cat \"$f\"; done; "
        f"if [ -e {file_oracle} ]; then echo '{FILE_ORACLE_PREFIX}{nonce}'; fi; exit $rc"
    )
    name = "harness-probe-" + sha256_hex(f"{image}:{test_file_path}:{nonce}")[:16]
    argv = ["docker", "run", "-i", *_hardening_args(), "--name", name, image, "sh", "-c", script]
    return await _run_container(argv, name=name, stdin=content.encode(),
                                timeout=s.sandbox_probe_timeout_s)
