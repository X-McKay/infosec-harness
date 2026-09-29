"""Docker-backed sandbox (D2): builds target images and runs probes under gVisor.

Every container runs with the configured OCI runtime (``runsc`` = gVisor by default),
as a non-root user, with all capabilities dropped, no new privileges, pid/memory/cpu
limits, a read-only root filesystem, and a wall-clock timeout. Probe containers have **no
network**. Builds fail closed when gVisor is unavailable (unless explicitly overridden),
validate the base image against an allowlist, and pin egress to the operator-configured registry
allowlist via the proxy (D14). Untrusted install steps run on a buildx builder so they are
gVisor-contained like probes.

The worker drives the Docker daemon through its socket. In Kubernetes this module is
replaced by a Job-based runner (phase 5) behind the same functions.
"""

from __future__ import annotations

import asyncio
import contextlib
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import shlex
import tempfile
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.settings import get_settings

ORACLE_PREFIX = "HARNESS_ORACLE::"
PRECONDITION_PREFIX = "HARNESS_PRECONDITION::"
# Printed *after* the sink call returns. The precondition marker is printed before it, so on
# its own it proves the probe meant to call the sink, not that the call completed: a probe that
# threw or swallowed an error in between is indistinguishable from one the code resisted. That
# produced a measured false negative on javascript-cmdi-vulnerable, the costliest error class
# this system has.
SINK_RETURNED_PREFIX = "HARNESS_SINK_RETURNED::"
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
IMAGE_FORMAT_VERSION = "2"  # Writable build staging from immutable source snapshots.
_PROXY_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
_NO_PROXY = "localhost,127.0.0.1"


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
    async def drain(stream: asyncio.StreamReader) -> bytes:
        chunks: deque[bytes] = deque()
        size = 0
        while chunk := await stream.read(16_384):
            chunks.append(chunk)
            size += len(chunk)
            while size > MAX_CAPTURE and chunks:
                excess = size - MAX_CAPTURE
                if excess >= len(chunks[0]):
                    size -= len(chunks.popleft())
                else:
                    chunks[0] = chunks[0][excess:]
                    size -= excess
        return b"".join(chunks)

    async def feed() -> None:
        if stdin is not None and proc.stdin is not None:
            proc.stdin.write(stdin)
            await proc.stdin.drain()
            proc.stdin.close()
            await proc.stdin.wait_closed()

    stdout_task = asyncio.create_task(drain(proc.stdout))
    stderr_task = asyncio.create_task(drain(proc.stderr))
    feed_task = asyncio.create_task(feed())
    timed_out = False
    try:
        await asyncio.wait_for(asyncio.gather(proc.wait(), feed_task), timeout=timeout)
    except TimeoutError:
        timed_out = True
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        await proc.wait()
    except asyncio.CancelledError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        await proc.wait()
        raise
    finally:
        if not feed_task.done():
            feed_task.cancel()
        out, err = await asyncio.gather(stdout_task, stderr_task)
    return ProcResult(
        exit_code=None if timed_out else proc.returncode,
        stdout=out.decode(errors="replace"),
        stderr=err.decode(errors="replace"),
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
    from infosec_harness.sandbox.policy import validate_environment_spec

    validate_environment_spec(spec)
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
    # Snapshots are sealed on the host. Only this disposable image copy becomes
    # writable so non-root installers can create build output and metadata.
    lines.append(f"RUN chmod -R u+rwX {REPO_STAGE}")
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

    identity = {"spec": spec.model_dump(mode="json"), "image_format": IMAGE_FORMAT_VERSION}
    return f"harness-target:{repo_hash[:12]}-{sha256_text(canonical_json(identity))[:12]}"


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
        # The proxy enforces which hosts are reachable from the operator-managed ecosystem and
        # internal registry list. NO_PROXY must stay minimal or it becomes a bypass.
        for var in _PROXY_ENV:
            proxy_args += ["--build-arg", f"{var}={s.build_egress_proxy}"]
        proxy_args += ["--build-arg", f"NO_PROXY={_NO_PROXY}",
                       "--build-arg", f"no_proxy={_NO_PROXY}"]
    if s.use_buildx:
        return ["docker", "buildx", "build", "--builder", s.buildx_builder, "--load",
                "-f", dockerfile, "-t", tag, "--progress=plain", "--network=default", *proxy_args,
                context]
    return ["docker", "build", "-f", dockerfile, "-t", tag, "--progress=plain",
            "--network=default", *proxy_args, context]


def _builder_proxy_environment() -> dict[str, str]:
    """Validate and return the one proxy identity admitted to the secure builder."""
    from infosec_harness.sandbox.policy import SandboxUnavailable

    s = get_settings()
    try:
        address = ipaddress.ip_address(s.build_egress_host_ip)
    except ValueError as exc:
        raise SandboxUnavailable(
            "secure builds require HARNESS_BUILD_EGRESS_HOST_IP to be a numeric IPv4 address"
        ) from exc
    if not isinstance(address, ipaddress.IPv4Address) or any((
        address.is_loopback, address.is_link_local, address.is_multicast,
        address.is_unspecified,
    )):
        raise SandboxUnavailable(
            "HARNESS_BUILD_EGRESS_HOST_IP must be a usable non-loopback IPv4 address"
        )
    try:
        parsed = urlsplit(s.build_egress_proxy)
        port = parsed.port
    except ValueError as exc:
        raise SandboxUnavailable("HARNESS_BUILD_EGRESS_PROXY is not a valid proxy URL") from exc
    if (parsed.scheme != "http" or parsed.hostname != str(address) or port is None
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise SandboxUnavailable(
            "HARNESS_BUILD_EGRESS_PROXY must be an http URL whose numeric host exactly matches "
            "HARNESS_BUILD_EGRESS_HOST_IP and includes a port"
        )
    environment = {name: s.build_egress_proxy for name in _PROXY_ENV}
    environment.update({"NO_PROXY": _NO_PROXY, "no_proxy": _NO_PROXY})
    return environment


def _driver_option(name: str, value: str) -> str:
    """Encode one Buildx driver option, whose CLI parser treats the value as CSV."""
    output = io.StringIO()
    csv.writer(output, lineterminator="").writerow([f"{name}={value}"])
    return output.getvalue()


async def ensure_build_egress_boundary() -> None:
    """Require an internal RUN network plus its allowlisting proxy, or fail closed."""
    s = get_settings()
    if s.allow_insecure_runtime:
        return
    if not s.build_egress_proxy or not s.build_egress_network:
        from infosec_harness.sandbox.policy import SandboxUnavailable

        raise SandboxUnavailable(
            "build egress requires HARNESS_BUILD_EGRESS_PROXY and an internal "
            "HARNESS_BUILD_EGRESS_NETWORK; proxy environment variables alone do not block "
            "direct connections"
        )
    _builder_proxy_environment()
    result = await _run(
        ["docker", "network", "inspect", s.build_egress_network,
         "--format", "{{.Internal}}"],
        timeout=30,
    )
    if result.exit_code != 0 or result.stdout.strip().lower() != "true":
        from infosec_harness.sandbox.policy import SandboxUnavailable

        raise SandboxUnavailable(
            f"build egress network {s.build_egress_network!r} is missing or not internal"
        )


async def build_image(snapshot_path: str, spec: EnvironmentSpec, tag: str,
                      egress_hosts: list[str] | None = None) -> ProcResult:
    """Build ``tag`` from the snapshot with a Dockerfile we render outside the repo, so the
    repository can supply neither its own Dockerfile nor its own ``.dockerignore``
    (a Dockerfile-specific ignore file takes precedence over the context's).

    The base image is validated against the allowlist first (raises DisallowedBaseImage),
    and build egress is pinned to the proxy/allowlist (D14)."""
    from infosec_harness.sandbox.policy import ensure_runtime_available, validate_base_image

    validate_base_image(spec.base_image)
    s = get_settings()
    requested = set(egress_hosts or s.default_registry_allowlist)
    unapproved = requested - set(s.default_registry_allowlist)
    if unapproved:
        from infosec_harness.sandbox.policy import SandboxUnavailable

        raise SandboxUnavailable(
            f"build requested registries outside the operator allowlist: {sorted(unapproved)!r}"
        )
    await ensure_runtime_available("build the target environment")
    await ensure_build_egress_boundary()
    await ensure_builder()
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
    if s.allow_insecure_runtime:
        if not s.use_buildx:
            return
        exists = await _run(
            ["docker", "buildx", "inspect", s.buildx_builder, "--bootstrap"], timeout=120)
        if exists.exit_code != 0:
            exists = await _run(
                ["docker", "buildx", "create", "--name", s.buildx_builder,
                 "--driver", "docker-container", "--bootstrap"],
                timeout=120,
            )
        if exists.exit_code != 0 or not re.search(
            r"^Driver:\s+docker-container\s*$", exists.stdout, re.MULTILINE
        ):
            raise RuntimeError(
                f"could not prepare development builder: {tail(exists.stderr or exists.stdout)}"
            )
        return
    if not s.use_buildx:
        from infosec_harness.sandbox.policy import SandboxUnavailable

        raise SandboxUnavailable("secure builds require the docker-container buildx driver")
    if not s.build_egress_network:
        from infosec_harness.sandbox.policy import SandboxUnavailable

        raise SandboxUnavailable("secure builds require an isolated build egress network")
    proxy_environment = _builder_proxy_environment()
    exists = await _run(
        ["docker", "buildx", "inspect", s.buildx_builder, "--bootstrap"], timeout=120)
    if exists.exit_code != 0:
        driver_options = ["--driver-opt", _driver_option("network", s.build_egress_network)]
        for name, value in proxy_environment.items():
            driver_options += ["--driver-opt", _driver_option(f"env.{name}", value)]
        created = await _run(["docker", "buildx", "create", "--name", s.buildx_builder,
                              "--driver", "docker-container", *driver_options,
                              "--bootstrap"], timeout=120)
        if created.exit_code != 0:
            from infosec_harness.sandbox.policy import SandboxUnavailable

            raise SandboxUnavailable(
                f"could not create sandbox builder: {tail(created.stderr or created.stdout)}"
            )
        exists = await _run(
            ["docker", "buildx", "inspect", s.buildx_builder, "--bootstrap"], timeout=120)
    if exists.exit_code != 0 or not re.search(
        r"^Driver:\s+docker-container\s*$", exists.stdout, re.MULTILINE
    ):
        from infosec_harness.sandbox.policy import SandboxUnavailable

        raise SandboxUnavailable(
            f"buildx builder {s.buildx_builder!r} is not the required docker-container executor"
        )
    nodes = re.findall(
        rf"^Name:\s+{re.escape(s.buildx_builder)}(\d+)\s*$", exists.stdout, re.MULTILINE
    )
    if nodes != ["0"]:
        from infosec_harness.sandbox.policy import SandboxUnavailable

        raise SandboxUnavailable(
            f"buildx builder must have exactly one verified node; found node indexes {nodes!r}"
        )
    # Docker documents this managed container name for the docker-container driver. Inspect the
    # live object rather than trusting buildx's inventory: an old builder may have the right name
    # and driver while still retaining a routable network or a weaker OCI runtime.
    container = f"buildx_buildkit_{s.buildx_builder}0"
    runtime = await _run(
        ["docker", "inspect", container, "--format", "{{.HostConfig.Runtime}}"], timeout=30)
    networks = await _run(
        ["docker", "inspect", container, "--format", "{{json .NetworkSettings.Networks}}"],
        timeout=30,
    )
    environment = await _run(
        ["docker", "inspect", container, "--format", "{{json .Config.Env}}"], timeout=30)
    try:
        attached = set(json.loads(networks.stdout)) if networks.exit_code == 0 else set()
    except (TypeError, json.JSONDecodeError):
        attached = set()
    if runtime.exit_code != 0 or runtime.stdout.strip() != s.sandbox_runtime:
        from infosec_harness.sandbox.policy import SandboxUnavailable

        raise SandboxUnavailable(
            f"buildx builder is not running under required runtime {s.sandbox_runtime!r}"
        )
    if attached != {s.build_egress_network}:
        from infosec_harness.sandbox.policy import SandboxUnavailable

        raise SandboxUnavailable(
            f"buildx builder networks {sorted(attached)!r} do not match the isolated build "
            f"network {s.build_egress_network!r}"
        )
    try:
        actual_environment = {
            name: value
            for item in json.loads(environment.stdout)
            if isinstance(item, str) and "=" in item
            for name, value in [item.split("=", 1)]
        } if environment.exit_code == 0 else {}
    except (TypeError, json.JSONDecodeError):
        actual_environment = {}
    mismatched = sorted(
        name
        for name, value in proxy_environment.items()
        if actual_environment.get(name) != value
    )
    unexpected = sorted(name for name in ("ALL_PROXY", "all_proxy")
                        if name in actual_environment)
    if mismatched or unexpected:
        from infosec_harness.sandbox.policy import SandboxUnavailable

        raise SandboxUnavailable(
            "buildx builder proxy configuration is stale or unsafe; recreate the managed "
            f"builder (mismatched variables={mismatched!r}, "
            f"unexpected variables={unexpected!r})"
        )


async def prune_images(keep: int | None = None) -> int:
    """Manually evict old target images after the operator has quiesced assessments.

    This is deliberately absent from build/probe paths: between activities an active prepared
    environment has no container reference, and durable image leases do not exist yet. Removal
    is non-forced so Docker still protects images referenced by containers, but that is not a
    substitute for leases; callers must ensure no workflow can still reference the candidates.
    """
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
        rm = await _run(["docker", "rmi", image_id], timeout=60)
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
    operation = idempotency_key or f"shell:{time.monotonic_ns()}"
    name = container_name(operation)
    argv = ["docker", "run", "-i", *_hardening_args(network=network), "--name", name]
    argv += [image, "sh", "-c", command]
    return await _run_container(argv, name=name, timeout=timeout or s.sandbox_probe_timeout_s)


def container_name(idempotency_key: str) -> str:
    """A stable, Docker-legal container name for one logical sandbox operation."""
    digest = hashlib.sha256(idempotency_key.encode()).hexdigest()[:16]
    return f"harness-shell-{digest}"


async def _remove_container(name: str) -> None:
    with contextlib.suppress(Exception):
        await _run(["docker", "rm", "-f", name], timeout=30)


async def _run_container(argv: list[str], *, name: str, timeout: float,
                         stdin: bytes | None = None) -> ProcResult:
    """Run a named workload and remove the engine-side container on timeout/cancellation."""
    try:
        result = await _run(argv, stdin=stdin, timeout=timeout)
    except asyncio.CancelledError:
        await asyncio.shield(_remove_container(name))
        raise
    if result.timed_out:
        await _remove_container(name)
    return result


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
        f"chmod -R u+rwX {WORK}; "
        f"if [ -d {HOME_STAGE} ]; then cp -a {HOME_STAGE} {WORK_HOME}; else mkdir -p {WORK_HOME}; fi; "
        f"export HOME={WORK_HOME}; cd {shlex.quote(workdir)}; "
        f"mkdir -p \"$(dirname {shlex.quote(rel)})\"; cat > {shlex.quote(rel)}; "
        f"set +e; ( {cmd} ); rc=$?; "
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
        f"if [ -e {canary} ]; then echo '{CANARY_PREFIX}{nonce}'; fi; exit $rc"
    )
    name = "harness-probe-" + hashlib.sha256(
        f"{image}:{test_file_path}:{nonce}".encode()).hexdigest()[:16]
    argv = ["docker", "run", "-i", *_hardening_args(network=False, read_only=s.sandbox_read_only_root),
            "--name", name,
            "--tmpfs=/tmp:rw,size=64m,mode=1777",
            "--tmpfs=/work:rw,mode=1777",
            image, "sh", "-c", script]
    return await _run_container(argv, name=name, stdin=content.encode(),
                                timeout=s.sandbox_probe_timeout_s)


# How to ask each known test runner whether it is actually installed. Keyed on the token that
# identifies the runner inside a test command. A runner absent from this table falls back to the
# trivial shell check, so an unfamiliar command can never fail preparation spuriously.
_RUNNER_VERSION_CHECKS: tuple[tuple[str, str], ...] = (
    ("python -m pytest", "python -m pytest --version"),
    ("pytest", "pytest --version"),
    ("npx jest", "npx --no-install jest --version"),
    ("jest", "jest --version"),
    ("npx vitest", "npx --no-install vitest --version"),
    # mocha, tsx and node's own runner were missing, so a spec naming any of them got the trivial
    # shell check and an absent runner surfaced at probe time as `npx canceled due to missing
    # packages` — exit 1, no test output, routed to probe repair, which cannot install anything.
    ("npx mocha", "npx --no-install mocha --version"),
    ("mocha", "mocha --version"),
    ("npx tsx", "npx --no-install tsx --version"),
    ("node --test", "node --version"),
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


def sink_returned(output: str, nonce: str) -> bool:
    """Whether the sink call completed, as distinct from the probe having reached it.

    A fired oracle implies it: the exploit condition cannot be observed without the call
    having produced something to observe.
    """
    if f"{SINK_RETURNED_PREFIX}{nonce}" in output:
        return True
    return (f"{ORACLE_PREFIX}{nonce}" in output) or (f"{CANARY_PREFIX}{nonce}" in output)


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


# A runner that executed *no test at all* is categorically different from one that ran the
# probe and saw the oracle stay silent -- the first is a probe defect, the second is evidence.
# Both leave the three markers unprinted, so without naming the difference the diagnosis agent
# has to guess from a bare exit code. Measured: perl-cmdi-vulnerable produced
# `t/...t .. skipped: (no reason given)` with exit 255 and an EMPTY stderr; the agent guessed
# "file not written correctly", repaired the wrong thing, and burned its whole repair budget to
# `inconclusive` on a case that is genuinely exploitable. Each signature below is a phrase the
# runner itself prints when it ran zero tests; they are quoted verbatim from real output.
_NO_TESTS_SIGNATURES: tuple[tuple[str, str], ...] = (
    # prove / TAP::Harness. "skipped: (no reason given)" is a `1..0` plan with no SKIP
    # directive; "Result: NOTESTS" is prove's own summary for the same thing.
    ("skipped: (no reason given)", "prove: the test file emitted a zero-test plan (1..0)"),
    ("Result: NOTESTS", "prove: no tests were run"),
    ("you planned 1 tests but ran 0", "prove: the plan promised tests that never ran"),
    # pytest
    ("no tests ran", "pytest: no tests ran"),
    ("collected 0 items", "pytest: collected 0 items"),
    # Maven Surefire. The "matching pattern" wording is the one that actually showed up, on
    # java-sqli-fixed: a selector handed a file path instead of a class name matches nothing.
    ("Tests run: 0", "surefire: ran 0 tests"),
    ("No tests to run", "surefire: found no tests to run"),
    ("No tests matching pattern", "surefire: the -Dtest selector matched no test class"),
    ("No tests were executed", "surefire: no tests were executed"),
    # A pom that configures maven-surefire-plugin with <skipTests>true</skipTests> at plugin
    # level. `-DskipTests=false` does not override an explicit plugin configuration (measured),
    # so the probe run exits 0 having executed nothing and written no reports at all. Named here
    # because the cause is the repository's build, not the probe: without this the diagnosis has
    # only a clean exit and no markers to go on, and repair rewrites a correct probe.
    ("Tests are skipped.", "surefire: the build itself skipped the tests -- the pom configures "
                           "maven-surefire-plugin with <skipTests>true</skipTests>, which "
                           "-DskipTests=false cannot override"),
    # Jest
    ("No tests found", "jest: found no test files"),
    ("Tests:       0 total", "jest: ran 0 tests"),
    # Vitest. Measured on real fixtures: a file with no `test()` in it is a *failed suite*, not
    # an empty one, and a path vitest cannot match is a different message again. Neither says
    # "no tests found", which is why jest's wording caught nothing here.
    ("No test suite found in file", "vitest: the file declared no test suite"),
    ("No test files found", "vitest: matched no test file"),
)
# Signatures that need a boundary a substring cannot express. mocha's summary is "  0 passing",
# and `"0 passing" in output` is TRUE for a ten-test run ("10 passing") -- measured -- which would
# report a healthy run as having executed nothing. node:test prints its own counters as TAP
# comments; `# pass 0` with `# fail 0` is a run in which every test was skipped or filtered out,
# which is exactly the zero-test shape (`node --test` has no "no tests" message of its own).
_NO_TESTS_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?<!\d)0 passing"), "mocha: 0 passing"),
    (re.compile(r"^# pass 0$", re.M), "node:test: every test was skipped or filtered out"),
)


def no_tests_executed(output: str) -> str | None:
    """Name the runner's own evidence that it executed zero tests, or None.

    Pure and deterministic, so the diagnosis agent is told *what happened* instead of inferring
    it from an exit code. A zero-test run is never a negative result: nothing exercised the
    sink, so it says nothing about exploitability. Callers put the returned phrase on
    `ProbeExecution.runner_reported_no_tests`, which is serialised into the diagnosis, repair,
    and verdict prompts.
    """
    for signature, reason in _NO_TESTS_SIGNATURES:
        if signature in output:
            return f"{reason} (matched {signature!r}). Zero tests ran, so this is not a negative result."
    for pattern, reason in _NO_TESTS_PATTERNS:
        match = pattern.search(output)
        if match:
            return (f"{reason} (matched {match.group(0)!r}). Zero tests ran, so this is not a "
                    "negative result.")
    return None


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
    res = await _run(
        ["docker", "info", "--format", "{{json .Runtimes}} {{.DefaultRuntime}}"], timeout=20)
    # buildx's docker-container executor inherits the daemon default. Requiring the configured
    # runtime to be both registered and selected prevents an advertised-but-unused runtime from
    # satisfying the startup check; probes additionally pass --runtime on every invocation.
    return (res.exit_code == 0 and f'"{runtime}"' in res.stdout
            and res.stdout.rstrip().endswith(runtime))


def default_workspace() -> Path:
    path = get_settings().workspace_dir.resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


__all__ = [
    "ORACLE_PREFIX",
    "PRECONDITION_PREFIX",
    "SINK_RETURNED_PREFIX",
    "ProcResult",
    "build_image",
    "default_workspace",
    "docker_available",
    "image_exists",
    "image_tag_for",
    "no_tests_executed",
    "oracle_signals",
    "render_dockerfile",
    "run_probe",
    "run_shell",
    "runtime_available",
    "tail",
]

os.environ.setdefault("DOCKER_BUILDKIT", "1")
