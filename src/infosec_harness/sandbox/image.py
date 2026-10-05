"""Target images: the Dockerfile we render, the identity an image is cached under, and the
build command. Pure apart from reading settings, so all of it is unit-tested without a daemon.

The repository supplies neither its Dockerfile nor its ``.dockerignore``: :func:`render_dockerfile`
writes one from a validated ``EnvironmentSpec``. Dependencies are installed at build time
through the operator's allowlisting proxy (D14); probes later run with no network.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import shlex
from urllib.parse import urlsplit

from infosec_harness.domain.canonical import digest
from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.sandbox.errors import SandboxUnavailable
from infosec_harness.sandbox.policy import validate_environment_spec
from infosec_harness.settings import get_settings

SANDBOX_USER = "10001:10001"
# The repo is baked in read-only at /opt/repo (with HOME at /opt/home); at probe time it is
# copied to a writable /work tmpfs so the root filesystem can be mounted read-only.
REPO_STAGE = "/opt/repo"
HOME_STAGE = "/opt/home"
WORK = "/work/repo"
WORK_HOME = "/work/home"
IMAGE_LABEL = "harness.image=target"
# Written by every build and required on every cache hit: a same-named image that this
# harness did not build under the current boundary is never reused.
PROVENANCE_LABEL = "harness.image.tag"
IMAGE_FORMAT_VERSION = "4"  # Build-boundary mode in the tag and a verified provenance label.
PROXY_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
NO_PROXY = "localhost,127.0.0.1"


def builder_proxy_environment() -> dict[str, str]:
    """Validate and return the one proxy identity admitted to the secure builder."""
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
    environment = {name: s.build_egress_proxy for name in PROXY_ENV}
    environment.update({"NO_PROXY": NO_PROXY, "no_proxy": NO_PROXY})
    return environment


def driver_option(name: str, value: str) -> str:
    """Encode one Buildx driver option, whose CLI parser treats the value as CSV."""
    output = io.StringIO()
    csv.writer(output, lineterminator="").writerow([f"{name}={value}"])
    return output.getvalue()


def _maven_build_proxy(spec: EnvironmentSpec) -> str | None:
    """Use only the existing validated operator proxy for recognized Maven runners."""
    try:
        tokens = shlex.split(spec.test_command)
    except ValueError:
        return None  # validate_environment_spec owns malformed command rejection.
    if not tokens or tokens[0].rsplit("/", 1)[-1] not in {"mvn", "mvnw"}:
        return None
    if not get_settings().build_egress_proxy:
        return None
    return builder_proxy_environment()["HTTP_PROXY"]


def _maven_install_prefix(proxy: str | None) -> str:
    if proxy is None:
        return ""
    parsed = urlsplit(proxy)
    # The caller obtained this identity exclusively from builder_proxy_environment.
    # Resolver1.9 native HTTP transport needs its explicit system-property opt-in.
    # Keep existing JVM options and settings; apply these options to this RUN only.
    properties = (
        "-Daether.connector.http.useSystemProperties=true "
        f"-Dhttp.proxyHost={parsed.hostname} -Dhttp.proxyPort={parsed.port} "
        f"-Dhttps.proxyHost={parsed.hostname} -Dhttps.proxyPort={parsed.port} "
        "-Dhttp.nonProxyHosts=localhost|127.0.0.1"
    )
    return 'export MAVEN_OPTS="${MAVEN_OPTS:-} ' + properties + '"; '


def module_suffix(spec: EnvironmentSpec) -> str:
    if spec.scope == "partial" and spec.module_path:
        return "/" + spec.module_path.strip("/")
    return ""


def render_dockerfile(spec: EnvironmentSpec) -> str:
    """Deterministic Dockerfile for a validated EnvironmentSpec (the one place it is validated
    before a build: base-image allowlist, single-line fields, selector grammar, module path)."""
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
    lines.append(f"WORKDIR {REPO_STAGE}{module_suffix(spec)}")
    install_prefix = _maven_install_prefix(_maven_build_proxy(spec))
    for cmd in spec.install_commands:
        lines.append(f"RUN {install_prefix}{cmd}")
    return "\n".join(lines) + "\n"


def _build_boundary() -> dict:
    """The isolation an image was built under; a weaker or different build is never reused."""
    s = get_settings()
    return {
        "insecure_runtime": s.allow_insecure_runtime,
        "runtime": s.sandbox_runtime,
        "buildx": s.use_buildx,
        "builder": s.buildx_builder if s.use_buildx else None,
        "egress_network": s.build_egress_network,
        "egress_proxy": s.build_egress_proxy,
    }


def image_tag_for(repo_hash: str, spec: EnvironmentSpec) -> str:
    identity = {
        "spec": spec.model_dump(mode="json"),
        "image_format": IMAGE_FORMAT_VERSION,
        "build_boundary": _build_boundary(),
    }
    if proxy := _maven_build_proxy(spec):
        identity["maven_build_proxy"] = proxy
    return f"harness-target:{repo_hash[:12]}-{digest(identity)[:12]}"


def build_argv(dockerfile: str, tag: str, context: str) -> list[str]:
    """Construct the build command. Uses a dedicated buildx builder (whose buildkit runs
    under the sandbox runtime, so untrusted install scripts are gVisor-contained, D2) and
    pins build egress through the allowlisting proxy (D14)."""
    s = get_settings()
    proxy_args: list[str] = []
    if s.build_egress_proxy:
        # Route ALL build egress through the allowlisting proxy; only loopback bypasses it.
        # The proxy enforces which hosts are reachable from the operator-managed ecosystem and
        # internal registry list. NO_PROXY must stay minimal or it becomes a bypass.
        for var in PROXY_ENV:
            proxy_args += ["--build-arg", f"{var}={s.build_egress_proxy}"]
        proxy_args += ["--build-arg", f"NO_PROXY={NO_PROXY}",
                       "--build-arg", f"no_proxy={NO_PROXY}"]
    labels = ["--label", f"{PROVENANCE_LABEL}={tag}"]
    if s.use_buildx:
        return ["docker", "buildx", "build", "--builder", s.buildx_builder, "--load",
                "-f", dockerfile, "-t", tag, *labels, "--progress=plain", "--network=default",
                *proxy_args, "--", context]
    return ["docker", "build", "-f", dockerfile, "-t", tag, *labels, "--progress=plain",
            "--network=default", *proxy_args, "--", context]
