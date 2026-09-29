"""Sandbox policy: fail-closed runtime checks, base-image allowlist, and the build-egress
allowlist derived from what a repo declares (D2/D14).

Pure, deterministic helpers (except the runtime probe), so they are unit-tested without a
daemon and enforced consistently by both the Docker and Kubernetes runners.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from infosec_harness.domain.models import EnvironmentSpec, StackFingerprint
from infosec_harness.settings import get_settings


class SandboxUnavailable(RuntimeError):
    """Raised when the required isolation runtime is not available and not overridden."""


class DisallowedBaseImage(ValueError):
    """Raised when an EnvironmentSpec names a base image outside the allowlist."""


class InvalidEnvironmentSpec(ValueError):
    """Raised when generated build fields could change Dockerfile structure or escape scope."""


_IMAGE_RE = re.compile(r"^(?:(?P<registry>[a-z0-9.\-]+(?::\d+)?)/)?(?P<repo>[a-z0-9._/\-]+)"
                       r"(?::(?P<tag>[\w.\-]+))?(?:@sha256:[0-9a-f]{64})?$", re.I)


def _registry_of(image: str) -> str:
    """Return the registry portion of an image ref, defaulting to docker.io/library.

    Docker's implicit rules: a single-segment repo (``python``) is ``docker.io/library``;
    a two-segment repo (``org/app``) is ``docker.io/org``; an explicit host (contains a dot
    or colon before the first slash) is used as-is.
    """
    m = _IMAGE_RE.match(image.strip())
    if not m:
        raise DisallowedBaseImage(f"unparseable image reference: {image!r}")
    registry = m.group("registry")
    if registry and ("." in registry or ":" in registry):
        return registry
    # No explicit host: it was part of the repo path.
    full = image.strip()
    segments = full.split("/")
    if len(segments) == 1:
        return "docker.io/library"
    return f"docker.io/{segments[0]}"


def validate_base_image(image: str, allowlist: list[str] | None = None) -> str:
    """Return the image if its registry is allowlisted, else raise DisallowedBaseImage."""
    allowed = allowlist if allowlist is not None else get_settings().allowed_base_registries
    registry = _registry_of(image)
    # docker.io/library is a subset of docker.io; match either exactly or by host prefix.
    if registry in allowed or registry.split("/")[0] in allowed:
        return image
    raise DisallowedBaseImage(
        f"base image {image!r} is from registry {registry!r}, not in the allowlist {allowed}")


_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PACKAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:@/~=\-]*$")


def validate_environment_spec(spec: EnvironmentSpec) -> EnvironmentSpec:
    """Validate model-authored fields before rendering a security-sensitive Dockerfile."""
    validate_base_image(spec.base_image)
    textual = [spec.base_image, spec.test_command, *spec.install_commands,
               *spec.env.keys(), *spec.env.values(), *spec.system_packages]
    if any("\n" in value or "\r" in value or "\0" in value for value in textual):
        raise InvalidEnvironmentSpec("environment fields must be single-line strings")
    if len(spec.install_commands) > 64 or any(len(command.encode()) > 8_192
                                               for command in spec.install_commands):
        raise InvalidEnvironmentSpec("install command count or size exceeds the build policy")
    if spec.test_command.count("{test_file}") != 1:
        raise InvalidEnvironmentSpec("test_command must contain exactly one {test_file} placeholder")
    for key in spec.env:
        if not _ENV_KEY.fullmatch(key):
            raise InvalidEnvironmentSpec(f"invalid environment variable name: {key!r}")
    for package in spec.system_packages:
        if not _PACKAGE.fullmatch(package):
            raise InvalidEnvironmentSpec(f"invalid system package token: {package!r}")
    if spec.module_path:
        module = PurePosixPath(spec.module_path.replace("\\", "/"))
        if module.is_absolute() or ".." in module.parts:
            raise InvalidEnvironmentSpec("module_path must stay inside the repository")
        if spec.scope != "partial":
            raise InvalidEnvironmentSpec("module_path is only valid for a partial environment")
    return spec


def build_egress_allowlist(stack: StackFingerprint) -> list[str]:
    """Hosts the build step may reach: the repo's declared registries plus the ecosystem
    defaults. Agents cannot widen this — it is derived from deterministic detection (D14)."""
    # Repository declarations are requests, not grants. Operators approve additional internal
    # registries by adding them to this configured allowlist; a checked-in .npmrc cannot widen it.
    hosts = set(get_settings().default_registry_allowlist)
    for reg in stack.registries:
        host = reg.split("//", 1)[-1].split("/", 1)[0]
        if host in hosts:
            hosts.add(host)
    return sorted(hosts)


async def ensure_runtime_available(purpose: str) -> None:
    """Fail closed: raise SandboxUnavailable if the gVisor runtime is missing, unless the
    operator explicitly allowed an insecure runtime for local development."""
    from infosec_harness.sandbox import docker

    s = get_settings()
    if s.allow_insecure_runtime:
        return
    if not await docker.runtime_available(s.sandbox_runtime):
        raise SandboxUnavailable(
            f"cannot {purpose}: sandbox runtime {s.sandbox_runtime!r} is not available on this "
            f"host. Install gVisor (runsc), or set HARNESS_ALLOW_INSECURE_RUNTIME=true for local "
            f"development (weaker isolation).")
