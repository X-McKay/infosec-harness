"""Sandbox policy: base-image allowlist, JVM selector grammar and build-spec validation.

Pure and deterministic, unit-tested without a daemon. The runtime probe and the build-egress
boundary are checked against the live daemon in ``docker`` and ``boundary``; repository
declarations never widen build egress (D14).
"""

from __future__ import annotations

import re
import shlex
from pathlib import PurePosixPath

from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.sandbox.errors import (
    DisallowedBaseImage,
    InvalidEnvironmentSpec,
    SandboxUnavailable,
)
from infosec_harness.settings import get_settings

__all__ = [
    "DisallowedBaseImage",
    "InvalidEnvironmentSpec",
    "SandboxUnavailable",
    "image_repository",
    "jvm_class_selector",
    "validate_base_image",
    "validate_environment_spec",
]

DOCKER_HUB = "docker.io"
# Docker's reference grammar, lowercase only. Anything that does not parse is rejected rather
# than guessed at: the allowlist decision is only as good as this normalization.
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*"
                   r"(?::[0-9]+)?")
_PATH_COMPONENT = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*")
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def image_repository(image: str) -> tuple[str, tuple[str, ...]]:
    """Normalize an image reference to ``(registry host, repository path)``.

    Docker's implicit rules: the first component is a registry host only when it contains a dot
    or a port or is ``localhost``; otherwise the image is on Docker Hub, and a single-component
    Docker Hub name (``python``) is an official image under ``library``.
    """
    ref = image.strip()
    name, at, digest = ref.partition("@")
    if at and not _DIGEST.fullmatch(digest):
        raise DisallowedBaseImage(f"unparseable image reference: {image!r}")
    head, slash, last = name.rpartition("/")
    last, colon, tag = last.partition(":")
    if colon and not _TAG.fullmatch(tag):
        raise DisallowedBaseImage(f"unparseable image reference: {image!r}")
    parts = [*(head.split("/") if slash else ()), last]
    host = DOCKER_HUB
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        host = parts.pop(0)
    if not _HOST.fullmatch(host) or not all(_PATH_COMPONENT.fullmatch(p) for p in parts):
        raise DisallowedBaseImage(f"unparseable image reference: {image!r}")
    if host == DOCKER_HUB and len(parts) == 1:
        parts.insert(0, "library")
    return host, tuple(parts)


def _entry(value: str) -> tuple[str, tuple[str, ...]] | None:
    parts = [part for part in value.strip().lower().split("/") if part]
    return (parts[0], tuple(parts[1:])) if parts else None


def validate_base_image(image: str, allowlist: list[str] | None = None) -> str:
    """Return the image if an allowlist entry covers it, else raise DisallowedBaseImage.

    An entry is a registry host (``public.ecr.aws``: every repository on it) or a host plus a
    namespace (``docker.io/library``: Docker official images only, not every Docker Hub
    account). Namespaces match whole path components, so ``docker.io/library`` never admits
    ``docker.io/library-evil/x``.
    """
    allowed = allowlist if allowlist is not None else get_settings().allowed_base_registries
    host, path = image_repository(image)
    for value in allowed:
        entry = _entry(value)
        if entry is not None and entry[0] == host and path[:len(entry[1])] == entry[1]:
            return image
    raise DisallowedBaseImage(
        f"base image {image!r} resolves to {host}/{'/'.join(path)}, which no allowlist entry "
        f"covers: {allowed}")


_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PACKAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:@/~=\-]*$")
_JVM_RUNNERS = frozenset({"mvn", "mvnw", "gradle", "gradlew"})
_TEST_CLASS = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def jvm_class_selector(command: str) -> str | None:
    """The one test class a JVM command selects, None for a non-JVM command.

    The only parser of the selector: the Dockerfile validation and the control-test writer in
    ``canary`` both use it, so the class a control test is written as is by construction the
    class the command runs. A JVM command that does not select exactly one literal simple class
    with its own runner's selector is rejected, never an arbitrary shell command.
    """
    try:
        tokens = shlex.split(command)
    except ValueError as error:
        first = command.split(maxsplit=1)[0] if command.strip() else ""
        if first.rsplit("/", 1)[-1].strip("\"'") in _JVM_RUNNERS:
            raise InvalidEnvironmentSpec("JVM test command has invalid quoting") from error
        return None
    if not tokens or tokens[0].rsplit("/", 1)[-1] not in _JVM_RUNNERS:
        return None
    if (len(command.encode()) > 8_192 or "{test_file}" in command
            or any(character in command for character in ";&|<>`$()")):
        raise InvalidEnvironmentSpec("JVM test command must select one literal test class")
    selectors = [i for i, token in enumerate(tokens)
                 if token == "-Dtest" or token.startswith("-Dtest=")
                 or token == "--tests" or token.startswith("--tests=")]
    mentions = [token for token in tokens if "-Dtest" in token or "--tests" in token]
    if len(selectors) != 1 or len(mentions) != 1:
        # A selector buried in another argument (``-Dother=-Dtest=X``) is as ambiguous to a
        # reader of the command as a second selector is to the runner.
        raise InvalidEnvironmentSpec("JVM test command must contain exactly one class selector")
    index = selectors[0]
    runner = tokens[0].rsplit("/", 1)[-1]
    if runner in {"mvn", "mvnw"} and tokens[index].startswith("-Dtest="):
        selected = tokens[index].removeprefix("-Dtest=")
    elif (runner in {"gradle", "gradlew"} and tokens[index] == "--tests"
          and index + 1 < len(tokens)):
        selected = tokens[index + 1].removeprefix("*")
    else:
        raise InvalidEnvironmentSpec("JVM test command requires its runner's class selector")
    if not _TEST_CLASS.fullmatch(selected):
        raise InvalidEnvironmentSpec("JVM selector must name one simple test class")
    # The class must be written literally after its selector, not assembled by shell quoting
    # inside the value (``-Dtest='X'``): the command text then says exactly what runs.
    if not re.search(rf"(?:-Dtest=|--tests\s+['\"]?\*?){selected}(?![\w$])", command):
        raise InvalidEnvironmentSpec("JVM selector must name its class literally")
    return selected


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
    if jvm_class_selector(spec.test_command) is None and spec.test_command.count("{test_file}") != 1:
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
