"""Build-boundary verification against the live daemon: the internal egress network and the
dedicated buildx builder that runs untrusted install steps.

Nothing here trusts a name. The egress network must report itself internal, and the builder's
managed BuildKit container is inspected for its OCI runtime, its networks and its proxy
environment, because buildx's own inventory can describe an old builder that has the right name
and driver while still holding a routable network or a weaker runtime.
"""

from __future__ import annotations

import json
import re

from infosec_harness.sandbox import engine
from infosec_harness.sandbox.errors import SandboxUnavailable
from infosec_harness.sandbox.image import builder_proxy_environment, driver_option
from infosec_harness.sandbox.output import tail
from infosec_harness.sandbox.process import ProcessResult
from infosec_harness.settings import get_settings

_DOCKER_CONTAINER_DRIVER = re.compile(r"^Driver:\s+docker-container\s*$", re.MULTILINE)


async def ensure_build_egress_boundary() -> None:
    """Require an internal RUN network plus its allowlisting proxy, or fail closed."""
    s = get_settings()
    if s.allow_insecure_runtime:
        return
    if not s.build_egress_proxy or not s.build_egress_network:
        raise SandboxUnavailable(
            "build egress requires HARNESS_BUILD_EGRESS_PROXY and an internal "
            "HARNESS_BUILD_EGRESS_NETWORK; proxy environment variables alone do not block "
            "direct connections"
        )
    builder_proxy_environment()
    result = await engine.run_docker(
        ["docker", "network", "inspect", s.build_egress_network, "--format", "{{.Internal}}"],
        timeout=30,
    )
    if result.exit_code != 0 or result.stdout.strip().lower() != "true":
        raise SandboxUnavailable(
            f"build egress network {s.build_egress_network!r} is missing or not internal"
        )


async def _inspect_builder(name: str) -> ProcessResult:
    return await engine.run_docker(["docker", "buildx", "inspect", name, "--bootstrap"],
                                   timeout=120)


async def _create_builder(name: str, *driver_options: str) -> ProcessResult:
    return await engine.run_docker(["docker", "buildx", "create", "--name", name,
                                    "--driver", "docker-container", *driver_options,
                                    "--bootstrap"], timeout=120)


async def ensure_builder() -> None:
    """Prepare the dedicated buildx builder (idempotent) and, unless the insecure development
    override is set, verify the live builder is the secure one. No-op without buildx under the
    override; secure builds require it."""
    s = get_settings()
    if s.allow_insecure_runtime:
        if s.use_buildx:
            await _bootstrap_dev_builder(s.buildx_builder)
        return
    if not s.use_buildx:
        raise SandboxUnavailable("secure builds require the docker-container buildx driver")
    if not s.build_egress_network:
        raise SandboxUnavailable("secure builds require an isolated build egress network")
    proxy_environment = builder_proxy_environment()
    inspected = await _inspect_builder(s.buildx_builder)
    if inspected.exit_code != 0:
        options = ["--driver-opt", driver_option("network", s.build_egress_network)]
        for name, value in proxy_environment.items():
            options += ["--driver-opt", driver_option(f"env.{name}", value)]
        created = await _create_builder(s.buildx_builder, *options)
        if created.exit_code != 0:
            raise SandboxUnavailable(
                f"could not create sandbox builder: {tail(created.stderr or created.stdout)}"
            )
        inspected = await _inspect_builder(s.buildx_builder)
    await _verify_secure_builder(inspected, builder=s.buildx_builder, runtime=s.sandbox_runtime,
                                 network=s.build_egress_network,
                                 proxy_environment=proxy_environment)


async def _bootstrap_dev_builder(builder: str) -> None:
    """Insecure development only: a docker-container builder, created if missing, unverified."""
    inspected = await _inspect_builder(builder)
    if inspected.exit_code != 0:
        inspected = await _create_builder(builder)
    if inspected.exit_code != 0 or not _DOCKER_CONTAINER_DRIVER.search(inspected.stdout):
        raise RuntimeError(
            f"could not prepare development builder: {tail(inspected.stderr or inspected.stdout)}"
        )


def _json_or(text: str, default):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


async def _verify_secure_builder(inspected: ProcessResult, *, builder: str, runtime: str,
                                 network: str, proxy_environment: dict[str, str]) -> None:
    """Fail closed unless the live builder is exactly the secure one this boundary describes."""
    if inspected.exit_code != 0 or not _DOCKER_CONTAINER_DRIVER.search(inspected.stdout):
        raise SandboxUnavailable(
            f"buildx builder {builder!r} is not the required docker-container executor"
        )
    nodes = re.findall(rf"^Name:\s+{re.escape(builder)}(\d+)\s*$", inspected.stdout, re.MULTILINE)
    if nodes != ["0"]:
        raise SandboxUnavailable(
            f"buildx builder must have exactly one verified node; found node indexes {nodes!r}"
        )
    # Docker documents this managed container name for the docker-container driver.
    container = f"buildx_buildkit_{builder}0"

    async def inspect(template: str) -> ProcessResult:
        return await engine.run_docker(["docker", "inspect", container, "--format", template],
                                       timeout=30)

    actual_runtime = await inspect("{{.HostConfig.Runtime}}")
    networks = await inspect("{{json .NetworkSettings.Networks}}")
    environment = await inspect("{{json .Config.Env}}")
    if actual_runtime.exit_code != 0 or actual_runtime.stdout.strip() != runtime:
        raise SandboxUnavailable(f"buildx builder is not running under required runtime {runtime!r}")
    attached = _json_or(networks.stdout, {}) if networks.exit_code == 0 else {}
    attached = set(attached) if isinstance(attached, dict) else set()
    if attached != {network}:
        raise SandboxUnavailable(
            f"buildx builder networks {sorted(attached)!r} do not match the isolated build "
            f"network {network!r}"
        )
    items = _json_or(environment.stdout, []) if environment.exit_code == 0 else []
    actual_environment = dict(
        item.split("=", 1) for item in (items if isinstance(items, list) else [])
        if isinstance(item, str) and "=" in item
    )
    mismatched = sorted(name for name, value in proxy_environment.items()
                        if actual_environment.get(name) != value)
    unexpected = sorted(name for name in ("ALL_PROXY", "all_proxy") if name in actual_environment)
    if mismatched or unexpected:
        # Names only: a stale builder's proxy URL can carry credentials.
        raise SandboxUnavailable(
            "buildx builder proxy configuration is stale or unsafe; recreate the managed "
            f"builder (mismatched variables={mismatched!r}, "
            f"unexpected variables={unexpected!r})"
        )
