"""The Docker CLI: the worker's only route to the daemon.

Every Docker invocation in the sandbox goes through :func:`run_docker`, which bounds output,
kills the process group on timeout or cancellation (``process.run_bounded``), and hands the
client nothing from the worker environment beyond what the Docker CLI and BuildKit read.
"""

from __future__ import annotations

import os

from infosec_harness.sandbox.errors import SandboxUnavailable
from infosec_harness.sandbox.process import ProcessResult, run_bounded

MAX_CAPTURE = 64_000
# The Docker CLI and BuildKit read only these from the worker environment; model, database and
# provider credentials are never handed to the daemon client.
_DOCKER_ENVIRONMENT = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG",
                       "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "DOCKER_API_VERSION",
                       "BUILDX_CONFIG", "XDG_RUNTIME_DIR")


def _docker_environment() -> dict[str, str]:
    environment = {name: os.environ[name] for name in _DOCKER_ENVIRONMENT if name in os.environ}
    environment["DOCKER_BUILDKIT"] = "1"
    return environment


async def run_docker(argv: list[str], *, stdin: bytes | None = None,
                     timeout: float) -> ProcessResult:
    """Run one Docker CLI command; a host without the client is an unavailable sandbox."""
    try:
        return await run_bounded(argv, env=_docker_environment(), timeout=timeout, stdin=stdin,
                                 capture_limit=MAX_CAPTURE)
    except FileNotFoundError as e:
        # Not a programming error: callers already fail closed on SandboxUnavailable, and
        # nothing executed.
        raise SandboxUnavailable(
            f"cannot run {argv[0]!r}: the Docker client is not installed on this host ({e})"
        ) from e
