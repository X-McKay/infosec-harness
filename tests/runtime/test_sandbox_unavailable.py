"""A host without a Docker client is an unavailable sandbox, never a crash.

Observed on a live build-repair eval on a laptop with no Docker: the sandbox-shell tool let a
raw FileNotFoundError for the `docker` binary escape, which aborted the whole experiment after
11 of 14 cases. Nothing had executed, so the honest outcome is a classified SandboxUnavailable
that the tool reports back as "no command was executed".
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from infosec_harness.runtime import capabilities
from infosec_harness.sandbox import docker, engine
from infosec_harness.sandbox.policy import SandboxUnavailable


async def test_a_missing_docker_client_is_reported_as_sandbox_unavailable(monkeypatch):
    async def no_docker(argv, **_):
        raise FileNotFoundError(2, "No such file or directory", argv[0])

    monkeypatch.setattr(engine, "run_bounded", no_docker)
    with pytest.raises(SandboxUnavailable, match="Docker client is not installed"):
        await engine.run_docker(["docker", "info"], timeout=5)
    # The availability predicates answer the question instead of raising it.
    assert await docker.docker_available() is False
    assert await docker.runtime_available("runsc") is False


async def test_the_sandbox_shell_tool_reports_an_unavailable_sandbox_without_executing(monkeypatch):
    async def unavailable(*_, **__):
        raise SandboxUnavailable("runsc is not available on this host")

    monkeypatch.setattr(docker, "run_shell", unavailable)
    ctx = SimpleNamespace(deps=SimpleNamespace(sandbox_image="img:1"), run_id="r1",
                          tool_call_id="c1")
    result = await capabilities.run_in_sandbox(ctx, "uname -a")
    assert result.startswith("[sandbox unavailable: runsc is not available")
    assert "No command was executed." in result
    assert "[exit code" not in result
