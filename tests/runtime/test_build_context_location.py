"""The build context is staged under the workspace, which the Docker VM can read.

Observed on a release qualification run from a macOS host against ./dev's Lima VM: the
Dockerfile was staged in the host's temp dir (/var/folders/...), which the VM does not mount,
so every build failed with "lstat /var/folders: no such file or directory" and every
execution-backed eval case was not_checked. The snapshot already lives under the workspace;
the Dockerfile must too.
"""

from __future__ import annotations

from pathlib import Path

from infosec_harness.domain.models import EnvironmentSpec
from infosec_harness.sandbox import docker, engine
from infosec_harness.sandbox.process import ProcessResult
from infosec_harness.settings import get_settings


async def test_the_dockerfile_is_staged_under_the_workspace(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    monkeypatch.setattr(get_settings(), "workspace_dir", workspace)
    seen: list[list[str]] = []

    async def ok(*_a, **_k):
        return None

    async def capture(argv, **_k):
        seen.append(list(argv))
        return ProcessResult(exit_code=0, stdout="", stderr="", timed_out=False, duration_s=0.0)

    monkeypatch.setattr(docker, "ensure_runtime_available", ok)
    monkeypatch.setattr(docker, "ensure_build_egress_boundary", ok)
    monkeypatch.setattr(docker, "ensure_builder", ok)
    monkeypatch.setattr(engine, "run_docker", capture)
    spec = EnvironmentSpec(base_image="python:3.12-slim", install_commands=[],
                           test_command="python -m pytest -q -s -o addopts= {test_file}")
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    await docker.build_image(snapshot, spec, "harness-target:test")

    argv = seen[0]
    dockerfile = Path(argv[argv.index("-f") + 1]) if "-f" in argv else Path(argv[argv.index("--file") + 1])
    assert dockerfile.is_relative_to(workspace.resolve() / "build")
    assert not str(dockerfile).startswith("/var/folders")
