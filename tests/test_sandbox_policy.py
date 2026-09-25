"""Sandbox policy and hardening: base-image allowlist, egress allowlist, fail-closed,
read-only probe args, image GC selection, and k8s Pod rendering — all deterministic."""
import pytest

from infosec_harness.domain.models import EnvironmentSpec, StackFingerprint
from infosec_harness.sandbox import docker, k8s
from infosec_harness.sandbox.policy import (
    DisallowedBaseImage,
    SandboxUnavailable,
    build_egress_allowlist,
    ensure_runtime_available,
    validate_base_image,
)
from infosec_harness.settings import get_settings

ALLOW = ["docker.io/library", "docker.io", "public.ecr.aws"]


@pytest.mark.parametrize("image", ["python:3.12-slim", "node:22-slim", "maven:3.9-eclipse-temurin-21",
                                   "docker.io/library/perl:5.40", "public.ecr.aws/x/y:1"])
def test_base_image_allowed(image):
    assert validate_base_image(image, ALLOW) == image


@pytest.mark.parametrize("image", ["evil.example.com/malware:latest", "ghcr.io/x/y:1",
                                    "quay.io/foo/bar"])
def test_base_image_rejected(image):
    with pytest.raises(DisallowedBaseImage):
        validate_base_image(image, ALLOW)


def test_egress_allowlist_includes_defaults_and_repo_registries():
    stack = StackFingerprint(registries=["artifactory.corp.internal", "https://nexus.corp/repo"])
    hosts = build_egress_allowlist(stack)
    assert "pypi.org" in hosts and "registry.npmjs.org" in hosts  # ecosystem defaults
    assert "artifactory.corp.internal" in hosts
    assert "nexus.corp" in hosts  # scheme/path stripped


async def test_fail_closed_when_runtime_missing(monkeypatch):
    async def _no(_runtime=None):
        return False

    monkeypatch.setattr(docker, "runtime_available", _no)
    monkeypatch.setattr(get_settings(), "allow_insecure_runtime", False, raising=False)
    with pytest.raises(SandboxUnavailable):
        await ensure_runtime_available("test")


async def test_fail_closed_bypassed_when_insecure_allowed(monkeypatch):
    async def _no(_runtime=None):
        return False

    monkeypatch.setattr(docker, "runtime_available", _no)
    monkeypatch.setattr(get_settings(), "allow_insecure_runtime", True, raising=False)
    await ensure_runtime_available("test")  # no raise


def _spec(**kw):
    return EnvironmentSpec(base_image="python:3.12-slim", install_commands=["pip install -e ."],
                           test_command="python -m pytest -q -s {test_file}", **kw)


def test_dockerfile_stages_repo_readonly():
    df = docker.render_dockerfile(_spec())
    assert f"COPY --chown={docker.SANDBOX_USER} . {docker.REPO_STAGE}" in df
    assert f"LABEL {docker.IMAGE_LABEL}" in df
    assert f"WORKDIR {docker.REPO_STAGE}" in df


def test_build_argv_uses_buildx_and_proxy(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "use_buildx", True, raising=False)
    monkeypatch.setattr(s, "build_egress_proxy", "http://egress:3128", raising=False)
    argv = docker.build_argv("/tmp/Dockerfile", "tag:1", "/ctx", ["pypi.org"])
    assert "buildx" in argv and "--builder" in argv and s.buildx_builder in argv
    joined = " ".join(argv)
    assert "HTTP_PROXY=http://egress:3128" in joined and "NO_PROXY=localhost,127.0.0.1" in joined


async def test_run_probe_readonly_argv_shape(monkeypatch):
    # Inspect the docker run argv the probe would use (via a captured _run).
    captured = {}

    async def fake_run(argv, *, stdin=None, timeout):
        captured["argv"] = argv
        captured["stdin"] = stdin
        return docker.ProcResult(exit_code=0, stdout=f"{docker.PRECONDITION_PREFIX}n",
                                 stderr="", timed_out=False, duration_s=0.1)

    monkeypatch.setattr(docker, "_run", fake_run)
    monkeypatch.setattr(get_settings(), "sandbox_read_only_root", True, raising=False)
    await docker.run_probe("img", "tests/t.py", "print('x')", "pytest {test_file}", "n")
    argv = captured["argv"]
    assert "--read-only" in argv and "--network=none" in argv
    assert any(a.startswith("--tmpfs=/work") for a in argv)
    assert captured["stdin"] == b"print('x')"


async def test_prune_images_removes_oldest(monkeypatch):
    ids = [f"id{i}\t2026-01-0{i}" for i in range(1, 6)]
    removed = []

    async def fake_run(argv, *, stdin=None, timeout):
        if argv[:2] == ["docker", "images"]:
            return docker.ProcResult(exit_code=0, stdout="\n".join(ids), stderr="", timed_out=False, duration_s=0)
        if argv[:2] == ["docker", "rmi"]:
            removed.append(argv[-1])
            return docker.ProcResult(exit_code=0, stdout="", stderr="", timed_out=False, duration_s=0)
        return docker.ProcResult(exit_code=1, stdout="", stderr="", timed_out=False, duration_s=0)

    monkeypatch.setattr(docker, "_run", fake_run)
    n = await docker.prune_images(keep=2)
    assert n == 3 and removed == ["id3", "id4", "id5"]  # newest-first; keep first 2


def test_k8s_probe_pod_is_hardened():
    pod = k8s.render_probe_pod("probe-1", "img:1", "echo hi")
    spec = pod["spec"]
    assert spec["runtimeClassName"] == "gvisor"
    assert spec["automountServiceAccountToken"] is False
    c = spec["containers"][0]["securityContext"]
    assert c["allowPrivilegeEscalation"] is False
    assert c["capabilities"]["drop"] == ["ALL"]
    assert spec["securityContext"]["runAsNonRoot"] is True
    assert spec["activeDeadlineSeconds"] == get_settings().sandbox_probe_timeout_s


async def test_build_and_probe_activities_with_faked_sandbox(tmp_path, monkeypatch):
    """Build/probe activities run with the new hardening (fail-closed + base-image + egress)
    when the runtime is faked present — the logic the Temporal integration test exercises,
    minus Temporal."""
    from infosec_harness.domain.models import ProbeSource, RepoSnapshot
    from infosec_harness.workflows import activities

    (tmp_path / "app.py").write_text("def f():\n    return 1\n")
    (tmp_path / "requirements.txt").write_text("")

    async def _rt(runtime=None):
        return True

    async def _exists(tag):
        return False

    async def _build(path, spec, tag, egress_hosts=None):
        assert egress_hosts and "pypi.org" in egress_hosts
        return docker.ProcResult(exit_code=0, stdout="built", stderr="", timed_out=False, duration_s=0.1)

    async def _probe(image, tfp, content, cmd, nonce, module_path=""):
        return docker.ProcResult(exit_code=0, stdout=f"{docker.PRECONDITION_PREFIX}{nonce}",
                                 stderr="", timed_out=False, duration_s=0.1)

    async def _prune(keep=None):
        return 0

    monkeypatch.setattr(docker, "runtime_available", _rt)
    monkeypatch.setattr(docker, "image_exists", _exists)
    monkeypatch.setattr(docker, "build_image", _build)
    monkeypatch.setattr(docker, "run_probe", _probe)
    monkeypatch.setattr(docker, "prune_images", _prune)

    snap = RepoSnapshot(repo_url=str(tmp_path), revision="HEAD", path=str(tmp_path), content_hash="h" * 8)
    spec = EnvironmentSpec(base_image="python:3.12-slim", install_commands=["pip install -e ."],
                          test_command="python -m pytest -q -s {test_file}")
    build = await activities.build_environment_activity({"snapshot": snap.model_dump(), "spec": spec.model_dump()})
    assert build.ok and build.image_tag

    probe = ProbeSource(test_file_path="tests/t.py", content="print('HARNESS')")
    ex = await activities.execute_probe_activity(
        {"image_tag": build.image_tag, "probe": probe.model_dump(), "spec": spec.model_dump(),
         "nonce": "abc", "attempt": 1})
    assert ex.precondition_reached and ex.exit_code == 0


async def test_build_activity_fails_closed_without_runtime(tmp_path, monkeypatch):
    from infosec_harness.domain.models import RepoSnapshot
    from infosec_harness.workflows import activities

    async def _no(runtime=None):
        return False

    async def _exists(tag):
        return False

    monkeypatch.setattr(docker, "runtime_available", _no)
    monkeypatch.setattr(docker, "image_exists", _exists)
    monkeypatch.setattr(get_settings(), "allow_insecure_runtime", False, raising=False)
    snap = RepoSnapshot(repo_url=str(tmp_path), revision="HEAD", path=str(tmp_path), content_hash="h" * 8)
    spec = EnvironmentSpec(base_image="python:3.12-slim", install_commands=[],
                          test_command="pytest {test_file}")
    build = await activities.build_environment_activity({"snapshot": snap.model_dump(), "spec": spec.model_dump()})
    assert not build.ok and "runsc" in build.error_excerpt
